import argparse
import sys
import json
from pathlib import Path

from parser.eml_parser import parse_eml
from analyzers.header_analyzer import analyze_headers
from analyzers.body_analyzer import analyze_body
from analyzers.attachment_analyzer import analyze_attachments
from enrichment.lookup import enrich_email
from scoring.scorer import compute_score
from output.report_html import generate_html_report


def main():
    parser = argparse.ArgumentParser(
        description="Dolos v1 — Phishing Email Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
USAGE:
  python main.py                          Analyze the first .eml found in current directory
  python main.py email.eml               Analyze a specific file
  python main.py email.eml --output html --save report.html
  python main.py email.eml --output json
  python main.py email.eml --no-enrichment

OUTPUT FORMATS:
  cli   Colored text output in terminal (default)
  html  Full HTML report, saveable with --save
  json  Structured output for integration with other tools

ANALYSIS MODULES:
  Header      SPF / DKIM / DMARC, Received chain, typosquatting (Levenshtein)
  Body        URL extraction, redirect chain, phishing keyword scoring
  Attachments Magic bytes, MD5/SHA256 hashes, double extension, Office macros (oletools)
  Enrichment  VirusTotal (hash + URL), AbuseIPDB (IP), URLhaus (IP)

SCORING:
  0           BENIGN           No anomalies detected
  1-29        SUSPICIOUS       Minor anomalies, monitor
  30-59       LIKELY_MALICIOUS Significant anomalies, probable phishing
  60-100      MALICIOUS        Clear indicators of phishing or malware

EXAMPLES:
  python main.py email.eml --no-enrichment
  python main.py email.eml --output html --save report.html
  python main.py email.eml --output json | jq '.verdict'

NOTES:
  If multiple .eml files are present, the first in alphabetical order is used.
  To analyze a specific one, pass it as an explicit argument.
        """
    )

    parser.add_argument("file", nargs="?", default=None,
                        help=".eml file to analyze (optional)")
    parser.add_argument("--output", choices=["cli", "html", "json"], default="cli")
    parser.add_argument("--save", metavar="PATH")
    parser.add_argument("--no-enrichment", action="store_true")
    parser.add_argument("--debug", action="store_true",
                        help="Show debug information")

    args = parser.parse_args()

    if args.file and args.file.lower() == "help":
        parser.print_help()
        sys.exit(0)

    # Resolve the file to analyze
    if args.file:
        eml_path = Path(args.file)
        if not eml_path.exists():
            print(f"[ERROR] File not found: {args.file}", file=sys.stderr)
            sys.exit(1)
    else:
        eml_files = sorted(Path(".").glob("*.eml"))
        if not eml_files:
            print("[ERROR] No .eml files found in current directory.", file=sys.stderr)
            sys.exit(1)
        if len(eml_files) > 1:
            print(f"[!] Found {len(eml_files)} .eml files, using first: {eml_files[0].name}", file=sys.stderr)
        eml_path = eml_files[0]

    print(f"[*] Analyzing: {eml_path.name}", file=sys.stderr)

    # Analysis pipeline
    print("[*] Parsing...", file=sys.stderr)
    parsed = parse_eml(str(eml_path))

    print("[*] Analyzing headers...", file=sys.stderr)
    header_analysis = analyze_headers(parsed["headers"])

    print("[*] Analyzing body...", file=sys.stderr)
    body_analysis = analyze_body(parsed["body"])

    print("[*] Analyzing attachments...", file=sys.stderr)
    attachment_analysis = analyze_attachments(parsed["attachments"])

    if args.no_enrichment:
        enrichment = {
            "ip_lookup": None,
            "attachment_hashes": [],
            "url_lookups": [],
            "anomalies": [],
        }
        print("[*] Enrichment skipped (--no-enrichment)", file=sys.stderr)
    else:
        print("[*] API enrichment...", file=sys.stderr)
        enrichment = enrich_email(header_analysis, body_analysis, attachment_analysis)

    print("[*] Scoring...", file=sys.stderr)
    score_result = compute_score(header_analysis, body_analysis, attachment_analysis, enrichment)

    # Debug
    if args.debug:
        print("\n=== DEBUG ===", file=sys.stderr)
        print(f"Body text length: {len(parsed['body'].get('text', ''))}", file=sys.stderr)
        print(f"Body html length: {len(parsed['body'].get('html', ''))}", file=sys.stderr)
        print(f"URLs found: {len(body_analysis['urls'])}", file=sys.stderr)
        for url in body_analysis['urls']:
            print(f"  URL: {url['original'][:100]}", file=sys.stderr)
            print(f"       final: {url.get('final', 'N/A')[:100]}", file=sys.stderr)
            print(f"       error: {url.get('error', 'none')}", file=sys.stderr)
        print(f"Header anomalies: {header_analysis.get('anomalies', [])}", file=sys.stderr)
        print(f"Body anomalies: {body_analysis.get('anomalies', [])}", file=sys.stderr)
        print(f"Enrichment anomalies: {enrichment.get('anomalies', [])}", file=sys.stderr)
        print("=============\n", file=sys.stderr)

    # Output
    if args.output == "cli":
        _print_cli(eml_path.name, parsed["headers"], header_analysis,
                   body_analysis, attachment_analysis, enrichment, score_result)

    elif args.output == "html":
        html = generate_html_report(
            filename=eml_path.name,
            headers=parsed["headers"],
            header_analysis=header_analysis,
            body_analysis=body_analysis,
            attachment_analysis=attachment_analysis,
            enrichment=enrichment,
            score_result=score_result,
        )
        if args.save:
            Path(args.save).write_text(html, encoding="utf-8")
            print(f"[✓] Report saved: {args.save}", file=sys.stderr)
        else:
            print(html)

    elif args.output == "json":
        output = {
            "file": eml_path.name,
            "score": score_result["score"],
            "verdict": score_result["verdict"],
            "anomalies": score_result["anomalies"],
            "header": {
                "authentication": header_analysis["authentication"],
                "sender": header_analysis["sender"],
            },
            "enrichment": enrichment,
            "attachments": attachment_analysis["attachments"],
        }
        content = json.dumps(output, indent=2, ensure_ascii=False)
        if args.save:
            Path(args.save).write_text(content, encoding="utf-8")
            print(f"[✓] JSON saved: {args.save}", file=sys.stderr)
        else:
            print(content)


def _print_cli(filename, raw_headers, header_analysis, body_analysis,
               attachment_analysis, enrichment, score_result):

    verdict_colors = {
        "BENIGN":           "\033[92m",
        "SUSPICIOUS":       "\033[93m",
        "LIKELY_MALICIOUS": "\033[33m",
        "MALICIOUS":        "\033[91m",
    }
    RESET = "\033[0m"
    BOLD  = "\033[1m"

    color = verdict_colors.get(score_result["verdict"], "")

    print(f"\n{'='*50}")
    print(f"{BOLD}  DOLOS v1{RESET}")
    print(f"  {filename}")
    print(f"{'='*50}")
    print(f"\n  Verdict: {color}{BOLD}{score_result['verdict']}{RESET}")
    print(f"  Score:   {score_result['score']}/100")
    print(f"  Anomalies: {score_result['anomaly_count']}")

    auth = header_analysis["authentication"]
    sender = header_analysis["sender"]
    print(f"\n  {'─'*46}")
    print(f"  HEADER")
    print(f"  {'─'*46}")
    print(f"  From:     {sender['from_address']}")
    print(f"  Subject:  {raw_headers.get('subject', '')}")
    print(f"  SPF:      {auth['spf'].upper()}")
    print(f"  DKIM:     {auth['dkim'].upper()}")
    print(f"  DMARC:    {auth['dmarc'].upper()}")

    if enrichment.get("ip_lookup"):
        ip_data = enrichment["ip_lookup"]
        ab = ip_data["abuseipdb"]
        print(f"\n  {'─'*46}")
        print(f"  SENDER IP")
        print(f"  {'─'*46}")
        print(f"  IP: {ip_data['ip']}")
        if ab.get("found"):
            print(f"  AbuseIPDB: {ab['abuse_confidence']}% | {ab.get('country')} | {ab.get('isp')}")

    print(f"\n  {'─'*46}")
    print(f"  URLs ({len(body_analysis['urls'])} found)")
    print(f"  {'─'*46}")
    if not body_analysis["urls"]:
        print("  No URLs extracted")
    for url in body_analysis["urls"]:
        original = url["original"]
        final = url.get("final", original)
        print(f"  {original[:70]}")
        if final != original:
            print(f"    → {final[:70]}")
        if url.get("error"):
            print(f"    ! error: {url['error']}")

    att_count = attachment_analysis["count"]
    print(f"\n  {'─'*46}")
    print(f"  ATTACHMENTS ({att_count})")
    print(f"  {'─'*46}")
    if att_count == 0:
        print("  No attachments")
    for att in attachment_analysis["attachments"]:
        print(f"  {att['filename']} ({att['size_bytes']} bytes)")
        print(f"  SHA256: {att['hashes']['sha256'][:48]}...")

    print(f"\n  {'─'*46}")
    print(f"  ANOMALIES")
    print(f"  {'─'*46}")
    if score_result["anomalies"]:
        for a in score_result["anomalies"]:
            sev_color = "\033[91m" if a["severity"] in ("critical", "high") else "\033[93m"
            print(f"  {sev_color}[{a['severity'].upper()}]{RESET} {a['type']}: {a['description']}")
    else:
        print(f"  \033[92m✓ No anomalies detected\033[0m")

    print(f"\n{'='*50}\n")


if __name__ == "__main__":
    main()
