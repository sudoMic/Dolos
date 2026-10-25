import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pathlib import Path
from parser.eml_parser import parse_eml
from analyzers.header_analyzer import analyze_headers
from analyzers.body_analyzer import analyze_body
from analyzers.attachment_analyzer import analyze_attachments
from scoring.scorer import compute_score

CORPUS = Path(__file__).parent / "corpus"

EXPECTED = {
    # phishing
    "test_phishing.eml":   "MALICIOUS",
    "test_hard.eml":       "MALICIOUS",
    "test_homograph.eml":  "MALICIOUS",
    "test_subtle.eml":     "LIKELY_MALICIOUS",
    "test_pdf.eml":        "MALICIOUS",
    # benign
    "newsletter.eml":      "BENIGN",
}

# No API calls in tests: results must not depend on keys, quotas or network
NO_ENRICHMENT = {
    "ip_lookup": None,
    "attachment_hashes": [],
    "url_lookups": [],
    "anomalies": [],
}


def analyze(path: Path) -> dict:
    parsed = parse_eml(str(path))
    headers = analyze_headers(parsed["headers"])
    body = analyze_body(parsed["body"])
    attachments = analyze_attachments(parsed["attachments"])
    return compute_score(headers, body, attachments, NO_ENRICHMENT)


def run_tests():
    passed = 0
    failed = 0
    seen = set()

    for folder in ("phishing", "benign"):
        for eml_path in sorted((CORPUS / folder).glob("*.eml")):
            seen.add(eml_path.name)
            expected = EXPECTED.get(eml_path.name)
            if expected is None:
                print(f"[SKIP] {eml_path.name} — no expected verdict defined")
                continue

            result = analyze(eml_path)
            verdict = result["verdict"]
            ok = verdict == expected

            status = "PASS" if ok else "FAIL"
            print(f"[{status}] {eml_path.name:25s} expected={expected:18s} got={verdict} ({result['score']}/100)")

            if ok:
                passed += 1
            else:
                failed += 1
                for a in result["anomalies"]:
                    print(f"         {a['type']} +{a['score']}")

    # Files listed in EXPECTED but missing from the corpus count as failures
    for name in EXPECTED:
        if name not in seen:
            print(f"[FAIL] {name} — listed in EXPECTED but not found in corpus")
            failed += 1

    print(f"\n{passed} passed, {failed} failed")
    return failed


def test_verdicts():
    assert run_tests() == 0


if __name__ == "__main__":
    sys.exit(run_tests())
