import requests
import hashlib
import base64
import os
from dotenv import load_dotenv

load_dotenv()

# Timeout for all requests
TIMEOUT = 10

# API key
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY  = os.getenv("ABUSEIPDB_API_KEY", "")

HEADERS_VT = {
    "x-apikey": VIRUSTOTAL_API_KEY,
}


def lookup_hash(sha256: str) -> dict:
    """
    Look up a SHA256 hash on VirusTotal.
    Returns the number of engines flagging it as malicious.
    """
    try:
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        response = requests.get(url, headers=HEADERS_VT, timeout=TIMEOUT)

        if response.status_code == 404:
            return {"found": False, "malicious": 0, "total": 0}

        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return {
                "found": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "total": sum(stats.values()),
            }

        return {"found": False, "error": f"HTTP {response.status_code}"}

    except Exception as e:
        return {"found": False, "error": str(e)}


def lookup_url(url: str) -> dict:
    """
    Look up a URL on VirusTotal.
    VT requires the URL encoded as base64 URL-safe without padding.
    """
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        response = requests.get(endpoint, headers=HEADERS_VT, timeout=TIMEOUT)

        if response.status_code == 404:
            return _submit_url_to_vt(url)

        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return {
                "found": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "total": sum(stats.values()),
            }

        return {"found": False, "error": f"HTTP {response.status_code}"}

    except Exception as e:
        return {"found": False, "error": str(e)}


def _submit_url_to_vt(url: str) -> dict:
    """
    Submit a URL to VirusTotal for first-time scanning.
    Returns pending — analysis takes time.
    """
    try:
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=HEADERS_VT,
            data={"url": url},
            timeout=TIMEOUT,
        )
        if response.status_code == 200:
            return {"found": False, "status": "submitted_for_analysis"}
        return {"found": False, "status": "submission_failed"}
    except Exception as e:
        return {"found": False, "error": str(e)}


def lookup_ip(ip: str) -> dict:
    """
    Check an IP address on AbuseIPDB.
    Returns abuse confidence score and country.
    """
    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json",
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90,
            },
            timeout=TIMEOUT,
        )

        if response.status_code == 200:
            data = response.json()["data"]
            return {
                "found": True,
                "abuse_confidence": data.get("abuseConfidenceScore", 0),
                "country": data.get("countryCode", ""),
                "total_reports": data.get("totalReports", 0),
                "isp": data.get("isp", ""),
                "is_public": data.get("isPublic", True),
            }

        return {"found": False, "error": f"HTTP {response.status_code}"}

    except Exception as e:
        return {"found": False, "error": str(e)}


def lookup_ip_urlhaus(ip: str) -> dict:
    """
    Check an IP address on URLhaus (abuse.ch).
    """
    try:
        response = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": ip},
            timeout=TIMEOUT,
        )

        if response.status_code == 200:
            data = response.json()
            if data.get("query_status") == "no_results":
                return {"found": False}
            return {
                "found": True,
                "urls_count": len(data.get("urls", [])),
                "blacklists": data.get("blacklists", {}),
            }

        return {"found": False, "error": f"HTTP {response.status_code}"}

    except Exception as e:
        return {"found": False, "error": str(e)}


def enrich_email(header_analysis: dict, body_analysis: dict, attachment_analysis: dict) -> dict:
    """
    Main enrichment function.
    Takes analyzer results and adds context from external sources.
    """
    enrichment = {
        "ip_lookup": None,
        "attachment_hashes": [],
        "url_lookups": [],
        "anomalies": [],
    }

    # Sender IP lookup from Received chain
    sender_ip = _extract_sender_ip(header_analysis)
    if sender_ip:
        abuseipdb = lookup_ip(sender_ip)
        urlhaus   = lookup_ip_urlhaus(sender_ip)
        enrichment["ip_lookup"] = {
            "ip": sender_ip,
            "abuseipdb": abuseipdb,
            "urlhaus": urlhaus,
        }

        if abuseipdb.get("abuse_confidence", 0) > 25:
            enrichment["anomalies"].append({
                "type": "MALICIOUS_IP",
                "description": f"IP {sender_ip} with abuse score {abuseipdb['abuse_confidence']}% ({abuseipdb.get('country', '')})",
                "severity": "high",
                "score": 30,
            })

        if urlhaus.get("found"):
            enrichment["anomalies"].append({
                "type": "IP_ON_URLHAUS",
                "description": f"IP {sender_ip} found on URLhaus with {urlhaus.get('urls_count', 0)} malicious URL",
                "severity": "critical",
                "score": 50,
            })

    # Attachment hash lookup on VirusTotal
    for att in attachment_analysis.get("attachments", []):
        sha256 = att["hashes"]["sha256"]
        vt_result = lookup_hash(sha256)
        entry = {
            "filename": att["filename"],
            "sha256": sha256,
            "virustotal": vt_result,
        }
        enrichment["attachment_hashes"].append(entry)

        if vt_result.get("malicious", 0) > 0:
            enrichment["anomalies"].append({
                "type": "MALICIOUS_HASH",
                "description": f"Attachment '{att['filename']}' flagged by {vt_result['malicious']}/{vt_result['total']} VT engines",
                "severity": "critical",
                "score": 60,
            })

    # Final URL lookup on VirusTotal (skip image/asset URLs)
    for url_data in body_analysis.get("urls", []):
        final_url = url_data.get("final", url_data.get("original", ""))
        if _is_resource_url(final_url):
            continue
        vt_result = lookup_url(final_url)
        entry = {
            "url": final_url,
            "virustotal": vt_result,
        }
        enrichment["url_lookups"].append(entry)

        if vt_result.get("malicious", 0) > 0:
            enrichment["anomalies"].append({
                "type": "MALICIOUS_URL",
                "description": f"URL flagged by {vt_result['malicious']}/{vt_result['total']} VT engines: {final_url[:80]}",
                "severity": "critical",
                "score": 60,
            })
            
        # Unreachable domain — suspicious signal
        if vt_result.get("error") and "connection" in vt_result["error"].lower():
            enrichment["anomalies"].append({
                "type": "UNREACHABLE_URL",
                "description": f"Unreachable URL (connection error): {final_url[:80]}",
                "severity": "medium",
                "score": 15,
            })

    return enrichment


def _extract_sender_ip(header_analysis: dict) -> str:
    """
    Extract the IP of the first external server from the Received chain.
    """
    chain = header_analysis.get("received_chain", [])
    for hop in chain:
        ip = hop.get("ip", "")
        if ip and not _is_private_ip(ip):
            return ip
    return ""
    
def _is_private_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False

    return (
        a == 10 or
        a == 127 or
        (a == 172 and 16 <= b <= 31) or
        (a == 192 and b == 168) or
        (a == 169 and b == 254)  # link-local
    )


def _is_resource_url(url: str) -> bool:
    """
    Exclude image and static asset URLs from VT lookup
    to avoid wasting API quota.
    """
    extensions = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".css", ".woff")
    return any(url.lower().endswith(ext) for ext in extensions)
