import re
from Levenshtein import distance as levenshtein_distance

HOMOGLYPH_MAP = str.maketrans({
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
    'у': 'y', 'х': 'x', 'і': 'i', 'ѕ': 's', 'ԁ': 'd',
})

def _normalize_homoglyphs(s: str) -> str:
    return s.translate(HOMOGLYPH_MAP)

# Legitimate domains excluded from typosquatting check
WHITELIST_DOMAINS = [
    "chess.com", "sendgrid.com", "sendgrid.net", "mailchimp.com",
    "amazonses.com", "outlook.com", "gmail.com", "yahoo.com",
    "hotmail.com", "protonmail.com", "example.com"
]

# Common brands to compare for typosquatting
KNOWN_BRANDS = [
    "paypal.com", "amazon.com", "google.com", "microsoft.com",
    "apple.com", "netflix.com", "instagram.com", "facebook.com",
    "linkedin.com", "twitter.com", "x.com", "bankofamerica.com",
    "chase.com", "wellsfargo.com", "ebay.com", "dropbox.com",
    "spotify.com", "adobe.com", "dhl.com", "fedex.com",
    "poste.it", "unicredit.it", "intesasanpaolo.com", "fineco.it",
]

# Maximum Levenshtein distance to flag a domain as suspicious
TYPOSQUATTING_THRESHOLD = 3


def _max_distance(base: str) -> int:
    # Short names need a stricter limit, otherwise unrelated domains
    # match (ups.com / ibm.com -> x.com, aol.com -> dhl.com)
    if len(base) <= 3:
        return 0
    if len(base) <= 5:
        return 1
    if len(base) <= 8:
        return 2
    return TYPOSQUATTING_THRESHOLD


def analyze_headers(headers: dict) -> dict:
    """
    Analyze headers extracted by the parser and return
    structured results and anomalies.
    """
    results = {
        "authentication": _parse_authentication(headers),
        "sender": _analyze_sender(headers),
        "received_chain": _analyze_received_chain(headers),
        "anomalies": [],
    }

    # Collect all anomalies found
    results["anomalies"] = _collect_anomalies(results)

    return results


def _parse_authentication(headers: dict) -> dict:
    """
    Extract SPF, DKIM, DMARC results from the
    Authentication-Results header string.
    """
    auth_str = headers.get("authentication_results", "")
    received_spf = headers.get("received_spf", "")

    auth = {
        "spf": _extract_auth_result(auth_str, "spf") or _extract_spf_from_received(received_spf),
        "dkim": _extract_auth_result(auth_str, "dkim"),
        "dmarc": _extract_auth_result(auth_str, "dmarc"),
    }

    return auth


def _extract_auth_result(auth_str: str, protocol: str) -> str:
    """
    Extract the result (pass/fail/none/...) of a protocol
    from the Authentication-Results header string.
    """
    pattern = rf"{protocol}=(\w+)"
    match = re.search(pattern, auth_str, re.IGNORECASE)
    return match.group(1).lower() if match else "none"


def _extract_spf_from_received(received_spf: str) -> str:
    """
    Fallback: extract SPF from the Received-SPF header if not
    present in Authentication-Results.
    """
    match = re.match(r"(\w+)", received_spf.strip(), re.IGNORECASE)
    return match.group(1).lower() if match else "none"


def _analyze_sender(headers: dict) -> dict:
    """
    Analyze the sender: split display name and address,
    compare with Reply-To and Return-Path, detect typosquatting.
    """
    from_raw = headers.get("from", "")
    reply_to = headers.get("reply_to", "")
    return_path = headers.get("return_path", "")

    display_name, from_address = _parse_address(from_raw)
    from_domain = _extract_domain(from_address)

    _, reply_to_address = _parse_address(reply_to)
    reply_to_domain = _extract_domain(reply_to_address)

    return_path_domain = _extract_domain(return_path)

    typosquatting = _check_typosquatting(from_domain)

    return {
        "display_name": display_name,
        "from_address": from_address,
        "from_domain": from_domain,
        "reply_to_address": reply_to_address,
        "reply_to_domain": reply_to_domain,
        "return_path_domain": return_path_domain,
        "reply_to_mismatch": reply_to_domain != from_domain and reply_to_domain != "",
        "typosquatting": typosquatting,
    }


def _parse_address(raw: str) -> tuple:
    """
    Split display name and email address from a string like
    '"Name" <email@domain.com>' or 'email@domain.com'.
    """
    match = re.match(r'"?([^"<]*)"?\s*<([^>]+)>', raw.strip())
    if match:
        return match.group(1).strip(), match.group(2).strip()
    # No display name, address only
    return "", raw.strip()


def _extract_domain(address: str) -> str:
    """
    Extract the domain from an email address or string containing @.
    """
    match = re.search(r"@([\w.\-]+)", address)
    return match.group(1).lower() if match else ""


# Suffixes to strip before comparison
STRIP_SUFFIXES = ["-secure", "-login", "-verify", "-support", "-official",
                  "-account", "-update", "-service", "-online", "-web",
                  "-notifications", "-alert", "-confirm", "-help", "-center"]

def _check_typosquatting(domain: str) -> list:
    if not domain:
        return []

    if domain in WHITELIST_DOMAINS:
        return []

    # Extract base domain without TLD for more robust comparison
    # e.g. "paypa1.com" → "paypa1", "paypal.com" → "paypal"
    domain_base = domain.rsplit(".", 1)[0] if "." in domain else domain
    
    # Normalize homoglyphs before stripping suffixes
    normalized = _normalize_homoglyphs(domain_base)
    # Strip deceptive suffixes (multiple passes)
    for suffix in STRIP_SUFFIXES:
        while normalized.endswith(suffix):
            normalized = normalized[: -len(suffix)]
            
    suspicious = []
    
    for brand in KNOWN_BRANDS:
        if domain == brand:
            return []  # Domain identical to brand — not typosquatting

        brand_base = brand.rsplit(".", 1)[0]
        
        if normalized == brand_base and domain_base != brand_base:
            suspicious.append({
                "brand": brand,
                "distance": 0,
                "homograph": True,
            })
            return suspicious
        
        dist = levenshtein_distance(normalized, brand_base)
        if 0 < dist <= _max_distance(brand_base):
            suspicious.append({
                "brand": brand,
                "distance": dist,
            })

    # Sort by distance ascending (most similar first)
    suspicious.sort(key=lambda x: x["distance"])
    return suspicious


def _analyze_received_chain(headers: dict) -> list:
    """
    Analyze the Received chain to reconstruct the email path
    and detect timing anomalies.
    """
    received_list = headers.get("received", [])
    chain = []

    for hop in received_list:
        hop_data = {
            "raw": hop,
            "from_host": _extract_received_from(hop),
            "by_host": _extract_received_by(hop),
            "timestamp": _extract_received_timestamp(hop),
            "ip": _extract_ip(hop),
        }
        chain.append(hop_data)

    return chain


def _extract_received_from(hop: str) -> str:
    match = re.search(r"from\s+([\w.\-\[\]]+)", hop, re.IGNORECASE)
    return match.group(1) if match else ""


def _extract_received_by(hop: str) -> str:
    match = re.search(r"by\s+([\w.\-]+)", hop, re.IGNORECASE)
    return match.group(1) if match else ""


def _extract_received_timestamp(hop: str) -> str:
    # Standard format: "Thu, 26 Mar 2026 05:08:47 +0000"
    match = re.search(
        r"(\w{3},\s+\d{1,2}\s+\w{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+[+-]\d{4})",
        hop
    )
    return match.group(1) if match else ""


def _extract_ip(hop: str) -> str:
    match = re.search(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]", hop)
    return match.group(1) if match else ""


def _collect_anomalies(results: dict) -> list:
    """
    Collect all anomalies found across sub-modules and return
    them as a structured list with severity and score.
    """
    anomalies = []
    auth = results["authentication"]
    sender = results["sender"]

    # Authentication
    if auth["spf"] not in ("pass", "none"):
        anomalies.append({
            "type": "SPF_FAIL",
            "description": f"SPF result: {auth['spf']}",
            "severity": "high",
            "score": 15,
        })

    if auth["dkim"] not in ("pass", "none"):
        anomalies.append({
            "type": "DKIM_FAIL",
            "description": f"DKIM result: {auth['dkim']}",
            "severity": "high",
            "score": 20,
        })

    if auth["dmarc"] not in ("pass", "none"):
        anomalies.append({
            "type": "DMARC_FAIL",
            "description": f"DMARC result: {auth['dmarc']}",
            "severity": "critical",
            "score": 25,
        })

    # Sender
    if sender["reply_to_mismatch"]:
        reply_domain = sender["reply_to_domain"]
        from_domain = sender["from_domain"]

        reply_base = reply_domain.rsplit(".", 1)[0] if "." in reply_domain else reply_domain
        from_base = from_domain.rsplit(".", 1)[0] if "." in from_domain else from_domain
        is_lookalike = levenshtein_distance(reply_base, from_base) <= _max_distance(from_base)

        if is_lookalike:
            anomalies.append({
                "type": "REPLY_TO_LOOKALIKE",
                "description": f"Reply-To ({reply_domain}) is a lookalike of sender domain ({from_domain})",
                "severity": "critical",
                "score": 40,
            })
        else:
            anomalies.append({
                "type": "REPLY_TO_MISMATCH",
                "description": f"Reply-To ({reply_domain}) differs from sender domain ({from_domain})",
                "severity": "medium",
                "score": 20,
            })

    if sender["typosquatting"]:
        best = sender["typosquatting"][0]
        is_homograph = best.get("homograph", False)
        anomalies.append({
            "type": "HOMOGRAPH_ATTACK" if is_homograph else "TYPOSQUATTING",
            "description": f"Domain '{sender['from_domain']}' {'homograph attack' if is_homograph else 'similar'} to '{best['brand']}' (distance: {best['distance']})",
            "severity": "critical" if is_homograph else "high",
            "score": 40 if is_homograph else 25,
        })

    return anomalies
