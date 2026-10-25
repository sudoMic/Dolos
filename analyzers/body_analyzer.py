import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from analyzers.header_analyzer import _check_typosquatting
from urllib.parse import urlparse, parse_qs

# Request timeout for HTTP calls
REQUEST_TIMEOUT = 10

# Neutral user agent
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}

# Known URL shorteners
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "short.link", "rebrand.ly", "cutt.ly", "is.gd", "buff.ly",
]

# Phishing keywords with weight scores
PHISHING_KEYWORDS = {
    # Urgency
    "urgente": 10, "urgent": 10, "immediatamente": 10, "immediately": 10,
    "entro 24 ore": 15, "within 24 hours": 15, "scaduto": 10, "expired": 10,
    "sospeso": 10, "suspended": 10, "bloccato": 10, "blocked": 10,
    # Credentials
    "verifica le tue credenziali": 20, "verify your credentials": 20,
    "conferma la tua password": 20, "confirm your password": 20,
    "aggiorna i tuoi dati": 15, "update your information": 15,
    "accedi al tuo account": 10, "sign in to your account": 10,
    # Threats
    "il tuo account sarà chiuso": 20, "your account will be closed": 20,
    "attività sospetta": 15, "suspicious activity": 15,
    "accesso non autorizzato": 15, "unauthorized access": 15,
    # Prizes / offers
    "hai vinto": 15, "you have won": 15,
    "clicca qui": 5, "click here": 5,
    # Sextortion / extortion
    "bitcoin wallet": 25, "btc": 10,
    "transfer me": 20, "send me": 10,
    "recorded you": 25, "your webcam": 25,
    "masturbat": 25, "porn": 15,
    "i have access to": 20, "remote access trojan": 30,
    "do not contact police": 25, "do not try to find": 20,
    "cryptocurrency": 10, "i hacked": 25, "i gained access": 20,
}

def analyze_body(body: dict) -> dict:
    """
    Analyze the email body and return extracted URLs,
    redirect results and keyword score.
    """
    text = body.get("text", "")
    html = body.get("html", "")

    urls = _extract_urls(text, html)
    resolved_urls = _resolve_urls(urls)
    keyword_results = _keyword_scoring(text + " " + html)

    anomalies = _collect_anomalies(resolved_urls, keyword_results)

    return {
        "urls": resolved_urls,
        "keyword_scoring": keyword_results,
        "anomalies": anomalies,
    }


def _extract_urls(text: str, html: str) -> list:
    """
    Extract URLs from plain text and HTML.
    Uses regex for plain text, BeautifulSoup for HTML
    to also catch URLs hidden in tags.
    """
    urls = set()

    # Regex for URLs in plain text
    url_pattern = re.compile(
        r'https?://[^\s<>"\'{}|\\^`\[\]]+'
    )
    urls.update(url_pattern.findall(text))

    # BeautifulSoup for HTML
    if html:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all(["a", "img", "form", "iframe", "script"]):
            for attr in ["href", "src", "action"]:
                val = tag.get(attr, "")
                if val.startswith("http"):
                    urls.add(val)
    
    # Extract URLs embedded in query parameters
    extra = []
    for url in list(urls):
        extra.extend(_extract_urls_from_params(url))
    urls.update(extra)

    return list(urls)


def _resolve_urls(urls: list) -> list:
    """
    Follow redirects for each URL and return the final destination.
    Detects and flags URL shorteners.
    """
    resolved = []

    for url in urls:
        domain = _extract_domain(url)
        is_shortener = domain in URL_SHORTENERS

        entry = {
            "original": url,
            "final": url,
            "domain": domain,
            "is_shortener": is_shortener,
            "redirect_chain": [],
            "error": None,
        }

        try:
            response = requests.get(
                url,
                headers=HEADERS,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
                stream=True,  # don't download the body
            )
            # Redirect chain
            chain = [r.url for r in response.history]
            entry["redirect_chain"] = chain
            entry["final"] = response.url
            entry["final_domain"] = _extract_domain(response.url)

        except requests.exceptions.Timeout:
            entry["error"] = "timeout"
        except requests.exceptions.ConnectionError:
            entry["error"] = "connection_error"
        except Exception as e:
            entry["error"] = str(e)

        resolved.append(entry)

    return resolved


def _extract_domain(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


def _keyword_scoring(text: str) -> dict:
    """
    Search for phishing keywords in text and compute a score.
    """
    text_lower = text.lower()
    found = []
    total_score = 0

    for keyword, score in PHISHING_KEYWORDS.items():
        if keyword in text_lower:
            found.append({
                "keyword": keyword,
                "score": score,
            })
            total_score += score

    return {
        "found": found,
        "total_score": total_score,
    }
    
def _extract_urls_from_params(url: str) -> list:
    """
    Extract URLs embedded in query parameters (e.g. ?url=http://..., ?redirect=http://...)
    """
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        embedded = []
        for key, values in params.items():
            if key.lower() in ("url", "redirect", "next", "goto", "return", "returnurl", "dest"):
                for v in values:
                    if v.startswith("http"):
                        embedded.append(v)
        return embedded
    except Exception:
        return []


def _collect_anomalies(resolved_urls: list, keyword_results: dict) -> list:
    """
    Build anomaly list from suspicious URLs and phishing keywords.
    """
    anomalies = []

    # URLs that could not be reached during resolution
    unreachable = set(u["original"] for u in resolved_urls if u.get("error") == "connection_error")

    for url_data in resolved_urls:
        # Skip redirect if original domain is already known/trusted
        original_domain = url_data.get("domain", "")
        
        if url_data["is_shortener"]:
            anomalies.append({
                "type": "URL_SHORTENER",
                "description": f"URL shortener detected: {url_data['original']} → {url_data['final']}",
                "severity": "medium",
                "score": 15,
            })

        elif url_data.get("redirect_chain") and len(url_data["redirect_chain"]) > 2:
            # Flag only long redirect chains (>2 hops) on non-obvious domains
            anomalies.append({
                "type": "URL_REDIRECT",
                "description": f"Redirect chain ({len(url_data['redirect_chain'])} hop): {url_data['original']} → {url_data['final']}",
                "severity": "low",
                "score": 5,
            })
            
        # Suspicious domain structure
        if original_domain and _is_suspicious_domain(original_domain):
            anomalies.append({
                "type": "SUSPICIOUS_DOMAIN",
                "description": f"Suspicious domain pattern: {original_domain}",
                "severity": "high",
                "score": 10,
            })
            
        # Unreachable URL (connection error during resolution)
        if url_data["original"] in unreachable:
            embedded = _extract_urls_from_params(url_data["original"])
            # wrapper link: skip if its destination is already flagged
            if not any(e in unreachable for e in embedded):
                anomalies.append({
                    "type": "UNREACHABLE_URL",
                    "description": f"Unreachable URL (connection error): {url_data['original'][:80]}",
                    "severity": "medium",
                    "score": 15,
                })
        
        # Homograph / typosquatting check on URL domain
        final_domain = url_data.get("final_domain") or original_domain
        for check_domain in set([original_domain, final_domain]):
            if not check_domain:
                continue
            squatting = _check_typosquatting(check_domain)
            if squatting:
                best = squatting[0]
                is_homograph = best.get("homograph", False)
                anomalies.append({
                    "type": "URL_HOMOGRAPH" if is_homograph else "URL_TYPOSQUATTING",
                    "description": f"URL domain '{check_domain}' {'homograph attack' if is_homograph else 'similar'} to '{best['brand']}' (distance: {best['distance']})",
                    "severity": "critical" if is_homograph else "high",
                    "score": 40 if is_homograph else 20,
                })
                break   

    if keyword_results["total_score"] > 0:
        anomalies.append({
            "type": "PHISHING_KEYWORDS",
            "description": f"Phishing keywords found: {[k['keyword'] for k in keyword_results['found']]}",
            "severity": "medium",
            "score": keyword_results["total_score"],
        })

    return anomalies
    
    
def _is_suspicious_domain(domain: str) -> bool:
    """
    Detect domains built to look legitimate but containing suspicious patterns.
    """
    # Numbers mixed with brand-like words
    suspicious_patterns = [
        r'\d+[a-z]+\d+',           # numbers-letters-numbers: blog1seguiment2
        r'[a-z]+-[a-z]+-[a-z]+-',  # too many hyphenated segments
        r'(secure|login|account|verify|update|banking|bank|pagamento|atendimento)[0-9]',
    ]
    for pattern in suspicious_patterns:
        if re.search(pattern, domain, re.IGNORECASE):
            return True
    # Unusual TLDs combined with brand-like words
    suspicious_tlds = [".me", ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click"]
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            return True
    return False
    
    
    
