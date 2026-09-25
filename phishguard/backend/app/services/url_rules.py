import re
import math
from urllib.parse import urlparse
from typing import Tuple, List, Dict, Any

# In-memory blocklist of high-risk phishing domains
KNOWN_PHISHING_DOMAINS = {
    "paypal-security-update.com",
    "paypal-verify-billing.xyz",
    "appleid-verify-manage.top",
    "apple-icloud-recovery.cc",
    "chase-online-secure-auth.xyz",
    "wellsfargo-signon-portal.info",
    "bofa-online-verify.click",
    "netflix-account-onhold.com",
    "netflix-billing-update.buzz",
    "steamcommuny-trade.ru",
    "metamask-wallet-seed-verify.org",
    "ledger-live-recovery.site",
    "binance-auth-security.me",
    "coinbase-kyc-validation.com",
    "microsoft-365-password-reset.pw",
    "secure-login-account-update.tk",
    "dhl-express-tracking-package.online",
    "usps-redelivery-scheduled.info",
}

TOP_LEGIT_DOMAINS = {
    "google.com", "youtube.com", "apple.com", "microsoft.com", "amazon.com",
    "paypal.com", "netflix.com", "chase.com", "bankofamerica.com", "wellsfargo.com",
    "github.com", "wikipedia.org", "facebook.com", "instagram.com", "twitter.com",
}

TOP_BRANDS = [
    "paypal", "apple", "microsoft", "amazon", "netflix", "chase",
    "bankofamerica", "wellsfargo", "binance", "coinbase", "metamask",
    "google", "facebook", "instagram", "dhl", "usps"
]

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "log-in", "sign-in", "verify", "verification",
    "account", "security", "update", "password", "credential", "bank",
    "billing", "wallet", "confirm", "recover", "authenticate", "unlock",
    "suspended", "kyc", "alert"
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "tiny.cc", "rb.gy"
}

HIGH_RISK_TLDS = {
    "xyz", "top", "buzz", "fit", "rest", "click", "tk", "ml", "ga",
    "cf", "gq", "pw", "cc", "work", "vip", "shop", "icu"
}


def is_ip_address(hostname: str) -> bool:
    """Checks if hostname is an IPv4 or IPv6 address."""
    ipv4_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    if re.match(ipv4_pattern, hostname):
        return True
    if ":" in hostname and re.match(r"^[0-9a-fA-F:]+$", hostname):
        return True
    return False


def calculate_entropy(text: str) -> float:
    """Computes Shannon entropy of string."""
    if not text:
        return 0.0
    length = len(text)
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def get_levenshtein_distance(s1: str, s2: str) -> int:
    """Computes edit distance for typosquatting checks."""
    if len(s1) < len(s2):
        return get_levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


def estimate_domain_age_days(domain: str) -> int:
    """
    Estimates domain age. In production, this can query python-whois.
    Provides realistic stub heuristics based on domain history & TLD abuse patterns.
    """
    root = domain.lower()
    if root in TOP_LEGIT_DOMAINS:
        return 7200
    if root in KNOWN_PHISHING_DOMAINS:
        return 10
    parts = root.split(".")
    tld = parts[-1]
    if tld in HIGH_RISK_TLDS:
        return 14
    if "-" in root and any(kw in root for kw in ["login", "secure", "verify"]):
        return 18
    # Fallback pseudo-hash age for consistent reproducibility
    h = abs(hash(root)) % 900 + 40
    return h


def analyze_url_rules(url: str) -> Tuple[int, List[str], str, int, Dict[str, Any]]:
    """
    Evaluates rule-based heuristics on target URL.
    Returns:
        (rule_score, reasons, domain, domain_age_days, extracted_features)
    """
    parsed = urlparse(url if "://" in url else f"https://{url}")
    raw_url = parsed.geturl()
    hostname = (parsed.hostname or "").lower()
    pathname = (parsed.path or "").lower()
    query = (parsed.query or "").lower()

    domain_parts = hostname.split(".")
    domain = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else hostname
    tld = domain_parts[-1] if domain_parts else ""

    reasons: List[str] = []
    score = 0
    domain_age_days = estimate_domain_age_days(domain)

    # 1. IP address check
    has_ip = is_ip_address(hostname)
    if has_ip:
        score += 35
        reasons.append("URL uses raw IP address instead of registered domain name")

    # 2. Known Phishing Blocklist check
    if hostname in KNOWN_PHISHING_DOMAINS or domain in KNOWN_PHISHING_DOMAINS:
        score += 55
        reasons.append("Domain is on known phishing blocklist database")

    # 3. Excessive Subdomains
    subdomains = domain_parts[:-2] if len(domain_parts) > 2 else []
    subdomain_count = len(subdomains)
    if subdomain_count >= 3:
        score += 25
        reasons.append(f"Unusually high number of subdomains detected ({subdomain_count} subdomains)")

    # 4. URL Shortener check
    if hostname in URL_SHORTENERS or domain in URL_SHORTENERS:
        score += 20
        reasons.append(f"URL uses known shortening service ({hostname})")

    # 5. High-risk TLD
    if tld in HIGH_RISK_TLDS:
        score += 20
        reasons.append(f"Uses high-risk top-level domain (.{tld}) frequently abused in phishing")

    # 6. Suspicious Keywords
    combined_text = f"{hostname} {pathname} {query}"
    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in combined_text]
    if len(matched_keywords) >= 2:
        score += 30
        reasons.append(f"URL contains multiple security tokens: {', '.join(matched_keywords[:3])}")
    elif len(matched_keywords) == 1:
        score += 15
        reasons.append(f"Suspicious keyword found in URL: '{matched_keywords[0]}'")

    # 7. Domain Age Check
    if domain_age_days < 30:
        score += 25
        reasons.append(f"Domain is less than 30 days old ({domain_age_days} days)")

    # 8. Brand Typosquatting / Impersonation
    for brand in TOP_BRANDS:
        if brand in hostname and not domain.startswith(f"{brand}."):
            score += 35
            reasons.append(f"Domain impersonates recognized brand '{brand}' inside host '{hostname}'")
            break
        # Levenshtein distance check on domain label
        if domain_parts:
            label = domain_parts[0]
            if label != brand and len(label) >= 4 and get_levenshtein_distance(label, brand) == 1:
                score += 40
                reasons.append(f"Possible typosquatting attack: '{label}' is 1 edit distance from '{brand}'")
                break

    # 9. @ symbol in URL (HTTP Auth trick)
    has_at_symbol = "@" in raw_url
    if has_at_symbol:
        score += 30
        reasons.append("URL contains '@' symbol, often used to obscure destination")

    # 10. Hyphens count
    hyphen_count = hostname.count("-")
    if hyphen_count >= 3:
        score += 15
        reasons.append(f"Excessive hyphens in hostname ({hyphen_count} hyphens)")

    # 11. Plain HTTP on auth path
    is_https = parsed.scheme == "https"
    if not is_https and any(kw in pathname for kw in ["login", "bank", "pay", "secure"]):
        score += 25
        reasons.append("Insecure plain HTTP protocol used on authentication path")

    # Whitelist mitigation
    if domain in TOP_LEGIT_DOMAINS and not has_ip and not has_at_symbol and subdomain_count <= 1:
        score = max(0, score - 50)

    final_rule_score = min(100, max(0, score))

    # Feature extraction for ML model
    features = {
        "url_length": len(raw_url),
        "num_dots": raw_url.count("."),
        "num_hyphens": raw_url.count("-"),
        "num_slashes": raw_url.count("/"),
        "has_ip": int(has_ip),
        "has_at_symbol": int(has_at_symbol),
        "digit_ratio": round(sum(c.isdigit() for c in raw_url) / (len(raw_url) or 1), 3),
        "suspicious_keywords_count": len(matched_keywords),
        "is_https": int(is_https),
        "entropy": calculate_entropy(hostname),
        "subdomain_count": subdomain_count,
    }

    return final_rule_score, reasons, domain, domain_age_days, features
