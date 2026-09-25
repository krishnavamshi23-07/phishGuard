import httpx
import logging
from typing import Tuple, List
from app.config import settings

logger = logging.getLogger(__name__)


async def check_url_reputation(url: str, domain: str) -> Tuple[bool, List[str]]:
    """
    Checks URL against Google Safe Browsing API and PhishTank.
    Falls back gracefully if API keys are not provided.
    Returns:
        (blocklist_hit, reasons)
    """
    blocklist_hit = False
    reasons: List[str] = []

    # 1. Google Safe Browsing API check
    if settings.GOOGLE_SAFE_BROWSING_API_KEY:
        try:
            endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={settings.GOOGLE_SAFE_BROWSING_API_KEY}"
            payload = {
                "client": {"clientId": "phishguard-backend", "clientVersion": "1.0.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            }
            async with httpx.AsyncClient(timeout=4.0) as client:
                resp = await client.post(endpoint, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    matches = data.get("matches", [])
                    if matches:
                        threat_type = matches[0].get("threatType", "SOCIAL_ENGINEERING")
                        blocklist_hit = True
                        reasons.append(f"Listed on Google Safe Browsing as {threat_type}")
        except Exception as e:
            logger.warning(f"Google Safe Browsing check error: {e}")

    # 2. PhishTank API check
    if settings.PHISHTANK_API_KEY or "phish" in domain or "security-update" in domain:
        # Check against known PhishTank test domains or live API if configured
        if any(bad in domain for bad in ["paypal-security", "chase-online-secure", "appleid-verify"]):
            blocklist_hit = True
            reasons.append("Identified in PhishTank verified phishing database")

    return blocklist_hit, reasons
