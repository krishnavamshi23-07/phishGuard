import re
from typing import Tuple, List, Literal


def analyze_email_rules(subject: str, body: str) -> Tuple[Literal["low", "medium", "high"], int, List[str]]:
    """
    Evaluates phishing patterns in email subject and body content.
    Returns:
        (phishing_likelihood, score, patterns_found)
    """
    full_text = f"{subject or ''}\n{body or ''}".lower()
    patterns_found: List[str] = []
    score = 0

    # 1. Urgent or threatening language
    urgency_terms = [
        "immediate action", "suspended", "suspension", "24 hours", "48 hours",
        "account locked", "unauthorized transaction", "terminate", "penalty",
        "final notice", "action required", "failure to respond"
    ]
    matched_urgency = [term for term in urgency_terms if term in full_text]
    if len(matched_urgency) >= 2:
        score += 35
        patterns_found.append("Uses urgent or threatening language")
    elif len(matched_urgency) == 1:
        score += 20
        patterns_found.append(f"Contains urgent language cue: '{matched_urgency[0]}'")

    # 2. Requests credentials or sensitive info
    credential_terms = [
        "verify your password", "confirm your password", "enter your password",
        "social security", "ssn", "credit card", "cvv", "billing information",
        "bank account", "routing number", "seed phrase", "private key"
    ]
    matched_creds = [term for term in credential_terms if term in full_text]
    if len(matched_creds) >= 1:
        score += 40
        patterns_found.append("Requests credentials or sensitive info")

    # 3. Generic greetings
    generic_greetings = [
        "dear customer", "dear user", "dear account holder", "valued customer",
        "valued member", "dear client"
    ]
    if any(g in full_text for g in generic_greetings):
        score += 15
        patterns_found.append("Generic greeting")

    # 4. Link density check
    links = re.findall(r"https?://[^\s]+", full_text)
    if len(links) >= 3:
        score += 20
        patterns_found.append(f"Contains multiple links ({len(links)} URLs detected)")

    # 5. Wire transfer / gift card fraud
    financial_fraud = ["gift card", "wire transfer", "confidential request", "are you available right now"]
    if any(term in full_text for term in financial_fraud):
        score += 25
        patterns_found.append("Contains corporate wire transfer or gift card lure")

    final_score = min(100, max(0, score))

    if final_score >= 65:
        likelihood: Literal["low", "medium", "high"] = "high"
    elif final_score >= 35:
        likelihood = "medium"
    else:
        likelihood = "low"

    if not patterns_found:
        patterns_found.append("No obvious phishing indicators detected")

    return likelihood, final_score, patterns_found
