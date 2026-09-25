from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session
from app.schemas import UrlScanRequest, UrlScanResponse, UrlScanDetails
from app.models import UrlScan
from app.services.url_rules import analyze_url_rules
from app.services.url_reputation import check_url_reputation
from app.services.url_ml import predict_url_phishing_probability

router = APIRouter(prefix="/analyze_url", tags=["URLs"])


@router.post("", response_model=UrlScanResponse)
async def analyze_url_endpoint(request: UrlScanRequest, session: Session = None):
    url = request.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    # Layer 1: Rule-based heuristics
    rule_score, rule_reasons, domain, domain_age, features = analyze_url_rules(url)

    # Layer 2: Reputation and blocklist lookup
    blocklist_hit, rep_reasons = await check_url_reputation(url, domain)

    # Layer 3: Machine Learning Model probability
    ml_prob = predict_url_phishing_probability(url, features, domain)

    # Score Fusion:
    # final_score = 0.4 * ml_probability + 0.3 * (rule_score / 100) + 0.3 * (1.0 if blocklist_hit else 0.0)
    rule_ratio = rule_score / 100.0
    blocklist_ratio = 1.0 if blocklist_hit else 0.0
    final_score = (0.4 * ml_prob) + (0.3 * rule_ratio) + (0.3 * blocklist_ratio)
    risk_score = int(round(final_score * 100))

    # Verdict assignment
    if risk_score >= 70:
        verdict = "likely_phishing"
    elif risk_score >= 40:
        verdict = "suspicious"
    else:
        verdict = "safe"

    # Assemble reasons
    all_reasons = []
    if blocklist_hit:
        all_reasons.extend(rep_reasons)
    if ml_prob >= 0.70:
        all_reasons.append(f"ML model predicts phishing (probability {ml_prob:.2f})")
    elif ml_prob >= 0.45:
        all_reasons.append(f"ML classifier flags suspicious lexical patterns (probability {ml_prob:.2f})")
    all_reasons.extend(rule_reasons)

    if not all_reasons and verdict == "safe":
        all_reasons.append("Standard domain syntax and trusted authority verification passed")

    details = UrlScanDetails(
        rule_score=rule_score,
        ml_probability=ml_prob,
        blocklist_hit=blocklist_hit,
        domain=domain,
        domain_age_days=domain_age,
    )

    # Persist to database if session is available
    if session is not None:
        try:
            db_record = UrlScan(
                url=url,
                risk_score=risk_score,
                verdict=verdict,
                reasons=all_reasons,
                details=details.dict(),
            )
            session.add(db_record)
            session.commit()
            session.refresh(db_record)
        except Exception:
            session.rollback()

    return UrlScanResponse(
        risk_score=risk_score,
        verdict=verdict,
        reasons=all_reasons,
        details=details,
    )
