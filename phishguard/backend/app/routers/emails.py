from fastapi import APIRouter, HTTPException
from sqlmodel import Session
from app.schemas import EmailScanRequest, EmailScanResponse
from app.models import EmailScan
from app.services.email_rules import analyze_email_rules

router = APIRouter(prefix="/analyze_email", tags=["Emails"])


@router.post("", response_model=EmailScanResponse)
def analyze_email_endpoint(request: EmailScanRequest, session: Session = None):
    subject = request.subject or ""
    body = request.body.strip() if request.body else ""

    if not subject and not body:
        raise HTTPException(status_code=400, detail="Either email subject or body must be provided.")

    likelihood, score, patterns = analyze_email_rules(subject, body)

    # Save to EmailScan table if session available
    if session is not None:
        try:
            preview = body[:200] + ("..." if len(body) > 200 else "")
            db_record = EmailScan(
                subject=subject,
                body_preview=preview,
                phishing_likelihood=likelihood,
                score=score,
                patterns_found=patterns,
            )
            session.add(db_record)
            session.commit()
            session.refresh(db_record)
        except Exception:
            session.rollback()

    return EmailScanResponse(
        phishing_likelihood=likelihood,
        score=score,
        patterns_found=patterns,
    )
