from fastapi import APIRouter, HTTPException
from sqlmodel import Session
from app.schemas import ReportRequest, ReportResponse
from app.models import Report

router = APIRouter(prefix="/report", tags=["Reports"])


@router.post("", response_model=ReportResponse)
def create_report_endpoint(request: ReportRequest, session: Session = None):
    content = request.content.strip()
    if not content:
        raise HTTPException(status_code=400, detail="Report content cannot be empty.")

    if session is not None:
        try:
            report_record = Report(
                type=request.type,
                content=content,
                notes=request.notes.strip() if request.notes else None,
            )
            session.add(report_record)
            session.commit()
            session.refresh(report_record)
        except Exception:
            session.rollback()

    return ReportResponse(success=True)
