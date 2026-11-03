"""PDF-отчёт по анализу: собирается по запросу из данных БД, на диск не сохраняется."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.api.v1.analyses import get_analysis
from app.db.session import get_db
from app.services.pdf_report import build_report, report_filename

router = APIRouter(prefix="/analyses", tags=["Отчёты"])


@router.get("/{analysis_id}/report.pdf", response_class=Response,
            responses={200: {"content": {"application/pdf": {}}}, 409: {"description": "анализ ещё не завершён"}})
def report_pdf(analysis_id: int, db: Session = Depends(get_db)) -> Response:
    a = get_analysis(db, analysis_id)
    if a.status != "done":
        raise HTTPException(409, f"Отчёт строится только для завершённого анализа (сейчас: {a.status})")
    return Response(build_report(a), media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{report_filename(a)}"'})
