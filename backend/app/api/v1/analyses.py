"""История анализов и детали одного анализа."""

from __future__ import annotations

from datetime import date, datetime, time, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, joinedload

from app.db.models import Analysis, Sample
from app.db.session import get_db
from app.schemas.api import (
    AnalysisList,
    AnalysisOut,
    IndicatorOut,
    IndicatorsOut,
    PredictionOut,
    StaticOut,
    UploadOut,
)
from app.services.upload import queue_rerun

router = APIRouter(prefix="/analyses", tags=["Анализы"])


def get_analysis(db: Session, analysis_id: int) -> Analysis:
    a = db.get(Analysis, analysis_id, options=[joinedload(Analysis.sample)])
    if a is None:
        raise HTTPException(404, "Анализ не найден")
    return a


@router.get("", response_model=AnalysisList)
def list_analyses(
    db: Session = Depends(get_db),
    verdict: str | None = None,
    family: str | None = None,
    status: str | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
    q: str | None = Query(None, description="поиск по имени файла или хешу"),
    limit: int = Query(20, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> AnalysisList:
    stmt = select(Analysis).join(Sample)
    if verdict:
        stmt = stmt.where(Analysis.verdict == verdict)
    if family:
        stmt = stmt.where(Analysis.final_family == family)
    if status:
        stmt = stmt.where(Analysis.status == status)
    if date_from:
        stmt = stmt.where(Analysis.created_at >= datetime.combine(date_from, time.min, timezone.utc))
    if date_to:
        stmt = stmt.where(Analysis.created_at <= datetime.combine(date_to, time.max, timezone.utc))
    if q:
        term = q.strip().lower()
        stmt = stmt.where(or_(Sample.sha256 == term, Sample.md5 == term, Sample.sha1 == term,
                              func.lower(Sample.original_name).contains(term)))
    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    rows = db.scalars(stmt.options(joinedload(Analysis.sample))
                      .order_by(Analysis.created_at.desc(), Analysis.id.desc()).limit(limit).offset(offset)).all()
    return AnalysisList(total=total, items=[AnalysisOut.model_validate(r) for r in rows])


@router.get("/{analysis_id}", response_model=AnalysisOut)
def read_analysis(analysis_id: int, db: Session = Depends(get_db)) -> AnalysisOut:
    return AnalysisOut.model_validate(get_analysis(db, analysis_id))


@router.get("/{analysis_id}/static", response_model=StaticOut)
def read_static(analysis_id: int, db: Session = Depends(get_db)) -> StaticOut:
    a = get_analysis(db, analysis_id)
    if a.sample.source == "dataset":
        return StaticOut(available=False, reason="Образец из тестовой выборки: есть только вектор признаков, файла нет")
    if a.status != "done" or a.features is None:
        return StaticOut(available=False, reason=f"Анализ в статусе {a.status}")
    imports: dict[str, list[str]] = {}
    for imp in a.imports:
        imports.setdefault(imp.dll, []).append(imp.function)
    return StaticOut(available=True, static_info=a.features.static_info, sections=a.sections, imports=imports)


@router.get("/{analysis_id}/indicators", response_model=IndicatorsOut)
def read_indicators(analysis_id: int, db: Session = Depends(get_db)) -> IndicatorsOut:
    a = get_analysis(db, analysis_id)
    if a.sample.source == "dataset":
        return IndicatorsOut(available=False, reason="Индикаторы строятся по самому файлу, а у образца из теста есть только вектор")
    if a.status != "done":
        return IndicatorsOut(available=False, reason=f"Анализ в статусе {a.status}")
    order = {"high": 0, "medium": 1, "low": 2}
    hits = sorted(a.indicator_hits, key=lambda h: order.get(h.severity, 3))
    return IndicatorsOut(available=True, items=[
        IndicatorOut(code=h.rule_code, title=h.rule.title, severity=h.severity, category=h.rule.category,
                     description=h.rule.description, caveat=h.rule.caveat, evidence=h.evidence)
        for h in hits])


@router.get("/{analysis_id}/predictions", response_model=list[PredictionOut])
def read_predictions(analysis_id: int, db: Session = Depends(get_db)) -> list[PredictionOut]:
    a = get_analysis(db, analysis_id)
    return [PredictionOut(task=p.task, algorithm=p.model_version.algorithm, model_version=p.model_version.version,
                          predicted_label=p.predicted_label, confidence=p.confidence, top_k=p.top_k,
                          latency_ms=p.latency_ms, is_final=p.is_final) for p in a.predictions]


@router.post("/{analysis_id}/rerun", status_code=202, response_model=UploadOut)
def rerun(analysis_id: int, db: Session = Depends(get_db)) -> UploadOut:
    a = get_analysis(db, analysis_id)
    new = queue_rerun(db, a)
    return UploadOut(analysis_id=new.id, sha256=a.sample.sha256, duplicate=False, status=new.status)
