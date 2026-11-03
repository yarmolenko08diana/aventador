"""Счётчики и данные для графиков панели управления. Все числа — запросы к БД."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import cast, func, select, text
from sqlalchemy.orm import Session
from sqlalchemy.types import Date

from app.db.models import Analysis, Sample
from app.db.session import get_db

router = APIRouter(prefix="/dashboard", tags=["Панель"])


@router.get("/stats")
def stats(db: Session = Depends(get_db), days: int = Query(14, ge=1, le=365)) -> dict:
    by_verdict = dict(db.execute(select(Analysis.verdict, func.count()).where(Analysis.status == "done")
                                 .group_by(Analysis.verdict)).all())
    by_status = dict(db.execute(select(Analysis.status, func.count()).group_by(Analysis.status)).all())
    families = db.execute(
        select(Analysis.final_family, func.count()).where(Analysis.final_family.is_not(None))
        .group_by(Analysis.final_family).order_by(func.count().desc()).limit(15)).all()
    unknown_family = db.scalar(select(func.count()).where(Analysis.family_status == "unknown"))
    since = datetime.now(timezone.utc) - timedelta(days=days - 1)
    day = cast(Analysis.created_at, Date)
    per_day = db.execute(
        select(day, Analysis.verdict, func.count()).where(Analysis.created_at >= since.replace(hour=0, minute=0))
        .group_by(day, Analysis.verdict).order_by(day)).all()
    timeline: dict[str, dict] = {}
    for d, verdict, n in per_day:
        timeline.setdefault(d.isoformat(), {})[verdict or "без вердикта"] = n
    return {
        "total_analyses": sum(by_status.values()),
        "total_samples": db.scalar(select(func.count()).select_from(Sample)),
        "by_status": by_status,
        "by_verdict": {k: by_verdict.get(k, 0) for k in ("clean", "suspicious", "malicious")},
        "families_detected": db.scalar(select(func.count(func.distinct(Analysis.final_family)))),
        "family_unknown": unknown_family,
        "top_families": [{"family": f, "count": n} for f, n in families],
        "timeline": [{"date": d, **v} for d, v in sorted(timeline.items())],
        "avg_duration_ms": db.scalar(select(func.avg(Analysis.duration_ms)).where(Analysis.status == "done")),
        "db_time": db.scalar(text("select now()")),
    }
