"""Уведомления о подозрительных и вредоносных файлах."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.db.models import Alert
from app.db.session import get_db
from app.schemas.api import AlertOut, AlertPatch

router = APIRouter(prefix="/alerts", tags=["Уведомления"])


@router.get("", response_model=list[AlertOut])
def list_alerts(db: Session = Depends(get_db), unread: bool = False,
                limit: int = Query(50, ge=1, le=200)) -> list[Alert]:
    stmt = select(Alert).order_by(Alert.created_at.desc(), Alert.id.desc()).limit(limit)
    if unread:
        stmt = stmt.where(Alert.is_read.is_(False))
    return list(db.scalars(stmt))


@router.get("/unread-count")
def unread_count(db: Session = Depends(get_db)) -> dict:
    return {"unread": db.scalar(select(func.count()).where(Alert.is_read.is_(False)))}


@router.post("/read-all")
def mark_all_read(db: Session = Depends(get_db)) -> dict:
    res = db.execute(update(Alert).where(Alert.is_read.is_(False))
                     .values(is_read=True, read_at=datetime.now(timezone.utc)))
    db.commit()
    return {"marked": res.rowcount}


@router.patch("/{alert_id}", response_model=AlertOut)
def mark(alert_id: int, body: AlertPatch, db: Session = Depends(get_db)) -> Alert:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(404, "Уведомление не найдено")
    alert.is_read = body.is_read
    alert.read_at = datetime.now(timezone.utc) if body.is_read else None
    db.commit()
    return alert
