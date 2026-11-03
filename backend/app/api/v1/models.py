"""Модели и их метрики на тесте (только из model_versions / model_evaluations)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import ModelVersion
from app.db.session import get_db
from app.schemas.api import ModelOut

router = APIRouter(prefix="/models", tags=["Модели"])


@router.get("", response_model=list[ModelOut])
def list_models(db: Session = Depends(get_db), active: bool = True) -> list[ModelVersion]:
    stmt = select(ModelVersion).order_by(ModelVersion.task, ModelVersion.algorithm)
    if active:
        stmt = stmt.where(ModelVersion.is_active)
    return list(db.scalars(stmt))


@router.get("/comparison")
def comparison(task: str = Query(..., pattern="^(detection|family|category)$"), db: Session = Depends(get_db)) -> dict:
    """Метрики всех алгоритмов задачи на тестовой выборке (по времени) и на validation."""
    rows = []
    for mv in db.scalars(select(ModelVersion).where(ModelVersion.task == task, ModelVersion.is_active)
                         .order_by(ModelVersion.algorithm)):
        ev = mv.evaluations[0] if mv.evaluations else None
        rows.append({
            "model_id": mv.id, "algorithm": mv.algorithm, "version": mv.version, "is_final": mv.is_final,
            "validation": mv.validation,
            "test": None if ev is None else {
                "split": ev.split_name, "accuracy": ev.accuracy, "precision_macro": ev.precision_macro,
                "recall_macro": ev.recall_macro, "f1_macro": ev.f1_macro, "roc_auc": ev.roc_auc,
                "tpr_at_fpr_1pct": ev.tpr_at_fpr_1pct, "metrics": ev.metrics, "per_class": ev.per_class,
            },
        })
    if not rows:
        raise HTTPException(404, "Нет активных моделей для этой задачи")
    return {"task": task, "classes": db.scalar(select(ModelVersion.classes).where(
        ModelVersion.task == task, ModelVersion.is_active)), "models": rows}


@router.get("/{model_id}/confusion-matrix")
def confusion(model_id: int, db: Session = Depends(get_db)) -> dict:
    mv = db.get(ModelVersion, model_id)
    if mv is None:
        raise HTTPException(404, "Модель не найдена")
    if not mv.evaluations:
        raise HTTPException(404, "У модели нет оценки на тесте")
    return {"model_id": mv.id, "task": mv.task, "algorithm": mv.algorithm, "classes": mv.classes,
            "matrix": mv.evaluations[0].confusion_matrix,
            "note": "строки — истина, столбцы — прогноз" + (", порог malicious" if mv.task == "detection" else "")}
