"""Модели и их метрики на тесте (только из model_versions / model_evaluations)."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
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


def _downsample(fpr: list[float], tpr: list[float], max_points: int = 1000) -> dict:
    """Прореживает ROC-кривую для графика; первая и последняя точки сохраняются."""
    n = len(fpr)
    if n <= max_points:
        return {"fpr": fpr, "tpr": tpr}
    step = (n - 1) / (max_points - 1)
    idx = sorted({round(i * step) for i in range(max_points)})
    return {"fpr": [fpr[i] for i in idx], "tpr": [tpr[i] for i in idx]}


@router.get("/{model_id}/curves")
def curves(model_id: int, db: Session = Depends(get_db)) -> dict:
    """ROC-кривая (для обнаружения) и диаграмма надёжности из evaluation.json этой версии модели.

    Файл берётся из папки моделей (MODELS_DIR) и принимается, только если он оценивал именно эту версию
    (manifest_sha256 в evaluation.json совпадает с хешем, записанным в БД).
    """
    mv = db.get(ModelVersion, model_id)
    if mv is None:
        raise HTTPException(404, "Модель не найдена")
    # Папку берём из настроек, а не artifact_path: в Docker модели смонтированы по другому пути,
    # чем при локальном запуске. Что файл тот самый, проверяет manifest_sha256 ниже.
    path = Path(get_settings().models_dir) / mv.task / mv.algorithm / "evaluation.json"
    if not path.exists():
        raise HTTPException(404, "У модели нет оценки на тесте")
    ev = json.loads(path.read_text(encoding="utf-8"))
    if ev.get("manifest_sha256") != mv.artifact_sha256:
        raise HTTPException(409, "evaluation.json относится к другой версии модели")
    roc = ev.get("roc_curve")
    return {"model_id": mv.id, "task": mv.task, "algorithm": mv.algorithm,
            "roc_auc": ev.get("roc_auc"), "roc": _downsample(roc["fpr"], roc["tpr"]) if roc else None,
            "reliability": ev.get("reliability", []), "ece": ev.get("ece")}
