"""Импорт обученных моделей и их метрик на тесте в БД (model_versions, model_evaluations).

Источник — только файлы этапов 4–5 (manifest.json, evaluation.json, selection.json), поэтому
цифры на странице «Модели» всегда совпадают с тем, что реально получено при обучении и оценке.
Также заполняет справочник правил indicator_rules из malcore.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.db.models import IndicatorRule, ModelEvaluation, ModelVersion
from malcore.indicators.engine import catalog
from malcore.inference.pipeline import ALGORITHMS, TASKS
from malcore.inference.registry import sha256_file


def sync_rules(db: Session) -> int:
    for rule in catalog():
        db.merge(IndicatorRule(**rule))
    db.commit()
    return len(catalog())


def _evaluation_row(ev: dict) -> ModelEvaluation:
    per_class = ev.get("per_class")
    macro = (per_class or {}).get("macro avg", {})
    skip = {"roc_curve", "reliability", "per_class", "confusion_matrix"}
    return ModelEvaluation(
        split_name=f"test_{ev.get('split', 'temporal')}",
        accuracy=ev.get("accuracy"),
        precision_macro=macro.get("precision"),
        recall_macro=macro.get("recall"),
        f1_macro=ev.get("macro_f1"),
        roc_auc=ev.get("roc_auc"),
        tpr_at_fpr_1pct=ev.get("tpr_at_fpr_1pct"),
        confusion_matrix=ev["confusion_matrix"],
        per_class=per_class,
        metrics={k: v for k, v in ev.items() if k not in skip},
        evaluated_at=datetime.fromisoformat(ev["evaluated_at"]) if ev.get("evaluated_at") else None,
    )


def sync_models(db: Session, models_dir: Path) -> dict[tuple[str, str], int]:
    """Делает активными модели из models_dir. Возвращает {(task, algorithm): model_version_id}."""
    models_dir = Path(models_dir)
    ids = {}
    for task in TASKS:
        selection = json.loads((models_dir / task / "selection.json").read_text(encoding="utf-8"))["selected"]
        for algo in ALGORITHMS:
            mdir = models_dir / task / algo
            manifest_sha = sha256_file(mdir / "manifest.json")
            mv = db.scalar(select(ModelVersion).where(
                ModelVersion.task == task, ModelVersion.algorithm == algo, ModelVersion.artifact_sha256 == manifest_sha))
            if mv is None:
                man = json.loads((mdir / "manifest.json").read_text(encoding="utf-8"))
                mv = ModelVersion(
                    task=task, algorithm=algo, version=manifest_sha[:12], feature_version=man["feature_version"],
                    dataset=man["data"]["dataset"], split_strategy=man["data"]["split"], classes=man["classes"],
                    thresholds=man.get("thresholds", {}), hyperparameters=man.get("hyperparameters", {}),
                    validation=man.get("validation", {}), artifact_path=str(mdir), artifact_sha256=manifest_sha,
                    trained_at=datetime.fromisoformat(man["created_at"]),
                )
                db.add(mv)
                db.flush()
            # Метрики теста могут появиться позже обучения (этап 5) — подтягиваем, если их ещё нет
            ev_path = mdir / "evaluation.json"
            if ev_path.exists() and not mv.evaluations:
                mv.evaluations.append(_evaluation_row(json.loads(ev_path.read_text(encoding="utf-8"))))
            db.execute(update(ModelVersion).where(
                ModelVersion.task == task, ModelVersion.algorithm == algo, ModelVersion.id != mv.id
            ).values(is_active=False, is_final=False))
            mv.is_active, mv.is_final = True, algo == selection
            ids[(task, algo)] = mv.id
    db.commit()
    return ids
