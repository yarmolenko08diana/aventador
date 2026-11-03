"""Запись результата анализа в БД одной транзакцией и создание уведомления (раздел 5 ТЗ)."""

from __future__ import annotations

from datetime import datetime, timezone

import numpy as np
from sqlalchemy.orm import Session

from app.db.models import (
    Alert,
    Analysis,
    AnalysisFeatures,
    IndicatorHit,
    ModelPrediction,
    PeImport,
    PeSection,
)
from malcore.features.static_info import public_view
from malcore.features.vector import FEATURE_VERSION
from malcore.inference.pipeline import PipelineResult

MAX_IMPORT_ROWS = 2000


def _now() -> datetime:
    return datetime.now(timezone.utc)


def alert_for(analysis: Analysis, result: PipelineResult, sample_name: str) -> Alert | None:
    if result.verdict == "clean":
        return None
    family = {
        "identified": f"семейство {result.final_family} (уверенность {result.family_confidence:.0%})",
        "unknown": "семейство не определено",
    }.get(result.family_status, "")
    title = ("Вредоносный файл" if result.verdict == "malicious" else "Подозрительный файл") + f": {sample_name}"
    message = (f"Оценка детектора {result.detector_score:.3f}; {family}; "
               f"категория {result.final_category or '—'}.")
    return Alert(analysis_id=analysis.id, severity="high" if result.verdict == "malicious" else "medium",
                 title=title, message=message)


def save_result(db: Session, analysis: Analysis, vector: np.ndarray, static_info: dict | None,
                hits: list[dict], result: PipelineResult, model_ids: dict[tuple[str, str], int],
                duration_ms: float) -> None:
    analysis.features = AnalysisFeatures(
        vector=[float(v) for v in vector],
        static_info=public_view(static_info) if static_info else None,
    )
    if static_info and "sections" in static_info:
        analysis.sections = [
            PeSection(name=s["name"], virtual_address=s["virtual_address"], virtual_size=s["virtual_size"],
                      raw_size=s["raw_size"], entropy=s["entropy"], is_read=s["readable"],
                      is_write=s["writable"], is_exec=s["executable"])
            for s in static_info["sections"]
        ]
        rows = [(dll, f) for dll, funcs in static_info.get("imports", {}).items() for f in funcs][:MAX_IMPORT_ROWS]
        analysis.imports = [PeImport(dll=d, function=f) for d, f in rows]
    analysis.indicator_hits = [IndicatorHit(rule_code=h["code"], severity=h["severity"], evidence=h["evidence"])
                               for h in hits]
    analysis.predictions = [
        ModelPrediction(model_version_id=model_ids[(p.task, p.algorithm)], task=p.task,
                        predicted_label=p.predicted_label, confidence=p.confidence, top_k=p.top_k,
                        latency_ms=p.latency_ms, is_final=p.is_final)
        for p in result.predictions
    ]
    analysis.verdict = result.verdict
    analysis.detector_score = result.detector_score
    analysis.final_family = result.final_family
    analysis.family_confidence = result.family_confidence
    analysis.family_status = result.family_status
    analysis.final_category = result.final_category
    analysis.category_confidence = result.category_confidence
    analysis.disagreement = result.disagreement
    analysis.feature_version = FEATURE_VERSION
    analysis.duration_ms = round(duration_ms, 1)
    analysis.status = "done"
    analysis.finished_at = _now()
    analysis.error_message = None
    db.flush()
    sample = analysis.sample
    alert = alert_for(analysis, result, sample.original_name or sample.sha256[:16])
    if alert is not None:
        db.add(alert)
    db.commit()


def save_failure(db: Session, analysis: Analysis, message: str, duration_ms: float | None = None) -> None:
    analysis.status = "failed"
    analysis.error_message = message[:2000]
    analysis.finished_at = _now()
    analysis.duration_ms = duration_ms
    db.commit()
