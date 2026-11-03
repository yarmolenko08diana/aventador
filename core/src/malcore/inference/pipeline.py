"""Конвейер прогноза для одного вектора EMBER v2 (раздел 3 ТЗ, модуль 4).

Ступень A: детектор benign/malware. Вердикт по порогам, выбранным на validation:
    score >= malicious  -> malicious
    score >= suspicious -> suspicious
    иначе               -> clean
Ступень B (только для suspicious и malicious): семейство и категория.
Если уверенность модели семейства ниже порога unknown_confidence, ответ — «семейство не определено».

На каждой ступени считаются все модели (RF, LightGBM, MLP, ансамбль), чтобы их можно было
сравнить в интерфейсе. Итоговый ответ даёт модель, выбранная по validation на этапе 5
(artifacts/models/<task>/selection.json). Конвейер не обращается к БД и не знает про файлы:
на вход только вектор, поэтому одинаково работает для загруженного файла и для образца из теста.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from malcore.features.vector import VECTOR_SIZE
from malcore.inference.predictors import Predictor
from malcore.inference.registry import load_predictor

TASKS = ("detection", "family", "category")
ALGORITHMS = ("rf", "lgbm", "mlp", "ensemble")
TOP_K = 3


@dataclass
class TaskModels:
    task: str
    predictors: dict[str, Predictor]
    selected: str

    @property
    def final(self) -> Predictor:
        return self.predictors[self.selected]


@dataclass
class ModelPrediction:
    task: str
    algorithm: str
    predicted_label: str
    confidence: float
    top_k: list[dict]
    latency_ms: float
    is_final: bool


@dataclass
class PipelineResult:
    verdict: str
    detector_score: float
    final_family: str | None  # None: не определено или ступень B не запускалась
    family_confidence: float | None
    family_status: str  # identified / unknown / not_applicable
    final_category: str | None
    category_confidence: float | None
    predictions: list[ModelPrediction] = field(default_factory=list)
    disagreement: dict[str, bool] = field(default_factory=dict)


def load_models(models_dir: Path) -> dict[str, TaskModels]:
    """Загружает все задачи. Модель без selection.json (этап 5 не пройден) использовать нельзя."""
    models_dir = Path(models_dir)
    out = {}
    for task in TASKS:
        sel_path = models_dir / task / "selection.json"
        if not sel_path.exists():
            raise FileNotFoundError(f"{sel_path}: нет выбора итоговой модели, сначала этап 5 (mltrain.evaluate)")
        selected = json.loads(sel_path.read_text(encoding="utf-8"))["selected"]
        predictors = {a: load_predictor(models_dir / task / a) for a in ALGORITHMS}
        out[task] = TaskModels(task, predictors, selected)
    return out


def _run_task(models: TaskModels, x: np.ndarray) -> tuple[dict[str, np.ndarray], list[ModelPrediction]]:
    probas, preds = {}, []
    for algo, predictor in models.predictors.items():
        start = time.perf_counter()
        p = predictor.predict_proba(x)[0]
        latency = (time.perf_counter() - start) * 1000
        order = np.argsort(-p)[:TOP_K]
        probas[algo] = p
        preds.append(ModelPrediction(
            task=models.task, algorithm=algo, predicted_label=predictor.classes[order[0]],
            confidence=float(p[order[0]]),
            top_k=[{"label": predictor.classes[i], "probability": float(p[i])} for i in order],
            latency_ms=round(latency, 2), is_final=(algo == models.selected),
        ))
    return probas, preds


def verdict_for(score: float, thresholds: dict) -> str:
    if score >= thresholds["malicious"]:
        return "malicious"
    if score >= thresholds["suspicious"]:
        return "suspicious"
    return "clean"


def predict(models: dict[str, TaskModels], vector: np.ndarray) -> PipelineResult:
    x = np.asarray(vector, dtype=np.float32).reshape(1, -1)
    if x.shape[1] != VECTOR_SIZE:
        raise ValueError(f"ожидался вектор из {VECTOR_SIZE} признаков, получено {x.shape[1]}")

    det = models["detection"]
    probas, preds = _run_task(det, x)
    malware_idx = det.final.classes.index("malware")
    score = float(probas[det.selected][malware_idx])
    verdict = verdict_for(score, det.final.manifest["thresholds"])
    result = PipelineResult(verdict=verdict, detector_score=score, final_family=None, family_confidence=None,
                            family_status="not_applicable", final_category=None, category_confidence=None)
    result.predictions += preds
    result.disagreement["detection"] = len({verdict_for(float(p[malware_idx]), det.predictors[a].manifest["thresholds"])
                                            for a, p in probas.items()}) > 1

    if verdict == "clean":
        return result

    fam = models["family"]
    fam_probas, fam_preds = _run_task(fam, x)
    result.predictions += fam_preds
    p = fam_probas[fam.selected]
    best = int(np.argmax(p))
    result.family_confidence = float(p[best])
    if p[best] >= fam.final.manifest["thresholds"]["unknown_confidence"]:
        result.final_family, result.family_status = fam.final.classes[best], "identified"
    else:
        result.family_status = "unknown"
    result.disagreement["family"] = len({pr.predicted_label for pr in fam_preds}) > 1

    cat = models["category"]
    cat_probas, cat_preds = _run_task(cat, x)
    result.predictions += cat_preds
    p = cat_probas[cat.selected]
    best = int(np.argmax(p))
    result.final_category, result.category_confidence = cat.final.classes[best], float(p[best])
    result.disagreement["category"] = len({pr.predicted_label for pr in cat_preds}) > 1
    return result
