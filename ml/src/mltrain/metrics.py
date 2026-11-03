"""Метрики и выбор порогов (раздел 7 ТЗ). Всё считается на переданных массивах, без тестовой выборки."""

from __future__ import annotations

import numpy as np
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score, roc_curve

UNKNOWN = "__unknown__"


def threshold_at_fpr(y_true: np.ndarray, score: np.ndarray, fpr: float) -> float:
    """Наименьший порог, при котором доля ложных тревог на безопасных не больше fpr.

    Вердикт «malware» ставится при score >= threshold.
    """
    benign = np.sort(score[y_true == 0])[::-1]
    if len(benign) == 0:
        raise ValueError("нет безопасных образцов для выбора порога")
    k = int(np.floor(fpr * len(benign)))  # столько безопасных можно пропустить выше порога
    if k >= len(benign):
        return float(benign[-1])
    # порог строго выше (k+1)-го по величине безопасного score, чтобы ложных было <= k
    return float(np.nextafter(benign[k], np.inf))


def detection_metrics(y_true: np.ndarray, score: np.ndarray, thresholds: dict[str, float] | None = None) -> dict:
    fpr, tpr, _ = roc_curve(y_true, score)
    out = {
        "roc_auc": float(roc_auc_score(y_true, score)),
        "tpr_at_fpr_1pct": float(np.interp(0.01, fpr, tpr)),
        "tpr_at_fpr_0_1pct": float(np.interp(0.001, fpr, tpr)),
    }
    for name, thr in (thresholds or {}).items():
        pred = score >= thr
        out[f"{name}_fpr"] = float(pred[y_true == 0].mean())
        out[f"{name}_tpr"] = float(pred[y_true == 1].mean())
    return out


def multiclass_metrics(y_true: np.ndarray, proba: np.ndarray) -> dict:
    pred = proba.argmax(axis=1)
    return {
        "macro_f1": float(f1_score(y_true, pred, average="macro", labels=np.arange(proba.shape[1]), zero_division=0)),
        "accuracy": float(accuracy_score(y_true, pred)),
    }


def expected_calibration_error(correct: np.ndarray, confidence: np.ndarray, bins: int = 15) -> float:
    """ECE: насколько уверенность модели расходится с реальной долей верных ответов."""
    edges = np.linspace(0, 1, bins + 1)
    idx = np.clip(np.digitize(confidence, edges[1:-1]), 0, bins - 1)
    ece = 0.0
    for b in range(bins):
        mask = idx == b
        if mask.any():
            ece += mask.mean() * abs(correct[mask].mean() - confidence[mask].mean())
    return float(ece)


def open_set_metrics(y_known: np.ndarray, proba_known: np.ndarray, proba_unknown: np.ndarray, threshold: float) -> dict:
    """Ответ «не определено», если максимальная вероятность ниже порога.

    unknown_rejected — доля образцов незнакомых семейств, на которых система честно сказала «не определено»;
    known_rejected — доля известных семейств, отвергнутых зря;
    open_set_macro_f1 — macro-F1, где «неизвестное» считается ещё одним классом.
    """
    n_classes = proba_known.shape[1]
    proba = np.vstack([proba_known, proba_unknown]) if len(proba_unknown) else proba_known
    y = np.concatenate([y_known, np.full(len(proba_unknown), n_classes)])
    pred = np.where(proba.max(axis=1) >= threshold, proba.argmax(axis=1), n_classes)
    f1 = f1_score(y, pred, average="macro", labels=np.arange(n_classes + 1), zero_division=0)
    return {
        "threshold": float(threshold),
        "open_set_macro_f1": float(f1),
        "unknown_rejected": float((proba_unknown.max(axis=1) < threshold).mean()) if len(proba_unknown) else None,
        "known_rejected": float((proba_known.max(axis=1) < threshold).mean()),
        "n_unknown": int(len(proba_unknown)),
    }


def choose_unknown_threshold(y_known: np.ndarray, proba_known: np.ndarray, proba_unknown: np.ndarray) -> dict:
    """Порог уверенности для ответа «семейство не определено», подобранный на validation.

    Перебираем пороги 0.00…1.00 и берём тот, где open-set macro-F1 максимален
    (при равенстве — меньший порог, чтобы реже отвергать известные семейства).
    """
    best = None
    for thr in np.round(np.linspace(0, 1, 101), 2):
        res = open_set_metrics(y_known, proba_known, proba_unknown, thr)
        if best is None or res["open_set_macro_f1"] > best["open_set_macro_f1"] + 1e-12:
            best = res
    return best


def reliability(correct_or_label: np.ndarray, confidence: np.ndarray, bins: int = 10) -> list[dict]:
    """Точки диаграммы надёжности: средняя уверенность и реальная доля в каждой корзине."""
    edges = np.linspace(0, 1, bins + 1)
    idx = np.clip(np.digitize(confidence, edges[1:-1]), 0, bins - 1)
    out = []
    for b in range(bins):
        mask = idx == b
        if mask.any():
            out.append({"bin": b, "mean_confidence": float(confidence[mask].mean()),
                        "observed": float(correct_or_label[mask].mean()), "count": int(mask.sum())})
    return out
