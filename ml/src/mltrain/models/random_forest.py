"""Random Forest (scikit-learn): сырые признаки, class_weight='balanced'."""

from __future__ import annotations

import time
from pathlib import Path

import joblib
from sklearn.ensemble import RandomForestClassifier

from mltrain.models import Fitted, Log, Select, grid

ALGORITHM = "rf"
MODEL_FILE = "model.joblib"


def fit(data, cfg: dict, seed: int, n_jobs: int, select: Select, log: Log) -> Fitted:
    best, search = None, []
    for params in grid(cfg["grid"]):
        start = time.time()
        model = RandomForestClassifier(
            **params, class_weight="balanced", random_state=seed, n_jobs=n_jobs
        )
        model.fit(data.X_train, data.y_train)
        proba = model.predict_proba(data.X_val)
        score = select(data.y_val, proba)
        seconds = round(time.time() - start, 1)
        search.append({"params": params, "val_score": score, "seconds": seconds})
        log(f"  rf {params}: val {score:.5f} ({seconds} с)")
        if best is None or score > best[0]:
            best = (score, model, proba, params)
        else:
            del model  # держим в памяти только лучший лес
    _, model, proba, params = best
    return Fitted(model=model, val_proba=proba, hyperparameters=params, search=search)


def save(fitted: Fitted, out_dir: Path) -> list[str]:
    fitted.model.n_jobs = 1
    joblib.dump(fitted.model, out_dir / MODEL_FILE, compress=3)
    return [MODEL_FILE]
