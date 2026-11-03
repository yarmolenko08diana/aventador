"""LightGBM: сырые признаки, веса образцов по классам, ранняя остановка по validation."""

from __future__ import annotations

import time
from pathlib import Path

import lightgbm as lgb
import numpy as np

from mltrain.datasets import balanced_weights
from mltrain.models import Fitted, Log, Select, grid

ALGORITHM = "lgbm"
MODEL_FILE = "model.txt"


def _proba(booster: lgb.Booster, X: np.ndarray) -> np.ndarray:
    p = booster.predict(X, num_iteration=booster.best_iteration)
    return np.column_stack([1 - p, p]) if p.ndim == 1 else p


def fit(data, cfg: dict, seed: int, n_jobs: int, select: Select, log: Log) -> Fitted:
    n_classes = len(data.classes)
    weights = balanced_weights(data.y_train, n_classes)
    base = {
        **cfg.get("fixed", {}),
        "verbosity": -1,
        "seed": seed,
        "num_threads": n_jobs,
        "deterministic": True,  # одинаковый результат при повторном запуске
        "force_col_wise": True,
    }
    if n_classes == 2:
        base.update(objective="binary", metric="binary_logloss")
    else:
        base.update(objective="multiclass", metric="multi_logloss", num_class=n_classes)

    # Бины признаков строятся по train один раз; validation использует те же границы
    train_set = lgb.Dataset(data.X_train, label=data.y_train, weight=weights[data.y_train], free_raw_data=False)
    val_set = lgb.Dataset(data.X_val, label=data.y_val, weight=weights[data.y_val], reference=train_set)

    best, search = None, []
    for params in grid(cfg["grid"]):
        start = time.time()
        booster = lgb.train(
            {**base, **params},
            train_set,
            num_boost_round=cfg["max_rounds"],
            valid_sets=[val_set],
            callbacks=[lgb.early_stopping(cfg["early_stopping"], verbose=False)],
        )
        proba = _proba(booster, data.X_val)
        score = select(data.y_val, proba)
        seconds = round(time.time() - start, 1)
        record = {**params, "best_iteration": booster.best_iteration}
        search.append({"params": record, "val_score": score, "seconds": seconds})
        log(f"  lgbm {record}: val {score:.5f} ({seconds} с)")
        if best is None or score > best[0]:
            best = (score, booster, proba, {**cfg.get("fixed", {}), **record})
    _, booster, proba, params = best
    return Fitted(model=booster, val_proba=proba, hyperparameters=params, search=search)


def save(fitted: Fitted, out_dir: Path) -> list[str]:
    # Сохраняем только деревья до лучшей итерации
    fitted.model.save_model(str(out_dir / MODEL_FILE), num_iteration=fitted.model.best_iteration)
    return [MODEL_FILE]
