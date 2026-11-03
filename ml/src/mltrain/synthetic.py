"""Маленький синтетический «BODMAS» для тестов ml и backend.

Только для проверки кода: векторы случайные, метрики на них ничего не значат.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
import yaml

from mltrain import metrics

N_FEATURES = 2381
TINY = {
    "seed": 7,
    "n_jobs": 2,
    "detection_verdict_fpr": {"malicious": 0.01, "suspicious": 0.05},
    "rf": {"grid": {"n_estimators": [20], "max_depth": [None, 6], "max_features": ["sqrt"], "min_samples_leaf": [1]}},
    "lgbm": {"fixed": {"learning_rate": 0.1, "min_child_samples": 5}, "grid": {"num_leaves": [7, 15]},
             "max_rounds": 60, "early_stopping": 10},
    "mlp": {"fixed": {"batch_size": 64, "max_epochs": 4, "patience": 2, "weight_decay": 0.0},
            "grid": {"hidden": [[32]], "dropout": [0.1], "lr": [0.003]}},
}


def make_dataset(tmp: Path, n: int = 900, seed: int = 0) -> tuple[Path, Path]:
    """bodmas.npz + data/splits/*.csv в том же формате, что создаёт этап 1."""
    rng = np.random.default_rng(seed)
    label = rng.integers(0, 2, n)
    family = np.where(label == 1, rng.choice(["fa", "fb", "fc", "rare"], n, p=[0.35, 0.3, 0.25, 0.1]), "")
    X = rng.normal(0, 1, (n, N_FEATURES)).astype(np.float32)
    X[:, :256] = np.abs(X[:, :256])  # неотрицательные «гистограммы»: к ним MLP применит log1p
    X[:, 0] += label * 2.0  # сигнал для обнаружения
    for i, f in enumerate(["fa", "fb", "fc"]):
        X[family == f, 10 + i] += 3.0  # сигнал для семейств
    raw = tmp / "raw"
    raw.mkdir(parents=True)
    np.savez(raw / "bodmas.npz", X=X, y=label)

    splits = tmp / "splits"
    splits.mkdir(parents=True)
    split = np.array(["train"] * int(n * 0.7) + ["val"] * int(n * 0.1) + ["test"] * (n - int(n * 0.7) - int(n * 0.1)))
    base = pd.DataFrame({"row": np.arange(n), "sha256": [f"{i:064x}" for i in range(n)],
                         "timestamp": "2020-01-01", "split": split})
    det = base.assign(target=np.where(label == 1, "malware", "benign"))
    det.to_csv(splits / "detection.csv", index=False)
    mal = base[label == 1].copy()
    fam = np.where(family[label == 1] == "rare", metrics.UNKNOWN, family[label == 1])
    mal.assign(target=fam).to_csv(splits / "family.csv", index=False)
    mal.assign(target=np.where(fam == "fa", "trojan", "worm")).to_csv(splits / "category.csv", index=False)
    return raw, splits


def build_models(tmp: Path) -> dict[str, Path]:
    """Обучает все модели на синтетике и прогоняет этап 5. Возвращает пути к артефактам."""
    from mltrain import evaluate, train

    raw, splits = make_dataset(tmp)
    cfg = tmp / "train.yaml"
    cfg.write_text(yaml.safe_dump(TINY), encoding="utf-8")
    models, reports = tmp / "models", tmp / "reports"
    common = ["--splits-dir", str(splits), "--models-dir", str(models), "--features", str(raw / "bodmas.npz")]
    if train.main(["--all", "--config", str(cfg), *common]) != 0:
        raise RuntimeError("обучение на синтетике не удалось")
    if evaluate.main(["--all", *common, "--reports-dir", str(reports)]) != 0:
        raise RuntimeError("оценка на синтетике не удалась")
    return {"models": models, "raw": raw, "splits": splits, "reports": reports}
