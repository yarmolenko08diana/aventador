"""Данные для обучения: train и validation одной задачи.

Тестовая выборка здесь не загружается вообще: в этапе 4 ей нечего делать. Её прочитает
только этап 5 (evaluate), один раз.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

from mltrain.data.load_bodmas import N_FEATURES, RAW_DIR, ROOT
from mltrain.metrics import UNKNOWN

SPLITS_DIR = ROOT / "data" / "splits"
TASKS = ("detection", "family", "category")
DETECTION_CLASSES = ["benign", "malware"]  # индекс 1 = вредоносный, его вероятность и есть score


@dataclass
class TaskData:
    task: str
    classes: list[str]
    X_train: np.ndarray
    y_train: np.ndarray  # индексы в classes
    X_val: np.ndarray
    y_val: np.ndarray
    X_val_unknown: np.ndarray | None  # family: образцы семейств вне классификатора (для порога «не определено»)
    split_file_sha256: str
    counts: dict


def load_features(path: Path = RAW_DIR / "bodmas.npz") -> np.ndarray:
    with np.load(path, allow_pickle=False) as data:
        X = np.ascontiguousarray(data["X"], dtype=np.float32)
    if X.ndim != 2 or X.shape[1] != N_FEATURES:
        raise ValueError(f"ожидался X с {N_FEATURES} признаками, получено {X.shape}")
    return X


def read_split(task: str, splits_dir: Path = SPLITS_DIR) -> tuple[pd.DataFrame, str]:
    path = Path(splits_dir) / f"{task}.csv"
    if not path.exists():
        raise FileNotFoundError(f"{path} не найден: сначала запусти python -m mltrain.data.prepare")
    return pd.read_csv(path), hashlib.sha256(path.read_bytes()).hexdigest()


def build_task(task: str, X: np.ndarray, split: pd.DataFrame, split_sha: str) -> TaskData:
    if task not in TASKS:
        raise ValueError(f"неизвестная задача {task}")
    train = split[split["split"] == "train"]
    val = split[split["split"] == "val"]

    unknown_val = None
    if task == "family":
        # В классификатор идут только семейства, прошедшие порог этапа 1
        unknown_val = val[val["target"] == UNKNOWN]
        train, val = train[train["target"] != UNKNOWN], val[val["target"] != UNKNOWN]

    classes = DETECTION_CLASSES if task == "detection" else sorted(train["target"].unique())
    index = {c: i for i, c in enumerate(classes)}
    missing = set(val["target"]) - set(index)
    if missing:
        raise ValueError(f"в validation есть классы, которых нет в train: {sorted(missing)}")

    def rows(frame):
        return X[frame["row"].to_numpy()]

    return TaskData(
        task=task,
        classes=list(classes),
        X_train=rows(train),
        y_train=train["target"].map(index).to_numpy(np.int64),
        X_val=rows(val),
        y_val=val["target"].map(index).to_numpy(np.int64),
        X_val_unknown=rows(unknown_val) if unknown_val is not None else None,
        split_file_sha256=split_sha,
        counts={
            "train": int(len(train)),
            "val": int(len(val)),
            "val_unknown": int(len(unknown_val)) if unknown_val is not None else 0,
            "test_not_loaded": int((split["split"] == "test").sum()),
        },
    )


def balanced_weights(y: np.ndarray, n_classes: int) -> np.ndarray:
    """Вес класса = n / (C * n_c), как class_weight='balanced' в scikit-learn."""
    counts = np.bincount(y, minlength=n_classes).astype(np.float64)
    w = len(y) / (n_classes * np.maximum(counts, 1))
    return w.astype(np.float32)
