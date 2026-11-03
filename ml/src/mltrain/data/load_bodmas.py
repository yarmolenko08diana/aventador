"""Загрузка BODMAS и проверка согласованности файлов.

Формат подтверждён скриптом inspect_bodmas (3 ноября 2026):
    bodmas.npz                  X (134435, 2381) float32, y (134435,) 0=benign, 1=malware
    bodmas_metadata.csv         sha, timestamp, family (NaN у безопасных)
    bodmas_malware_category.csv sha256, category (только вредоносные)
Строки X/y и metadata идут в одном порядке; это проверяется ниже по меткам.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[4]
RAW_DIR = ROOT / "data" / "raw" / "bodmas"
N_FEATURES = 2381  # размер вектора EMBER v2


@dataclass
class Bodmas:
    X: np.ndarray  # (n, 2381) float32
    meta: pd.DataFrame  # row, sha256, timestamp, label, family, category


class DataConsistencyError(ValueError):
    """Файлы датасета не согласуются друг с другом."""


def build_meta(y: np.ndarray, metadata: pd.DataFrame, categories: pd.DataFrame) -> pd.DataFrame:
    """Собирает одну таблицу метаданных и проверяет её согласованность с метками y."""
    if len(metadata) != len(y):
        raise DataConsistencyError(f"строк в metadata {len(metadata)}, а в y {len(y)}")

    meta = pd.DataFrame(
        {
            "row": np.arange(len(y)),
            "sha256": metadata["sha"].astype(str).str.lower(),
            "timestamp": pd.to_datetime(metadata["timestamp"], utc=True),
            "label": y.astype(np.int8),
            "family": metadata["family"],
        }
    )

    # Порядок строк: у вредоносных есть семейство, у безопасных нет
    has_family = meta["family"].notna().to_numpy()
    mismatched = int((has_family != (meta["label"].to_numpy() == 1)).sum())
    if mismatched:
        raise DataConsistencyError(
            f"{mismatched} строк, где наличие семейства не совпадает с y: порядок строк нарушен"
        )
    if meta["sha256"].duplicated().any():
        raise DataConsistencyError("в metadata есть повторяющиеся sha")

    cats = categories.rename(columns={"sha256": "sha256_cat"})
    cats["sha256_cat"] = cats["sha256_cat"].astype(str).str.lower()
    meta = meta.merge(cats, how="left", left_on="sha256", right_on="sha256_cat").drop(
        columns="sha256_cat"
    )
    missing_cat = int(((meta["label"] == 1) & meta["category"].isna()).sum())
    if missing_cat:
        raise DataConsistencyError(f"у {missing_cat} вредоносных образцов нет категории")
    if (meta.loc[meta["label"] == 0, "category"].notna()).any():
        raise DataConsistencyError("категория указана у безопасного образца")
    return meta


def load_bodmas(raw_dir: Path = RAW_DIR) -> Bodmas:
    with np.load(raw_dir / "bodmas.npz", allow_pickle=False) as data:
        X = np.ascontiguousarray(data["X"], dtype=np.float32)
        y = np.asarray(data["y"])
    if X.shape != (len(y), N_FEATURES):
        raise DataConsistencyError(f"ожидался X формы ({len(y)}, {N_FEATURES}), получено {X.shape}")
    metadata = pd.read_csv(raw_dir / "bodmas_metadata.csv")
    categories = pd.read_csv(raw_dir / "bodmas_malware_category.csv")
    return Bodmas(X=X, meta=build_meta(y, metadata, categories))
