"""Дедупликация и разбиение по времени (раздел 7 ТЗ).

Правила:
- одинаковые векторы признаков считаются одним образцом, остаётся самый ранний;
- detection: внутри каждого класса ранние 70% -> train, следующие 10% -> val,
  поздние 20% -> test. Делим по классам отдельно, потому что метки времени
  безопасных файлов начинаются с 2007 года, а вредоносные собраны в 2019–2020:
  общий порог по времени отправил бы почти все безопасные файлы в train;
- family и category: только вредоносные, общий порог по времени;
- в family попадают семейства с достаточным числом образцов во всех выборках,
  остальные помечаются как unknown и служат для оценки ответа «не определено».
"""

from __future__ import annotations

import hashlib

import numpy as np
import pandas as pd

SPLITS = ("train", "val", "test")
UNKNOWN = "__unknown__"
OTHER = "other"


def find_duplicate_rows(X: np.ndarray, meta: pd.DataFrame) -> np.ndarray:
    """Маска строк, которые повторяют более ранний образец с тем же вектором признаков."""
    digests = np.array([hashlib.blake2b(row.tobytes(), digest_size=16).hexdigest() for row in X])
    order = meta.sort_values(["timestamp", "sha256"], kind="stable").index.to_numpy()
    dup = pd.Series(digests[order]).duplicated(keep="first").to_numpy()
    mask = np.zeros(len(X), dtype=bool)
    mask[order[dup]] = True
    return mask


def temporal_split(frame: pd.DataFrame, ratios: dict[str, float]) -> pd.Series:
    """Ставит каждой строке train/val/test по её месту во времени (ничьи по времени — по sha)."""
    order = frame.sort_values(["timestamp", "sha256"], kind="stable").index
    n = len(order)
    n_train = int(round(n * ratios["train"]))
    n_val = int(round(n * ratios["val"]))
    labels = np.array(["test"] * n, dtype=object)
    labels[:n_train] = "train"
    labels[n_train : n_train + n_val] = "val"
    return pd.Series(labels, index=order).reindex(frame.index)


def split_detection(meta: pd.DataFrame, ratios: dict[str, float]) -> pd.DataFrame:
    parts = [temporal_split(group, ratios) for _, group in meta.groupby("label")]
    out = meta[["row", "sha256", "timestamp"]].copy()
    out["split"] = pd.concat(parts).reindex(meta.index)
    out["target"] = meta["label"].map({0: "benign", 1: "malware"})
    return out


def split_family(meta: pd.DataFrame, ratios: dict[str, float], min_counts: dict[str, int]) -> pd.DataFrame:
    mal = meta[meta["label"] == 1]
    out = mal[["row", "sha256", "timestamp", "family"]].copy()
    out["split"] = temporal_split(mal, ratios)
    counts = out.groupby(["family", "split"]).size().unstack(fill_value=0).reindex(columns=SPLITS, fill_value=0)
    keep = counts[
        (counts["train"] >= min_counts["min_train"])
        & (counts["val"] >= min_counts["min_val"])
        & (counts["test"] >= min_counts["min_test"])
    ].index
    out["target"] = out["family"].where(out["family"].isin(keep), UNKNOWN)
    return out.drop(columns="family")


def split_category(meta: pd.DataFrame, ratios: dict[str, float], min_train: int) -> pd.DataFrame:
    mal = meta[meta["label"] == 1]
    out = mal[["row", "sha256", "timestamp", "category"]].copy()
    out["split"] = temporal_split(mal, ratios)
    train_counts = out.loc[out["split"] == "train", "category"].value_counts()
    keep = train_counts[train_counts >= min_train].index
    out["target"] = out["category"].where(out["category"].isin(keep), OTHER)
    return out.drop(columns="category")


def class_table(split_frame: pd.DataFrame) -> pd.DataFrame:
    """Число образцов каждого класса в каждой выборке (для отчёта)."""
    table = split_frame.groupby(["target", "split"]).size().unstack(fill_value=0)
    table = table.reindex(columns=SPLITS, fill_value=0)
    table["total"] = table.sum(axis=1)
    return table.sort_values("total", ascending=False)
