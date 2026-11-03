"""Проверки этапа 1 на маленьких синтетических данных.

Синтетика здесь только проверяет логику функций; реальные выборки строятся из BODMAS.
"""

import numpy as np
import pandas as pd
import pytest

from mltrain.data.load_bodmas import DataConsistencyError, build_meta
from mltrain.data.splits import (
    UNKNOWN,
    find_duplicate_rows,
    split_category,
    split_detection,
    split_family,
)

RATIOS = {"train": 0.7, "val": 0.1, "test": 0.2}


def make_raw(n_benign=200, n_mal=300, seed=0):
    rng = np.random.default_rng(seed)
    n = n_benign + n_mal
    y = np.array([0] * n_benign + [1] * n_mal, dtype=np.int32)
    benign_times = pd.date_range("2007-01-01", periods=n_benign, freq="7D", tz="UTC")
    mal_times = pd.date_range("2019-08-29", periods=n_mal, freq="h", tz="UTC")
    families = np.array(["alpha"] * 150 + ["beta"] * 140 + ["rare"] * 10)
    metadata = pd.DataFrame(
        {
            "sha": [f"{i:064x}" for i in range(n)],
            "timestamp": list(benign_times.astype(str)) + list(mal_times.astype(str)),
            "family": [np.nan] * n_benign + list(families),
        }
    )
    categories = pd.DataFrame(
        {
            "sha256": metadata["sha"][n_benign:].to_list(),
            "category": ["trojan"] * 200 + ["worm"] * 95 + ["rootkit"] * 5,
        }
    )
    X = rng.random((n, 8), dtype=np.float32)
    return X, y, metadata, categories


def test_build_meta_ok():
    _, y, metadata, categories = make_raw()
    meta = build_meta(y, metadata, categories)
    assert len(meta) == len(y)
    assert meta.loc[meta["label"] == 1, "category"].notna().all()


def test_build_meta_mixed_timestamp_formats():
    # Как в реальном bodmas_metadata.csv: часть строк с поясом, часть без
    _, y, metadata, categories = make_raw()
    metadata.loc[0, "timestamp"] = "2007-01-01 08:46:39+00:00"
    metadata.loc[1, "timestamp"] = "2016-10-30 15:59:55"
    meta = build_meta(y, metadata, categories)
    assert str(meta.loc[1, "timestamp"]) == "2016-10-30 15:59:55+00:00"


def test_build_meta_detects_misaligned_rows():
    _, y, metadata, categories = make_raw()
    y = y[::-1].copy()  # порядок меток больше не совпадает с metadata
    with pytest.raises(DataConsistencyError):
        build_meta(y, metadata, categories)


def test_duplicates_keep_earliest():
    X, y, metadata, categories = make_raw()
    meta = build_meta(y, metadata, categories)
    X[400] = X[250]  # строка 400 позже строки 250 и повторяет её вектор
    mask = find_duplicate_rows(X, meta)
    assert mask.sum() == 1 and mask[400] and not mask[250]


def test_detection_split_is_disjoint_and_temporal():
    _, y, metadata, categories = make_raw()
    meta = build_meta(y, metadata, categories)
    det = split_detection(meta, RATIOS)
    assert det["sha256"].is_unique
    assert set(det["split"]) == {"train", "val", "test"}
    for _, group in det.groupby("target"):
        tr = group[group["split"] == "train"]["timestamp"].max()
        va = group[group["split"] == "val"]
        te = group[group["split"] == "test"]["timestamp"].min()
        assert tr <= va["timestamp"].min() and va["timestamp"].max() <= te
        # оба класса представлены во всех выборках
        assert group["split"].value_counts().min() > 0


def test_family_rare_becomes_unknown():
    _, y, metadata, categories = make_raw()
    meta = build_meta(y, metadata, categories)
    fam = split_family(meta, RATIOS, {"min_train": 5, "min_val": 1, "min_test": 1})
    assert UNKNOWN in set(fam["target"])
    assert "rare" not in set(fam["target"])


def test_category_rare_merged_to_other():
    _, y, metadata, categories = make_raw()
    meta = build_meta(y, metadata, categories)
    cat = split_category(meta, RATIOS, {"min_train": 10, "min_val": 1, "min_test": 1})
    assert "rootkit" not in set(cat["target"])
    assert "other" in set(cat["target"])
