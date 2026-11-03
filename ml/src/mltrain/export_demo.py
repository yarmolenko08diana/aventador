"""Векторы тестовой выборки BODMAS для режима «образец из тестовой выборки» (раздел 3 ТЗ).

    python -m mltrain.export_demo

Создаёт data/processed/demo/:
    vectors.npy  — векторы EMBER v2 только тестовых образцов (float32), сервис читает их через memmap;
    index.csv    — sha256, номер строки в vectors.npy, истинные метка, семейство, категория
                   (исходная и в классах модели), дата.

Берутся только образцы из test: модели их не видели ни при обучении, ни при подборе порогов.
Самих файлов нет, поэтому индикаторы в этом режиме не строятся.
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

from mltrain.data.load_bodmas import ROOT, load_bodmas
from mltrain.datasets import SPLITS_DIR, read_split
from mltrain.metrics import UNKNOWN

OUT_DIR = ROOT / "data" / "processed" / "demo"


def main(out_dir: Path = OUT_DIR) -> int:
    det, _ = read_split("detection", SPLITS_DIR)
    fam, _ = read_split("family", SPLITS_DIR)
    cat, _ = read_split("category", SPLITS_DIR)
    test = det[det["split"] == "test"].reset_index(drop=True)
    known = set(fam.loc[(fam["split"] == "test") & (fam["target"] != UNKNOWN), "sha256"])

    print("Загрузка BODMAS...", flush=True)
    data = load_bodmas()
    meta = data.meta.set_index("row")
    rows = test["row"].to_numpy()
    index = test[["sha256", "timestamp"]].copy()
    index["idx"] = np.arange(len(test))
    index["label"] = test["target"]
    index["family"] = meta.loc[rows, "family"].to_numpy()
    index["category"] = meta.loc[rows, "category"].to_numpy()
    index["family_in_classifier"] = index["sha256"].isin(known)
    # Категория так, как её знает классификатор: редкие объединены в other на этапе 1
    index["category_target"] = index["sha256"].map(cat.set_index("sha256")["target"])

    out_dir.mkdir(parents=True, exist_ok=True)
    np.save(out_dir / "vectors.npy", data.X[rows])
    index.to_csv(out_dir / "index.csv", index=False)
    print(f"Сохранено {len(index)} тестовых образцов в {out_dir}")
    print(index.groupby("label").size().to_string())
    return 0


if __name__ == "__main__":
    sys.exit(main())
