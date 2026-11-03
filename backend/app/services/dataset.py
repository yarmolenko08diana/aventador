"""Режим «образец из тестовой выборки»: готовый вектор BODMAS вместо загруженного файла.

Векторы готовит mltrain.export_demo. Файл vectors.npy открывается через memmap,
поэтому в память читается только нужная строка.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import numpy as np
import pandas as pd
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Analysis, Sample


class DemoUnavailable(Exception):
    pass


@lru_cache(maxsize=4)
def _load(demo_dir: str) -> tuple[pd.DataFrame, np.ndarray]:
    d = Path(demo_dir)
    if not (d / "index.csv").exists():
        raise DemoUnavailable(f"нет {d / 'index.csv'}: запусти python -m mltrain.export_demo")
    index = pd.read_csv(d / "index.csv").set_index("sha256")
    vectors = np.load(d / "vectors.npy", mmap_mode="r")
    return index, vectors


def lookup(demo_dir: Path, sha256: str) -> dict | None:
    index, _ = _load(str(demo_dir))
    if sha256 not in index.index:
        return None
    row = index.loc[sha256]
    truth = {"label": row["label"], "family": None if pd.isna(row["family"]) else row["family"],
             "category": None if pd.isna(row["category"]) else row["category"],
             "category_target": None if pd.isna(row.get("category_target")) else row.get("category_target"),
             "family_in_classifier": bool(row["family_in_classifier"]), "timestamp": str(row["timestamp"])}
    return {"idx": int(row["idx"]), "truth": truth}


def vector(demo_dir: Path, sha256: str) -> np.ndarray:
    found = lookup(demo_dir, sha256)
    if found is None:
        raise KeyError(sha256)
    _, vectors = _load(str(demo_dir))
    return np.array(vectors[found["idx"]], dtype=np.float32)


def examples(demo_dir: Path, per_group: int = 5, seed: int = 0) -> list[dict]:
    """Несколько sha256 для демонстрации: безопасные, известные семейства, неизвестные семейства."""
    index, _ = _load(str(demo_dir))
    df = index.reset_index()
    groups = {
        "benign": df[df["label"] == "benign"],
        "known_family": df[(df["label"] == "malware") & df["family_in_classifier"]],
        "unknown_family": df[(df["label"] == "malware") & ~df["family_in_classifier"]],
    }
    out = []
    for name, g in groups.items():
        for _, r in g.sample(min(per_group, len(g)), random_state=seed).iterrows():
            out.append({"group": name, "sha256": r["sha256"], "label": r["label"],
                        "family": None if pd.isna(r["family"]) else r["family"]})
    return out


def queue_dataset_sample(db: Session, demo_dir: Path, sha256: str) -> Analysis:
    found = lookup(demo_dir, sha256)
    if found is None:
        raise KeyError(sha256)
    sample = db.scalar(select(Sample).where(Sample.sha256 == sha256))
    if sample is None:
        sample = Sample(sha256=sha256, source="dataset", storage_path=None, dataset_truth=found["truth"])
        db.add(sample)
        db.flush()
    analysis = Analysis(sample_id=sample.id, status="queued")
    db.add(analysis)
    db.commit()
    return analysis
