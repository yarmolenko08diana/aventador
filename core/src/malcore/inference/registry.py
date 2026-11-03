"""Загрузка обученных моделей по manifest.json с проверками.

Перед загрузкой проверяется:
- feature_version модели совпадает с версией экстрактора в malcore (иначе векторы несовместимы);
- sha256 каждого файла модели совпадает с записанным при обучении (файл не подменён и не испорчен).

Раскладка каталога моделей:
    artifacts/models/<task>/<algorithm>/manifest.json + файлы модели
    artifacts/models/<task>/ensemble/manifest.json      (ссылается на участников)
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from malcore.features.vector import FEATURE_VERSION, VECTOR_SIZE
from malcore.inference.predictors import LOADERS, EnsemblePredictor, Predictor


class ModelIntegrityError(RuntimeError):
    """Модель нельзя использовать: файлы изменены или признаки несовместимы."""


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def read_manifest(model_dir: Path) -> dict:
    return json.loads((Path(model_dir) / "manifest.json").read_text(encoding="utf-8"))


def verify(model_dir: Path, manifest: dict) -> None:
    if manifest["feature_version"] != FEATURE_VERSION:
        raise ModelIntegrityError(
            f"{model_dir}: модель обучена на признаках {manifest['feature_version']}, "
            f"а экстрактор выдаёт {FEATURE_VERSION}"
        )
    if manifest["n_features"] != VECTOR_SIZE:
        raise ModelIntegrityError(f"{model_dir}: ожидалось {VECTOR_SIZE} признаков, в модели {manifest['n_features']}")
    for name, expected in manifest.get("files", {}).items():
        path = Path(model_dir) / name
        if not path.exists():
            raise ModelIntegrityError(f"{model_dir}: нет файла {name}")
        if sha256_file(path) != expected:
            raise ModelIntegrityError(f"{model_dir}: sha256 файла {name} не совпадает с manifest")


def load_predictor(model_dir: Path) -> Predictor:
    model_dir = Path(model_dir)
    manifest = read_manifest(model_dir)
    verify(model_dir, manifest)
    algo = manifest["algorithm"]
    if algo == "ensemble":
        members = [load_predictor(model_dir.parent / m) for m in manifest["members"]]
        return EnsemblePredictor(manifest, members)
    if algo not in LOADERS:
        raise ModelIntegrityError(f"{model_dir}: неизвестный алгоритм {algo}")
    return LOADERS[algo](manifest, model_dir)
