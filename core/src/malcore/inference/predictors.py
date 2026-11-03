"""Единый интерфейс predict_proba для Random Forest, LightGBM, MLP и ансамбля.

Каждый предиктор принимает матрицу векторов EMBER v2 (n x 2381, float32) и возвращает
вероятности (n x C) в порядке классов из manifest.json. Никаких «запасных» значений:
если модель не загрузилась, это ошибка, а не случайный прогноз.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np


class Predictor:
    def __init__(self, manifest: dict):
        self.manifest = manifest
        self.classes: list[str] = manifest["classes"]

    def predict_proba(self, X: np.ndarray) -> np.ndarray:  # pragma: no cover - интерфейс
        raise NotImplementedError

    def _check(self, proba: np.ndarray, n: int) -> np.ndarray:
        if proba.shape != (n, len(self.classes)):
            raise ValueError(f"модель вернула форму {proba.shape}, ожидалась {(n, len(self.classes))}")
        return proba.astype(np.float32)


class RandomForestPredictor(Predictor):
    def __init__(self, manifest: dict, model_dir: Path):
        import joblib

        super().__init__(manifest)
        # joblib-файл — это pickle: загружаем только после проверки sha256 в registry
        self.model = joblib.load(model_dir / "model.joblib")
        self.model.n_jobs = 1  # предсказание одного файла не стоит распараллеливать

    def predict_proba(self, X):
        return self._check(self.model.predict_proba(X), len(X))


class LightGBMPredictor(Predictor):
    def __init__(self, manifest: dict, model_dir: Path):
        import lightgbm as lgb

        super().__init__(manifest)
        self.booster = lgb.Booster(model_file=str(model_dir / "model.txt"))

    def predict_proba(self, X):
        p = self.booster.predict(X, num_iteration=self.booster.best_iteration or None)
        if p.ndim == 1:  # бинарная задача: LightGBM отдаёт вероятность класса 1
            p = np.column_stack([1 - p, p])
        return self._check(p, len(X))


class MLPPredictor(Predictor):
    def __init__(self, manifest: dict, model_dir: Path):
        import torch

        from malcore.inference.mlp_net import MLPNet
        from malcore.preprocessing import Standardizer

        super().__init__(manifest)
        hp = manifest["hyperparameters"]
        self.scaler = Standardizer.load(model_dir / "standardizer.npz")
        self.net = MLPNet(manifest["n_features"], len(self.classes), hp["hidden"], hp["dropout"])
        state = torch.load(model_dir / "model.pt", map_location="cpu", weights_only=True)
        self.net.load_state_dict(state)
        self.net.eval()

    def predict_proba(self, X):
        from malcore.inference.mlp_net import predict_proba

        return self._check(predict_proba(self.net, self.scaler.transform(X)), len(X))


class EnsemblePredictor(Predictor):
    """Среднее вероятностей моделей-участников (раздел 7 ТЗ)."""

    def __init__(self, manifest: dict, members: list[Predictor]):
        super().__init__(manifest)
        for m in members:
            if m.classes != self.classes:
                raise ValueError(f"у участника {m.manifest['algorithm']} другой список классов")
        self.members = members

    def predict_proba(self, X):
        return self._check(np.mean([m.predict_proba(X) for m in self.members], axis=0), len(X))


LOADERS = {"rf": RandomForestPredictor, "lgbm": LightGBMPredictor, "mlp": MLPPredictor}
