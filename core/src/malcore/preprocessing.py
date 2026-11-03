"""Предобработка вектора EMBER v2 для MLP (раздел 7 ТЗ).

Деревья (Random Forest, LightGBM) работают с сырыми признаками. Нейросети нужны признаки
одного масштаба, а в EMBER рядом стоят доли от 0 до 1 и размеры в миллионы байт. Поэтому:
1) к столбцам, которые на train всегда >= 0 (счётчики, размеры), применяем log1p;
2) затем стандартизуем: (x - mean) / std, где mean и std посчитаны ТОЛЬКО на train;
3) обрезаем до [-CLIP, CLIP], чтобы один выброс в новом файле не «взорвал» сеть.

Параметры хранятся в .npz (только числовые массивы, без pickle), чтобы сервис мог
загрузить их без выполнения кода из файла.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import numpy as np

CLIP = 10.0


@dataclass
class Standardizer:
    log_mask: np.ndarray  # bool (n_features,): где применять log1p
    mean: np.ndarray  # float32 (n_features,)
    std: np.ndarray  # float32 (n_features,), нули заменены на 1

    @classmethod
    def fit(cls, X: np.ndarray, chunk: int = 20000) -> "Standardizer":
        log_mask = X.min(axis=0) >= 0
        # Среднее и дисперсия по кускам, чтобы не держать в памяти вторую копию X
        n, total, total_sq = 0, np.zeros(X.shape[1]), np.zeros(X.shape[1])
        for start in range(0, len(X), chunk):
            part = _log(X[start : start + chunk], log_mask).astype(np.float64)
            n += len(part)
            total += part.sum(axis=0)
            total_sq += (part**2).sum(axis=0)
        mean = total / n
        std = np.sqrt(np.maximum(total_sq / n - mean**2, 0.0))
        std[std < 1e-8] = 1.0  # постоянный на train признак не масштабируем
        return cls(log_mask, mean.astype(np.float32), std.astype(np.float32))

    def transform(self, X: np.ndarray) -> np.ndarray:
        out = (_log(X, self.log_mask) - self.mean) / self.std
        return np.clip(out, -CLIP, CLIP).astype(np.float32)

    def save(self, path: Path) -> None:
        np.savez(path, log_mask=self.log_mask, mean=self.mean, std=self.std)

    @classmethod
    def load(cls, path: Path) -> "Standardizer":
        with np.load(path, allow_pickle=False) as d:
            return cls(d["log_mask"], d["mean"], d["std"])


def _log(X: np.ndarray, mask: np.ndarray) -> np.ndarray:
    out = np.array(X, dtype=np.float32, copy=True)
    # на новых файлах признак может оказаться отрицательным: такие значения считаем нулём
    out[:, mask] = np.log1p(np.maximum(out[:, mask], 0.0))
    return out
