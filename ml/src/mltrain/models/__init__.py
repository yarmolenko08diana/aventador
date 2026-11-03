"""Обучение трёх алгоритмов с подбором гиперпараметров на validation.

У каждого модуля одинаковый интерфейс:
    fit(data, cfg, seed, n_jobs, select, log) -> Fitted
где select(y_val, proba_val) -> число (больше = лучше), а Fitted содержит лучшую модель,
её вероятности на validation и журнал всех опробованных вариантов.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class Fitted:
    model: Any
    val_proba: Any
    hyperparameters: dict
    search: list[dict] = field(default_factory=list)
    extra_files: dict = field(default_factory=dict)  # имя файла -> объект (например, скейлер MLP)


def grid(params: dict) -> list[dict]:
    """{'a': [1, 2], 'b': [3]} -> [{'a': 1, 'b': 3}, {'a': 2, 'b': 3}]"""
    keys = sorted(params)
    return [dict(zip(keys, values)) for values in itertools.product(*(params[k] for k in keys))]


Select = Callable[[Any, Any], float]
Log = Callable[[str], None]
