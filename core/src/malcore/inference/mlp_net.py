"""Архитектура MLP. Одна и та же для обучения (ml) и для сервиса (backend)."""

from __future__ import annotations

import torch
from torch import nn


class MLPNet(nn.Module):
    """n_features -> hidden[0] -> hidden[1] -> ... -> n_classes (логиты, без softmax)."""

    def __init__(self, n_features: int, n_classes: int, hidden: list[int], dropout: float):
        super().__init__()
        layers: list[nn.Module] = []
        size = n_features
        for width in hidden:
            layers += [nn.Linear(size, width), nn.BatchNorm1d(width), nn.ReLU(), nn.Dropout(dropout)]
            size = width
        layers.append(nn.Linear(size, n_classes))
        self.net = nn.Sequential(*layers)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


def predict_proba(model: MLPNet, X, batch: int = 4096):
    """Вероятности классов (numpy, n x C) в режиме eval: без dropout, BatchNorm по статистике train."""
    import numpy as np

    model.eval()
    out = []
    with torch.no_grad():
        for start in range(0, len(X), batch):
            xb = torch.from_numpy(np.ascontiguousarray(X[start : start + batch], dtype=np.float32))
            out.append(torch.softmax(model(xb), dim=1).numpy())
    return np.concatenate(out) if out else np.zeros((0, model.net[-1].out_features), dtype=np.float32)
