"""MLP (PyTorch): log1p + стандартизация по train, взвешенная cross-entropy, ранняя остановка."""

from __future__ import annotations

import copy
import time
from pathlib import Path

import numpy as np
import torch

from malcore.inference.mlp_net import MLPNet, predict_proba
from malcore.preprocessing import Standardizer
from mltrain.datasets import balanced_weights
from mltrain.models import Fitted, Log, Select, grid

ALGORITHM = "mlp"
MODEL_FILE = "model.pt"
SCALER_FILE = "standardizer.npz"


def _train_one(Xtr, ytr, Xva, yva, n_classes, params, fixed, seed, select, log) -> tuple:
    torch.manual_seed(seed)
    net = MLPNet(Xtr.shape[1], n_classes, params["hidden"], params["dropout"])
    opt = torch.optim.Adam(net.parameters(), lr=params["lr"], weight_decay=fixed["weight_decay"])
    loss_fn = torch.nn.CrossEntropyLoss(weight=torch.from_numpy(balanced_weights(ytr, n_classes)))
    Xt, yt = torch.from_numpy(Xtr), torch.from_numpy(ytr)
    rng = np.random.default_rng(seed)
    batch = fixed["batch_size"]

    best_score, best_state, best_epoch, best_proba, stale = -np.inf, None, 0, None, 0
    for epoch in range(1, fixed["max_epochs"] + 1):
        net.train()
        order = torch.from_numpy(rng.permutation(len(Xtr)))
        total = 0.0
        for start in range(0, len(order), batch):
            idx = order[start : start + batch]
            if len(idx) < 2:  # BatchNorm не работает на одном образце
                continue
            opt.zero_grad()
            loss = loss_fn(net(Xt[idx]), yt[idx])
            loss.backward()
            opt.step()
            total += float(loss) * len(idx)
        proba = predict_proba(net, Xva)
        score = select(yva, proba)
        log(f"    эпоха {epoch}: loss {total / len(Xtr):.4f}, val {score:.5f}")
        if score > best_score + 1e-6:
            best_score, best_state, best_epoch, best_proba, stale = score, copy.deepcopy(net.state_dict()), epoch, proba, 0
        else:
            stale += 1
            if stale >= fixed["patience"]:
                break
    net.load_state_dict(best_state)
    return net, best_proba, best_score, best_epoch


def fit(data, cfg: dict, seed: int, n_jobs: int, select: Select, log: Log) -> Fitted:
    torch.set_num_threads(n_jobs)
    torch.use_deterministic_algorithms(True)
    scaler = Standardizer.fit(data.X_train)  # только train: validation не влияет на масштаб
    Xtr, Xva = scaler.transform(data.X_train), scaler.transform(data.X_val)
    fixed = cfg["fixed"]

    best, search = None, []
    for params in grid(cfg["grid"]):
        start = time.time()
        log(f"  mlp {params}")
        net, proba, score, epoch = _train_one(
            Xtr, data.y_train, Xva, data.y_val, len(data.classes), params, fixed, seed, select, log
        )
        seconds = round(time.time() - start, 1)
        search.append({"params": {**params, "best_epoch": epoch}, "val_score": score, "seconds": seconds})
        log(f"  mlp {params}: val {score:.5f}, лучшая эпоха {epoch} ({seconds} с)")
        if best is None or score > best[0]:
            best = (score, net, proba, {**fixed, **params, "best_epoch": epoch})
    _, net, proba, params = best
    return Fitted(model=net, val_proba=proba, hyperparameters=params, search=search, extra_files={SCALER_FILE: scaler})


def save(fitted: Fitted, out_dir: Path) -> list[str]:
    torch.save(fitted.model.state_dict(), out_dir / MODEL_FILE)
    fitted.extra_files[SCALER_FILE].save(out_dir / SCALER_FILE)
    return [MODEL_FILE, SCALER_FILE]
