"""Проверка конвейера обучения на маленьких синтетических данных.

Синтетика нужна только чтобы проверить код: запись артефактов, загрузку через malcore,
выбор порогов на validation, воспроизводимость. Метрики на ней ничего не говорят о BODMAS.
"""

from pathlib import Path

import numpy as np
import pandas as pd
import pytest
import yaml

from malcore.inference.registry import ModelIntegrityError, load_predictor, read_manifest
from mltrain import metrics, train

N_FEATURES = 2381
TINY = {
    "seed": 7,
    "n_jobs": 2,
    "detection_verdict_fpr": {"malicious": 0.01, "suspicious": 0.05},
    "rf": {"grid": {"n_estimators": [20], "max_depth": [None, 6], "max_features": ["sqrt"], "min_samples_leaf": [1]}},
    "lgbm": {"fixed": {"learning_rate": 0.1, "min_child_samples": 5}, "grid": {"num_leaves": [7, 15]},
             "max_rounds": 60, "early_stopping": 10},
    "mlp": {"fixed": {"batch_size": 64, "max_epochs": 4, "patience": 2, "weight_decay": 0.0},
            "grid": {"hidden": [[32]], "dropout": [0.1], "lr": [0.003]}},
}


def make_dataset(tmp: Path, n: int = 900, seed: int = 0) -> tuple[Path, Path]:
    """bodmas.npz + data/splits/*.csv в том же формате, что создаёт этап 1."""
    rng = np.random.default_rng(seed)
    label = rng.integers(0, 2, n)
    family = np.where(label == 1, rng.choice(["fa", "fb", "fc", "rare"], n, p=[0.35, 0.3, 0.25, 0.1]), "")
    X = rng.normal(0, 1, (n, N_FEATURES)).astype(np.float32)
    X[:, :256] = np.abs(X[:, :256])  # неотрицательные «гистограммы»: к ним MLP применит log1p
    X[:, 0] += label * 2.0  # сигнал для обнаружения
    for i, f in enumerate(["fa", "fb", "fc"]):
        X[family == f, 10 + i] += 3.0  # сигнал для семейств
    raw = tmp / "raw"
    raw.mkdir()
    np.savez(raw / "bodmas.npz", X=X, y=label)

    splits = tmp / "splits"
    splits.mkdir()
    split = np.array(["train"] * int(n * 0.7) + ["val"] * int(n * 0.1) + ["test"] * (n - int(n * 0.7) - int(n * 0.1)))
    base = pd.DataFrame({"row": np.arange(n), "sha256": [f"{i:064x}" for i in range(n)],
                         "timestamp": "2020-01-01", "split": split})
    det = base.assign(target=np.where(label == 1, "malware", "benign"))
    det.to_csv(splits / "detection.csv", index=False)
    mal = base[label == 1].copy()
    fam = np.where(family[label == 1] == "rare", metrics.UNKNOWN, family[label == 1])
    mal.assign(target=fam).to_csv(splits / "family.csv", index=False)
    mal.assign(target=np.where(fam == "fa", "trojan", "worm")).to_csv(splits / "category.csv", index=False)
    return raw, splits


@pytest.fixture(scope="module")
def trained(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("bodmas")
    raw, splits = make_dataset(tmp)
    cfg_path = tmp / "train.yaml"
    cfg_path.write_text(yaml.safe_dump(TINY), encoding="utf-8")
    models = tmp / "models"
    args = ["--config", str(cfg_path), "--splits-dir", str(splits), "--models-dir", str(models),
            "--features", str(raw / "bodmas.npz")]
    assert train.main(["--all", *args]) == 0
    return models, args, raw


@pytest.mark.parametrize("task", ["detection", "family", "category"])
@pytest.mark.parametrize("algo", ["rf", "lgbm", "mlp", "ensemble"])
def test_artifacts_and_reload(trained, task, algo):
    models, _, raw = trained
    model_dir = models / task / algo
    man = read_manifest(model_dir)
    assert man["task"] == task and man["algorithm"] == algo
    assert man["feature_version"] == "ember-v2" and man["n_features"] == N_FEATURES
    assert man["evaluated_on_test"] is False
    assert man["data"]["test_not_loaded"] > 0
    if algo != "ensemble":
        assert man["reload_check"]["passed"]
        assert (model_dir / "train.log").read_text(encoding="utf-8").strip()
        assert len(man["search"]) >= 1
    # Загрузка так, как это сделает сервис, и предсказание на новых векторах
    X = np.load(raw / "bodmas.npz")["X"][:5]
    proba = load_predictor(model_dir).predict_proba(X)
    assert proba.shape == (5, len(man["classes"]))
    assert np.allclose(proba.sum(axis=1), 1.0, atol=1e-4)


def test_family_excludes_unknown_and_has_threshold(trained):
    models, _, _ = trained
    man = read_manifest(models / "family" / "lgbm")
    assert metrics.UNKNOWN not in man["classes"] and man["classes"] == ["fa", "fb", "fc"]
    assert man["data"]["val_unknown"] > 0
    assert 0.0 <= man["thresholds"]["unknown_confidence"] <= 1.0
    assert "open_set" in man["validation"]


def test_detection_thresholds_respect_fpr(trained):
    models, _, _ = trained
    man = read_manifest(models / "detection" / "rf")
    val = man["validation"]
    assert val["malicious_fpr"] <= 0.01 + 1e-9 and val["suspicious_fpr"] <= 0.05 + 1e-9
    assert man["thresholds"]["malicious"] >= man["thresholds"]["suspicious"]


def test_tampered_model_is_rejected(trained, tmp_path):
    import shutil

    models, _, _ = trained
    copy = tmp_path / "lgbm"
    shutil.copytree(models / "detection" / "lgbm", copy)
    with open(copy / "model.txt", "a", encoding="utf-8") as f:
        f.write("\n")
    with pytest.raises(ModelIntegrityError):
        load_predictor(copy)


@pytest.mark.parametrize("algo", ["rf", "lgbm", "mlp"])
def test_reproducible(trained, algo):
    _, args, _ = trained
    assert train.main(["--task", "family", "--model", algo, "--verify", *args]) == 0


def test_threshold_at_fpr():
    y = np.array([0] * 100 + [1] * 10)
    score = np.concatenate([np.linspace(0, 0.9, 100), np.full(10, 0.95)])
    thr = metrics.threshold_at_fpr(y, score, 0.05)
    assert (score[y == 0] >= thr).mean() <= 0.05
    assert (score[y == 1] >= thr).all()


def test_unknown_threshold_rejects_low_confidence():
    known = np.array([[0.9, 0.1], [0.1, 0.9], [0.85, 0.15]])
    unknown = np.array([[0.55, 0.45], [0.5, 0.5]])
    res = metrics.choose_unknown_threshold(np.array([0, 1, 0]), known, unknown)
    assert res["unknown_rejected"] == 1.0 and res["known_rejected"] == 0.0
