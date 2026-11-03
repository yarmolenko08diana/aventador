"""Проверка конвейера обучения на маленьких синтетических данных.

Синтетика нужна только чтобы проверить код: запись артефактов, загрузку через malcore,
выбор порогов на validation, воспроизводимость. Метрики на ней ничего не говорят о BODMAS.
"""

import json
from pathlib import Path

import numpy as np
import pytest
import yaml

from malcore.inference.registry import ModelIntegrityError, load_predictor, read_manifest
from mltrain import metrics, train

from mltrain.synthetic import N_FEATURES, TINY, make_dataset


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


# --- этап 5: оценка на тесте и эксперименты -------------------------------------------------


@pytest.fixture(scope="module")
def evaluated(trained, tmp_path_factory):
    from mltrain import evaluate

    models, args, raw = trained
    reports = tmp_path_factory.mktemp("reports")
    common = ["--splits-dir", args[3], "--models-dir", str(models), "--features", str(raw / "bodmas.npz"),
              "--reports-dir", str(reports)]
    assert evaluate.main(["--all", *common]) == 0
    return models, reports, common


def test_evaluation_files(evaluated):
    models, reports, _ = evaluated
    for task in ("detection", "family", "category"):
        for algo in ("rf", "lgbm", "mlp", "ensemble"):
            ev = json.loads((models / task / algo / "evaluation.json").read_text(encoding="utf-8"))
            assert ev["split"] == "temporal" and ev["n_test"] > 0
            cm = np.asarray(ev["confusion_matrix"])
            assert cm.sum() == ev["n_test"]
        sel = json.loads((models / task / "selection.json").read_text(encoding="utf-8"))
        assert sel["selected"] in ("rf", "lgbm", "mlp", "ensemble")
    fam = json.loads((models / "family" / "rf" / "evaluation.json").read_text(encoding="utf-8"))
    assert fam["open_set"]["n_unknown"] > 0
    det = json.loads((models / "detection" / "lgbm" / "evaluation.json").read_text(encoding="utf-8"))
    assert sum(sum(v.values()) for v in det["verdicts"].values()) == det["n_test"]
    text = (reports / "evaluation.md").read_text(encoding="utf-8")
    assert "## detection" in text and "## family" in text
    for name in ("detection_roc.png", "detection_confusion.png", "family_reliability.png", "category_confusion.png"):
        assert (reports / "figures" / name).stat().st_size > 1000


def test_test_set_is_used_once(evaluated):
    from mltrain import evaluate

    _, _, common = evaluated
    with pytest.raises(SystemExit, match="уже использован"):
        evaluate.main(["--task", "detection", *common])
    assert evaluate.main(["--task", "detection", "--again", *common]) == 0
    marker = json.loads((evaluated[0] / "detection" / "test_evaluated.json").read_text(encoding="utf-8"))
    assert len(marker["runs"]) == 2


def test_experiments(evaluated):
    from mltrain import experiments

    models, reports, common = evaluated
    assert experiments.main([*common, "--n-jobs", "2"]) == 0
    res = json.loads((reports / "experiments.json").read_text(encoding="utf-8"))
    assert set(res["random_split"]) == {"detection", "family", "category"}
    assert 1 <= res["importance"]["detection"]["timestamp_rank"] <= 2381
    assert "roc_auc" in res["timestamp"]["without_timestamp"]
    assert "Случайное разбиение" in (reports / "experiments.md").read_text(encoding="utf-8")
