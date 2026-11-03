"""Конвейер прогноза malcore.inference.pipeline на моделях, обученных на синтетике."""

import json

import numpy as np
import pytest

from malcore.inference import pipeline
from mltrain.synthetic import build_models


@pytest.fixture(scope="module")
def setup(tmp_path_factory):
    paths = build_models(tmp_path_factory.mktemp("pipe"))
    models = pipeline.load_models(paths["models"])
    X = np.load(paths["raw"] / "bodmas.npz")["X"]
    y = np.load(paths["raw"] / "bodmas.npz")["y"]
    return paths, models, X, y


def test_every_model_answers_for_malicious_file(setup):
    _, models, X, y = setup
    # Берём образец, который итоговый детектор считает вредоносным
    for i in np.where(y == 1)[0]:
        res = pipeline.predict(models, X[i])
        if res.verdict != "clean":
            break
    else:
        pytest.fail("ни один вредоносный образец не получил вердикт suspicious/malicious")
    tasks = {(p.task, p.algorithm) for p in res.predictions}
    assert tasks == {(t, a) for t in pipeline.TASKS for a in pipeline.ALGORITHMS}
    for task in pipeline.TASKS:
        finals = [p for p in res.predictions if p.task == task and p.is_final]
        assert len(finals) == 1
    assert res.final_category is not None
    assert res.family_status in ("identified", "unknown")
    if res.family_status == "identified":
        assert res.final_family in models["family"].final.classes
    for p in res.predictions:
        assert 1 <= len(p.top_k) <= 3 and abs(p.top_k[0]["probability"] - p.confidence) < 1e-6


def test_clean_file_skips_stage_b(setup):
    _, models, X, y = setup
    for i in np.where(y == 0)[0]:
        res = pipeline.predict(models, X[i])
        if res.verdict == "clean":
            break
    else:
        pytest.fail("ни один безопасный образец не получил вердикт clean")
    assert {p.task for p in res.predictions} == {"detection"}
    assert res.family_status == "not_applicable" and res.final_family is None


def test_verdict_uses_validation_thresholds(setup):
    _, models, X, _ = setup
    thr = models["detection"].final.manifest["thresholds"]
    assert pipeline.verdict_for(thr["malicious"], thr) == "malicious"
    assert pipeline.verdict_for((thr["malicious"] + thr["suspicious"]) / 2, thr) in ("suspicious", "malicious")
    assert pipeline.verdict_for(0.0, thr) == "clean" or thr["suspicious"] <= 0.0


def test_low_confidence_family_is_unknown(setup):
    paths, models, X, y = setup
    fam = models["family"]
    fam.final.manifest["thresholds"]["unknown_confidence"] = 1.01  # никакая уверенность не проходит
    try:
        for i in np.where(y == 1)[0]:
            res = pipeline.predict(models, X[i])
            if res.verdict != "clean":
                assert res.family_status == "unknown" and res.final_family is None
                assert res.family_confidence is not None
                return
    finally:
        saved = json.loads((paths["models"] / "family" / fam.selected / "manifest.json").read_text(encoding="utf-8"))
        fam.final.manifest["thresholds"] = saved["thresholds"]
    pytest.fail("нет вредоносного образца с вердиктом не clean")


def test_wrong_vector_size_is_rejected(setup):
    _, models, _, _ = setup
    with pytest.raises(ValueError):
        pipeline.predict(models, np.zeros(100, dtype=np.float32))


def test_missing_selection_is_an_error(setup, tmp_path):
    with pytest.raises(FileNotFoundError):
        pipeline.load_models(tmp_path)
