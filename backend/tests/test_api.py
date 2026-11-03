"""Сквозные тесты API и worker на PostgreSQL (критерий этапа 6 из раздела 12 ТЗ):
загрузка безопасного .exe доходит до done с прогнозами всех моделей, испорченный — до failed.
"""

from __future__ import annotations

import os
import stat
import struct
from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parents[2] / "core" / "tests" / "fixtures" / "pe"


def upload(client, path: Path, name: str | None = None):
    with open(path, "rb") as f:
        return client.post("/api/v1/samples", files={"file": (name or path.name, f, "application/octet-stream")})


def test_health_reports_models(client, worker):
    r = client.get("/api/v1/health")
    assert r.status_code == 200
    body = r.json()
    assert body["database"] == "ok" and body["models_ready"] is True
    assert body["active_models"] == {"detection": 4, "family": 4, "category": 4}


def test_upload_benign_exe_goes_to_done(client, worker, benign_exe, env):
    r = upload(client, benign_exe)
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["duplicate"] is False and body["status"] == "queued"
    aid, sha = body["analysis_id"], body["sha256"]

    # Файл лежит в карантине под именем <sha256>.bin и только для чтения
    stored = Path(os.environ["QUARANTINE_DIR"]) / f"{sha}.bin"
    assert stored.exists()
    assert not stored.stat().st_mode & (stat.S_IWUSR | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    assert list(stored.parent.glob(".upload-*")) == []

    assert worker.run_once() >= 1
    a = client.get(f"/api/v1/analyses/{aid}").json()
    assert a["status"] == "done", a
    assert a["verdict"] in ("clean", "suspicious", "malicious")
    assert a["sample"]["original_name"] == benign_exe.name
    assert a["feature_version"] == "ember-v2" and a["duration_ms"] > 0

    preds = client.get(f"/api/v1/analyses/{aid}/predictions").json()
    det = [p for p in preds if p["task"] == "detection"]
    assert {p["algorithm"] for p in det} == {"rf", "lgbm", "mlp", "ensemble"}
    assert sum(p["is_final"] for p in det) == 1
    if a["verdict"] != "clean":
        assert {p["task"] for p in preds} == {"detection", "family", "category"}

    static = client.get(f"/api/v1/analyses/{aid}/static").json()
    assert static["available"] and static["sections"] and static["imports"]
    assert "all_lower" not in static["static_info"]["strings"]
    ind = client.get(f"/api/v1/analyses/{aid}/indicators").json()
    assert ind["available"] is True
    for item in ind["items"]:
        assert item["caveat"] and item["evidence"]


def test_duplicate_returns_previous_analysis_and_rerun_creates_new(client, worker, benign_exe):
    first = upload(client, benign_exe).json()
    assert first["duplicate"] is True
    r = client.post(f"/api/v1/analyses/{first['analysis_id']}/rerun")
    assert r.status_code == 202
    new_id = r.json()["analysis_id"]
    assert new_id != first["analysis_id"]
    worker.run_once()
    assert client.get(f"/api/v1/analyses/{new_id}").json()["status"] == "done"


def test_not_pe_is_rejected(client):
    r = upload(client, FIXTURES / "crafted" / "not_pe.bin")
    assert r.status_code == 415
    assert "MZ" in r.json()["detail"]


def test_too_large_is_rejected(client, tmp_path, monkeypatch):
    from app.config import get_settings

    monkeypatch.setattr(get_settings(), "max_upload_mb", 0)
    r = upload(client, FIXTURES / "benign" / "pip_t64.exe")
    assert r.status_code == 413


def test_broken_pe_goes_to_failed(client, worker, tmp_path):
    broken = tmp_path / "broken.exe"
    broken.write_bytes(b"MZ" + b"\0" * 58 + struct.pack("<I", 0x40) + b"PE\0\0")
    r = upload(client, broken)
    assert r.status_code == 202, r.text
    aid = r.json()["analysis_id"]
    worker.run_once()
    a = client.get(f"/api/v1/analyses/{aid}").json()
    assert a["status"] == "failed"
    assert "File Header" in a["error_message"]
    assert a["verdict"] is None


def test_parse_timeout_is_failed_not_hang(benign_exe):
    from worker.sandboxed_parse import ParseFailed, parse_in_sandbox

    with pytest.raises(ParseFailed, match="не уложился"):
        parse_in_sandbox(benign_exe, timeout=0.01)


def test_dataset_sample(client, worker, env):
    test = env["test_split"]
    sha = test.loc[test["target"] == "malware", "sha256"].iloc[0]
    r = client.post("/api/v1/analyses/from-dataset", json={"sha256": sha})
    assert r.status_code == 202, r.text
    aid = r.json()["analysis_id"]
    worker.run_once()
    a = client.get(f"/api/v1/analyses/{aid}").json()
    assert a["status"] == "done"
    assert a["sample"]["source"] == "dataset" and a["sample"]["dataset_truth"]["label"] == "malware"
    assert client.get(f"/api/v1/analyses/{aid}/indicators").json()["available"] is False
    assert client.get(f"/api/v1/analyses/{aid}/static").json()["available"] is False
    assert client.post("/api/v1/analyses/from-dataset", json={"sha256": "0" * 64}).status_code == 404
    assert len(client.get("/api/v1/dataset/examples?per_group=2").json()) >= 2


def test_history_filters_and_search(client, worker, env):
    all_ = client.get("/api/v1/analyses?limit=200").json()
    assert all_["total"] >= 4
    done = client.get("/api/v1/analyses?status=done").json()
    assert all(i["status"] == "done" for i in done["items"])
    sha = next(i["sample"]["sha256"] for i in all_["items"] if i["sample"]["source"] == "upload")
    found = client.get(f"/api/v1/analyses?q={sha}").json()
    assert found["total"] >= 1 and all(i["sample"]["sha256"] == sha for i in found["items"])
    by_name = client.get("/api/v1/analyses?q=setuptools").json()
    assert by_name["total"] >= 1
    assert client.get("/api/v1/analyses/999999").status_code == 404


def test_models_and_comparison_match_evaluation_files(client, env):
    import json

    models = client.get("/api/v1/models").json()
    assert len(models) == 12
    cmp_ = client.get("/api/v1/models/comparison?task=family").json()
    assert {m["algorithm"] for m in cmp_["models"]} == {"rf", "lgbm", "mlp", "ensemble"}
    for m in cmp_["models"]:
        ev = json.loads((env["models"] / "family" / m["algorithm"] / "evaluation.json").read_text(encoding="utf-8"))
        assert m["test"]["f1_macro"] == pytest.approx(ev["macro_f1"])
    final = [m for m in cmp_["models"] if m["is_final"]]
    sel = json.loads((env["models"] / "family" / "selection.json").read_text(encoding="utf-8"))["selected"]
    assert [m["algorithm"] for m in final] == [sel]
    cm = client.get(f"/api/v1/models/{final[0]['model_id']}/confusion-matrix").json()
    assert len(cm["matrix"]) == len(cm["classes"])

    det = client.get("/api/v1/models/comparison?task=detection").json()["models"][0]
    cur = client.get(f"/api/v1/models/{det['model_id']}/curves").json()
    ev = json.loads((env["models"] / "detection" / det["algorithm"] / "evaluation.json").read_text(encoding="utf-8"))
    assert cur["roc_auc"] == pytest.approx(ev["roc_auc"])
    assert cur["roc"]["fpr"][0] == ev["roc_curve"]["fpr"][0] and cur["roc"]["tpr"][-1] == ev["roc_curve"]["tpr"][-1]
    assert len(cur["roc"]["fpr"]) <= 1000 and cur["reliability"] == ev["reliability"]


def test_alerts_follow_verdicts(client, worker):
    analyses = client.get("/api/v1/analyses?status=done&limit=200").json()["items"]
    flagged = {a["id"] for a in analyses if a["verdict"] in ("suspicious", "malicious")}
    alerts = client.get("/api/v1/alerts?limit=200").json()
    assert {a["analysis_id"] for a in alerts} == flagged
    if alerts:
        aid = alerts[0]["id"]
        before = client.get("/api/v1/alerts/unread-count").json()["unread"]
        r = client.patch(f"/api/v1/alerts/{aid}", json={"is_read": True})
        assert r.status_code == 200 and r.json()["read_at"]
        assert client.get("/api/v1/alerts/unread-count").json()["unread"] == before - 1
        client.post("/api/v1/alerts/read-all")
        assert client.get("/api/v1/alerts/unread-count").json()["unread"] == 0


def test_dashboard(client):
    s = client.get("/api/v1/dashboard/stats").json()
    assert s["total_analyses"] >= 4
    assert set(s["by_verdict"]) == {"clean", "suspicious", "malicious"}
    assert s["timeline"]


def test_roc_downsample_keeps_ends_and_order():
    from app.api.v1.models import _downsample

    fpr = [i / 4999 for i in range(5000)]
    tpr = [min(1.0, 2 * x) for x in fpr]
    out = _downsample(fpr, tpr, max_points=1000)
    assert len(out["fpr"]) <= 1000
    assert out["fpr"][0] == 0.0 and out["fpr"][-1] == 1.0 and out["tpr"][-1] == 1.0
    assert out["fpr"] == sorted(out["fpr"])
    assert _downsample([0.0, 1.0], [0.0, 1.0]) == {"fpr": [0.0, 1.0], "tpr": [0.0, 1.0]}
