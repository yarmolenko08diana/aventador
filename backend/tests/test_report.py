"""PDF-отчёт (этап 9): файл открывается, кириллица читается, данные совпадают с API."""

from __future__ import annotations

import io
import shutil
from pathlib import Path

from pypdf import PdfReader

FIXTURES = Path(__file__).resolve().parents[2] / "core" / "tests" / "fixtures" / "pe"
ALGOS = ("Random Forest", "LightGBM", "MLP", "Ансамбль")
VERDICT = {"clean": "БЕЗОПАСНЫЙ", "suspicious": "ПОДОЗРИТЕЛЬНЫЙ", "malicious": "ВРЕДОНОСНЫЙ"}


def pdf_text(content: bytes) -> str:
    reader = PdfReader(io.BytesIO(content))
    return "\n".join(page.extract_text() for page in reader.pages)


def get_pdf(client, aid: int) -> tuple[bytes, str]:
    r = client.get(f"/api/v1/analyses/{aid}/report.pdf")
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/pdf"
    assert r.content.startswith(b"%PDF")
    return r.content, r.headers["content-disposition"]


def test_report_for_uploaded_file(client, worker):
    # Имя с разметкой: ReportLab не должен воспринять его как теги
    name = "<b>отчёт & тест</b>.exe"
    with open(FIXTURES / "benign" / "setuptools_gui-64.exe", "rb") as f:
        r = client.post("/api/v1/samples", files={"file": (name, f, "application/octet-stream")})
    aid, sha = r.json()["analysis_id"], r.json()["sha256"]
    worker.run_once()
    a = client.get(f"/api/v1/analyses/{aid}").json()
    assert a["status"] == "done"

    content, disposition = get_pdf(client, aid)
    assert f"report-{sha}.pdf" in disposition
    text = pdf_text(content)
    assert "Отчёт статического анализа файла" in text
    assert a["sample"]["original_name"] in text
    assert sha in text.replace("\n", "")
    assert VERDICT[a["verdict"]] in text
    assert f"{a['detector_score']:.4f}" in text
    for algo in ALGOS:
        assert algo in text
    # Версии моделей из отчёта совпадают с ответом API
    for p in client.get(f"/api/v1/analyses/{aid}/predictions").json():
        assert p["model_version"] in text
    assert "Структура PE-файла" in text and ".text" in text
    assert "Ограничения метода" in text


def test_report_for_dataset_sample_compares_with_truth(client, worker, env):
    test = env["test_split"]
    sha = test[test["target"] == "malware"]["sha256"].iloc[-1]
    aid = client.post("/api/v1/analyses/from-dataset", json={"sha256": sha}).json()["analysis_id"]
    worker.run_once()
    a = client.get(f"/api/v1/analyses/{aid}").json()
    text = pdf_text(get_pdf(client, aid)[0])
    assert "Сравнение с правильным ответом" in text
    assert "Не строятся" in text  # индикаторов у вектора нет
    if a["verdict"] != "clean":
        assert "Семейство" in text and "Категория" in text


def test_report_needs_finished_analysis(client, tmp_path):
    path = tmp_path / "queued.exe"
    shutil.copy(FIXTURES / "benign" / "setuptools_gui-32.exe", path)
    with open(path, "rb") as f:
        aid = client.post("/api/v1/samples", files={"file": (path.name, f, "application/octet-stream")}).json()["analysis_id"]
    assert client.get(f"/api/v1/analyses/{aid}/report.pdf").status_code == 409
    assert client.get("/api/v1/analyses/999999/report.pdf").status_code == 404
