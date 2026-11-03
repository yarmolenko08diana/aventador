"""Общая подготовка тестов backend.

- Отдельная БД <имя>_test на том же PostgreSQL (создаётся заново, схема — миграциями Alembic).
- Модели обучаются на маленькой синтетике (mltrain.synthetic) и проходят этап 5, как настоящие.
- Карантин и «образцы из теста» — во временных папках.
Настоящий BODMAS и настоящие модели тестам не нужны.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import numpy as np
import pandas as pd
import psycopg
import pytest
from sqlalchemy.engine import make_url

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
FIXTURES = ROOT / "core" / "tests" / "fixtures" / "pe"


def _base_url() -> str:
    url = os.environ.get("DATABASE_URL")
    if not url and (ROOT / ".env").exists():
        for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
            if line.startswith("DATABASE_URL="):
                url = line.split("=", 1)[1].strip()
    return url or "postgresql+psycopg://malscan:change-me@localhost:5433/malscan"


@pytest.fixture(scope="session")
def env(tmp_path_factory):
    from mltrain.synthetic import build_models

    base = make_url(_base_url())
    test_db = f"{base.database}_test"
    admin = base.set(drivername="postgresql").render_as_string(hide_password=False)
    with psycopg.connect(admin, autocommit=True) as conn:
        conn.execute(f'DROP DATABASE IF EXISTS "{test_db}" WITH (FORCE)')
        conn.execute(f'CREATE DATABASE "{test_db}"')
    tmp = tmp_path_factory.mktemp("backend")
    paths = build_models(tmp / "ml")

    # Векторы теста синтетики в формате mltrain.export_demo
    split = pd.read_csv(paths["splits"] / "detection.csv")
    test = split[split["split"] == "test"].reset_index(drop=True)
    X = np.load(paths["raw"] / "bodmas.npz")["X"]
    demo = tmp / "demo"
    demo.mkdir()
    np.save(demo / "vectors.npy", X[test["row"].to_numpy()])
    pd.DataFrame({"sha256": test["sha256"], "timestamp": test["timestamp"], "idx": np.arange(len(test)),
                  "label": test["target"], "family": np.where(test["target"] == "malware", "fa", None),
                  "category": np.where(test["target"] == "malware", "trojan", None),
                  "family_in_classifier": test["target"] == "malware"}).to_csv(demo / "index.csv", index=False)

    os.environ.update(
        DATABASE_URL=base.set(database=test_db).render_as_string(hide_password=False),
        QUARANTINE_DIR=str(tmp / "quarantine"), MODELS_DIR=str(paths["models"]), DEMO_DIR=str(demo),
        PARSE_TIMEOUT_SECONDS="30", WORKER_POLL_SECONDS="0.1",
    )
    from app.config import get_settings
    from app.db.session import get_engine, get_sessionmaker

    for f in (get_settings, get_engine, get_sessionmaker):
        f.cache_clear()

    from alembic import command
    from alembic.config import Config

    cfg = Config(str(BACKEND / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND / "alembic"))
    command.upgrade(cfg, "head")
    yield {"tmp": tmp, "demo": demo, "test_split": test, **paths}
    get_engine().dispose()


@pytest.fixture(scope="session")
def client(env):
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def worker(env):
    from app.config import get_settings
    from worker.main import Worker

    return Worker(get_settings())


@pytest.fixture
def benign_exe(tmp_path) -> Path:
    path = tmp_path / "setuptools_cli-64.exe"
    shutil.copy(FIXTURES / "benign" / "setuptools_cli-64.exe", path)
    return path
