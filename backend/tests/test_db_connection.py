"""Проверка этапа 0: PostgreSQL из docker compose доступна.

Тест читает DATABASE_URL из окружения или из .env в корне репозитория.
Если БД не запущена, тест падает с понятной причиной (а не пропускается),
потому что это критерий готовности этапа 0.
"""

import os
from pathlib import Path

import psycopg

ROOT = Path(__file__).resolve().parents[2]


def _database_url() -> str:
    url = os.environ.get("DATABASE_URL")
    env_file = ROOT / ".env"
    if not url and env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            if line.startswith("DATABASE_URL="):
                url = line.split("=", 1)[1].strip()
    assert url, "DATABASE_URL не задан: выполните `make env`"
    # psycopg принимает обычный DSN без указания драйвера SQLAlchemy
    return url.replace("postgresql+psycopg://", "postgresql://")


def test_postgres_answers():
    with psycopg.connect(_database_url(), connect_timeout=5) as conn:
        version = conn.execute("select version()").fetchone()[0]
    assert "PostgreSQL 16" in version
