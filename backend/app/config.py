"""Настройки backend из переменных окружения или файла .env в корне репозитория."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=ROOT / ".env", extra="ignore")

    database_url: str = "postgresql+psycopg://malscan:change-me@localhost:5433/malscan"
    # Карантин: файлы лежат под именем <sha256>.bin, только для чтения, вне веб-корня
    quarantine_dir: Path = ROOT / "quarantine"
    models_dir: Path = ROOT / "artifacts" / "models"
    # Векторы тестовой выборки BODMAS для режима «образец из теста» (mltrain.export_demo)
    demo_dir: Path = ROOT / "data" / "processed" / "demo"
    max_upload_mb: int = 50
    parse_timeout_seconds: int = 60
    parse_memory_mb: int = 1024  # лимит памяти дочернего процесса разбора
    worker_poll_seconds: float = 1.0
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
