"""FastAPI-приложение. Запуск для разработки (из папки backend):

    uvicorn app.main:app --reload

Документация Swagger: http://localhost:8000/docs
API никогда не разбирает PE-файлы сам: это делает только worker (python -m worker.main).
"""

from __future__ import annotations

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.api.v1 import alerts, analyses, dashboard, models, reports, samples
from app.config import get_settings
from app.db.models import ModelVersion
from app.db.session import get_db
from malcore.features.vector import FEATURE_VERSION

app = FastAPI(
    title="Malscan: статический анализ PE и классификация семейств ВПО",
    version="0.6.0",
    description="Файлы не запускаются. Загрузка → разбор в изолированном процессе → индикаторы и прогнозы моделей.",
)
app.add_middleware(CORSMiddleware, allow_origins=get_settings().cors_origins, allow_methods=["*"], allow_headers=["*"])

PREFIX = "/api/v1"
for module in (samples, analyses, reports, models, alerts, dashboard):
    app.include_router(module.router, prefix=PREFIX)


@app.get(f"{PREFIX}/health", tags=["Служебное"])
def health(db: Session = Depends(get_db)) -> dict:
    """Состояние БД и импортированных моделей."""
    db.execute(text("select 1"))
    active = dict(db.execute(select(ModelVersion.task, func.count()).where(ModelVersion.is_active)
                             .group_by(ModelVersion.task)).all())
    return {"database": "ok", "feature_version": FEATURE_VERSION, "active_models": active,
            "models_ready": all(active.get(t, 0) == 4 for t in ("detection", "family", "category"))}
