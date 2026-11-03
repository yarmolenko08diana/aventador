"""POST /samples — загрузка файла; POST /analyses/from-dataset — образец из тестовой выборки."""

from __future__ import annotations

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.session import get_db
from app.schemas.api import DatasetRequest, UploadOut
from app.services import dataset
from app.services.upload import UploadError, accept_upload

router = APIRouter(tags=["Загрузка"])


@router.post("/samples", status_code=202, response_model=UploadOut,
             responses={413: {"description": "Файл больше лимита"}, 415: {"description": "Не PE-файл"}})
def upload_sample(file: UploadFile = File(...), db: Session = Depends(get_db)) -> UploadOut:
    """Принимает файл, проверяет сигнатуры MZ/PE, считает хеши и ставит анализ в очередь.

    Если такой SHA-256 уже анализировался, возвращает прошлый анализ (duplicate=true);
    повторный анализ — POST /analyses/{id}/rerun.
    """
    s = get_settings()
    try:
        res = accept_upload(db, file.file, file.filename, s.quarantine_dir, s.max_upload_bytes)
    except UploadError as exc:
        raise HTTPException(exc.status_code, exc.message) from exc
    return UploadOut(analysis_id=res.analysis_id, sha256=res.sha256, duplicate=res.duplicate, status=res.status)


@router.post("/analyses/from-dataset", status_code=202, response_model=UploadOut, tags=["Образец из теста"])
def analyze_dataset_sample(body: DatasetRequest, db: Session = Depends(get_db)) -> UploadOut:
    """Прогоняет готовый вектор образца из тестовой выборки BODMAS через те же модели.

    Индикаторов не будет: самого файла нет, есть только вектор признаков.
    """
    sha = body.sha256.strip().lower()
    try:
        analysis = dataset.queue_dataset_sample(db, get_settings().demo_dir, sha)
    except dataset.DemoUnavailable as exc:
        raise HTTPException(503, str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(404, "Такого sha256 нет в тестовой выборке") from exc
    return UploadOut(analysis_id=analysis.id, sha256=sha, duplicate=False, status=analysis.status)


@router.get("/dataset/examples", tags=["Образец из теста"])
def dataset_examples(per_group: int = 5) -> list[dict]:
    """Несколько sha256 из теста: безопасные, известные и неизвестные семейства."""
    try:
        return dataset.examples(get_settings().demo_dir, per_group=min(per_group, 20))
    except dataset.DemoUnavailable as exc:
        raise HTTPException(503, str(exc)) from exc
