"""Worker: забирает анализы из очереди в PostgreSQL и выполняет их.

    python -m worker.main            # бесконечный цикл
    python -m worker.main --once     # обработать всё, что есть в очереди, и выйти

Очередь — сама таблица analyses: SELECT ... WHERE status='queued' FOR UPDATE SKIP LOCKED,
поэтому несколько worker не возьмут одну задачу дважды (раздел 8 ТЗ).
Для загруженного файла: разбор в дочернем процессе → индикаторы → модели → запись.
Для образца из теста: готовый вектор → модели → запись (индикаторов нет, файла нет).
"""

from __future__ import annotations

import argparse
import logging
import time
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.db.models import Analysis
from app.db.session import get_sessionmaker
from app.services import dataset
from app.services.analysis import save_failure, save_result
from app.services.model_sync import sync_models, sync_rules
from malcore.indicators.engine import evaluate as evaluate_indicators
from malcore.inference.pipeline import load_models, predict
from worker.sandboxed_parse import ParseFailed, parse_in_sandbox

log = logging.getLogger("worker")


def claim_next(db: Session) -> Analysis | None:
    analysis = db.scalar(
        select(Analysis).where(Analysis.status == "queued").order_by(Analysis.created_at, Analysis.id)
        .with_for_update(skip_locked=True).limit(1)
    )
    if analysis is None:
        db.rollback()
        return None
    analysis.status = "processing"
    analysis.started_at = datetime.now(timezone.utc)
    db.commit()
    return analysis


class Worker:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.models = load_models(settings.models_dir)  # проверка sha256 и feature_version внутри
        with get_sessionmaker()() as db:
            sync_rules(db)
            self.model_ids = sync_models(db, settings.models_dir)
        log.info("модели загружены: %s", {t: m.selected for t, m in self.models.items()})

    def process(self, db: Session, analysis: Analysis) -> None:
        start = time.perf_counter()
        sample = analysis.sample
        try:
            if sample.source == "dataset":
                vector, info, hits = dataset.vector(self.settings.demo_dir, sample.sha256), None, []
            else:
                parsed = parse_in_sandbox(self.settings.quarantine_dir / sample.storage_path,
                                          self.settings.parse_timeout_seconds, self.settings.parse_memory_mb)
                vector, info = parsed.vector, parsed.static_info
                hits = evaluate_indicators(info)
            result = predict(self.models, vector)
        except (ParseFailed, KeyError, FileNotFoundError, ValueError) as exc:
            save_failure(db, analysis, str(exc), (time.perf_counter() - start) * 1000)
            log.warning("анализ %s: failed: %s", analysis.id, exc)
            return
        save_result(db, analysis, vector, info, hits, result, self.model_ids, (time.perf_counter() - start) * 1000)
        log.info("анализ %s: %s за %.0f мс", analysis.id, result.verdict, analysis.duration_ms)

    def run_once(self) -> int:
        """Обрабатывает очередь до конца. Возвращает число обработанных анализов."""
        done = 0
        while True:
            with get_sessionmaker()() as db:
                analysis = claim_next(db)
                if analysis is None:
                    return done
                try:
                    self.process(db, analysis)
                except Exception as exc:  # noqa: BLE001 - один анализ не должен ронять worker
                    db.rollback()
                    save_failure(db, db.get(Analysis, analysis.id), f"внутренняя ошибка: {exc}")
                    log.exception("анализ %s: внутренняя ошибка", analysis.id)
                done += 1

    def run_forever(self) -> None:
        while True:
            if self.run_once() == 0:
                time.sleep(self.settings.worker_poll_seconds)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    worker = Worker(get_settings())
    if args.once:
        log.info("обработано: %d", worker.run_once())
    else:
        worker.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
