"""Разбор PE-файла в отдельном дочернем процессе (раздел 4 ТЗ).

Вредоносные файлы бывают специально испорчены, чтобы ронять или вешать парсеры. Поэтому
LIEF и pefile работают не в процессе worker, а в дочернем процессе:
- тайм-аут (по умолчанию 60 с): зависший разбор убивается;
- лимит адресного пространства (RLIMIT_AS) и процессорного времени (RLIMIT_CPU);
- падение дочернего процесса (в том числе segfault внутри LIEF) даёт понятную ошибку,
  а worker продолжает работу.
Файл только читается: он никогда не запускается.
"""

from __future__ import annotations

import multiprocessing as mp
import traceback
from dataclasses import dataclass
from pathlib import Path

import numpy as np


class ParseFailed(Exception):
    pass


@dataclass
class ParsedFile:
    vector: np.ndarray
    static_info: dict


def _child(path: str, memory_mb: int, cpu_seconds: int, conn) -> None:
    try:
        # Библиотеки импортируем до установки лимитов: при импорте numpy/LIEF резервируют много
        # виртуальной памяти, а ограничить нужно именно разбор файла
        from malcore.features.static_info import analyze
        from malcore.features.vector import extract_vector

        try:
            import resource

            limit = memory_mb * 1024 * 1024 + _address_space()
            resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 5))
        except (ImportError, ValueError, OSError):
            pass  # на системах без resource лимиты не ставятся, тайм-аут всё равно работает

        data = Path(path).read_bytes()
        info = analyze(data)
        if "parse_error" in info:
            conn.send(("error", f"pefile не смог разобрать файл: {info['parse_error']}"))
            return
        conn.send(("ok", (extract_vector(data), info)))
    except MemoryError:
        conn.send(("error", f"разбор превысил лимит памяти {memory_mb} МБ"))
    except Exception as exc:  # noqa: BLE001 - любую ошибку разбора возвращаем как текст
        conn.send(("error", f"{type(exc).__name__}: {exc}\n{traceback.format_exc(limit=3)}"))
    finally:
        conn.close()


def _address_space() -> int:
    """Текущий объём виртуальной памяти процесса (Linux), чтобы лимит считался сверх него."""
    try:
        with open("/proc/self/statm") as f:
            return int(f.read().split()[0]) * 4096
    except OSError:
        return 0


def parse_in_sandbox(path: Path, timeout: float, memory_mb: int = 1024) -> ParsedFile:
    ctx = mp.get_context("spawn")  # чистый интерпретатор без состояния worker
    parent, child = ctx.Pipe(duplex=False)
    proc = ctx.Process(target=_child, args=(str(path), memory_mb, int(timeout), child), daemon=True)
    proc.start()
    child.close()
    try:
        if not parent.poll(timeout):
            raise ParseFailed(f"разбор не уложился в {timeout:.0f} с и был остановлен")
        try:
            status, payload = parent.recv()
        except EOFError as exc:
            raise ParseFailed(f"процесс разбора аварийно завершился (код {proc.exitcode})") from exc
    finally:
        if proc.is_alive():
            proc.kill()
        proc.join(5)
        parent.close()
    if status != "ok":
        raise ParseFailed(payload)
    vector, info = payload
    return ParsedFile(np.asarray(vector, dtype=np.float32), info)
