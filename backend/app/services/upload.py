"""Приём файла: проверка по содержимому, хеши, карантин, постановка анализа в очередь (модуль 1 ТЗ).

API сам PE-файл не разбирает: здесь читаются только первые байты (MZ, e_lfanew, PE\\0\\0).
Файл сохраняется в карантин под именем <sha256>.bin с правами только на чтение.
Исходное имя остаётся лишь текстом в БД.
"""

from __future__ import annotations

import hashlib
import os
import struct
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Analysis, Sample

CHUNK = 1024 * 1024


class UploadError(Exception):
    def __init__(self, status_code: int, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.message = message


@dataclass
class UploadResult:
    analysis_id: int
    sample_id: int
    sha256: str
    duplicate: bool
    status: str


def check_pe_header(head: bytes, size: int) -> None:
    """MZ в начале, e_lfanew внутри файла и сигнатура PE\\0\\0 по этому смещению."""
    if len(head) < 0x40 or head[:2] != b"MZ":
        raise UploadError(415, "Это не PE-файл: нет сигнатуры MZ в начале")
    (e_lfanew,) = struct.unpack_from("<I", head, 0x3C)
    if e_lfanew + 4 > size:
        raise UploadError(415, "Это не PE-файл: смещение заголовка PE за пределами файла")
    if e_lfanew + 4 > len(head):
        raise UploadError(415, "Заголовок PE слишком далеко от начала файла")
    if head[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise UploadError(415, "Это не PE-файл: нет сигнатуры PE\\0\\0")


def store_upload(stream: BinaryIO, quarantine: Path, max_bytes: int) -> tuple[Path, dict, int, bytes]:
    """Пишет поток во временный файл карантина, считая хеши. Возвращает путь, хеши, размер, начало файла."""
    quarantine.mkdir(parents=True, exist_ok=True)
    hashes = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    size, head = 0, b""
    fd, tmp_name = tempfile.mkstemp(dir=quarantine, prefix=".upload-", suffix=".part")
    try:
        with os.fdopen(fd, "wb") as out:
            while chunk := stream.read(CHUNK):
                size += len(chunk)
                if size > max_bytes:
                    raise UploadError(413, f"Файл больше {max_bytes // (1024 * 1024)} МБ")
                if len(head) < 4096:
                    head += chunk[: 4096 - len(head)]
                for h in hashes.values():
                    h.update(chunk)
                out.write(chunk)
        if size == 0:
            raise UploadError(415, "Пустой файл")
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise
    return Path(tmp_name), {k: h.hexdigest() for k, h in hashes.items()}, size, head


def accept_upload(db: Session, stream: BinaryIO, filename: str | None, quarantine: Path, max_bytes: int) -> UploadResult:
    tmp, hashes, size, head = store_upload(stream, quarantine, max_bytes)
    try:
        check_pe_header(head, size)
        sha = hashes["sha256"]
        sample = db.scalar(select(Sample).where(Sample.sha256 == sha))
        if sample is not None:
            last = db.scalar(select(Analysis).where(Analysis.sample_id == sample.id).order_by(Analysis.id.desc()))
            if last is not None:
                return UploadResult(last.id, sample.id, sha, True, last.status)
        final = quarantine / f"{sha}.bin"
        if not final.exists():
            os.replace(tmp, final)
            os.chmod(final, 0o444)  # только чтение, без права исполнения
        if sample is None:
            sample = Sample(sha256=sha, md5=hashes["md5"], sha1=hashes["sha1"], size_bytes=size,
                            original_name=(filename or "")[:255] or None, source="upload", storage_path=final.name)
            db.add(sample)
            db.flush()
        analysis = Analysis(sample_id=sample.id, status="queued")
        db.add(analysis)
        db.commit()
        return UploadResult(analysis.id, sample.id, sha, False, analysis.status)
    finally:
        tmp.unlink(missing_ok=True)


def queue_rerun(db: Session, analysis: Analysis) -> Analysis:
    new = Analysis(sample_id=analysis.sample_id, status="queued")
    db.add(new)
    db.commit()
    return new
