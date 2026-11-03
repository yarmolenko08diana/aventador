"""Читаемое описание PE-файла для аналитика (раздел 6 ТЗ).

В отличие от vector.py, здесь не числа для моделей, а то, что показывается в интерфейсе
и проверяется правилами индикаторов: секции с энтропией и правами, импорты по DLL,
экспорты, ресурсы, overlay, строки. Разбор делает pefile; файл не исполняется.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from datetime import datetime, timezone

import pefile

MAX_STRINGS = 300  # сколько строк каждого вида отдаём в интерфейс
MAX_EXPORTS = 200

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000
DEBUG_DIR, SECURITY_DIR = 6, 4
DEBUG_TYPE_REPRO = 16

_ASCII = re.compile(rb"[\x20-\x7e]{5,}")
_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")
_URL = re.compile(r"https?://[^\s\"'<>]{4,}", re.IGNORECASE)
_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_REGISTRY = re.compile(r"(?:HKEY_[A-Z_]+|Software\\Microsoft\\Windows\\CurrentVersion\\Run\w*)[^\x00]*", re.IGNORECASE)


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def hashes(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def extract_strings(data: bytes) -> dict:
    ascii_ = [s.decode("ascii") for s in _ASCII.findall(data)]
    utf16 = [s.decode("utf-16-le") for s in _UTF16.findall(data)]
    everything = ascii_ + utf16
    joined = "\n".join(everything)
    return {
        "ascii_count": len(ascii_),
        "utf16_count": len(utf16),
        "urls": sorted(set(_URL.findall(joined)))[:MAX_STRINGS],
        "ips": sorted(set(_IPV4.findall(joined)))[:MAX_STRINGS],
        "registry": sorted({m.strip() for m in _REGISTRY.findall(joined)})[:MAX_STRINGS],
        "sample": everything[:MAX_STRINGS],
        "all_lower": [s.lower() for s in everything],  # для правил; в интерфейс не отдаётся
    }


def _section_name(raw: bytes) -> str:
    return raw.rstrip(b"\x00").decode("latin-1")


def _resources(pe: pefile.PE, data: bytes) -> list[dict]:
    out: list[dict] = []
    root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if root is None:
        return out

    def walk(entry, path):
        for e in getattr(entry, "entries", []):
            name = str(e.name) if e.name is not None else pefile.RESOURCE_TYPE.get(e.id, str(e.id))
            if hasattr(e, "directory"):
                walk(e.directory, path + [name])
            elif hasattr(e, "data"):
                rva, size = e.data.struct.OffsetToData, e.data.struct.Size
                try:
                    blob = pe.get_data(rva, min(size, 4096))
                except pefile.PEFormatError:
                    blob = b""
                out.append(
                    {
                        "path": "/".join(path + [name]),
                        "size": size,
                        "entropy": round(entropy(blob), 3),
                        "starts_with_mz": blob[:2] == b"MZ",
                    }
                )

    walk(root, [])
    return out


def analyze(data: bytes) -> dict:
    """Возвращает словарь, готовый к сохранению в JSON. При ошибке разбора — поле parse_error."""
    info: dict = {"size": len(data), "hashes": hashes(data), "entropy": round(entropy(data), 3)}
    info["strings"] = extract_strings(data)
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except pefile.PEFormatError as exc:
        info["parse_error"] = str(exc)
        return info

    fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
    is_dll = bool(fh.Characteristics & 0x2000)
    ts = fh.TimeDateStamp
    ep = oh.AddressOfEntryPoint
    ep_section = next((s for s in pe.sections if s.contains_rva(ep)), None)

    sections = []
    for s in pe.sections:
        flags = s.Characteristics
        sections.append(
            {
                "name": _section_name(s.Name),
                "virtual_address": s.VirtualAddress,
                "virtual_size": s.Misc_VirtualSize,
                "raw_size": s.SizeOfRawData,
                "entropy": round(s.get_entropy(), 3),
                "readable": bool(flags & IMAGE_SCN_MEM_READ),
                "writable": bool(flags & IMAGE_SCN_MEM_WRITE),
                "executable": bool(flags & IMAGE_SCN_MEM_EXECUTE),
            }
        )

    imports: dict[str, list[str]] = {}
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = entry.dll.decode("latin-1", "replace") if entry.dll else ""
        funcs = imports.setdefault(dll, [])
        for imp in entry.imports:
            funcs.append(imp.name.decode("latin-1", "replace") if imp.name else f"ordinal{imp.ordinal}")

    exports = []
    exp_dir = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if exp_dir is not None:
        exports = [
            (e.name.decode("latin-1", "replace") if e.name else f"ordinal{e.ordinal}")
            for e in exp_dir.symbols[:MAX_EXPORTS]
        ]

    overlay_offset = pe.get_overlay_data_start_offset()
    overlay = data[overlay_offset:] if overlay_offset else b""
    dirs = oh.DATA_DIRECTORY
    debug_types = sorted({d.struct.Type for d in getattr(pe, "DIRECTORY_ENTRY_DEBUG", [])})

    info.update(
        {
            "format": "PE32+" if oh.Magic == 0x20B else "PE32",
            "kind": "DLL" if is_dll else "EXE",
            "machine": pefile.MACHINE_TYPE.get(fh.Machine, hex(fh.Machine)),
            "subsystem": pefile.SUBSYSTEM_TYPE.get(oh.Subsystem, str(oh.Subsystem)),
            "compile_timestamp": ts,
            "compile_time": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat() if ts else None,
            "entry_point_rva": ep,
            "entry_point_section": _section_name(ep_section.Name) if ep_section else None,
            "entry_point_in_last_section": bool(ep_section is not None and ep_section == pe.sections[-1]),
            "image_base": oh.ImageBase,
            "checksum_header": oh.CheckSum,
            "checksum_computed": pe.generate_checksum(),
            "sections": sections,
            "imports": imports,
            "import_count": sum(len(v) for v in imports.values()),
            "exports": exports,
            "resources": _resources(pe, data),
            "overlay_size": len(overlay),
            "overlay_starts_with_mz": overlay[:2] == b"MZ",
            "has_signature": len(dirs) > SECURITY_DIR and dirs[SECURITY_DIR].Size > 0,
            "has_debug": len(dirs) > DEBUG_DIR and dirs[DEBUG_DIR].Size > 0,
            "debug_types": debug_types,
            # Запись IMAGE_DEBUG_TYPE_REPRO: сборка воспроизводимая, и в TimeDateStamp лежит хеш, а не дата
            "reproducible_build": DEBUG_TYPE_REPRO in debug_types,
            "has_tls": hasattr(pe, "DIRECTORY_ENTRY_TLS"),
            "warnings": pe.get_warnings()[:20],
        }
    )
    pe.close()
    return info


def public_view(info: dict) -> dict:
    """Копия без служебных полей — для API и PDF."""
    view = dict(info)
    if "strings" in view:
        view["strings"] = {k: v for k, v in view["strings"].items() if k != "all_lower"}
    return view
