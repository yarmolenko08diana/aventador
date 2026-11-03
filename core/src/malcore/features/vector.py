"""Вектор признаков EMBER v2 (2381 число) для загружаемого PE-файла.

Это перенос оригинального экстрактора elastic/ember (ember/features.py, AGPL-3.0,
https://github.com/elastic/ember) на LIEF 1.x. Нужен ровно тот же вектор, на котором
обучены модели BODMAS, поэтому логика каждой группы признаков сохранена без изменений.

Что пришлось переписать и почему:
- в LIEF 1.x флаги секций, заголовка и DLL возвращаются в другом виде, а старые
  имена флагов попадают в хеширование признаков. Поэтому флаги раскладываются
  по числовому значению с таблицами имён, снятыми с LIEF 0.12.3;
- правило раскладки воспроизводит LIEF 0.12: флаг считается установленным, если
  у него есть хотя бы один общий бит со значением (это важно для ALIGN_*);
- в sklearn >= 1.2 FeatureHasher не принимает одиночную строку; в оригинале имя
  секции точки входа хешировалось посимвольно, здесь это сделано явно.

Совпадение с оригиналом проверено тестом core/tests/test_vector_reference.py:
эталонные векторы получены оригинальным кодом на LIEF 0.10.1 и 0.12.3.
"""

from __future__ import annotations

import re
import warnings

import lief
import numpy as np
from sklearn.feature_extraction import FeatureHasher

FEATURE_VERSION = "ember-v2"
VECTOR_SIZE = 2381

lief.logging.disable()
warnings.filterwarnings("ignore", message=".*is not a valid", category=RuntimeWarning)

# --- имена флагов, как их выдавала LIEF 0.12.3 (значение -> имя) ---------------------

SECTION_FLAGS = {
    0x8: "TYPE_NO_PAD", 0x20: "CNT_CODE", 0x40: "CNT_INITIALIZED_DATA", 0x80: "CNT_UNINITIALIZED_DATA",
    0x100: "LNK_OTHER", 0x200: "LNK_INFO", 0x800: "LNK_REMOVE", 0x1000: "LNK_COMDAT", 0x8000: "GPREL",
    0x10000: "MEM_PURGEABLE", 0x20000: "MEM_16BIT", 0x40000: "MEM_LOCKED", 0x80000: "MEM_PRELOAD",
    0x100000: "ALIGN_1BYTES", 0x200000: "ALIGN_2BYTES", 0x300000: "ALIGN_4BYTES", 0x400000: "ALIGN_8BYTES",
    0x500000: "ALIGN_16BYTES", 0x600000: "ALIGN_32BYTES", 0x700000: "ALIGN_64BYTES", 0x800000: "ALIGN_128BYTES",
    0x900000: "ALIGN_256BYTES", 0xA00000: "ALIGN_512BYTES", 0xB00000: "ALIGN_1024BYTES",
    0xC00000: "ALIGN_2048BYTES", 0xD00000: "ALIGN_4096BYTES", 0xE00000: "ALIGN_8192BYTES",
    0x1000000: "LNK_NRELOC_OVFL", 0x2000000: "MEM_DISCARDABLE", 0x4000000: "MEM_NOT_CACHED",
    0x8000000: "MEM_NOT_PAGED", 0x10000000: "MEM_SHARED", 0x20000000: "MEM_EXECUTE",
    0x40000000: "MEM_READ", 0x80000000: "MEM_WRITE",
}
HEADER_FLAGS = {
    0x1: "RELOCS_STRIPPED", 0x2: "EXECUTABLE_IMAGE", 0x4: "LINE_NUMS_STRIPPED", 0x8: "LOCAL_SYMS_STRIPPED",
    0x10: "AGGRESSIVE_WS_TRIM", 0x20: "LARGE_ADDRESS_AWARE", 0x80: "BYTES_REVERSED_LO",
    0x100: "CHARA_32BIT_MACHINE", 0x200: "DEBUG_STRIPPED", 0x400: "REMOVABLE_RUN_FROM_SWAP",
    0x800: "NET_RUN_FROM_SWAP", 0x1000: "SYSTEM", 0x2000: "DLL", 0x4000: "UP_SYSTEM_ONLY",
    0x8000: "BYTES_REVERSED_HI",
}
DLL_FLAGS = {
    0x20: "HIGH_ENTROPY_VA", 0x40: "DYNAMIC_BASE", 0x80: "FORCE_INTEGRITY", 0x100: "NX_COMPAT",
    0x200: "NO_ISOLATION", 0x400: "NO_SEH", 0x800: "NO_BIND", 0x1000: "APPCONTAINER",
    0x2000: "WDM_DRIVER", 0x4000: "GUARD_CF", 0x8000: "TERMINAL_SERVER_AWARE",
}
MACHINES = {
    0x0: "UNKNOWN", 0x14C: "I386", 0x166: "R4000", 0x169: "WCEMIPSV2", 0x1A2: "SH3", 0x1A3: "SH3DSP",
    0x1A6: "SH4", 0x1A8: "SH5", 0x1C0: "ARM", 0x1C2: "THUMB", 0x1C4: "ARMNT", 0x1D3: "AM33",
    0x1F0: "POWERPC", 0x1F1: "POWERPCFP", 0x200: "IA64", 0x266: "MIPS16", 0x366: "MIPSFPU",
    0x466: "MIPSFPU16", 0xEBC: "EBC", 0x8664: "AMD64", 0x9041: "M32R", 0xAA64: "ARM64", 0xFFFF: "INVALID",
}
SUBSYSTEMS = {
    0: "UNKNOWN", 1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI", 5: "OS2_CUI", 7: "POSIX_CUI",
    8: "NATIVE_WINDOWS", 9: "WINDOWS_CE_GUI", 10: "EFI_APPLICATION", 11: "EFI_BOOT_SERVICE_DRIVER",
    12: "EFI_RUNTIME_DRIVER", 13: "EFI_ROM", 14: "XBOX", 16: "WINDOWS_BOOT_APPLICATION",
}
MAGICS = {0x10B: "PE32", 0x20B: "PE32_PLUS"}
UNKNOWN_ENUM = "???"  # так LIEF 0.12 печатал значение, которого нет в перечислении


def flag_names(value: int, table: dict[int, str]) -> list[str]:
    return [name for bit, name in table.items() if value & bit]


def enum_name(value, table: dict[int, str]) -> str:
    # LIEF 1.x отдаёт перечисление, а для неизвестного значения — просто int
    return table.get(int(getattr(value, "value", value)), UNKNOWN_ENUM)


def _hash(n: int, items, input_type: str = "string") -> np.ndarray:
    return FeatureHasher(n, input_type=input_type).transform([items]).toarray()[0]


# --- группы признаков: порядок и размеры как в EMBER v2 ---------------------------------


def byte_histogram(bytez: bytes) -> np.ndarray:
    counts = np.bincount(np.frombuffer(bytez, dtype=np.uint8), minlength=256).astype(np.float32)
    return counts / counts.sum()


def byte_entropy_histogram(bytez: bytes, step: int = 1024, window: int = 2048) -> np.ndarray:
    def entropy_bin_counts(block):
        c = np.bincount(block >> 4, minlength=16)
        p = c.astype(np.float32) / window
        wh = np.where(c)[0]
        H = np.sum(-p[wh] * np.log2(p[wh])) * 2
        Hbin = int(H * 2)
        return min(Hbin, 15), c

    output = np.zeros((16, 16), dtype=np.int64)
    a = np.frombuffer(bytez, dtype=np.uint8)
    if a.shape[0] < window:
        Hbin, c = entropy_bin_counts(a)
        output[Hbin, :] += c
    else:
        shape = a.shape[:-1] + (a.shape[-1] - window + 1, window)
        strides = a.strides + (a.strides[-1],)
        blocks = np.lib.stride_tricks.as_strided(a, shape=shape, strides=strides)[::step, :]
        for block in blocks:
            Hbin, c = entropy_bin_counts(block)
            output[Hbin, :] += c
    counts = output.flatten().astype(np.float32)
    return counts / counts.sum()


_ALLSTRINGS = re.compile(b"[\x20-\x7f]{5,}")
_PATHS = re.compile(b"c:\\\\", re.IGNORECASE)
_URLS = re.compile(b"https?://", re.IGNORECASE)
_REGISTRY = re.compile(b"HKEY_")
_MZ = re.compile(b"MZ")


def string_features(bytez: bytes) -> np.ndarray:
    allstrings = _ALLSTRINGS.findall(bytez)
    if allstrings:
        lengths = [len(s) for s in allstrings]
        avlength = sum(lengths) / len(lengths)
        shifted = [b - 0x20 for b in b"".join(allstrings)]
        c = np.bincount(shifted, minlength=96)
        csum = c.sum()
        p = c.astype(np.float32) / csum
        wh = np.where(c)[0]
        H = float(np.sum(-p[wh] * np.log2(p[wh])))
    else:
        avlength, c, H, csum = 0, np.zeros(96, dtype=np.float32), 0.0, 0
    divisor = float(csum) if csum > 0 else 1.0
    return np.hstack(
        [
            len(allstrings), avlength, int(csum), np.asarray(c) / divisor, H,
            len(_PATHS.findall(bytez)), len(_URLS.findall(bytez)),
            len(_REGISTRY.findall(bytez)), len(_MZ.findall(bytez)),
        ]
    ).astype(np.float32)


def _has_debug(pe) -> int:
    """LIEF 0.12 ставил has_debug по наличию каталога DEBUG, даже если его не удалось прочитать
    (например, в обрезанном файле). LIEF 1.x в этом случае даёт False, поэтому смотрим каталог."""
    dirs = list(pe.data_directories)
    return int(pe.has_debug or (len(dirs) > 6 and dirs[6].rva != 0))


def general_info(bytez: bytes, pe) -> np.ndarray:
    if pe is None:
        return np.asarray([len(bytez)] + [0] * 9, dtype=np.float32)
    return np.asarray(
        [
            len(bytez), pe.virtual_size, _has_debug(pe), len(pe.exported_functions),
            len(pe.imported_functions), int(pe.has_relocations), int(pe.has_resources),
            int(pe.has_signatures), int(pe.has_tls), len(pe.symbols),
        ],
        dtype=np.float32,
    )


def header_info(pe) -> np.ndarray:
    coff = {"timestamp": 0, "machine": "", "characteristics": []}
    opt = {"subsystem": "", "dll_characteristics": [], "magic": ""}
    nums = [0] * 11  # версии и размеры из Optional Header
    if pe is not None:
        h, o = pe.header, pe.optional_header
        coff = {
            "timestamp": h.time_date_stamps,
            "machine": enum_name(h.machine, MACHINES),
            "characteristics": flag_names(h.characteristics, HEADER_FLAGS),
        }
        opt = {
            "subsystem": enum_name(o.subsystem, SUBSYSTEMS),
            "dll_characteristics": flag_names(o.dll_characteristics, DLL_FLAGS),
            "magic": enum_name(o.magic, MAGICS),
        }
        nums = [
            o.major_image_version, o.minor_image_version, o.major_linker_version, o.minor_linker_version,
            o.major_operating_system_version, o.minor_operating_system_version,
            o.major_subsystem_version, o.minor_subsystem_version,
            o.sizeof_code, o.sizeof_headers, o.sizeof_heap_commit,
        ]
    return np.hstack(
        [
            coff["timestamp"],
            _hash(10, [coff["machine"]]),
            _hash(10, coff["characteristics"]),
            _hash(10, [opt["subsystem"]]),
            _hash(10, opt["dll_characteristics"]),
            _hash(10, [opt["magic"]]),
            *nums,
        ]
    ).astype(np.float32)


def section_info(pe) -> np.ndarray:
    if pe is None:
        entry, sections = "", []
    else:
        sections = [
            {
                "name": s.name, "size": s.size, "entropy": s.entropy, "vsize": s.virtual_size,
                "props": flag_names(s.characteristics, SECTION_FLAGS),
            }
            for s in pe.sections
        ]
        found = pe.section_from_rva(pe.entrypoint - pe.imagebase)
        if found is not None:
            entry = found.name
        else:  # точка входа вне секций: берём первую исполняемую, как в оригинале
            entry = next((s["name"] for s in sections if "MEM_EXECUTE" in s["props"]), "")

    general = [
        len(sections),
        sum(1 for s in sections if s["size"] == 0),
        sum(1 for s in sections if s["name"] == ""),
        sum(1 for s in sections if "MEM_READ" in s["props"] and "MEM_EXECUTE" in s["props"]),
        sum(1 for s in sections if "MEM_WRITE" in s["props"]),
    ]
    characteristics = [p for s in sections for p in s["props"] if s["name"] == entry]
    return np.hstack(
        [
            general,
            _hash(50, [(s["name"], s["size"]) for s in sections], "pair"),
            _hash(50, [(s["name"], s["entropy"]) for s in sections], "pair"),
            _hash(50, [(s["name"], s["vsize"]) for s in sections], "pair"),
            _hash(50, list(entry)),  # посимвольно, как в оригинале
            _hash(50, characteristics),
        ]
    ).astype(np.float32)


def imports_info(pe) -> np.ndarray:
    imports: dict[str, list[str]] = {}
    if pe is not None:
        for lib in pe.imports:
            entries = imports.setdefault(lib.name, [])
            for e in lib.entries:
                entries.append(f"ordinal{e.ordinal}" if e.is_ordinal else e.name[:10000])
    libraries = list({name.lower() for name in imports})
    functions = [lib.lower() + ":" + e for lib, items in imports.items() for e in items]
    return np.hstack([_hash(256, libraries), _hash(1024, functions)]).astype(np.float32)


def exports_info(pe) -> np.ndarray:
    names = [] if pe is None else [f.name[:10000] for f in pe.exported_functions]
    return _hash(128, names).astype(np.float32)


def data_directories(pe) -> np.ndarray:
    out = np.zeros(30, dtype=np.float32)
    if pe is not None:
        for i, d in enumerate(list(pe.data_directories)[:15]):
            out[2 * i] = d.size
            out[2 * i + 1] = d.rva
    return out


def parse_pe(bytez: bytes):
    """Разбор LIEF; None, если файл не удаётся разобрать как PE (как в оригинале)."""
    return lief.PE.parse(list(bytez))


def extract_vector(bytez: bytes) -> np.ndarray:
    pe = parse_pe(bytez)
    vector = np.hstack(
        [
            byte_histogram(bytez),
            byte_entropy_histogram(bytez),
            string_features(bytez),
            general_info(bytez, pe),
            header_info(pe),
            section_info(pe),
            imports_info(pe),
            exports_info(pe),
            data_directories(pe),
        ]
    ).astype(np.float32)
    assert vector.shape == (VECTOR_SIZE,), vector.shape
    return vector
