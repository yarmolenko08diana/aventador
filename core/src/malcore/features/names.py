"""Имена признаков вектора EMBER v2: нужны, чтобы объяснять важность признаков в отчёте.

Порядок групп и их размеры совпадают с vector.extract_vector (проверяется тестом).
"""

from __future__ import annotations

from functools import lru_cache

GROUPS = [
    ("histogram", 256), ("byteentropy", 256), ("strings", 104), ("general", 10), ("header", 62),
    ("section", 255), ("imports", 1280), ("exports", 128), ("datadirectories", 30),
]

_STRINGS = ["numstrings", "avlength"] + [f"printabledist[{i}]" for i in range(96)] + [
    "printables", "entropy", "paths", "urls", "registry", "MZ"]
_GENERAL = ["size", "vsize", "has_debug", "exports", "imports", "has_relocations", "has_resources",
            "has_signature", "has_tls", "symbols"]
_HEADER = (["coff.timestamp"] + [f"coff.machine#{i}" for i in range(10)]
           + [f"coff.characteristics#{i}" for i in range(10)] + [f"optional.subsystem#{i}" for i in range(10)]
           + [f"optional.dll_characteristics#{i}" for i in range(10)] + [f"optional.magic#{i}" for i in range(10)]
           + ["optional.major_image_version", "optional.minor_image_version", "optional.major_linker_version",
              "optional.minor_linker_version", "optional.major_operating_system_version",
              "optional.minor_operating_system_version", "optional.major_subsystem_version",
              "optional.minor_subsystem_version", "optional.sizeof_code", "optional.sizeof_headers",
              "optional.sizeof_heap_commit"])
_SECTION = (["section.count", "section.zero_size", "section.empty_name", "section.rx", "section.w"]
            + [f"section.size_hash#{i}" for i in range(50)] + [f"section.entropy_hash#{i}" for i in range(50)]
            + [f"section.vsize_hash#{i}" for i in range(50)] + [f"section.entry_name#{i}" for i in range(50)]
            + [f"section.entry_characteristics#{i}" for i in range(50)])
_IMPORTS = [f"imports.library#{i}" for i in range(256)] + [f"imports.function#{i}" for i in range(1024)]
_DIRS = [f"datadirectories[{i}].{k}" for i in range(15) for k in ("size", "rva")]


@lru_cache(maxsize=1)
def feature_names() -> list[str]:
    names = (
        [f"histogram[{i}]" for i in range(256)]
        + [f"byteentropy[{i}]" for i in range(256)]
        + [f"strings.{n}" for n in _STRINGS]
        + [f"general.{n}" for n in _GENERAL]
        + [f"header.{n}" for n in _HEADER]
        + _SECTION
        + _IMPORTS
        + [f"exports#{i}" for i in range(128)]
        + _DIRS
    )
    return names


def index_of(name: str) -> int:
    return feature_names().index(name)


def group_of(index: int) -> str:
    start = 0
    for name, size in GROUPS:
        if index < start + size:
            return name
        start += size
    raise IndexError(index)
