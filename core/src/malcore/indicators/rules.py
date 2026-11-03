"""Правила подозрительных индикаторов (раздел 6 ТЗ).

Каждое правило получает результат static_info.analyze() и возвращает доказательство
(словарь, что именно найдено) или None. Индикатор объясняет аналитику, на что обратить
внимание, но сам по себе не доказывает вредоносность: у каждого правила есть поле caveat
с типичной безобидной причиной срабатывания. На вердикт моделей правила не влияют.
"""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlparse

from malcore.indicators import api_lists as api

HIGH_ENTROPY = 7.2
FEW_IMPORTS = 10
DYNLOAD_MAX_IMPORTS = 20

PACKER_SECTIONS = {
    "upx0", "upx1", "upx2", ".aspack", ".adata", ".mpress1", ".mpress2", ".themida",
    ".vmp0", ".vmp1", ".vmp2", ".petite", ".nsp0", ".nsp1", ".packed", "pec1", "pec2",
}
# Домены, которые встречаются в манифестах и сертификатах обычных программ
BENIGN_URL_HOSTS = {
    "schemas.microsoft.com", "www.w3.org", "ocsp.digicert.com", "crl3.digicert.com",
    "crl4.digicert.com", "www.digicert.com", "cacerts.digicert.com", "crl.microsoft.com",
    "www.microsoft.com", "ocsp.verisign.com", "crl.verisign.com", "ts-ocsp.ws.symantec.com",
    "ts-crl.ws.symantec.com", "ts-aia.ws.symantec.com", "ocsp.sectigo.com", "crl.sectigo.com",
    "crt.sectigo.com", "sectigo.com", "ocsp.globalsign.com", "crl.globalsign.com",
    "secure.globalsign.com", "www.globalsign.com", "ocsp.comodoca.com", "crl.comodoca.com",
}
SEVERITIES = ("low", "medium", "high")


@dataclass(frozen=True)
class Rule:
    code: str
    title: str
    severity: str
    category: str
    description: str  # почему это подозрительно
    caveat: str  # почему это ещё не доказательство
    check: Callable[[dict], dict | None]


# --- вспомогательные функции -------------------------------------------------------------


def _functions(info: dict) -> dict[str, str]:
    """Нормализованное имя -> имя как в файле (dll:func)."""
    out = {}
    for dll, funcs in info.get("imports", {}).items():
        for f in funcs:
            out.setdefault(api.normalize(f), f"{dll}:{f}")
    return out


def _found(info: dict, group: set[str]) -> list[str]:
    funcs = _functions(info)
    return sorted(funcs[name] for name in group if name in funcs)


def _strings(info: dict) -> list[str]:
    return info.get("strings", {}).get("all_lower", [])


def _high_entropy_sections(info: dict) -> list[dict]:
    return [
        {"section": s["name"], "entropy": s["entropy"]}
        for s in info.get("sections", [])
        if s["raw_size"] > 0 and s["entropy"] > HIGH_ENTROPY
    ]


def _suspicious_ips(info: dict) -> list[str]:
    out = []
    for ip in info.get("strings", {}).get("ips", []):
        parts = ip.split(".")
        if parts.count("0") >= 2 or parts[0] == "0":  # похоже на номер версии, например 6.0.0.0
            continue
        try:
            addr = ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        if not (addr.is_loopback or addr.is_multicast or addr.is_reserved or addr.is_unspecified):
            out.append(ip)
    return out


def _suspicious_urls(info: dict) -> list[str]:
    out = []
    for url in info.get("strings", {}).get("urls", []):
        try:
            host = (urlparse(url).hostname or "").lower()
        except ValueError:  # строка из файла лишь похожа на URL (например, «http://[...»)
            host = ""
        if host and host not in BENIGN_URL_HOSTS:
            out.append(url)
    return out


# --- проверки ------------------------------------------------------------------------------


def check_high_entropy(info):
    found = _high_entropy_sections(info)
    return {"sections": found, "threshold": HIGH_ENTROPY} if found else None


def check_packer_section(info):
    names = [s["name"] for s in info.get("sections", []) if s["name"].lower() in PACKER_SECTIONS]
    return {"sections": names} if names else None


def check_few_imports(info):
    if "sections" not in info:
        return None
    count = info.get("import_count", 0)
    packed = _high_entropy_sections(info) or info.get("entropy", 0) > HIGH_ENTROPY
    return {"import_count": count, "high_entropy": True} if count < FEW_IMPORTS and packed else None


def check_rwx(info):
    names = [s["name"] for s in info.get("sections", []) if s["writable"] and s["executable"]]
    return {"sections": names} if names else None


def check_entry_point(info):
    if "sections" not in info or not info.get("entry_point_rva"):
        return None  # DLL без точки входа — норма
    ep_name = info.get("entry_point_section")
    if ep_name is None:
        return {"reason": "точка входа не попадает ни в одну секцию", "rva": info["entry_point_rva"]}
    section = next((s for s in info["sections"] if s["name"] == ep_name), None)
    if section is not None and not section["executable"]:
        return {"reason": "секция точки входа не помечена как исполняемая", "section": ep_name}
    if info.get("entry_point_in_last_section") and len(info["sections"]) > 1:
        return {"reason": "точка входа в последней секции", "section": ep_name}
    return None


def check_injection(info):
    found = _found(info, api.INJECTION)
    return {"functions": found} if len(found) >= 2 else None  # одна функция встречается часто


def check_antidebug(info):
    found = _found(info, api.ANTIDEBUG)
    return {"functions": found} if found else None


def check_keylog(info):
    found = _found(info, api.KEYLOG)
    return {"functions": found} if found else None


def check_dynload(info):
    load, resolve = _found(info, api.DYNLOAD_LOAD), _found(info, api.DYNLOAD_RESOLVE)
    count = info.get("import_count", 0)
    if load and resolve and count < DYNLOAD_MAX_IMPORTS:
        return {"functions": load + resolve, "import_count": count}
    return None


def check_download(info):
    found = _found(info, api.DOWNLOAD)
    return {"functions": found} if found else None


def check_persistence(info):
    keys = sorted({s for s in _strings(info) if "currentversion\\run" in s})[:10]
    services = _found(info, api.SERVICE)
    if keys or services:
        return {"registry_strings": keys, "functions": services}
    return None


def check_shell(info):
    hits = []
    for s in _strings(info):
        if "powershell" in s and ("-enc" in s or "-encodedcommand" in s):
            hits.append(s)
        elif "cmd.exe /c" in s or "cmd /c" in s:
            hits.append(s)
        elif "vssadmin" in s and "delete" in s and "shadows" in s:
            hits.append(s)
    return {"strings": sorted(set(hits))[:10]} if hits else None


def check_network(info):
    urls, ips = _suspicious_urls(info), _suspicious_ips(info)
    return {"urls": urls[:20], "ips": ips[:20]} if urls or ips else None


def check_timestamp(info, now: float | None = None):
    if "compile_timestamp" not in info:
        return None
    ts = info["compile_timestamp"]
    now = time.time() if now is None else now
    if ts == 0:
        return {"reason": "время компиляции равно 0"}
    if ts > now + 86400:
        return {"reason": "время компиляции в будущем", "compile_time": info.get("compile_time")}
    return None


def check_checksum(info):
    header, computed = info.get("checksum_header", 0), info.get("checksum_computed", 0)
    if header and header != computed:
        return {"header": header, "computed": computed}
    return None


def check_embedded_pe(info):
    resources = [r["path"] for r in info.get("resources", []) if r["starts_with_mz"]]
    overlay = info.get("overlay_starts_with_mz", False)
    if resources or overlay:
        return {"resources": resources, "overlay": overlay}
    return None


RULES: list[Rule] = [
    Rule("PACK_HIGH_ENTROPY", "Высокая энтропия секции", "medium", "packing",
         "Данные секции близки к случайным (энтропия > 7.2 из 8): так выглядят сжатый или зашифрованный код.",
         "Сжатые ресурсы, инсталляторы и медиа тоже дают высокую энтропию.", check_high_entropy),
    Rule("PACK_KNOWN_SECTION", "Секция известного упаковщика", "medium", "packing",
         "Имя секции совпадает с упаковщиком (UPX, ASPack, MPRESS, Themida, VMProtect и др.).",
         "Легитимные программы тоже упаковывают для уменьшения размера или защиты от копирования.",
         check_packer_section),
    Rule("PACK_FEW_IMPORTS", "Мало импортов при высокой энтропии", "high", "packing",
         "Меньше 10 импортируемых функций вместе с высокой энтропией: настоящая таблица импорта, вероятно, скрыта.",
         "Бывает у очень маленьких утилит и у программ, упакованных без злого умысла.", check_few_imports),
    Rule("SEC_RWX", "Секция одновременно записываемая и исполняемая", "high", "structure",
         "Код, который может сам себя переписывать: типично для распаковщиков и внедрения кода.",
         "Встречается у JIT-компиляторов и некоторых систем защиты от копирования.", check_rwx),
    Rule("EP_OUTSIDE_CODE", "Необычная точка входа", "high", "structure",
         "Точка входа вне исполняемой секции, вне всех секций или в последней секции.",
         "Так устроены многие упаковщики, в том числе легитимные.", check_entry_point),
    Rule("API_INJECTION", "API для внедрения в чужой процесс", "high", "behavior",
         "Импортировано не меньше двух функций для записи в память и запуска кода в другом процессе.",
         "Отладчики, антивирусы и средства мониторинга используют те же функции.", check_injection),
    Rule("API_ANTIDEBUG", "Проверка отладчика", "low", "evasion",
         "Программа проверяет, не запущена ли она под отладчиком.",
         "Эти функции импортируют стандартные среды выполнения C/C++.", check_antidebug),
    Rule("API_KEYLOG", "API перехвата клавиатуры", "medium", "behavior",
         "Импортированы функции глобального перехвата или опроса клавиш.",
         "Горячие клавиши и специальные возможности в обычных программах.", check_keylog),
    Rule("API_DYNLOAD", "Динамическая загрузка функций при малом импорте", "medium", "evasion",
         "LoadLibrary + GetProcAddress при небольшой таблице импорта: нужные функции находятся во время работы.",
         "Плагины и отложенная загрузка в обычных программах.", check_dynload),
    Rule("API_DOWNLOAD", "API загрузки файлов из сети", "medium", "network",
         "Программа умеет скачивать файлы по URL.",
         "Так работают автообновления.", check_download),
    Rule("PERSIST_RUNKEY", "Признаки автозапуска", "medium", "persistence",
         "Строка ключа реестра Run или создание службы Windows.",
         "Автозапуск используют и легитимные службы и агенты.", check_persistence),
    Rule("STR_SHELL", "Командные строки оболочки", "high", "behavior",
         "Строки запуска PowerShell с закодированной командой, cmd.exe /c или удаления теневых копий.",
         "Встречаются в скриптах администрирования и инсталляторах.", check_shell),
    Rule("STR_NETWORK", "URL или IP-адреса в строках", "low", "network",
         "В файле есть адреса, к которым программа может обращаться.",
         "Часто это сайт разработчика или справки.", check_network),
    Rule("HDR_TIMESTAMP", "Странное время компиляции", "low", "structure",
         "Время компиляции равно нулю или находится в будущем: поле могли подделать.",
         "Воспроизводимые сборки специально ставят фиксированное время.", check_timestamp),
    Rule("HDR_CHECKSUM", "Контрольная сумма не совпадает", "low", "structure",
         "Контрольная сумма в заголовке заполнена, но не совпадает с вычисленной: файл мог быть изменён.",
         "Для обычных .exe поле часто не проверяется и может быть неточным.", check_checksum),
    Rule("RES_EMBEDDED_PE", "Вложенный исполняемый файл", "high", "structure",
         "Внутри ресурсов или в хвосте файла (overlay) лежит ещё один PE-файл.",
         "Инсталляторы так хранят устанавливаемые программы.", check_embedded_pe),
]
