"""Тесты правил подозрительных индикаторов.

Два вида проверок:
- на настоящих файлах из fixtures (безопасные, упакованные UPX, специально испорченные);
- на синтетических словарях в формате static_info.analyze() для правил, под которые
  у нас нет безопасного настоящего файла (вложенный PE, команды оболочки и т.п.).
Для каждого правила проверяем и срабатывание, и отсутствие срабатывания.
"""

from pathlib import Path

import pytest

from malcore.features.static_info import analyze
from malcore.indicators import api_lists
from malcore.indicators.engine import catalog, evaluate
from malcore.indicators.rules import RULES, check_timestamp

PE = Path(__file__).parent / "fixtures" / "pe"


def codes(info: dict) -> set[str]:
    return {h["code"] for h in evaluate(info)}


def base_info(**over) -> dict:
    """Минимальный «чистый» результат analyze(): ни одно правило не срабатывает."""
    info = {
        "entropy": 5.0,
        "strings": {"urls": [], "ips": [], "all_lower": []},
        "compile_timestamp": 1_600_000_000,
        "compile_time": "2020-09-13T12:26:40Z",
        "entry_point_rva": 0x1000,
        "entry_point_section": ".text",
        "entry_point_in_last_section": False,
        "checksum_header": 0,
        "checksum_computed": 12345,
        "sections": [
            {"name": ".text", "raw_size": 4096, "entropy": 6.0, "writable": False, "executable": True},
            {"name": ".data", "raw_size": 512, "entropy": 2.0, "writable": True, "executable": False},
        ],
        "imports": {"kernel32.dll": [f"Func{i}" for i in range(40)]},
        "import_count": 40,
        "resources": [],
        "overlay_starts_with_mz": False,
    }
    info.update(over)
    return info


def with_imports(*funcs: str, count: int = 40) -> dict:
    return base_info(imports={"kernel32.dll": list(funcs)}, import_count=count)


def with_strings(*strings: str, urls=(), ips=()) -> dict:
    return base_info(strings={"urls": list(urls), "ips": list(ips), "all_lower": [s.lower() for s in strings]})


# --- общие свойства ----------------------------------------------------------------------


def test_clean_info_has_no_hits():
    assert evaluate(base_info()) == []


def test_catalog_is_complete_and_unique():
    cat = catalog()
    assert len(cat) == len(RULES) == 16
    assert len({r["code"] for r in cat}) == 16
    for r in cat:
        assert r["severity"] in ("low", "medium", "high")
        assert r["description"] and r["caveat"]


def test_hits_sorted_by_severity():
    info = base_info(checksum_header=1, sections=[
        {"name": ".text", "raw_size": 4096, "entropy": 6.0, "writable": True, "executable": True}])
    hits = evaluate(info)
    assert [h["severity"] for h in hits] == ["high", "low"]


def test_api_suffix_normalization():
    assert api_lists.normalize("LoadLibraryExW") == "LoadLibraryEx"
    assert api_lists.normalize("GetAsyncKeyState") == "GetAsyncKeyState"
    assert api_lists.normalize("ordinal123") == "ordinal123"


# --- настоящие файлы ------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["pip_t64_upx.exe", "pip_t32_upx.exe"])
def test_upx_packed_file(name):
    hits = codes(analyze((PE / "packed" / name).read_bytes()))
    assert {"PACK_KNOWN_SECTION", "PACK_HIGH_ENTROPY", "PACK_FEW_IMPORTS", "SEC_RWX"} <= hits


def test_unpacked_original_has_no_packing_hits():
    paths = sorted((PE / "benign").iterdir())
    assert len(paths) == 17
    for path in paths:
        hits = codes(analyze(path.read_bytes()))
        assert not hits & {"PACK_KNOWN_SECTION", "PACK_FEW_IMPORTS", "SEC_RWX", "EP_OUTSIDE_CODE"}, path.name


def test_crafted_rwx_and_bad_entry():
    assert "SEC_RWX" in codes(analyze((PE / "crafted" / "rwx_align8192.exe").read_bytes()))
    assert "EP_OUTSIDE_CODE" in codes(analyze((PE / "crafted" / "bad_entry.exe").read_bytes()))


@pytest.mark.parametrize("name", ["not_pe.bin", "truncated.exe"])
def test_unparseable_file_gives_no_hits(name):
    assert evaluate(analyze((PE / "crafted" / name).read_bytes())) == []


# --- правила на синтетических данных ---------------------------------------------------


def test_high_entropy_section():
    info = base_info(sections=[{"name": ".text", "raw_size": 4096, "entropy": 7.9, "writable": False, "executable": True}])
    assert "PACK_HIGH_ENTROPY" in codes(info)
    # секция без данных на диске не считается
    info["sections"][0]["raw_size"] = 0
    assert "PACK_HIGH_ENTROPY" not in codes(info)


def test_packer_section_name():
    info = base_info()
    info["sections"].append({"name": ".vmp0", "raw_size": 10, "entropy": 1.0, "writable": False, "executable": False})
    assert "PACK_KNOWN_SECTION" in codes(info)


def test_few_imports_requires_high_entropy():
    assert "PACK_FEW_IMPORTS" not in codes(with_imports("ExitProcess", count=1))
    info = with_imports("ExitProcess", count=1)
    info["entropy"] = 7.8
    assert "PACK_FEW_IMPORTS" in codes(info)


def test_entry_point_variants():
    assert "EP_OUTSIDE_CODE" in codes(base_info(entry_point_section=None))
    assert "EP_OUTSIDE_CODE" in codes(base_info(entry_point_section=".data"))
    assert "EP_OUTSIDE_CODE" in codes(base_info(entry_point_in_last_section=True))
    assert "EP_OUTSIDE_CODE" not in codes(base_info(entry_point_rva=0, entry_point_section=None))


def test_injection_needs_two_functions():
    assert "API_INJECTION" not in codes(with_imports("WriteProcessMemory"))
    assert "API_INJECTION" in codes(with_imports("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"))


def test_antidebug_keylog_download():
    assert "API_ANTIDEBUG" in codes(with_imports("IsDebuggerPresent"))
    assert "API_KEYLOG" in codes(with_imports("SetWindowsHookExW"))
    assert "API_DOWNLOAD" in codes(with_imports("URLDownloadToFileA"))
    assert not codes(with_imports("CreateFileW", "ReadFile"))


def test_dynload_only_with_small_import_table():
    assert "API_DYNLOAD" in codes(with_imports("LoadLibraryA", "GetProcAddress", count=2))
    assert "API_DYNLOAD" not in codes(with_imports("LoadLibraryA", "GetProcAddress", count=200))
    assert "API_DYNLOAD" not in codes(with_imports("LoadLibraryA", count=2))


def test_persistence():
    assert "PERSIST_RUNKEY" in codes(with_strings(r"Software\Microsoft\Windows\CurrentVersion\Run"))
    assert "PERSIST_RUNKEY" in codes(with_imports("CreateServiceW"))
    assert "PERSIST_RUNKEY" not in codes(with_strings(r"Software\Microsoft\Windows\CurrentVersion\Uninstall"))


def test_shell_strings():
    assert "STR_SHELL" in codes(with_strings("powershell -nop -enc SQBFAFgA"))
    assert "STR_SHELL" in codes(with_strings("cmd.exe /c del %temp%\\x.exe"))
    assert "STR_SHELL" in codes(with_strings("vssadmin delete shadows /all /quiet"))
    assert "STR_SHELL" not in codes(with_strings("powershell.exe", "cmd.exe"))


def test_network_filters_benign_hosts_and_versions():
    assert "STR_NETWORK" in codes(with_strings(urls=["http://evil.example.net/a.exe"]))
    assert "STR_NETWORK" in codes(with_strings(ips=["185.10.20.30"]))
    assert "STR_NETWORK" in codes(with_strings(ips=["8.8.8.8"]))
    benign = with_strings(urls=["http://schemas.microsoft.com/SMI/2005/WindowsSettings"],
                          ips=["6.0.0.0", "127.0.0.1", "1.0.0.0", "1.1.0.14"])
    assert "STR_NETWORK" not in codes(benign)


def test_timestamp():
    now = 1_700_000_000
    assert check_timestamp(base_info(compile_timestamp=0), now) is not None
    assert check_timestamp(base_info(compile_timestamp=now + 10 * 86400), now) is not None
    assert check_timestamp(base_info(compile_timestamp=now - 86400), now) is None


def test_checksum():
    assert "HDR_CHECKSUM" in codes(base_info(checksum_header=111, checksum_computed=222))
    assert "HDR_CHECKSUM" not in codes(base_info(checksum_header=222, checksum_computed=222))
    assert "HDR_CHECKSUM" not in codes(base_info(checksum_header=0))  # поле не заполнено


def test_embedded_pe():
    res = [{"path": "RCDATA/101/1033", "size": 50000, "entropy": 6.1, "starts_with_mz": True}]
    assert "RES_EMBEDDED_PE" in codes(base_info(resources=res))
    assert "RES_EMBEDDED_PE" in codes(base_info(overlay_starts_with_mz=True))
    res[0]["starts_with_mz"] = False
    assert "RES_EMBEDDED_PE" not in codes(base_info(resources=res))


def test_network_survives_malformed_url():
    info = with_strings(urls=["http://[bad", "http://evil.example.net/x"])
    assert "STR_NETWORK" in codes(info)
    assert "STR_NETWORK" not in codes(with_strings(urls=["http://[bad"]))


def test_timestamp_skipped_for_reproducible_build():
    future = base_info(compile_timestamp=4_000_000_000)
    assert "HDR_TIMESTAMP" in codes(future)
    future["reproducible_build"] = True  # у /Brepro-сборок в поле лежит хеш
    assert "HDR_TIMESTAMP" not in codes(future)
    assert "HDR_TIMESTAMP" in codes(base_info(compile_timestamp=0, reproducible_build=True))


def test_fp_report_on_fixtures(capsys):
    from malcore.indicators import fp_report

    fp_report.main([str(PE), "--limit", "0", "--top", "3"])
    out = capsys.readouterr().out
    assert "Разобрано PE: 25" in out
    assert "PACK_KNOWN_SECTION: самые частые находки" in out
    assert "Ошибки правил" not in out
