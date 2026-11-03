import hashlib
import json
from pathlib import Path

from malcore.features.static_info import analyze, public_view

PE = Path(__file__).parent / "fixtures" / "pe"


def test_exe_basic_fields():
    data = (PE / "benign" / "pip_t64.exe").read_bytes()
    info = analyze(data)
    assert "parse_error" not in info
    assert info["hashes"]["sha256"] == hashlib.sha256(data).hexdigest()
    assert info["format"] == "PE32+" and info["kind"] == "EXE"
    assert info["machine"] == "IMAGE_FILE_MACHINE_AMD64"
    assert info["sections"] and all(0 <= s["entropy"] <= 8 for s in info["sections"])
    assert any(s["executable"] for s in info["sections"])
    assert any(dll.lower() == "kernel32.dll" for dll in info["imports"])
    assert info["entry_point_section"] == ".text"


def test_dll_exports():
    info = analyze((PE / "benign" / "psutil_win_amd64__psutil_windows.pyd").read_bytes())
    assert info["kind"] == "DLL"
    assert "PyInit__psutil_windows" in info["exports"]


def test_crafted_rwx_section_is_visible():
    info = analyze((PE / "crafted" / "rwx_align8192.exe").read_bytes())
    first = info["sections"][0]
    assert first["writable"] and first["executable"]


def test_bad_entry_point_has_no_section():
    info = analyze((PE / "crafted" / "bad_entry.exe").read_bytes())
    assert info["entry_point_section"] is None


def test_not_pe_reports_error_instead_of_crashing():
    info = analyze((PE / "crafted" / "not_pe.bin").read_bytes())
    assert "parse_error" in info
    assert info["strings"]["ascii_count"] > 0


def test_result_is_json_serializable_without_internal_fields():
    view = public_view(analyze((PE / "benign" / "setuptools_gui-64.exe").read_bytes()))
    assert "all_lower" not in view["strings"]
    json.dumps(view)


def test_ip_regex_ignores_oid_fragments():
    from malcore.features.static_info import extract_strings

    ips = extract_strings(b"oid 1.3.6.1.5.5.7.3.1 ver 10.0.22621.1 c2 185.10.20.30 end").get("ips")
    assert ips == ["185.10.20.30"]
