"""O2 comparison script: it must pass on a valid PE, and catch a wrong tool."""
import struct

import pytest

pytest.importorskip("pefile")

from malworn.agent import evaluate_tools as et


def make_pe(path, overlay=b""):
    """A minimal valid PE32 with one section (not executable content)."""
    dos = bytearray(64)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 64)
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 224, 0x102)
    opt = bytearray(224)
    struct.pack_into("<H", opt, 0, 0x10B)
    struct.pack_into("<I", opt, 32, 0x1000)   # SectionAlignment
    struct.pack_into("<I", opt, 36, 0x200)    # FileAlignment
    struct.pack_into("<I", opt, 56, 0x2000)   # SizeOfImage
    struct.pack_into("<I", opt, 60, 0x200)    # SizeOfHeaders
    struct.pack_into("<I", opt, 92, 16)       # NumberOfRvaAndSizes
    sect = b".text\0\0\0" + struct.pack("<IIIIIIHHI", 0x100, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    header = bytes(dos) + b"PE\0\0" + coff + bytes(opt) + sect
    body = header.ljust(0x200, b"\0") + (b"This is a test string\0" + bytes(range(64))).ljust(0x200, b"\0")
    path.write_bytes(body + overlay)


def test_valid_pe_agrees_with_reference(tmp_path):
    f = tmp_path / "a.exe"
    make_pe(f, overlay=b"APPENDED-DATA")
    tools = {t.name: t for t in et.load_tools()[0] if t.name in et.CHECKED_TOOLS}
    result = et.evaluate_file(f, tools)
    failed = [r for r in result["checks"] if r["passed"] is False]
    assert failed == []
    assert any(r["check"] == "overlay size" and r["passed"] for r in result["checks"])


def test_non_pe_is_not_called_pe(tmp_path):
    f = tmp_path / "t.bin"
    f.write_bytes(b"hello, not a pe file")
    tools = {t.name: t for t in et.load_tools()[0] if t.name in et.CHECKED_TOOLS}
    result = et.evaluate_file(f, tools)
    assert not result["is_pe"]
    assert [r for r in result["checks"] if r["passed"] is False] == []


def test_wrong_hash_and_sections_are_caught():
    ref = {"sha256": "aa"}
    assert et.compare_hashes({"sha256": "bb"}, ref)[0][1] is False
    raw = {"sections": [{"name": ".text", "virtual_address": 4096, "virtual_size": 1,
                         "raw_size": 2, "raw_pointer": 0, "entropy": 5.0}]}
    bad = {"sections": [{"name": ".text", "virtual_address": 4096, "virtual_size": 1,
                         "raw_size": 2, "entropy": 6.0}]}
    assert et.compare_sections(bad, raw)[1][1] is False


def test_die_missing_is_skipped_not_failed():
    assert et.compare_packers({"suspected_packers": []}, None)[0][1] is None


def test_summary_counts_mismatches():
    evals = [{"file": "x", "is_pe": True, "checks": [
        {"tool": "hashes", "check": "c", "passed": False, "detail": "d"}]}]
    text, per_tool = et.summarise(evals)
    assert per_tool["hashes"]["fail"] == 1 and "Mismatches (1)" in text
