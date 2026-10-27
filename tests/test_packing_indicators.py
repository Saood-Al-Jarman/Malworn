"""
Tests for malworn.packing.indicators.

Uses SYNTHETIC PE files built in code (harmless, never executed, nothing binary
is committed), so the logic can be tested with no malware involved.
Run:  pytest tests/test_packing_indicators.py
"""
import os
import socket
import struct
from pathlib import Path

import pytest

from malworn.packing import indicators as pi

R, W, X = 0x40000000, 0x80000000, 0x20000000
CODE = 0x20 | R | X
DATA = 0x40 | R | W


def build_pe(sections, entry_rva):
    """sections: list of (name, raw_bytes, vsize, characteristics). Minimal PE32."""
    file_align, sec_align, hdr_size = 0x200, 0x1000, 0x200
    n = len(sections)
    raw_ptr, rva = hdr_size, 0x1000
    table, blobs, size_of_image = b"", b"", 0x1000
    for name, raw, vsize, ch in sections:
        padded = raw + b"\x00" * (-len(raw) % file_align)
        table += struct.pack("<8sIIIIIIHHI", name.encode().ljust(8, b"\0"), vsize, rva,
                             len(padded), raw_ptr if padded else 0, 0, 0, 0, 0, ch)
        blobs += padded
        raw_ptr += len(padded)
        rva += (max(vsize, len(raw)) + sec_align - 1) // sec_align * sec_align
        size_of_image = rva
    dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40)
    coff = struct.pack("<HHIIIHH", 0x14C, n, 0, 0, 0, 224, 0x102)
    opt = struct.pack("<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
                      0x10B, 1, 0, 0, 0, 0, entry_rva, 0x1000, 0x2000, 0x400000,
                      sec_align, file_align, 4, 0, 0, 0, 4, 0, 0, size_of_image,
                      hdr_size, 0, 3, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    opt += b"\x00" * (16 * 8)
    return (dos + b"PE\0\0" + coff + opt + table).ljust(hdr_size, b"\0") + blobs


@pytest.fixture
def write_pe(tmp_path):
    def _w(data, name="s.bin"):
        p = tmp_path / name
        p.write_bytes(data)
        return str(p)
    return _w


def ids(r):
    return {i["id"] for i in r["indicators"]}


def upx_like():
    return build_pe([("UPX0", b"", 0x8000, DATA | X),
                     ("UPX1", os.urandom(8000), 0x2000, CODE | W)], 0x9000)


def test_clean_pe_is_not_flagged(write_pe):
    text = bytes(range(32)) * 100 + b"\x90" * 500
    r = pi.analyze(write_pe(build_pe([(".text", text, 0x1000, CODE),
                                      (".data", b"A" * 600, 0x1000, DATA)], 0x1000)))
    assert r["packing_indicators_level"] == "none_detected"
    assert r["needs_unpacking"] is False
    assert r["packed_sections"] == []
    assert "re-upload" not in r["user_message"]


def test_upx_like_file_and_sections_are_flagged(write_pe):
    r = pi.analyze(write_pe(upx_like()))
    assert {"PACKER_SECTION_NAME", "EMPTY_WRITABLE_SECTION", "SECTION_ENTROPY_HIGH"} <= ids(r)
    assert r["packing_indicators_level"] == "likely"
    assert r["needs_unpacking"] is True
    names = {s["name"] for s in r["packed_sections"]}
    assert {"UPX0", "UPX1"} <= names              # the sections are named
    assert r["static_evidence_reliability"] == "reduced"


def test_user_message_asks_for_unpack_and_reupload(write_pe):
    msg = pi.analyze(write_pe(upx_like()))["user_message"]
    assert "UPX1" in msg and "unpack" in msg and "re-upload" in msg
    assert "malware" not in msg.lower()            # FR7: no malicious verdict


def test_only_the_packed_section_is_named(write_pe):
    """A normal .text next to a suspicious high-entropy executable section."""
    secs = [(".text", bytes(range(32)) * 100, 0x1000, CODE),
            (".stub", os.urandom(6000), 0x2000, CODE | W)]
    r = pi.analyze(write_pe(build_pe(secs, 0x2000)))      # entry point in .stub
    flagged = {s["name"] for s in r["packed_sections"]}
    assert ".stub" in flagged
    assert ".text" not in flagged


def test_low_entropy_packer_limitation_is_documented(write_pe):
    """Entropy alone misses it; structure indicators still fire."""
    r = pi.analyze(write_pe(build_pe([(".stub", b"AB" * 4000, 0x2000, CODE | W)], 0x1000)))
    assert "SECTION_ENTROPY_HIGH" not in ids(r)
    assert "EP_NONSTANDARD_SECTION" in ids(r)


def test_high_entropy_regions_are_mapped_to_sections(write_pe):
    r = pi.analyze(write_pe(upx_like()))
    assert r["high_entropy_regions"]
    assert any("UPX1" in reg["sections"] for reg in r["high_entropy_regions"])


UPX_STUB = bytes.fromhex("60BE00704000" "8DBE00A0FFFF" "57") + b"\x00" * 40


def upx_with_real_stub():
    return build_pe([("UPX0", b"", 0x8000, DATA | X),
                     ("UPX1", UPX_STUB + os.urandom(6000), 0x2000, CODE | W)], 0x9000)


def test_bundled_signature_matches_upx_entry_stub(write_pe):
    r = pi.analyze(write_pe(upx_with_real_stub()))
    sig = [i for i in r["indicators"] if i["id"] == "SIGNATURE_MATCH"]
    assert any(i["value"]["signature"] == "UPX_EP_STUB_PUSHAD_MOV_LEA" for i in sig)
    assert any(p["packer"] == "UPX" for p in r["suspected_packers"])


def test_every_bundled_pattern_compiles():
    from malworn.packing import signatures as sg
    for s in sg.SIGNATURES:
        assert sg.compile_pattern(s["pattern"]).pattern
        assert s["source"] and isinstance(s["verified"], bool)


def test_wildcards_and_jumps_in_patterns():
    from malworn.packing import signatures as sg
    assert sg.compile_pattern("60 ?? 61").match(b"\x60\x99\x61")
    assert sg.compile_pattern("60 [2] 61").match(b"\x60\x01\x02\x61")
    assert not sg.compile_pattern("60 ?? 61").match(b"\x60\x99\x62")


def test_message_lists_all_evidence_for_and_against(write_pe):
    packed = pi.analyze(write_pe(upx_with_real_stub()))["user_message"]
    for needle in ("Evidence for packing", "SECTION_ENTROPY_HIGH", "threshold 7.0",
                   "Suspected packer", "UPX", "How the confidence was reached", "re-upload"):
        assert needle in packed, needle
    clean = pi.analyze(write_pe(build_pe([(".text", bytes(range(32)) * 100, 0x1000, CODE),
                                          (".data", b"A" * 600, 0x1000, DATA)], 0x1000)))
    assert clean["counter_evidence"]                       # a clean answer is also evidence-backed
    assert "Evidence against packing" in clean["user_message"]
    assert "EP_IN_STANDARD_CODE_SECTION" in clean["user_message"]


def test_every_indicator_has_observed_value_points_and_location(write_pe):
    r = pi.analyze(write_pe(upx_with_real_stub()))
    for i in r["indicators"]:
        assert {"id", "value", "points", "location", "why", "source"} <= set(i)


def test_runs_with_networking_disabled(write_pe, monkeypatch):
    """Offline guarantee: any attempt to open a socket would fail this test."""
    def boom(*a, **k):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    r = pi.analyze(write_pe(upx_with_real_stub()))
    assert r["offline"] is True and r["needs_unpacking"] is True


def test_source_has_no_network_or_subprocess_use():
    pkg = Path(pi.__file__).parent
    for f in ("indicators.py", "signatures.py", "batch_detect.py", "structure.py", "yara_rules.py",
              "train_codeness.py", "die.py", "packer_signatures.py", "packing_indicators.py"):
        src = (pkg / f).read_text()
        banned_list = ["import socket", "import requests", "urllib", "http.client",
                       "import ftplib", "import smtplib"]
        if f != "die.py":                    # die.py is the only place that starts an external program
            banned_list.append("import subprocess")
        for banned in banned_list:
            assert banned not in src, f"{f} uses {banned}"


def test_garbage_input_is_handled(write_pe):
    assert pi.analyze(write_pe(b"not a pe file"))["error"] == "not_a_valid_pe"


# ---------------- known / modified / unknown packer classification ----------------
def renamed_upx():
    """Real-looking UPX stub, but section names changed (a 'custom variant')."""
    return build_pe([(".aa0", b"", 0x8000, DATA | X),
                     (".bb1", UPX_STUB + os.urandom(6000), 0x2000, CODE | W)], 0x9000)


def test_known_packer_when_name_and_signature_agree(write_pe):
    c = pi.analyze(write_pe(upx_with_real_stub()))["packer_classification"]
    assert c["status"] == "known_packer" and c["packer"] == "UPX"


def test_modified_variant_when_stub_matches_but_names_changed(write_pe):
    r = pi.analyze(write_pe(renamed_upx()))
    assert r["packer_classification"]["status"] == "known_packer_modified_variant"
    assert "MODIFIED" in r["user_message"]


def test_unknown_packer_when_packed_but_nothing_names_it(write_pe):
    secs = [(".text", bytes(range(32)) * 100, 0x1000, CODE),
            (".stub", os.urandom(6000), 0x2000, CODE | W)]
    r = pi.analyze(write_pe(build_pe(secs, 0x2000)))
    c = r["packer_classification"]
    assert r["needs_unpacking"] and c["status"] == "unknown_packer" and c["packer"] is None
    assert "UNKNOWN packer" in r["user_message"]


def test_clean_file_has_no_packer_classification(write_pe):
    r = pi.analyze(write_pe(build_pe([(".text", bytes(range(32)) * 100, 0x1000, CODE)], 0x1000)))
    assert r["packer_classification"]["status"] == "none_detected"


# ---------------- instruction-structure (code-likeness) -----------------------------
def synthetic_code(seed, n_bytes=40000):
    """Valid 32-bit x86 snippets in random order: stands in for benign code."""
    import random
    rng = random.Random(seed)
    snippets = [bytes.fromhex(h) for h in (
        "5589E5", "83EC10", "8B4508", "8945FC", "8B45FC", "5DC3", "31C0", "40", "50", "58",
        "6A00", "E800000000", "85C0", "7405", "8B4D0C", "01C8", "89C2", "29D0", "0FB600", "C9C3",
        "FF7508", "8B55F8", "8D45F4", "83C404", "3B45FC", "7C05", "EB02", "895DF8")]
    out = b""
    while len(out) < n_bytes:
        out += rng.choice(snippets)
    return out[:n_bytes]


def test_structure_model_separates_code_from_random_and_substituted():
    pytest.importorskip("capstone")
    from malworn.packing import structure as st
    model = st.train([synthetic_code(1), synthetic_code(2)], 32)
    code = synthetic_code(3)[: st.WINDOW]
    perm = list(range(256))[::-1]
    substituted = bytes(perm[b] for b in code)
    assert model.is_code_like(code)
    assert not model.is_code_like(os.urandom(st.WINDOW))
    assert not model.is_code_like(substituted)           # entropy-preserving transformation


def test_entropy_misses_but_structure_catches_substituted_code(write_pe, monkeypatch, tmp_path):
    """The research claim in miniature: a LOW-entropy executable section that is not code."""
    pytest.importorskip("capstone")
    from malworn.packing import structure as st
    st.save(st.train([synthetic_code(1), synthetic_code(2)], 32), tmp_path / "codeness_x86_32.json")
    monkeypatch.setenv(st.MODEL_ENV, str(tmp_path))

    good = synthetic_code(3, 20000)
    perm = [(b * 7 + 13) & 255 for b in range(256)]
    bad = bytes(perm[b] for b in good)                    # same length, same entropy

    r_good = pi.analyze(write_pe(build_pe([(".text", good, 0x6000, CODE)], 0x1000), "g.bin"))
    r_bad = pi.analyze(write_pe(build_pe([(".text", bad, 0x6000, CODE)], 0x1000), "b.bin"))
    assert "EXEC_SECTION_CODE_LIKE" in ids(r_good) and not r_good["needs_unpacking"]
    assert "SECTION_ENTROPY_HIGH" not in ids(r_bad)       # entropy alone says nothing is wrong
    assert "EXEC_SECTION_NOT_CODE_LIKE" in ids(r_bad)     # structure does
    assert r_bad["needs_unpacking"] and r_bad["packer_classification"]["status"] == "unknown_packer"


def test_structure_check_reports_when_model_missing(write_pe, monkeypatch, tmp_path):
    from malworn.packing import structure as st
    monkeypatch.setenv(st.MODEL_ENV, str(tmp_path))       # empty folder
    r = pi.analyze(write_pe(upx_with_real_stub()))
    assert not r["optional_checks"]["instruction_structure"]["ran"]


def test_local_yara_rules_are_used_if_present(write_pe, monkeypatch, tmp_path):
    pytest.importorskip("yara")
    from malworn.packing import yara_rules
    (tmp_path / "demo.yar").write_text('rule upx_demo { strings: $a = {60 BE} condition: $a }')
    monkeypatch.setenv(yara_rules.RULES_ENV, str(tmp_path))
    r = pi.analyze(write_pe(upx_with_real_stub()))
    assert any(i["source"] == "local_yara_rules" and i["value"]["packer"] == "UPX" for i in r["indicators"])


# ---------------- final packed / not-packed answer with a confidence tier -----------------
@pytest.fixture
def no_die(monkeypatch):
    from malworn.packing import die
    monkeypatch.setenv(die.DIEC_ENV, "")
    monkeypatch.setenv("PATH", "")
    die.clear_cache()


def test_final_packed_high_when_three_families_agree(write_pe, no_die):
    f = pi.analyze(write_pe(upx_with_real_stub()))["final_assessment"]
    assert f["determination"] == "packed" and f["confidence"] == "high"
    assert len(f["evidence_families_supporting"]) >= 3
    assert f["label"] == "PACKED (high confidence)"


def test_final_not_packed_confidence_depends_on_checks_that_ran(write_pe, no_die):
    clean = build_pe([(".text", bytes(range(32)) * 100, 0x1000, CODE)], 0x1000)
    f = pi.analyze(write_pe(clean))["final_assessment"]
    assert f["determination"] == "not_packed" and f["confidence"] == "low"   # DIE + structure did not run
    assert "Checks that did NOT run" in " ".join(f["basis"])
    assert "never a guarantee" in f["caveat"]


def test_final_uncertain_on_borderline_evidence(write_pe, no_die):
    secs = [(".text", bytes(range(32)) * 100, 0x1000, CODE), (".mix", b"A" * 600, 0x1000, DATA | X)]
    r = pi.analyze(write_pe(build_pe(secs, 0x1000)))
    assert r["packing_indicators_level"] == "possible"
    assert r["final_assessment"]["determination"] == "uncertain"
    assert r["user_message"].startswith("FINAL ANSWER: UNCERTAIN")


def test_final_answer_is_the_first_line_of_the_message(write_pe, no_die):
    msg = pi.analyze(write_pe(upx_with_real_stub()))["user_message"]
    assert msg.startswith("FINAL ANSWER: PACKED (high confidence)")


def test_one_call_report_has_each_tool_summary_and_final(write_pe, no_die):
    from malworn.packing import report
    rep = report.packing_report(write_pe(upx_with_real_stub()))
    assert set(rep["summaries"]) == {"packer_signatures", "packing_indicators"}
    assert rep["final"]["determination"] == "packed"
    for needle in ("[1] packer_signatures", "[2] packing_indicators", "FINAL ANSWER: PACKED", "re-upload"):
        assert needle in rep["text"], needle
