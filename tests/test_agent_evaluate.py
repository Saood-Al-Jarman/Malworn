"""Tests for the prompt comparison script.

The fixtures in tests/fixtures/ are real Qwen 3 8B answers to
examples/reports/invoice_upx.json (prompt v0 and v1, seed 42), so these tests
check the mistake detectors against what the model actually wrote."""

import json
from pathlib import Path

import pytest

from malworn.agent import evaluate
from malworn.agent.client import load_report

from tests.conftest import DONE, FakeOllama

ROOT = Path(__file__).resolve().parents[1]
REPORT = load_report(ROOT / "examples" / "reports" / "invoice_upx.json")
FIXTURES = Path(__file__).parent / "fixtures"


def flagged(answer):
    return {key for key, hits in evaluate.run_checks(answer, REPORT).items() if hits}


# ---------------------------------------------------------------------------
# Real answers: the checks must agree with the hand review
# ---------------------------------------------------------------------------
def test_real_v0_answer_flags_match_hand_review():
    answer = (FIXTURES / "answer_v0_seed42.md").read_text(encoding="utf-8")
    assert flagged(answer) == {"assumes_executed", "stub_imports", "bad_lookup", "invented_apis"}


def test_real_v1_answer_flags_match_hand_review():
    answer = (FIXTURES / "answer_v1_seed42.md").read_text(encoding="utf-8")
    assert flagged(answer) == {"unsafe_sandbox"}


# ---------------------------------------------------------------------------
# Individual checks: one sentence that should flag, one that should not
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "check, bad, good",
    [
        ("proof_language",
         "The registry string confirms persistence.",
         "Static analysis cannot confirm persistence; confirm it with dynamic analysis."),
        ("assumes_executed",
         "Next, check for registry modifications on the host.",
         "Static analysis cannot determine if the file modifies the registry."),
        ("assumes_executed",
         "The malware has modified the Run key.",
         "The file contains a string referencing the Run key."),
        ("bad_lookup",
         "Upload the file to VirusTotal.",
         "Never upload the sample; search its SHA-256 hash instead."),
        ("bad_lookup",
         "Search for invoice.exe or its hash on VirusTotal.",
         "Search for its SHA-256 hash on VirusTotal."),
        ("upx_encrypts",
         "UPX encrypts the file and enhances security.",
         "UPX compresses the file; it does not encrypt it."),
        ("unsafe_sandbox",
         "Run it only after confirming it is safe to execute.",
         "It is never safe to run outside an isolated sandbox."),
        ("stub_imports",
         "VirtualProtect could be used for code injection.",
         "VirtualProtect and LoadLibraryA most likely belong to the UPX unpacking stub."),
    ],
)
def test_check_flags_bad_and_passes_good(check, bad, good):
    fn = evaluate.CHECKS[check][1]
    assert fn(bad, REPORT), f"{check} should flag: {bad}"
    assert not fn(good, REPORT), f"{check} should not flag: {good}"


def test_stub_check_only_applies_to_packed_files():
    unpacked = dict(REPORT, packing={"is_packed": False})
    text = "It imports VirtualProtect and LoadLibraryA."
    assert evaluate.check_stub_imports(text, REPORT)
    assert not evaluate.check_stub_imports(text, unpacked)


# ---------------------------------------------------------------------------
# End to end against the fake Ollama server
# ---------------------------------------------------------------------------
def test_main_runs_every_prompt_and_seed(fake_ollama, tmp_path, capsys):
    FakeOllama.chunks = [
        {"message": {"role": "assistant", "content": "UPX encrypts the file."}},
        DONE,
    ]
    out = tmp_path / "eval"
    code = evaluate.main([
        str(ROOT / "examples" / "reports" / "invoice_upx.json"),
        "--prompts", "v0", "v1", "--runs", "2", "--url", fake_ollama, "--out", str(out),
    ])
    assert code == 0

    # 2 prompts x 2 seeds, each with its own seed, same seeds for both prompts.
    sent = FakeOllama.received
    assert len(sent) == 4
    assert [r["options"]["seed"] for r in sent] == [1, 2, 1, 2]
    assert sorted(p.name for p in out.glob("invoice_upx_*.json")) == [
        "invoice_upx_v0_seed1.json", "invoice_upx_v0_seed2.json",
        "invoice_upx_v1_seed1.json", "invoice_upx_v1_seed2.json",
    ]

    summary = json.loads((out / "summary.json").read_text())
    assert summary["v0"]["mistakes"]["upx_encrypts"] == 2
    assert summary["v1"]["clean_runs"] == 0

    table = capsys.readouterr().out
    assert "| Says packing encrypts / adds security | 2/2 | 2/2 |" in table
    assert "UPX encrypts the file" in (out / "summary.md").read_text()


def test_main_rejects_zero_runs(capsys):
    assert evaluate.main([str(ROOT / "examples" / "reports" / "invoice_upx.json"), "--runs", "0"]) == 2


# ---------------------------------------------------------------------------
# Real sentences from the first 5-seed run (2026-10-22). Each was flagged by the
# first version of the checks; the hand review decided whether that was right.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "check, sentence",
    [
        # Advice on HOW to confirm is correct, not a claim of proof.
        ("proof_language", "The analyst should prioritize unpacking and behavioral testing to confirm the threat."),
        ("proof_language", "Cross-check the hash with known malware databases (e.g., VirusTotal) to confirm if it's a known threat."),
        ("proof_language", "Unpack the file and analyze its original code. This will help confirm if it's malicious."),
        # "instead of uploading" is the right advice.
        ("bad_lookup", "Search the hash (SHA-256) against threat intelligence databases instead of uploading the file to external services."),
        # Plural "stubs" still means the imports were attributed to the stub.
        ("stub_imports", "The imports for `VirtualProtect` and `LoadLibraryA` are typical of UPX stubs, not the actual payload."),
        # Correct general description of entropy, not "UPX encrypts".
        ("upx_encrypts", "The high entropy (7.91) in UPX1 suggests the data is encrypted or compressed, making it harder to analyze."),
        ("upx_encrypts", "High entropy (7.91) in `UPX1` (encrypted/compressed data)."),
    ],
)
def test_real_false_alarms_are_not_flagged(check, sentence):
    assert not evaluate.CHECKS[check][1](sentence, REPORT)


@pytest.mark.parametrize(
    "check, sentence",
    [
        ("stub_imports", "`VirtualProtect`: Used to change memory permissions (often for code injection)."),
        ("stub_imports", "The file imports functions like `VirtualProtect` (used to modify memory) and `LoadLibraryA` (loads DLLs)."),
        ("assumes_executed", "Use Registry Editor to see if the malware has written itself to the registry."),
        ("assumes_executed", "Use tools like Process Monitor or Regmon to check if the malware writes to the registry key."),
        ("bad_lookup", "Check if 'invoice.exe' or its hashes are listed in malware databases."),
    ],
)
def test_real_mistakes_are_still_flagged(check, sentence):
    assert evaluate.CHECKS[check][1](sentence, REPORT)


def test_recheck_rescores_saved_runs_without_the_model(tmp_path, capsys):
    # A saved run whose flags were computed by an older, buggier check.
    record = {
        "prompt_version": "v1",
        "seed": 4,
        "seconds": 11.5,
        "answer": "The imports `VirtualProtect` and `LoadLibraryA` are typical of UPX stubs.",
        "thinking": "",
        "stats": {"output_tokens": 743},
        "flags": {"stub_imports": ["old false alarm"]},
    }
    (tmp_path / "invoice_upx_v1_seed4.json").write_text(json.dumps(record))

    code = evaluate.main([str(ROOT / "examples" / "reports" / "invoice_upx.json"),
                          "--recheck", str(tmp_path), "--url", "http://127.0.0.1:9"])
    assert code == 0

    updated = json.loads((tmp_path / "invoice_upx_v1_seed4.json").read_text())
    assert updated["flags"]["stub_imports"] == []
    summary = json.loads((tmp_path / "summary.json").read_text())
    assert summary["v1"]["clean_runs"] == 1
    assert summary["v1"]["avg_seconds"] == 11.5
    assert "**1/1**" in capsys.readouterr().out


def test_recheck_empty_folder(tmp_path):
    assert evaluate.main([str(ROOT / "examples" / "reports" / "invoice_upx.json"),
                          "--recheck", str(tmp_path)]) == 2
