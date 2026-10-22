"""Tests for the tool contract, and for docs/data-format.md matching it."""

import json
import re
from pathlib import Path

import pytest

from malworn import contract
from malworn.contract import ToolResult, ToolSpec

DOC = Path(__file__).resolve().parents[1] / "docs" / "data-format.md"

SPEC = ToolSpec(
    name="sections",
    description="List the PE sections with their sizes and entropy.",
    data_keys=("section_count", "sections"),
    requirement="FR4",
    owner="Ahmed",
)


# ---------------------------------------------------------------------------
# ToolSpec
# ---------------------------------------------------------------------------
def test_spec_requires_snake_case_name_and_description():
    with pytest.raises(ValueError, match="snake_case"):
        ToolSpec(name="PE Sections", description="x", data_keys=())
    with pytest.raises(ValueError, match="description"):
        ToolSpec(name="sections", description="  ", data_keys=())


# ---------------------------------------------------------------------------
# Building results
# ---------------------------------------------------------------------------
def test_ok_fills_missing_keys_with_none():
    result = contract.ok(SPEC, {"section_count": 2})
    assert result.status == "ok"
    assert result.data == {"section_count": 2, "sections": None}
    assert result.error is None
    assert contract.validate(result, SPEC) == []


def test_ok_rejects_keys_not_in_the_spec():
    with pytest.raises(ValueError, match="not in its ToolSpec"):
        contract.ok(SPEC, {"section_count": 2, "is_packed": True})


def test_failure_and_skipped_keep_every_key():
    for result in (contract.failure(SPEC, "not a PE file"), contract.skipped(SPEC, "PDF input")):
        assert result.data == {"section_count": None, "sections": None}
        assert result.error
        assert contract.validate(result, SPEC) == []


# ---------------------------------------------------------------------------
# run_tool never lets a tool crash the analysis
# ---------------------------------------------------------------------------
def test_run_tool_times_a_good_tool():
    result = contract.run_tool(SPEC, lambda path: contract.ok(SPEC, {"section_count": 1}), "x.exe")
    assert result.status == "ok"
    assert isinstance(result.duration_ms, int)


def test_run_tool_turns_exceptions_into_error_results():
    def broken(path):
        raise FileNotFoundError("x.exe")

    result = contract.run_tool(SPEC, broken, "x.exe")
    assert result.status == "error"
    assert "FileNotFoundError" in result.error
    assert result.data == {"section_count": None, "sections": None}


@pytest.mark.parametrize("bad_return", [{"section_count": 1}, None, "ok"])
def test_run_tool_rejects_non_toolresult_returns(bad_return):
    result = contract.run_tool(SPEC, lambda path: bad_return, "x.exe")
    assert result.status == "error"
    assert "must return a ToolResult" in result.error


def test_run_tool_rejects_a_result_labelled_as_another_tool():
    other = ToolSpec(name="imports", description="x", data_keys=())
    result = contract.run_tool(SPEC, lambda path: contract.ok(other, {}), "x.exe")
    assert result.status == "error"
    assert "expected 'sections'" in result.error


def test_run_tool_reports_bad_keys_as_an_error_not_a_crash():
    result = contract.run_tool(SPEC, lambda path: contract.ok(SPEC, {"verdict": "x"}), "x.exe")
    assert result.status == "error"
    assert "not in its ToolSpec" in result.error


# ---------------------------------------------------------------------------
# Facts only (FR7)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("warning", [
    "The file is malicious",
    "Suspicious API VirtualAlloc imported",
    "Section looks Benign",
    "File is clean",
])
def test_validate_rejects_verdict_words_in_warnings(warning):
    result = contract.ok(SPEC, {}, warnings=[warning])
    problems = contract.validate(result, SPEC)
    assert any("verdict words" in p for p in problems)


def test_validate_accepts_factual_warnings():
    result = contract.ok(SPEC, {}, warnings=["Section UPX1 has entropy 7.91",
                                             "Both sections are writable and executable"])
    assert contract.validate(result, SPEC) == []


def test_validate_catches_status_and_error_mismatches():
    assert any("must not have an error" in p
               for p in contract.validate(ToolResult("sections", "ok", {}, [], error="boom")))
    assert any("explain why" in p
               for p in contract.validate(ToolResult("sections", "error", {}, [])))
    assert any("status must be" in p
               for p in contract.validate(ToolResult("sections", "done", {}, [])))


def test_validate_checks_keys_against_spec():
    result = ToolResult("sections", "ok", {"section_count": 1, "extra": 2}, [])
    problems = contract.validate(result, SPEC)
    assert any("missing keys ['sections']" in p for p in problems)
    assert any("not in the ToolSpec ['extra']" in p for p in problems)


# ---------------------------------------------------------------------------
# The report
# ---------------------------------------------------------------------------
def test_new_report_and_add_result(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ" + b"\x00" * 100)
    report = contract.new_report(sample, original_name="invoice.exe")

    assert report["schema_version"] == contract.SCHEMA_VERSION
    assert report["sample"]["file_name"] == "invoice.exe"
    assert report["sample"]["file_size"] == 102
    # SHA-256 of the bytes written above.
    import hashlib
    assert report["sample"]["sha256"] == hashlib.sha256(sample.read_bytes()).hexdigest()

    contract.add_result(report, contract.ok(SPEC, {"section_count": 0, "sections": []}))
    assert report["tool_calls"] == ["sections"]
    assert report["results"]["sections"]["data"]["section_count"] == 0
    assert contract.validate_report(report, {"sections": SPEC}) == []
    json.dumps(report)  # the report must be plain JSON


def test_validate_report_finds_problems():
    report = {"schema_version": "0.2", "sample": {}, "tool_calls": ["hashes"], "results": {}}
    problems = contract.validate_report(report)
    assert "sample is missing 'sha256'" in problems
    assert "tool_calls lists 'hashes' but it has no result" in problems


# ---------------------------------------------------------------------------
# docs/data-format.md must match the code
# ---------------------------------------------------------------------------
def _doc_catalogue():
    """Build {tool: ToolSpec} from the '### `name`' tables in the tool catalogue."""
    text = DOC.read_text(encoding="utf-8")
    catalogue = text.split("## Tool catalogue", 1)[1].split("\n## ", 1)[0]
    specs = {}
    for block in re.split(r"\n### ", catalogue)[1:]:
        name = re.match(r"`(\w+)`", block).group(1)
        keys = re.findall(r"^\| `(\w+)` \|", block, re.MULTILINE)
        specs[name] = ToolSpec(name=name, description=f"{name} (from docs)", data_keys=keys)
    return specs


def _doc_example_report():
    text = DOC.read_text(encoding="utf-8")
    section = text.split("## Full example report", 1)[1]
    block = re.search(r"```json\n(.*?)\n```", section, re.DOTALL).group(1)
    return json.loads(block)


def test_doc_catalogue_lists_the_five_mvp_tool_areas():
    assert set(_doc_catalogue()) == {
        "hashes", "file_type", "sections", "imports", "packing_indicators", "virustotal",
    }


def test_doc_example_report_follows_the_contract():
    report = _doc_example_report()
    assert report["schema_version"] == contract.SCHEMA_VERSION
    assert contract.validate_report(report, _doc_catalogue()) == []


def test_doc_example_has_no_verdict_anywhere():
    text = json.dumps(_doc_example_report()).lower()
    assert "verdict" not in text
    assert "is_packed" not in text
