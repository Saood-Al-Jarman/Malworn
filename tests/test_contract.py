"""Tests for the tool contract, and for docs/data-format.md matching the real code
(Ahmed's tools in static_analysis/ and Hassan's aggregator in detection/)."""

import json
import re
from pathlib import Path

import pytest

from malworn import contract
from malworn.contract import ToolResult, ToolSpec
from malworn.detection.malworn_aggregator import aggregate_agent_run, aggregate_results
from malworn.static_analysis import file_type, hashes, imports, sections, strings

DOC = Path(__file__).resolve().parents[1] / "docs" / "data-format.md"

SPEC = ToolSpec(
    name="sections",
    description="List the PE sections with their sizes and entropy.",
    data_keys=("sections",),
    requirement="FR4",
    owner="Ahmed",
)


# ---------------------------------------------------------------------------
# docs/data-format.md, parsed
# ---------------------------------------------------------------------------
def doc_specs():
    """{tool: ToolSpec} built from the '### `name`' tables in the tool catalogue."""
    text = DOC.read_text(encoding="utf-8")
    catalogue = text.split("## Tool catalogue", 1)[1].split("\n## ", 1)[0]
    specs = {}
    for block in re.split(r"\n### ", catalogue)[1:]:
        name = re.match(r"`(\w+)`", block).group(1)
        keys = re.findall(r"^\| `(\w+)` \|", block, re.MULTILINE)
        specs[name] = ToolSpec(name=name, description=f"{name} (from docs)", data_keys=keys)
    return specs


def doc_example_run():
    text = DOC.read_text(encoding="utf-8")
    section = text.split("### Example agent run", 1)[1]
    return json.loads(re.search(r"```json\n(.*?)\n```", section, re.DOTALL).group(1))


# ---------------------------------------------------------------------------
# ToolSpec
# ---------------------------------------------------------------------------
def test_spec_requires_snake_case_name_and_description():
    with pytest.raises(ValueError, match="snake_case"):
        ToolSpec(name="PE Sections", description="x", data_keys=())
    with pytest.raises(ValueError, match="description"):
        ToolSpec(name="sections", description="  ", data_keys=())


def test_tool_catalogue_is_what_the_model_sees():
    other = ToolSpec(name="imports", description="List imported DLLs.", data_keys=())
    assert contract.tool_catalogue([SPEC, other]) == [
        {"name": "sections", "description": "List the PE sections with their sizes and entropy."},
        {"name": "imports", "description": "List imported DLLs."},
    ]
    with pytest.raises(ValueError, match="duplicate"):
        contract.tool_catalogue([SPEC, SPEC])


# ---------------------------------------------------------------------------
# Building results
# ---------------------------------------------------------------------------
def test_success_fills_missing_keys_and_rejects_unknown_ones():
    result = contract.success(SPEC, {})
    assert result.status == "success"
    assert result.data == {"sections": None}
    assert contract.validate(result, SPEC) == []
    with pytest.raises(ValueError, match="not in its SPEC"):
        contract.success(SPEC, {"sections": [], "is_packed": True})


def test_failure_and_skipped_explain_why():
    for result in (contract.failure(SPEC, "not a PE file"), contract.skipped(SPEC, "PDF input")):
        assert result.data == {}
        assert result.error
        assert contract.validate(result, SPEC) == []


def test_to_dict_leaves_out_an_unset_call_id():
    assert "call_id" not in contract.success(SPEC, {}).to_dict()


# ---------------------------------------------------------------------------
# run_tool: normalises results and never lets a tool crash the analysis
# ---------------------------------------------------------------------------
def test_run_tool_accepts_a_plain_dict_like_ahmeds_tools():
    def run(path):
        return {"tool": "sections", "status": "success", "data": {"sections": []}}

    result = contract.run_tool(SPEC, run, "x.exe", call_id="call-001")
    assert result.status == "success"
    assert result.warnings == []
    assert result.call_id == "call-001"
    assert isinstance(result.duration_ms, int)
    assert contract.validate(result, SPEC) == []


@pytest.mark.parametrize("given, expected", [("ok", "success"), ("error", "failure"), ("OK", "success")])
def test_run_tool_converts_status_aliases(given, expected):
    def run(path):
        return {"tool": "sections", "status": given, "data": {}, "error": None if expected == "success" else "x"}

    assert contract.run_tool(SPEC, run, "x.exe").status == expected


def test_run_tool_turns_exceptions_into_failures():
    def broken(path):
        raise FileNotFoundError("x.exe")

    result = contract.run_tool(SPEC, broken, "x.exe")
    assert result.status == "failure"
    assert "FileNotFoundError" in result.error


@pytest.mark.parametrize("bad, message", [
    (lambda p: None, "must return a dict"),
    (lambda p: {"tool": "imports", "status": "success", "data": {}}, "expected 'sections'"),
    (lambda p: {"tool": "sections", "status": "done", "data": {}}, "unknown status"),
    (lambda p: {"tool": "sections", "status": "success", "data": [1, 2]}, "data must be a dict"),
    (lambda p: {"tool": "sections", "status": "success", "data": {"verdict": "x"}}, "not in its SPEC"),
])
def test_run_tool_reports_bad_results_as_failures(bad, message):
    result = contract.run_tool(SPEC, bad, "x.exe")
    assert result.status == "failure"
    assert message in result.error


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("warning", [
    "The file is malicious",
    "Suspicious API VirtualAlloc imported",
    "Section looks Benign",
    "File is clean",
])
def test_validate_rejects_verdict_words_in_warnings(warning):
    result = contract.success(SPEC, {}, warnings=[warning])
    assert any("verdict words" in p for p in contract.validate(result, SPEC))


def test_validate_accepts_factual_warnings():
    result = contract.success(SPEC, {}, warnings=["Section UPX1 has entropy 7.91",
                                                  "Both sections are writable and executable"])
    assert contract.validate(result, SPEC) == []


def test_validate_reports_what_run_tool_would_fix_in_a_plain_dict():
    raw = {"tool": "sections", "status": "ok", "data": {"sections": []}}
    problems = contract.validate(raw, SPEC)
    assert any("status must be one of" in p for p in problems)
    assert any("warnings is missing" in p for p in problems)


def test_validate_checks_status_error_and_keys():
    assert any("must not have an error" in p
               for p in contract.validate(ToolResult("sections", "success", {}, [], error="boom")))
    assert any("explain why" in p
               for p in contract.validate(ToolResult("sections", "failure", {}, [])))
    problems = contract.validate(ToolResult("sections", "success", {"extra": 1}, []), SPEC)
    assert any("missing keys ['sections']" in p for p in problems)
    assert any("not in the SPEC ['extra']" in p for p in problems)


# ---------------------------------------------------------------------------
# Ahmed's real tools fit the contract and the doc
# ---------------------------------------------------------------------------
TOOLS = {"hashes": hashes, "file_type": file_type, "sections": sections,
         "imports": imports, "strings": strings}


@pytest.fixture
def not_a_pe(tmp_path):
    path = tmp_path / "notes.bin"
    path.write_bytes(b"Hello Malworn\x00http://example.invalid/path\x00")
    return path


@pytest.mark.parametrize("name", ["hashes", "file_type", "strings"])
def test_real_tools_that_work_on_any_file_match_the_doc(name, not_a_pe):
    spec = doc_specs()[name]
    result = contract.run_tool(spec, TOOLS[name].run, not_a_pe)
    assert result.status == "success", result.error
    assert contract.validate(result, spec) == []


@pytest.mark.parametrize("name", ["sections", "imports"])
def test_real_pe_tools_fail_cleanly_on_a_non_pe_file(name, not_a_pe):
    spec = doc_specs()[name]
    result = contract.run_tool(spec, TOOLS[name].run, not_a_pe)
    assert result.status == "failure"
    assert "PEFormatError" in result.error
    assert contract.validate(result, spec) == []


def test_real_sections_and_imports_output_match_the_doc(monkeypatch):
    # The PE parsing itself is covered by Ahmed's tests; here we check the shape.
    monkeypatch.setattr(sections, "analyze_sections", lambda p: [
        {"name": "UPX1", "virtual_address": 4096, "virtual_size": 10, "raw_size": 10, "entropy": 7.91}])
    monkeypatch.setattr(imports, "analyze_imports", lambda p: {
        "dll_count": 1, "function_count": 1, "dlls": [{"dll": "KERNEL32.DLL", "functions": ["ExitProcess"]}]})
    specs = doc_specs()
    for name in ("sections", "imports"):
        result = contract.run_tool(specs[name], TOOLS[name].run, "x.exe")
        assert result.status == "success", result.error
        assert contract.validate(result, specs[name]) == []


# ---------------------------------------------------------------------------
# Results go through Hassan's aggregator
# ---------------------------------------------------------------------------
def test_run_tool_results_are_accepted_by_the_aggregator(not_a_pe):
    specs = doc_specs()
    results = [contract.run_tool(specs[name], TOOLS[name].run, not_a_pe, call_id=f"call-{i:03d}").to_dict()
               for i, name in enumerate(["hashes", "file_type", "sections"], 1)]
    report = aggregate_results(results, file_info={"file_name": "notes.bin",
                                                   "sha256": results[0]["data"]["sha256"]})
    summary = report["execution_summary"]
    assert summary["successful_calls"] == 2
    assert [f["tool"] for f in summary["failed_calls"]] == ["sections"]
    assert report["tool_results"][0]["facts"][0]["source_tool"] == "hashes"
    assert report["tool_results"][0]["provenance"]["tool_version"] == "0.1"


# ---------------------------------------------------------------------------
# docs/data-format.md matches the code
# ---------------------------------------------------------------------------
def test_doc_catalogue_lists_every_tool():
    assert set(doc_specs()) == {"hashes", "file_type", "sections", "imports", "strings",
                                "packing_indicators", "virustotal"}


def test_doc_example_results_follow_the_contract():
    specs = doc_specs()
    for result in doc_example_run()["tool_results"]:
        assert contract.validate(result, specs[result["tool"]]) == [], result["tool"]


def test_doc_example_run_goes_through_the_aggregator():
    report = aggregate_agent_run(doc_example_run())
    summary = report["execution_summary"]
    assert summary["not_selected_tools"] == ["strings"]
    assert summary["missing_results"] == []
    assert summary["successful_calls"] == 6
    text = json.dumps(report).lower()
    assert "verdict" not in text.replace("no malware verdict", "")
    assert "is_packed" not in text
