# AI assistance: Claude (Anthropic), October 2026. Used for: integration tests between the packing tools, the aggregator and the report generator. To be reviewed by Viha.
"""Compatibility tests: packing tools <-> Detect It Easy first <-> aggregator <-> report generator."""
import json
import os
import stat
import sys

import pytest

from malworn import packing
from malworn.packing import die, indicators
agg = pytest.importorskip("malworn.detection.malworn_aggregator")     # exists in the full repo
rg = pytest.importorskip("malworn.detection.report_generator")

sys.path.insert(0, os.path.dirname(__file__))
from test_packing_indicators import build_pe, upx_with_real_stub, CODE, DATA, X  # noqa: E402

FAKE_DIE_JSON = {"detects": [{"filetype": "PE32", "values": [
    {"type": "linker", "name": "Microsoft Linker", "version": "14", "info": ""},
    {"type": "packer", "name": "UPX", "version": "4.24", "info": "NRV, brute"},
    {"type": "~packer", "name": "Generic", "version": "", "info": ""},
    {"type": "~protection", "name": "Generic", "version": "", "info": ""}]}]}


@pytest.fixture
def fake_diec(tmp_path, monkeypatch):
    """A stand-in `diec` that prints canned JSON and logs each call (so order/caching can be tested)."""
    log = tmp_path / "calls.log"
    script = tmp_path / "diec"
    script.write_text('#!/bin/sh\ncase "$1" in --version) echo "die 3.21"; exit 0;; esac\n'
                      f'echo run >> "{log}"\ncat <<\'EOF\'\n{json.dumps(FAKE_DIE_JSON)}\nEOF\n')
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv(die.DIEC_ENV, str(script))
    die.clear_cache()
    yield log
    die.clear_cache()


@pytest.fixture
def sample(tmp_path):
    p = tmp_path / "s.bin"
    p.write_bytes(upx_with_real_stub())
    return str(p)


def test_die_output_is_parsed(fake_diec, sample):
    r = die.run_die(sample)
    assert r["ran"] and r["version"] == "die 3.21"
    assert any(p["name"] == "UPX" and p["info"] == "NRV, brute" for p in r["packers"])
    assert r["other_detections"] and r["other_detections"][0]["type"] == "linker"


def test_die_runs_once_and_before_other_checks(fake_diec, sample, monkeypatch):
    order = []
    real_struct = indicators._structure_indicators
    real_die = die.run_die
    monkeypatch.setattr(die, "run_die", lambda p: (order.append("die"), real_die(p))[1])
    monkeypatch.setattr(indicators, "_structure_indicators",
                        lambda *a, **k: (order.append("structure"), real_struct(*a, **k))[1])
    packing.run_packing_checks(sample)
    assert order[0] == "die" and "structure" in order
    assert fake_diec.read_text().count("run") == 1          # cached: one DIE run per sample


def test_selecting_only_packing_indicators_still_runs_die_first(fake_diec, sample):
    res = packing.packing_indicators.run(sample)
    assert res["status"] == "success"
    assert fake_diec.read_text().count("run") == 1
    ids = {e["id"] for e in res["data"]["evidence_for"]}
    assert "DIE_PACKER_DETECTED" in ids and "DIE_GENERIC_HEURISTIC" in ids
    assert "Detect It Easy" in res["data"]["message_for_analyst"]


def test_missing_diec_is_reported_not_hidden(monkeypatch, sample):
    monkeypatch.setenv(die.DIEC_ENV, "")
    monkeypatch.setenv("PATH", "")
    die.clear_cache()
    res = packing.packing_indicators.run(sample)
    assert res["status"] == "success"
    assert any("Detect It Easy was NOT run" in w for w in res["warnings"])
    assert "WARNING: Detect It Easy was NOT run" in res["data"]["message_for_analyst"]


def test_non_pe_is_skipped_but_die_still_runs(fake_diec, tmp_path):
    p = tmp_path / "x.txt"; p.write_bytes(b"hello world")
    res = packing.run_packing_checks(str(p))
    assert res[0]["status"] == "success" and res[0]["data"]["pe_checks"].startswith("skipped")
    assert res[1]["status"] == "skipped" and res[1]["warnings"]


def test_results_pass_the_real_aggregator(fake_diec, sample):
    results = packing.run_packing_checks(sample)
    report = agg.aggregate_results(results, file_info={"sha256": "a" * 64},
                                   selected_tools=packing.PACKING_TOOL_ORDER)
    assert report["execution_summary"]["successful_calls"] == 2
    assert report["execution_summary"]["total_facts"] > 0
    assert not report["execution_summary"]["missing_results"]
    json.dumps(report, allow_nan=False)                       # no NaN/Infinity anywhere


def test_report_generator_renders_sections_table(fake_diec, sample, tmp_path):
    report = agg.aggregate_results(packing.run_packing_checks(sample), file_info={"sha256": "a" * 64})
    view = rg.build_view(report)
    sec = next(s for s in view["sections"] if s["tool"] == "packing_indicators")
    table = next(t for t in sec["tables"] if t["title"] == "Sections")
    assert any("UPX1" in row for row in table["rows"])          # per_section feeds the Sections table
    out = tmp_path / "r.html"
    rg.render_html(report, out)
    html = out.read_text(encoding="utf-8")
    assert "Packing and obfuscation indicators" in html and "Packer signatures" in html
