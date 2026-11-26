"""capa tool (FR12): capa's JSON -> capabilities, ATT&CK techniques and the tactic chain."""
import json
import subprocess
from pathlib import Path

import pytest

from malworn.attack import capa_tool as ct

FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "capa_upx.json").read_text())


def test_parse_real_capa_output_of_a_upx_file():
    d = ct.parse(FIXTURE)
    names = [c["name"] for c in d["capabilities"]]
    assert "packed with UPX" in names and "contain loop" not in names           # library rules dropped
    assert not any(n.startswith("(internal)") for n in names)
    assert d["packed_limitation"] is True and "packed" in d["limitations"][0]
    assert d["observed_tactics"] == ["Execution", "Defense Evasion"]            # ATT&CK order
    assert d["furthest_tactic"] == "Defense Evasion"
    later = [x["tactic"] for x in d["look_for_next"]]
    assert later[0] == "Credential Access" and later[-1] == "Impact" and "Execution" not in later
    assert all(x["look_for"] for x in d["look_for_next"])
    ids = [t["id"] for t in d["attack_techniques"]]
    assert ids == ["T1129", "T1027.002"]
    assert len(d["tactic_chain"]) == 14 and d["tactic_chain"][3] == {"tactic": "Execution", "observed": True,
                                                                     "techniques": ["T1129"]}


def test_parse_with_no_attack_mapping():
    d = ct.parse({"meta": {"version": "x"}, "rules": {"read file": {"meta": {"namespace": "host/file"}}}})
    assert d["observed_tactics"] == [] and d["furthest_tactic"] is None and d["look_for_next"] == []
    assert "none map" in d["summary"]


def test_non_pe_is_skipped(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("hello")
    assert ct.run(f).status == "skipped"


def test_missing_capa_is_a_clear_failure(tmp_path, monkeypatch):
    f = tmp_path / "a.exe"
    f.write_bytes(b"MZ" + bytes(100))
    monkeypatch.delenv("MALWORN_CAPA", raising=False)
    monkeypatch.setattr(ct.shutil, "which", lambda name: None)
    r = ct.run(f)
    assert r.status == "failure" and "not installed" in r.error


def test_run_parses_capa_json_and_passes_rule_paths(tmp_path, monkeypatch):
    f = tmp_path / "a.exe"
    f.write_bytes(b"MZ" + bytes(100))
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(FIXTURE), stderr="")
    monkeypatch.setenv("MALWORN_CAPA", "/opt/capa")
    monkeypatch.setenv("MALWORN_CAPA_RULES", "/r")
    monkeypatch.setenv("MALWORN_CAPA_SIGS", "/s")
    monkeypatch.setattr(ct.subprocess, "run", fake_run)
    r = ct.run(f)
    assert r.status == "success" and r.warnings and "packed" in r.warnings[0]
    assert seen["cmd"][:6] == ["/opt/capa", "--json", "-r", "/r", "-s", "/s"]


def test_capa_error_output_becomes_a_failure(tmp_path, monkeypatch):
    f = tmp_path / "a.exe"
    f.write_bytes(b"MZ" + bytes(100))
    monkeypatch.setenv("MALWORN_CAPA", "/opt/capa")
    monkeypatch.setattr(ct.subprocess, "run", lambda cmd, **kw: subprocess.CompletedProcess(
        cmd, 14, stdout="", stderr="ERROR    capa: Input file does not appear to be a supported file.\n"))
    r = ct.run(f)
    assert r.status == "failure" and "supported file" in r.error


def test_capa_is_offered_to_the_model_and_a5_explains_it():
    from malworn.agent.prompts import AGENT_PROMPTS, DEFAULT_AGENT_PROMPT
    from malworn.agent.tools import load_tools
    names = [t.name for t in load_tools()[0]]
    assert names.index("capa") == names.index("virustotal") - 1
    assert DEFAULT_AGENT_PROMPT == "a5"
    assert "## MITRE ATT&CK view" in AGENT_PROMPTS["a5"] and "10. capa" in AGENT_PROMPTS["a5"]
    assert AGENT_PROMPTS["a5"].startswith(AGENT_PROMPTS["a4"].split("Answer format")[0].rstrip()[:2000])


def test_attack_template_answer_passes_the_check(monkeypatch):
    from malworn.agent import verify
    from malworn.finetune import build_dataset as bd
    view = {"status": "success", "data": {k: v for k, v in ct.parse(FIXTURE).items()}}
    answer = bd.build_answer("attack", {"capa": view})
    assert "T1027.002" in answer and "Defense Evasion" in answer and "not a prediction" in answer
    assert not verify.has_problems(verify.check_answer(answer, ["capa"], ["capa", "imports"]))
