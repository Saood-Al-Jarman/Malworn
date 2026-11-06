"""The agent comparison script, with a scripted model and real tools."""

import json

import pytest

from malworn.agent import evaluate_agent

from tests.conftest import DONE, FakeOllama


def call(*names):
    return [{"message": {"role": "assistant", "content": "",
                         "tool_calls": [{"function": {"name": n, "arguments": {}}} for n in names]}}, DONE]


def answer(text):
    return [{"message": {"role": "assistant", "content": text}}, DONE]


@pytest.fixture
def sample(tmp_path):
    path = tmp_path / "notes.bin"
    path.write_bytes(b"not a program http://example.invalid")
    return path


def test_compares_configs_and_scores_each_run(fake_ollama, sample, tmp_path, capsys):
    FakeOllama.script = [
        # a2, no check: stops early, cites a tool it never ran, leans to a verdict
        call("hashes"), answer("Looks legitimate. No URLs [strings]."),
        # a3+check: same mistake first, then the correction makes it call the tools
        call("hashes"), answer("No URLs [strings]."),
        call("file_type", "strings", "virustotal"),
        answer("A URL [strings]; not a PE [file_type]; unknown to VirusTotal [virustotal]; hash [hashes]."),
    ]
    out = tmp_path / "eval"
    code = evaluate_agent.main([str(sample), "--configs", "a2", "a3+check", "--runs", "1",
                                "--url", fake_ollama, "--out", str(out)])
    assert code == 0

    data = json.loads((out / "summary.json").read_text())
    a2, a3 = data["runs"]
    assert a2["config"] == "a2" and a2["tool_recall"] == 0.25
    assert a2["cited_not_run_final"] == ["strings"] and a2["verdict_final"]
    assert a3["tool_recall"] == 1.0 and a3["missed_tools"] == []
    assert a3["cited_not_run_first"] == ["strings"] and a3["cited_not_run_final"] == []
    assert a3["corrections"] == 1

    s = data["summary"]
    assert s["a2"]["runs_citing_unrun_tools_final"] == 1
    assert s["a3+check"]["runs_citing_unrun_tools_final"] == 0
    assert s["a3+check"]["runs_with_all_expected_tools"] == 1

    # seeds are passed to the model, and each run's outputs are saved
    assert [r["options"]["seed"] for r in FakeOllama.received] == [1] * len(FakeOllama.received)
    assert (out / "notes_a3-check_seed1" / "explanation.md").is_file()
    table = capsys.readouterr().out
    assert "| Mean tool recall (O3 target 0.9) | 0.25 | 1.00 |" in table


def test_expected_tools_depend_on_the_file_type(tmp_path):
    pe, other = tmp_path / "a.exe", tmp_path / "b.txt"
    pe.write_bytes(b"MZ...")
    other.write_bytes(b"hello")
    tools = ["hashes", "file_type", "sections", "strings", "virustotal"]
    assert evaluate_agent.expected_tools(pe, tools) == tools
    assert evaluate_agent.expected_tools(other, tools) == ["hashes", "file_type", "strings", "virustotal"]


@pytest.mark.parametrize("bad", ["a9", "a3+fast"])
def test_rejects_unknown_configs(sample, bad, capsys):
    assert evaluate_agent.main([str(sample), "--configs", bad]) == 2
