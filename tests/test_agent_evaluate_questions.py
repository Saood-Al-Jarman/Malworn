"""O3 question evaluation, with a scripted model and real tools."""

import json

import pytest

from malworn.agent import evaluate_questions as eq
from malworn.agent.tools import load_tools

from tests.conftest import DONE, FakeOllama


def call(*names):
    return [{"message": {"role": "assistant", "content": "",
                         "tool_calls": [{"function": {"name": n, "arguments": {}}} for n in names]}}, DONE]


def answer(text):
    return [{"message": {"role": "assistant", "content": text}}, DONE]


def test_answer_key_uses_only_real_tools():
    names = {t.name for t in load_tools()[0]}
    for q in eq.QUESTIONS:
        used = {t for group in q["required"] for t in group} | set(q["acceptable"])
        assert used <= names, q["id"]
    assert len({q["id"] for q in eq.QUESTIONS}) == len(eq.QUESTIONS)


@pytest.mark.parametrize("selected, correct, exact, unnecessary", [
    (["packer_signatures"], True, True, []),
    (["packing_indicators", "sections"], True, True, []),
    (["packing_indicators", "strings"], True, False, ["strings"]),
    (["sections"], False, False, []),
])
def test_scoring_with_alternatives(selected, correct, exact, unnecessary):
    q = next(q for q in eq.QUESTIONS if q["id"] == "packer_name")
    s = eq.score_selection(q, selected)
    assert (s["correct"], s["exact"], s["unnecessary"]) == (correct, exact, unnecessary)


def test_triage_needs_every_group():
    q = next(q for q in eq.QUESTIONS if q["id"] == "triage")
    s = eq.score_selection(q, ["file_type", "packing_indicators"])
    assert not s["correct"] and s["missing_groups"] == [["virustotal"]]


def test_runs_questions_and_scores_them(fake_ollama, tmp_path, capsys):
    sample = tmp_path / "notes.bin"
    sample.write_bytes(b"not a program http://example.invalid")
    FakeOllama.script = [
        call("hashes"), answer("MD5 and SHA-256 are in [hashes]."),                     # hashes: exact
        call("hashes", "strings"), answer("It is a text file [hashes] with a URL [strings]."),  # file_type: missed
    ]
    out = tmp_path / "q"
    code = eq.main([str(sample), "--only", "hashes", "file_type", "--url", fake_ollama, "--out", str(out)])
    assert code == 0
    data = json.loads((out / "summary.json").read_text())
    by_q = {r["question_id"]: r for r in data["runs"]}
    assert by_q["hashes"]["exact"] is True
    assert by_q["file_type"]["correct"] is False and by_q["file_type"]["unnecessary"] == ["strings"]
    assert data["summary"]["a3+check"]["correct"] == 1
    # the model chose every tool itself: nothing ran in code
    assert "already been run" not in FakeOllama.received[0]["messages"][1]["content"]
    assert "Correct tool selection (O3 target 90%) | 1/2 (50%)" in capsys.readouterr().out
