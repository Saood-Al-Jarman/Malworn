"""Fine-tuning dataset builder: real tool runs, correct citations, no leaks into the test set."""
import json

import pytest

pytest.importorskip("pefile")

from malworn.agent import verify
from malworn.agent.evaluate_injection import GOALS, build_pe
from malworn.agent.evaluate_questions import QUESTIONS
from malworn.finetune import build_dataset as bd


@pytest.fixture
def corpus(tmp_path):
    files = []
    for i, text in enumerate(["http://update.example.org/check", "C:\\ProgramData\\tool\\log.txt", None]):
        files.append(build_pe(tmp_path / f"f{i}.exe", ascii_text=text, overlay="TRAILER" if i == 2 else None))
    return files


def build(corpus, tmp_path, **kw):
    out = tmp_path / "out"
    result = bd.build(corpus, out, **kw)
    rows = [json.loads(l) for name in ("train", "val") for l in (out / f"{name}.jsonl").read_text().splitlines()]
    return result, rows, out


def test_every_example_is_well_formed_and_passes_the_check(corpus, tmp_path):
    _, rows, out = build(corpus, tmp_path)
    types = {r["meta"]["type"] for r in rows}
    expected = set(bd.QUESTION_TYPES) - ({"attack"} if not bd._capa_works(
        {t.name: t for t in bd.load_tools()[0]}, corpus) else set())
    assert expected | {"injection", "report"} <= types
    for r in rows:
        msgs = r["messages"]
        assert msgs[0]["role"] == "system" and msgs[1]["role"] == "user"
        calls = [c["function"]["name"] for m in msgs if m.get("tool_calls") for c in m["tool_calls"]]
        tool_msgs = [m["name"] for m in msgs if m["role"] == "tool"]
        assert calls == tool_msgs == r["meta"]["tools_called"]          # every call gets its result
        assert msgs[-1]["role"] == "assistant" and "tool_calls" not in msgs[-1]
        problems = verify.check_answer(msgs[-1]["content"], calls, [t["function"]["name"] for t in r["tools"]])
        assert not verify.has_problems(problems), (r["meta"], msgs[-1]["content"])
    assert "| verdict |" in (out / "stats.md").read_text()


def test_answers_use_the_real_tool_results(corpus, tmp_path):
    _, rows, _ = build(corpus, tmp_path)
    ioc = [r for r in rows if r["meta"]["type"] == "iocs" and r["meta"]["file"] == "f0.exe"]
    assert ioc and "http://update.example.org/check" in ioc[0]["messages"][-1]["content"]
    overlay = [r for r in rows if r["meta"]["type"] == "overlay" and r["meta"]["file"] == "f2.exe"]
    assert overlay[0]["messages"][-1]["content"].startswith("Yes: 7 bytes")


def test_validation_split_is_by_file(corpus, tmp_path):
    out = tmp_path / "out"
    bd.build(corpus, out)
    files = lambda name: {json.loads(l)["meta"]["sha256"] for l in (out / f"{name}.jsonl").read_text().splitlines()}
    assert files("val") and not files("train") & files("val")


def test_test_files_are_refused(corpus, tmp_path):
    excluded = bd.sha256_of(corpus[0])
    result, rows, _ = build(corpus, tmp_path, exclude_hashes=[excluded])
    assert excluded not in {r["meta"]["sha256"] for r in rows}
    assert any("test file" in why for _, why in result["refused"])
    assert "32acc1bc543116cbe2cff10cb867772df2f254ff2634c870aef0b46c4b696fdb" in bd.BUILTIN_TEST_HASHES


def test_o3_questions_never_appear(corpus, tmp_path):
    for q in QUESTIONS:
        assert bd.too_close_to_test(q["question"])
    for v in bd.QUESTION_TYPES.values():
        assert not any(bd.too_close_to_test(p) for p in v["phrasings"])
    result, rows, _ = build(corpus, tmp_path, extra_questions={"packed": [QUESTIONS[0]["question"]]})
    assert QUESTIONS[0]["question"] in result["rejected_phrasings"]
    assert QUESTIONS[0]["question"] not in {r["meta"]["question"] for r in rows}


def test_injection_payloads_differ_from_tc10():
    assert not set(bd.INJECTION_PAYLOADS) & set(GOALS.values())


def test_manifest_uses_only_train_rows(corpus, tmp_path):
    manifest = tmp_path / "m.csv"
    manifest.write_text("path,split\n" + f"{corpus[0]},train\n{corpus[1]},test\n{corpus[2]},train\n")
    assert bd.main([str(manifest), "--out", str(tmp_path / "o")]) == 0
    used = {json.loads(l)["meta"]["file"] for n in ("train", "val")
            for l in (tmp_path / "o" / f"{n}.jsonl").read_text().splitlines()}
    assert "f1.exe" not in used and "f0.exe" in used


def test_next_steps_never_name_a_tool_that_was_not_called(corpus, tmp_path):
    _, rows, _ = build(corpus, tmp_path)
    tool_names = [t["function"]["name"] for t in rows[0]["tools"]]
    for r in rows:
        answer = r["messages"][-1]["content"]
        if r["meta"]["type"] in bd.QUESTION_TYPES and bd.ANALYST_STEPS.get(r["meta"]["type"]):
            assert "Next steps:" in answer, r["meta"]
        if "Next steps:" in answer:
            steps = answer.split("Next steps:")[1]
            named = verify.tools_mentioned(steps, tool_names)
            assert set(named) <= set(r["meta"]["tools_called"]), (named, r["meta"]["type"], steps)


def test_exclude_hash_file_ignores_names_and_comments(corpus, tmp_path):
    lst = tmp_path / "test_hashes.txt"
    lst.write_text("# comment line\n" + bd.sha256_of(corpus[0]) + "  B001 calc.exe\n")
    out = tmp_path / "o"
    assert bd.main(["--files", *map(str, corpus), "--out", str(out), "--exclude-hashes", str(lst)]) == 0
    assert "test file" in (out / "stats.md").read_text()


def test_hard_cut_results_are_skipped_not_crashed(corpus, tmp_path, monkeypatch):
    real = bd.result_for_model
    monkeypatch.setattr(bd, "result_for_model",
                        lambda r, keys=None: real(r, keys)[:50] + " ... [result cut: too long]"
                        if r.tool == "strings" else real(r, keys))
    result, rows, out = build(corpus, tmp_path)
    assert result["skipped"] and all(q in ("iocs", "injection", "report") for _, q, _ in result["skipped"])
    assert "Examples skipped" in (out / "stats.md").read_text()


def test_capa_answer_uses_count_the_model_sees():
    """capability_count is hidden from the model; the answer must take the count from the summary."""
    from malworn.finetune.build_dataset import answer_part, build_answer
    view = {"status": "success", "data": {
        "summary": "3 capabilities; none map to an ATT&CK technique.",
        "capabilities": [{"name": "access .NET resource"}, {"name": "manipulate console buffer"},
                         {"name": "compiled to the .NET platform"}],
        "attack_techniques": [], "look_for_next": []}}
    text = answer_part("capa", view, "attack")
    assert "None" not in text.replace("None of them", "")
    assert "3 capabilities" in text and "access .NET resource" in text
    full = build_answer("attack", {"capa": view})
    assert "listed above" not in full          # nothing is listed when no tactics were observed
    empty = {"status": "success", "data": {"summary": "0 capabilities.", "capabilities": [],
                                            "attack_techniques": [], "look_for_next": []}}
    assert "no capabilities" in answer_part("capa", empty, "attack")


def test_every_corpus_file_gets_a_triage_example_when_sampling(corpus, tmp_path):
    """v1 had only 9 triage (multi-tool) examples and missed every O3 triage question."""
    _, rows, _ = build(corpus, tmp_path, per_file=3)
    corpus_files = {r["meta"]["file"] for r in rows if r["meta"]["source"] == "corpus"}
    triaged = {r["meta"]["file"] for r in rows if r["meta"]["source"] == "corpus" and r["meta"]["type"] == "triage"}
    assert corpus_files and triaged == corpus_files


def test_report_examples_have_the_a5_sections_and_untrained_tool_turn(corpus, tmp_path):
    """The full-report examples: every tool run in code, then the five a5 sections. The code-run
    turn has no reasoning_content, so Qwen renders it without <think> and it is not a target."""
    _, rows, _ = build(corpus, tmp_path)
    reports = [r for r in rows if r["meta"]["type"] == "report"]
    assert {r["meta"]["file"] for r in reports} >= {r["meta"]["file"] for r in rows if r["meta"]["source"] == "corpus"}
    for r in reports:
        code_turn = r["messages"][2]
        assert code_turn["role"] == "assistant" and len(code_turn["tool_calls"]) == len(r["tools"])
        assert not code_turn.get("reasoning_content")
        answer = r["messages"][-1]["content"]
        heads = [l for l in answer.splitlines() if l.startswith("## ")]
        assert heads == ["## Summary", "## Evidence", "## MITRE ATT&CK view", "## What we cannot tell yet",
                         "## Next steps"]
    assert any("instruction to an AI assistant" in r["messages"][-1]["content"] for r in reports)
