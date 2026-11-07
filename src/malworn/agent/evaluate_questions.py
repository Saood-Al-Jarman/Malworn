"""Sub-objective O3: does the agent select the correct tools for a request?

Owner: Saood

A full analysis runs every tool in code (loop preset "all"), so tool choice is
measured where it matters: narrow analyst questions. Each question has an
answer key:

  required    groups of tools; at least one tool from every group must be
              called (e.g. "which packer?" can be answered by packer_signatures
              or packing_indicators)
  acceptable  tools that are reasonable extras for the question

A selection is CORRECT when every required group is covered (the O3 measure,
target: at least 90% of requests). It is EXACT when it is correct and calls
nothing outside required + acceptable. Unnecessary tools are counted too.

Usage (inside the VM; each question takes roughly 10-30 s):

    PYTHONPATH=src python3 -m malworn.agent.evaluate_questions ~/demo-files/launcher.exe ~/demo-files/launcher_upx.exe
    ... --configs a3+check a3 --runs 2

Output: runs/questions_eval_<time>/summary.md, summary.json, one folder per run.
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from malworn.agent import verify
from malworn.agent.client import DEFAULT_MODEL, DEFAULT_OLLAMA_URL, OllamaError
from malworn.agent.evaluate_agent import live_progress, parse_config
from malworn.agent.loop import run_agent, save_outputs
from malworn.agent.tools import load_tools

# The answer key. Written for Windows PE files (the demo files are both PE).
QUESTIONS = [
    {"id": "packed", "question": "Is this file packed? What is the evidence?",
     "required": [["packing_indicators"]],
     "acceptable": ["packer_signatures", "sections", "file_type", "imports"]},
    {"id": "packer_name", "question": "Which packer was used on this file, if any?",
     "required": [["packer_signatures", "packing_indicators"]],
     "acceptable": ["packer_signatures", "packing_indicators", "sections", "file_type"]},
    {"id": "imports", "question": "Which DLLs and API functions does this file import?",
     "required": [["imports"]],
     "acceptable": ["file_type", "packing_indicators"]},
    {"id": "virustotal", "question": "Is this file known to VirusTotal, and how many engines flag it?",
     "required": [["virustotal"]],
     "acceptable": ["hashes"]},
    {"id": "signed", "question": "Is this file digitally signed, and which company and product does it claim to be?",
     "required": [["version_info"]],
     "acceptable": ["file_type"]},
    {"id": "iocs", "question": "Does the file contain any URLs, IP addresses, file paths or registry keys?",
     "required": [["strings"]],
     "acceptable": ["packing_indicators", "file_type"]},
    {"id": "overlay", "question": "Does this file have extra data appended after the end of the program (an overlay)?",
     "required": [["extra_checks"]],
     "acceptable": ["file_type", "sections"]},
    {"id": "hashes", "question": "What are the MD5, SHA-1 and SHA-256 hashes of this file?",
     "required": [["hashes"]],
     "acceptable": []},
    {"id": "file_type", "question": "What type of file is this?",
     "required": [["file_type"]],
     "acceptable": ["hashes"]},
    {"id": "sections", "question": "List the sections of this file and say which ones have high entropy.",
     "required": [["sections"]],
     "acceptable": ["packing_indicators", "file_type"]},
    {"id": "imphash", "question": "What is this file's imphash, so I can search for related samples?",
     "required": [["extra_checks"]],
     "acceptable": ["imports", "hashes"]},
    {"id": "triage", "question": "Give me a quick triage: what kind of file is it, is it packed, and is it known to VirusTotal?",
     "required": [["file_type"], ["packing_indicators", "packer_signatures"], ["virustotal"]],
     "acceptable": ["hashes", "sections", "packer_signatures", "packing_indicators"]},
]


def score_selection(question, selected):
    required = [set(group) for group in question["required"]]
    allowed = set().union(*required) | set(question.get("acceptable", []))
    covered = [bool(group & set(selected)) for group in required]
    unnecessary = [t for t in selected if t not in allowed]
    correct = all(covered)
    return {
        "correct": correct,
        "exact": correct and not unnecessary,
        "missing_groups": [sorted(g) for g, ok in zip(required, covered) if not ok],
        "unnecessary": unnecessary,
    }


def summarize(rows, configs):
    out = {}
    for config in configs:
        mine = [r for r in rows if r["config"] == config and "error" not in r]
        n = len(mine)
        if not n:
            out[config] = {"runs": 0}
            continue
        out[config] = {
            "runs": n,
            "correct": sum(r["correct"] for r in mine),
            "correct_rate": round(sum(r["correct"] for r in mine) / n, 3),
            "exact": sum(r["exact"] for r in mine),
            "mean_unnecessary": round(sum(len(r["unnecessary"]) for r in mine) / n, 2),
            "citing_unrun_final": sum(1 for r in mine if r["cited_not_run_final"]),
            "verdict_final": sum(1 for r in mine if r["verdict_final"]),
            "mean_seconds": round(sum(r["seconds"] for r in mine) / n, 1),
        }
    return out


def write_summary(path, summary, rows, configs, files, model):
    lines = ["# Malworn tool selection on analyst questions (O3)", "",
             f"- Files: {', '.join(Path(f).name for f in files)}",
             f"- Model: `{model}`; {len(QUESTIONS)} questions; no tools run in code (the model chooses all)",
             f"- Created: {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}", "",
             "| Measure | " + " | ".join(configs) + " |", "|---|" + "---|" * len(configs)]

    def row(label, fmt):
        lines.append(f"| {label} | " + " | ".join(fmt(summary[c]) if summary[c].get("runs") else "n/a"
                                                  for c in configs) + " |")

    row("Correct tool selection (O3 target 90%)", lambda s: f"{s['correct']}/{s['runs']} ({s['correct_rate']:.0%})")
    row("Exact (correct, nothing unnecessary)", lambda s: f"{s['exact']}/{s['runs']}")
    row("Mean unnecessary tools per question", lambda s: f"{s['mean_unnecessary']}")
    row("Answers citing tools that never ran", lambda s: f"{s['citing_unrun_final']}/{s['runs']}")
    row("Answers with verdict language", lambda s: f"{s['verdict_final']}/{s['runs']}")
    row("Mean seconds per question", lambda s: f"{s['mean_seconds']}")

    lines += ["", "## Each question", "",
              "| File | Config | Question | Seed | Called | Correct | Missing | Unnecessary | s |",
              "|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        if "error" in r:
            lines.append(f"| {r['file']} | {r['config']} | {r['question_id']} | {r['seed']} | error: {r['error']} | | | | |")
            continue
        missing = "; ".join(" or ".join(g) for g in r["missing_groups"]) or "-"
        lines.append(f"| {r['file']} | {r['config']} | {r['question_id']} | {r['seed']} "
                     f"| {', '.join(r['selected']) or '-'} | {'yes' if r['correct'] else 'NO'} "
                     f"| {missing} | {', '.join(r['unnecessary']) or '-'} | {r['seconds']} |")
    lines += ["", "Answer key: see QUESTIONS in src/malworn/agent/evaluate_questions.py."]
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python3 -m malworn.agent.evaluate_questions",
                                     description="Measure tool selection on analyst questions (O3).")
    parser.add_argument("files", nargs="+")
    parser.add_argument("--configs", nargs="+", default=["a3+check"])
    parser.add_argument("--runs", type=int, default=1, help="seeds per question (default: %(default)s)")
    parser.add_argument("--only", nargs="+", metavar="ID", help="run only these question ids")
    parser.add_argument("--out", help="output folder (default: runs/questions_eval_<time>)")
    parser.add_argument("--url", default=os.environ.get("MALWORN_OLLAMA_URL", DEFAULT_OLLAMA_URL))
    parser.add_argument("--model", default=os.environ.get("MALWORN_MODEL", DEFAULT_MODEL))
    args = parser.parse_args(argv)

    try:
        configs = {c: parse_config(c) for c in args.configs}
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    files = list(dict.fromkeys(str(Path(f).resolve()) for f in args.files))
    missing = [f for f in files if not Path(f).is_file()]
    questions = [q for q in QUESTIONS if not args.only or q["id"] in args.only]
    if missing or args.runs < 1 or not questions:
        print("error: " + ("no such file: " + ", ".join(missing) if missing else
                           "--runs must be at least 1" if args.runs < 1 else "no questions match --only"),
              file=sys.stderr)
        return 2

    tools, _ = load_tools()
    available = [t.name for t in tools]
    out_dir = Path(args.out or f"runs/questions_eval_{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}")
    out_dir.mkdir(parents=True, exist_ok=True)
    total = len(files) * len(configs) * len(questions) * args.runs
    print(f"[malworn] {total} questions ({len(files)} files x {len(configs)} configs x "
          f"{len(questions)} questions x {args.runs} seeds)", file=sys.stderr)

    rows, done = [], 0
    for file in files:
        for config, (prompt, check, preset) in configs.items():
            if preset != "none":
                print(f"warning: {config} runs tools in code, so it doesn't measure tool choice",
                      file=sys.stderr)
            for q in questions:
                for seed in range(1, args.runs + 1):
                    done += 1
                    base = {"file": Path(file).name, "config": config, "question_id": q["id"], "seed": seed}
                    print(f"[{done}/{total}] {base['file']} {config} {q['id']} seed {seed}: started",
                          file=sys.stderr, flush=True)
                    try:
                        outcome = run_agent(file, request=q["question"], base_url=args.url, model=args.model,
                                            prompt=prompt, check=check, preset=preset, tools=tools,
                                            options={"seed": seed}, on_event=live_progress(time.monotonic()))
                    except OllamaError as exc:
                        print(f"error: {exc}", file=sys.stderr)
                        return 1
                    except Exception as exc:  # noqa: BLE001
                        rows.append({**base, "error": f"{type(exc).__name__}: {exc}"})
                        continue
                    selected = outcome["agent_run"]["selected_tools"]
                    final = verify.check_answer(outcome["explanation"], selected, available)
                    folder = f"{Path(file).stem}_{config.replace('+', '-')}_{q['id']}_seed{seed}"
                    save_outputs(outcome, out_dir / folder, html=False)
                    row = {**base, "question": q["question"], "selected": selected,
                           **score_selection(q, selected),
                           "cited_not_run_final": final["cited_not_run"], "verdict_final": final["verdict"],
                           "corrections": outcome["stats"].get("corrections", 0),
                           "seconds": outcome["stats"]["seconds"], "folder": folder}
                    rows.append(row)
                    print(f"    -> {'correct' if row['correct'] else 'MISSED ' + str(row['missing_groups'])}"
                          f"{'; unnecessary ' + ', '.join(row['unnecessary']) if row['unnecessary'] else ''}"
                          f" ({row['seconds']} s)", file=sys.stderr, flush=True)

    summary = summarize(rows, list(configs))
    (out_dir / "summary.json").write_text(json.dumps({"summary": summary, "runs": rows}, indent=2),
                                          encoding="utf-8")
    write_summary(out_dir / "summary.md", summary, rows, list(configs), files, args.model)
    print((out_dir / "summary.md").read_text(encoding="utf-8").split("## Each question")[0].strip())
    print(f"\n[malworn] details: {out_dir / 'summary.md'}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
