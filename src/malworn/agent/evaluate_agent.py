"""Compare agent configurations on real files: does the model pick the right tools
and write an answer that stays honest to them?

Owner: Saood

Runs the full agent (real tools, real model) on each file, for each
configuration, with the same seeds, and measures:

  tool recall      share of the expected tools the model called (sub-objective O3:
                   the right tools in at least 90% of requests)
  extra tools      tools called that weren't expected
  cited not run    tools the FINAL answer cites or recommends but never ran
                   (the check before any correction is recorded too)
  verdict          verdict language in the final answer
  corrections      how often the answer check had to send the model back
  seconds          time for the whole analysis (sub-objective O4: at most 60 s)

Expected tools for a general analysis: all available tools on a Windows PE;
hashes, file_type, strings and virustotal on anything else. (The packing tools
skip non-PE files, so calling them there is counted as extra, not wrong.)

Usage (inside the VM, from the repo root; each run takes about a minute):

    PYTHONPATH=src python3 -m malworn.agent.evaluate_agent ~/demo-files/launcher.exe ~/demo-files/launcher_upx.exe
    PYTHONPATH=src python3 -m malworn.agent.evaluate_agent FILES... --configs a2 a3 --runs 3

Configurations: a name is a prompt version; "+check" turns the answer check on;
"+core" runs the core triage tools in code first; "+all" runs every tool.
Default: "a2" (Nov 4 baseline), "a3+check", "a3+check+core".

Output: runs/agent_eval_<time>/summary.md, summary.json and one folder per run.
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
from malworn.agent.loop import CORE_TOOLS, run_agent, save_outputs
from malworn.agent.prompts import AGENT_PROMPTS, DEFAULT_AGENT_REQUEST
from malworn.agent.tools import load_tools

DEFAULT_CONFIGS = ["a2", "a3+check", "a3+check+core"]
NON_PE_EXPECTED = ("hashes", "file_type", "strings", "virustotal")


def parse_config(name):
    """'a3+check+core' -> ('a3', check=True, preset='core'). '+all' runs every tool in code."""
    prompt, *flags = name.split("+")
    if prompt not in AGENT_PROMPTS or any(f not in ("check", "core", "all") for f in flags) \
            or ("core" in flags and "all" in flags):
        raise ValueError(f"Unknown configuration {name!r}: use a prompt ({', '.join(AGENT_PROMPTS)}), "
                         "optionally followed by +check and one of +core / +all")
    preset = "all" if "all" in flags else "core" if "core" in flags else "none"
    return prompt, "check" in flags, preset


def is_pe(path):
    try:
        with open(path, "rb") as fh:
            return fh.read(2) == b"MZ"
    except OSError:
        return False


def expected_tools(path, available):
    return list(available) if is_pe(path) else [t for t in NON_PE_EXPECTED if t in available]


def score_run(outcome, expected, available):
    selected = outcome["agent_run"]["selected_tools"]
    final = verify.check_answer(outcome["explanation"], selected, available)
    checks = outcome["stats"].get("checks") or []
    first = checks[0]["problems"] if checks else final
    hit = [t for t in expected if t in selected]
    # The tools the MODEL had to choose: everything expected except the core
    # triage. Measured the same way for every configuration, so they compare.
    choice = [t for t in expected if t not in CORE_TOOLS]
    chosen = [t for t in choice if t in selected]
    return {
        "selected": selected,
        "expected": expected,
        "tool_recall": round(len(hit) / len(expected), 3) if expected else 1.0,
        "choice_recall": round(len(chosen) / len(choice), 3) if choice else 1.0,
        "missed_tools": [t for t in expected if t not in selected],
        "extra_tools": [t for t in selected if t not in expected],
        "cited_not_run_first": first["cited_not_run"],
        "cited_not_run_final": final["cited_not_run"],
        "verdict_final": final["verdict"],
        "corrections": outcome["stats"].get("corrections", 0),
        "cutoffs": outcome["stats"].get("cutoffs", 0),
        "seconds": outcome["stats"]["seconds"],
        "output_tokens": outcome["stats"]["output_tokens"],
    }


def live_progress(started):
    """Print what the agent is doing while a run is in progress, so a long
    model turn is visible instead of looking stuck."""
    state = {"tokens": 0, "last": started}

    def on_event(kind, payload):
        now = time.monotonic()
        stamp = f"    {now - started:5.0f}s"
        if kind in ("thinking", "answer"):
            state["tokens"] += 1
            if now - state["last"] >= 15:   # a heartbeat while the model writes
                print(f"{stamp}  model writing ({kind}, ~{state['tokens']} chunks so far)",
                      file=sys.stderr, flush=True)
                state["last"] = now
            return
        state["last"] = now
        if kind == "tool_call":
            print(f"{stamp}  -> {payload}", file=sys.stderr, flush=True)
        elif kind == "tool_result":
            print(f"{stamp}  <- {payload.tool}: {payload.status} ({payload.duration_ms} ms)",
                  file=sys.stderr, flush=True)
        elif kind == "check":
            bad = [k for k, v in payload.items() if v]
            print(f"{stamp}  answer check: {'failed (' + ', '.join(bad) + ')' if bad else 'passed'}",
                  file=sys.stderr, flush=True)
        elif kind in ("cutoff", "invalid_call", "repeat_call", "limit"):
            print(f"{stamp}  {kind}: {payload}", file=sys.stderr, flush=True)

    return on_event


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
            "mean_tool_recall": round(sum(r["tool_recall"] for r in mine) / n, 3),
            "mean_choice_recall": round(sum(r["choice_recall"] for r in mine) / n, 3),
            "runs_with_all_expected_tools": sum(1 for r in mine if not r["missed_tools"]),
            "runs_citing_unrun_tools_first": sum(1 for r in mine if r["cited_not_run_first"]),
            "runs_citing_unrun_tools_final": sum(1 for r in mine if r["cited_not_run_final"]),
            "runs_with_verdict_language": sum(1 for r in mine if r["verdict_final"]),
            "runs_needing_correction": sum(1 for r in mine if r["corrections"]),
            "mean_seconds": round(sum(r["seconds"] for r in mine) / n, 1),
            "max_seconds": max(r["seconds"] for r in mine),
            "runs_within_60s": sum(1 for r in mine if r["seconds"] <= 60),
        }
    return out


def write_summary(path, summary, rows, configs, files, model):
    lines = [
        "# Malworn agent comparison",
        "",
        f"- Files: {', '.join(Path(f).name for f in files)}",
        f"- Model: `{model}`; same seeds for every configuration",
        f"- Created: {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}",
        "",
        "| Measure | " + " | ".join(configs) + " |",
        "|---|" + "---|" * len(configs),
    ]

    def row(label, key, fmt=lambda s, k: f"{s[k]}/{s['runs']}"):
        cells = [fmt(summary[c], key) if summary[c].get("runs") else "n/a" for c in configs]
        lines.append(f"| {label} | " + " | ".join(cells) + " |")

    row("Mean tool coverage, all expected tools", "mean_tool_recall", lambda s, k: f"{s[k]:.2f}")
    row("Mean model-choice recall, non-core tools (O3 target 0.9)", "mean_choice_recall", lambda s, k: f"{s[k]:.2f}")
    row("Runs that called every expected tool", "runs_with_all_expected_tools")
    row("Runs citing tools that never ran (before any correction)", "runs_citing_unrun_tools_first")
    row("Runs citing tools that never ran (final answer)", "runs_citing_unrun_tools_final")
    row("Runs with verdict language (final answer)", "runs_with_verdict_language")
    row("Runs that needed a correction", "runs_needing_correction")
    row("Mean seconds per analysis", "mean_seconds", lambda s, k: f"{s[k]}")
    row("Runs within 60 s (O4)", "runs_within_60s")

    lines += ["", "## Each run", "",
              "| File | Config | Seed | Tools called | Missed | Cited, never ran | Verdict | Fixes | s |",
              "|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        if "error" in r:
            lines.append(f"| {r['file']} | {r['config']} | {r['seed']} | error: {r['error']} | | | | | |")
            continue
        lines.append(
            f"| {r['file']} | {r['config']} | {r['seed']} | {len(r['selected'])}/{len(r['expected'])} "
            f"| {', '.join(r['missed_tools']) or '-'} "
            f"| {', '.join(r['cited_not_run_final']) or '-'}"
            + (f" (first: {', '.join(r['cited_not_run_first'])})" if r['cited_not_run_first'] != r['cited_not_run_final'] else "")
            + f" | {'; '.join(r['verdict_final']) or '-'} | {r['corrections']} | {r['seconds']} |")
    lines += ["", "The checks are automatic. Read the saved explanations (one folder per run) before "
              "quoting these numbers, and correct any false flags by hand."]
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python3 -m malworn.agent.evaluate_agent",
                                     description="Compare agent configurations on real files.")
    parser.add_argument("files", nargs="+", help="files to analyse (read, never run)")
    parser.add_argument("--configs", nargs="+", default=DEFAULT_CONFIGS)
    parser.add_argument("--runs", type=int, default=3, help="seeds per file and config (default: %(default)s)")
    parser.add_argument("--request", default=DEFAULT_AGENT_REQUEST)
    parser.add_argument("--out", help="output folder (default: runs/agent_eval_<time>)")
    parser.add_argument("--url", default=os.environ.get("MALWORN_OLLAMA_URL", DEFAULT_OLLAMA_URL))
    parser.add_argument("--model", default=os.environ.get("MALWORN_MODEL", DEFAULT_MODEL))
    args = parser.parse_args(argv)

    try:
        configs = {c: parse_config(c) for c in args.configs}
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    missing = [f for f in args.files if not Path(f).is_file()]
    if missing or args.runs < 1:
        print(f"error: {'no such file: ' + ', '.join(missing) if missing else '--runs must be at least 1'}",
              file=sys.stderr)
        return 2

    args.files = list(dict.fromkeys(str(Path(f).resolve()) for f in args.files))  # drop duplicates
    tools, _ = load_tools()
    available = [t.name for t in tools]
    out_dir = Path(args.out or f"runs/agent_eval_{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}")
    out_dir.mkdir(parents=True, exist_ok=True)
    total = len(args.files) * len(configs) * args.runs
    print(f"[malworn] {total} analyses ({len(args.files)} files x {', '.join(configs)} x {args.runs} seeds)",
          file=sys.stderr)

    rows, done = [], 0
    for file in args.files:
        expected = expected_tools(file, available)
        for config, (prompt, check, preset) in configs.items():
            for seed in range(1, args.runs + 1):
                done += 1
                base = {"file": Path(file).name, "config": config, "seed": seed}
                print(f"[{done}/{total}] {base['file']} {config} seed {seed}: started", file=sys.stderr, flush=True)
                try:
                    outcome = run_agent(file, request=args.request, base_url=args.url, model=args.model,
                                        prompt=prompt, check=check, preset=preset, tools=tools,
                                        options={"seed": seed},
                                        on_event=live_progress(time.monotonic()))
                except OllamaError as exc:
                    print(f"error: {exc}", file=sys.stderr)
                    return 1
                except Exception as exc:  # noqa: BLE001 - record and carry on
                    rows.append({**base, "error": f"{type(exc).__name__}: {exc}"})
                    continue
                run_name = f"{Path(file).stem}_{config.replace('+', '-')}_seed{seed}"
                save_outputs(outcome, out_dir / run_name, html=False)
                row = {**base, **score_run(outcome, expected, available), "folder": run_name}
                rows.append(row)
                print(f"[{done}/{total}] {base['file']} {config} seed {seed}: "
                      f"{len(row['selected'])}/{len(expected)} tools, "
                      f"cited-not-run {row['cited_not_run_final'] or '-'}, "
                      f"verdict {'yes' if row['verdict_final'] else 'no'}, "
                      f"fixes {row['corrections']}, {row['seconds']} s", file=sys.stderr, flush=True)

    summary = summarize(rows, list(configs))
    (out_dir / "summary.json").write_text(json.dumps({"summary": summary, "runs": rows}, indent=2),
                                          encoding="utf-8")
    write_summary(out_dir / "summary.md", summary, rows, list(configs), args.files, args.model)
    print((out_dir / "summary.md").read_text(encoding="utf-8").split("## Each run")[0].strip())
    print(f"\n[malworn] details: {out_dir / 'summary.md'}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
