"""Compare prompt versions: run each one several times and count known mistakes.

Owner: Saood

One run per prompt is not enough, because the model's output varies from run to
run. This script runs every prompt version N times on the same report, using
the same seeds (1..N) for every version so the comparison is fair, and checks
each answer for the mistakes seen in the baseline.

Usage (inside the VM, from the repo root):

    PYTHONPATH=src python3 -m malworn.agent.evaluate examples/reports/invoice_upx.json
    PYTHONPATH=src python3 -m malworn.agent.evaluate examples/reports/invoice_upx.json \\
        --prompts v0 v1 --runs 5

Output goes to runs/eval_<time>/:
    summary.md     table of how often each mistake appeared, plus what triggered each flag
    summary.json   the same numbers, for scripts
    <report>_<prompt>_seed<N>.json   every individual run (thinking + answer)

The checks are simple text patterns. They are a quick first pass, not a final
judgement: read the flagged snippets in summary.md and correct any false flags
by hand before using the numbers in a report.
"""

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from malworn.agent.client import (
    DEFAULT_MODEL,
    DEFAULT_OLLAMA_URL,
    DEFAULT_OPTIONS,
    DEFAULT_TIMEOUT,
    OllamaError,
    build_messages,
    chat,
    load_report,
)
from malworn.agent.prompts import PROMPTS

# A match counts as negated when one of these appears earlier in the same
# sentence, e.g. "does NOT prove", "cannot confirm", "instead of uploading".
_NEGATION = re.compile(
    r"(\bnot\b|n't\b|\bnever\b|\bcannot\b|\bno\b|\bwithout\b|rather than|instead of|\bnor\b|\bavoid\b)",
    re.IGNORECASE,
)
_SENTENCE_BREAK = re.compile(r"[.!?\n]")


def _sentence_before(text, index):
    """Text from the start of the current sentence up to ``index``."""
    start = 0
    for m in _SENTENCE_BREAK.finditer(text, 0, index):
        start = m.end()
    return text[start:index]


def _sentence_end(text, index):
    m = _SENTENCE_BREAK.search(text, index)
    return m.start() if m else len(text)


def _snippet(text, start, end, width=60):
    left = max(0, start - width)
    right = min(len(text), end + width)
    return " ".join(text[left:right].split())


def _find(text, pattern, skip_negated=True):
    """Return snippets for every (non-negated) match of ``pattern``."""
    hits = []
    for m in re.finditer(pattern, text, re.IGNORECASE):
        if skip_negated and _NEGATION.search(_sentence_before(text, m.start())):
            continue
        hits.append(_snippet(text, m.start(), m.end()))
    return hits


# ---------------------------------------------------------------------------
# Mistake checks. Each takes (answer, report) and returns a list of snippets
# that triggered it (empty list = mistake not found).
# ---------------------------------------------------------------------------
def check_proof_language(answer, report):
    """Evidence treated as proof: 'confirms', 'proves', 'definitely'...

    Not flagged, because these are advice on HOW to confirm, which is correct:
    "... to confirm the threat", "this will help confirm", confirming with dynamic
    analysis or a sandbox. "confirm ... safe to run" is counted by check_unsafe_sandbox.
    """
    hits = []
    pattern = r"\b(confirm(s|ed|ing)?|prove[sdn]?|proof|definitely|certainly)\b"
    for m in re.finditer(pattern, answer, re.IGNORECASE):
        before = _sentence_before(answer, m.start())
        sentence = before + answer[m.start():_sentence_end(answer, m.end())]
        if _NEGATION.search(before):
            continue
        if re.search(r"\b(to|helps?|help you)\s*$", before, re.IGNORECASE):
            continue
        if re.search(r"\b(dynamic|sandbox|safe to)\b", sentence, re.IGNORECASE):
            continue
        hits.append(_snippet(answer, m.start(), m.end()))
    return hits


def check_assumes_executed(answer, report):
    """Advice or claims that assume the sample already ran."""
    patterns = [
        # "check for registry modifications", "check if the file writes to..."
        r"\b(check|verify|look|inspect|monitor)\b[^.\n]{0,40}\b(modifications?|modified|modifies|wrote|written|writes|changes made)\b",
        # "has modified the registry", "has persisted"
        r"\b(has|have|had)\s+(modified|written|created|persisted|executed|injected|connected)\b",
    ]
    hits = []
    for p in patterns:
        hits += _find(answer, p)
    return hits


def check_stub_imports(answer, report):
    """Packer stub imports read as malicious / injection."""
    hits = _find(answer, r"\binject(ion|ed|s|ing)?\b")
    mentions_imports = re.search(r"VirtualProtect|LoadLibrary|GetProcAddress|VirtualAlloc", answer)
    is_packed = (report.get("packing") or {}).get("is_packed")
    if mentions_imports and is_packed and not re.search(r"\bstubs?\b", answer, re.IGNORECASE):
        m = mentions_imports
        hits.append("imports discussed without saying they belong to the unpacking stub: "
                    + _snippet(answer, m.start(), m.end()))
    return hits


def check_bad_lookup(answer, report):
    """Uploading the sample, or looking it up by file name instead of hash."""
    hits = _find(answer, r"\bupload(ing|ed|s)?\b")
    file_name = ((report.get("sample") or {}).get("file_name") or "").strip()
    if file_name:
        name = re.escape(file_name)
        hits += _find(
            answer,
            rf"\b(search|look\s*up|query|check)\b[^.\n]{{0,25}}[`'\"]?{name}[`'\"]?\s+(or|in|on|are|is)\b",
        )
    return hits


def check_upx_encrypts(answer, report):
    """Packing described as encryption or as a security feature.

    Not flagged: "encrypted or compressed" (a correct general description of
    high entropy, not a claim that UPX encrypts).
    """
    hits = []
    either = re.compile(r"encrypt\w*\s*(or|/)\s*compress|compress\w*\s*(or|/)\s*encrypt", re.IGNORECASE)
    for m in re.finditer(r"\bencrypt(s|ed|ion|ing)?\b", answer, re.IGNORECASE):
        before = _sentence_before(answer, m.start())
        sentence = before + answer[m.start():_sentence_end(answer, m.end())]
        if _NEGATION.search(before) or either.search(sentence):
            continue
        hits.append(_snippet(answer, m.start(), m.end()))
    hits += _find(answer, r"\b(enhance|improve|increase)s?\b[^.\n]{0,15}\bsecurity\b")
    return hits


def check_unsafe_sandbox(answer, report):
    """Suggests the sample can be 'confirmed safe' or run outside a sandbox."""
    return _find(answer, r"\bsafe to (run|execute|open)\b")


def check_invented_apis(answer, report):
    """Windows API names in the answer that are not in the report."""
    report_text = json.dumps(report)
    hits = []
    for m in re.finditer(r"`([A-Z][A-Za-z0-9]+(?:A|W|Ex|ExA|ExW)?)`", answer):
        name = m.group(1)
        looks_like_api = re.match(r"^(Create|Write|Read|Open|Reg|Virtual|Load|Get|Set|Nt|Zw|Internet|Http|WinHttp|Shell|Url)", name)
        if looks_like_api and name not in report_text:
            hits.append(_snippet(answer, m.start(), m.end()))
    return hits


CHECKS = {
    "proof_language": ("Evidence treated as proof", check_proof_language),
    "assumes_executed": ("Assumes the sample ran", check_assumes_executed),
    "stub_imports": ("UPX stub imports read as malicious", check_stub_imports),
    "bad_lookup": ("Upload or file-name lookup", check_bad_lookup),
    "upx_encrypts": ("Says packing encrypts / adds security", check_upx_encrypts),
    "unsafe_sandbox": ("Says the sample can be 'safe to run'", check_unsafe_sandbox),
    "invented_apis": ("Mentions APIs not in the report (review)", check_invented_apis),
}


def run_checks(answer, report):
    return {key: fn(answer, report) for key, (_, fn) in CHECKS.items()}


# ---------------------------------------------------------------------------
# Running the comparison
# ---------------------------------------------------------------------------
@dataclass
class RunResult:
    prompt: str
    seed: int
    answer: str
    thinking: str
    stats: dict
    flags: dict
    seconds: float


def evaluate(report, report_path, prompts, runs, out_dir, url, model, timeout, think=True, log=print):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = Path(report_path).stem
    results = []

    for prompt in prompts:
        messages = build_messages(report, prompt)
        for seed in range(1, runs + 1):
            options = dict(DEFAULT_OPTIONS, seed=seed)
            started = time.monotonic()
            result = chat(messages, base_url=url, model=model, options=options,
                          think=think, timeout=timeout)
            seconds = round(time.monotonic() - started, 1)
            flags = run_checks(result["answer"], report)
            run = RunResult(prompt, seed, result["answer"], result["thinking"],
                            result["stats"], flags, seconds)
            results.append(run)

            record = {
                "report_file": str(report_path),
                "prompt_version": prompt,
                "seed": seed,
                "seconds": seconds,
                "model": result["model"],
                "options": options,
                "messages": messages,
                "thinking": run.thinking,
                "answer": run.answer,
                "stats": run.stats,
                "flags": flags,
            }
            path = out_dir / f"{stem}_{prompt}_seed{seed}.json"
            path.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")

            found = [k for k, v in flags.items() if v]
            log(f"[{prompt} seed {seed}/{runs}] {seconds}s, "
                f"{run.stats.get('output_tokens')} tokens, flags: {', '.join(found) or 'none'}")
    return results


def recheck(run_dir, report):
    """Re-score saved runs with the current checks (no model calls).

    Use this after improving a check: the answers stay the same, only the flags
    are recomputed. Each run file's "flags" field is updated in place.
    """
    results = []
    for path in sorted(Path(run_dir).glob("*_seed*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        seed = record.get("seed") or int(re.search(r"_seed(\d+)\.json$", path.name).group(1))
        stats = record.get("stats") or {}
        seconds = record.get("seconds") or stats.get("total_seconds") or 0
        flags = run_checks(record["answer"], report)
        record["flags"] = flags
        path.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
        results.append(RunResult(record["prompt_version"], seed, record["answer"],
                                 record.get("thinking", ""), stats, flags, seconds))
    results.sort(key=lambda r: (r.prompt, r.seed))
    return results


def summarize(results, prompts, runs):
    """Count, per prompt, how many runs triggered each check."""
    summary = {}
    for prompt in prompts:
        mine = [r for r in results if r.prompt == prompt]
        tokens = [r.stats.get("output_tokens") or 0 for r in mine]
        summary[prompt] = {
            "runs": len(mine),
            "mistakes": {key: sum(1 for r in mine if r.flags[key]) for key in CHECKS},
            "clean_runs": sum(1 for r in mine if not any(r.flags.values())),
            "avg_seconds": round(sum(r.seconds for r in mine) / len(mine), 1) if mine else None,
            "avg_output_tokens": round(sum(tokens) / len(tokens)) if tokens else None,
        }
    return summary


def write_summary_md(path, summary, results, prompts, report_path, model):
    lines = [
        "# Malworn prompt comparison",
        "",
        f"- Report: `{report_path}`",
        f"- Model: `{model}`, temperature {DEFAULT_OPTIONS['temperature']}, seeds 1..{summary[prompts[0]]['runs']}",
        f"- Created: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "Each cell is the number of runs where the mistake was flagged.",
        "",
        "| Mistake | " + " | ".join(prompts) + " |",
        "|---|" + "---|" * len(prompts),
    ]
    for key, (label, _) in CHECKS.items():
        cells = [f"{summary[p]['mistakes'][key]}/{summary[p]['runs']}" for p in prompts]
        lines.append(f"| {label} | " + " | ".join(cells) + " |")
    lines.append("| **Runs with no flags** | " + " | ".join(
        f"**{summary[p]['clean_runs']}/{summary[p]['runs']}**" for p in prompts) + " |")
    lines.append("| Avg. time (s) | " + " | ".join(str(summary[p]["avg_seconds"]) for p in prompts) + " |")
    lines.append("| Avg. output tokens | " + " | ".join(str(summary[p]["avg_output_tokens"]) for p in prompts) + " |")

    lines += ["", "## What triggered each flag", "",
              "Automatic checks can be wrong. Review each snippet and correct the table by hand if needed.", ""]
    any_flag = False
    for r in results:
        for key, snippets in r.flags.items():
            for s in snippets:
                any_flag = True
                lines.append(f"- **{r.prompt} seed {r.seed}**, {CHECKS[key][0]}: \"{s}\"")
    if not any_flag:
        lines.append("No flags.")
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------
def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="python3 -m malworn.agent.evaluate",
        description="Run each prompt version several times and count known mistakes.",
    )
    parser.add_argument("report", help="path to a report.json")
    parser.add_argument("--prompts", nargs="+", default=sorted(PROMPTS), choices=sorted(PROMPTS),
                        help="prompt versions to compare (default: all)")
    parser.add_argument("--runs", type=int, default=5, help="runs per prompt (default: %(default)s)")
    parser.add_argument("--out", help="output folder (default: runs/eval_<time>)")
    parser.add_argument("--url", default=os.environ.get("MALWORN_OLLAMA_URL", DEFAULT_OLLAMA_URL))
    parser.add_argument("--model", default=os.environ.get("MALWORN_MODEL", DEFAULT_MODEL))
    parser.add_argument("--no-think", action="store_true", help="turn off Qwen's thinking mode")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--recheck", metavar="DIR",
                        help="re-score the saved runs in DIR with the current checks (no model calls)")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.runs < 1:
        print("error: --runs must be at least 1", file=sys.stderr)
        return 2
    try:
        report = load_report(args.report)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.recheck:
        out_dir = Path(args.recheck)
        results = recheck(out_dir, report)
        if not results:
            print(f"error: no *_seed*.json runs found in {out_dir}", file=sys.stderr)
            return 2
        prompts = sorted({r.prompt for r in results})
        print(f"[malworn] rechecked {len(results)} saved runs in {out_dir}", file=sys.stderr)
        return _write_and_print(out_dir, results, prompts, args)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = Path(args.out or f"runs/eval_{stamp}")
    total = len(args.prompts) * args.runs
    print(f"[malworn] {total} runs ({', '.join(args.prompts)} x {args.runs}) on {args.report}"
          f" -> {args.model} at {args.url}", file=sys.stderr)

    try:
        results = evaluate(report, args.report, args.prompts, args.runs, out_dir,
                           args.url, args.model, args.timeout, think=not args.no_think,
                           log=lambda msg: print(msg, file=sys.stderr, flush=True))
    except OllamaError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    return _write_and_print(out_dir, results, args.prompts, args)


def _write_and_print(out_dir, results, prompts, args):
    summary = summarize(results, prompts, None)
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    write_summary_md(out_dir / "summary.md", summary, results, prompts, args.report, args.model)

    # Print the table part of summary.md.
    table = (out_dir / "summary.md").read_text(encoding="utf-8").split("## What triggered")[0]
    print(table.strip())
    print(f"\n[malworn] details and flagged snippets: {out_dir / 'summary.md'}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
