"""Malworn agent client: send a report.json to the local LLM and print the explanation.

Owner: Saood

Runs inside the analysis VM. Talks to Ollama on the Windows host over the
host-only network (default http://192.168.5.1:11434). Uses only the Python
standard library so it works on a fresh REMnux without extra installs.

Usage (from the repo root):

    PYTHONPATH=src python3 -m malworn.agent.client examples/reports/invoice_upx.json
    PYTHONPATH=src python3 -m malworn.agent.client report.json --hide-thinking
    PYTHONPATH=src python3 -m malworn.agent.client report.json --save runs/

Settings can come from flags or environment variables:
    MALWORN_OLLAMA_URL   default http://192.168.5.1:11434
    MALWORN_MODEL        default qwen3:8b
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from malworn.agent.prompts import DEFAULT_PROMPT_VERSION, PROMPTS

DEFAULT_OLLAMA_URL = "http://192.168.5.1:11434"
DEFAULT_MODEL = "qwen3:8b"
DEFAULT_TIMEOUT = 600  # seconds; long answers with thinking can take a few minutes

# Fixed sampling settings so runs with different prompts are comparable.
# 0.6 is Qwen 3's recommended temperature for thinking mode.
DEFAULT_OPTIONS = {"temperature": 0.6, "seed": 42}

_THINK_TAGS = re.compile(r"<think>.*?</think>", re.DOTALL)


class OllamaError(RuntimeError):
    """Raised when Ollama cannot be reached or returns an error."""


# ---------------------------------------------------------------------------
# Building the request
# ---------------------------------------------------------------------------
def load_report(path):
    """Load a Malworn report from a JSON file. The top level must be an object."""
    path = Path(path)
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ValueError(f"Report not found: {path}") from None
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path} is not valid JSON: {exc}") from None
    if not isinstance(report, dict):
        raise ValueError(f"{path} must contain a JSON object at the top level")
    return report


def build_messages(report, prompt_version=DEFAULT_PROMPT_VERSION):
    """Turn a report into the chat messages sent to the model."""
    if prompt_version not in PROMPTS:
        known = ", ".join(sorted(PROMPTS))
        raise ValueError(f"Unknown prompt version {prompt_version!r} (known: {known})")
    prompt = PROMPTS[prompt_version]

    messages = []
    if prompt["system"]:
        messages.append({"role": "system", "content": prompt["system"]})
    # json.dumps defaults match the compact report text used in the v0 baseline.
    report_text = json.dumps(report, ensure_ascii=False)
    messages.append(
        {"role": "user", "content": f"{prompt['user_instruction']}\n\n{report_text}"}
    )
    return messages


def split_thinking(text):
    """Separate <think>...</think> blocks from the answer (older Ollama versions)."""
    thinking = "\n".join(m.strip() for m in re.findall(r"<think>(.*?)</think>", text, re.DOTALL))
    answer = _THINK_TAGS.sub("", text).strip()
    return thinking, answer


# ---------------------------------------------------------------------------
# Talking to Ollama
# ---------------------------------------------------------------------------
def chat(
    messages,
    base_url=DEFAULT_OLLAMA_URL,
    model=DEFAULT_MODEL,
    options=None,
    think=True,
    timeout=DEFAULT_TIMEOUT,
    on_token=None,
):
    """Send messages to Ollama's /api/chat and return the full result.

    Streams the response so long answers don't look frozen. ``on_token`` is
    called as ``on_token(kind, text)`` with kind "thinking" or "answer".

    Returns a dict: {"answer", "thinking", "model", "stats"}.
    """
    url = base_url.rstrip("/") + "/api/chat"
    body = {
        "model": model,
        "messages": messages,
        "stream": True,
        "think": think,
        "options": dict(DEFAULT_OPTIONS if options is None else options),
    }
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    thinking_parts, answer_parts, final = [], [], {}
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            for raw_line in response:
                line = raw_line.strip()
                if not line:
                    continue
                chunk = json.loads(line)
                if "error" in chunk:
                    raise OllamaError(f"Ollama error: {chunk['error']}")
                message = chunk.get("message", {})
                if message.get("thinking"):
                    thinking_parts.append(message["thinking"])
                    if on_token:
                        on_token("thinking", message["thinking"])
                if message.get("content"):
                    answer_parts.append(message["content"])
                    if on_token:
                        on_token("answer", message["content"])
                if chunk.get("done"):
                    final = chunk
                    break
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise OllamaError(f"Ollama returned HTTP {exc.code}: {detail}") from None
    except urllib.error.URLError as exc:
        raise OllamaError(
            f"Could not reach Ollama at {base_url} ({exc.reason}).\n"
            "Check on Windows: Ollama is running, OLLAMA_HOST=192.168.5.1:11434, "
            "and the 'Ollama - Malworn VM only' firewall rule is enabled.\n"
            "Check in the VM: the network adapter is host-only and "
            f"'curl {base_url}' prints 'Ollama is running'."
        ) from None
    except (TimeoutError, OSError) as exc:
        raise OllamaError(f"Connection to Ollama failed: {exc}") from None

    # Older Ollama versions put thinking inside the content as <think> tags.
    tag_thinking, answer = split_thinking("".join(answer_parts))
    thinking = "".join(thinking_parts).strip() or tag_thinking

    return {
        "answer": answer,
        "thinking": thinking,
        "model": final.get("model", model),
        "stats": _stats(final),
    }


def _stats(final):
    """Pull timing numbers out of Ollama's final chunk (durations are in ns)."""
    tokens = final.get("eval_count")
    eval_ns = final.get("eval_duration")
    stats = {
        "prompt_tokens": final.get("prompt_eval_count"),
        "output_tokens": tokens,
        "total_seconds": round(final["total_duration"] / 1e9, 1)
        if final.get("total_duration")
        else None,
    }
    stats["tokens_per_second"] = round(tokens / (eval_ns / 1e9), 1) if tokens and eval_ns else None
    return stats


# ---------------------------------------------------------------------------
# Saving runs (for comparing prompt versions)
# ---------------------------------------------------------------------------
def save_run(out_dir, report_path, prompt_version, messages, result):
    """Write one run to <out_dir>/<report>_<prompt>_<timestamp>.json and return its path."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = out_dir / f"{Path(report_path).stem}_{prompt_version}_{stamp}.json"
    record = {
        "created_utc": stamp,
        "report_file": str(report_path),
        "prompt_version": prompt_version,
        "model": result["model"],
        "options": DEFAULT_OPTIONS,
        "messages": messages,
        "thinking": result["thinking"],
        "answer": result["answer"],
        "stats": result["stats"],
    }
    path.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------
def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="python3 -m malworn.agent.client",
        description="Explain a Malworn report.json using the local LLM.",
    )
    parser.add_argument("report", help="path to a report.json")
    parser.add_argument(
        "--url",
        default=os.environ.get("MALWORN_OLLAMA_URL", DEFAULT_OLLAMA_URL),
        help="Ollama base URL (default: %(default)s)",
    )
    parser.add_argument(
        "--model",
        default=os.environ.get("MALWORN_MODEL", DEFAULT_MODEL),
        help="Ollama model name (default: %(default)s)",
    )
    parser.add_argument(
        "--prompt",
        default=DEFAULT_PROMPT_VERSION,
        choices=sorted(PROMPTS),
        help="prompt version (default: %(default)s)",
    )
    parser.add_argument(
        "--hide-thinking",
        action="store_true",
        help="print only the answer, not the model's reasoning (reasoning is still saved with --save)",
    )
    parser.add_argument("--no-think", action="store_true", help="turn off Qwen's thinking mode")
    parser.add_argument("--save", metavar="DIR", help="save the run as JSON in DIR (e.g. runs/)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="seconds (default: %(default)s)")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    try:
        report = load_report(args.report)
        messages = build_messages(report, args.prompt)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"[malworn] {args.report} -> {args.model} at {args.url} (prompt {args.prompt})", file=sys.stderr)

    state = {"section": None}

    def on_token(kind, text):
        if kind == "thinking" and args.hide_thinking:
            return
        if state["section"] != kind:
            header = "--- thinking ---" if kind == "thinking" else "--- answer ---"
            print(("\n" if state["section"] else "") + header, flush=True)
            state["section"] = kind
        print(text, end="", flush=True)

    started = time.monotonic()
    try:
        result = chat(
            messages,
            base_url=args.url,
            model=args.model,
            think=not args.no_think,
            timeout=args.timeout,
            on_token=on_token,
        )
    except OllamaError as exc:
        print(f"\nerror: {exc}", file=sys.stderr)
        return 1
    print()

    stats = result["stats"]
    print(
        f"[malworn] done in {time.monotonic() - started:.1f}s, "
        f"{stats['output_tokens']} tokens, {stats['tokens_per_second']} tok/s",
        file=sys.stderr,
    )
    if args.save:
        path = save_run(args.save, args.report, args.prompt, messages, result)
        print(f"[malworn] saved run to {path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
