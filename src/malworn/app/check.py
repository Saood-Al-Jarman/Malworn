"""Pre-flight check: is everything the demo needs reachable? Run it in the VM.

    PYTHONPATH=src python3 -m malworn.app.check

Checks Ollama and the model, the VirusTotal bridge, Detect It Easy, Flask, the
tool list and the data folder, and says how to fix anything that fails.
"""

import json
import os
import shutil
import sys
import urllib.error
import urllib.request
from pathlib import Path

from malworn.agent.client import DEFAULT_MODEL, DEFAULT_OLLAMA_URL
from malworn.agent.vt_tool import DEFAULT_BRIDGE


def _get(url, timeout=5):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read() or b"{}")


def check_ollama(url, model):
    try:
        tags = _get(url.rstrip("/") + "/api/tags")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return False, (f"can't reach Ollama at {url} ({getattr(exc, 'reason', exc)}). On Windows: is Ollama "
                       "running, with OLLAMA_HOST=192.168.5.1:11434? Is the VM's network host-only?")
    names = [m.get("name") for m in tags.get("models", [])]
    if model not in names and f"{model}:latest" not in names:
        return False, f"Ollama is up but {model} isn't pulled (have: {', '.join(names) or 'none'}). On Windows: ollama pull {model}"
    return True, f"Ollama at {url} has {model}"


def check_bridge(url):
    if os.environ.get("MALWORN_VT_MODE") == "mock":
        return True, "VirusTotal in mock mode (MALWORN_VT_MODE=mock): no bridge needed, no real lookups"
    try:
        health = _get(url.rstrip("/") + "/health")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return False, (f"can't reach the VirusTotal bridge at {url} ({getattr(exc, 'reason', exc)}). On Windows: "
                       "run  python -m malworn.agent.vt_bridge  and check the firewall rule for port 8770. "
                       "Or demo without it: export MALWORN_VT_MODE=mock")
    mode = health.get("mode")
    note = "" if mode == "live" else f" (mode {mode}: lookups aren't live)"
    return True, f"VirusTotal bridge at {url} is up{note}"


def check_diec():
    path = os.environ.get("MALWORN_DIEC") or shutil.which("diec")
    if not path:
        return False, ("Detect It Easy (diec) not found. The packing tools still work but warn that DIE didn't run. "
                       "On REMnux it should be installed; check  which diec")
    return True, f"Detect It Easy found at {path}"


def check_flask():
    try:
        import flask  # noqa: F401
    except ImportError:
        return False, "Flask isn't installed: python3 -m pip install --user flask (with NAT on)"
    return True, "Flask installed"


def check_tools():
    from malworn.agent.tools import load_tools
    tools, skipped = load_tools()
    msg = f"{len(tools)} tools: {', '.join(t.name for t in tools)}"
    if skipped:
        return False, msg + f"; not loaded: {skipped}"
    return True, msg


def check_data(path):
    root = Path(path).expanduser()
    try:
        root.mkdir(parents=True, exist_ok=True)
        probe = root / ".write-test"
        probe.write_text("ok")
        probe.unlink()
    except OSError as exc:
        return False, f"can't write to {root}: {exc}"
    return True, f"data folder {root} is writable"


def main():
    url = os.environ.get("MALWORN_OLLAMA_URL", DEFAULT_OLLAMA_URL)
    model = os.environ.get("MALWORN_MODEL", DEFAULT_MODEL)
    checks = [
        ("Model", lambda: check_ollama(url, model)),
        ("VirusTotal", lambda: check_bridge(os.environ.get("MALWORN_VT_BRIDGE", DEFAULT_BRIDGE))),
        ("Detect It Easy", check_diec),
        ("Web app", check_flask),
        ("Tools", check_tools),
        ("Data", lambda: check_data(os.environ.get("MALWORN_DATA", "~/malworn-data"))),
    ]
    failed = 0
    for label, fn in checks:
        try:
            ok, msg = fn()
        except Exception as exc:  # noqa: BLE001
            ok, msg = False, f"{type(exc).__name__}: {exc}"
        failed += not ok
        print(f"[{'ok' if ok else 'FAIL':>4}] {label:15} {msg}")
    print("\nReady for the demo." if not failed else f"\n{failed} check(s) need attention.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
