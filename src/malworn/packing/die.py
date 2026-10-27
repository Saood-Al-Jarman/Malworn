# AI assistance: Claude (Anthropic), October 2026. Used for: running Detect It Easy (diec) as the FIRST packing check and parsing its JSON. To be reviewed and tested by Viha.
"""
malworn.packing.die  -  run Detect It Easy (DIE) first, once per file, offline.

DIE is a local program (installed in the REMnux VM, see docs/vm-setup.md). It
needs no network. This module is the ONLY place in the packing package that
starts an external program; the file is passed as a plain argument (never through
a shell) and is never executed.

"Run DIE first": every packing tool calls run_die() before doing anything else.
Results are cached per (path, size, mtime) for the life of the process, so DIE
runs once per sample no matter which packing tool the agent calls first, and
later tools reuse the same result. If DIE has already been run elsewhere,
call run_die() is cheap and returns the cached result.

Output format verified against Detect It Easy 3.21 (`diec --json`):
    {"detects": [{"filetype": "PE32", "values": [
        {"type": "packer", "name": "UPX", "version": "4.24", "info": "NRV, brute"}, ...]}]}
Heuristic detections (--heuristicscan) have types starting with "~", e.g.
"~packer"/"Generic".
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

DIEC_ENV = "MALWORN_DIEC"        # optional: full path to diec
DB_ENV = "MALWORN_DIE_DB"        # optional: DIE signature database folder (-D)
TIMEOUT_S = 60
PACKER_TYPES = {"packer", "protector", "protection", "cryptor", "crypter"}

_CACHE: Dict[Tuple[str, int, int], Dict[str, Any]] = {}


def clear_cache() -> None:
    _CACHE.clear()


def find_diec() -> Optional[str]:
    return os.environ.get(DIEC_ENV) or shutil.which("diec")


def _parse(stdout: str) -> Dict[str, Any]:
    start = stdout.find("{")
    if start < 0:
        raise ValueError(f"no JSON in output: {stdout[:100]!r}")
    return json.loads(stdout[start:])


def summarize(parsed: Dict[str, Any]) -> Dict[str, Any]:
    """Boil DIE's JSON down to packer-related detections plus a short list of others."""
    packers: List[Dict[str, Any]] = []
    others: List[Dict[str, Any]] = []
    file_type = None
    for block in parsed.get("detects", []):
        file_type = file_type or block.get("filetype")
        for v in block.get("values", []):
            typ = str(v.get("type", ""))
            heuristic = typ.startswith("~")
            base = typ.lstrip("~").lower()
            item = {"type": base, "name": v.get("name"), "version": v.get("version", ""),
                    "info": v.get("info", ""), "heuristic": heuristic}
            if base in PACKER_TYPES and v.get("name") != "Unknown":
                packers.append(item)
            elif v.get("name") != "Unknown" and len(others) < 20:
                others.append({k: item[k] for k in ("type", "name", "version")})
    return {"file_type": file_type, "packers": packers, "other_detections": others}


def run_die(path: str) -> Dict[str, Any]:
    """Run DIE on `path` (once per file per process) and return a summary dict:
    {available, ran, version, error, file_type, packers[], other_detections[]}"""
    p = Path(path)
    try:
        st = p.stat()
        key = (str(p.resolve()), st.st_size, st.st_mtime_ns)
    except OSError as e:
        return {"available": False, "ran": False, "error": f"cannot stat file: {e}",
                "packers": [], "other_detections": []}
    if key in _CACHE:
        return _CACHE[key]

    out: Dict[str, Any] = {"available": False, "ran": False, "version": None, "error": None,
                           "file_type": None, "packers": [], "other_detections": []}
    exe = find_diec()
    if not exe:
        out["error"] = "diec (Detect It Easy) was not found on PATH; DIE was NOT run"
        _CACHE[key] = out
        return out
    out["available"] = True
    cmd = [exe, "--json", "--heuristicscan"]
    if os.environ.get(DB_ENV):
        cmd += ["-D", os.environ[DB_ENV]]
    cmd.append(str(p.resolve()))               # absolute path: cannot be read as an option
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_S,
                              stdin=subprocess.DEVNULL)
        out.update(summarize(_parse(proc.stdout)))
        out["ran"] = True
    except subprocess.TimeoutExpired:
        out["error"] = f"DIE timed out after {TIMEOUT_S}s"
    except (OSError, ValueError) as e:         # includes JSONDecodeError
        out["error"] = f"DIE output could not be used: {str(e)[:150]}"
    try:
        v = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=10,
                           stdin=subprocess.DEVNULL)
        out["version"] = (v.stdout or v.stderr).strip().splitlines()[0][:40]
    except Exception:  # noqa: BLE001
        pass
    _CACHE[key] = out
    return out
