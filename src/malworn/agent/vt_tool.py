"""Tool `virustotal`, as the agent runs it inside the VM.

Owner: Saood (the lookup itself is Hassan's, in malworn.detection.virustotal_tool)

The VM has no internet. This tool hashes the sample inside the VM and sends
ONLY the SHA-256 to the VirusTotal bridge on the Windows host
(malworn.agent.vt_bridge), which does the real lookup with the API key that
lives on Windows. The result is Hassan's ToolResult, returned unchanged.

Settings (environment variables in the VM):
    MALWORN_VT_BRIDGE  default http://192.168.5.1:8770
    MALWORN_VT_MODE    default bridge   ("mock" = Hassan's mock answer, no bridge needed)
"""

import hashlib
import json
import os
import urllib.error
import urllib.request

from malworn.contract import ToolSpec

DEFAULT_BRIDGE = "http://192.168.5.1:8770"
TIMEOUT_SECONDS = 20
MAX_RESPONSE_BYTES = 200_000

SPEC = ToolSpec(
    name="virustotal",
    description=("Look up the file's SHA-256 hash on VirusTotal (only the hash is sent, never the file) "
                 "and report whether VirusTotal knows it, how many engines flag it, when it was first "
                 "seen, and VirusTotal's threat label."),
    data_keys=("sha256", "found", "detections", "engines_total", "first_seen",
               "last_analysis_date", "threat_label", "permalink", "source"),
    requirement="FR3",
    owner="Hassan",
)


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _failure(error, sha256=None):
    return {"tool": "virustotal", "status": "failure",
            "data": {"sha256": sha256} if sha256 else {}, "warnings": [], "error": error}


def run(file_path):
    try:
        sha256 = _sha256(file_path)
    except OSError as exc:
        return _failure(f"Could not read the file to hash it: {exc}")

    if os.environ.get("MALWORN_VT_MODE", "bridge") == "mock":
        from malworn.detection.virustotal_tool import lookup_sha256
        return lookup_sha256(sha256, mode="mock")

    bridge = os.environ.get("MALWORN_VT_BRIDGE", DEFAULT_BRIDGE).rstrip("/")
    try:
        with urllib.request.urlopen(f"{bridge}/vt/{sha256}", timeout=TIMEOUT_SECONDS) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        return _failure(f"VirusTotal bridge returned HTTP {exc.code}", sha256)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        return _failure(f"VirusTotal bridge not reachable at {bridge} ({reason}). Is vt_bridge running "
                        "on Windows, and does the firewall allow port 8770 from the VM?", sha256)
    if len(raw) > MAX_RESPONSE_BYTES:
        return _failure("VirusTotal bridge response was too large", sha256)
    try:
        result = json.loads(raw)
    except ValueError:
        return _failure("VirusTotal bridge sent a response that isn't JSON", sha256)
    if not isinstance(result, dict) or result.get("tool") != "virustotal":
        return _failure("VirusTotal bridge sent an unexpected response", sha256)
    data = result.get("data")
    if isinstance(data, dict) and data.get("sha256") not in (None, sha256):
        return _failure("VirusTotal bridge answered for a different hash", sha256)
    return result
