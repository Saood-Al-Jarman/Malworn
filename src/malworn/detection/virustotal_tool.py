"""Malworn H2: VirusTotal v3 SHA-256 *lookup-only* tool.

Returns the provisional ToolResult dictionary expected by Hassan's existing
malworn_aggregator.py. No file is executed, uploaded, or sent to VirusTotal.
Only the SHA-256 string is queried. Live lookup requires VT_API_KEY in the
process environment; mock and cache-only modes are available without it.

Hash-tool integration:
  lookup_from_hash_result(hashes_tool_result)
  lookup_from_file(path, hash_module='malworn.tools.hashes', hash_function='run')

Review against the team's finalized contract.py before merging into GitHub.
"""
from __future__ import annotations

import argparse
from collections import deque
from datetime import datetime, timezone
from importlib import import_module
import json
import os
from pathlib import Path
import re
import tempfile
import threading
import time
from typing import Any, Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from uuid import uuid4

VT_ENDPOINT = "https://www.virustotal.com/api/v3/files/"
VT_REPORT_PAGE = "https://www.virustotal.com/gui/file/"
MAX_RESPONSE_BYTES = 2_000_000
MAX_HASH_JSON_BYTES = 1_000_000
DEFAULT_TTL_SECONDS = 24 * 60 * 60
NOT_FOUND_TTL_SECONDS = 60 * 60
RATE_LIMIT = 4                 # Conservative local cap for public/free usage
RATE_WINDOW_SECONDS = 60.0

_rate_timestamps: deque[float] = deque()
_rate_lock = threading.Lock()
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class HashInputError(ValueError):
    """No valid SHA-256 was supplied by the upstream hash tool."""


def _tool_result(
    *, status: str, data: dict[str, Any], source: str,
    error: str | None = None, warnings: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "tool": "virustotal",
        "call_id": f"vt-{uuid4().hex[:12]}",
        "status": status,          # 'success' or 'failure' for the aggregator
        "source": source,          # 'api', 'cache', 'mock', or 'none'
        "data": data,
        "warnings": warnings or [],
        "error": error,
    }


def _validate_sha256(value: Any) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value.strip()):
        raise HashInputError("Expected a SHA-256 containing exactly 64 hexadecimal characters")
    return value.strip().lower()


def extract_sha256(hash_result: Any) -> str:
    """Accept a SHA-256 string, or a result returned by the future hash tool.

    Supported examples:
      'a' * 64
      {'sha256': '...'}
      {'tool': 'hashes', 'status': 'success', 'data': {'sha256': '...'}}
      {'data': {'hashes': {'sha256': '...'}}}
    """
    if isinstance(hash_result, str):
        return _validate_sha256(hash_result)
    if not isinstance(hash_result, Mapping):
        raise HashInputError("Hash tool output must be a SHA-256 string or a dictionary")
    status = hash_result.get("status")
    if status is not None and status not in ("success", "ok"):
        raise HashInputError(f"Hash generator did not succeed (status: {status})")

    possible: list[Any] = [hash_result]
    data = hash_result.get("data")
    if isinstance(data, Mapping):
        possible.append(data)
    for container in (hash_result, data):
        if isinstance(container, Mapping) and isinstance(container.get("hashes"), Mapping):
            possible.append(container["hashes"])

    values = []
    for container in possible:
        if isinstance(container, Mapping):
            for key, value in container.items():
                if isinstance(key, str) and key.lower() in ("sha256", "sha_256"):
                    values.append(_validate_sha256(value))
    if not values:
        raise HashInputError("No SHA-256 field found in the hash tool result")
    if len(set(values)) > 1:
        raise HashInputError("Conflicting SHA-256 values in hash tool result")
    return values[0]


def _empty_data(sha256: str) -> dict[str, Any]:
    # Keep the same fields as the previous H3 mock_agent_run.json.
    return {
        "sha256": sha256,
        "found": None,
        "detections": None,
        "engines_total": None,
        "first_seen": None,
        "last_analysis_date": None,
        "threat_label": None,
        "permalink": None,
        "source": "none",
    }


def _timestamp_utc(value: Any) -> str | None:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return None
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _parse_vt_response(payload: Any, queried_sha256: str) -> dict[str, Any]:
    """Extract factual VirusTotal attributes; do not infer any malware verdict."""
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), dict):
        raise ValueError("Invalid VirusTotal response: missing data object")
    item = payload["data"]
    attributes = item.get("attributes")
    if not isinstance(attributes, dict):
        raise ValueError("Invalid VirusTotal response: missing attributes object")
    reported_sha = attributes.get("sha256") or item.get("id")
    if reported_sha is not None and _validate_sha256(reported_sha) != queried_sha256:
        raise ValueError("VirusTotal response SHA-256 does not match queried hash")

    stats = attributes.get("last_analysis_stats")
    detections = engines_total = None
    if isinstance(stats, dict):
        counts = [n for n in stats.values() if type(n) is int and n >= 0]
        if counts:
            engines_total = sum(counts)
            malicious = stats.get("malicious")
            suspicious = stats.get("suspicious")
            if type(malicious) is int and type(suspicious) is int:
                detections = malicious + suspicious

    classification = attributes.get("popular_threat_classification")
    label = (classification.get("suggested_threat_label")
             if isinstance(classification, dict) else None)
    return {
        "sha256": queried_sha256,
        "found": True,
        "detections": detections,
        "engines_total": engines_total,
        "first_seen": _timestamp_utc(attributes.get("first_submission_date")),
        "last_analysis_date": _timestamp_utc(attributes.get("last_analysis_date")),
        "threat_label": label if isinstance(label, str) else None,
        "permalink": VT_REPORT_PAGE + queried_sha256,
        "source": "api",
    }


def _cache_file(cache_dir: Path, sha256: str) -> Path:
    return cache_dir / f"{sha256}.json"


def _read_cache(cache_dir: Path, sha256: str, *, now: float) -> dict[str, Any] | None:
    path = _cache_file(cache_dir, sha256)
    try:
        if path.stat().st_size > MAX_RESPONSE_BYTES:
            return None
        content = json.loads(path.read_text(encoding="utf-8"))
        if content.get("sha256") != sha256 or not isinstance(content.get("data"), dict):
            return None
        if not isinstance(content.get("expires_at"), (int, float)) or content["expires_at"] <= now:
            return None
        return content["data"]
    except (OSError, ValueError, TypeError, AttributeError):
        return None


def _write_cache(cache_dir: Path, sha256: str, data: dict[str, Any], *, now: float) -> None:
    """Best-effort atomic write. Never writes the API key or raw sample."""
    temporary: str | None = None
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        ttl = NOT_FOUND_TTL_SECONDS if data.get("found") is False else DEFAULT_TTL_SECONDS
        record = {"sha256": sha256, "expires_at": now + ttl, "data": data}
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=cache_dir,
                                         prefix=".vt-", suffix=".tmp", delete=False) as stream:
            temporary = stream.name
            json.dump(record, stream, ensure_ascii=False)
        os.replace(temporary, _cache_file(cache_dir, sha256))
    except OSError:
        pass  # Cache failure must not discard an otherwise valid lookup.
    finally:
        if temporary:
            try:
                os.unlink(temporary)
            except OSError:
                pass


def _allow_network_request() -> bool:
    """Enforces four VirusTotal queries/60s within this Python process."""
    with _rate_lock:
        now = time.monotonic()
        while _rate_timestamps and now - _rate_timestamps[0] >= RATE_WINDOW_SECONDS:
            _rate_timestamps.popleft()
        if len(_rate_timestamps) >= RATE_LIMIT:
            return False
        _rate_timestamps.append(now)
        return True


def lookup_sha256(
    sha256: str,
    *,
    mode: str = "live",                   # live | mock | cache_only
    api_key: str | None = None,
    cache_dir: str | Path | None = None,
    opener: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """One VirusTotal lookup as a Malworn-compatible ToolResult.

    `opener` is injectable for tests; production defaults to urllib.urlopen.
    HTTP 404 means 'not in VirusTotal', NOT that the file is safe.
    """
    try:
        sha256 = _validate_sha256(sha256)
    except HashInputError as exc:
        return _tool_result(status="failure", data={}, source="none", error=str(exc))
    if mode not in ("live", "mock", "cache_only"):
        return _tool_result(status="failure", data={"sha256": sha256}, source="none",
                            error="Invalid mode; expected live, mock, or cache_only")

    if mode == "mock":
        data = _empty_data(sha256)
        data.update({"found": False, "source": "mock"})
        return _tool_result(status="success", data=data, source="mock", warnings=[
            "Synthetic mock result; no VirusTotal lookup was performed",
            "No VirusTotal record is not evidence that a file is safe",
        ])

    directory = Path(cache_dir) if cache_dir is not None else Path.home() / ".malworn" / "vt_cache"
    cached = _read_cache(directory, sha256, now=time.time())
    if cached is not None:
        result_data = {**cached, "source": "cache"}
        return _tool_result(status="success", data=result_data, source="cache",
                            warnings=["Result retrieved from local cache; may not reflect a new scan"])

    if mode == "cache_only":
        return _tool_result(status="failure", data={"sha256": sha256}, source="none",
                            error="No unexpired local cached VirusTotal result")
    key = api_key if api_key is not None else os.getenv("VT_API_KEY")
    if not key:
        return _tool_result(status="failure", data={"sha256": sha256}, source="none",
                            error="VT_API_KEY is not configured")
    if not _allow_network_request():
        return _tool_result(status="failure", data={"sha256": sha256}, source="none",
                            error="Local rate limit: at most 4 API calls per 60 seconds")

    request = Request(
        VT_ENDPOINT + sha256,
        headers={"x-apikey": key, "Accept": "application/json"},
        method="GET",
    )
    try:
        with (opener or urlopen)(request, timeout=10) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ValueError("VirusTotal API response exceeds maximum supported size")
        parsed = json.loads(raw)
        data = _parse_vt_response(parsed, sha256)
        _write_cache(directory, sha256, data, now=time.time())
        return _tool_result(status="success", data=data, source="api")
    except HTTPError as exc:
        if exc.code == 404:
            data = _empty_data(sha256)
            data.update({"found": False, "source": "api"})
            _write_cache(directory, sha256, data, now=time.time())
            return _tool_result(status="success", data=data, source="api", warnings=[
                "Hash not found in VirusTotal; this is not evidence of safety",
            ])
        message = {
            401: "VirusTotal API authentication failed (401)",
            403: "VirusTotal API access denied or quota unavailable (403)",
            429: "VirusTotal rate limit or quota exceeded (429); retry later",
        }.get(exc.code, f"VirusTotal returned HTTP {exc.code}")
        return _tool_result(status="failure", data={"sha256": sha256}, source="none", error=message)
    except (URLError, TimeoutError, OSError):
        return _tool_result(status="failure", data={"sha256": sha256}, source="none",
                            error="VirusTotal service unavailable or network timed out")
    except (ValueError, TypeError, UnicodeDecodeError) as exc:
        return _tool_result(status="failure", data={"sha256": sha256}, source="none",
                            error=f"Invalid VirusTotal API response: {exc}")


def lookup_from_hash_result(hash_result: Any, **lookup_options: Any) -> dict[str, Any]:
    """Consume Ahmed's future hashes ToolResult or a direct SHA-256 value."""
    try:
        sha256 = extract_sha256(hash_result)
    except HashInputError as exc:
        return _tool_result(status="failure", data={}, source="none", error=str(exc))
    return lookup_sha256(sha256, **lookup_options)


def lookup_from_file(
    file_path: str | Path,
    *,
    hash_module: str = "malworn.tools.hashes",
    hash_function: str = "run",
    **lookup_options: Any,
) -> dict[str, Any]:
    """Load the future hashes.py module; never upload/open/execute the sample here.

    The hash module's callable must accept the path and return either a
    {'data': {'sha256': '...'}} ToolResult, {'sha256': '...'}, or a SHA-256 string.
    """
    try:
        module = import_module(hash_module)
        generate_hash = getattr(module, hash_function)
        if not callable(generate_hash):
            raise TypeError("hash function is not callable")
        hash_result = generate_hash(str(file_path))
        return lookup_from_hash_result(hash_result, **lookup_options)
    except (ModuleNotFoundError, AttributeError, TypeError, OSError, ValueError) as exc:
        return _tool_result(status="failure", data={}, source="none",
                            error=f"Could not obtain SHA-256 from hash module: {exc}")


def run(input_value: Any, *, mode: str = "live", **options: Any) -> dict[str, Any]:
    """Simple tool entrypoint for Saood's agent.

    Accepts an already-computed SHA-256, a hash ToolResult dictionary, or a file
    path (delegated to the imported hash module). The sample is never uploaded.
    """
    if isinstance(input_value, Mapping):
        return lookup_from_hash_result(input_value, mode=mode, **options)
    if isinstance(input_value, str) and _SHA256_RE.fullmatch(input_value):
        return lookup_sha256(input_value, mode=mode, **options)
    return lookup_from_file(input_value, mode=mode, **options)


def main() -> int:
    parser = argparse.ArgumentParser(description="Malworn hash-only VirusTotal lookup")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--sha256", help="64-character SHA-256 to look up")
    group.add_argument("--hash-json", type=Path, help="JSON result from the hash tool")
    group.add_argument("--file", type=Path, help="Pass a path to the separate hash generator")
    parser.add_argument("--hash-module", default="malworn.tools.hashes",
                        help="Import path for future hashes.py (default: malworn.tools.hashes)")
    parser.add_argument("--hash-function", default="run", help="Hash module entrypoint")
    parser.add_argument("--mode", choices=["live", "mock", "cache_only"], default="mock")
    parser.add_argument("--output", type=Path, help="Optional output path for the ToolResult JSON")
    args = parser.parse_args()
    if args.sha256:
        result = lookup_sha256(args.sha256, mode=args.mode)
    elif args.hash_json:
        try:
            if args.hash_json.stat().st_size > MAX_HASH_JSON_BYTES:
                raise ValueError("Hash JSON input is too large")
            hash_input = json.loads(args.hash_json.read_text(encoding="utf-8"))
            result = lookup_from_hash_result(hash_input, mode=args.mode)
        except (OSError, ValueError) as exc:
            result = _tool_result(status="failure", data={}, source="none",
                                  error=f"Cannot load hash JSON: {exc}")
    else:
        result = lookup_from_file(args.file, hash_module=args.hash_module,
                                  hash_function=args.hash_function, mode=args.mode)

    output = json.dumps(result, indent=2, ensure_ascii=False)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output + "\n", encoding="utf-8")
    print(output)
    return 0 if result["status"] == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
