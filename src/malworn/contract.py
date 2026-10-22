"""The tool contract: the one shape every Malworn tool returns.

Owner: Saood. Do not change this file without a team decision (it is the
interface between everyone's work). The rules it enforces are explained in
docs/data-format.md.

How a tool uses it (example for a tool in src/malworn/static_analysis/):

    from malworn.contract import ToolSpec, ok

    SPEC = ToolSpec(
        name="hashes",
        description="Compute the MD5, SHA-1 and SHA-256 hashes of the file.",
        data_keys=("md5", "sha1", "sha256"),
        requirement="FR2",
        owner="Ahmed",
    )

    def run(file_path):
        hashes = calculate_hashes(file_path)
        return ok(SPEC, hashes)

The agent never calls run() directly. It calls run_tool(SPEC, run, path),
which times the tool and turns any exception into an "error" result, so one
broken tool can never crash the analysis.
"""

import hashlib
import re
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "0.2"

STATUS_OK = "ok"
STATUS_ERROR = "error"
STATUS_SKIPPED = "skipped"
STATUSES = (STATUS_OK, STATUS_ERROR, STATUS_SKIPPED)

# Tools report facts, never judgements (FR7). These words must not appear in a
# tool's warnings. ("suspicious" is included: say WHAT was observed instead.)
VERDICT_WORDS = ("malicious", "benign", "safe", "clean", "suspicious", "harmless", "infected")
_VERDICT_RE = re.compile(r"\b(" + "|".join(VERDICT_WORDS) + r")\b", re.IGNORECASE)
_TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")


# ---------------------------------------------------------------------------
# What a tool is, and what it returns
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ToolSpec:
    """Describes one tool. The agent shows name + description to the model so
    it can choose which tools to call (FR9)."""

    name: str              # snake_case, unique, e.g. "sections"
    description: str       # one or two sentences, written for the model
    data_keys: tuple       # every key the tool's data always contains
    requirement: str = ""  # the FR it implements, e.g. "FR4"
    owner: str = ""        # who maintains it
    version: str = "0.1"   # bump when the data keys or meaning change

    def __post_init__(self):
        if not _TOOL_NAME_RE.match(self.name):
            raise ValueError(f"tool name must be snake_case: {self.name!r}")
        if not self.description.strip():
            raise ValueError(f"tool {self.name!r} needs a description")
        object.__setattr__(self, "data_keys", tuple(self.data_keys))


@dataclass
class ToolResult:
    """What every tool returns. Serialised with to_dict() into the report."""

    tool: str
    status: str
    data: dict
    warnings: list = field(default_factory=list)
    error: str = None
    tool_version: str = "0.1"
    duration_ms: int = None

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, d):
        return cls(
            tool=d["tool"],
            status=d["status"],
            data=d.get("data") or {},
            warnings=list(d.get("warnings") or []),
            error=d.get("error"),
            tool_version=d.get("tool_version", "0.1"),
            duration_ms=d.get("duration_ms"),
        )


# ---------------------------------------------------------------------------
# Building results (tools use these instead of constructing ToolResult)
# ---------------------------------------------------------------------------
def ok(spec, data, warnings=None):
    """A successful result. Missing keys become None; unknown keys are an error,
    because they mean the tool and docs/data-format.md have drifted apart."""
    data = dict(data or {})
    unknown = sorted(set(data) - set(spec.data_keys))
    if unknown:
        raise ValueError(
            f"tool {spec.name!r} returned keys not in its ToolSpec: {unknown}. "
            "Add them to data_keys and docs/data-format.md."
        )
    full = {key: data.get(key) for key in spec.data_keys}
    return ToolResult(spec.name, STATUS_OK, full, list(warnings or []),
                      tool_version=spec.version)


def failure(spec, error):
    """The tool could not do its job. Every data key is present and None."""
    return ToolResult(spec.name, STATUS_ERROR, {k: None for k in spec.data_keys}, [],
                      error=str(error), tool_version=spec.version)


def skipped(spec, reason):
    """The tool did not apply (e.g. a PE-only tool on a PDF)."""
    return ToolResult(spec.name, STATUS_SKIPPED, {k: None for k in spec.data_keys}, [],
                      error=str(reason), tool_version=spec.version)


def run_tool(spec, run, file_path):
    """Run one tool safely: time it, and never let an exception escape."""
    started = time.perf_counter()
    try:
        result = run(file_path)
        if not isinstance(result, ToolResult):
            raise TypeError(f"run() must return a ToolResult, got {type(result).__name__}")
        if result.tool != spec.name:
            raise ValueError(f"result is labelled {result.tool!r}, expected {spec.name!r}")
    except Exception as exc:  # noqa: BLE001 - turning any failure into data is the point
        result = failure(spec, f"{type(exc).__name__}: {exc}")
    result.duration_ms = round((time.perf_counter() - started) * 1000)
    return result


# ---------------------------------------------------------------------------
# Checking results
# ---------------------------------------------------------------------------
def find_verdict_words(text):
    """Return the verdict words used in ``text`` (empty list if none)."""
    return [m.group(0) for m in _VERDICT_RE.finditer(text or "")]


def validate(result, spec=None):
    """Return a list of problems with a result (empty list = valid).

    Use it in every tool's tests:  assert validate(run(path), SPEC) == []
    """
    if isinstance(result, dict):
        result = ToolResult.from_dict(result)
    problems = []
    if not _TOOL_NAME_RE.match(result.tool or ""):
        problems.append(f"tool name must be snake_case: {result.tool!r}")
    if result.status not in STATUSES:
        problems.append(f"status must be one of {STATUSES}, got {result.status!r}")
    if not isinstance(result.data, dict):
        problems.append("data must be a dict")
    if not isinstance(result.warnings, list) or not all(isinstance(w, str) for w in result.warnings):
        problems.append("warnings must be a list of strings")
    else:
        for w in result.warnings:
            words = find_verdict_words(w)
            if words:
                problems.append(f"warning uses verdict words {words}: {w!r}")
    if result.status == STATUS_OK and result.error:
        problems.append("an ok result must not have an error")
    if result.status != STATUS_OK and not result.error:
        problems.append(f"a {result.status} result must explain why in error")
    if spec is not None and isinstance(result.data, dict):
        if result.tool != spec.name:
            problems.append(f"tool is {result.tool!r}, expected {spec.name!r}")
        missing = [k for k in spec.data_keys if k not in result.data]
        extra = [k for k in result.data if k not in spec.data_keys]
        if missing:
            problems.append(f"data is missing keys {missing}")
        if extra:
            problems.append(f"data has keys not in the ToolSpec {extra}")
    return problems


# ---------------------------------------------------------------------------
# The report
# ---------------------------------------------------------------------------
def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def new_report(file_path, original_name=None):
    """Start a report for one sample. The sample is identified by its SHA-256."""
    path = Path(file_path)
    return {
        "schema_version": SCHEMA_VERSION,
        "sample": {
            "file_name": original_name or path.name,
            "sha256": _sha256(path),
            "file_size": path.stat().st_size,
            "received_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        "tool_calls": [],
        "results": {},
    }


def add_result(report, result):
    """Record a tool result in the report (in the order the agent called it)."""
    if isinstance(result, ToolResult):
        result = result.to_dict()
    report["tool_calls"].append(result["tool"])
    report["results"][result["tool"]] = result
    return report


def validate_report(report, specs=None):
    """Return a list of problems with a whole report (empty list = valid).

    ``specs`` is an optional {tool_name: ToolSpec} map to check data keys too.
    """
    problems = []
    for key in ("schema_version", "sample", "tool_calls", "results"):
        if key not in report:
            problems.append(f"report is missing {key!r}")
    if problems:
        return problems
    for key in ("file_name", "sha256", "file_size", "received_at"):
        if key not in report["sample"]:
            problems.append(f"sample is missing {key!r}")
    for name, result in report["results"].items():
        if result.get("tool") != name:
            problems.append(f"results[{name!r}] is labelled {result.get('tool')!r}")
        spec = (specs or {}).get(name)
        problems += [f"{name}: {p}" for p in validate(result, spec)]
    for name in report["tool_calls"]:
        if name not in report["results"]:
            problems.append(f"tool_calls lists {name!r} but it has no result")
    return problems
