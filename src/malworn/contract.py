"""The tool contract: how every Malworn tool describes itself and what it returns.

Owner: Saood. Do not change this file without a team decision (it is the
interface between everyone's work). The rules are explained in
docs/data-format.md.

Each tool module has two things:

    SPEC = ToolSpec(
        name="hashes",
        description="Compute the MD5, SHA-1 and SHA-256 hashes of the file.",
        data_keys=("md5", "sha1", "sha256"),
        requirement="FR2",
        owner="Ahmed",
    )

    def run(file_path):
        ...
        return {"tool": "hashes", "status": "success", "data": {...}}

run() may return a plain dict (as above) or use the helpers success(),
failure() and skipped() below. The agent never calls run() directly: it calls
run_tool(SPEC, run, path), which times the tool, fills in anything missing,
checks the result against SPEC, and turns any exception into a "failure" result,
so one broken tool can never crash the analysis.

The results go to Hassan's aggregator (src/malworn/detection/malworn_aggregator.py),
which builds the final report. This file does not define the report.
"""

import re
import time
from dataclasses import asdict, dataclass, field

CONTRACT_VERSION = "0.3"

STATUS_SUCCESS = "success"
STATUS_FAILURE = "failure"
STATUS_SKIPPED = "skipped"
STATUSES = (STATUS_SUCCESS, STATUS_FAILURE, STATUS_SKIPPED)

# Accepted when reading a result, converted to the names above (the same
# aliases the aggregator accepts).
_STATUS_ALIASES = {"ok": STATUS_SUCCESS, "error": STATUS_FAILURE, "failed": STATUS_FAILURE}

# Tools report facts, never judgements (FR7). These words must not appear in a
# tool's warnings. ("suspicious" is included: say WHAT was observed instead;
# the agent explains why it matters.)
VERDICT_WORDS = ("malicious", "benign", "safe", "clean", "suspicious", "harmless", "infected")
_VERDICT_RE = re.compile(r"\b(" + "|".join(VERDICT_WORDS) + r")\b", re.IGNORECASE)
_TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")


# ---------------------------------------------------------------------------
# What a tool is
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
    version: str = "0.1"   # bump when the data keys or their meaning change

    def __post_init__(self):
        if not _TOOL_NAME_RE.match(self.name):
            raise ValueError(f"tool name must be snake_case: {self.name!r}")
        if not self.description.strip():
            raise ValueError(f"tool {self.name!r} needs a description")
        object.__setattr__(self, "data_keys", tuple(self.data_keys))

    def for_model(self):
        """The tool as the model sees it when choosing tools."""
        return {"name": self.name, "description": self.description}


# ---------------------------------------------------------------------------
# What a tool returns
# ---------------------------------------------------------------------------
@dataclass
class ToolResult:
    """One tool's result. to_dict() is what goes to the aggregator."""

    tool: str
    status: str
    data: dict
    warnings: list = field(default_factory=list)
    error: str = None
    tool_version: str = "0.1"
    duration_ms: int = None
    call_id: str = None  # set by the agent; the aggregator numbers calls if missing

    def to_dict(self):
        d = asdict(self)
        if d["call_id"] is None:
            del d["call_id"]
        return d

    @classmethod
    def from_dict(cls, d):
        status = d.get("status")
        if isinstance(status, str):
            status = _STATUS_ALIASES.get(status.lower(), status.lower())
        return cls(
            tool=d.get("tool"),
            status=status,
            data=d.get("data") if d.get("data") is not None else {},
            warnings=list(d.get("warnings") or []),
            error=d.get("error"),
            tool_version=d.get("tool_version", "0.1"),
            duration_ms=d.get("duration_ms"),
            call_id=d.get("call_id"),
        )


def success(spec, data, warnings=None):
    """A successful result. Missing keys become None."""
    data = dict(data or {})
    return ToolResult(spec.name, STATUS_SUCCESS, _complete(spec, data), list(warnings or []),
                      tool_version=spec.version)


def failure(spec, error):
    """The tool could not do its job (e.g. the file is not a valid PE)."""
    return ToolResult(spec.name, STATUS_FAILURE, {}, [], error=str(error),
                      tool_version=spec.version)


def skipped(spec, reason):
    """The tool does not apply to this file (e.g. a PE-only tool on a PDF)."""
    return ToolResult(spec.name, STATUS_SKIPPED, {}, [], error=str(reason),
                      tool_version=spec.version)


def _complete(spec, data):
    """Every SPEC key present (None if the tool didn't fill it); refuse unknown keys,
    because they mean the tool and docs/data-format.md have drifted apart."""
    unknown = sorted(set(data) - set(spec.data_keys))
    if unknown:
        raise ValueError(
            f"tool {spec.name!r} returned keys not in its SPEC: {unknown}. "
            "Add them to data_keys and docs/data-format.md."
        )
    return {key: data.get(key) for key in spec.data_keys}


# ---------------------------------------------------------------------------
# Running a tool (used by the agent)
# ---------------------------------------------------------------------------
def run_tool(spec, run, file_path, call_id=None):
    """Run one tool safely and return a normalised ToolResult.

    - accepts a ToolResult or a plain dict from run()
    - converts "ok"/"error" to "success"/"failure", adds missing warnings
    - fills missing data keys with None; unknown keys make it a failure
    - gives a failure/skipped result without an error message the reason it reported
    - turns any exception into a "failure" result instead of crashing
    """
    started = time.perf_counter()
    try:
        raw = run(file_path)
        if isinstance(raw, ToolResult):
            result = raw
        elif isinstance(raw, dict):
            result = ToolResult.from_dict(raw)
        else:
            raise TypeError(f"run() must return a dict or ToolResult, got {type(raw).__name__}")
        if result.tool != spec.name:
            raise ValueError(f"result is labelled {result.tool!r}, expected {spec.name!r}")
        if result.status not in STATUSES:
            raise ValueError(f"unknown status {result.status!r}")
        if not isinstance(result.data, dict):
            raise TypeError("data must be a dict")
        if result.status == STATUS_SUCCESS:
            result.data = _complete(spec, result.data)
        elif not result.error:
            # e.g. {"status": "skipped", "data": {"reason": "not a PE"}}: keep the reason as the error
            result.error = (result.data.get("reason") or (result.warnings or [None])[0]
                            or f"tool reported {result.status} without a reason")
        result.tool_version = spec.version
    except Exception as exc:  # noqa: BLE001 - turning any failure into data is the point
        result = failure(spec, f"{type(exc).__name__}: {exc}")
    result.duration_ms = round((time.perf_counter() - started) * 1000)
    result.call_id = call_id
    return result


# ---------------------------------------------------------------------------
# Checking results (use in every tool's tests)
# ---------------------------------------------------------------------------
def find_verdict_words(text):
    """Return the verdict words used in ``text`` (empty list if none)."""
    return [m.group(0) for m in _VERDICT_RE.finditer(text or "")]


def validate(result, spec=None):
    """Return a list of problems with a result (empty list = valid).

    In a tool's tests:  assert validate(run(path), SPEC) == []
    Plain dicts from run() are checked as they are, so a missing "warnings"
    list or an "ok" status is reported (run_tool would fix them silently).
    """
    problems = []
    if isinstance(result, dict):
        raw = result
        if raw.get("status") not in STATUSES:
            problems.append(f"status must be one of {STATUSES}, got {raw.get('status')!r}")
        if "warnings" not in raw:
            problems.append("warnings is missing (use [] when there are none)")
        result = ToolResult.from_dict(raw)
    elif result.status not in STATUSES:
        problems.append(f"status must be one of {STATUSES}, got {result.status!r}")

    if not _TOOL_NAME_RE.match(result.tool or ""):
        problems.append(f"tool name must be snake_case: {result.tool!r}")
    if not isinstance(result.data, dict):
        problems.append("data must be a dict")
    if not isinstance(result.warnings, list) or not all(isinstance(w, str) for w in result.warnings):
        problems.append("warnings must be a list of strings")
    else:
        for w in result.warnings:
            words = find_verdict_words(w)
            if words:
                problems.append(f"warning uses verdict words {words}: {w!r}")
    if result.status == STATUS_SUCCESS and result.error:
        problems.append("a success result must not have an error")
    if result.status in (STATUS_FAILURE, STATUS_SKIPPED) and not result.error:
        problems.append(f"a {result.status} result must explain why in error")
    if spec is not None:
        if result.tool != spec.name:
            problems.append(f"tool is {result.tool!r}, expected {spec.name!r}")
        if result.status == STATUS_SUCCESS and isinstance(result.data, dict):
            missing = [k for k in spec.data_keys if k not in result.data]
            extra = [k for k in result.data if k not in spec.data_keys]
            if missing:
                problems.append(f"data is missing keys {missing}")
            if extra:
                problems.append(f"data has keys not in the SPEC {extra}")
    return problems


def tool_catalogue(specs):
    """The list of tools given to the model: [{"name", "description"}, ...]."""
    names = [s.name for s in specs]
    if len(names) != len(set(names)):
        raise ValueError(f"duplicate tool names: {names}")
    return [s.for_model() for s in specs]
