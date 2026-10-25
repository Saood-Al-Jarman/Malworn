
"""Malworn H3: deterministic aggregation of agent-selected static-analysis tools.

This standalone, standard-library-only reference implementation consumes tool
outputs. It does NOT run binaries, dispatch tools, call an LLM, contact VirusTotal,
or determine whether a file is malicious or benign.

IMPORTANT: The exact current contents of Malworn's contract.py were unavailable
when this was written. The input adapter below is a PROVISIONAL mapping of the
October 19 task list's shared ToolResult concept. Before merging, compare the
adapter against the repo's actual ToolResult and report helpers.
"""

from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Mapping, Sequence
from uuid import uuid4

SCHEMA_VERSION = "malworn.aggregated-report.provisional.v1"
MAX_INPUT_BYTES = 10 * 1024 * 1024  # Aggregator inputs only; not uploaded binaries.
MAX_FACTS_PER_CALL = 20_000
MAX_NESTING_DEPTH = 32

STATUS_ALIASES = {
    "success": "success",
    "ok": "success",
    "failure": "failure",
    "failed": "failure",
    "error": "failure",
    "skipped": "skipped",
}


class AggregationError(ValueError):
    """Malformed or inconsistent agent/tool results."""


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AggregationError(f"{label} must be a JSON object (Python dict)")
    return value


def _unique_tool_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list):
        raise AggregationError(f"{label} must be an array of tool-name strings")
    if not all(isinstance(item, str) and item.strip() for item in value):
        raise AggregationError(f"{label} contains an empty/non-string tool name")
    names = [name.strip() for name in value]
    if len(names) != len(set(names)):
        raise AggregationError(f"{label} contains repeated tool names")
    return names


def _normalize_status(raw: Mapping[str, Any]) -> str:
    """Provisional adapter: supports {status:'success'} or {ok: True}."""
    status = raw.get("status")
    if status is None:
        for flag in ("ok", "success"):
            if isinstance(raw.get(flag), bool):
                return "success" if raw[flag] else "failure"
        raise AggregationError("Tool result must include status, ok, or success")
    if not isinstance(status, str) or status.lower() not in STATUS_ALIASES:
        raise AggregationError(f"Unrecognized ToolResult status: {status!r}")
    return STATUS_ALIASES[status.lower()]


def _normalize_tool_result(raw: Any, call_index: int) -> dict[str, Any]:
    obj = _require_object(raw, f"tool_results[{call_index}]")
    tool = obj.get("tool", obj.get("tool_name", obj.get("name")))
    if not isinstance(tool, str) or not tool.strip():
        raise AggregationError(f"tool_results[{call_index}] requires a nonempty 'tool' name")

    status = _normalize_status(obj)
    # Data belongs to the tool and is never synthesized by the AI/aggregator.
    if "data" in obj:
        data = obj["data"]
    elif "result" in obj:
        data = obj["result"]
    else:
        data = {}
    if not isinstance(data, (dict, list)):
        raise AggregationError(f"Data for {tool!r} must be a dict or list")
    if status == "success" and not ("data" in obj or "result" in obj):
        raise AggregationError(f"Successful result {tool!r} needs a data or result field")

    warnings = obj.get("warnings", [])
    if not isinstance(warnings, list) or not all(isinstance(x, str) for x in warnings):
        raise AggregationError(f"warnings for {tool!r} must be a list of strings")
    error = obj.get("error")
    if error is not None and not isinstance(error, str):
        raise AggregationError(f"error for {tool!r} must be a string or null")

    call_id = obj.get("call_id")
    if call_id is None:
        call_id = f"call-{call_index + 1:03d}"
    if not isinstance(call_id, str) or not call_id.strip():
        raise AggregationError(f"call_id for {tool!r} must be a nonempty string")

    # Optional metadata that is useful for provenance; no model-created facts.
    provenance = {}
    for key in ("tool_version", "source", "duration_ms", "started_at", "finished_at"):
        if key in obj:
            provenance[key] = deepcopy(obj[key])
    return {
        "tool": tool.strip(),
        "call_id": call_id,
        "execution_status": status,
        "display_status": "not_available" if status == "failure" else status,
        "data": deepcopy(data),
        "warnings": list(warnings),
        "error": error,
        "provenance": provenance,
    }


def _extract_facts(value: Any, *, tool: str, call_id: str) -> tuple[list[dict[str, Any]], bool]:
    """Flatten JSON leaves for explicit per-fact attribution; retain full data too.

    This is structural extraction, NOT security classification or semantic analysis.
    Paths index into a tool's `data` field. Dictionary/list containers with no
    children do not count as facts.
    """
    facts: list[dict[str, Any]] = []
    stack: list[tuple[str, Any, int]] = [("data", value, 0)]
    truncated = False
    while stack:
        path, node, depth = stack.pop()
        if depth > MAX_NESTING_DEPTH:
            truncated = True
            continue
        if isinstance(node, dict):
            for key, item in reversed(list(node.items())):
                stack.append((f"{path}[{json.dumps(str(key), ensure_ascii=False)}]", item, depth + 1))
        elif isinstance(node, list):
            for index in range(len(node) - 1, -1, -1):
                stack.append((f"{path}[{index}]", node[index], depth + 1))
        else:
            if len(facts) >= MAX_FACTS_PER_CALL:
                truncated = True
                break
            facts.append({
                "field_path": path,
                "value": deepcopy(node),
                "source_tool": tool,
                "source_call_id": call_id,
            })
    return facts, truncated


def aggregate_results(
    tool_results: Sequence[Mapping[str, Any]],
    *,
    file_info: Mapping[str, Any],
    selected_tools: Sequence[str] | None = None,
    available_tools: Sequence[str] | None = None,
    agent_explanation: str | None = None,
    analysis_id: str | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build one factual JSON report from tool-returned data.

    `selected_tools` is what the agent chose. A selected tool with no result is
    listed under missing_results, never faked as success. `available_tools`
    is an OPTIONAL registry, allowing not-selected tools to be identified.
    """
    if isinstance(tool_results, (str, bytes)) or not isinstance(tool_results, (list, tuple)):
        raise AggregationError("tool_results must be a list of tool return objects")
    file_data = _require_object(file_info, "file_info")
    sha256 = file_data.get("sha256")
    if sha256 is not None and (not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", sha256)):
        raise AggregationError("file_info.sha256 must be 64 hexadecimal characters when provided")
    if agent_explanation is not None and not isinstance(agent_explanation, str):
        raise AggregationError("agent_explanation must be a string or null")

    results = [_normalize_tool_result(raw, i) for i, raw in enumerate(tool_results)]
    observed_tools = list(dict.fromkeys(result["tool"] for result in results))
    if selected_tools is None:
        selections = observed_tools
    else:
        selections = _unique_tool_list(list(selected_tools), "selected_tools")
    if available_tools is None:
        available = list(dict.fromkeys(selections + observed_tools))
    else:
        available = _unique_tool_list(list(available_tools), "available_tools")
        unregistered = set(selections + observed_tools) - set(available)
        if unregistered:
            raise AggregationError(f"Selected/returned tools not in available_tools: {sorted(unregistered)}")
    unexpected = set(observed_tools) - set(selections)
    if unexpected:
        raise AggregationError(f"Received results not in agent's selected_tools: {sorted(unexpected)}")

    call_ids: set[str] = set()
    for result in results:
        if result["call_id"] in call_ids:
            raise AggregationError(f"Repeated call_id: {result['call_id']!r}")
        call_ids.add(result["call_id"])
        facts, truncated = _extract_facts(
            result["data"], tool=result["tool"], call_id=result["call_id"]
        ) if result["execution_status"] == "success" else ([], False)
        result["facts"] = facts
        result["facts_truncated"] = truncated

    returned_names = set(observed_tools)
    missing = [tool for tool in selections if tool not in returned_names]
    not_selected = [tool for tool in available if tool not in set(selections)]

    # Explicitly differentiate: not selected / selected but no result / tool failed.
    failed = [
        {"tool": r["tool"], "call_id": r["call_id"], "reason": r["error"] or "Tool returned failure"}
        for r in results if r["execution_status"] == "failure"
    ]
    status_counts = Counter(r["execution_status"] for r in results)
    summary = {
        "selected_tools": selections,
        "available_tools": available,
        "not_selected_tools": not_selected,
        "missing_results": missing,
        "failed_calls": failed,
        "successful_calls": status_counts["success"],
        "failed_call_count": status_counts["failure"],
        "skipped_call_count": status_counts["skipped"],
        "total_returned_calls": len(results),
        "total_facts": sum(len(r["facts"]) for r in results),
        "fact_limit_reached": any(r["facts_truncated"] for r in results),
    }

    # An explanation is separated from facts and marked model-generated.
    return {
        "schema_version": SCHEMA_VERSION,
        "analysis_id": analysis_id or str(uuid4()),
        "generated_at": generated_at or datetime.now(timezone.utc).isoformat(),
        "analysis_scope": "static_only",
        "file": deepcopy(file_data),
        "execution_summary": summary,
        "tool_results": results,
        "agent_commentary": {
            "text": agent_explanation,
            "origin": "agent_generated_not_tool_evidence" if agent_explanation is not None else "not_supplied",
        },
        "notice": "Factual tool outputs only. No malware verdict or classification is generated by this aggregator.",
    }


def aggregate_agent_run(run: Mapping[str, Any]) -> dict[str, Any]:
    """Convenience interface for a JSON agent-run envelope.

    Proposed example input keys: file, tool_results, selected_tools,
    available_tools, agent_explanation. Adjust this thin adapter to the
    REAL `contract.py` before integration; do not fork the team's schema.
    """
    obj = _require_object(run, "agent_run")
    return aggregate_results(
        obj.get("tool_results", []),
        file_info=obj.get("file", {}),
        selected_tools=obj.get("selected_tools"),
        available_tools=obj.get("available_tools"),
        agent_explanation=obj.get("agent_explanation"),
        analysis_id=obj.get("analysis_id"),
        generated_at=obj.get("generated_at"),
    )


def load_json(path: str | Path) -> dict[str, Any]:
    """Read only JSON; reject very large inputs rather than consuming a sample file."""
    path = Path(path)
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise AggregationError(f"JSON input exceeds {MAX_INPUT_BYTES} bytes")
    with path.open("r", encoding="utf-8") as stream:
        return _require_object(json.load(stream), "input JSON")


def write_report_json(report: Mapping[str, Any], output_path: str | Path) -> Path:
    """Save the combined JSON atomically; does not read or run the sample."""
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=target.parent, prefix=".malworn_",
            suffix=".tmp", delete=False,
        ) as tmp:
            temporary_path = tmp.name
            json.dump(report, tmp, indent=2, ensure_ascii=False, allow_nan=False)
            tmp.write("\n")
        os.replace(temporary_path, target)
    finally:
        if temporary_path and os.path.exists(temporary_path):
            os.unlink(temporary_path)
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Aggregate Malworn static-tool results into a JSON report")
    parser.add_argument("--input", required=True, help="JSON envelope with agent-selected tool results")
    parser.add_argument("--output", required=True, help="Output report.json path")
    args = parser.parse_args(argv)
    try:
        report = aggregate_agent_run(load_json(args.input))
        path = write_report_json(report, args.output)
    except (AggregationError, OSError, json.JSONDecodeError, TypeError, OverflowError) as exc:
        parser.exit(2, f"Aggregation failed: {exc}\n")
    print(f"Wrote aggregated report: {path}")
    print(json.dumps(report["execution_summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
