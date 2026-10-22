# Malworn Data Format

**Version:** 0.2 (draft, open for team review)
**Owner:** Saood
**Code:** [`src/malworn/contract.py`](../src/malworn/contract.py) implements everything in this document. If the two ever disagree, fix whichever is wrong in the same pull request.

This document defines what every Malworn tool returns and what the final report looks like. If everyone follows it, the four of us can build our tools in parallel and the agent can use any of them without knowing how they work inside.

## The design in one paragraph

Malworn is an **agent, not a chatbot** (Meeting 1): the model *chooses and calls tools* (FR9), each tool is a normal Python script that reads the file and returns **facts**, and the model explains those facts to the analyst. The model never reads the file itself and never decides whether the file is malicious. The report contains the full evidence with **no malicious/benign verdict** (FR7), and every fact is credited to the tool that produced it (NFR4, NFR7).

```
analyst uploads file (FR1)
        │
        ▼
new_report()  ── sample: name, SHA-256, size
        │
        ▼
┌─────────────── agent loop (Saood) ───────────────┐
│ model sees the list of tools (name + description) │
│ model picks a tool ──► run_tool() ──► ToolResult  │
│ result added to report, model sees it             │
│ ...repeat until the model has what it needs...    │
└───────────────────────────────────────────────────┘
        │
        ▼
report.json ──► report builder (Hassan) ──► web page (FR10)
        │
        └──► model's explanation + follow-up chat, citing tool names
```

## Rules

1. **Tools report facts, never verdicts.** A tool says "section UPX1 has entropy 7.91", not "the file is packed" or "suspicious". The words *malicious, benign, safe, clean, suspicious, harmless, infected* are not allowed in a tool's `warnings`; `validate()` rejects them (FR7).
2. **Every tool returns a `ToolResult`** (below), built with `ok()`, `failure()` or `skipped()` from `contract.py`.
3. **Every data key is always present.** If a value is unknown, it is `null` (or `[]` for lists). The keys a tool returns are fixed in its `ToolSpec`; `ok()` refuses keys that aren't listed, so the code and this document can't drift apart.
4. **A tool never crashes the analysis.** The agent runs tools through `run_tool()`, which turns any exception into an `"error"` result. The analysis continues and the report shows that tool as unavailable.
5. **The model never chooses which file a tool reads.** Tools take only `file_path`, and the agent supplies it. The model picks *which* tool, not *what* it runs on.
6. **Text from the sample is untrusted (NFR3).** Section names, strings and names from VirusTotal can contain anything, including text written to trick the model. Tools copy it as data and never act on it; the agent treats it as data, not instructions.
7. **Packing is shown as indicators, never as a decision (FR5).** Legitimate software is often packed too (ViPER: 73% of benign samples), so there is no `is_packed` field.
8. **Only hashes leave the machine (FR3, NFR2).** The VirusTotal tool looks up the SHA-256; the sample is never uploaded anywhere.
9. **Changing this format needs a pull request** that updates this document and `contract.py` together, approved by the team.

## `ToolResult`: what every tool returns

```json
{
  "tool": "sections",
  "tool_version": "0.1",
  "status": "ok",
  "data": { "...": "the tool's facts; keys fixed by its ToolSpec" },
  "warnings": ["Section UPX1 has entropy 7.91"],
  "error": null,
  "duration_ms": 14
}
```

| Field | Type | Meaning |
|---|---|---|
| `tool` | string | The tool's name (snake_case). Lets every fact be credited to its tool (NFR7). |
| `tool_version` | string | Bumped when the tool's keys or their meaning change (NFR9). |
| `status` | `"ok"`, `"error"`, `"skipped"` | `skipped` = the tool doesn't apply (e.g. a PE-only tool on a PDF). |
| `data` | object | The facts. Every key from the tool's `ToolSpec` is present. |
| `warnings` | list of strings | Facts worth the analyst's attention, phrased as observations. Never verdict words. |
| `error` | string or null | Required when status is `error` or `skipped`, `null` when `ok`. |
| `duration_ms` | int | Filled in by `run_tool()` (helps with the 60-second target, sub-objective O4). |

## `ToolSpec`: how a tool describes itself

Each tool module has one `SPEC` and one `run(file_path)` function:

```python
from malworn.contract import ToolSpec, ok, skipped

SPEC = ToolSpec(
    name="sections",
    description="List the PE sections with their sizes, entropy and permissions.",
    data_keys=("section_count", "sections"),
    requirement="FR4",
    owner="Ahmed",
)

def run(file_path):
    ...  # read the file, never execute it
    return ok(SPEC, {"section_count": 2, "sections": [...]},
              warnings=["Section UPX1 has entropy 7.91"])
```

The `description` is what the model reads when deciding which tool to call, so write it for the model: what the tool returns, in one or two plain sentences.

Adding a new tool means adding a module with a `SPEC` and `run()`, plus a line in the agent's tool list. The agent loop itself doesn't change (NFR8).

## The report

```json
{
  "schema_version": "0.2",
  "sample": {
    "file_name": "invoice.exe",
    "sha256": "<64 hex characters>",
    "file_size": 245760,
    "received_at": "2026-10-22T16:30:00Z"
  },
  "tool_calls": ["hashes", "file_type", "sections", "packing_indicators"],
  "results": {
    "hashes": { "...ToolResult..." },
    "file_type": { "...ToolResult..." }
  }
}
```

| Field | Meaning |
|---|---|
| `sample` | Filled in by `new_report()` before any tool runs. The SHA-256 identifies the sample and names the report file. |
| `tool_calls` | The tools the agent called, in order. This is how we measure tool selection (sub-objective O3: the right tools in ≥90% of requests). |
| `results` | One `ToolResult` per tool that ran, keyed by tool name. A tool the agent didn't call is simply absent. |

There is deliberately **no verdict field** anywhere in the report.

## Tool catalogue (MVP: sub-objective O1)

Proposed keys for each tool. Owners: please check yours and say what to change in the pull request.

### `hashes`: Ahmed, FR2

| Key | Type | Meaning |
|---|---|---|
| `md5` | string | MD5 hash |
| `sha1` | string | SHA-1 hash |
| `sha256` | string | SHA-256 hash |

### `file_type`: Ahmed, FR4

| Key | Type | Meaning |
|---|---|---|
| `description` | string | e.g. `"Windows PE executable"` |
| `is_pe` | bool | True if the file parses as a PE |
| `machine` | string or null | `"x86"`, `"x64"`, `"arm64"` |
| `is_dll` | bool or null | True for a DLL |
| `subsystem` | string or null | `"windows_gui"`, `"windows_cui"`, ... |
| `compile_timestamp` | string or null | From the PE header, ISO 8601 UTC (can be faked by the author) |

### `sections`: Ahmed, FR4

| Key | Type | Meaning |
|---|---|---|
| `section_count` | int | Number of sections |
| `sections` | list | One object per section: `name`, `virtual_address`, `virtual_size`, `raw_size`, `entropy` (0–8, 2 decimals), `characteristics` (e.g. `["read", "execute"]`) |

### `imports`: Ahmed, FR6

| Key | Type | Meaning |
|---|---|---|
| `dll_count` | int | Number of imported DLLs |
| `function_count` | int | Total imported functions |
| `dlls` | object | DLL name → list of function names (imports by ordinal written as `"ordinal_123"`) |

### `packing_indicators`: Viha, FR5

| Key | Type | Meaning |
|---|---|---|
| `indicators` | list | One object per indicator: `name`, `value`, `threshold`, `triggered` (bool), `detail` |
| `triggered_count` | int | How many indicators fired |
| `signatures` | list | Packer signature matches, each `{"source": "diec", "match": "UPX(3.96)"}`; `[]` if none |

Suggested indicators to start with (from the literature review): section entropy, raw vs virtual size, entry point outside the first code section, number of imports, unusual section names. There is intentionally **no `is_packed`**: the indicators are the evidence, and the analyst decides.

### `virustotal`: Hassan, FR3

| Key | Type | Meaning |
|---|---|---|
| `found` | bool or null | Whether VirusTotal knows this SHA-256 (`null` if the lookup failed) |
| `detections` | int or null | Engines that flagged the file in VirusTotal's last analysis |
| `engines_total` | int or null | Engines in that analysis |
| `first_seen` | string or null | First submission date on VirusTotal, ISO 8601 |
| `last_analysis_date` | string or null | ISO 8601 |
| `threat_label` | string or null | VirusTotal's popular threat label (VirusTotal's opinion, reported as such) |
| `permalink` | string or null | Link to the VirusTotal page for the hash |
| `source` | `"live"`, `"cache"`, `"mock"` | Where the answer came from (mock mode lets us work without an API key) |

These are facts *about VirusTotal's results*, credited to VirusTotal: "41 of 72 VirusTotal engines flag this hash" is a fact; "the file is malicious" is not.

## Full example report

The values are placeholders that show the layout. They are not real data.

```json
{
  "schema_version": "0.2",
  "sample": {
    "file_name": "invoice.exe",
    "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
    "file_size": 245760,
    "received_at": "2026-10-22T16:30:00Z"
  },
  "tool_calls": ["hashes", "file_type", "sections", "imports", "packing_indicators", "virustotal"],
  "results": {
    "hashes": {
      "tool": "hashes", "tool_version": "0.1", "status": "ok",
      "data": {
        "md5": "00000000000000000000000000000000",
        "sha1": "0000000000000000000000000000000000000000",
        "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
      },
      "warnings": [], "error": null, "duration_ms": 3
    },
    "file_type": {
      "tool": "file_type", "tool_version": "0.1", "status": "ok",
      "data": {
        "description": "Windows PE executable", "is_pe": true, "machine": "x86",
        "is_dll": false, "subsystem": "windows_gui", "compile_timestamp": "2019-03-14T08:21:55Z"
      },
      "warnings": [], "error": null, "duration_ms": 9
    },
    "sections": {
      "tool": "sections", "tool_version": "0.1", "status": "ok",
      "data": {
        "section_count": 2,
        "sections": [
          {"name": "UPX0", "virtual_address": 4096, "virtual_size": 155648, "raw_size": 0,
           "entropy": 0.0, "characteristics": ["read", "write", "execute"]},
          {"name": "UPX1", "virtual_address": 159744, "virtual_size": 86016, "raw_size": 85504,
           "entropy": 7.91, "characteristics": ["read", "write", "execute"]}
        ]
      },
      "warnings": [
        "Section UPX1 has entropy 7.91",
        "Section UPX0 has raw size 0 and virtual size 155648",
        "Both sections are writable and executable"
      ],
      "error": null, "duration_ms": 14
    },
    "imports": {
      "tool": "imports", "tool_version": "0.1", "status": "ok",
      "data": {
        "dll_count": 1, "function_count": 5,
        "dlls": {"kernel32.dll": ["LoadLibraryA", "GetProcAddress", "VirtualProtect", "VirtualAlloc", "ExitProcess"]}
      },
      "warnings": ["Only 5 functions are imported, from 1 DLL"],
      "error": null, "duration_ms": 11
    },
    "packing_indicators": {
      "tool": "packing_indicators", "tool_version": "0.1", "status": "ok",
      "data": {
        "indicators": [
          {"name": "max_section_entropy", "value": 7.91, "threshold": 7.2, "triggered": true,
           "detail": "Highest section entropy (UPX1)"},
          {"name": "raw_vs_virtual_size", "value": 0, "threshold": null, "triggered": true,
           "detail": "UPX0 has raw size 0 but virtual size 155648"},
          {"name": "import_count", "value": 5, "threshold": 10, "triggered": true,
           "detail": "Fewer imported functions than the threshold"}
        ],
        "triggered_count": 3,
        "signatures": [{"source": "diec", "match": "UPX(3.96)"}]
      },
      "warnings": ["3 packing indicators triggered", "Detect It Easy matched UPX(3.96)"],
      "error": null, "duration_ms": 120
    },
    "virustotal": {
      "tool": "virustotal", "tool_version": "0.1", "status": "ok",
      "data": {
        "found": true, "detections": 41, "engines_total": 72,
        "first_seen": "2024-05-02T10:11:12Z", "last_analysis_date": "2026-10-01T09:00:00Z",
        "threat_label": "trojan.example/placeholder",
        "permalink": "https://www.virustotal.com/gui/file/0000000000000000000000000000000000000000000000000000000000000000",
        "source": "mock"
      },
      "warnings": ["41 of 72 VirusTotal engines flag this hash"],
      "error": null, "duration_ms": 2
    }
  }
}
```

## Where the code lives

| Path | Owner | Contents |
|---|---|---|
| `src/malworn/contract.py` | Saood | `ToolSpec`, `ToolResult`, `ok/failure/skipped`, `run_tool`, `validate`, `new_report`, `add_result` |
| `src/malworn/static_analysis/` | Ahmed | `hashes`, `file_type`, `sections`, `imports` (one module each, each with `SPEC` + `run`) |
| `src/malworn/packing/` | Viha | `packing_indicators` |
| `src/malworn/detection/` | Hassan | `virustotal`, and the report builder |
| `src/malworn/agent/` | Saood | Tool list, agent loop, prompts, Ollama client |

Every tool's tests should include `assert validate(run(path), SPEC) == []` on a benign file and on a UPX-packed copy.

## Where things run

The sample, the tools and the agent loop all run **inside the analysis VM**. The agent sends only text (tool descriptions, tool results, its own messages) to the model on the Windows host through Ollama's API on the host-only network. Reports and run logs leave the VM as `.json`/`.md` files only, never samples.

## Changes from v0.1

v0.1 (Oct 20) described a fixed pipeline in which every module always ran and each added its own report section. It was never merged, and it conflicted with Deliverable 1:

| v0.1 | v0.2 | Why |
|---|---|---|
| Fixed pipeline, every module always runs | The agent chooses which tools to call | FR9, Meeting 1 ("an agent, not a chatbot") |
| `detection.verdict: "malicious"` from an ML model | No verdict anywhere; VirusTotal lookup instead | FR7, Meeting 1 ("not a binary verdict"); Hassan's role is VirusTotal + aggregation |
| `packing.is_packed` as "final decision" | Indicators side by side, no decision | FR5 |
| One section per module (`static_analysis`, `packing`, `detection`) | One `ToolResult` per tool, same shape for all | NFR7, NFR8: every fact credited to a tool; new tools need no new format |

Kept from v0.1: every key always present, a `status` on everything, errors don't stop the analysis, the sample is identified by SHA-256, and only JSON leaves the VM.

## Open questions for the team

- **Ahmed:** do the keys for `hashes`, `file_type`, `sections` and `imports` match what your code returns? Your current functions return plain values; each needs a `SPEC` and a `run()` that wraps it with `ok()` (see the example above).
- **Viha:** are the starting indicators and the `indicators` shape right for your approach? Which thresholds do you want to start with?
- **Hassan:** are the `virustotal` keys the fields you need from the API? Should the folder be renamed from `detection/` to `threat_intel/` to match what it holds?
- **All:** is anything missing that the agent would need to explain a result to an analyst?
