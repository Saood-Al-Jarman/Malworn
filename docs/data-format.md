# Malworn Data Format

**Version:** 0.3.1 (draft, open for team review)
**Owner:** Saood
**Code:** [`src/malworn/contract.py`](../src/malworn/contract.py) (what tools return) and Hassan's [`src/malworn/detection/malworn_aggregator.py`](../src/malworn/detection/malworn_aggregator.py) (the report). `tests/test_contract.py` checks this document against both, so if the doc and the code disagree, the tests fail.

This document defines what every Malworn tool returns, what the agent hands to the aggregator, and what the final report looks like. v0.3 describes the code that already exists (Ahmed's five tools and Hassan's aggregator) instead of asking anyone to rewrite it.

## The design in one paragraph

Malworn is an **agent, not a chatbot** (Meeting 1): the model *chooses and calls tools* (FR9), each tool is a normal Python script that reads the file and returns **facts**, and the model explains those facts to the analyst. The model never reads the file itself and never decides whether the file is malicious. The report contains the full evidence with **no malicious/benign verdict** (FR7), and every fact is credited to the tool that produced it (NFR4, NFR7).

```
analyst uploads file (FR1)
        │
        ▼
┌──────────────────── agent loop (Saood) ────────────────────┐
│ model sees the tool catalogue (each SPEC's name + description)│
│ model picks a tool ──► run_tool(SPEC, run, path) ──► result  │
│ model sees the result, picks the next tool or stops          │
└──────────────────────────────────────────────────────────────┘
        │  agent run: file info + selected tools + all results + explanation
        ▼
aggregator (Hassan) ──► aggregated report.json ──► report_generator ──► HTML / PDF
                                               └─► web page (FR10) + follow-up chat
```

## Rules

1. **Tools report facts, never verdicts.** A tool says "section UPX1 has entropy 7.91", not "the file is packed" or "suspicious". The words *malicious, benign, safe, clean, suspicious, harmless, infected* are not allowed in a tool's `warnings`; `validate()` rejects them. The agent explains why a fact matters (FR7).
2. **Every tool module has a `SPEC` and a `run(file_path)`.** The `SPEC` (a `ToolSpec`) gives the tool's name, a description the model reads when choosing tools, and its data keys. Without a `SPEC` the agent can't offer the tool to the model.
3. **`run()` returns a result dict** with `tool`, `status` (`"success"`, `"failure"` or `"skipped"`), `data`, `warnings` and `error`. Ahmed's existing `run()` functions already do this; they only need `"warnings": []` added.
4. **Every data key is always present on success.** A tool's keys are fixed in its `SPEC`. Unknown values are `null`; keys not in the `SPEC` are rejected, so the code and this document can't drift apart.
5. **A tool never crashes the analysis.** The agent runs tools through `run_tool()`, which turns any exception into a `"failure"` result. The aggregator shows a failed tool as "not available" and the analysis continues.
6. **The model never chooses which file a tool reads.** Tools take only `file_path`, supplied by the agent. The model picks *which* tool, not *what* it runs on.
7. **Text from the sample is untrusted (NFR3).** Strings, section names, DLL names and names from VirusTotal can contain anything, including text written to trick the model. Tools copy it as data and never act on it; the agent treats it as data, not instructions; the report generator escapes it in HTML.
8. **Packing is shown as indicators, never as a decision (FR5).** Legitimate software is often packed too (ViPER: 73% of benign samples), so there is no `is_packed` field.
9. **Only hashes leave the machine (FR3, NFR2).** The VirusTotal tool looks up the SHA-256; the sample is never uploaded anywhere.
10. **Changing this format needs a pull request** that updates this document and the code together, reviewed by someone other than the author.

## Tool result

What `run()` returns (after `run_tool()` has filled in timing and the call ID):

```json
{
  "tool": "sections",
  "status": "success",
  "data": { "sections": [ { "name": "UPX1", "entropy": 7.91, "...": "..." } ] },
  "warnings": [],
  "error": null,
  "tool_version": "0.1",
  "duration_ms": 14,
  "call_id": "call-003"
}
```

| Field | Type | Meaning |
|---|---|---|
| `tool` | string | The tool's name (snake_case), same as `SPEC.name`. Every fact is credited to it (NFR7). |
| `status` | `"success"`, `"failure"`, `"skipped"` | `skipped` = the tool doesn't apply to this file. (`"ok"`/`"error"` are accepted and converted.) |
| `data` | object | The facts. On success, every key from the tool's `SPEC` is present. Empty on failure. |
| `warnings` | list of strings | Facts worth the analyst's attention, phrased as observations. Never verdict words. `[]` if none. |
| `error` | string or null | Required on `failure`/`skipped`, `null` on success. |
| `tool_version` | string | From the `SPEC`; bumped when the tool's keys or their meaning change (NFR9). |
| `duration_ms` | int | Filled in by `run_tool()` (helps with the 60-second target, sub-objective O4). |
| `call_id` | string | Filled in by the agent; the aggregator numbers calls itself if it's missing. |

## `ToolSpec`: how a tool describes itself

Example for Ahmed's `hashes` tool. His `run()` stays as it is; only the `SPEC` and `"warnings": []` are added:

```python
from malworn.contract import ToolSpec

SPEC = ToolSpec(
    name="hashes",
    description="Compute the MD5, SHA-1 and SHA-256 hashes of the file.",
    data_keys=("md5", "sha1", "sha256"),
    requirement="FR2",
    owner="Ahmed",
)

def run(file_path):
    try:
        data = calculate_hashes(file_path)
    except Exception as exc:
        return {"tool": "hashes", "status": "failure", "error": f"{type(exc).__name__}: {exc}"}
    return {"tool": "hashes", "status": "success", "data": data, "warnings": []}
```

The `description` is what the model reads when deciding which tool to call, so write it for the model: what the tool returns, in one or two plain sentences.

In tests, check every tool with `assert validate(run(path), SPEC) == []`, on a benign file, a UPX-packed copy and a non-PE file.

Adding a new tool means adding a module with a `SPEC` and `run()`, and one line in the agent's tool list. The agent loop and the aggregator don't change (NFR8).

## Tool catalogue

The keys below are what each tool returns **today** (or, for tools not built yet, the proposal). `run_tool()` and the tests enforce them. "Planned" keys are agreed additions that are not required until a tool's `SPEC` lists them; they use the field names Hassan's report generator already displays.

### `hashes`: Ahmed, FR2, built

| Key | Type | Meaning |
|---|---|---|
| `md5` | string | MD5 hash |
| `sha1` | string | SHA-1 hash |
| `sha256` | string | SHA-256 hash |

### `file_type`: Ahmed, FR4, built

| Key | Type | Meaning |
|---|---|---|
| `description` | string | e.g. `"Windows PE executable"`, `"MZ file (not a valid PE)"`, `"PDF document"` |

Planned: `is_pe`, `architecture`, `is_dll`, `subsystem`, `compile_timestamp`.

### `sections`: Ahmed, FR4, built

| Key | Type | Meaning |
|---|---|---|
| `sections` | list | One object per section: `name`, `virtual_address`, `virtual_size`, `raw_size`, `entropy` (0–8, 2 decimals) |

Planned: `section_count`, `entry_point_section`, and per-section `characteristics` (e.g. `["read", "write", "execute"]`).

### `imports`: Ahmed, FR6, built

| Key | Type | Meaning |
|---|---|---|
| `dll_count` | int | Number of imported DLLs (normal + delay-loaded) |
| `function_count` | int | Total imported functions |
| `dlls` | list | One object per DLL: `dll` (name) and `functions` (list; imports by ordinal appear as `"ordinal_123"`) |

Planned: `imphash`.

### `strings`: Ahmed, FR4/FR6 support, built

| Key | Type | Meaning |
|---|---|---|
| `string_count` | int | Number of unique strings found (ASCII and UTF-16LE, length ≥ 4) |
| `strings` | list of strings | The strings, in file order, duplicates removed |

**Open issue:** a small benign 100 KB executable already gives 843 strings, so a real sample can give tens of thousands. That is too much to send to the model and is all untrusted text (rule 7). Proposed: cap the list (e.g. first 500, with `truncated: true`), and add grouped keys the agent can use directly: `urls`, `ips`, `file_paths`, `registry_keys`.

### `extra_checks`: Ahmed, FR4, built

| Key | Type | Meaning |
|---|---|---|
| `has_overlay` | bool | Whether there is data after the last section |
| `overlay_size` | int | Size of that data in bytes (0 if none) |
| `imphash` | string or null | Hash of the import list; samples built from the same code often share it |

### `version_info`: Ahmed, FR4, built

| Key | Type | Meaning |
|---|---|---|
| `version_info` | object | Version-resource fields that are present: `CompanyName`, `FileDescription`, `FileVersion`, `InternalName`, `OriginalFilename`, `ProductName`, `ProductVersion`, `LegalCopyright` |
| `resource_count` | int | Number of embedded resources |
| `has_signature` | bool | A signature block is present. It is **not** verified. |

### `packing_indicators`: Viha, FR5, built

Detect It Easy runs first (once per file, cached). On a file that isn't a PE, the tool returns `"skipped"` with the reason.

| Key | Type | Meaning |
|---|---|---|
| `summary` | string | One line: final assessment, level, score, sections that look packed, packer |
| `final_assessment` | object | `determination`, `confidence`, `label` (e.g. "PACKED (high confidence)"), `basis`, `caveat` |
| `packing_level` | string | `none_detected`, `possible` (score ≥ 3) or `likely` (score ≥ 6) |
| `needs_unpacking` | bool | True when the level is `possible` or `likely`: the analyst should unpack and re-upload |
| `score` | int | Total points from `evidence_for` |
| `static_evidence_reliability` | string | `normal` or `reduced`; reduced means imports and strings mostly come from the unpacking stub |
| `packer_classification` | object | `status` (`known_packer`, `known_packer_modified_variant`, `known_packer_weak`, `unknown_packer`, `none_detected`), `packer`, `why` |
| `per_section` | list | Per section: `name`, `raw_size`, `virtual_size`, `entropy`, `permissions`, `packing_level`, `packing_points`, `packing_evidence_ids` |
| `evidence_for` | list | Every indicator that adds points: `id`, `value`, `threshold`, `points`, `severity`, `location`, `why`, `source` |
| `evidence_weak` | list | Low-severity observations (0 points) |
| `counter_evidence` | list | What was checked and looked normal |
| `observations` | list | Information-only facts |
| `high_entropy_regions` | list | Byte ranges with high entropy, mapped onto sections or the overlay |
| `checks_run` | object | Which optional checks ran (Detect It Easy, instruction structure, YARA) and why not |
| `thresholds_used` | object | Every threshold, so results can be reproduced (NFR9) |
| `message_for_analyst` | string | All of the above as a readable report |

The agent sends the model a shorter view of this result (see `MODEL_VIEWS` in `agent/tools.py`); the report keeps all of it.

**Open question:** `final_assessment` gives a packed / not-packed headline with a confidence tier. Rule 8 says packing is shown as indicators, never as a decision (FR5). The team needs to agree whether the headline stays; the agent prompt tells the model to report it as the tool's assessment, with the evidence.

### `packer_signatures`: Viha, FR5, built

| Key | Type | Meaning |
|---|---|---|
| `detect_it_easy` | object | Whether Detect It Easy ran, and the packers, compilers and file type it found |
| `pe_checks` | string | `"run"`, or why the PE checks could not run (e.g. not a PE) |
| `section_name_matches` | list | Sections whose names match a known packer (e.g. `UPX0`) |
| `bundled_signature_matches` | list | Byte patterns matched at the entry point or elsewhere, with source and whether verified |
| `suspected_packers` | list | Packer names with the evidence that supports each |
| `local_yara` | object | Whether local YARA rules were used, and any matches |
| `final_assessment` | object or null | Same as in `packing_indicators`, when the PE checks ran |
| `summary` | string | One line for the analyst |

### `virustotal`: Hassan, FR3, not built yet (proposal)

| Key | Type | Meaning |
|---|---|---|
| `found` | bool or null | Whether VirusTotal knows this SHA-256 (`null` if the lookup failed) |
| `detections` | int or null | Engines that flagged the file in VirusTotal's last analysis |
| `engines_total` | int or null | Engines in that analysis |
| `first_seen` | string or null | First submission date on VirusTotal, ISO 8601 |
| `last_analysis_date` | string or null | ISO 8601 |
| `threat_label` | string or null | VirusTotal's popular threat label (VirusTotal's opinion, reported as such) |
| `permalink` | string or null | Link to the VirusTotal page for the hash |
| `source` | string | `"live"`, `"cache"` or `"mock"` (mock mode lets us work without an API key) |

These match the field names in Hassan's report generator. They are facts *about VirusTotal's results*, credited to VirusTotal: "41 of 72 VirusTotal engines flag this hash" is a fact; "the file is malicious" is not.

## The agent run: what the agent gives the aggregator

After the loop finishes, the agent builds one object and passes it to `aggregate_agent_run()`:

| Field | Meaning |
|---|---|
| `file` | `file_name`, `sha256` (64 hex characters), `file_size` |
| `available_tools` | Every tool in the catalogue |
| `selected_tools` | The tools the model chose, in order. Used to measure tool selection (sub-objective O3: the right tools in ≥90% of requests). |
| `tool_results` | One result per call, as above |
| `agent_explanation` | The model's explanation, kept separate from tool evidence |

### Example agent run

The values are placeholders that show the layout. They are not real data.

```json
{
  "file": {
    "file_name": "invoice.exe",
    "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
    "file_size": 245760
  },
  "available_tools": ["hashes", "file_type", "packing_indicators", "packer_signatures", "sections", "imports", "strings", "extra_checks", "version_info", "virustotal"],
  "selected_tools": ["hashes", "file_type", "sections", "imports", "extra_checks", "virustotal"],
  "tool_results": [
    {
      "tool": "hashes", "status": "success", "call_id": "call-001",
      "data": {
        "md5": "00000000000000000000000000000000",
        "sha1": "0000000000000000000000000000000000000000",
        "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
      },
      "warnings": [], "error": null, "tool_version": "0.1", "duration_ms": 3
    },
    {
      "tool": "file_type", "status": "success", "call_id": "call-002",
      "data": {"description": "Windows PE executable"},
      "warnings": [], "error": null, "tool_version": "0.1", "duration_ms": 9
    },
    {
      "tool": "sections", "status": "success", "call_id": "call-003",
      "data": {
        "sections": [
          {"name": "UPX0", "virtual_address": 4096, "virtual_size": 155648, "raw_size": 0, "entropy": 0.0},
          {"name": "UPX1", "virtual_address": 159744, "virtual_size": 86016, "raw_size": 85504, "entropy": 7.91}
        ]
      },
      "warnings": ["Section UPX1 has entropy 7.91", "Section UPX0 has raw size 0 and virtual size 155648"],
      "error": null, "tool_version": "0.1", "duration_ms": 14
    },
    {
      "tool": "imports", "status": "success", "call_id": "call-004",
      "data": {
        "dll_count": 1, "function_count": 5,
        "dlls": [{"dll": "KERNEL32.DLL", "functions": ["LoadLibraryA", "GetProcAddress", "VirtualProtect", "VirtualAlloc", "ExitProcess"]}]
      },
      "warnings": ["Only 5 functions are imported, from 1 DLL"],
      "error": null, "tool_version": "0.1", "duration_ms": 11
    },
    {
      "tool": "extra_checks", "status": "success", "call_id": "call-005",
      "data": {"has_overlay": false, "overlay_size": 0, "imphash": "00000000000000000000000000000000"},
      "warnings": [], "error": null, "tool_version": "0.1", "duration_ms": 6
    },
    {
      "tool": "virustotal", "status": "success", "call_id": "call-006",
      "data": {
        "found": true, "detections": 41, "engines_total": 72,
        "first_seen": "2024-05-02T10:11:12Z", "last_analysis_date": "2026-10-01T09:00:00Z",
        "threat_label": "trojan.example/placeholder",
        "permalink": "https://www.virustotal.com/gui/file/0000000000000000000000000000000000000000000000000000000000000000",
        "source": "mock"
      },
      "warnings": ["41 of 72 VirusTotal engines flag this hash"],
      "error": null, "tool_version": "0.1", "duration_ms": 2
    }
  ],
  "agent_explanation": null
}
```

This shortened example leaves out the packing tools, whose results are long (see the catalogue above); tools the model didn't call are listed by the aggregator under `not_selected_tools`.

## The report (Hassan's aggregator)

`aggregate_agent_run()` turns the agent run into the report. Main fields:

| Field | Meaning |
|---|---|
| `schema_version`, `analysis_id`, `generated_at` | Report metadata |
| `analysis_scope` | Always `"static_only"` |
| `file` | Copied from the agent run |
| `execution_summary` | `selected_tools`, `available_tools`, `not_selected_tools`, `missing_results` (selected but no result), `failed_calls`, counts, `total_facts` |
| `tool_results` | Each result, with `execution_status`, `display_status` (`"not_available"` for failures), `data`, `warnings`, `error`, `provenance`, and `facts` |
| `facts` (per result) | Every value in `data` as its own entry: `field_path` (e.g. `data["sections"][1]["entropy"]`), `value`, `source_tool`, `source_call_id` |
| `agent_commentary` | The model's explanation, marked `"agent_generated_not_tool_evidence"` |
| `notice` | States that the report contains tool outputs only and no verdict |

There is deliberately **no verdict field** anywhere. `report_generator.py` renders this report as HTML (and PDF with `reportlab`).

## Where the code lives

| Path | Owner | Contents |
|---|---|---|
| `src/malworn/contract.py` | Saood | `ToolSpec`, `ToolResult`, `success/failure/skipped`, `run_tool`, `validate`, `tool_catalogue` |
| `src/malworn/static_analysis/` | Ahmed | `hashes`, `file_type`, `sections`, `imports`, `strings`, `extra_checks`, `version_info` |
| `src/malworn/packing/` | Viha | `packing_indicators`, `packer_signatures` |
| `src/malworn/detection/` | Hassan | `virustotal`, the aggregator and the report generator |
| `src/malworn/agent/` | Saood | Tool list, agent loop, prompts, Ollama client |

## Where things run

The sample, the tools and the agent loop all run **inside the analysis VM**. The agent sends only text (tool descriptions, tool results, its own messages) to the model on the Windows host through Ollama's API on the host-only network. Reports leave the VM as `.json`/`.html`/`.pdf` files only, never samples.

## Changes

**v0.3.1 (Oct 29):** catalogue updated with the tools merged since: `extra_checks` and `version_info` (Ahmed), and the real keys of `packing_indicators` plus `packer_signatures` (Viha), replacing the earlier proposal. A `failure`/`skipped` result without an `error` now gets its reported reason as the error.

**v0.3 (Oct 26):** aligned with the code that was merged over the weekend.

| v0.2 | v0.3 | Why |
|---|---|---|
| Status `ok` / `error` / `skipped` | `success` / `failure` / `skipped` (`ok`/`error` still accepted) | Matches Ahmed's tools and Hassan's aggregator |
| My own report format (`tool_calls`, `results`) and `new_report`/`add_result` | Hassan's aggregator report; report helpers removed from `contract.py` | His format already has per-fact provenance and separates not-selected, missing and failed tools |
| Tools must return a `ToolResult` object | Plain dicts are fine; `run_tool()` normalises them | Ahmed's `run()` functions work as they are |
| Proposed keys (`section_count`, `imports` as a dict, ...) | The keys the tools actually return; extras listed as planned | The doc describes the real code |
| No `strings` tool | `strings` added, with the size issue noted | New tool from Ahmed |

**v0.2 (Oct 22, never merged):** replaced v0.1's fixed pipeline with tools chosen by the agent, removed the ML verdict and `is_packed`, and added `ToolSpec`.

## Open questions for the team

- **Ahmed:** can you add a `SPEC` and `"warnings": []` to your five tools (about 5 lines each, example above)? And what do you think of capping `strings` and grouping URLs, IPs, paths and registry keys?
- **Viha:** should `final_assessment` keep its packed / not-packed headline (see the open question under `packing_indicators`)? And can you check that `diec` runs in the VM?
- **Hassan:** are the `virustotal` keys right? Can you upload the missing `examples/mock_agent_run.json` (one aggregator test fails without it), and could the aggregator's `SCHEMA_VERSION` become `"0.3"` once this is agreed?
- **All:** is anything missing that the agent would need to explain a result to an analyst?
