# AI assistance: Claude (Anthropic), October 2026. Used for: wrapping signature-based packer detection as an aggregator-ready tool. To be reviewed and tested by Viha.
"""Tool `packer_signatures`: signature evidence for packers. Detect It Easy runs FIRST.

Contract (same as malworn.static_analysis.*): run(file_path) -> dict with
tool / status / data (and warnings, error, provenance keys the aggregator accepts).
Reports signature evidence only: DIE detections, section-name matches, bundled
byte signatures and optional local YARA rules. It issues no malware verdict.
"""
import time

from malworn.packing import die, indicators

TOOL = "packer_signatures"


def make_summary(data, final):
    d = data["detect_it_easy"]
    if d.get("ran"):
        found = [f"{x['name']} {x['version']}".strip() for x in d["packers"] if x["name"] != "Generic"]
        die_txt = "Detect It Easy ran first: " + (", ".join(found) if found else "no packer named") + "."
    else:
        die_txt = "Detect It Easy was NOT run."
    names = ", ".join(sorted({m["section"] for m in data["section_name_matches"]})) or "none"
    sigs_ = ", ".join(m["signature"] for m in data["bundled_signature_matches"] if m["severity"] != "low") or "none"
    return (f"{die_txt} Packer-named sections: {names}. Bundled signature matches: {sigs_}. "
            f"Final: {final['label']}." if final else f"{die_txt} Packer-named sections: {names}. "
            f"Bundled signature matches: {sigs_}.")


def run(file_path):
    t0 = time.time()
    try:
        data = indicators.signature_report(str(file_path))     # DIE runs first inside
    except Exception as exc:  # noqa: BLE001
        return {"tool": TOOL, "status": "failure", "error": f"{type(exc).__name__}: {exc}"}
    final = None
    if data["pe_checks"] == "run":                       # full engine (DIE result is cached, not re-run)
        try:
            final = indicators.analyze(str(file_path))["final_assessment"]
        except Exception:  # noqa: BLE001
            final = None
    data["final_assessment"] = final
    data["summary"] = make_summary(data, final)
    warnings = []
    d = data["detect_it_easy"]
    if not d.get("ran"):
        warnings.append(f"Detect It Easy was NOT run: {d.get('error')}")
    if data["pe_checks"] != "run":
        warnings.append(f"PE signature checks {data['pe_checks']}")
    if not data["local_yara"].get("used"):
        data["local_yara"] = {k: v for k, v in data["local_yara"].items() if k != "matches"} | {"matches": []}
    return {"tool": TOOL, "status": "success", "data": data, "warnings": warnings,
            "provenance": {"tool_version": indicators.TOOL_VERSION, "source": "malworn.packing",
                           "duration_ms": int((time.time() - t0) * 1000)}}
