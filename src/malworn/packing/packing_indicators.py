# AI assistance: Claude (Anthropic), October 2026. Used for: wrapping packing/obfuscation indicator analysis as an aggregator-ready tool. To be reviewed and tested by Viha.
"""Tool `packing_indicators`: is the file (and which sections) packed, with evidence.

Contract (same as malworn.static_analysis.*): run(file_path) -> dict with
tool / status / data. Detect It Easy runs FIRST (cached), before every other
check, and its findings are part of the evidence. Detection only: the tool never
unpacks. It issues no malware verdict (packing is common in benign software).

Shape notes for the report generator: `data["per_section"]` rows carry
name / raw_size / virtual_size / entropy (rendered as the Sections table); all
other per-section fields appear as additional fields. Section facts such as
virtual addresses and imports are reported by the `sections` and `imports` tools,
so they are not repeated here.
"""
import time

from malworn.packing import indicators

TOOL = "packing_indicators"


def make_summary(r):
    """One short deterministic line for the analyst (the tool summary)."""
    f = r["final_assessment"]
    flagged = ", ".join(f"{s['name']} ({s['level']})" for s in r["packed_sections"]) or "none"
    pk = r["packer_classification"]
    pk_txt = (f"{pk['status']}" + (f" ({pk['packer']})" if pk.get("packer") else ""))
    return (f"Final: {f['label']}. Level {r['packing_indicators_level']} (score {r['score']}). "
            f"Sections that look packed: {flagged}. Packer: {pk_txt}.")


def to_data(r):
    """Reshape the engine output into the aggregator-friendly `data` object."""
    assess = {a["index"]: a for a in r["section_assessments"]}
    per_section = [{"name": s["name"], "raw_size": s["raw_size"], "virtual_size": s["virtual_size"],
                    "entropy": s["entropy"], "permissions": s["perms"],
                    "packing_level": assess[s["index"]]["level"], "packing_points": assess[s["index"]]["points"],
                    "packing_evidence_ids": assess[s["index"]]["reasons"]} for s in r["sections"]]
    observations = [{"id": i["id"], "value": i["value"], "location": i["location"]}
                    for i in r["indicators"] if i["points"] == 0 and i["severity"] == "info"]
    return {
        "summary": make_summary(r),
        "final_assessment": r["final_assessment"],
        "packing_level": r["packing_indicators_level"],
        "needs_unpacking": r["needs_unpacking"],
        "score": r["score"],
        "static_evidence_reliability": r["static_evidence_reliability"],
        "packer_classification": r["packer_classification"],
        "per_section": per_section,
        "evidence_for": r["evidence_for"],
        "evidence_weak": r["evidence_weak"],
        "counter_evidence": r["counter_evidence"],
        "observations": observations,
        "high_entropy_regions": [{k: v for k, v in g.items() if k != "section_indexes"}
                                 for g in r["high_entropy_regions"]],
        "checks_run": r["optional_checks"],
        "thresholds_used": r["thresholds_used"],
        "message_for_analyst": r["user_message"],
    }


def run(file_path):
    t0 = time.time()
    try:
        r = indicators.analyze(str(file_path))                  # DIE runs first inside
    except Exception as exc:  # noqa: BLE001
        return {"tool": TOOL, "status": "failure", "error": f"{type(exc).__name__}: {exc}"}
    prov = {"tool_version": indicators.TOOL_VERSION, "source": "malworn.packing",
            "duration_ms": int((time.time() - t0) * 1000)}
    if "error" in r:       # e.g. not a valid PE: not applicable, not a tool failure
        return {"tool": TOOL, "status": "skipped", "data": {"reason": r["error"], "detail": r.get("detail")},
                "warnings": [f"packing checks not applicable: {r['error']}"], "provenance": prov}
    warnings = []
    die_info = r["optional_checks"]["detect_it_easy"]
    if not die_info.get("ran"):
        warnings.append(f"Detect It Easy was NOT run: {die_info.get('error')}")
    if not r["optional_checks"]["instruction_structure"].get("ran"):
        warnings.append("Instruction-structure check not run: "
                        + str(r["optional_checks"]["instruction_structure"].get("reason")))
    return {"tool": TOOL, "status": "success", "data": to_data(r), "warnings": warnings, "provenance": prov}
