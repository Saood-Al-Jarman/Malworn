# AI assistance: Claude (Anthropic), October 2026. Used for: a one-call packing report with a summary per tool and the final answer. To be reviewed and tested by Viha.
"""One call / one command: run both packing tools (Detect It Easy first), print a summary of
each tool and the FINAL packed / not-packed answer with its confidence tier.

    python -m malworn.packing.report sample.exe          # readable text
    python -m malworn.packing.report sample.exe --json   # full structured result
"""
import argparse
import json
import sys

from malworn import packing


def packing_report(file_path):
    """Returns {"tools": [results in order], "summaries": {tool: text}, "final": {...}, "text": str}."""
    results = packing.run_packing_checks(str(file_path))
    summaries, final = {}, None
    for r in results:
        data = r.get("data") or {}
        summaries[r["tool"]] = data.get("summary") or (r.get("warnings") or ["no summary"])[0]
        final = data.get("final_assessment") or final
    lines = [f"File: {file_path}", ""]
    for i, r in enumerate(results, 1):
        lines.append(f"[{i}] {r['tool']} ({r['status']}): {summaries[r['tool']]}")
        lines += [f"    warning: {w}" for w in r.get("warnings", [])]
    lines.append("")
    if final:
        lines.append(f"FINAL ANSWER: {final['label']}")
        lines += [f"  - {b}" for b in final["basis"]] + [f"  Note: {final['caveat']}"]
        if final["determination"] != "not_packed":
            lines.append("  Action: please unpack the sample and re-upload it for further analysis.")
    else:
        lines.append("FINAL ANSWER: not available (the file is not a valid PE; see warnings).")
    return {"tools": results, "summaries": summaries, "final": final, "text": "\n".join(lines)}


def main():
    ap = argparse.ArgumentParser(description="Malworn packing report (offline, detect-only)")
    ap.add_argument("file")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    rep = packing_report(a.file)
    print(json.dumps({k: rep[k] for k in ("tools", "summaries", "final")}, indent=2) if a.json else rep["text"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
