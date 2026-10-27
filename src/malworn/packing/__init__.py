"""Packing and obfuscation detection.

Owner: Viha

Two aggregator-ready tools (same run(file_path) contract as static_analysis):
    packer_signatures   signature evidence; Detect It Easy runs FIRST
    packing_indicators  per-section packing evidence; Detect It Easy also runs first (cached)

Detect-only: nothing here unpacks or executes a sample.
"""
PACKING_TOOL_ORDER = ["packer_signatures", "packing_indicators"]


def tools():
    """name -> run() for the agent's tool registry (imported lazily)."""
    from malworn.packing import packer_signatures, packing_indicators
    return {"packer_signatures": packer_signatures.run, "packing_indicators": packing_indicators.run}


def run_packing_checks(file_path):
    """Run both packing tools in the required order; returns a list of tool results
    ready for malworn.detection.malworn_aggregator.aggregate_results()."""
    reg = tools()
    return [reg[name](file_path) for name in PACKING_TOOL_ORDER]


def packing_report(file_path):
    """Both tools in order + a summary per tool + the final packed / not-packed answer."""
    from malworn.packing.report import packing_report as _r
    return _r(file_path)
