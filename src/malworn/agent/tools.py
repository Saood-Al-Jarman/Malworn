"""The tools the agent can offer to the model.

Owner: Saood

Each tool is a module with a SPEC (malworn.contract.ToolSpec) and a
run(file_path). To add a tool, add its module path to TOOL_MODULES; nothing
else in the agent changes (NFR8). A module that doesn't exist yet (e.g. a
teammate's tool that isn't merged) is skipped, so the list can name tools
before they're built.
"""

import importlib

from malworn.contract import ToolSpec, tool_catalogue

# The order the model sees them in, roughly the order an analyst works in.
TOOL_MODULES = [
    "malworn.static_analysis.hashes",
    "malworn.static_analysis.file_type",
    "malworn.packing.packing_indicators",
    "malworn.packing.packer_signatures",
    "malworn.static_analysis.sections",
    "malworn.static_analysis.imports",
    "malworn.static_analysis.strings",
    "malworn.static_analysis.extra_checks",
    "malworn.static_analysis.version_info",
    "malworn.detection.virustotal",         # Hassan, not built yet
]

# Temporary SPECs for tools whose module doesn't define one yet. A SPEC in the
# tool's own module always wins; delete an entry here once its owner adds one.
FALLBACK_SPECS = {
    "malworn.static_analysis.hashes": ToolSpec(
        name="hashes",
        description="Compute the MD5, SHA-1 and SHA-256 hashes of the file.",
        data_keys=("md5", "sha1", "sha256"),
        requirement="FR2", owner="Ahmed",
    ),
    "malworn.static_analysis.file_type": ToolSpec(
        name="file_type",
        description="Identify the file type from its header, e.g. whether it is a valid Windows PE executable.",
        data_keys=("description",),
        requirement="FR4", owner="Ahmed",
    ),
    "malworn.static_analysis.sections": ToolSpec(
        name="sections",
        description=("List the PE sections with each section's name, virtual address, virtual size, "
                     "raw size and entropy. Only works on Windows PE files."),
        data_keys=("sections",),
        requirement="FR4", owner="Ahmed",
    ),
    "malworn.static_analysis.imports": ToolSpec(
        name="imports",
        description=("List the DLLs the PE file imports and the API functions it imports from each, "
                     "including delay-loaded imports. Only works on Windows PE files."),
        data_keys=("dll_count", "function_count", "dlls"),
        requirement="FR6", owner="Ahmed",
    ),
    "malworn.static_analysis.strings": ToolSpec(
        name="strings",
        description=("Extract readable ASCII and UTF-16 strings (4+ characters) from the file, "
                     "such as URLs, file paths, registry keys and messages."),
        data_keys=("string_count", "strings"),
        requirement="FR4", owner="Ahmed",
    ),
    "malworn.static_analysis.extra_checks": ToolSpec(
        name="extra_checks",
        description=("Check whether the PE file has an overlay (data appended after the last section) "
                     "and its size, and compute the imphash, a fingerprint of the import list that "
                     "can link related samples. Only works on Windows PE files."),
        data_keys=("has_overlay", "overlay_size", "imphash"),
        requirement="FR4", owner="Ahmed",
    ),
    "malworn.static_analysis.version_info": ToolSpec(
        name="version_info",
        description=("Read the PE file's version resource (company, product, description, version), "
                     "count its embedded resources, and report whether a digital signature is present "
                     "(presence only; the signature is not verified). Only works on Windows PE files."),
        data_keys=("version_info", "resource_count", "has_signature"),
        requirement="FR4", owner="Ahmed",
    ),
    "malworn.packing.packing_indicators": ToolSpec(
        name="packing_indicators",
        description=("Measure packing and obfuscation indicators (entropy, section layout, section names, "
                     "entry point, imports, Detect It Easy) for the file and each section, with every piece "
                     "of evidence for and against packing, a score, and whether the imports and strings "
                     "can be trusted. Only works on Windows PE files."),
        data_keys=("summary", "final_assessment", "packing_level", "needs_unpacking", "score",
                   "static_evidence_reliability", "packer_classification", "per_section",
                   "evidence_for", "evidence_weak", "counter_evidence", "observations",
                   "high_entropy_regions", "checks_run", "thresholds_used", "message_for_analyst"),
        requirement="FR5", owner="Viha",
    ),
    "malworn.packing.packer_signatures": ToolSpec(
        name="packer_signatures",
        description=("Look for signatures that name a packer: Detect It Easy results, known packer section "
                     "names (like UPX0), byte patterns at the entry point, and local YARA rules."),
        data_keys=("detect_it_easy", "pe_checks", "section_name_matches", "bundled_signature_matches",
                   "suspected_packers", "local_yara", "final_assessment", "summary"),
        requirement="FR5", owner="Viha",
    ),
}

# Some tools return more than the model needs in order to reason. For these,
# the model is sent only the listed keys (the report still keeps everything).
# packing_indicators: message_for_analyst repeats evidence_for as prose, and the
# thresholds, weak evidence and entropy regions add length without changing
# what the model should say.
MODEL_VIEWS = {
    "packing_indicators": ("summary", "packing_level", "score", "needs_unpacking",
                           "static_evidence_reliability", "packer_classification", "per_section",
                           "evidence_for", "counter_evidence", "checks_run"),
}


class Tool:
    """A loaded tool: its SPEC and its run function."""

    def __init__(self, spec, run, module):
        self.spec = spec
        self.run = run
        self.module = module
        self.model_keys = MODEL_VIEWS.get(spec.name)

    @property
    def name(self):
        return self.spec.name

    def ollama_definition(self):
        """The tool as Ollama's /api/chat expects it. Tools take no arguments:
        the agent always supplies the file (data-format rule 6)."""
        return {
            "type": "function",
            "function": {
                "name": self.spec.name,
                "description": self.spec.description,
                "parameters": {"type": "object", "properties": {}, "required": []},
            },
        }


def load_tools(module_names=None):
    """Import every available tool. Returns (tools, skipped) where skipped is a
    list of (module, reason) for modules that couldn't be used."""
    tools, skipped = [], []
    for module_name in module_names or TOOL_MODULES:
        try:
            module = importlib.import_module(module_name)
        except ModuleNotFoundError as exc:
            if exc.name and module_name.startswith(exc.name):
                skipped.append((module_name, "not built yet"))
                continue
            raise
        spec = getattr(module, "SPEC", None) or FALLBACK_SPECS.get(module_name)
        run = getattr(module, "run", None)
        if spec is None:
            skipped.append((module_name, "no SPEC"))
            continue
        if not callable(run):
            skipped.append((module_name, "no run() function"))
            continue
        tools.append(Tool(spec, run, module_name))
    tool_catalogue([t.spec for t in tools])  # raises on duplicate names
    return tools, skipped
