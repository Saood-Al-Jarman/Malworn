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

# Order matters only for display: it's the order the model sees.
TOOL_MODULES = [
    "malworn.static_analysis.hashes",
    "malworn.static_analysis.file_type",
    "malworn.static_analysis.sections",
    "malworn.static_analysis.imports",
    "malworn.static_analysis.strings",
    "malworn.packing.packing_indicators",   # Viha, not built yet
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
}


class Tool:
    """A loaded tool: its SPEC and its run function."""

    def __init__(self, spec, run, module):
        self.spec = spec
        self.run = run
        self.module = module

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
