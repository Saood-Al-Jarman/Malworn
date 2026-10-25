
# AI assistance: ChatGPT, October 2026. Used for: implementing PE import analysis with pefile. Reviewed and tested by Ahmed.

import pefile


def analyze_imports(file_path):
    """Extract imported DLLs and API functions from a Windows PE file."""
    pe = pefile.PE(str(file_path), fast_load=True)
    
    try:
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
            ]
        )

        dlls = []
        function_count = 0

        all_imports = list(getattr(pe, "DIRECTORY_ENTRY_IMPORT", []))
        all_imports.extend(getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", []))

        for entry in all_imports:
            dll_name = entry.dll.decode("utf-8", errors="replace")

            # Preserve the DLL name and collect its imported functions.
            functions = []
            for imported_function in entry.imports:
                if imported_function.name is not None:
                    function_name = imported_function.name.decode(
                        "utf-8", errors="replace"
                    )
                else:
                    function_name = f"ordinal_{imported_function.ordinal}"

                functions.append(function_name)

            dlls.append({
                "dll": dll_name,
                "functions": functions,
            })
            function_count += len(functions)

        return {
            "dll_count": len(dlls),
            "function_count": function_count,
            "dlls": dlls,
        }
    finally:
        pe.close()

def run(file_path):
    """Wrap analyze_imports as an aggregator-ready tool result."""
    try:
        data = analyze_imports(file_path)
    except Exception as exc:
        return {
            "tool": "imports",
            "status": "failure",
            "error": f"{type(exc).__name__}: {exc}",
        }
    return {
        "tool": "imports",
        "status": "success",
        "data": data,
    }
