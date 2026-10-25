# AI assistance: ChatGPT, October 2026. Used for: implementing PE section analysis to extract section names, virtual addresses, sizes, and entropy. Reviewed and tested by Ahmed.
import pefile


def analyze_sections(file_path):
    pe = pefile.PE(str(file_path), fast_load=True)

    try:
        sections = []

        for section in pe.sections:
            section_info = {
                "name": section.Name.split(b"\x00")[0].decode(
                    "utf-8", errors="replace"
                ),
                "virtual_address": section.VirtualAddress,
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": round(section.get_entropy(), 2),
            }

            sections.append(section_info)

        return sections

    finally:
        pe.close()

def run(file_path):
    """Wrap analyze_sections as an aggregator-ready tool result."""
    try:
        data = analyze_sections(file_path)
    except Exception as exc:
        return {
            "tool": "sections",
            "status": "failure",
            "error": f"{type(exc).__name__}: {exc}",
        }
    return {
        "tool": "sections",
        "status": "success",
        "data": {"sections": data},
    }