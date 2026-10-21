import pefile


def analyze_sections(file_path):
    pe = pefile.PE(str(file_path), fast_load=True)

    try:
        sections = []

        for section in pe.sections:
            section_info = {
                "name": section.Name.rstrip(b"\x00").decode(
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