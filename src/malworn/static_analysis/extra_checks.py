import pefile


def analyze_extra_checks(file_path):
    """Compute overlay size and import hash (imphash) for a Windows PE file."""
    pe = pefile.PE(str(file_path), fast_load=True)

    try:
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )

        overlay_offset = pe.get_overlay_data_start_offset()
        if overlay_offset is None:
            overlay_size = 0
            has_overlay = False
        else:
            overlay_size = len(pe.__data__) - overlay_offset
            has_overlay = overlay_size > 0

        imphash = pe.get_imphash()

        return {
            "has_overlay": has_overlay,
            "overlay_size": overlay_size,
            "imphash": imphash if imphash else None,
        }
    finally:
        pe.close()


def run(file_path):
    """Wrap analyze_extra_checks as an aggregator-ready tool result."""
    try:
        data = analyze_extra_checks(file_path)
    except Exception as exc:
        return {
            "tool": "extra_checks",
            "status": "failure",
            "error": f"{type(exc).__name__}: {exc}",
        }
    return {
        "tool": "extra_checks",
        "status": "success",
        "data": data,
    }