import pefile

# Common version-resource fields worth surfacing to an analyst.
VERSION_FIELDS = (
    "CompanyName",
    "FileDescription",
    "FileVersion",
    "InternalName",
    "OriginalFilename",
    "ProductName",
    "ProductVersion",
    "LegalCopyright",
)


def analyze_version_info(file_path):
    """Extract version info, resource summary, and digital signature presence
    from a Windows PE file. Does not validate the signature, only reports
    whether a certificate table is present.
    """
    pe = pefile.PE(str(file_path), fast_load=True)

    try:
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
        )

        version_info = {}
        if hasattr(pe, "FileInfo"):
            for file_info_list in pe.FileInfo:
                for entry in file_info_list:
                    if hasattr(entry, "StringTable"):
                        for string_table in entry.StringTable:
                            for key, value in string_table.entries.items():
                                key = key.decode() if isinstance(key, bytes) else key
                                value = (
                                    value.decode() if isinstance(value, bytes) else value
                                )
                                if key in VERSION_FIELDS:
                                    version_info[key] = value

        resource_count = 0
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            resource_count = sum(
                len(entry.directory.entries)
                for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries
                if hasattr(entry, "directory")
            )

        security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ]
        has_signature = security_dir.Size > 0

        return {
            "version_info": version_info,
            "resource_count": resource_count,
            "has_signature": has_signature,
        }
    finally:
        pe.close()


def run(file_path):
    """Wrap analyze_version_info as an aggregator-ready tool result."""
    try:
        data = analyze_version_info(file_path)
    except Exception as exc:
        return {
            "tool": "version_info",
            "status": "failure",
            "error": f"{type(exc).__name__}: {exc}",
        }
    return {
        "tool": "version_info",
        "status": "success",
        "data": data,
    }