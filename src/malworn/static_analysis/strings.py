
# AI assistance: ChatGPT, October 2026. Used for: implementing static string extraction. Reviewed and tested by Ahmed.

import re
from pathlib import Path


MIN_STRING_LENGTH = 4


def analyze_strings(file_path, min_length=MIN_STRING_LENGTH):
    """Extract readable ASCII and UTF-16LE strings from a file."""
    if min_length < 1:
        raise ValueError("min_length must be at least 1")

    data = Path(file_path).read_bytes()

    ascii_pattern = rb"[\x20-\x7e]{" + str(min_length).encode() + rb",}"
    unicode_pattern = (
        rb"(?:[\x20-\x7e]\x00){" + str(min_length).encode() + rb",}"
    )

    ascii_strings = [
        match.decode("ascii")
        for match in re.findall(ascii_pattern, data)
    ]

    unicode_strings = [
        match[::2].decode("ascii")
        for match in re.findall(unicode_pattern, data)
    ]

    # Preserve order and avoid duplicate strings.
    strings = list(dict.fromkeys(ascii_strings + unicode_strings))

    return {
        "string_count": len(strings),
        "strings": strings,
    }
