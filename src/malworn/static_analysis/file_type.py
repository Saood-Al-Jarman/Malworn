# AI assistance: ChatGPT, October 2026. Used for: implementing file type identification using file signatures and PE format validation. Reviewed and tested by Ahmed.
from pathlib import Path
import pefile


def identify_file_type(file_path):
    path = Path(file_path)

    with path.open("rb") as file:
        header = file.read(8)

    if header.startswith(b"MZ"):
        try:
            pe = pefile.PE(str(path), fast_load=True)
            try:
                return "Windows PE executable"
            finally:
                pe.close()
        except pefile.PEFormatError:
            return "MZ file (not a valid PE)"

    if header.startswith(b"%PDF-"):
        return "PDF document"

    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG image"

    if header.startswith(b"PK\x03\x04"):
        return "ZIP archive"

    return "Unknown file type"