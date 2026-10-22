from malworn.static_analysis.file_type import identify_file_type
from pathlib import Path
import os
import pytest

def test_pdf_detection(tmp_path):
    file = tmp_path / "sample.bin"
    file.write_bytes(b"%PDF-1.7\nTest content")

    assert identify_file_type(file) == "PDF document"


def test_png_detection(tmp_path):
    file = tmp_path / "image.bin"
    file.write_bytes(b"\x89PNG\r\n\x1a\nTest content")

    assert identify_file_type(file) == "PNG image"


def test_zip_detection(tmp_path):
    file = tmp_path / "archive.bin"
    file.write_bytes(b"PK\x03\x04Test content")

    assert identify_file_type(file) == "ZIP archive"


def test_unknown_file(tmp_path):
    file = tmp_path / "unknown.bin"
    file.write_bytes(b"Hello Malworn")

    assert identify_file_type(file) == "Unknown file type"

@pytest.mark.skipif(
    os.name != "nt",
    reason="This test requires Windows"
)
def test_windows_pe_detection():
    notepad = Path(os.environ["WINDIR"]) / "System32" / "notepad.exe"

    assert identify_file_type(notepad) == "Windows PE executable"

def test_invalid_pe_detection(tmp_path):
    test_file = tmp_path / "fake.exe"
    test_file.write_bytes(b"MZ" + b"\x00" * 100)

    assert identify_file_type(test_file) == "MZ file (not a valid PE)"