import os
from pathlib import Path

import pefile
import pytest

from malworn.static_analysis.sections import analyze_sections


@pytest.mark.skipif(os.name != "nt", reason="Requires Windows")
def test_analyze_windows_executable():
    notepad = Path(os.environ["WINDIR"]) / "System32" / "notepad.exe"

    results = analyze_sections(notepad)

    assert len(results) > 0

    for section in results:
        assert isinstance(section["name"], str)
        assert isinstance(section["virtual_address"], int)
        assert isinstance(section["virtual_size"], int)
        assert isinstance(section["raw_size"], int)
        assert 0 <= section["entropy"] <= 8


def test_invalid_pe_file(tmp_path):
    fake_file = tmp_path / "fake.exe"
    fake_file.write_bytes(b"This is not a Windows executable")

    with pytest.raises(pefile.PEFormatError):
        analyze_sections(fake_file)