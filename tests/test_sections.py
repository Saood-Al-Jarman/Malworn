import os
from pathlib import Path
from malworn.static_analysis.sections import run

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

@pytest.mark.skipif(os.name != "nt", reason="Requires Windows")
def test_run_wraps_success_on_real_pe():
    notepad = Path(os.environ["WINDIR"]) / "System32" / "notepad.exe"

    result = run(notepad)

    assert result["tool"] == "sections"
    assert result["status"] == "success"
    assert len(result["data"]["sections"]) > 0

    for section in result["data"]["sections"]:
        assert isinstance(section["name"], str)
        assert 0 <= section["entropy"] <= 8
        
def test_run_wraps_invalid_file_as_failure(tmp_path):
    sample = tmp_path / "invalid.exe"
    sample.write_bytes(b"not a valid Windows executable")

    result = run(sample)

    assert result["tool"] == "sections"
    assert result["status"] == "failure"
    assert "error" in result