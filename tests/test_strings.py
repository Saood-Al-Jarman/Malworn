
import pytest

from malworn.static_analysis.strings import analyze_strings
from malworn.static_analysis.strings import run


def test_analyze_strings_extracts_ascii_strings(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x00CreateFileW\x00https://example.com\x00")

    result = analyze_strings(sample)

    assert result["string_count"] == 2
    assert "CreateFileW" in result["strings"]
    assert "https://example.com" in result["strings"]


def test_analyze_strings_extracts_utf16le_strings(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes("Software\\Example".encode("utf-16le"))

    result = analyze_strings(sample)

    assert "Software\\Example" in result["strings"]


def test_analyze_strings_removes_duplicates(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"CreateFileW\x00CreateFileW\x00")

    result = analyze_strings(sample)

    assert result["strings"].count("CreateFileW") == 1


def test_analyze_strings_rejects_invalid_min_length(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample text")

    with pytest.raises(ValueError):
        analyze_strings(sample, min_length=0)


def test_analyze_strings_respects_min_length(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"cat\x00house\x00elephant\x00")

    result = analyze_strings(sample, min_length=5)

    assert "cat" not in result["strings"]
    assert "house" in result["strings"]
    assert "elephant" in result["strings"]


def test_analyze_strings_count_matches_results(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"CreateFileW\x00ReadFile\x00")

    result = analyze_strings(sample)

    assert result["string_count"] == len(result["strings"])

def test_run_wraps_success(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"hello world this is a test file")

    result = run(sample)

    assert result["tool"] == "strings"
    assert result["status"] == "success"
    assert result["data"]["string_count"] == len(result["data"]["strings"])


def test_run_wraps_missing_file_as_failure():
    result = run("does_not_exist.bin")

    assert result["tool"] == "strings"
    assert result["status"] == "failure"
    assert "error" in result
