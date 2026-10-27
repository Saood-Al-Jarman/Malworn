import pefile
import pytest

from malworn.static_analysis.extra_checks import analyze_extra_checks, run


class FakePE:
    def __init__(self, *args, **kwargs):
        self.__data__ = b"X" * 1000
        self.DIRECTORY_ENTRY_IMPORT = []

    def parse_data_directories(self, directories):
        pass

    def get_overlay_data_start_offset(self):
        return 900  # 1000 - 900 = 100 bytes of overlay

    def get_imphash(self):
        return "d41d8cd98f00b204e9800998ecf8427e"

    def close(self):
        pass


class FakePENoOverlay(FakePE):
    def get_overlay_data_start_offset(self):
        return None

    def get_imphash(self):
        return ""


def test_analyze_extra_checks_detects_overlay(monkeypatch):
    monkeypatch.setattr(pefile, "PE", FakePE)

    result = analyze_extra_checks("fake.exe")

    assert result["has_overlay"] is True
    assert result["overlay_size"] == 100
    assert result["imphash"] == "d41d8cd98f00b204e9800998ecf8427e"


def test_analyze_extra_checks_no_overlay_or_imports(monkeypatch):
    monkeypatch.setattr(pefile, "PE", FakePENoOverlay)

    result = analyze_extra_checks("fake.exe")

    assert result["has_overlay"] is False
    assert result["overlay_size"] == 0
    assert result["imphash"] is None


def test_analyze_extra_checks_rejects_invalid_file(tmp_path):
    sample = tmp_path / "invalid.exe"
    sample.write_bytes(b"not a valid Windows executable")

    with pytest.raises(pefile.PEFormatError):
        analyze_extra_checks(sample)


def test_run_wraps_success(monkeypatch):
    monkeypatch.setattr(pefile, "PE", FakePE)

    result = run("fake.exe")

    assert result["tool"] == "extra_checks"
    assert result["status"] == "success"
    assert result["data"]["has_overlay"] is True


def test_run_wraps_invalid_file_as_failure(tmp_path):
    sample = tmp_path / "invalid.exe"
    sample.write_bytes(b"not a valid Windows executable")

    result = run(sample)

    assert result["tool"] == "extra_checks"
    assert result["status"] == "failure"
    assert "error" in result