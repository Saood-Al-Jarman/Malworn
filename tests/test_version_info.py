import pefile
import pytest

from malworn.static_analysis.version_info import analyze_version_info, run


class FakeStringTable:
    entries = {b"FileDescription": b"Fake App", b"CompanyName": b"Fake Corp"}


class FakeFileInfoEntry:
    StringTable = [FakeStringTable()]


class FakeDataDirectoryEntry:
    def __init__(self, size):
        self.Size = size


class FakeOptionalHeader:
    def __init__(self, security_size):
        self.DATA_DIRECTORY = [FakeDataDirectoryEntry(0) for _ in range(16)]
        self.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ] = FakeDataDirectoryEntry(security_size)


class FakePE:
    def __init__(self, *args, **kwargs):
        self.FileInfo = [[FakeFileInfoEntry()]]
        self.OPTIONAL_HEADER = FakeOptionalHeader(security_size=1024)

    def parse_data_directories(self, directories):
        pass

    def close(self):
        pass


class FakePEUnsigned(FakePE):
    def __init__(self, *args, **kwargs):
        self.FileInfo = [[]]
        self.OPTIONAL_HEADER = FakeOptionalHeader(security_size=0)


def test_analyze_version_info_extracts_fields(monkeypatch):
    monkeypatch.setattr(pefile, "PE", FakePE)

    result = analyze_version_info("fake.exe")

    assert result["version_info"]["FileDescription"] == "Fake App"
    assert result["version_info"]["CompanyName"] == "Fake Corp"
    assert result["has_signature"] is True


def test_analyze_version_info_handles_unsigned_no_version(monkeypatch):
    monkeypatch.setattr(pefile, "PE", FakePEUnsigned)

    result = analyze_version_info("fake.exe")

    assert result["version_info"] == {}
    assert result["has_signature"] is False


def test_analyze_version_info_rejects_invalid_file(tmp_path):
    sample = tmp_path / "invalid.exe"
    sample.write_bytes(b"not a valid Windows executable")

    with pytest.raises(pefile.PEFormatError):
        analyze_version_info(sample)


def test_run_wraps_success(monkeypatch):
    monkeypatch.setattr(pefile, "PE", FakePE)

    result = run("fake.exe")

    assert result["tool"] == "version_info"
    assert result["status"] == "success"
    assert result["data"]["has_signature"] is True


def test_run_wraps_invalid_file_as_failure(tmp_path):
    sample = tmp_path / "invalid.exe"
    sample.write_bytes(b"not a valid Windows executable")

    result = run(sample)

    assert result["tool"] == "version_info"
    assert result["status"] == "failure"
    assert "error" in result