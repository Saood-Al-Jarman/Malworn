
import pefile
import pytest

from malworn.static_analysis.imports import analyze_imports
from malworn.static_analysis.imports import run


class FakeImport:
    def __init__(self, name=None, ordinal=None):
        self.name = name
        self.ordinal = ordinal


class FakeDLL:
    def __init__(self, dll, imports):
        self.dll = dll
        self.imports = imports


class FakePE:
    def __init__(self, *args, **kwargs):
        self.DIRECTORY_ENTRY_IMPORT = [
            FakeDLL(
                b"KERNEL32.dll",
                [
                    FakeImport(name=b"CreateFileW"),
                    FakeImport(name=b"ReadFile"),
                    FakeImport(ordinal=123),
                ],
            ),
            FakeDLL(
                b"USER32.dll",
                [FakeImport(name=b"MessageBoxW")],
            ),
        ]
        self.DIRECTORY_ENTRY_DELAY_IMPORT = [
            FakeDLL(
                b"DELAYED.dll",
                [
                    FakeImport(name=b"DelayedFunction"),
                    FakeImport(ordinal=456),
                ],
            )
        ]

    def parse_data_directories(self, directories):
        pass

    def close(self):
        pass


def test_analyze_imports_extracts_dlls_and_functions(monkeypatch):
    monkeypatch.setattr(pefile, "PE", FakePE)

    result = analyze_imports("fake.exe")

    assert result["dll_count"] == 3
    assert result["function_count"] == 6
    assert result["dlls"] == [
    {
        "dll": "KERNEL32.dll",
        "functions": [
            "CreateFileW",
            "ReadFile",
            "ordinal_123",
        ],
    },
    {
        "dll": "USER32.dll",
        "functions": ["MessageBoxW"],
    },
    {
        "dll": "DELAYED.dll",
        "functions": [
            "DelayedFunction",
            "ordinal_456",
        ],
    },
]

def test_analyze_imports_rejects_invalid_file(tmp_path):
    sample = tmp_path / "invalid.exe"
    sample.write_bytes(b"not a valid Windows executable")

    with pytest.raises(pefile.PEFormatError):
        analyze_imports(sample)

def test_run_wraps_success(monkeypatch):
    monkeypatch.setattr(pefile, "PE", FakePE)

    result = run("fake.exe")

    assert result["tool"] == "imports"
    assert result["status"] == "success"
    assert result["data"]["dll_count"] == 3
    assert result["data"]["function_count"] == 6


def test_run_wraps_invalid_file_as_failure(tmp_path):
    sample = tmp_path / "invalid.exe"
    sample.write_bytes(b"not a valid Windows executable")

    result = run(sample)

    assert result["tool"] == "imports"
    assert result["status"] == "failure"
    assert "error" in result