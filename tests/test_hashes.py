import hashlib
import pytest


from malworn.static_analysis.hashes import calculate_sha256, calculate_hashes

def test_calculate_sha256(tmp_path):
    test_file = tmp_path / "sample.txt"
    test_file.write_bytes(b"Hello Malworn")

    expected = hashlib.sha256(b"Hello Malworn").hexdigest()
    actual = calculate_sha256(test_file)

    assert actual == expected

def test_calculate_all_hashes(tmp_path):
    test_file = tmp_path / "sample.txt"
    content = b"Hello Malworn"
    test_file.write_bytes(content)

    results = calculate_hashes(test_file)

    assert results["md5"] == hashlib.md5(content).hexdigest()
    assert results["sha1"] == hashlib.sha1(content).hexdigest()
    assert results["sha256"] == hashlib.sha256(content).hexdigest()

def test_calculate_sha256_missing_file(tmp_path):
    missing_file = tmp_path / "does_not_exist.exe"

    with pytest.raises(FileNotFoundError):
        calculate_sha256(missing_file)

def test_calculate_hashes_large_file(tmp_path):
    test_file = tmp_path / "large_sample.bin"
    content = b"Malworn" * 10000
    test_file.write_bytes(content)

    results = calculate_hashes(test_file)

    assert results["md5"] == hashlib.md5(content).hexdigest()
    assert results["sha1"] == hashlib.sha1(content).hexdigest()
    assert results["sha256"] == hashlib.sha256(content).hexdigest()