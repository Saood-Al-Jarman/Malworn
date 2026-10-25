# AI assistance: ChatGPT, October 2026. Used for: implementing file hashing with MD5, SHA-1, and SHA-256. Reviewed and tested by Ahmed.
import hashlib

def calculate_hashes(file_path):
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()

    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(8192)

            if not chunk:
                break

            sha256.update(chunk)
            md5.update(chunk)
            sha1.update(chunk)

    return {
        "sha256": sha256.hexdigest(),
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
    }

def calculate_sha256(file_path):
    return calculate_hashes(file_path)["sha256"]

def run(file_path):
    """Wrap calculate_hashes as an aggregator-ready tool result."""
    try:
        data = calculate_hashes(file_path)
    except Exception as exc:
        return {
            "tool": "hashes",
            "status": "failure",
            "error": f"{type(exc).__name__}: {exc}",
        }
    return {
        "tool": "hashes",
        "status": "success",
        "data": data,
    }