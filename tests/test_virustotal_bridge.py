"""The VirusTotal path: VM tool -> bridge on Windows -> Hassan's lookup.

The bridge runs here on 127.0.0.1 with a fake lookup (or Hassan's mock mode),
so nothing reaches VirusTotal or the internet."""

import hashlib
import json
import threading
import urllib.error
import urllib.request

import pytest

from malworn import contract
from malworn.agent import vt_bridge, vt_tool
from malworn.detection.virustotal_tool import lookup_sha256


@pytest.fixture
def bridge():
    """Start a bridge on a free local port. Yields (url, calls)."""
    calls = []

    def fake_lookup(sha256, mode):
        calls.append((sha256, mode))
        return lookup_sha256(sha256, mode="mock")

    server = vt_bridge.make_server("127.0.0.1", 0, "live", lookup=fake_lookup, log=lambda m: None)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}", calls
    server.shutdown()
    server.server_close()


@pytest.fixture
def sample(tmp_path):
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ not really a program")
    return path


def get(url):
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


# ---------------------------------------------------------------------------
# The bridge accepts a hash and nothing else
# ---------------------------------------------------------------------------
def test_bridge_looks_up_a_sha256(bridge):
    url, calls = bridge
    sha = "A" * 64
    status, body = get(f"{url}/vt/{sha}")
    assert status == 200
    assert body["tool"] == "virustotal"
    assert calls == [("a" * 64, "live")]  # lower-cased, mode passed through


@pytest.mark.parametrize("path", [
    "/vt/" + "a" * 63,                 # too short
    "/vt/" + "g" * 64,                 # not hex
    "/vt/" + "a" * 64 + "/x",
    "/vt/../../etc/passwd",
    "/",
    "/vt/" + "a" * 64 + "?file=x",
])
def test_bridge_refuses_anything_but_a_hash(bridge, path):
    url, calls = bridge
    status, _ = get(url + path)
    assert status == 404
    assert calls == []


def test_bridge_refuses_uploads(bridge):
    url, calls = bridge
    req = urllib.request.Request(f"{url}/vt/{'a' * 64}", data=b"MZ...", method="POST")
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req, timeout=5)
    assert exc.value.code == 405
    assert calls == []


def test_bridge_health(bridge):
    url, _ = bridge
    assert get(f"{url}/health") == (200, {"ok": True, "mode": "live"})


def test_bridge_refuses_to_listen_on_every_network(capsys):
    assert vt_bridge.main(["--host", "0.0.0.0", "--mode", "mock"]) == 2
    assert "host-only" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# The VM-side tool
# ---------------------------------------------------------------------------
def test_tool_sends_only_the_hash_and_returns_hassans_result(bridge, sample, monkeypatch):
    url, calls = bridge
    monkeypatch.setenv("MALWORN_VT_MODE", "bridge")
    monkeypatch.setenv("MALWORN_VT_BRIDGE", url)

    result = contract.run_tool(vt_tool.SPEC, vt_tool.run, sample)
    expected = hashlib.sha256(sample.read_bytes()).hexdigest()
    assert calls == [(expected, "live")]
    assert result.status == "success"
    assert result.data["sha256"] == expected
    assert result.data["source"] == "mock"
    assert contract.validate(result, vt_tool.SPEC) == []


def test_tool_explains_when_the_bridge_is_down(sample, monkeypatch):
    monkeypatch.setenv("MALWORN_VT_MODE", "bridge")
    monkeypatch.setenv("MALWORN_VT_BRIDGE", "http://127.0.0.1:9")
    result = contract.run_tool(vt_tool.SPEC, vt_tool.run, sample)
    assert result.status == "failure"
    assert "not reachable" in result.error and "vt_bridge" in result.error


def test_tool_rejects_an_answer_for_another_hash(sample, monkeypatch):
    other = lookup_sha256("b" * 64, mode="mock")
    server = vt_bridge.make_server("127.0.0.1", 0, "live", lookup=lambda sha, mode: other, log=lambda m: None)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        monkeypatch.setenv("MALWORN_VT_MODE", "bridge")
        monkeypatch.setenv("MALWORN_VT_BRIDGE", f"http://127.0.0.1:{server.server_port}")
        result = vt_tool.run(sample)
    finally:
        server.shutdown()
        server.server_close()
    assert result["status"] == "failure"
    assert "different hash" in result["error"]


def test_mock_mode_needs_no_bridge(sample):
    # conftest sets MALWORN_VT_MODE=mock for every test
    result = contract.run_tool(vt_tool.SPEC, vt_tool.run, sample)
    assert result.status == "success"
    assert result.data["source"] == "mock"
    assert any("mock" in w.lower() for w in result.warnings)
