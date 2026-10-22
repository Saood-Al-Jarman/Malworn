"""Tests for the agent client. A fake Ollama server stands in for the real one,
so these run anywhere (no GPU, no VM, no network)."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from malworn.agent import client
from malworn.agent.prompts import V0_USER_INSTRUCTION

EXAMPLE_REPORT = Path(__file__).resolve().parents[1] / "examples" / "reports" / "invoice_upx.json"


# ---------------------------------------------------------------------------
# Fake Ollama server
# ---------------------------------------------------------------------------
class FakeOllama(BaseHTTPRequestHandler):
    chunks = []       # list of dicts streamed back, one JSON object per line
    received = []     # request bodies the server got
    status = 200

    def do_POST(self):
        length = int(self.headers["Content-Length"])
        FakeOllama.received.append(json.loads(self.rfile.read(length)))
        self.send_response(FakeOllama.status)
        self.send_header("Content-Type", "application/x-ndjson")
        self.end_headers()
        if FakeOllama.status != 200:
            self.wfile.write(b'{"error": "model not found"}')
            return
        for chunk in FakeOllama.chunks:
            self.wfile.write((json.dumps(chunk) + "\n").encode())

    def log_message(self, *args):
        pass


@pytest.fixture
def fake_ollama():
    FakeOllama.chunks, FakeOllama.received, FakeOllama.status = [], [], 200
    server = HTTPServer(("127.0.0.1", 0), FakeOllama)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


DONE = {
    "done": True,
    "model": "qwen3:8b",
    "prompt_eval_count": 210,
    "eval_count": 100,
    "eval_duration": 2_000_000_000,
    "total_duration": 3_500_000_000,
}


# ---------------------------------------------------------------------------
# Building the request
# ---------------------------------------------------------------------------
def test_example_report_loads():
    report = client.load_report(EXAMPLE_REPORT)
    assert report["packing"]["packer_name"] == "UPX"


def test_load_report_rejects_bad_files(tmp_path):
    with pytest.raises(ValueError, match="not found"):
        client.load_report(tmp_path / "missing.json")

    broken = tmp_path / "broken.json"
    broken.write_text("{not json")
    with pytest.raises(ValueError, match="not valid JSON"):
        client.load_report(broken)

    a_list = tmp_path / "list.json"
    a_list.write_text("[1, 2]")
    with pytest.raises(ValueError, match="JSON object"):
        client.load_report(a_list)


def test_v0_messages_match_the_baseline_format():
    report = client.load_report(EXAMPLE_REPORT)
    messages = client.build_messages(report, "v0")

    assert len(messages) == 1  # v0 had no system prompt
    content = messages[0]["content"]
    assert messages[0]["role"] == "user"
    assert content.startswith(V0_USER_INSTRUCTION)
    # The report is embedded compactly, the same way it was pasted in the baseline.
    assert '{"sample": {"file_name": "invoice.exe"}' in content
    assert json.loads(content.split("\n\n", 1)[1]) == report


def test_v1_uses_a_system_prompt_and_is_the_default():
    report = client.load_report(EXAMPLE_REPORT)
    messages = client.build_messages(report)  # default version

    assert [m["role"] for m in messages] == ["system", "user"]
    system = messages[0]["content"]
    # One rule for each v0 mistake must be present.
    assert "has NOT been run" in system
    assert "Indicators are not proof" in system
    assert "only COMPRESSES" in system
    assert "unpacking stub" in system
    assert "never the file name" in system
    assert "Do not invent" in system
    assert json.loads(messages[1]["content"].split("\n\n", 1)[1]) == report


def test_unknown_prompt_version():
    with pytest.raises(ValueError, match="Unknown prompt version"):
        client.build_messages({}, "v99")


def test_split_thinking_handles_think_tags():
    thinking, answer = client.split_thinking("<think>\nreasoning here\n</think>\n\nThe answer.")
    assert thinking == "reasoning here"
    assert answer == "The answer."


# ---------------------------------------------------------------------------
# Talking to Ollama
# ---------------------------------------------------------------------------
def test_chat_streams_thinking_and_answer(fake_ollama):
    FakeOllama.chunks = [
        {"message": {"role": "assistant", "thinking": "Let me "}},
        {"message": {"role": "assistant", "thinking": "look."}},
        {"message": {"role": "assistant", "content": "UPX only "}},
        {"message": {"role": "assistant", "content": "compresses."}},
        DONE,
    ]
    seen = []
    result = client.chat(
        [{"role": "user", "content": "hi"}],
        base_url=fake_ollama,
        on_token=lambda kind, text: seen.append(kind),
    )

    assert result["answer"] == "UPX only compresses."
    assert result["thinking"] == "Let me look."
    assert result["stats"] == {
        "prompt_tokens": 210,
        "output_tokens": 100,
        "total_seconds": 3.5,
        "tokens_per_second": 50.0,
    }
    assert seen == ["thinking", "thinking", "answer", "answer"]

    sent = FakeOllama.received[0]
    assert sent["model"] == "qwen3:8b"
    assert sent["stream"] is True
    assert sent["think"] is True
    assert sent["options"] == {"temperature": 0.6, "seed": 42}


def test_chat_reports_http_errors(fake_ollama):
    FakeOllama.status = 404
    with pytest.raises(client.OllamaError, match="HTTP 404"):
        client.chat([{"role": "user", "content": "hi"}], base_url=fake_ollama)


def test_chat_explains_connection_failures():
    # Port 9 on localhost is closed, so the connection is refused immediately.
    with pytest.raises(client.OllamaError, match="Could not reach Ollama"):
        client.chat([{"role": "user", "content": "hi"}], base_url="http://127.0.0.1:9", timeout=2)


# ---------------------------------------------------------------------------
# Command line, end to end
# ---------------------------------------------------------------------------
def test_main_prints_answer_and_saves_run(fake_ollama, tmp_path, capsys):
    FakeOllama.chunks = [
        {"message": {"role": "assistant", "thinking": "hidden reasoning"}},
        {"message": {"role": "assistant", "content": "This file is packed with UPX."}},
        DONE,
    ]
    exit_code = client.main(
        [str(EXAMPLE_REPORT), "--url", fake_ollama, "--save", str(tmp_path), "--hide-thinking", "--prompt", "v0"]
    )

    assert exit_code == 0
    out = capsys.readouterr().out
    assert "This file is packed with UPX." in out
    assert "hidden reasoning" not in out  # --hide-thinking keeps it off screen...

    saved = list(tmp_path.glob("invoice_upx_v0_*.json"))
    assert len(saved) == 1
    record = json.loads(saved[0].read_text())
    assert record["answer"] == "This file is packed with UPX."
    assert record["thinking"] == "hidden reasoning"  # ...but it is still saved
    assert record["prompt_version"] == "v0"


def test_main_shows_thinking_by_default(fake_ollama, capsys):
    FakeOllama.chunks = [
        {"message": {"role": "assistant", "thinking": "visible reasoning"}},
        {"message": {"role": "assistant", "content": "Answer."}},
        DONE,
    ]
    assert client.main([str(EXAMPLE_REPORT), "--url", fake_ollama]) == 0
    out = capsys.readouterr().out
    assert out.index("--- thinking ---") < out.index("visible reasoning") < out.index("--- answer ---")


def test_main_bad_report_exits_2(tmp_path, capsys):
    assert client.main([str(tmp_path / "nope.json")]) == 2
    assert "Report not found" in capsys.readouterr().err
