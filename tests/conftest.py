"""Shared test helpers: a fake Ollama server so agent tests need no GPU, VM or network."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

# ---------------------------------------------------------------------------
# Fake Ollama server
# ---------------------------------------------------------------------------
class FakeOllama(BaseHTTPRequestHandler):
    chunks = []       # list of dicts streamed back, one JSON object per line
    script = []       # optional: one chunk list per request, used in order
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
        chunks = FakeOllama.script.pop(0) if FakeOllama.script else FakeOllama.chunks
        for chunk in chunks:
            self.wfile.write((json.dumps(chunk) + "\n").encode())

    def log_message(self, *args):
        pass


@pytest.fixture
def fake_ollama():
    FakeOllama.chunks, FakeOllama.script, FakeOllama.received, FakeOllama.status = [], [], [], 200
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
