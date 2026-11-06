"""The web app end to end: upload -> agent (scripted fake model) -> report -> follow-up."""

import json
import os
import stat
import time

import pytest

from malworn.app.web import create_app, render_markdown

from tests.conftest import DONE, FakeOllama


def call(*names):
    return [{"message": {"role": "assistant", "content": "",
                         "tool_calls": [{"function": {"name": n, "arguments": {}}} for n in names]}}, DONE]


def answer(text):
    return [{"message": {"role": "assistant", "thinking": "Reasoning."}},
            {"message": {"role": "assistant", "content": text}}, DONE]


@pytest.fixture
def app(fake_ollama, tmp_path):
    app = create_app(data_dir=tmp_path / "data", ollama_url=fake_ollama, model="qwen3:8b")
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def upload(client, content=b"MZ fake sample http://example.invalid", name="invoice.exe", req=""):
    import io
    return client.post("/analyze", data={"sample": (io.BytesIO(content), name), "request": req},
                       content_type="multipart/form-data")


def wait_done(client, location, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = client.get(location + "/status").get_json()
        if s["status"] in ("done", "error"):
            return s
        time.sleep(0.05)
    raise AssertionError("analysis didn't finish")


def test_home_page_lists_the_tools(client):
    page = client.get("/").get_data(as_text=True)
    assert "Analyse a file" in page
    for tool in ("hashes", "packing_indicators", "virustotal"):
        assert f"<code>{tool}</code>" in page


def test_full_flow(client, app):
    FakeOllama.script = [call("hashes", "file_type", "virustotal"),
                         answer("## Summary\nNot a PE file [file_type].\n\n- Hash looked up [virustotal]")]
    res = upload(client, req="Is this a Windows program?")
    assert res.status_code == 303
    location = res.headers["Location"]
    status = wait_done(client, location)
    assert status["status"] == "done", status
    called = [e["tool"] for e in status["events"] if e["kind"] == "tool_call"]
    assert called[:4] == ["hashes", "file_type", "packing_indicators", "virustotal"]  # core triage first

    page = client.get(location).get_data(as_text=True)
    assert "<h3>Summary</h3>" in page
    assert '<span class="cite">file_type</span>' in page
    assert "Mock VirusTotal result" in page          # mock lookup is labelled
    assert "Is this a Windows program?" in page

    report = client.get(location + "/report.html")
    assert report.status_code == 200
    assert "default-src 'none'" in report.headers["Content-Security-Policy"]
    assert client.get(location + "/report.json").get_json()["execution_summary"]["successful_calls"] == 3

    # the sample is stored by hash, read-only, not executable
    store = app.extensions["malworn"]["store"]
    meta = json.loads((store.runs / location.rsplit("/", 1)[1] / "meta.json").read_text())
    mode = os.stat(store.sample_path(meta["sha256"])).st_mode
    assert not mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    assert not mode & stat.S_IWUSR

    # follow-up question
    FakeOllama.script = [answer("The file type tool says it is not a PE [file_type].")]
    res = client.post(location + "/ask", json={"question": "Why not a PE?"})
    body = res.get_json()
    assert res.status_code == 200, body
    assert '<span class="cite">file_type</span>' in body["answer_html"]
    assert "Why not a PE?" in client.get(location).get_data(as_text=True)  # saved in chat history


def test_model_unreachable_shows_an_error(tmp_path):
    app = create_app(data_dir=tmp_path / "d", ollama_url="http://127.0.0.1:9")
    client = app.test_client()
    location = upload(client).headers["Location"]
    status = wait_done(client, location)
    assert status["status"] == "error"
    assert "Could not reach Ollama" in status["error"]
    assert "The analysis stopped" in client.get(location).get_data(as_text=True)


def test_upload_validation(client):
    import io
    assert client.post("/analyze", data={}, content_type="multipart/form-data").status_code == 400
    assert upload(client, content=b"").status_code == 400


def test_unknown_or_malformed_run_ids_are_404(client):
    assert client.get("/analysis/../../etc/passwd").status_code == 404
    assert client.get("/analysis/0123456789ab-20260101T000000Z").status_code == 404


def test_cannot_ask_before_the_analysis_finishes(client, app, monkeypatch):
    monkeypatch.setattr(app.extensions["malworn"]["jobs"], "start", lambda *a, **k: None)
    location = upload(client).headers["Location"]
    assert client.post(location + "/ask", json={"question": "x"}).status_code == 409


def test_pages_send_a_strict_content_security_policy(client):
    csp = client.get("/").headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp


def test_markdown_rendering_escapes_html():
    html = str(render_markdown("## Head\n<script>alert(1)</script> **bold** [sections]\n\n- a\n- b\n\n1. one"))
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert "<h3>Head</h3>" in html and "<strong>bold</strong>" in html
    assert '<span class="cite">sections</span>' in html
    assert "<ul>" in html and "<ol>" in html


def test_preflight_check_reports_each_problem(tmp_path, monkeypatch, capsys):
    from malworn.app import check
    monkeypatch.setenv("MALWORN_OLLAMA_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("MALWORN_DATA", str(tmp_path))
    monkeypatch.setenv("MALWORN_DIEC", "")
    assert check.main() == 1
    out = capsys.readouterr().out
    assert "[FAIL] Model" in out and "OLLAMA_HOST" in out
    assert "[  ok] VirusTotal" in out          # mock mode in tests
    assert "[  ok] Tools" in out and "10 tools" in out


def test_preflight_check_passes_when_everything_is_up(fake_ollama, tmp_path, monkeypatch, capsys):
    from malworn.app import check
    FakeOllama.get_body = {"models": [{"name": "qwen3:8b"}]}
    monkeypatch.setenv("MALWORN_OLLAMA_URL", fake_ollama)
    monkeypatch.setenv("MALWORN_DATA", str(tmp_path))
    monkeypatch.setenv("MALWORN_DIEC", "/usr/bin/true")
    assert check.main() == 0, capsys.readouterr().out
