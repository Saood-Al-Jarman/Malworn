"""Malworn web app: upload a file, watch the agent work, read the report, ask follow-ups.

Owner: Saood (page layout open to Ahmed's A6 work)

Runs INSIDE the analysis VM, on 127.0.0.1:8080 only (NFR6). Open it in the
VM's browser. Nothing on the page loads from the internet.

    PYTHONPATH=src python3 -m malworn.app.web

Uploaded files are saved as <data>/samples/<sha256> with no extension and no
execute permission, and are only ever read by the tools (FR1). Each analysis is
saved in <data>/runs/<run id>/ (report.json, report.html, explanation.md,
transcript.json, agent_run.json, chat.json, meta.json).

Settings (environment variables):
    MALWORN_DATA        default ~/malworn-data   (keep it outside the git repo)
    MALWORN_OLLAMA_URL  default http://192.168.5.1:11434
    MALWORN_MODEL       default qwen3:8b
    MALWORN_VT_MODE     bridge (default) or mock
"""

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import threading
import traceback
from datetime import datetime, timezone
from html import escape
from pathlib import Path

from flask import Flask, abort, jsonify, redirect, render_template, request, send_file, url_for
from markupsafe import Markup

from malworn.agent import loop
from malworn.agent.client import DEFAULT_MODEL, DEFAULT_OLLAMA_URL, OllamaError
from malworn.agent.prompts import DEFAULT_AGENT_REQUEST
from malworn.agent.tools import load_tools

MAX_UPLOAD_BYTES = 64 * 1024 * 1024
RUN_ID = re.compile(r"^[0-9a-f]{12}-\d{8}T\d{6}Z$")
THINKING_TAIL = 2000


# ---------------------------------------------------------------------------
# Small markdown renderer for the model's answers (safe: escapes first)
# ---------------------------------------------------------------------------
def _inline(text):
    text = escape(text)
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"\[([a-z_]+)\]", r'<span class="cite">\1</span>', text)
    return text


def render_markdown(text):
    """Headings, bullet and numbered lists, bold, code and [tool] citations.
    Everything is HTML-escaped first, so text from the model can't inject markup."""
    out, list_tag, para = [], None, []

    def flush_para():
        if para:
            out.append("<p>" + " ".join(para) + "</p>")
            para.clear()

    def close_list():
        nonlocal list_tag
        if list_tag:
            out.append(f"</{list_tag}>")
            list_tag = None

    for raw in (text or "").splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        heading = re.match(r"^(#{1,4})\s+(.*)$", stripped)
        bullet = re.match(r"^[-*]\s+(.*)$", stripped)
        number = re.match(r"^\d+[.)]\s+(.*)$", stripped)
        if not stripped:
            flush_para()
            close_list()
        elif heading:
            flush_para()
            close_list()
            level = min(len(heading.group(1)) + 1, 4)
            out.append(f"<h{level}>{_inline(heading.group(2))}</h{level}>")
        elif bullet or number:
            flush_para()
            tag = "ul" if bullet else "ol"
            if list_tag != tag:
                close_list()
                out.append(f"<{tag}>")
                list_tag = tag
            out.append(f"<li>{_inline((bullet or number).group(1))}</li>")
        elif list_tag and raw.startswith(("  ", "\t")):
            out[-1] = out[-1][:-5] + " " + _inline(stripped) + "</li>"
        else:
            close_list()
            para.append(_inline(stripped))
    flush_para()
    close_list()
    return Markup("\n".join(out))


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------
class Store:
    def __init__(self, root):
        self.root = Path(root).expanduser()
        self.samples = self.root / "samples"
        self.runs = self.root / "runs"
        self.samples.mkdir(parents=True, exist_ok=True)
        self.runs.mkdir(parents=True, exist_ok=True)
        os.chmod(self.samples, 0o700)

    def save_sample(self, stream):
        """Stream an upload to disk, named by its SHA-256, read-only, never executable."""
        digest, size = hashlib.sha256(), 0
        fd, tmp = tempfile.mkstemp(dir=self.samples, prefix=".upload-")
        try:
            with os.fdopen(fd, "wb") as out:
                for chunk in iter(lambda: stream.read(65536), b""):
                    size += len(chunk)
                    if size > MAX_UPLOAD_BYTES:
                        raise ValueError(f"File is larger than {MAX_UPLOAD_BYTES // (1024 * 1024)} MB")
                    digest.update(chunk)
                    out.write(chunk)
            if size == 0:
                raise ValueError("The file is empty")
            sha256 = digest.hexdigest()
            final = self.samples / sha256
            if final.exists():
                os.unlink(tmp)
            else:
                os.chmod(tmp, 0o400)
                os.replace(tmp, final)
            return sha256, size
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

    def sample_path(self, sha256):
        return self.samples / sha256

    def run_dir(self, run_id):
        if not RUN_ID.match(run_id or ""):
            abort(404)
        path = self.runs / run_id
        if not (path / "meta.json").is_file():
            abort(404)
        return path

    def read_meta(self, run_dir):
        return json.loads((Path(run_dir) / "meta.json").read_text(encoding="utf-8"))

    def write_meta(self, run_dir, meta):
        path = Path(run_dir) / "meta.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, path)

    def recent(self, limit=25):
        metas = []
        for meta_file in self.runs.glob("*/meta.json"):
            try:
                metas.append(json.loads(meta_file.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                continue
        return sorted(metas, key=lambda m: m.get("created", ""), reverse=True)[:limit]


# ---------------------------------------------------------------------------
# Background analyses (one at a time: there is one GPU)
# ---------------------------------------------------------------------------
class Jobs:
    def __init__(self, store, settings):
        self.store = store
        self.settings = settings
        self.gpu = threading.Lock()
        self.live = {}            # run id -> progress shown on the page
        self.lock = threading.Lock()

    def progress(self, run_id):
        with self.lock:
            return self.live.get(run_id)

    def _event(self, run_id, kind, payload):
        with self.lock:
            job = self.live[run_id]
            if kind == "thinking":
                job["thinking"] = (job["thinking"] + payload)[-THINKING_TAIL * 2:]
            elif kind == "answer":
                job["answer"] += payload
            elif kind == "tool_call":
                job["events"].append({"kind": "tool_call", "tool": payload})
                job["answer"] = ""
            elif kind == "tool_result":
                job["events"].append({"kind": "tool_result", "tool": payload.tool, "status": payload.status,
                                      "ms": payload.duration_ms, "error": payload.error})
            elif kind in ("invalid_call", "repeat_call"):
                job["events"].append({"kind": kind, "tool": payload})
            elif kind == "limit":
                job["events"].append({"kind": "limit", "tool": str(payload)})

    def start(self, run_id, run_dir, sample, meta):
        with self.lock:
            self.live[run_id] = {"status": "queued", "events": [], "thinking": "", "answer": "", "error": None}
        threading.Thread(target=self._analyse, args=(run_id, run_dir, sample, meta), daemon=True).start()

    def _set(self, run_id, run_dir, meta, **changes):
        meta.update(changes)
        self.store.write_meta(run_dir, meta)
        with self.lock:
            self.live[run_id].update({k: v for k, v in changes.items() if k in ("status", "error")})

    def _analyse(self, run_id, run_dir, sample, meta):
        with self.gpu:
            self._set(run_id, run_dir, meta, status="running",
                      started=datetime.now(timezone.utc).isoformat())
            try:
                outcome = loop.run_agent(
                    sample, request=meta["request"], original_name=meta["file_name"],
                    base_url=self.settings["ollama_url"], model=self.settings["model"],
                    on_event=lambda kind, payload: self._event(run_id, kind, payload),
                )
                loop.save_outputs(outcome, run_dir)
                stats = outcome["stats"]
                self._set(run_id, run_dir, meta, status="done",
                          finished=datetime.now(timezone.utc).isoformat(),
                          seconds=stats["seconds"], tools_used=outcome["agent_run"]["selected_tools"])
            except OllamaError as exc:
                self._set(run_id, run_dir, meta, status="error", error=str(exc))
            except Exception as exc:  # noqa: BLE001 - show any failure on the page
                traceback.print_exc()
                self._set(run_id, run_dir, meta, status="error", error=f"{type(exc).__name__}: {exc}")

    def ask(self, run_dir, sample, question):
        with self.gpu:
            return loop.ask_followup(run_dir, sample, question,
                                     base_url=self.settings["ollama_url"], model=self.settings["model"])


# ---------------------------------------------------------------------------
# The app
# ---------------------------------------------------------------------------
def create_app(data_dir=None, ollama_url=None, model=None):
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES + 64 * 1024
    store = Store(data_dir or os.environ.get("MALWORN_DATA", "~/malworn-data"))
    settings = {"ollama_url": ollama_url or os.environ.get("MALWORN_OLLAMA_URL", DEFAULT_OLLAMA_URL),
                "model": model or os.environ.get("MALWORN_MODEL", DEFAULT_MODEL)}
    jobs = Jobs(store, settings)
    app.extensions["malworn"] = {"store": store, "jobs": jobs}

    # analyses that were running when the app stopped can't resume
    for meta in store.recent(limit=10_000):
        if meta.get("status") in ("queued", "running"):
            run_dir = store.runs / meta["run_id"]
            meta.update(status="error", error="The app was stopped before this analysis finished.")
            store.write_meta(run_dir, meta)

    app.jinja_env.filters["markdown"] = render_markdown

    @app.after_request
    def security_headers(response):
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "frame-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'")
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.get("/favicon.ico")
    def favicon():
        return "", 204

    @app.get("/")
    def index():
        tools, _ = load_tools()
        return render_template("index.html", recent=store.recent(), tools=tools,
                               default_request=DEFAULT_AGENT_REQUEST, settings=settings,
                               max_mb=MAX_UPLOAD_BYTES // (1024 * 1024))

    @app.post("/analyze")
    def analyze():
        upload = request.files.get("sample")
        if upload is None or not upload.filename:
            return render_template("error.html", message="Choose a file to analyse."), 400
        try:
            sha256, size = store.save_sample(upload.stream)
        except ValueError as exc:
            return render_template("error.html", message=str(exc)), 400
        now = datetime.now(timezone.utc)
        run_id = f"{sha256[:12]}-{now:%Y%m%dT%H%M%SZ}"
        run_dir = store.runs / run_id
        run_dir.mkdir(parents=True, exist_ok=False)
        meta = {
            "run_id": run_id,
            "file_name": Path(upload.filename).name[:200],
            "sha256": sha256,
            "file_size": size,
            "request": (request.form.get("request") or "").strip()[:1000] or DEFAULT_AGENT_REQUEST,
            "model": settings["model"],
            "status": "queued",
            "created": now.isoformat(),
        }
        store.write_meta(run_dir, meta)
        jobs.start(run_id, run_dir, store.sample_path(sha256), meta)
        return redirect(url_for("analysis", run_id=run_id), code=303)

    @app.get("/analysis/<run_id>")
    def analysis(run_id):
        run_dir = store.run_dir(run_id)
        meta = store.read_meta(run_dir)
        report = explanation = None
        chat = []
        if meta["status"] == "done":
            report = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
            explanation = (run_dir / "explanation.md").read_text(encoding="utf-8")
            try:
                chat = json.loads((run_dir / "chat.json").read_text(encoding="utf-8"))
            except (OSError, ValueError):
                chat = []
        return render_template("analysis.html", meta=meta, report=report,
                               explanation=explanation, chat=chat)

    @app.get("/analysis/<run_id>/status")
    def status(run_id):
        run_dir = store.run_dir(run_id)
        meta = store.read_meta(run_dir)
        live = jobs.progress(run_id) or {}
        since = request.args.get("since", default=0, type=int)
        events = live.get("events", [])
        return jsonify({
            "status": meta["status"],
            "error": meta.get("error"),
            "events": events[max(since, 0):],
            "event_count": len(events),
            "thinking": (live.get("thinking") or "")[-THINKING_TAIL:],
            "answer": live.get("answer") or "",
        })

    @app.get("/analysis/<run_id>/report.html")
    def report_html(run_id):
        path = store.run_dir(run_id) / "report.html"
        if not path.is_file():
            abort(404)
        response = send_file(path, mimetype="text/html")
        # Hassan's report uses inline styles; it never needs scripts.
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'self'")
        return response

    @app.get("/analysis/<run_id>/report.json")
    def report_json(run_id):
        path = store.run_dir(run_id) / "report.json"
        if not path.is_file():
            abort(404)
        return send_file(path, mimetype="application/json", as_attachment=True,
                         download_name=f"malworn-{run_id}.json")

    @app.post("/analysis/<run_id>/ask")
    def ask(run_id):
        run_dir = store.run_dir(run_id)
        meta = store.read_meta(run_dir)
        if meta["status"] != "done":
            return jsonify({"error": "The analysis hasn't finished yet."}), 409
        question = ((request.get_json(silent=True) or {}).get("question") or "").strip()
        if not question:
            return jsonify({"error": "Type a question first."}), 400
        if len(question) > 2000:
            return jsonify({"error": "Keep the question under 2,000 characters."}), 400
        try:
            result = jobs.ask(run_dir, store.sample_path(meta["sha256"]), question)
        except OllamaError as exc:
            return jsonify({"error": str(exc)}), 502
        return jsonify({"question": question, "answer_html": str(render_markdown(result["answer"])),
                        "new_tools": result["new_tools"], "seconds": result["seconds"]})

    return app


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python3 -m malworn.app.web",
                                     description="Malworn web app (run it inside the analysis VM).")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--data", help="data folder (default: $MALWORN_DATA or ~/malworn-data)")
    args = parser.parse_args(argv)
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("warning: the app is meant for 127.0.0.1 only (NFR6); anyone who can reach "
              f"{args.host}:{args.port} can upload files and read reports.", file=sys.stderr)
    app = create_app(args.data)
    store = app.extensions["malworn"]["store"]
    print(f"Malworn on http://{args.host}:{args.port}  (data: {store.root})")
    app.run(host=args.host, port=args.port, threaded=True, debug=False, use_reloader=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
