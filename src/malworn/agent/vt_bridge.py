"""VirusTotal bridge: runs on the WINDOWS host, never in the VM.

Owner: Saood (uses Hassan's lookup in malworn.detection.virustotal_tool)

The analysis VM has no internet, so it can't reach VirusTotal. This small
server sits on the Windows side of the host-only network, next to Ollama. The
VM sends it a SHA-256; it asks VirusTotal and returns Hassan's ToolResult.

    VM: virustotal tool ── GET /vt/<sha256> ──► this bridge ── HTTPS ──► VirusTotal

What it accepts: exactly one route, GET /vt/<64 hex characters>. Anything else
gets 404 or 405. No request body is read, so nothing but a hash can arrive.
The API key is read from the Windows environment (VT_API_KEY) and never sent to
the VM. Hassan's lookup adds the cache (~/.malworn/vt_cache), the 4-per-minute
limit and the error handling.

Run it on Windows, from the repo root, in PowerShell:

    $env:PYTHONPATH = "src"
    python -m malworn.agent.vt_bridge                  # live lookups (needs VT_API_KEY)
    python -m malworn.agent.vt_bridge --mode mock      # no key needed, fake "not found" answers

Settings (flags or environment variables):
    MALWORN_BRIDGE_HOST  default 192.168.5.1  (the host-only adapter; never 0.0.0.0)
    MALWORN_BRIDGE_PORT  default 8770
    MALWORN_VT_MODE      default live         (live | mock | cache_only)
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from malworn.detection.virustotal_tool import lookup_sha256

DEFAULT_HOST = "192.168.5.1"
DEFAULT_PORT = 8770
ROUTE = re.compile(r"^/vt/([0-9a-fA-F]{64})$")


def make_handler(mode, lookup=lookup_sha256, log=print):
    class Handler(BaseHTTPRequestHandler):
        server_version = "MalwornVTBridge/1.0"
        sys_version = ""

        def _send(self, status, payload):
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802 (http.server naming)
            if self.path == "/health":
                return self._send(200, {"ok": True, "mode": mode})
            match = ROUTE.match(self.path)
            if not match:
                return self._send(404, {"error": "Only GET /vt/<sha256> is supported"})
            sha256 = match.group(1).lower()
            result = lookup(sha256, mode=mode)
            log(f"[{datetime.now():%H:%M:%S}] {self.client_address[0]} lookup {sha256[:12]}... "
                f"-> {result.get('status')} ({result.get('source')})")
            self._send(200, result)

        def _refuse(self):
            self._send(405, {"error": "Only GET is supported"})

        do_POST = do_PUT = do_DELETE = do_PATCH = _refuse  # noqa: N815

        def log_message(self, *args):  # silence the default per-request log
            pass

    return Handler


def make_server(host, port, mode, lookup=lookup_sha256, log=print):
    return ThreadingHTTPServer((host, port), make_handler(mode, lookup, log))


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m malworn.agent.vt_bridge",
                                     description="Hash-only VirusTotal bridge for the Malworn VM.")
    parser.add_argument("--host", default=os.environ.get("MALWORN_BRIDGE_HOST", DEFAULT_HOST))
    parser.add_argument("--port", type=int, default=int(os.environ.get("MALWORN_BRIDGE_PORT", DEFAULT_PORT)))
    parser.add_argument("--mode", choices=["live", "mock", "cache_only"],
                        default=os.environ.get("MALWORN_VT_MODE", "live"))
    args = parser.parse_args(argv)

    if args.host in ("0.0.0.0", "::", ""):
        print("error: refusing to listen on every network. Use the host-only address (192.168.5.1).",
              file=sys.stderr)
        return 2
    if args.mode == "live" and not os.environ.get("VT_API_KEY"):
        print("warning: VT_API_KEY is not set, so live lookups will fail. "
              "Set it with:  setx VT_API_KEY \"your-key\"  (then open a new PowerShell), "
              "or run with --mode mock.", file=sys.stderr)
    try:
        server = make_server(args.host, args.port, args.mode)
    except OSError as exc:
        print(f"error: can't listen on {args.host}:{args.port} ({exc}). Is the host-only adapter up, "
              "and is another bridge already running?", file=sys.stderr)
        return 1
    print(f"Malworn VirusTotal bridge on http://{args.host}:{args.port}  (mode: {args.mode})")
    print("Only GET /vt/<sha256> is accepted. Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
