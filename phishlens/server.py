"""A tiny local web server for the PhishLens window.

It only listens on 127.0.0.1 and refuses requests that did not come from its own
page (Host and Origin checks plus a custom header), so a website you happen to
visit cannot talk to it.
"""
from __future__ import annotations

import json
import os
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

from . import __version__
from .engine import run

WEB = Path(__file__).parent / "web"
SAMPLE = Path(__file__).parent / "samples" / "sample_phish.eml"
MAX_BYTES = 10 * 1024 * 1024

STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/static/style.css": ("style.css", "text/css; charset=utf-8"),
    "/static/app.js": ("app.js", "application/javascript; charset=utf-8"),
}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


class _Server(ThreadingHTTPServer):
    # On Windows, SO_REUSEADDR lets a second process share the same port.
    allow_reuse_address = os.name != "nt"
    allowed_hosts: set = set()
    allowed_origins: set = set()


class Handler(BaseHTTPRequestHandler):
    server_version = "PhishLens/" + __version__

    def log_message(self, fmt, *args):  # keep the terminal quiet
        pass

    # ------------------------------------------------------------- helpers
    def _send(self, code: int, body: bytes = b"", ctype: str = "text/plain; charset=utf-8") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", CSP)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _json(self, code: int, obj: dict) -> None:
        self._send(code, json.dumps(obj).encode("utf-8"), "application/json; charset=utf-8")

    def _trusted(self) -> bool:
        if self.headers.get("Host", "") not in self.server.allowed_hosts:
            return False
        origin = self.headers.get("Origin")
        return origin is None or origin in self.server.allowed_origins

    def _api_ok(self) -> bool:
        if self.headers.get("X-PhishLens") != "1":
            self._json(403, {"error": "forbidden"})
            return False
        return True

    # ------------------------------------------------------------- routes
    def do_GET(self):
        if not self._trusted():
            return self._json(403, {"error": "forbidden"})
        path = urlsplit(self.path).path
        if path in STATIC:
            name, ctype = STATIC[path]
            try:
                return self._send(200, (WEB / name).read_bytes(), ctype)
            except OSError:
                return self._json(500, {"error": "missing UI file: %s" % name})
        if path == "/favicon.ico":
            return self._send(204)
        if path == "/api/demo":
            if not self._api_ok():
                return
            return self._json(200, run(SAMPLE.read_bytes(), SAMPLE.name))
        self._json(404, {"error": "not found"})

    def do_POST(self):
        if not self._trusted():
            return self._json(403, {"error": "forbidden"})
        path = urlsplit(self.path).path
        if path == "/api/quit":
            if not self._api_ok():
                return
            self._json(200, {"ok": True})
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return
        if path != "/api/analyze":
            return self._json(404, {"error": "not found"})
        if not self._api_ok():
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            return self._json(400, {"error": "Choose an .eml file first."})
        if length > MAX_BYTES:
            return self._json(413, {"error": "That file is larger than 10 MB."})

        data = self.rfile.read(length)
        name = unquote(self.headers.get("X-Filename", "email.eml"))[:200] or "email.eml"
        use_intel = self.headers.get("X-Intel") == "1"
        try:
            payload = run(
                data, name, use_intel=use_intel,
                vt_key=(self.headers.get("X-VT-Key") or "").strip() or None,
                abuse_key=(self.headers.get("X-Abuse-Key") or "").strip() or None,
            )
        except Exception:
            return self._json(422, {"error": "That file could not be read as an email."})
        self._json(200, payload)


def make_server(port: int = 8765, host: str = "127.0.0.1") -> _Server:
    """Bind to the first free port at or after `port` (use 0 for any free port)."""
    candidates = [0] if port == 0 else range(port, port + 20)
    last_error = None
    for p in candidates:
        try:
            srv = _Server((host, p), Handler)
            break
        except OSError as exc:
            last_error = exc
    else:
        raise last_error
    actual = srv.server_address[1]
    srv.allowed_hosts = {"127.0.0.1:%d" % actual, "localhost:%d" % actual}
    srv.allowed_origins = {"http://" + h for h in srv.allowed_hosts}
    return srv


def serve(port: int = 8765, open_browser: bool = True) -> None:
    srv = make_server(port)
    url = "http://127.0.0.1:%d/" % srv.server_address[1]
    print("PhishLens is running at %s" % url)
    print("Press Ctrl+C to stop.")
    if open_browser:
        threading.Timer(0.6, webbrowser.open, args=(url,)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
        print("PhishLens stopped.")
