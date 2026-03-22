from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
from urllib import parse

import httpx

from api.app.config import get_settings

OPENAI_OAUTH_LOCAL_REDIRECT_URI = "http://localhost:1455/auth/callback"

SUCCESS_HTML = """<!doctype html>
<html><head><meta charset='utf-8'><title>Authentication Complete</title></head>
<body style='font-family: sans-serif; padding: 2rem;'>
<h1>Authentication Complete</h1>
<p>You can return to your terminal now.</p>
</body></html>
"""

FAIL_HTML = """<!doctype html>
<html><head><meta charset='utf-8'><title>Authentication Failed</title></head>
<body style='font-family: sans-serif; padding: 2rem;'>
<h1>Authentication Failed</h1>
<p>The local callback could not complete. Check the backend logs and retry.</p>
</body></html>
"""

_server_lock = threading.Lock()
_server: ThreadingHTTPServer | None = None
_server_thread: threading.Thread | None = None


def _backend_callback_url() -> str:
    return f"{get_settings().ai_oauth_redirect_base_url.rstrip('/')}/openai/oauth/callback"


class _OpenAiOAuthHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # pragma: no cover - exercised in manual flow
        parsed = parse.urlsplit(self.path)
        if parsed.path != "/auth/callback":
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"not found")
            return

        params = parse.parse_qs(parsed.query)
        state = params.get("state", [None])[0]
        code = params.get("code", [None])[0]
        if not state or not code:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"missing code or state")
            return

        try:
            response = httpx.get(
                _backend_callback_url(),
                params={"state": state, "code": code},
                timeout=20.0,
            )
            ok = response.status_code < 400
        except Exception:
            ok = False

        self.send_response(200 if ok else 500)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write((SUCCESS_HTML if ok else FAIL_HTML).encode("utf-8"))

    def log_message(self, format: str, *args) -> None:  # pragma: no cover
        return


def ensure_openai_oauth_server() -> None:
    global _server, _server_thread
    with _server_lock:
        if _server is not None:
            return
        try:
            server = ThreadingHTTPServer(("127.0.0.1", 1455), _OpenAiOAuthHandler)
        except OSError:
            return
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        _server = server
        _server_thread = thread
