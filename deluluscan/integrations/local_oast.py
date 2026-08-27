"""Localhost-bound out-of-band (OAST) listener.

Confirms HTTP-based blind vulnerabilities (SSRF, XXE via http:// entity, and
curl-style command injection) against a LOCAL, authorized target by catching the
callback the target makes to this listener. It drops into the same interface as
the interactsh client (`new_canary`/`poll_for`/`base_domain`), so the oob-aware
scanners use it transparently.

SAFETY / SCOPE: the listener binds **127.0.0.1 only** — it is reachable only from
the local machine, so it can confirm OOB from a locally-running target but is not
an internet-facing collaborator and cannot be used to catch callbacks from remote
systems. For internet-facing authorized targets, use the real `interactsh` client
(already integrated) under your own accountability. DNS-only exfiltration is not
supported here (no local resolver); use interactsh for that.
"""
from __future__ import annotations

import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional


class _Handler(BaseHTTPRequestHandler):
    def _record(self):
        hits = self.server._hits  # type: ignore[attr-defined]
        hits.append({"path": self.path, "time": time.time(),
                     "headers": {k: v for k, v in self.headers.items()},
                     "method": self.command})
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")
        except Exception:
            pass

    do_GET = do_POST = do_PUT = do_HEAD = _record

    def log_message(self, *a):  # silence
        pass


class LocalOastListener:
    def __init__(self, config=None):
        self.config = config
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.base_domain: Optional[str] = None
        self._hits: list[dict] = []

    def start(self) -> bool:
        try:
            # bind loopback only, ephemeral port
            self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
            self._server._hits = self._hits  # type: ignore[attr-defined]
            port = self._server.server_address[1]
            self.base_domain = f"127.0.0.1:{port}"
            self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            self._thread.start()
            return True
        except Exception:
            return False

    def new_canary(self, meta: Optional[dict] = None) -> tuple[str, str, str]:
        """Return (token, host, full_url). The token is embedded in the PATH so a
        loopback HTTP/curl callback carries it (no subdomain on 127.0.0.1)."""
        token = "dfz" + secrets.token_hex(6)
        host = f"{self.base_domain}/{token}"          # curl <host> and http://<host>/ both carry the token
        full_url = f"http://{host}"
        return token, host, full_url

    def poll_for(self, token: str, timeout_s: float = 6.0) -> list[dict]:
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            hits = [h for h in list(self._hits) if token in h.get("path", "")]
            if hits:
                return hits
            time.sleep(0.25)
        return [h for h in list(self._hits) if token in h.get("path", "")]

    def stop(self) -> None:
        try:
            if self._server:
                self._server.shutdown()
        except Exception:
            pass
