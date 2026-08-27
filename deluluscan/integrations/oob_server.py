"""Self-hosted out-of-band responder.

A drop-in collaborator for authorized engagements where the target can reach the
tester's host but you don't want to depend on the external interactsh binary or a
public server. It runs a tiny HTTP listener; any request whose path contains a
canary token is recorded, giving the same out-of-band confirmation signal for
blind SSRF / command injection / XXE.

Exposes the same duck-typed interface the scanners use: ``base_domain``,
``new_canary(meta)``, ``poll_for(token)``, ``confirmed_canaries()``, ``start()``,
``stop()``. Binds to a caller-chosen interface (default loopback). This only ever
*receives* requests the target chooses to send; it initiates nothing.
"""
from __future__ import annotations

import json
import socket
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional


class _Handler(BaseHTTPRequestHandler):
    def _record(self):
        hits = self.server.deluluscan_hits  # type: ignore[attr-defined]
        hits.append({"path": self.path, "headers": dict(self.headers),
                     "client": self.client_address[0], "ts": time.time()})
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    do_GET = _record
    do_POST = _record
    do_PUT = _record

    def log_message(self, *a):  # silence
        return


class OobServer:
    def __init__(self, cfg=None, host: str = "127.0.0.1", advertised_host: str = "",
                 port: int = 0):
        self.host = host
        # advertised_host is what canaries embed (e.g. the tester's LAN IP the
        # target can reach); defaults to the bind host.
        self.advertised = advertised_host or host
        self.port = port
        self._srv: Optional[ThreadingHTTPServer] = None
        self._hits: list[dict] = []
        self._canaries: dict[str, dict] = {}
        self.base_domain: Optional[str] = None

    def available(self) -> bool:
        return True

    def start(self) -> bool:
        try:
            self._srv = ThreadingHTTPServer((self.host, self.port), _Handler)
        except OSError:
            return False
        self._srv.deluluscan_hits = self._hits  # type: ignore[attr-defined]
        self.port = self._srv.server_address[1]
        self.base_domain = f"{self.advertised}:{self.port}"
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        return True

    def new_canary(self, meta: Optional[dict] = None) -> tuple[str, str, str]:
        token = uuid.uuid4().hex[:16]
        self._canaries[token] = dict(meta or {})
        host = self.base_domain or f"{self.advertised}:{self.port}"
        return token, host, f"http://{host}/{token}"

    def _blob(self) -> str:
        return json.dumps(self._hits).lower()

    def poll_for(self, token: str, timeout_s: float = 8.0) -> list[dict]:
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            hits = [h for h in self._hits if token.lower() in json.dumps(h).lower()]
            if hits:
                return hits
            time.sleep(0.3)
        return []

    def confirmed_canaries(self) -> list[dict]:
        blob = self._blob()
        out = []
        for token, meta in self._canaries.items():
            if token.lower() in blob:
                m = dict(meta); m["token"] = token
                out.append(m)
        return out

    def record_hit(self, path: str) -> None:
        """Test helper: simulate an inbound callback."""
        self._hits.append({"path": path, "ts": time.time()})

    def stop(self) -> None:
        if self._srv:
            self._srv.shutdown()


def local_ip() -> str:
    """Best-effort routable IP of this host (for advertised canary hosts)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"
