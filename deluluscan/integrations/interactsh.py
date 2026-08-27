"""Interactsh integration (out-of-band collaborator for blind SSRF).

We shell out to the `interactsh-client` binary, which registers with an
Interactsh server and prints JSON interaction events. The SSRF scanner asks this
client for a unique canary subdomain per probe; if the target server resolves or
requests that host, the event shows up here and we correlate it back by the
unique token embedded in the subdomain.

This is purely a detection signal: the canary host serves nothing and the probe
points the target only at the collaborator.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import threading
import time
import uuid
from typing import Optional

from ..config import Config


class InteractshClient:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.path = cfg.integrations.interactsh_client_path
        self.base_domain: Optional[str] = None
        self._events: list[dict] = []
        self._canaries: dict[str, dict] = {}
        self._proc: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()

    def available(self) -> bool:
        return shutil.which(self.path) is not None

    def start(self) -> bool:
        if not self.available():
            return False
        cmd = [self.path, "-json"]
        if self.cfg.integrations.interactsh_server:
            cmd += ["-server", self.cfg.integrations.interactsh_server]
        self._proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, text=True,
                                      bufsize=1)
        threading.Thread(target=self._reader, daemon=True).start()
        # The client prints its assigned domain early; grab it.
        deadline = time.time() + 10
        while time.time() < deadline and not self.base_domain:
            time.sleep(0.2)
        return self.base_domain is not None

    def _reader(self) -> None:
        assert self._proc and self._proc.stdout
        for line in self._proc.stdout:
            line = line.strip()
            if not line:
                continue
            # Some builds print the domain as a plain line first.
            if not self.base_domain and line.endswith(".oast.fun") or \
                    (not self.base_domain and "interactsh" in line.lower()
                     and "." in line and " " not in line):
                self.base_domain = line.split()[-1]
                continue
            try:
                evt = json.loads(line)
                with self._lock:
                    self._events.append(evt)
                if not self.base_domain and "full-id" in evt:
                    # derive base domain from a unique-id event if needed
                    fid = evt.get("full-id", "")
                    self.base_domain = fid.split(".", 1)[1] if "." in fid else None
            except json.JSONDecodeError:
                continue

    def new_canary(self, meta: Optional[dict] = None) -> tuple[str, str, str]:
        """Return (token, host, url) for a unique canary subdomain and remember
        what probe it belongs to so callbacks can be correlated post-scan."""
        token = uuid.uuid4().hex[:16]
        host = f"{token}.{self.base_domain}" if self.base_domain else f"{token}.example.invalid"
        with self._lock:
            self._canaries[token] = dict(meta or {})
        return token, host, f"http://{host}/ssrf"

    def poll_for(self, token: str, timeout_s: float = 8.0) -> list[dict]:
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            with self._lock:
                hits = [e for e in self._events
                        if token in json.dumps(e).lower()]
            if hits:
                return hits
            time.sleep(0.5)
        return []

    def confirmed_canaries(self) -> list[dict]:
        """Metas of every issued canary that actually received a callback — i.e.
        proven out-of-band interactions (blind SSRF / cmd injection / XXE)."""
        blob = json.dumps(self._events).lower()
        out = []
        with self._lock:
            for token, meta in self._canaries.items():
                if token.lower() in blob:
                    m = dict(meta); m["token"] = token
                    out.append(m)
        return out

    def stop(self) -> None:
        if self._proc:
            self._proc.terminate()
