"""sqlmap integration (opt-in confirmation step).

The SQLi scanner produces *candidates*. This wrapper hands a single candidate to
sqlmap to confirm injectability against your authorized localhost target. We run
sqlmap in non-interactive batch mode with conservative level/risk and an explicit
host allowlist check, so it can't be pointed at anything but the configured
target. sqlmap is a standard, widely used SQLi testing tool; here it is the
confirmation oracle, not a data-exfiltration step (we don't pass --dump etc.).
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from urllib.parse import urlparse

from ..config import Config
from ..models import Finding


class SqlmapRunner:
    def __init__(self, cfg: Config, auth=None):
        self.cfg = cfg
        self.path = cfg.integrations.sqlmap_path
        self.auth = auth   # AuthManager, so sqlmap can reuse a LIVE token

    def available(self) -> bool:
        return shutil.which(self.path) is not None

    def confirm(self, finding: Finding) -> dict:
        """Run sqlmap on the finding's endpoint+param. Returns a result dict."""
        if not self.available():
            return {"ran": False, "reason": "sqlmap not found on PATH"}
        ev = finding.evidence[-1] if finding.evidence else None
        if not ev:
            return {"ran": False, "reason": "no evidence URL"}
        # Safety: never let sqlmap hit a non-target host.
        target_host = urlparse(self.cfg.base_url).hostname
        if urlparse(ev.url).hostname != target_host:
            return {"ran": False, "reason": "evidence URL host != configured target"}

        param = finding.detail.get("param", "")
        with tempfile.TemporaryDirectory() as out:
            cmd = [
                self.path, "-u", ev.url,
                "--batch", "--smart",
                "--level", "2", "--risk", "1",
                "--technique", "BEUST",
                "--output-dir", out,
            ]
            if param:
                cmd += ["-p", param]
            # Reuse a LIVE token: the recorded header is redacted for safety, so
            # resolve the identity that produced this evidence and mint fresh auth
            # via the AuthManager — otherwise sqlmap tests unauthenticated (401).
            auth_headers = {}
            if self.auth is not None:
                try:
                    ident = None
                    for cand in (self.cfg.identities or {}).values():
                        if cand.label() == getattr(ev, "identity", None):
                            ident = cand; break
                    ident = ident or (self.cfg.identities or {}).get("backend") \
                        or (self.cfg.identities or {}).get("admin")
                    if ident is not None:
                        auth_headers = dict(self.auth.headers_for(ident) or {})
                except Exception:
                    auth_headers = {}
            for h, val in auth_headers.items():
                if h.lower() in ("authorization", "cookie") and val:
                    cmd += ["--headers", f"{h}: {val}"]
            if not auth_headers:
                val = ev.req_headers.get("Authorization") or ev.req_headers.get("authorization")
                if val and val != "<redacted>":
                    cmd += ["--headers", f"Authorization: {val}"]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True,
                                      timeout=600)
            except subprocess.TimeoutExpired:
                return {"ran": True, "confirmed": None, "reason": "timeout"}
            stdout = proc.stdout
            confirmed = "is vulnerable" in stdout or "Parameter:" in stdout
            return {"ran": True, "confirmed": confirmed,
                    "summary": _tail(stdout, 40)}


def _tail(text: str, n: int) -> str:
    return "\n".join(text.splitlines()[-n:])
