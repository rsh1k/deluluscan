"""Nuclei integration (opt-in template sweep).

Nuclei runs community/auth-safe templates against the target and emits JSONL.
We constrain it to the configured target, run with rate limiting that matches
our own politeness budget, and fold its results back into our Finding model so
everything lands in one report. Templates are detection signatures, not
exploits; we avoid intrusive tags by default.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from urllib.parse import urlparse

from ..config import Config
from ..models import Finding, Severity, VulnClass

_SEV_MAP = {"info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
            "high": Severity.HIGH, "critical": Severity.CRITICAL}


class NucleiRunner:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.path = cfg.integrations.nuclei_path

    def available(self) -> bool:
        return shutil.which(self.path) is not None

    def run(self) -> list[Finding]:
        if not self.available():
            return []
        findings: list[Finding] = []
        with tempfile.NamedTemporaryFile("r+", suffix=".jsonl") as jf:
            cmd = [
                self.path, "-u", self.cfg.base_url,
                "-jsonl", "-o", jf.name,
                "-rate-limit", str(int(self.cfg.scan.rate_limit_rps * 60)),
                "-timeout", str(int(self.cfg.scan.timeout_s)),
                # Detection-oriented; exclude intrusive/destructive tags.
                "-exclude-tags", "intrusive,dos,fuzz",
                "-severity", "low,medium,high,critical",
                "-silent",
            ]
            if not self.cfg.verify_tls:
                pass  # nuclei follows its own TLS handling
            try:
                subprocess.run(cmd, capture_output=True, text=True, timeout=900)
            except subprocess.TimeoutExpired:
                pass
            jf.seek(0)
            for line in jf:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                info = obj.get("info", {})
                sev = _SEV_MAP.get(info.get("severity", "info"), Severity.INFO)
                findings.append(Finding(
                    vuln_class=VulnClass.INFO_LEAK,
                    severity=sev,
                    title=f"[nuclei] {info.get('name', obj.get('template-id'))}",
                    endpoint=obj.get("matched-at", self.cfg.base_url),
                    description=(info.get("description")
                                 or "Nuclei template match.")[:600],
                    detail={"template": obj.get("template-id"),
                            "tags": info.get("tags", [])},
                    confidence="firm"))
        return findings
