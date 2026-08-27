"""SastScan — walk a source tree, apply dangerous-pattern rules per file type,
and reuse the secret scanner. Emits Findings with file:line evidence. Offline."""
from __future__ import annotations

import os
from typing import Optional

from ..models import Finding, Severity, VulnClass
from ..secrets.scanner import scan_text as _scan_secrets
from .rules import RULES

_SEV = {"low": Severity.LOW, "medium": Severity.MEDIUM, "high": Severity.HIGH,
        "critical": Severity.CRITICAL}
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist",
              "build", "target", ".mypy_cache", ".pytest_cache", "vendor"}
_TEXT_EXT = {"py", "js", "ts", "jsx", "tsx", "java", "rb", "go", "php", "cs",
             "kt", "scala", "c", "cpp", "h", "yaml", "yml", "env", "sh", "sql",
             "json", "xml", "properties", "tf"}
_MAX_BYTES = 1_500_000
_MAX_LINE = 2000                # skip absurdly long (minified) lines


def _ext(path: str) -> str:
    return os.path.splitext(path)[1].lstrip(".").lower()


class SastScan:
    def __init__(self, secrets: bool = True, max_files: int = 20000):
        self.secrets = secrets
        self.max_files = max_files

    def scan_file(self, path: str, rel: Optional[str] = None) -> list:
        rel = rel or path
        try:
            with open(path, "r", errors="ignore") as fh:
                text = fh.read(_MAX_BYTES)
        except Exception:
            return []
        out = self._scan_text(text, rel, _ext(path))
        return out

    def _scan_text(self, text: str, rel: str, ext: str) -> list:
        out: list[Finding] = []
        applicable = [r for r in RULES if not r.langs or ext in r.langs]
        for lineno, line in enumerate(text.splitlines(), 1):
            if len(line) > _MAX_LINE:
                continue
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*")):     # skip obvious comments
                pass  # still scan — a risky call in a comment is usually a false positive; skip
            for rule in applicable:
                if rule.pattern.search(line):
                    out.append(Finding(
                        vuln_class=VulnClass(rule.vuln_class),
                        severity=_SEV[rule.severity],
                        title=f"{rule.id}: {rule.message.split('.')[0]}",
                        endpoint=f"{rel}:{lineno}",
                        description=rule.message,
                        detail={"rule": rule.id, "line": lineno, "code": stripped[:200],
                                "remediation": rule.remediation, "source": "sast"},
                        confidence="firm", verdict="likely_true_positive",
                        exploitability="conditional"))
        if self.secrets:
            for f in _scan_secrets(text, source=rel):
                out.append(f)
        return out

    def scan_path(self, root: str) -> list:
        out: list[Finding] = []
        if os.path.isfile(root):
            return self.scan_file(root)
        seen = 0
        for dirpath, dirs, names in os.walk(root):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            for n in names:
                if seen >= self.max_files:
                    return out
                ext = _ext(n)
                if ext not in _TEXT_EXT:
                    continue
                fp = os.path.join(dirpath, n)
                seen += 1
                out += self.scan_file(fp, os.path.relpath(fp, root))
        return out
