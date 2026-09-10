"""CicdScan — walk a repo's .github/workflows and analyze each workflow."""
from __future__ import annotations

import os

from .github_actions import analyze_workflow

_WF_DIRS = (os.path.join(".github", "workflows"),)


class CicdScan:
    def scan_text(self, text: str, source: str) -> list:
        if source.lower().endswith((".yml", ".yaml")):
            return analyze_workflow(text, source)
        return []

    def scan_path(self, root: str) -> list:
        out = []
        if os.path.isfile(root):
            try:
                return self.scan_text(open(root, encoding="utf-8", errors="replace").read(), root)
            except Exception:
                return []
        for wfdir in _WF_DIRS:
            full = os.path.join(root, wfdir)
            if not os.path.isdir(full):
                continue
            for name in sorted(os.listdir(full)):
                if not name.lower().endswith((".yml", ".yaml")):
                    continue
                fp = os.path.join(full, name)
                try:
                    text = open(fp, encoding="utf-8", errors="replace").read()
                except Exception:
                    continue
                out.extend(self.scan_text(text, os.path.relpath(fp, root)))
        return out
