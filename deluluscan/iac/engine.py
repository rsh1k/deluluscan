"""IacScan — walk a source tree, detect Terraform / CloudFormation, analyze."""
from __future__ import annotations

import os

from .terraform import analyze_terraform
from .cloudformation import analyze_cloudformation, load_template

_SKIP = {".git", "node_modules", "__pycache__", ".venv", "venv", ".terraform", "dist", "build"}


def _looks_cfn(text: str, data) -> bool:
    if "AWSTemplateFormatVersion" in (text or ""):
        return True
    if isinstance(data, dict) and isinstance(data.get("Resources"), dict):
        return any(isinstance(r, dict) and str(r.get("Type", "")).startswith(("AWS::", "Custom::", "Alexa::"))
                   for r in data["Resources"].values())
    return False


class IacScan:
    def scan_text(self, text: str, source: str) -> list:
        low = source.lower()
        if low.endswith(".tf"):
            return analyze_terraform(text, source)
        if low.endswith((".yaml", ".yml", ".json", ".template")):
            data = load_template(text)
            if _looks_cfn(text, data):
                return analyze_cloudformation(data, source)
        return []

    def scan_path(self, root: str, max_files: int = 5000) -> list:
        out, n = [], 0
        if os.path.isfile(root):
            try:
                return self.scan_text(open(root, encoding="utf-8", errors="replace").read(), root)
            except Exception:
                return []
        for dirpath, dirs, names in os.walk(root):
            dirs[:] = [d for d in dirs if d not in _SKIP]
            for name in names:
                if n >= max_files:
                    return out
                if not name.lower().endswith((".tf", ".yaml", ".yml", ".json", ".template")):
                    continue
                n += 1
                fp = os.path.join(dirpath, name)
                try:
                    text = open(fp, encoding="utf-8", errors="replace").read()
                except Exception:
                    continue
                out.extend(self.scan_text(text, os.path.relpath(fp, root)))
        return out
