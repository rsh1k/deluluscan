"""ApiSpecScan — lint an OpenAPI/Swagger spec file or dict for security issues."""
from __future__ import annotations

import json
from typing import Optional

from ..models import Finding
from .linter import lint_spec


class ApiSpecScan:
    def scan_dict(self, spec: dict) -> list:
        return lint_spec(spec)

    def scan_file(self, path: str) -> list:
        with open(path, "r", errors="ignore") as fh:
            raw = fh.read()
        try:
            spec = json.loads(raw)
        except Exception:
            import yaml
            spec = yaml.safe_load(raw)
        return lint_spec(spec if isinstance(spec, dict) else {})
