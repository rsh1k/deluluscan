"""SbomScan — load an SBOM file (CycloneDX/SPDX JSON) and analyze it."""
from __future__ import annotations

import json

from .parse import parse_sbom, detect_format
from .analyzer import analyze_components


class SbomScan:
    def scan_data(self, data, source: str = "sbom") -> list:
        import json as _json
        if isinstance(data, str):
            try:
                data = _json.loads(data)
            except Exception:
                return []
        if not detect_format(data):
            return []          # not a CycloneDX/SPDX SBOM — don't treat it as one
        return analyze_components(parse_sbom(data), source=source)

    def scan_file(self, path: str) -> list:
        with open(path, encoding="utf-8", errors="replace") as fh:
            try:
                data = json.load(fh)
            except Exception:
                return []
        return self.scan_data(data, source=path)
