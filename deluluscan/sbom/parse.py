"""Parse CycloneDX (JSON) and SPDX (JSON) SBOMs into a normalized component list."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass


@dataclass
class Component:
    name: str
    version: str = ""
    purl: str = ""
    ecosystem: str = ""
    has_hash: bool = False
    supplier: str = ""


_PURL_ECO = re.compile(r"pkg:([a-z]+)/", re.I)


def _eco(purl: str) -> str:
    m = _PURL_ECO.match(purl or "")
    return m.group(1).lower() if m else ""


def detect_format(data) -> str:
    if not isinstance(data, dict):
        return ""
    if data.get("bomFormat") == "CycloneDX" or "components" in data and "spdxVersion" not in data:
        return "cyclonedx"
    if str(data.get("spdxVersion", "")).startswith("SPDX") or "spdxVersion" in data:
        return "spdx"
    return ""


def _cyclonedx(data) -> list:
    out = []
    for c in data.get("components", []) or []:
        if not isinstance(c, dict):
            continue
        purl = c.get("purl", "")
        out.append(Component(
            name=c.get("name", ""), version=c.get("version", ""), purl=purl,
            ecosystem=_eco(purl),
            has_hash=bool(c.get("hashes")),
            supplier=(c.get("supplier") or {}).get("name", "") if isinstance(c.get("supplier"), dict)
                     else (c.get("author") or c.get("publisher") or "")))
    return out


def _spdx(data) -> list:
    out = []
    for p in data.get("packages", []) or []:
        if not isinstance(p, dict):
            continue
        purl = ""
        for ref in p.get("externalRefs", []) or []:
            if isinstance(ref, dict) and ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator", "")
        sup = p.get("supplier", "") or p.get("originator", "")
        if isinstance(sup, str) and sup.upper() == "NOASSERTION":
            sup = ""
        out.append(Component(
            name=p.get("name", ""), version=p.get("versionInfo", ""), purl=purl,
            ecosystem=_eco(purl),
            has_hash=bool(p.get("checksums")), supplier=sup))
    return out


def parse_sbom(data) -> list:
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except Exception:
            return []
    fmt = detect_format(data)
    if fmt == "cyclonedx":
        return _cyclonedx(data)
    if fmt == "spdx":
        return _spdx(data)
    return []
