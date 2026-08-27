"""Ingest Google Mantis (github.com/google/mantis) autonomous code-scan findings.

Mantis reviews source with AI coding agents and emits findings (find/reproduce/
patch candidates). This reads a Mantis workspace/findings directory into (a)
knowledge docs for the RAG index and (b) targeted PROBE HINTS the live scanner can
turn into deeper, vuln-class-specific probes — the same idea as `--source-scan`,
now fed by an autonomous campaign.

The parser is deliberately field-name tolerant (Mantis output shapes vary): it
accepts a list of findings or {"findings":[...]}, and reads title/description/
severity/file/line/vuln-class/cwe/route under several common key spellings; plain
.md/.txt files become one doc each.
"""
from __future__ import annotations

import json
import os
import re
from typing import Optional

from .index import KbDoc

_VCLASS_HINTS = {
    "sql": "sqli", "injection": "injection", "xss": "xss", "ssrf": "ssrf",
    "ssti": "ssti", "template": "ssti", "traversal": "injection", "path": "injection",
    "auth": "authz", "access": "authz", "idor": "idor", "deserial": "deser",
    "command": "injection", "rce": "injection", "secret": "info_leak",
    "crypto": "crypto", "csrf": "csrf", "xxe": "injection",
}


def _first(d: dict, keys, default=""):
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return default


def _norm_vclass(text: str) -> Optional[str]:
    t = (text or "").lower()
    for needle, cls in _VCLASS_HINTS.items():
        if needle in t:
            return cls
    return None


def _finding_to_doc(f: dict, i: int, src: str) -> KbDoc:
    title = str(_first(f, ["title", "name", "summary", "rule", "check"], f"mantis-finding-{i}"))
    desc = str(_first(f, ["description", "detail", "message", "explanation", "body"], ""))
    file = str(_first(f, ["file", "path", "location", "filename"], ""))
    line = _first(f, ["line", "line_number", "lineno"], "")
    cwe = str(_first(f, ["cwe", "cwe_id"], ""))
    sev = str(_first(f, ["severity", "priority", "confidence"], ""))
    vclass = _norm_vclass(title + " " + desc + " " + str(_first(f, ["vuln_class", "category", "type", "class"], "")))
    text = " ".join(x for x in [desc, f"file={file}:{line}" if file else "", f"CWE={cwe}" if cwe else ""] if x)
    return KbDoc(id=f"mantis:{src}:{f.get('id', i)}", title=title, text=text, source="mantis",
                 metadata={"file": file, "line": line, "cwe": cwe, "severity": sev,
                           "vuln_class": vclass,
                           "route": _first(f, ["route", "endpoint", "url", "path_route"], "")})


def _iter_findings(obj):
    if isinstance(obj, dict):
        if isinstance(obj.get("findings"), list):
            yield from obj["findings"]
        elif isinstance(obj.get("results"), list):
            yield from obj["results"]
        else:
            yield obj
    elif isinstance(obj, list):
        yield from obj


def load_mantis_findings(path: str) -> list:
    """Return KbDocs parsed from a Mantis findings file or directory."""
    docs: list[KbDoc] = []
    files = []
    if os.path.isfile(path):
        files = [path]
    elif os.path.isdir(path):
        for root, dirs, names in os.walk(path):
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules")]
            for n in names:
                if n.endswith((".json", ".md", ".txt")):
                    files.append(os.path.join(root, n))
    for fp in files:
        try:
            with open(fp, errors="ignore") as fh:
                raw = fh.read()
        except Exception:
            continue
        base = os.path.basename(fp)
        if fp.endswith(".json"):
            try:
                obj = json.loads(raw)
            except Exception:
                continue
            for i, f in enumerate(_iter_findings(obj)):
                if isinstance(f, dict):
                    docs.append(_finding_to_doc(f, i, base))
        else:  # markdown / text -> one doc
            m = re.search(r"^#\s*(.+)$", raw, re.M)
            docs.append(KbDoc(id=f"mantis:{base}", title=(m.group(1) if m else base),
                              text=raw[:4000], source="mantis", metadata={"file": base}))
    return docs


def mantis_probe_hints(path: str) -> list:
    """Targeted probe seeds: findings that map to a live surface + vuln class."""
    hints = []
    for d in load_mantis_findings(path):
        vclass = d.metadata.get("vuln_class")
        route = d.metadata.get("route")
        if vclass and (route or d.metadata.get("file")):
            hints.append({"vuln_class": vclass, "path": route or "",
                          "file": d.metadata.get("file", ""), "why": d.title,
                          "source": "mantis"})
    return hints
