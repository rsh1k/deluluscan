"""PassiveScan — analyze responses the scanner already has, without new requests.

This is the ZAP passive-scan model: given (status, url, headers, body), apply the
high-precision RULES plus the secrets patterns, and emit Findings. Because it adds
no traffic, the orchestrator can feed it *every* response captured during a scan.

Body is capped before regex to keep it cheap on large pages. Detection only.
"""
from __future__ import annotations

import re
from typing import Optional

from ..models import Finding, RequestRecord, Severity, VulnClass
from .rules import RULES, PassiveRule

_SEV = {"info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
        "high": Severity.HIGH, "critical": Severity.CRITICAL}
_BODY_CAP = 200_000
_compiled = {r.id: re.compile(r.pattern) for r in RULES}


def _target_text(rule: PassiveRule, url: str, headers: dict, body: str) -> str:
    if rule.where == "url":
        return url or ""
    if rule.where == "body":
        return body or ""
    if rule.where.startswith("header:"):
        return headers.get(rule.where.split(":", 1)[1].lower(), "")
    return ""


class PassiveScan:
    def analyze(self, status: int, url: str, headers: Optional[dict] = None,
                body: str = "", *, include_secrets: bool = True) -> list:
        headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        body = (body or "")[:_BODY_CAP]
        rec = RequestRecord(method="GET", url=url, identity="anon", status=status,
                            elapsed_ms=0.0, resp_headers=headers,
                            resp_body=body[:2000], resp_len=len(body))
        out: list = []
        seen: set = set()
        for rule in RULES:
            text = _target_text(rule, url, headers, body)
            if not text:
                continue
            m = _compiled[rule.id].search(text)
            if not m:
                continue
            key = (rule.id,)
            if key in seen:
                continue
            seen.add(key)
            out.append(Finding(
                vuln_class=VulnClass(rule.vuln_class), severity=_SEV[rule.severity],
                title=rule.title, endpoint=url,
                description=f"{rule.note} (passive; matched near: {_snippet(m)}).",
                evidence=[rec], confidence=rule.confidence,
                detail={"rule": rule.id, "where": rule.where, "cwe": rule.cwe,
                        "match": _snippet(m), "source": "passive"}))
        if include_secrets and body:
            from ..secrets.scanner import scan_text
            out.extend(scan_text(body, source=url))
        return out

    def analyze_record(self, rec: RequestRecord, **kw) -> list:
        return self.analyze(rec.status, rec.url, rec.resp_headers, rec.resp_body, **kw)


def _snippet(m: re.Match) -> str:
    s = m.group(0)
    s = re.sub(r"\s+", " ", s).strip()
    return (s[:80] + "…") if len(s) > 80 else s
