"""WebSocket security checks — cross-site WebSocket hijacking (CSWSH).

A WebSocket handshake is a plain HTTP upgrade; the browser sends the page's
`Origin`, but (unlike CORS) the server must validate it explicitly. If a
cookie-authenticated WS endpoint accepts a FOREIGN Origin, a malicious page can
open an authenticated socket in the victim's session and read/drive it — CSWSH.

`connect(origin) -> (status, headers)` performs the upgrade with a given Origin
(injected so this is testable and transport-agnostic). Detection only.
"""
from __future__ import annotations

from typing import Callable

from ..models import Finding, Severity, VulnClass


def _accepted(status: int, headers: dict) -> bool:
    if status == 101:
        return True
    up = " ".join(f"{k}:{v}" for k, v in (headers or {}).items()).lower()
    return "upgrade: websocket" in up or "sec-websocket-accept" in up


def check_cswsh(connect: Callable, url: str, *, authenticated: bool = True,
                same_origin: str = "https://app.local",
                evil_origin: str = "https://evil.example") -> list:
    out: list[Finding] = []
    try:
        s_status, s_headers = connect(same_origin)
        e_status, e_headers = connect(evil_origin)
    except Exception:
        return out
    same_ok = _accepted(s_status, s_headers)
    evil_ok = _accepted(e_status, e_headers)
    if same_ok and evil_ok:
        out.append(Finding(
            vuln_class=VulnClass.MISCONFIG,
            severity=Severity.HIGH if authenticated else Severity.MEDIUM,
            title="Cross-site WebSocket hijacking (CSWSH)", endpoint=url,
            description=("The WebSocket endpoint completed the upgrade for a foreign Origin "
                         f"({evil_origin}) — Origin is not validated. "
                         + ("With cookie-based auth, a malicious page can open an authenticated "
                            "socket in the victim's session (read/drive it)."
                            if authenticated else
                            "Add Origin validation and a per-session CSWSH token.")),
            detail={"same_origin_accepted": same_ok, "evil_origin_accepted": evil_ok,
                    "authenticated": authenticated, "rule": "cswsh"},
            confidence="confirmed" if authenticated else "firm",
            verdict="true_positive" if authenticated else "likely_true_positive",
            exploitability="exploitable" if authenticated else "conditional"))
    return out
