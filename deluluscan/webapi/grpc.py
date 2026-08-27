"""gRPC server-reflection exposure.

gRPC server reflection lets any client enumerate all services and methods at
runtime — convenient in dev, an information-disclosure/attack-surface exposure in
production. `reflect() -> (available: bool, services: list[str])` performs a
ListServices reflection call (injected for testability). Detection only.
"""
from __future__ import annotations

from typing import Callable

from ..models import Finding, Severity, VulnClass


def check_grpc_reflection(reflect: Callable, url: str) -> list:
    try:
        available, services = reflect()
    except Exception:
        return []
    if not available:
        return []
    services = [s for s in (services or []) if not str(s).startswith("grpc.reflection")]
    return [Finding(
        vuln_class=VulnClass.INVENTORY, severity=Severity.MEDIUM,
        title="gRPC server reflection enabled", endpoint=url,
        description=(f"Server reflection is enabled — {len(services)} service(s) and their methods "
                     "are enumerable by any client, disclosing the full RPC attack surface. Disable "
                     "reflection in production."),
        detail={"services": services[:50], "rule": "grpc-reflection"},
        confidence="confirmed", verdict="true_positive", exploitability="conditional")]
