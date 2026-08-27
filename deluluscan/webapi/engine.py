"""WebApiScan — deeper web/API surface checks (GraphQL / WebSocket / gRPC)."""
from __future__ import annotations

from typing import Callable, Optional

from ..models import Finding
from .graphql import analyze_graphql
from .websocket import check_cswsh
from .grpc import check_grpc_reflection


class WebApiScan:
    def graphql(self, fetch: Callable, url: str) -> list:
        _, findings = analyze_graphql(fetch, url)
        return findings

    def graphql_surface(self, fetch: Callable, url: str):
        return analyze_graphql(fetch, url)

    def websocket(self, connect: Callable, url: str, **kw) -> list:
        return check_cswsh(connect, url, **kw)

    def grpc(self, reflect: Callable, url: str) -> list:
        return check_grpc_reflection(reflect, url)
