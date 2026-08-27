"""Deluluscan deeper web/API surface (WS-7): GraphQL introspection mapping,
WebSocket CSWSH, gRPC server reflection.

    from deluluscan.webapi import analyze_graphql, check_cswsh, check_grpc_reflection
CLI: python3 -m deluluscan.webapi --graphql http://127.0.0.1:8080/graphql
"""
from .graphql import analyze_graphql, parse_schema, surface_to_findings, GraphQLSurface, INTROSPECTION_QUERY
from .websocket import check_cswsh
from .grpc import check_grpc_reflection
from .engine import WebApiScan

__all__ = ["analyze_graphql", "parse_schema", "surface_to_findings", "GraphQLSurface",
           "INTROSPECTION_QUERY", "check_cswsh", "check_grpc_reflection", "WebApiScan"]
