"""Deluluscan OpenAPI/Swagger security linter.

    from deluluscan.apispec import lint_spec, ApiSpecScan
CLI: python3 -m deluluscan.apispec --spec openapi.json
"""
from .linter import lint_spec
from .engine import ApiSpecScan

__all__ = ["lint_spec", "ApiSpecScan"]
