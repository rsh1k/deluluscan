"""Deluluscan HTTP security-header / CORS / cookie analysis.

    from deluluscan.headers import HeaderScan, analyze_all
CLI: python3 -m deluluscan.headers --url https://127.0.0.1:8443/
"""
from .analyzer import (analyze_all, check_security_headers, check_cors,
                       check_cookies, check_disclosure)
from .engine import HeaderScan

__all__ = ["analyze_all", "check_security_headers", "check_cors", "check_cookies",
           "check_disclosure", "HeaderScan"]
