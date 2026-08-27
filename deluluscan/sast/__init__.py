"""Deluluscan lightweight SAST — scan a source tree for dangerous patterns +
hardcoded secrets (file:line evidence). Offline.

    from deluluscan.sast import SastScan
    findings = SastScan().scan_path("./src")

CLI: python3 -m deluluscan.sast --path ./src
"""
from .engine import SastScan
from .rules import RULES

__all__ = ["SastScan", "RULES"]
