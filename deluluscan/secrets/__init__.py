"""Deluluscan secret/credential exposure scanning (responses & JS).

    from deluluscan.secrets import scan_text, SecretScan
CLI: python3 -m deluluscan.secrets --url https://127.0.0.1:8443/
"""
from .scanner import scan_text
from .engine import SecretScan
from .patterns import RULES, mask, shannon_entropy

__all__ = ["scan_text", "SecretScan", "RULES", "mask", "shannon_entropy"]
