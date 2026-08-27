"""Passive response analysis (ZAP passive-scan parity): stack-trace/error
disclosure, SQL errors, debug consoles, directory listing, internal-IP leaks,
secrets-in-URL, and HTML-comment leaks — no extra requests."""
from .engine import PassiveScan
from .rules import RULES, PassiveRule

__all__ = ["PassiveScan", "RULES", "PassiveRule"]
