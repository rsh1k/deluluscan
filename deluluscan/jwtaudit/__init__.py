"""Offline JWT audit: structural/crypto weaknesses + HS* weak-secret cracking."""
from .audit import audit_token, crack_hs, find_and_audit
from .secrets_list import WEAK_SECRETS

__all__ = ["audit_token", "crack_hs", "find_and_audit", "WEAK_SECRETS"]
