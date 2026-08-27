"""Semantic response diffing.

Length-bucket hashing (in models.RequestRecord) is a coarse "are these the same
response" signal. For IDOR/authz it helps to know *how* two responses differ —
two users hitting the same object id should get structurally similar JSON if
there's a leak, and a denied request should look different from an allowed one.

This module provides a structural similarity score for JSON/text bodies that the
IDOR scanner and the validator can use to raise or lower confidence. Pure
standard library; no heavy deps.
"""
from __future__ import annotations

import json
from difflib import SequenceMatcher
from typing import Any


def _shape(obj: Any) -> Any:
    """Reduce a JSON value to its structure (keys + types), dropping leaf values
    so two records of the same kind compare equal regardless of content."""
    if isinstance(obj, dict):
        return {k: _shape(v) for k, v in sorted(obj.items())}
    if isinstance(obj, list):
        return [_shape(obj[0])] if obj else []
    return type(obj).__name__


def structural_similarity(a: str, b: str) -> float:
    """0.0 (different) .. 1.0 (same structure). Falls back to text ratio for
    non-JSON bodies."""
    try:
        ja, jb = json.loads(a), json.loads(b)
        sa = json.dumps(_shape(ja), sort_keys=True)
        sb = json.dumps(_shape(jb), sort_keys=True)
        return SequenceMatcher(None, sa, sb).ratio()
    except (json.JSONDecodeError, TypeError):
        return SequenceMatcher(None, a[:4000], b[:4000]).ratio()


def looks_like_same_object(a: str, b: str, threshold: float = 0.9) -> bool:
    """True when two bodies are structurally near-identical — i.e. a lower-privilege
    identity likely received the *same kind of* object a privileged one did."""
    return structural_similarity(a, b) >= threshold
