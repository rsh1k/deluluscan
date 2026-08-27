"""Grounding helper — retrieve KB context for a lead and format it for the AI.

Keeps the AI advisory: retrieved facts are prepended to a prompt so the model
reasons with grounded CVE/advisory/prior-finding/Mantis context; the live
differential verifier still decides truth.
"""
from __future__ import annotations

from typing import Optional

from .index import KnowledgeIndex


def ground(index: KnowledgeIndex, query: str, k: int = 4, max_chars: int = 1400) -> str:
    hits = index.search(query, k)
    if not hits:
        return ""
    lines = ["Relevant knowledge (advisory — verify against live evidence):"]
    for h in hits:
        d = h["doc"]
        lines.append(f"- [{d.source}] {d.title}: {(d.text or '')[:260]}")
    return "\n".join(lines)[:max_chars]


def augment_system(index: Optional[KnowledgeIndex], base_system: str, query: str) -> str:
    if index is None or len(index) == 0:
        return base_system
    ctx = ground(index, query)
    return base_system + ("\n\n" + ctx if ctx else "")
