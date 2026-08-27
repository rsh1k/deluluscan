"""Deluluscan knowledge base (WS-6): offline BM25 retrieval to ground the AI layer,
+ Google Mantis code-scan ingestion.

    from deluluscan.kb import KnowledgeIndex, KbDoc, load_mantis_findings, ground
    idx = KnowledgeIndex(); idx.add_many(load_mantis_findings("mantis-out/"))
    context = ground(idx, "unsanitized orderby leads to sql injection")

CLI: python3 -m deluluscan.kb --build <dir> --out kb.json ; --query "…" --index kb.json
"""
from .index import KnowledgeIndex, KbDoc, docs_from_findings, tokenize
from .mantis import load_mantis_findings, mantis_probe_hints
from .retriever import ground, augment_system

__all__ = ["KnowledgeIndex", "KbDoc", "docs_from_findings", "tokenize",
           "load_mantis_findings", "mantis_probe_hints", "ground", "augment_system"]
