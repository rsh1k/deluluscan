"""CLI: build/query the local knowledge index.

    python3 -m deluluscan.kb --build ./mantis-out --out kb.json   # ingest a dir
    python3 -m deluluscan.kb --query "orderby sql injection" --index kb.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from .index import KnowledgeIndex, KbDoc, docs_from_findings
from .mantis import load_mantis_findings


def _build(path: str) -> KnowledgeIndex:
    idx = KnowledgeIndex()
    # Mantis + notes across the dir
    idx.add_many(load_mantis_findings(path))
    # any results.json -> prior-finding docs
    for root, _, names in os.walk(path):
        for n in names:
            if n == "results.json":
                try:
                    with open(os.path.join(root, n)) as fh:
                        idx.add_many(docs_from_findings(json.load(fh), scan_id=root))
                except Exception:
                    pass
    return idx


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="deluluscan.kb", description="local knowledge index (RAG)")
    p.add_argument("--build", help="directory to ingest (Mantis findings, notes, results.json)")
    p.add_argument("--out", help="write the index to this JSON file")
    p.add_argument("--index", help="load an existing index for --query")
    p.add_argument("--query", help="search the index")
    p.add_argument("-k", type=int, default=5)
    args = p.parse_args(argv)

    idx = None
    if args.build:
        idx = _build(args.build)
        print(f"[kb] ingested {len(idx)} docs from {args.build}")
        if args.out:
            idx.save(args.out); print(f"[kb] wrote {args.out}")
    if args.query:
        if idx is None:
            if not args.index:
                p.error("--query needs --index or --build")
            idx = KnowledgeIndex.load(args.index)
        for h in idx.search(args.query, args.k):
            d = h["doc"]
            print(f"  {h['score']:.3f}  [{d.source}] {d.title}")
    if not args.build and not args.query:
        p.error("provide --build and/or --query")
    return 0


if __name__ == "__main__":
    sys.exit(main())
