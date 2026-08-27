"""A local, offline knowledge index (RAG retrieval) for grounding the AI layer.

No embeddings API, no network, no heavy deps — a pure-Python **BM25** keyword
retriever so it runs on the same low-capacity device as everything else. Ingest
CVEs, advisories, prior findings, Mantis code-scan findings, and notes; retrieve
the most relevant passages for a lead so the AI reasons with grounded facts
instead of guessing. Advisory only — retrieved context informs the AI; the live
verifier still decides truth.
"""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field, asdict
from typing import Iterable, Optional

_TOKEN = re.compile(r"[a-z0-9]+")
_STOP = {"the", "a", "an", "and", "or", "of", "to", "in", "is", "for", "on", "with",
         "as", "by", "at", "be", "this", "that", "it", "from", "are", "was"}


def tokenize(text: str) -> list:
    return [t for t in _TOKEN.findall((text or "").lower()) if t not in _STOP and len(t) > 1]


@dataclass
class KbDoc:
    id: str
    title: str = ""
    text: str = ""
    source: str = "note"                 # cve | advisory | finding | mantis | note
    metadata: dict = field(default_factory=dict)

    def blob(self) -> str:
        return f"{self.title}\n{self.text}"


class KnowledgeIndex:
    def __init__(self):
        self.docs: dict[str, KbDoc] = {}
        self._tokens: dict[str, list] = {}
        self._df: dict[str, int] = {}
        self.k1 = 1.5
        self.b = 0.75

    # -- build --------------------------------------------------------------
    def add(self, doc: KbDoc) -> None:
        if doc.id in self.docs:               # replace: undo old df first
            for t in set(self._tokens.get(doc.id, [])):
                self._df[t] = max(0, self._df.get(t, 0) - 1)
        toks = tokenize(doc.blob())
        self.docs[doc.id] = doc
        self._tokens[doc.id] = toks
        for t in set(toks):
            self._df[t] = self._df.get(t, 0) + 1

    def add_many(self, docs: Iterable[KbDoc]) -> int:
        n = 0
        for d in docs:
            self.add(d); n += 1
        return n

    def __len__(self):
        return len(self.docs)

    # -- retrieve (BM25) ----------------------------------------------------
    def _avgdl(self) -> float:
        if not self._tokens:
            return 0.0
        return sum(len(t) for t in self._tokens.values()) / len(self._tokens)

    def _idf(self, term: str, N: int) -> float:
        df = self._df.get(term, 0)
        return math.log(1 + (N - df + 0.5) / (df + 0.5))

    def score(self, query_tokens: list, doc_id: str, N: int, avgdl: float) -> float:
        toks = self._tokens.get(doc_id, [])
        if not toks:
            return 0.0
        dl = len(toks)
        tf = {}
        for t in toks:
            tf[t] = tf.get(t, 0) + 1
        s = 0.0
        for qt in set(query_tokens):
            if qt not in tf:
                continue
            f = tf[qt]
            s += self._idf(qt, N) * (f * (self.k1 + 1)) / (f + self.k1 * (1 - self.b + self.b * dl / avgdl))
        return s

    def search(self, query: str, k: int = 5, source: Optional[str] = None) -> list:
        qt = tokenize(query)
        if not qt or not self.docs:
            return []
        N = len(self.docs)
        avgdl = self._avgdl() or 1.0
        scored = []
        for did, doc in self.docs.items():
            if source and doc.source != source:
                continue
            sc = self.score(qt, did, N, avgdl)
            if sc > 0:
                scored.append((sc, doc))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [{"score": round(s, 4), "doc": d} for s, d in scored[:k]]

    # -- persistence --------------------------------------------------------
    def save(self, path: str) -> None:
        with open(path, "w") as fh:
            json.dump({"docs": [asdict(d) for d in self.docs.values()]}, fh, indent=2)

    @classmethod
    def load(cls, path: str) -> "KnowledgeIndex":
        idx = cls()
        with open(path) as fh:
            data = json.load(fh)
        idx.add_many(KbDoc(**d) for d in data.get("docs", []))
        return idx


# --- ingest prior scan findings --------------------------------------------
def docs_from_findings(results: dict, scan_id: str = "prev") -> list:
    """Turn a previous results.json into knowledge docs (cross-scan grounding)."""
    out = []
    for i, f in enumerate(results.get("findings", []) or []):
        out.append(KbDoc(
            id=f"finding:{scan_id}:{f.get('id', i)}",
            title=f.get("title", ""),
            text=(f.get("description", "") + " " +
                  json.dumps(f.get("detail", {}))[:500]),
            source="finding",
            metadata={"vuln_class": f.get("vuln_class"), "severity": f.get("severity"),
                      "endpoint": f.get("endpoint"), "verdict": f.get("verdict")}))
    return out
