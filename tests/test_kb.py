"""Tests for the knowledge base / RAG index + Mantis ingestion (deluluscan/kb/, WS-6).

Fully offline. Locks down BM25 retrieval ranking, id-replace df accounting,
persistence round-trip, Mantis findings ingestion (docs + vuln-class-mapped probe
hints), prior-findings ingestion, and the grounding helpers. Run: python3 -m tests.test_kb
"""
import json
import os
import sys
import tempfile
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deluluscan.kb import (KnowledgeIndex, KbDoc, docs_from_findings,  # noqa: E402
                           load_mantis_findings, mantis_probe_hints, ground, augment_system)

_PASS = 0
_FAIL = 0


def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1; print(f"PASS  {name}")
    else:
        _FAIL += 1; print(f"FAIL  {name}  [{detail}]")


def sample_index():
    idx = KnowledgeIndex()
    idx.add_many([
        KbDoc("cve-jq", "jQuery XSS CVE-2020-11022",
              "jQuery before 3.5.0 cross-site scripting via htmlPrefilter in append and html", "cve"),
        KbDoc("cve-log4j", "Log4Shell CVE-2021-44228",
              "Apache Log4j2 JNDI lookup remote code execution", "cve"),
        KbDoc("note-ssrf", "SSRF to metadata",
              "server side request forgery reaches 169.254.169.254 to steal AWS credentials", "note"),
    ])
    return idx


def test_bm25_ranks_relevant_first():
    idx = sample_index()
    r = idx.search("jquery cross site scripting append", k=3)
    check("relevant doc ranked first", r and r[0]["doc"].id == "cve-jq", [x["doc"].id for x in r])
    r2 = idx.search("aws metadata credentials ssrf", k=3)
    check("ssrf note ranked first for ssrf query", r2 and r2[0]["doc"].id == "note-ssrf")
    check("unrelated query returns nothing", idx.search("kubernetes helm chart") == [])


def test_source_filter():
    idx = sample_index()
    r = idx.search("remote code execution", k=5, source="cve")
    check("source filter restricts results", all(x["doc"].source == "cve" for x in r))


def test_replace_keeps_df_consistent():
    idx = KnowledgeIndex()
    idx.add(KbDoc("d1", "alpha", "beta gamma"))
    idx.add(KbDoc("d1", "alpha", "delta"))    # replace
    check("replacing a doc id does not duplicate it", len(idx) == 1)
    check("old tokens removed from df after replace", idx._df.get("beta", 0) == 0, idx._df.get("beta"))
    check("new tokens searchable after replace", bool(idx.search("delta")))


def test_persistence_roundtrip():
    idx = sample_index()
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        path = f.name
    try:
        idx.save(path)
        idx2 = KnowledgeIndex.load(path)
        check("loaded index has all docs", len(idx2) == len(idx))
        check("loaded index still retrieves correctly",
              idx2.search("log4j jndi rce")[0]["doc"].id == "cve-log4j")
    finally:
        os.unlink(path)


def test_mantis_ingestion_and_hints():
    d = tempfile.mkdtemp()
    json.dump({"findings": [
        {"title": "Unsanitized orderby -> SQL injection", "description": "orderby concatenated into SQL",
         "file": "Dao.java", "line": 42, "severity": "high", "route": "/api/v1/items"},
        {"name": "SSTI template eval", "detail": "velocity evaluates user input", "file": "Tpl.java"},
    ]}, open(os.path.join(d, "findings.json"), "w"))
    with open(os.path.join(d, "notes.md"), "w") as f:
        f.write("# Auth bypass\nmatrix parameter bypasses the access filter")
    docs = load_mantis_findings(d)
    by = {x.title: x for x in docs}
    check("mantis json finding parsed", any("orderby" in t for t in by))
    check("vuln class inferred (sqli)", any(x.metadata.get("vuln_class") == "sqli" for x in docs))
    check("ssti inferred", any(x.metadata.get("vuln_class") == "ssti" for x in docs))
    check("markdown note ingested as a doc", any(x.source == "mantis" and "Auth bypass" in x.title
                                                 for x in docs))
    hints = mantis_probe_hints(d)
    sqli = [h for h in hints if h["vuln_class"] == "sqli"]
    check("probe hint carries the route", sqli and sqli[0]["path"] == "/api/v1/items", hints)


def test_docs_from_findings():
    res = {"findings": [{"id": "abc", "title": "IDOR on /users", "description": "id swap works",
                         "vuln_class": "idor", "severity": "high", "endpoint": "GET /users/1"}]}
    docs = docs_from_findings(res, scan_id="s1")
    check("prior finding -> kb doc", len(docs) == 1 and docs[0].source == "finding")
    check("finding metadata preserved", docs[0].metadata.get("vuln_class") == "idor")


def test_grounding_helpers():
    idx = sample_index()
    ctx = ground(idx, "jquery xss")
    check("ground returns context with the top title", "jQuery XSS" in ctx)
    base = "You are a reviewer."
    check("augment_system with empty index returns base unchanged",
          augment_system(KnowledgeIndex(), base, "x") == base)
    aug = augment_system(idx, base, "log4j2 jndi remote code execution")
    check("augment_system appends grounded context", aug.startswith(base) and len(aug) > len(base))


if __name__ == "__main__":
    for fn in [v for v in list(globals().values())
               if isinstance(v, types.FunctionType) and v.__name__.startswith("test_")]:
        try:
            fn()
        except Exception as e:
            import traceback
            _FAIL += 1
            print(f"FAIL  {fn.__name__}  [exception: {e}]")
            traceback.print_exc()
    print(f"\n{_PASS}/{_PASS + _FAIL} checks passed")
    sys.exit(1 if _FAIL else 0)
