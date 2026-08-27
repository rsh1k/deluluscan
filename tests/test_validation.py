"""Unit tests for the v0.7 validation agent: response differ, confidence engine +
FP memory, passive checks, and JS endpoint recon.
Run: python -m tests.test_validation
"""
from __future__ import annotations
import sys, os, tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deluluscan.models import RequestRecord
from deluluscan.verify.differ import diff_responses, marker_context
from deluluscan.verify.validation import (ConfidenceEngine, FalsePositiveMemory,
                                       signature, STATE_REVIEWED, STATE_DISMISSED)
from deluluscan.active.jsrecon import extract_from_js, script_srcs, JsEndpointMiner

results = []
def check(name, cond, extra=""):
    results.append((name, cond))
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + (f"  [{extra}]" if extra and not cond else ""))

def rec(status=200, body="", ms=10.0):
    return RequestRecord(method="GET", url="http://h/x", identity="anon", status=status,
                         elapsed_ms=ms, resp_headers={}, resp_body=body, resp_len=len(body))


# ---- differ ----------------------------------------------------------------
def test_diff_marker_html_context():
    base = rec(200, "<div>hello</div>")
    poc = rec(200, "<div>hello <b>dfz123</b></div>")
    d = diff_responses(base, poc, marker="dfz123")
    check("differ: marker in html context is exploitable signal",
          d.marker_reflected and d.marker_context == "html" and d.exploitable_signal())

def test_diff_marker_json_not_exploitable():
    base = rec(200, '{"q":""}')
    poc = rec(200, '{"q":"dfz123"}')
    d = diff_responses(base, poc, marker="dfz123")
    check("differ: marker in json context is NOT an executable signal",
          d.marker_reflected and d.marker_context == "json" and not d.exploitable_signal())

def test_diff_new_error_signature():
    base = rec(200, '{"rows":[]}')
    poc = rec(500, "you have an error in your SQL syntax near ''")
    d = diff_responses(base, poc, marker="")
    check("differ: new SQL error is an exploitable signal",
          d.new_error_signature and d.exploitable_signal())

def test_diff_timing():
    base = rec(200, "ok", ms=50)
    poc = rec(200, "ok", ms=5200)
    d = diff_responses(base, poc)
    check("differ: large timing delta is an exploitable signal",
          d.timing_delta_ms > 1000 and d.exploitable_signal())

def test_marker_context_attribute():
    body = '<input value="dfz9">'
    check("marker_context detects attribute", marker_context(body, "dfz9") == "attribute")


# ---- confidence engine + FP memory -----------------------------------------
def _finding(verdict, expl="exploitable", test="authz_matrix_bypass", endpoint="GET /api/x"):
    return {"vuln_class": "authz", "title": "t", "endpoint": endpoint,
            "verdict": verdict, "exploitability": expl,
            "detail": {"test": test, "verification": {"verdict": verdict, "exploitability": expl}},
            "evidence": [{"resp_body": "{}"}]}

def test_confidence_true_positive_reviewed():
    vs = ConfidenceEngine().evaluate(_finding("true_positive"))
    check("confidence: true_positive -> reviewed, high confidence",
          vs.state == STATE_REVIEWED and vs.confidence >= 0.85, str(vs.to_dict()))

def test_confidence_false_positive_dismissed():
    vs = ConfidenceEngine().evaluate(_finding("false_positive", expl="not_exploitable"))
    check("confidence: false_positive -> dismissed",
          vs.state == STATE_DISMISSED, str(vs.to_dict()))

def test_fp_memory_learns_and_suppresses():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "fp.json")
        mem = FalsePositiveMemory(path)
        eng = ConfidenceEngine(mem)
        f = _finding("false_positive", expl="not_exploitable")
        vs1 = eng.evaluate(f); mem.save()
        # reload memory in a fresh run; a now-'inconclusive' same finding is auto-suppressed
        mem2 = FalsePositiveMemory(path)
        eng2 = ConfidenceEngine(mem2)
        f2 = _finding("inconclusive", expl="unknown")
        vs2 = eng2.evaluate(f2)
        check("FP memory: dismissal persists and suppresses the repeat",
              vs1.state == STATE_DISMISSED and vs2.state == STATE_DISMISSED
              and "known false-positive" in vs2.dismissed_reason, str(vs2.to_dict()))

def test_signature_generalizes_ids():
    a = signature(_finding("false_positive", endpoint="GET /api/user/123"))
    b = signature(_finding("false_positive", endpoint="GET /api/user/999"))
    check("signature generalizes across numeric ids", a == b, f"{a} vs {b}")

def test_true_positive_not_suppressed_by_memory():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "fp.json")
        mem = FalsePositiveMemory(path)
        eng = ConfidenceEngine(mem)
        eng.evaluate(_finding("false_positive")); mem.save()
        # same signature but now a confirmed TRUE positive must NOT be suppressed
        mem2 = FalsePositiveMemory(path); eng2 = ConfidenceEngine(mem2)
        vs = eng2.evaluate(_finding("true_positive"))
        check("FP memory does not suppress a confirmed true positive",
              vs.state == STATE_REVIEWED, str(vs.to_dict()))


# ---- JS endpoint recon -----------------------------------------------------
def test_js_extracts_api_paths():
    js = 'const u="/api/v1/users";fetch("/api/internal/config");axios.get("/rest/admin/keys")'
    paths, ssrf = extract_from_js(js)
    check("jsrecon extracts api paths from JS",
          "/api/v1/users" in paths and "/api/internal/config" in paths, str(paths))

def test_js_flags_ssrf_candidates():
    js = 'fetch("/api/proxy?url=x");fetch("/api/image/preview")'
    paths, ssrf = extract_from_js(js)
    check("jsrecon flags SSRF-prone endpoints",
          any("proxy" in s for s in ssrf) and any("preview" in s for s in ssrf), str(ssrf))

def test_js_miner_follows_scripts():
    html = '<script src="/static/app.js"></script>'
    def fetch_text(p):
        return 'fetch("/api/v2/secret/data")' if p == "/static/app.js" else ""
    recon = JsEndpointMiner(fetch_text).mine(html)
    check("jsrecon follows <script> srcs and mines them",
          "/api/v2/secret/data" in recon.paths and recon.scripts_scanned == 1, str(recon.paths))


# ---- passive scanner logic (header checks) ---------------------------------
def test_passive_header_helper():
    from deluluscan.scanners.passive import _h
    check("passive _h is case-insensitive",
          _h({"Content-Type": "application/json"}, "content-type") == "application/json")


def test_dedup_collapses_duplicates_keeps_distinct():
    from deluluscan.orchestrator import Orchestrator
    from deluluscan.models import Finding, Severity, VulnClass
    fs = []
    for i in range(6):
        f = Finding(vuln_class=VulnClass.ERROR_HANDLING, severity=Severity.LOW,
                    title="Verbose error / stack trace disclosure",
                    endpoint=f"GET /api/v1/e{i}", description="d", evidence=[],
                    detail={"test": "verbose_error"})
        f.verdict = "true_positive"; fs.append(f)
    dist = Finding(vuln_class=VulnClass.SQLI, severity=Severity.CRITICAL,
                   title="SQL injection via 'orderby'", endpoint="GET /api/v1/containers",
                   description="d", evidence=[], detail={"test": "sqli"})
    dist.verdict = "true_positive"; fs.append(dist)
    out, removed = Orchestrator._dedup_findings(fs)
    ok = (len(out) == 2 and removed == 5
          and any(f.detail.get("affected_count") == 6 for f in out)
          and any(f.vuln_class == VulnClass.SQLI for f in out))
    check("dedup collapses 6 duplicates to 1 (+count) and keeps the distinct SQLi", ok,
          f"{len(out)} findings, removed={removed}")


if __name__ == "__main__":
    for fn in list(globals().values()):
        if callable(fn) and getattr(fn, "__name__", "").startswith("test_"):
            fn()
    total = len(results); passed = sum(1 for _, c in results if c)
    print(f"\n{passed}/{total} checks passed")
    sys.exit(0 if passed == total else 1)
