"""Tests for the enterprise report (exec summary, matrix, remediation) and
custom wordlist loading."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deluluscan.reporting.report import (write_html, _risk_posture, _remediation_for,
                                     _priority_matrix)

_PASS = 0
_FAIL = 0


def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1; print(f"PASS  {name}")
    else:
        _FAIL += 1; print(f"FAIL  {name}  [{detail}]")


def _f(sev, verdict="unverified", vc="misconfig", exploit="unknown"):
    return {"severity": sev, "verdict": verdict, "vuln_class": vc, "exploitability": exploit,
            "title": f"{vc} issue", "endpoint": "GET /x", "description": "d", "confidence": "t", "detail": {}}


def test_risk_posture_levels():
    check("confirmed critical -> CRITICAL",
          _risk_posture([_f("critical", "true_positive", "sqli", "exploitable")])[0] == "CRITICAL")
    check("unconfirmed critical only -> HIGH",
          _risk_posture([_f("critical", "unverified")])[0] == "HIGH")
    check("confirmed high -> HIGH",
          _risk_posture([_f("high", "true_positive")])[0] == "HIGH")
    check("medium only -> ELEVATED", _risk_posture([_f("medium")])[0] == "ELEVATED")
    check("nothing -> LOW", _risk_posture([])[0] == "LOW")


def test_remediation_specific_per_class():
    check("sqli remediation mentions parameterized queries",
          "parameterized" in _remediation_for(_f("high", vc="sqli")).lower())
    check("xss remediation mentions encoding/CSP",
          "encode" in _remediation_for(_f("high", vc="xss")).lower())
    check("unknown class -> generic but non-empty",
          len(_remediation_for(_f("low", vc="totally_unknown"))) > 20)


def test_matrix_counts_by_severity_and_confidence():
    findings = [_f("critical", "true_positive"), _f("high", "conditional"), _f("medium", "unverified")]
    m = _priority_matrix(findings)
    check("matrix renders a table with confidence columns",
          "Prioritization matrix" in m and "Confirmed" in m and "Candidate" in m)


def test_full_report_has_all_sections():
    result = {"meta": {"target": "http://127.0.0.1:8080", "endpoints_scanned": 10,
                       "fingerprint": {"detections": [{"tech": "nginx", "version": "1.10.3"}]}},
              "findings": [_f("critical", "true_positive", "sqli", "exploitable"),
                           _f("high", "conditional", "authz"), _f("info", "unverified", "inventory")]}
    d = tempfile.mkdtemp()
    html = open(write_html(result, d)).read()
    for tok in ["Executive summary", "Prioritization matrix", "Technical findings",
                "Remediation:", "Deluluscan — security assessment report"]:
        check(f"report contains '{tok}'", tok in html)
    check("no leftover the target branding in title", "the target API security report" not in html)


if __name__ == "__main__":
    for fn in list(globals().values()):
        if callable(fn) and getattr(fn, "__name__", "").startswith("test_"):
            try:
                fn()
            except Exception as e:
                _FAIL += 1
                print(f"FAIL  {fn.__name__}  [exception: {e}]")
    print(f"\n{_PASS}/{_PASS + _FAIL} checks passed")
    sys.exit(1 if _FAIL else 0)
