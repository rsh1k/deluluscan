"""Tests for deluluscan.recheck (live single-endpoint re-test) and deluluscan.dashboard."""
import json
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deluluscan.dashboard import _TMPL, build_html
from deluluscan.recheck import _build_endpoint, recheck
from deluluscan.config import Config, ScanConfig
from deluluscan.models import Identity, IdentityRole
from tests.mock_target import serve

_PASS = 0
_FAIL = 0


def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1; print(f"PASS  {name}")
    else:
        _FAIL += 1; print(f"FAIL  {name}  [{detail}]")


_PORT = 8195
threading.Thread(target=serve, args=(_PORT,), daemon=True).start()
time.sleep(0.6)


def _cfg():
    c = Config(base_url=f"http://127.0.0.1:{_PORT}", verify_tls=False, output_dir="/tmp/rcheck")
    c.identities = {"anonymous": Identity(role=IdentityRole.ANON)}
    c.scan = ScanConfig(rate_limit_rps=1000.0)
    c.ai.enabled = False; c.ai.provider = "none"
    return c


# ---- recheck --------------------------------------------------------------
def test_recheck_reproduces_real_finding():
    res = recheck(_cfg(), _build_endpoint("GET", "/api/vuln/search", "q", None), ["xss"])
    check("recheck reproduces a finding on the known-vulnerable endpoint",
          len(res["findings"]) >= 1 and res["retested"], str(res.get("findings")))


def test_recheck_nonexistent_endpoint_is_false_positive():
    res = recheck(_cfg(), _build_endpoint("GET", "/api/does/not/exist", "q", None), ["xss"])
    check("recheck on a nonexistent endpoint -> false_positive (nothing reproduced)",
          res["verdict"] == "false_positive" and res["findings"] == [], str(res))


def test_recheck_unknown_scanner_is_not_tested():
    """An unknown scanner name must NOT be reported as a refutation.

    This previously returned verdict=false_positive/confidence=firm with
    retested=True, i.e. a confident refutation for an endpoint that was never
    contacted. See tests/test_verdict_discipline.py for the full invariant.
    """
    res = recheck(_cfg(), _build_endpoint("GET", "/api/vuln/search", "q", None), ["nope_scanner"])
    check("recheck with an unknown scanner name doesn't crash", res["findings"] == [], str(res))
    check("unknown scanner -> not_tested, not a refutation",
          res["verdict"] == "not_tested" and res["retested"] is False, str(res))
    check("unknown scanner -> zero probes recorded",
          res["probe_stats"]["requests"] == 0, str(res.get("probe_stats")))


# ---- dashboard ------------------------------------------------------------
def _result():
    return {"meta": {"target": "http://127.0.0.1:8080", "endpoints_scanned": 197},
            "findings": [
                {"severity": "critical", "vuln_class": "sqli", "title": "SQLi via orderby",
                 "endpoint": "GET /api/categories", "verdict": "true_positive",
                 "exploitability": "exploitable", "confidence": "firm", "detail": {}},
                {"severity": "high", "vuln_class": "authz", "title": "BFLA _addtouser",
                 "endpoint": "PUT /api/roles/{id}/members", "verdict": "conditional",
                 "exploitability": "conditional", "confidence": "firm", "detail": {}},
                {"severity": "medium", "vuln_class": "misconfig", "title": "soft-404 phantom",
                 "endpoint": "GET /.env", "verdict": "false_positive",
                 "exploitability": "not_exploitable", "confidence": "firm", "detail": {}},
            ]}


# The dashboard is the React SPA in dashboard/, built to one self-contained file
# and vendored as deluluscan/assets/dashboard_bundle.html; findings are injected as a
# `var SCANS=[…]` payload and rendered client-side. So these assert on the payload
# plus the shell's own strings — NOT on identifiers, which minification mangles.
# Behavioural assertions about the UI live in dashboard/src/test/*.test.tsx.
def test_dashboard_renders_core_sections():
    h = build_html(_result())
    for tok in ["SQLi via orderby", "BFLA _addtouser", "var SCANS=",
                "Users & Access", "Pentest Report", "Vulnerability Summary"]:
        check(f"dashboard contains '{tok}'", tok in h)


def test_dashboard_embeds_all_findings_incl_fp():
    # All findings live in the payload. A false positive is routed to the
    # "excluded" view client-side by its triage status, never dropped server-side —
    # the report has to be able to show what was retracted and why.
    h = build_html(_result())
    check("false-positive finding retained in payload", "soft-404 phantom" in h)
    check("shell can render excluded findings",
          "Dismissed" in h and "Not Applicable" in h and "Show excluded" in h)


def test_dashboard_empty_is_safe():
    h = build_html({"meta": {"target": "t", "endpoints_scanned": 0}, "findings": []})
    check("empty results render without crashing", "var SCANS=" in h and "<html" in h.lower())


# ---- dashboard security regressions ---------------------------------------
def _result_with_secret_evidence():
    jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.SIGSIGSIG"
    return {"meta": {"target": "http://127.0.0.1:8080"}, "findings": [{
        "severity": "high", "vuln_class": "authz", "title": "token issuance",
        "endpoint": "POST /api/tokens", "verdict": "true_positive",
        "exploitability": "exploitable", "confidence": "firm", "detail": {},
        "evidence": [{
            "method": "POST", "url": "http://127.0.0.1:8080/api/tokens",
            "identity": "backend", "status": 200,
            "req_headers": {"Authorization": "Bearer sk-supersecret"},
            "resp_headers": {"Set-Cookie": f"JSESSIONID=ABCDEF0123456789ABCDEF; Path=/; HttpOnly, rme={jwt}; Path=/"},
            "resp_body": '{"entity":{"jwt":"' + jwt + '"}}', "resp_len": 120,
        }]}]}


def test_dashboard_redacts_secrets():
    import re
    h = build_html(_result_with_secret_evidence())
    check("no raw JSESSIONID value in dashboard",
          not re.search(r"JSESSIONID=[A-F0-9]{16,}", h))
    check("no raw JWT in dashboard",
          not re.search(r"eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}", h))
    check("no raw bearer secret in dashboard", "sk-supersecret" not in h)
    check("redaction markers present", "redacted" in h)


def test_dashboard_escapes_script_breakout():
    r = {"meta": {}, "findings": [{
        "severity": "info", "vuln_class": "xss", "title": "reflect",
        "endpoint": "GET /x", "verdict": "true_positive", "detail": {},
        "evidence": [{"method": "GET", "url": "http://h/x", "identity": "anonymous",
                      "status": 200, "resp_body": "boom</script><script>alert(1)</script>",
                      "resp_len": 40}]}]}
    h = build_html(r)
    # The payload must contribute NO literal </script>: any it carries is escaped
    # to \u003c, so the only ones present are the shell's own inline blocks.
    shell_closes = _TMPL.count("</script>")
    check("evidence </script> is neutralised (no breakout)",
          h.count("</script>") == shell_closes and "\\u003c/script>" in h,
          f"shell has {shell_closes}, page has {h.count('</script>')}")


# Policy: >=50 chars including upper, lower, digit and special.
_PW_A = "Deluluscan-Test-Passphrase-2026!alpha$ONE#seventeen-chars-ok1"
_PW_B = "Deluluscan-Test-Passphrase-2026!bravo$TWO#seventeen-chars-ok2"
_PW_C = "Deluluscan-Test-Passphrase-2026!delta$FOUR#seventeen-chars-ok4"
_PW_WRONG = "Deluluscan-Test-Passphrase-2026!wrong$NOPE#seventeen-chars-x9"


def test_dashboard_password_encrypts_payload():
    h = build_html(_result(), password=_PW_A)   # policy-compliant (>=50, all classes)
    check("encrypted build nulls the plaintext payload", "var SCANS=null" in h)
    check("encrypted build embeds the AES-GCM blob", "var __ENC__={" in h)
    check("finding titles absent from encrypted file", "SQLi via orderby" not in h)


def test_dashboard_password_length_enforced():
    from deluluscan.dashboard import _validate_password, generate_password, _MIN_PW, _MAX_PW
    def rejects(pw):
        try: _validate_password(pw); return False
        except ValueError: return True
    check("password under the minimum length rejected", rejects("short"))
    check("password over the maximum length rejected", rejects("Aa1!" + "x"*_MAX_PW))
    check("50 chars but no uppercase rejected", rejects("a1!" + "b"*50))
    check("50 chars but no lowercase rejected", rejects("A1!" + "B"*50))
    check("50 chars but no digit rejected", rejects("Ab!" + "c"*50))
    check("50 chars but no special char rejected", rejects("Ab1" + "c"*50))
    check("compliant password accepted", not rejects(_PW_A))
    g = generate_password()
    check("generated password is within policy length", _MIN_PW <= len(g) <= _MAX_PW)
    check("generated password satisfies all character classes", not rejects(g))
    check("two generated passwords differ", generate_password() != generate_password())
    # build_html must refuse a too-short password
    try:
        build_html(_result(), password="tooshort"); check("build_html rejects short pw", False)
    except ValueError:
        check("build_html rejects short pw", True)


def test_dashboard_rekey_changes_password(tmp=None):
    import os, tempfile
    from deluluscan.dashboard import rekey_dashboard, _decrypt_payload
    import re as _re, json as _json
    old, new = _PW_A, _PW_B
    path = os.path.join(tempfile.gettempdir(), "rk_test_dashboard.html")
    open(path, "w").write(build_html(_result(), password=old))
    rekey_dashboard(path, old, new)
    blob = _json.loads(_re.search(r"var __ENC__=(\{.*?\});", open(path).read()).group(1))
    ok_new = True
    try: _decrypt_payload(blob, new)
    except Exception: ok_new = False
    old_rejected = False
    try: _decrypt_payload(blob, old)
    except Exception: old_rejected = True
    check("rekey: new password decrypts", ok_new)
    check("rekey: old password no longer works", old_rejected)
    # wrong old password must fail
    wrong = False
    try: rekey_dashboard(path, _PW_WRONG, _PW_C)
    except Exception: wrong = True
    check("rekey: wrong old password rejected", wrong)
    try: os.remove(path)
    except OSError: pass


# ---- http_client redaction unit -------------------------------------------
def test_http_client_redaction_helpers():
    from deluluscan.http_client import redact_headers, redact_body
    hdrs = redact_headers({"Set-Cookie": "JSESSIONID=DEADBEEFDEADBEEF00; Secure; HttpOnly",
                           "Authorization": "Bearer x", "Content-Type": "application/json"})
    check("Set-Cookie value masked, flags kept",
          "DEADBEEFDEADBEEF00" not in hdrs["Set-Cookie"] and "HttpOnly" in hdrs["Set-Cookie"])
    check("Authorization redacted", hdrs["Authorization"] == "<redacted>")
    check("benign header preserved", hdrs["Content-Type"] == "application/json")
    raw_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.s1gnatureBytes"
    body = redact_body('{"jwt":"' + raw_jwt + '","note":"keep me"}')
    check("JWT masked in body, rest kept",
          raw_jwt not in body and "keep me" in body)


if __name__ == "__main__":
    for fn in list(globals().values()):
        if callable(fn) and getattr(fn, "__name__", "").startswith("test_"):
            try:
                fn()
            except Exception as e:
                import traceback
                _FAIL += 1
                print(f"FAIL  {fn.__name__}  [exception: {e}]")
                traceback.print_exc()
    print(f"\n{_PASS}/{_PASS + _FAIL} checks passed")
    sys.exit(1 if _FAIL else 0)
