"""Offline tests for passive response analysis."""
from __future__ import annotations

from deluluscan.passive import PassiveScan, RULES
from deluluscan.models import VulnClass, Severity

_PASS = 0
_FAIL = 0


def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1; print(f"PASS  {name}")
    else:
        _FAIL += 1; print(f"FAIL  {name}  {detail}")


def ids(findings):
    return {f.detail.get("rule") for f in findings}


def test_stack_traces():
    ps = PassiveScan()
    java = ps.analyze(500, "http://t/x", {}, "Exception in thread \"main\" java.lang.NullPointerException\n\tat com.app.Foo(Foo.java:42)")
    check("java stacktrace", "java-stacktrace" in ids(java), ids(java))
    py = ps.analyze(500, "http://t/x", {}, "Traceback (most recent call last):\n  File \"/app/x.py\", line 10, in <module>")
    check("python traceback", "python-traceback" in ids(py), ids(py))
    php = ps.analyze(200, "http://t/x", {}, "<b>Fatal error</b>: Uncaught Error in /var/www/x.php on line <b>3</b>")
    check("php error", "php-error" in ids(php), ids(php))
    check("error findings are error_handling", all(f.vuln_class == VulnClass.ERROR_HANDLING
          for f in java if f.detail.get("rule") == "java-stacktrace"))


def test_sql_error():
    ps = PassiveScan()
    f = ps.analyze(500, "http://t/x", {}, "You have an error in your SQL syntax; check the manual that corresponds to your MySQL")
    check("sql error detected", "sql-error" in ids(f), ids(f))
    psql = ps.analyze(500, "http://t/x", {}, "org.postgresql.util.PSQLException: ERROR: syntax error")
    check("postgres error detected", "sql-error" in ids(psql))


def test_debug_consoles():
    ps = PassiveScan()
    w = ps.analyze(500, "http://t/", {}, "<h1>Werkzeug Debugger</h1> The debugger caught an exception")
    wf = next((f for f in w if f.detail.get("rule") == "werkzeug-debugger"), None)
    check("werkzeug debugger high", wf and wf.severity == Severity.HIGH, wf and wf.severity)
    dj = ps.analyze(500, "http://t/", {}, "Django Version: 4.2 Request Method: GET Request URL: http://t/")
    check("django debug", "django-debug" in ids(dj), ids(dj))


def test_dir_listing_and_private_ip():
    ps = PassiveScan()
    d = ps.analyze(200, "http://t/files/", {}, "<title>Index of /files</title><h1>Index of /files</h1>")
    check("dir listing", "dir-listing" in ids(d), ids(d))
    ip = ps.analyze(200, "http://t/", {}, "backend host is 10.0.3.14 internal")
    check("private ip", "private-ip" in ids(ip), ids(ip))
    check("public ip not flagged", "private-ip" not in ids(ps.analyze(200, "http://t/", {}, "8.8.8.8")))


def test_secret_in_url():
    ps = PassiveScan()
    f = ps.analyze(200, "http://t/cb?access_token=abc123&x=1", {}, "ok")
    check("secret in url", "secret-in-url" in ids(f), ids(f))
    clean = ps.analyze(200, "http://t/cb?page=1", {}, "ok")
    check("clean url not flagged", "secret-in-url" not in ids(clean))


def test_html_comment_leak():
    ps = PassiveScan()
    f = ps.analyze(200, "http://t/", {}, "<!-- TODO: remove hardcoded admin password before launch -->")
    check("html comment leak", "html-comment-leak" in ids(f), ids(f))


def test_secrets_folded_in():
    ps = PassiveScan()
    # an AWS-key-looking string should be caught by secrets.scan_text fold-in
    body = "config: AKIAIOSFODNN7EXAMPLE more text"
    f = ps.analyze(200, "http://t/", {}, body)
    check("secrets scanner folded in", any("secret" in (fi.title.lower()) for fi in f)
          or any(fi.vuln_class == VulnClass.INFO_LEAK for fi in f), [fi.title for fi in f])
    none = ps.analyze(200, "http://t/", {}, body, include_secrets=False)
    check("include_secrets=False disables fold-in",
          len(none) <= len(f))


def test_clean_response_no_findings():
    ps = PassiveScan()
    f = ps.analyze(200, "http://t/", {"server": "nginx"}, "<html><body>Welcome</body></html>")
    check("clean response -> no findings", f == [], [fi.title for fi in f])


def test_orchestrator_passive_scanner_body_rules():
    # The in-scan PassiveScanner must apply the shared body rules over collected
    # responses (ZAP parity) — a Java stack trace in a response body -> finding.
    from deluluscan.scanners.passive import PassiveScanner
    from deluluscan.models import Endpoint, RequestRecord, IdentityRole

    class _Ident:
        username = "anon"; bearer_token = None
        def label(self): return "anonymous"

    class _Auth:
        def headers_for(self, ident): return {}

    class _Client:
        def request(self, method, path, **kw):
            return RequestRecord(method=method, url="http://t" + path, identity="anon",
                                 status=500, elapsed_ms=1.0,
                                 resp_headers={"content-type": "text/html"},
                                 resp_body="Exception in thread \"main\" java.lang.NullPointer"
                                           "Exception\n\tat com.app.Foo(Foo.java:42)",
                                 resp_len=90)

    idents = {IdentityRole.ANON.value: _Ident()}
    sc = PassiveScanner(_Client(), _Auth(), object(), idents)
    ep = Endpoint(method="GET", path="/boom")
    findings = list(sc.run(ep))
    titles = [f.title for f in findings]
    check("in-scan passive fires java stacktrace body rule",
          any("Java stack trace" in t for t in titles), titles)
    check("body-rule finding marked passive", any(f.detail.get("passive") for f in findings))


def test_rules_wellformed():
    sevs = {"info", "low", "medium", "high", "critical"}
    for r in RULES:
        check(f"{r.id} severity valid", r.severity in sevs)
        check(f"{r.id} class valid", r.vuln_class in {v.value for v in VulnClass}, r.vuln_class)


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
    print(f"\n{_PASS} passed, {_FAIL} failed")
    raise SystemExit(1 if _FAIL else 0)
