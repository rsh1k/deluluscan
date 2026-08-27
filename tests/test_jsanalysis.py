"""Offline tests for static JS endpoint extraction."""
from __future__ import annotations

from deluluscan.recon.jsanalysis import extract_endpoints, JsEndpoint

_PASS = 0
_FAIL = 0


def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1; print(f"PASS  {name}")
    else:
        _FAIL += 1; print(f"FAIL  {name}  {detail}")


def paths(eps):
    return {e.path for e in eps}


def by_path(eps, p):
    return next((e for e in eps if e.path == p), None)


def test_fetch_axios_jquery_xhr():
    js = """
    fetch('/api/v1/users', {method:'POST'});
    axios.get('/api/v2/orders/5');
    $.ajax({url:'/rest/settings', type:'PUT'});
    $.post('/api/login');
    xhr.open('DELETE','/api/v1/session');
    """
    eps = extract_endpoints(js)
    check("fetch found", by_path(eps, "/api/v1/users") is not None)
    check("fetch method inferred POST", by_path(eps, "/api/v1/users").method == "POST")
    check("axios found w/ method", by_path(eps, "/api/v2/orders/5").method == "GET")
    check("jquery ajax url found", "/rest/settings" in paths(eps))
    check("jquery $.post found POST", by_path(eps, "/api/login").method == "POST")
    check("xhr open found w/ method", by_path(eps, "/api/v1/session").method == "DELETE")


def test_template_literal_normalized():
    js = "const u = `/api/users/${userId}/profile`; fetch(u);"
    eps = extract_endpoints(js)
    check("template param normalized", "/api/users/{param}/profile" in paths(eps), paths(eps))


def test_assets_filtered_out():
    js = "load('/static/app.js'); img('/img/logo.png'); fetch('/api/data');"
    eps = extract_endpoints(js)
    check("asset .js filtered", "/static/app.js" not in paths(eps))
    check("asset .png filtered", "/img/logo.png" not in paths(eps))
    check("api kept", "/api/data" in paths(eps))


def test_no_duplicate_literal_when_method_known():
    js = "fetch('/api/v1/users', {method:'POST'}); const x = '/api/v1/users';"
    eps = extract_endpoints(js)
    hits = [e for e in eps if e.path == "/api/v1/users"]
    check("single entry for method-known path", len(hits) == 1, [(e.method, e.kind) for e in hits])
    check("kept the specific fetch entry", hits[0].kind == "fetch")


def test_bare_literal_surfaced():
    js = "const secret = '/api/internal/flag';"
    eps = extract_endpoints(js)
    e = by_path(eps, "/api/internal/flag")
    check("bare api literal surfaced", e is not None)
    check("bare literal has no method", e and e.method == "")


def test_empty_and_junk():
    check("empty -> []", extract_endpoints("") == [])
    check("no endpoints -> []", extract_endpoints("var x = 1 + 2; console.log('hi');") == [])


def test_recon_integration():
    from deluluscan.recon.engine import ReconEngine
    HOME = ('<html><head><script src="/assets/app.js"></script></head>'
            '<body><script>fetch("/api/inline/ping")</script></body></html>')
    def fetch(url, method="GET", timeout=10):
        if url.endswith("/assets/app.js"):
            return 200, {}, "axios.post('/api/v1/checkout'); $.get('/api/v1/cart');"
        if url.rstrip("/").endswith("t") or url.endswith("/"):
            return 200, {"server": "nginx"}, HOME
        return 404, {}, ""
    prof = ReconEngine(fetch=fetch, crt_fetch=lambda d: [], resolve=lambda h: False).run(
        "http://t/", do_subdomains=False, do_content=False, do_platform=False, do_edge=False)
    got = {e["path"] for e in prof.js_endpoints}
    check("inline JS endpoint found", "/api/inline/ping" in got, got)
    check("linked-bundle endpoints found", {"/api/v1/checkout", "/api/v1/cart"} <= got, got)
    titles = [f.title for f in prof.to_findings()]
    check("shadow-surface INVENTORY finding emitted",
          any("discovered in client JavaScript" in t for t in titles), titles)


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
    print(f"\n{_PASS} passed, {_FAIL} failed")
    raise SystemExit(1 if _FAIL else 0)
