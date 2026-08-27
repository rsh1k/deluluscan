"""Tests for HTTP security-header / CORS / cookie analysis (deluluscan/headers/)."""
import os, sys, types
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from deluluscan.headers import analyze_all, check_cors, check_cookies, HeaderScan  # noqa: E402
from deluluscan.models import VulnClass  # noqa: E402
_PASS = 0; _FAIL = 0
def check(n, c, d=""):
    global _PASS, _FAIL
    if c: _PASS += 1; print(f"PASS  {n}")
    else: _FAIL += 1; print(f"FAIL  {n}  [{d}]")
def titles(fs): return {f.title for f in fs}

def test_insecure_response_flags_everything():
    h = {"content-type": "text/html", "server": "Apache/2.4.29",
         "set-cookie": "SESSIONID=abc; Path=/"}
    t = titles(analyze_all(200, h, "https://t/"))
    for e in ["Missing Content-Security-Policy", "Missing HSTS",
              "Missing X-Content-Type-Options: nosniff", "Missing clickjacking protection",
              "Version disclosure via server", "Insecure cookie flags: SESSIONID"]:
        check(f"flags: {e}", e in t, t)

def test_hardened_response_is_clean():
    h = {"content-type": "text/html",
         "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
         "strict-transport-security": "max-age=31536000; includeSubDomains",
         "x-content-type-options": "nosniff", "referrer-policy": "no-referrer",
         "set-cookie": "SID=x; Secure; HttpOnly; SameSite=Lax"}
    check("hardened response yields no findings", analyze_all(200, h, "https://t/") == [], 
          [f.title for f in analyze_all(200, h, "https://t/")])

def test_cors_reflection_with_credentials_is_high():
    fs = check_cors({}, {"sent_origin": "https://evil.example",
                         "acao": "https://evil.example", "acac": "true"}, "https://t/")
    check("reflected origin + credentials flagged", any("reflects arbitrary Origin" in f.title for f in fs))
    f = fs[0]
    check("graded high/exploitable/true_positive",
          f.severity.value == "high" and f.exploitability == "exploitable" and f.verdict == "true_positive")

def test_cors_wildcard_credentials():
    fs = check_cors({"access-control-allow-origin": "*", "access-control-allow-credentials": "true"}, None, "https://t/")
    check("wildcard+credentials flagged", any("wildcard with credentials" in f.title for f in fs))

def test_cors_null_origin():
    fs = check_cors({}, {"sent_origin": "x", "acao": "null", "acac": "true"}, "https://t/")
    check("null origin + credentials flagged", any("null" in f.title for f in fs))

def test_cookie_list_and_session_grading():
    fs = check_cookies({"set-cookie": ["JWT=x; Path=/", "theme=dark; Secure; HttpOnly; SameSite=Lax"]}, "https://t/")
    check("session-like cookie without flags flagged medium",
          any(f.title == "Insecure cookie flags: JWT" and f.severity.value == "medium" for f in fs))
    check("fully-flagged benign cookie not flagged", not any("theme" in f.title for f in fs))

def test_engine_cors_probe_via_fetch():
    def fetch(url, extra):
        base = {"content-type": "application/json"}
        if (extra or {}).get("Origin"):
            base["access-control-allow-origin"] = extra["Origin"]
            base["access-control-allow-credentials"] = "true"
        return 200, base
    fs = HeaderScan().scan(fetch, "https://t/api")
    check("engine detects reflected-origin CORS via its probe",
          any("reflects arbitrary Origin" in f.title for f in fs), [f.title for f in fs])

def test_cli_scope_gate():
    from deluluscan.headers.__main__ import main
    try:
        main(["--url", "https://example.com/"]); check("remote blocked", False, "no SystemExit")
    except SystemExit as e:
        check("remote blocked without --allow-remote", "scope" in str(e).lower(), str(e))

if __name__ == "__main__":
    for fn in [v for v in list(globals().values()) if isinstance(v, types.FunctionType) and v.__name__.startswith("test_")]:
        try: fn()
        except Exception as e:
            import traceback; _FAIL += 1; print(f"FAIL  {fn.__name__}  [exc: {e}]"); traceback.print_exc()
    print(f"\n{_PASS}/{_PASS + _FAIL} checks passed"); sys.exit(1 if _FAIL else 0)
