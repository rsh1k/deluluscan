"""Tests for the advanced reconnaissance module (deluluscan/recon/).

Fully offline: fetch/resolve/crt are injected. Locks down web-tech + version
detection, known-vulnerable-library flagging (version comparison), CT-log
subdomain enumeration, content discovery (exposed .git vs 404, admin 401, dedup),
Finding mapping, and the CLI scope gate. Run: python3 -m tests.test_recon
"""
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deluluscan.recon.engine import ReconEngine  # noqa: E402
from deluluscan.recon.signatures import lib_is_vulnerable  # noqa: E402
from deluluscan.models import VulnClass  # noqa: E402

_PASS = 0
_FAIL = 0


def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1; print(f"PASS  {name}")
    else:
        _FAIL += 1; print(f"FAIL  {name}  [{detail}]")


HOME = ('<html><head>'
        '<script src="/assets/jquery-3.3.1.min.js"></script>'
        '<script src="/assets/lodash.min.js"></script>'
        '<meta name="generator" content="WordPress 5.2">'
        '</head><body><div ng-app></div></body></html>')


def make_fetch(pages):
    def fetch(url, method="GET", timeout=10):
        for suffix, resp in pages.items():
            if url.rstrip("/").endswith(suffix.rstrip("/")) or (suffix == "/" and url.endswith("/")):
                return resp
        return 404, {}, "not found"
    return fetch


def test_web_fingerprint_and_versions():
    fetch = make_fetch({"/": (200, {"server": "nginx/1.18.0", "x-powered-by": "PHP/8.1.0"}, HOME)})
    techs = ReconEngine(fetch=fetch).web_fingerprint("http://t/")
    by = {t.name: t for t in techs}
    check("detects jQuery with version", "jQuery" in by and by["jQuery"].version == "3.3.1",
          by.get("jQuery"))
    check("detects nginx server + version", "nginx" in by and by["nginx"].version == "1.18.0")
    check("detects PHP via x-powered-by", "PHP" in by and by["PHP"].version == "8.1.0")
    check("detects WordPress via meta generator", "WordPress" in by)
    check("detects AngularJS via ng-app", "AngularJS" in by)
    check("flags vulnerable jQuery 3.3.1", bool(by["jQuery"].vulnerabilities), by["jQuery"].vulnerabilities)


def test_version_comparison_rules():
    check("jQuery 3.3.1 is flagged", bool(lib_is_vulnerable("jQuery", "3.3.1")))
    check("jQuery 3.6.0 is NOT flagged", not lib_is_vulnerable("jQuery", "3.6.0"))
    check("Lodash 4.17.20 flagged (< 4.17.21)", bool(lib_is_vulnerable("Lodash", "4.17.20")))
    check("Lodash 4.17.21 not flagged", not lib_is_vulnerable("Lodash", "4.17.21"))
    check("AngularJS any version flagged (EOL)", bool(lib_is_vulnerable("AngularJS", "1.8.3")))


def test_subdomain_enumeration():
    eng = ReconEngine(fetch=make_fetch({}),
                      crt_fetch=lambda d: ["www.t.test", "api.t.test", "old.t.test"],
                      resolve=lambda h: h.startswith(("www", "api")))
    subs = eng.enumerate_subdomains("t.test")
    live = [s["name"] for s in subs if s["live"]]
    check("enumerates all CT names", len(subs) == 3)
    check("marks only resolvable ones live", set(live) == {"www.t.test", "api.t.test"}, live)


def test_content_discovery_exposures_and_dedup():
    fetch = make_fetch({
        "/.git/HEAD": (200, {}, "ref: refs/heads/main"),
        "/.env": (404, {}, "nf"),                 # not exposed
        "/admin": (401, {}, "auth"),              # exists but protected -> still interesting
        "/server-status": (200, {}, "Apache Server Status"),
    })
    paths, exposures = ReconEngine(fetch=fetch).content_discovery("http://t")
    ex = {e["path"]: e for e in exposures}
    check("exposed .git (200) is flagged", "/.git/HEAD" in ex)
    check("non-existent .env (404) is NOT flagged", "/.env" not in ex)
    check("protected /admin (401) is surfaced", "/admin" in ex)
    check("server-status (200) flagged", "/server-status" in ex)
    check("/admin is not duplicated", sum(1 for e in exposures if e["path"] == "/admin") == 1)


def test_profile_to_findings_mapping():
    fetch = make_fetch({
        "/": (200, {"server": "nginx"}, HOME),
        "/.git/HEAD": (200, {}, "ref: refs/heads/main"),
        "/admin": (401, {}, "auth"),
    })
    prof = ReconEngine(fetch=fetch, crt_fetch=lambda d: [], resolve=lambda h: False).run(
        "http://t/", domain="t.test", do_subdomains=False)
    findings = prof.to_findings()
    classes = {f.vuln_class for f in findings}
    check("vulnerable lib -> supply_chain finding", VulnClass.SUPPLY_CHAIN in classes)
    check("exposed .git -> info_leak finding", VulnClass.INFO_LEAK in classes)
    check("exposed admin -> misconfig finding", VulnClass.MISCONFIG in classes)
    git = next((f for f in findings if ".git" in f.title), None)
    check("exposed .git graded true_positive/high",
          git and git.verdict == "true_positive" and git.severity.value == "high", git and git.verdict)


def test_cli_scope_gate():
    from deluluscan.recon.__main__ import main
    try:
        main(["--url", "https://example.com/", "--no-subdomains"])
        check("remote target blocked without --allow-remote", False, "no SystemExit")
    except SystemExit as e:
        check("remote target blocked without --allow-remote", "scope" in str(e).lower(), str(e))


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
