"""Offline tests for subdomain-takeover detection."""
from __future__ import annotations

from deluluscan.recon.takeover import classify, check_subdomains, TAKEOVER_SIGS
from deluluscan.recon.engine import ReconEngine
from deluluscan.models import VulnClass, Severity

_PASS = 0
_FAIL = 0


def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1; print(f"PASS  {name}")
    else:
        _FAIL += 1; print(f"FAIL  {name}  {detail}")


def test_classify_providers():
    check("s3 NoSuchBucket", classify("<Error>NoSuchBucket</Error>").provider == "AWS S3")
    check("github pages", classify("There isn't a GitHub Pages site here").provider == "GitHub Pages")
    check("heroku", classify("No such app").provider == "Heroku")
    check("clean page -> None", classify("<html>Welcome home</html>") is None)


def test_cname_corroboration():
    # body matches S3, but CNAME points elsewhere -> the CNAME guard rejects it
    hit = classify("NoSuchBucket", cname="cdn.example.com")
    check("mismatched CNAME rejects S3 match", hit is None, hit and hit.provider)
    hit2 = classify("NoSuchBucket", cname="foo.s3-website-us-east-1.amazonaws.com")
    check("matching CNAME confirms S3", hit2 and hit2.provider == "AWS S3")


def test_check_subdomains_findings():
    subs = [{"name": "gone.example.com", "live": True},
            {"name": "ok.example.com", "live": True},
            {"name": "dead.example.com", "live": False}]  # skipped (not live)
    def fetch(url):
        if "gone.example.com" in url:
            return 404, {}, "<h1>There isn't a GitHub Pages site here.</h1>"
        return 200, {}, "<html>normal site</html>"
    finds = check_subdomains(fetch, subs)
    check("one takeover finding", len(finds) == 1, [f.title for f in finds])
    f = finds[0]
    check("finding names the subdomain", "gone.example.com" in f.title, f.title)
    check("finding is MISCONFIG", f.vuln_class == VulnClass.MISCONFIG)
    check("github pages is tentative -> MEDIUM", f.severity == Severity.MEDIUM, f.severity)
    check("not-live subdomain skipped", not any("dead.example.com" in x.title for x in finds))


def test_firm_provider_is_high():
    subs = [{"name": "s3.example.com", "live": True}]
    def fetch(url):
        return 404, {}, "<Error><Code>NoSuchBucket</Code></Error>"
    finds = check_subdomains(fetch, subs)
    check("S3 takeover HIGH", finds and finds[0].severity == Severity.HIGH, finds and finds[0].severity)
    check("S3 verdict likely_true_positive", finds[0].verdict == "likely_true_positive")


def test_recon_integration():
    def crt(domain):
        return ["gone.example.com", "www.example.com"]
    def fetch(url, method="GET", timeout=10):
        if "gone.example.com" in url:
            return 404, {}, "No such app"   # Heroku
        return 200, {"server": "nginx"}, "<html>ok</html>"
    prof = ReconEngine(fetch=fetch, crt_fetch=crt, resolve=lambda h: True).run(
        "http://www.example.com/", domain="example.com", do_content=False,
        do_platform=False, do_edge=False, do_js=False)
    titles = [f.title for f in prof.to_findings()]
    check("recon surfaces subdomain takeover",
          any("subdomain takeover" in t.lower() for t in titles), titles)


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
    print(f"\n{_PASS} passed, {_FAIL} failed")
    raise SystemExit(1 if _FAIL else 0)
