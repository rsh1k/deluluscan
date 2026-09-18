"""Offline tests for subdomain-takeover detection."""
from __future__ import annotations

from deluluscan.recon.takeover import (classify, check_subdomains, TAKEOVER_SIGS,
                                       provider_for_cname, check_dangling, check_all)
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


def test_provider_for_cname():
    check("s3 cname -> AWS S3",
          provider_for_cname("victim.s3.amazonaws.com").provider == "AWS S3")
    check("heroku cname -> Heroku",
          provider_for_cname("victim.herokudns.com").provider == "Heroku")
    check("unknown cname -> None", provider_for_cname("cdn.acme.com") is None)


def test_check_dangling():
    subs = ["blog.example.com", "app.example.com", "ok.example.com", "plain.example.com"]
    cnames = {
        "blog.example.com": "old-bucket.s3.amazonaws.com",   # known service, dead
        "app.example.com": "removed.internal-vendor.net",     # generic, dead
        "ok.example.com": "live-bucket.s3.amazonaws.com",     # known service, still resolves
        "plain.example.com": "",                              # no CNAME (A record)
    }
    dead = {"old-bucket.s3.amazonaws.com", "removed.internal-vendor.net"}
    finds = check_dangling(subs,
                           resolve_cname=lambda h: cnames.get(h, ""),
                           resolve_host=lambda h: h not in dead)
    by_sub = {f.detail["subdomain"]: f for f in finds}
    check("dead known-service CNAME -> finding", "blog.example.com" in by_sub, list(by_sub))
    check("dead S3 CNAME is HIGH+firm",
          by_sub["blog.example.com"].severity == Severity.HIGH and
          by_sub["blog.example.com"].confidence == "firm")
    check("dead S3 finding names provider",
          by_sub["blog.example.com"].detail.get("provider") == "AWS S3")
    check("generic dead CNAME -> MEDIUM+tentative",
          "app.example.com" in by_sub and by_sub["app.example.com"].severity == Severity.MEDIUM
          and by_sub["app.example.com"].confidence == "tentative")
    check("live CNAME target -> no finding", "ok.example.com" not in by_sub)
    check("no CNAME -> no finding", "plain.example.com" not in by_sub)


def test_check_all_combines_and_dedups():
    subs = [{"name": "fp.example.com", "live": True}, "dangle.example.com"]
    def fetch(url):
        if "fp.example.com" in url:
            return 404, {}, "There isn't a GitHub Pages site here."
        return 0, {}, ""                                   # dangle: no live response
    cnames = {"fp.example.com": "victim.github.io", "dangle.example.com": "gone.herokudns.com"}
    finds = check_all(fetch, subs,
                      resolve_cname=lambda h: cnames.get(h, ""),
                      resolve_host=lambda h: False)         # both targets dead
    subs_hit = {f.detail["subdomain"] for f in finds}
    check("check_all surfaces the fingerprint takeover", "fp.example.com" in subs_hit, subs_hit)
    check("check_all surfaces the dangling takeover", "dangle.example.com" in subs_hit, subs_hit)
    check("no subdomain double-reported",
          len(finds) == len({f.detail["subdomain"] for f in finds}), [f.title for f in finds])


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
    print(f"\n{_PASS} passed, {_FAIL} failed")
    raise SystemExit(1 if _FAIL else 0)
