"""Tests for the unified assessment runner + multi-format LOCAL report writer."""
import os, sys, json, tempfile, types
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from deluluscan.assess import Assessment, run_web_assessment, write_reports, to_markdown, to_html, dedup  # noqa: E402
from deluluscan.models import Finding, Severity, VulnClass  # noqa: E402
_PASS = 0; _FAIL = 0
def check(n, c, d=""):
    global _PASS, _FAIL
    if c: _PASS += 1; print(f"PASS  {n}")
    else: _FAIL += 1; print(f"FAIL  {n}  [{d}]")
def F(vc, title, ep, sev=Severity.HIGH):
    return Finding(vuln_class=vc, severity=sev, title=title, endpoint=ep, description="d")

def test_aggregation_and_dedup():
    a = Assessment("https://t/")
    a.add([F(VulnClass.INFO_LEAK, "Exposed: /.git/HEAD", "https://t/.git/HEAD")], "recon")
    a.add([F(VulnClass.INFO_LEAK, "Exposed: /.git/HEAD", "https://t/.git/HEAD"),  # dup
           F(VulnClass.MISCONFIG, "Missing HSTS", "https://t/")], "headers")
    pl = a.payload()
    check("duplicate finding removed", pl["meta"]["finding_count"] == 2, pl["meta"])
    check("payload carries target + modules", pl["meta"]["target"] == "https://t/"
          and "recon" in pl["meta"]["modules"])
    check("findings are dicts", all(isinstance(f, dict) for f in pl["findings"]))

def test_dedup_helper():
    fs = [F(VulnClass.XSS, "X", "/a"), F(VulnClass.XSS, "x ", "/a"), F(VulnClass.XSS, "X", "/b")]
    check("dedup collapses case/space, keeps distinct endpoints", len(dedup(fs)) == 2)

def test_markdown_and_html_render():
    pl = {"meta": {"target": "https://t/", "generated_at": 0},
          "findings": [{"id": "1", "title": "Public S3 bucket", "severity": "high",
                        "vuln_class": "info_leak", "endpoint": "s3://d", "verdict": "true_positive",
                        "confidence": "firm", "exploitability": "exploitable",
                        "description": "Bucket is public.", "detail": {"remediation": "Make private."}}]}
    md = to_markdown(pl)
    check("markdown has title + summary + finding", "# Security Assessment" in md
          and "Public S3 bucket" in md and "| High | 1 |" in md)
    html = to_html(pl)
    check("html contains the finding", "Public S3 bucket" in html)
    check("html is self-contained (no external script/link src)",
          "<script src" not in html and "<link " not in html and "http-equiv" not in html)
    check("remediation rendered", "Make private." in md and "Make private." in html)

def test_write_all_formats_locally():
    pl = {"meta": {"target": "t", "generated_at": 0},
          "findings": [{"id": "1", "title": "T", "severity": "high", "vuln_class": "xss",
                        "endpoint": "/x", "verdict": "true_positive", "confidence": "firm",
                        "exploitability": "conditional", "description": "d", "detail": {}}]}
    d = tempfile.mkdtemp()
    w = write_reports(pl, d, ["json", "md", "html", "csv", "junit", "sarif"])
    for fmt in ["json", "md", "html", "csv", "junit", "sarif"]:
        check(f"{fmt} file written and non-empty",
              fmt in w and os.path.exists(w[fmt]) and os.path.getsize(w[fmt]) > 0, w.get(fmt))
    # json round-trips
    with open(w["json"]) as fh:
        check("json is valid + has findings", json.load(fh)["meta"]["target"] == "t")

def test_unknown_format_raises():
    try:
        write_reports({"findings": [], "meta": {}}, tempfile.mkdtemp(), ["pdf"])
        check("unknown format rejected", False, "no error")
    except ValueError as e:
        check("unknown format rejected", "unknown format" in str(e).lower())

def test_run_web_assessment_merges_modules_offline():
    HTML = ('<html><head><script src="/app.js"></script></head>'
            '<body><script src="/assets/jquery-3.3.1.min.js"></script></body></html>')
    def recon_fetch(url, method="GET"):
        if url.endswith("/.git/HEAD"): return 200, {}, "ref: refs/heads/main"
        if url.rstrip("/").endswith("t") or url.endswith("/"): return 200, {"server": "nginx"}, HTML
        return 404, {}, ""
    def header_fetch(url, extra):
        h = {"content-type": "text/html"}
        if (extra or {}).get("Origin"):
            h["access-control-allow-origin"] = extra["Origin"]; h["access-control-allow-credentials"] = "true"
        return 200, h
    def secret_fetch(url):
        if url.endswith("/app.js"): return 200, 'const K="AKIAIOSFODNN7EXAMPLE";'
        return 200, HTML
    a = run_web_assessment("http://t/", recon_fetch=recon_fetch, header_fetch=header_fetch,
                           secret_fetch=secret_fetch)
    classes = {f.vuln_class.value for f in a.findings}
    check("recon findings merged (info_leak/supply_chain)", "info_leak" in classes or "supply_chain" in classes)
    check("headers CORS reflection merged", any("reflects arbitrary Origin" in f.title for f in a.findings))
    check("secrets from JS merged", any("Exposed secret" in f.title for f in a.findings))
    check("modules recorded", set(["recon", "headers", "secrets"]) <= set(a.modules_run))



def test_netscan_and_passive_merge_offline():
    def netscan_fetch(url, method="GET", timeout=10):
        return 200, {"server": "cloudflare", "cf-ray": "1-EWR"}, "<html>ok</html>"
    def netscan_connect(host, port, timeout=1.5):
        return "-NOAUTH Authentication required.\r\n" if port == 6379 else None
    def passive_fetch(url):
        return 500, {"content-type": "text/html"}, \
            "<b>Fatal error</b>: boom in /var/www/x.php on line <b>3</b>"
    a = run_web_assessment(
        "http://t/", modules=["netscan", "passive"], netscan_ports=True,
        netscan_fetch=netscan_fetch, netscan_connect=netscan_connect,
        passive_fetch=passive_fetch)
    titles = [f.title for f in a.findings]
    check("netscan edge (Cloudflare) merged", any("Cloudflare" in t for t in titles), titles)
    check("netscan dangerous-port (Redis) merged", any("Redis" in t or "6379" in t for t in titles), titles)
    check("passive PHP-error merged", any("PHP error" in t for t in titles), titles)
    check("netscan+passive recorded", {"netscan", "passive"} <= set(a.modules_run), a.modules_run)


def test_crawl_module_merges_with_injected_driver():
    from deluluscan.crawler.browser import RenderedPage, NetworkRequest
    class FakeDriver:
        def render(self, url, timeout=15):
            if url.rstrip("/") == "http://t":
                return RenderedPage(url=url, status=200, links=[],
                                    requests=[NetworkRequest("GET", "http://t/api/v1/profile", "xhr")])
            return RenderedPage(url=url, status=404)
        def close(self): pass
    a = run_web_assessment("http://t/", modules=["crawl"], crawl_driver=FakeDriver())
    check("crawl recorded", "crawl" in a.modules_run, a.modules_run)
    check("dynamic API endpoint surfaced",
          any("observed via dynamic crawl" in f.title for f in a.findings),
          [f.title for f in a.findings])


def test_crawl_module_failsoft_without_driver():
    # No injected driver + Playwright may be absent/unusable at http://t -> fail-soft.
    a = run_web_assessment("http://t/", modules=["crawl"])
    check("crawl module recorded even on failure", "crawl" in a.modules_run, a.modules_run)


def test_assess_includes_sast_and_apispec():
    import tempfile, json as _json
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "app.py"), "w") as fh:
        fh.write("eval(user_input)\nconst=1\n")
    spec_p = os.path.join(d, "openapi.json")
    with open(spec_p, "w") as fh:
        _json.dump({"openapi": "3.0.0", "paths": {"/a": {"post": {"security": []}}}}, fh)
    # modules=[] -> skip live web modules (offline); only sast + apispec run
    a = run_web_assessment("http://t/", modules=[], sast_path=d, spec_path=spec_p)
    check("sast findings included", any(f.detail.get("source") == "sast" for f in a.findings),
          [f.title for f in a.findings])
    check("apispec findings included", any(f.detail.get("rule", "").startswith("spec-") for f in a.findings))
    check("modules recorded sast+apispec", {"sast", "apispec"} <= set(a.modules_run), a.modules_run)
    # merged report exports fine
    pl = a.payload()
    check("payload merges source+contract findings", pl["meta"]["finding_count"] >= 2)




def test_assess_payload_surfaces_attack_chains():
    a = Assessment("http://t/")
    a.add([F(VulnClass.SSRF, "Blind SSRF on fetch", "http://t/f"),
           F(VulnClass.INFO_LEAK, "instance credentials via metadata IMDS", "169.254.169.254")], "recon")
    pl = a.payload()
    check("attack_chains present in meta", isinstance(pl["meta"].get("attack_chains"), list)
          and len(pl["meta"]["attack_chains"]) >= 1, pl["meta"].get("attack_chains"))
    check("chain finding surfaced in report",
          any("Correlated attack chain" in f["title"] for f in pl["findings"]))
    check("chain objective references the agentic engine target",
          "objective" in pl["meta"]["attack_chains"][0])
    # correlation can be disabled
    pl2 = a.payload(correlate_chains=False)
    check("correlation is optional", pl2["meta"]["attack_chains"] == []
          and not any("Correlated attack chain" in f["title"] for f in pl2["findings"]))


if __name__ == "__main__":
    for fn in [v for v in list(globals().values()) if isinstance(v, types.FunctionType) and v.__name__.startswith("test_")]:
        try: fn()
        except Exception as e:
            import traceback; _FAIL += 1; print(f"FAIL  {fn.__name__}  [exc: {e}]"); traceback.print_exc()
    print(f"\n{_PASS}/{_PASS + _FAIL} checks passed"); sys.exit(1 if _FAIL else 0)
