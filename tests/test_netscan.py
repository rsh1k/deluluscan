"""Offline tests for edge/network recon — injected fetch + connect, no network."""
from __future__ import annotations

from deluluscan.netscan import NetScan, WafScan, PortScan
from deluluscan.netscan import honeypot
from deluluscan.models import VulnClass, Severity

_PASS = 0
_FAIL = 0


def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1; print(f"PASS  {name}")
    else:
        _FAIL += 1; print(f"FAIL  {name}  {detail}")


# ---- WAF/CDN passive: Cloudflare via cf-ray + server + cookie ------------
def test_cloudflare_passive():
    def fetch(url, method="GET", timeout=10):
        return (200, {"server": "cloudflare", "cf-ray": "8abc123-EWR",
                      "cf-cache-status": "HIT",
                      "set-cookie": "__cf_bm=xyz; path=/"}, "<html>hi</html>")
    edges = WafScan(fetch=fetch).detect("http://t", active=False)
    cf = next((e for e in edges if e.name == "Cloudflare"), None)
    check("cloudflare detected", cf is not None, [e.name for e in edges])
    check("cloudflare multi-signal confirmed", cf and cf.confidence == "confirmed",
          cf and (cf.score, cf.confidence))
    check("cloudflare kind both", cf and cf.kind == "both")


# ---- WAF active block probe: clean 200, malicious 403 block page ---------
def test_active_block_detection():
    def fetch(url, method="GET", timeout=10):
        if "deluluscan_waf_probe" in url:
            return (403, {"server": "nginx"},
                    "<html>Request blocked by Web Application Firewall</html>")
        return (200, {"server": "nginx"}, "<html>ok</html>")
    edges = WafScan(fetch=fetch).detect("http://t", active=True)
    blocking = [e for e in edges if e.blocking]
    check("active probe flagged blocking WAF", len(blocking) >= 1, [e.name for e in edges])


# ---- Imperva via x-iinfo + incap cookie ----------------------------------
def test_imperva():
    def fetch(url, method="GET", timeout=10):
        return (200, {"x-iinfo": "9-12345-12345 NNNN",
                      "set-cookie": "visid_incap_123=abc; incap_ses_1=def"}, "ok")
    edges = WafScan(fetch=fetch).detect("http://t", active=False)
    check("imperva detected", any(e.name == "Imperva Incapsula" for e in edges),
          [e.name for e in edges])


# ---- Port scan + dangerous-service finding (Redis, Docker API) -----------
def test_ports_and_dangerous():
    banners = {6379: "-NOAUTH Authentication required.\r\n",
               2375: "HTTP/1.1 200 OK\r\n", 22: "SSH-2.0-OpenSSH_9.2\r\n"}
    def connect(host, port, timeout=1.5):
        return banners.get(port)  # None => closed
    res = PortScan(connect=connect).scan("t", ports=(22, 80, 6379, 2375, 3306))
    open_ports = {p.port for p in res}
    check("open ports found", open_ports == {22, 6379, 2375}, open_ports)
    redis = next((p for p in res if p.port == 6379), None)
    check("redis service id", redis and redis.service == "redis", redis and redis.service)
    check("redis flagged dangerous", redis and redis.dangerous, redis and redis.dangerous)
    check("ssh banner captured", any(p.port == 22 and "OpenSSH" in p.banner for p in res))


# ---- Honeypot heuristics: known banner + multi-service spread ------------
def test_honeypot():
    leads = honeypot.assess(banners=["SSH-2.0-OpenSSH_5.1p1 Debian-5"], open_ports=[22])
    check("cowrie banner lead", any("Cowrie" in l.matched for l in leads), leads)
    many = honeypot.assess(open_ports=[21, 22, 23, 445, 1433, 3306, 6379, 9200, 27017])
    check("multi-service honeypot lead", any("honeypot" in l.reason.lower() for l in many),
          [l.reason for l in many])
    check("honeypot always tentative", all(l.confidence == "tentative" for l in leads + many))


# ---- IDS/IPS inference: clean ok, malicious dropped (status 0) -----------
def test_ids_ips_inference():
    def fetch(url, method="GET", timeout=10):
        if "DROP" in url:            # urlencoded malicious probe (space -> +)
            return (0, {}, "")       # connection dropped
        if "deluluscan_waf_probe" in url:
            return (200, {}, "ok")
        return (200, {"server": "x"}, "ok")
    scan = NetScan(fetch=fetch, connect=lambda h, p, t=1.5: None)
    prof = scan.run("http://t", do_ports=False)
    check("ids/ips inline drop inferred", prof.ids_ips and prof.ids_ips["inline_drop_observed"],
          prof.ids_ips)
    findings = scan.to_findings(prof)
    check("ids/ips finding emitted", any("IDS/IPS" in f.title for f in findings),
          [f.title for f in findings])


# ---- End-to-end findings shape -------------------------------------------
def test_findings_shape():
    def fetch(url, method="GET", timeout=10):
        return (200, {"server": "cloudflare", "cf-ray": "1-EWR"}, "ok")
    def connect(host, port, timeout=1.5):
        return "-NOAUTH\r\n" if port == 6379 else None
    scan = NetScan(fetch=fetch, connect=connect)
    prof = scan.run("http://t", ports=(6379, 80))
    findings = scan.to_findings(prof)
    titles = [f.title for f in findings]
    check("edge finding present", any("Cloudflare" in t for t in titles), titles)
    check("dangerous-port finding present", any("Redis" in t or "6379" in t for t in titles), titles)
    check("all findings have detail.source", all(f.detail.get("source") for f in findings))
    check("profile round-trips to_dict", isinstance(prof.to_dict(), dict))


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
    print(f"\n{_PASS} passed, {_FAIL} failed")
    raise SystemExit(1 if _FAIL else 0)
