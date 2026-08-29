"""Offline tests for DNS/email intelligence — injected resolver + AXFR."""
from __future__ import annotations

from deluluscan.recon.dnsintel import DnsIntel
from deluluscan.models import VulnClass, Severity

_PASS = 0; _FAIL = 0
def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond: _PASS += 1; print(f"PASS  {name}")
    else: _FAIL += 1; print(f"FAIL  {name}  {detail}")


def _resolver(table):
    def resolve(name, rtype): return table.get((name, rtype), [])
    return resolve

def titles(f): return {x.title for x in f}


def test_missing_spf_dmarc():
    di = DnsIntel(resolve=_resolver({("x.test", "TXT"): [], ("x.test", "NS"): [],
                                     ("x.test", "A"): ["1.2.3.4"]}), axfr=lambda d, n: None)
    prof, finds = di.run("x.test", try_axfr=False)
    t = titles(finds)
    check("missing SPF flagged", "No SPF record" in t, t)
    check("missing DMARC flagged", "No DMARC record" in t, t)


def test_weak_spf_and_dmarc():
    di = DnsIntel(resolve=_resolver({
        ("x.test", "TXT"): ["v=spf1 +all"], ("x.test", "NS"): [],
        ("_dmarc.x.test", "TXT"): ["v=DMARC1; p=none"]}), axfr=lambda d, n: None)
    prof, finds = di.run("x.test", try_axfr=False)
    t = titles(finds)
    check("SPF +all flagged MEDIUM",
          any("SPF allows any sender" in x.title and x.severity == Severity.MEDIUM for x in finds), t)
    check("DMARC p=none flagged", any("monitor-only" in x.title for x in finds), t)


def test_zone_transfer():
    di = DnsIntel(resolve=_resolver({("x.test", "NS"): ["ns1.x.test"], ("x.test", "TXT"): ["v=spf1 -all"],
                                     ("_dmarc.x.test", "TXT"): ["v=DMARC1; p=reject"]}),
                  axfr=lambda d, ns: ["@ SOA ns1", "admin A 10.0.0.5", "vpn A 10.0.0.9"])
    prof, finds = di.run("x.test")
    axfr = next((x for x in finds if "zone transfer" in x.title.lower()), None)
    check("AXFR flagged HIGH", axfr and axfr.severity == Severity.HIGH, axfr and axfr.severity)
    check("AXFR is true_positive", axfr and axfr.verdict == "true_positive")
    check("AXFR record count", axfr and axfr.detail["record_count"] == 3)
    check("no spf/dmarc findings when strong", not any(x.title in ("No SPF record", "No DMARC record")
          for x in finds))


def test_email_harvest():
    di = DnsIntel(resolve=_resolver({("x.test", "TXT"): ["v=spf1 -all"],
                                     ("_dmarc.x.test", "TXT"): ["v=DMARC1; p=reject"]}),
                  axfr=lambda d, n: None)
    prof, finds = di.run("x.test", page_body="reach us: admin@x.test and sales@x.test", try_axfr=False)
    em = next((x for x in finds if "email address" in x.title), None)
    check("emails harvested", em and set(prof.emails) == {"admin@x.test", "sales@x.test"}, prof.emails)
    check("email finding is INFO", em and em.severity == Severity.INFO)


def test_recon_integration():
    from deluluscan.recon.engine import ReconEngine
    def fetch(url, method="GET", timeout=10):
        return 200, {"server": "nginx"}, "<html>mail us at hi@example.com</html>"
    di_resolve = _resolver({("example.com", "TXT"): [], ("example.com", "NS"): [],
                            ("example.com", "A"): ["1.1.1.1"]})
    eng = ReconEngine(fetch=fetch, crt_fetch=lambda d: [], resolve=lambda h: True)
    prof = eng.run("http://example.com/", domain="example.com", do_content=False,
                   do_platform=False, do_edge=False, do_js=False, do_subdomains=False,
                   dns_resolve=di_resolve, dns_axfr=lambda d, n: None)
    t = [f.title for f in prof.to_findings()]
    check("recon surfaces DNS findings", any("SPF" in x or "DMARC" in x for x in t), t)


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
    print(f"\n{_PASS} passed, {_FAIL} failed")
    raise SystemExit(1 if _FAIL else 0)
