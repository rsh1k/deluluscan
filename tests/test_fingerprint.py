"""Tests for the technology fingerprinting engine."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deluluscan.fingerprint import fingerprint, default_file_probes

_PASS = 0
_FAIL = 0


def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1; print(f"PASS  {name}")
    else:
        _FAIL += 1; print(f"FAIL  {name}  [{detail}]")


class R:
    def __init__(self, headers, body="", url=""):
        self.resp_headers = headers; self.resp_body = body; self.url = url





def test_detects_stack_server_and_waf():
    fp = fingerprint([R({"Server": "nginx", "CF-Ray": "x"}, "", "http://t/")])
    techs = set(fp.techs())
    check("detects nginx + Cloudflare from headers", {"nginx", "Cloudflare"} <= techs, str(techs))




def test_no_false_positive_on_bland_response():
    fp = fingerprint([R({"Content-Type": "text/html"}, "<html><body>hello</body></html>", "http://t/")])
    # should not hallucinate a CMS/framework from nothing
    cms = [d for d in fp.detections if d.category in ("cms", "framework")]
    check("no CMS/framework hallucinated from a bland page", cms == [], str([d.tech for d in cms]))


def test_non_target_cms_not_detected():
    # WordPress markers must NOT produce a detection — this is a target-only tool
    fp = fingerprint([R({"X-Powered-By": "PHP/8.1"},
                        '<meta name="generator" content="WordPress 6.4.2"/>wp-content', "http://t/")])
    check("WordPress/PHP are no longer detected (target-only build)",
          not any(d.tech in ("WordPress", "PHP", "Drupal", "Joomla", "Magento") for d in fp.detections),
          str([d.tech for d in fp.detections]))


def test_graphql_and_openapi_api_styles():
    fp = fingerprint([R({}, "", "http://t/graphql")], extra_paths=["/openapi.json"])
    techs = set(fp.techs())
    check("GraphQL + OpenAPI API styles detected from paths", {"GraphQL", "OpenAPI / Swagger"} <= techs, str(techs))


def test_default_file_probes_nonempty():
    probes = default_file_probes()
    check("default-file probe list is populated and de-duplicated",
          len(probes) >= 1 and len(probes) == len(set(p for _, p in probes)), str(probes[:3]))


if __name__ == "__main__":
    for fn in list(globals().values()):
        if callable(fn) and getattr(fn, "__name__", "").startswith("test_"):
            try:
                fn()
            except Exception as e:
                _FAIL += 1
                print(f"FAIL  {fn.__name__}  [exception: {e}]")
    print(f"\n{_PASS}/{_PASS + _FAIL} checks passed")
    sys.exit(1 if _FAIL else 0)
