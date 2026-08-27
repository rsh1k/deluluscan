"""Offline tests for platform intelligence — a synthetic fetch serves canned
responses so identify()/assess() run with no network."""
from __future__ import annotations

from deluluscan.platforms import PlatformScan, PROFILES, profile_by_name
from deluluscan.models import VulnClass, Severity

_PASS = 0
_FAIL = 0


def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1
        print(f"PASS  {name}")
    else:
        _FAIL += 1
        print(f"FAIL  {name}  {detail}")


def make_fetch(routes: dict):
    """routes: {path -> (status, headers, body)}; default 404."""
    def fetch(url, method="GET", timeout=10):
        # strip scheme+host
        path = "/" + url.split("://", 1)[-1].split("/", 1)[1] if "://" in url else url
        for p, resp in routes.items():
            if path == p or path.rstrip("/") == p.rstrip("/"):
                return resp
        return (404, {}, "not found")
    return fetch


# ---- WordPress: fingerprint + user enum + xmlrpc -------------------------
def test_wordpress():
    routes = {
        "/wp-login.php": (200, {}, "<html>Log In</html>"),
        "/wp-json/": (200, {"content-type": "application/json"},
                      '{"namespaces":["wp/v2"],"description":"WordPress 6.4.2 site"}'),
        "/": (200, {"x-pingback": "https://t/xmlrpc.php"},
              '<html><meta name="generator" content="WordPress 6.4.2">'
              '<link href="/wp-content/themes/x/style.css"></html>'),
        "/wp-json/wp/v2/users": (200, {}, '[{"id":1,"name":"admin","slug":"admin"},'
                                          '{"id":2,"name":"editor","slug":"editor"}]'),
        "/xmlrpc.php": (200, {}, "XML-RPC server accepts POST requests only."),
    }
    scan = PlatformScan(fetch=make_fetch(routes))
    det, findings = scan.run("http://t")
    check("wp detected", det and det.profile.name == "WordPress", det and det.profile.name)
    check("wp firm+", det and det.score >= 4, det and det.score)
    titles = [f.title for f in findings]
    check("wp user-enum finding", any("user enumeration" in t for t in titles), titles)
    enum = next((f for f in findings if "user enumeration" in f.title), None)
    check("wp enum names captured", enum and "admin" in enum.detail.get("users_sample", []),
          enum and enum.detail.get("users_sample"))
    check("wp enum is INFO_LEAK", enum and enum.vuln_class == VulnClass.INFO_LEAK)
    check("wp xmlrpc finding", any("xmlrpc" in f.endpoint for f in findings), titles)
    check("wp knows API base", det and det.profile.api_base == "/wp-json")
    check("wp knows auth", det and "cookie" in det.profile.auth_methods)


# ---- Drupal: CHANGELOG version + jsonapi user enum -----------------------
def test_drupal():
    routes = {
        "/CHANGELOG.txt": (200, {}, "\nDrupal 9.5.11, 2023-06-07\n-----------\n"),
        "/jsonapi": (200, {}, '{"jsonapi":{"version":"1.0"},"data":[]}'),
        "/user/login": (200, {}, "<form>login</form>"),
        "/": (200, {"x-generator": "Drupal 9 (https://www.drupal.org)"},
              '<html><link href="/sites/default/files/css/x.css"></html>'),
        "/jsonapi/user/user": (200, {}, '{"data":[{"attributes":{"name":"webadmin","display_name":"Web Admin"}}]}'),
    }
    scan = PlatformScan(fetch=make_fetch(routes))
    det, findings = scan.run("http://t")
    check("drupal detected", det and det.profile.name == "Drupal", det and det.profile.name)
    titles = [f.title for f in findings]
    check("drupal version finding", any("version disclosure" in t for t in titles), titles)
    ver = next((f for f in findings if "version disclosure" in f.title), None)
    check("drupal version value", ver and ver.detail.get("version") == "9.5.11",
          ver and ver.detail.get("version"))
    check("drupal user-enum", any("user enumeration" in t for t in titles), titles)


# ---- No platform: nothing detected, no findings --------------------------
def test_unknown():
    routes = {"/": (200, {}, "<html>plain static site</html>")}
    scan = PlatformScan(fetch=make_fetch(routes))
    det, findings = scan.run("http://t")
    check("unknown -> no detection", det is None, det)
    check("unknown -> no findings", findings == [], findings)


# ---- Cloud hosting header fingerprint ------------------------------------
def test_cloud_hosting():
    routes = {"/": (200, {"server": "AmazonS3", "x-amz-request-id": "ABC123",
                          "via": "1.1 abc.cloudfront.net (CloudFront)"}, "<html></html>")}
    scan = PlatformScan(fetch=make_fetch(routes))
    det, findings = scan.run("http://t")
    check("aws hosting detected", det and det.profile.name.startswith("AWS"), det and det.profile.name)
    check("aws category hosting", det and det.profile.category == "hosting")


# ---- Profiles are well-formed --------------------------------------------
def test_profiles_wellformed():
    check("profiles present", len(PROFILES) >= 5, len(PROFILES))
    for p in PROFILES:
        check(f"{p.name} has signals", len(p.signals) > 0)
        for c in p.relevant_classes:
            check(f"{p.name} class {c} valid", c in {v.value for v in VulnClass}, c)
    check("profile_by_name works", profile_by_name("WordPress") is not None)
    check("profile_by_name miss", profile_by_name("Nope") is None)


def test_spring_boot_actuator():
    routes = {
        "/actuator": (200, {}, '{"_links":{"health":{"href":"/actuator/health"}}}'),
        "/actuator/health": (200, {}, '{"status":"UP"}'),
        "/actuator/env": (200, {}, '{"propertySources":[{"name":"systemEnvironment"}]}'),
        "/actuator/heapdump": (200, {}, "JAVA PROFILE 1.0.1 binary heap dump ..."),
        "/actuator/mappings": (404, {}, "nf"),
        "/": (200, {}, "Whitelabel Error Page"),
    }
    scan = PlatformScan(fetch=make_fetch(routes))
    det, findings = scan.run("http://t")
    check("spring detected", det and det.profile.name.startswith("Spring"), det and det.profile.name)
    titles = [f.title for f in findings]
    check("spring heapdump critical", any("heapdump" in t for t in titles), titles)
    hd = next((f for f in findings if "heapdump" in f.title), None)
    check("heapdump graded critical", hd and hd.severity == Severity.CRITICAL, hd and hd.severity)
    check("spring env finding", any("/actuator/env" in f.endpoint for f in findings), titles)


def test_jenkins_script_console():
    routes = {
        "/": (200, {"x-jenkins": "2.426.1"}, "Jenkins ver. 2.426.1 Dashboard [Jenkins]"),
        "/script": (200, {}, "<form>Groovy script console</form>"),
    }
    scan = PlatformScan(fetch=make_fetch(routes))
    det, findings = scan.run("http://t")
    check("jenkins detected", det and det.profile.name == "Jenkins", det and det.profile.name)
    sc = next((f for f in findings if "/script" in f.endpoint), None)
    check("jenkins script console critical", sc and sc.severity == Severity.CRITICAL, sc and sc.severity)
    ver = next((f for f in findings if "version" in f.title), None)
    check("jenkins version", ver and ver.detail.get("version") == "2.426.1", ver and ver.detail.get("version"))


def test_elasticsearch_open():
    routes = {
        "/": (200, {}, '{"cluster_name":"prod","version":{"number":"7.17.0","lucene_version":"8.11.1"}}'),
        "/_cat/indices": (200, {}, "green open users ..."),
        "/_nodes": (200, {}, '{"nodes":{}}'),
    }
    scan = PlatformScan(fetch=make_fetch(routes))
    det, findings = scan.run("http://t")
    check("elasticsearch detected", det and det.profile.name == "Elasticsearch", det and det.profile.name)
    idx = next((f for f in findings if "_cat/indices" in f.endpoint), None)
    check("es indices critical", idx and idx.severity == Severity.CRITICAL, idx and idx.severity)
    check("es version", any("version disclosure" in f.title for f in findings))


def test_control_surface_protected():
    # A 401/403 on an exposed_check is an INFO "present but protected", not a hit.
    routes = {
        "/": (200, {"x-jenkins": "2.4"}, "Jenkins ver. 2.4"),
        "/script": (403, {}, "forbidden"),
    }
    scan = PlatformScan(fetch=make_fetch(routes))
    det, findings = scan.run("http://t")
    sc = next((f for f in findings if "/script" in f.endpoint), None)
    check("protected surface -> INFO", sc and sc.severity == Severity.INFO, sc and sc.severity)
    check("protected surface tentative", sc and sc.confidence == "tentative")


if __name__ == "__main__":
    test_wordpress()
    test_drupal()
    test_unknown()
    test_cloud_hosting()
    test_spring_boot_actuator()
    test_jenkins_script_console()
    test_elasticsearch_open()
    test_control_surface_protected()
    test_profiles_wellformed()
    print(f"\n{_PASS} passed, {_FAIL} failed")
    raise SystemExit(1 if _FAIL else 0)
