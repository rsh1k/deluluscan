"""Software-composition analysis: manifest + classpath + advisories.

The discipline under test is the one that separates a real finding from a false
alarm, measured on the target build 1.2.3:
  * the manifest declares jdom 1.1.3 (XXE) but the image ships the FIXED
    jdom2-2.0.6.1 -> must NOT be reported;
  * the image ships poi-3.17 BESIDE poi-5.5.1 -> the vulnerable copy really is
    loadable, so it MUST be reported, and the duplication called out.
Fully offline: the advisory database is injected.

Run: python3 -m tests.test_sca
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

from deluluscan import sca
from deluluscan.models import Endpoint, Severity, VulnClass
from deluluscan.scanners.dependency_scanner import DependencyScanner

_checks = 0
_failures: list[str] = []


def check(label, cond, detail=""):
    global _checks
    _checks += 1
    print(f"{'PASS' if cond else 'FAIL'}  {label}" + (f"  [{detail}]" if not cond else ""))
    if not cond:
        _failures.append(label)


POM = """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <properties><netty.version>4.1.118.Final</netty.version></properties>
  <dependencies>
    <dependency><groupId>org.jdom</groupId><artifactId>jdom</artifactId>
      <version>1.1.3</version></dependency>
    <dependency><groupId>org.apache.poi</groupId><artifactId>poi</artifactId>
      <version>3.17</version></dependency>
    <dependency><groupId>io.netty</groupId><artifactId>netty-handler</artifactId>
      <version>${netty.version}</version></dependency>
    <dependency><groupId>junit</groupId><artifactId>junit</artifactId>
      <version>4.12</version><scope>test</scope></dependency>
    <dependency><groupId>com.x</groupId><artifactId>unresolved</artifactId>
      <version>${nope.version}</version></dependency>
  </dependencies>
</project>
"""


def _root():
    d = tempfile.mkdtemp(prefix="sca_")
    with open(os.path.join(d, "pom.xml"), "w") as fh:
        fh.write(POM)
    os.makedirs(os.path.join(d, "ui"), exist_ok=True)
    with open(os.path.join(d, "ui", "package.json"), "w") as fh:
        json.dump({"dependencies": {"lodash": "^4.17.20"}}, fh)
    return d


def test_maven_parsing():
    deps = {d.name: d for d in sca.parse_maven(_root())}
    check("resolves a ${property} version",
          deps.get("io.netty:netty-handler") and
          deps["io.netty:netty-handler"].version == "4.1.118.Final",
          str(sorted(deps)))
    check("test-scoped dependencies are excluded (not shipped)",
          "junit:junit" not in deps, str(sorted(deps)))
    check("an unresolvable ${property} is skipped, never guessed",
          "com.x:unresolved" not in deps, str(sorted(deps)))


def test_npm_parsing():
    deps = {d.name: d for d in sca.parse_npm(_root())}
    check("npm range spec is normalised to a version",
          deps.get("lodash") and deps["lodash"].version == "4.17.20",
          str({k: v.version for k, v in deps.items()}))


def test_jar_name_parsing():
    from deluluscan.sca import _JAR_RE
    cases = {"jdom-1.1.3.jar": ("jdom", "1.1.3"),
             "netty-handler-4.1.118.Final.jar": ("netty-handler", "4.1.118.Final"),
             "poi-ooxml-5.5.1.jar": ("poi-ooxml", "5.5.1")}
    ok = all((_JAR_RE.match(k) and
              (_JAR_RE.match(k).group("name"), _JAR_RE.match(k).group("version").rstrip("."))
              == v) for k, v in cases.items())
    check("jar filenames split into artifact + version", ok, str(cases))


def _fixture():
    """Two real shapes from the target build 1.2.3:
      * poi 3.17 IS on the classpath (beside poi 5.5.1) -> report it;
      * the declared `jdom` artifact is ABSENT from this classpath, which only
        carries jdom2 2.0.6.1 -> reporting it would be a false alarm.
    (In the real image jdom-1.1.3.jar IS present, so it is correctly reported
    there; this fixture exercises the absent case.)"""
    declared = [sca.Dependency("org.jdom:jdom", "1.1.3"),
                sca.Dependency("org.apache.poi:poi", "3.17")]
    shipped = [sca.Dependency("jdom2", "2.0.6.1", source="classpath"),
               sca.Dependency("poi", "3.17", source="classpath"),
               sca.Dependency("poi", "5.5.1", source="classpath")]
    hits = {"org.jdom:jdom@1.1.3": ["GHSA-jdom"],
            "org.apache.poi:poi@3.17": ["GHSA-poi"]}
    details = {
        "GHSA-jdom": {"database_specific": {"severity": "HIGH"},
                      "aliases": ["CVE-2021-33813"], "summary": "XXE in JDOM",
                      "affected": [{"ranges": [{"events": [{"fixed": "2.0.6.1"}]}]}]},
        "GHSA-poi": {"database_specific": {"severity": "HIGH"},
                     "aliases": ["CVE-2019-12415"], "summary": "XXE in POI",
                     "affected": [{"ranges": [{"events": [{"fixed": "4.1.1"}]}]}]},
    }
    return declared, shipped, hits, details


def test_classpath_overrides_the_manifest():
    declared, shipped, hits, details = _fixture()
    out = sca.correlate(declared, shipped, hits, details)
    names = {h.dep.name for h in out}
    check("an artifact absent from the classpath is NOT reported",
          "org.jdom:jdom" not in names, str(names))
    check("an artifact confirmed on the classpath IS reported",
          "org.apache.poi:poi" in names, str(names))
    poi = [h for h in out if h.dep.name == "org.apache.poi:poi"][0]
    check("confirmed-shipped is flagged as such", poi.shipped is True, str(poi.shipped))
    check("severity + CVE + fix version are carried through",
          poi.severity == "HIGH" and poi.cves == ["CVE-2019-12415"]
          and poi.fixed_in == ["4.1.1"], f"{poi.severity} {poi.cves} {poi.fixed_in}")


def test_manifest_only_is_downgraded_not_dropped():
    declared, _shipped, hits, details = _fixture()
    out = sca.correlate(declared, [], hits, details)   # no classpath view at all
    check("with no classpath view, manifest findings survive",
          len(out) == 2, str(len(out)))
    check("...but are marked not-confirmed-shipped",
          all(h.shipped is False for h in out), str([h.shipped for h in out]))


def test_duplicate_artifacts_detected():
    _d, shipped, _h, _x = _fixture()
    dupes = sca.duplicate_artifacts(shipped)
    check("an artifact shipping at two versions is flagged",
          dupes.get("poi") == ["3.17", "5.5.1"], str(dupes))
    check("single-version artifacts are not flagged", "jdom2" not in dupes, str(dupes))


def test_scanner_emits_graded_findings():
    class _Cfg:
        source_root = _root()
        class _Obs:
            container = ""          # no container -> manifest-only path
            docker_path = "docker"
        observe = _Obs()

    def fake_osv(url, payload):
        if "querybatch" in url:
            res = []
            for q in payload["queries"]:
                nm = f"{q['package']['name']}@{q['version']}"
                res.append({"vulns": [{"id": "GHSA-x"}]} if "jdom" in nm else {})
            return {"results": res}
        return {"database_specific": {"severity": "HIGH"},
                "aliases": ["CVE-2021-33813"], "summary": "XXE in JDOM",
                "affected": [{"ranges": [{"events": [{"fixed": "2.0.6.1"}]}]}]}

    sc = DependencyScanner(None, None, _Cfg(), {}, osv_fetch=fake_osv)
    ep = Endpoint(method="GET", path="/")
    check("scanner applies when a source root is configured", sc.applies_to(ep) is True, "")
    fs = list(sc.run(ep))
    check("emits a supply-chain finding for the vulnerable dependency",
          len(fs) == 1 and fs[0].vuln_class == VulnClass.SUPPLY_CHAIN,
          str([(f.vuln_class, f.title) for f in fs]))
    if fs:
        check("manifest-only evidence is graded tentative/unverified (not asserted)",
              fs[0].confidence == "tentative" and fs[0].verdict == "unverified",
              f"{fs[0].confidence}/{fs[0].verdict}")
        check("the CVE is named in the title", "CVE-2021-33813" in fs[0].title, fs[0].title)
        check("remediation names the fixed version",
              "2.0.6.1" in fs[0].detail.get("remediation", ""), fs[0].detail.get("remediation"))
    check("runs once, not per endpoint", sc.applies_to(ep) is False, "")


def main():
    print("== deluluscan SCA (vulnerable dependencies) ==")
    for fn in list(globals().values()):
        if callable(fn) and getattr(fn, "__name__", "").startswith("test_"):
            fn()
    print()
    if _failures:
        print(f"{len(_failures)} FAILED of {_checks}:")
        for f in _failures:
            print("  -", f)
        return 1
    print(f"{_checks}/{_checks} checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
