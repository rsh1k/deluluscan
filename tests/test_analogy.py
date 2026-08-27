"""Analogical vulnerability research — peer-product CVEs distilled into patterns.

Locks down the pipeline (corpus -> cluster -> distill -> SourcePattern) and the
discipline that keeps it honest: every generated pattern carries the CVEs it came
from, a malformed LLM answer is rejected rather than half-used, and an
uncompilable regex is dropped instead of crashing a scan.

Fully offline — the CVE feed and the LLM are both injected.

Run: python3 -m tests.test_analogy
"""
from __future__ import annotations

import os
import sys
import tempfile

from deluluscan.analogy import (Advisory, AdvisoryCluster, BugPattern, cluster,
                           distill, fetch_nvd, load_patterns, save_patterns,
                           to_source_patterns)
from deluluscan.models import Severity

_checks = 0
_failures: list[str] = []


def check(label, cond, detail=""):
    global _checks
    _checks += 1
    print(f"{'PASS' if cond else 'FAIL'}  {label}" + (f"  [{detail}]" if not cond else ""))
    if not cond:
        _failures.append(label)


NVD_PAGE = {"vulnerabilities": [
    {"cve": {"id": "CVE-2020-7961",
             "descriptions": [{"lang": "en", "value": "Deserialization of Untrusted Data in Liferay Portal allows RCE via JSONWS."}],
             "weaknesses": [{"description": [{"value": "CWE-502"}]}],
             "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "CRITICAL"}}]},
             "published": "2020-03-20T00:00:00"}},
    {"cve": {"id": "CVE-2021-46364",
             "descriptions": [{"lang": "en", "value": "SnakeYAML parser of Magnolia CMS allows arbitrary code execution via a crafted YAML file."}],
             "weaknesses": [{"description": [{"value": "CWE-502"}]}],
             "metrics": {}, "published": "2022-02-01T00:00:00"}},
    {"cve": {"id": "CVE-2023-42344",
             "descriptions": [{"lang": "en", "value": "Alkacon OpenCms allows unauthenticated attackers to obtain information via an XXE attack."}],
             "weaknesses": [{"description": [{"value": "NVD-CWE-noinfo"}]}],
             "metrics": {}, "published": "2023-09-01T00:00:00"}},
]}


def test_fetch_parses_nvd():
    ads = fetch_nvd("liferay", max_results=3, fetch=lambda url: NVD_PAGE, pause_s=0)
    check("parses NVD into advisories", len(ads) == 3, str(len(ads)))
    by = {a.id: a for a in ads}
    check("carries CWE", by["CVE-2020-7961"].cwe == ["CWE-502"], str(by["CVE-2020-7961"].cwe))
    check("carries severity", by["CVE-2020-7961"].severity == "CRITICAL",
          by["CVE-2020-7961"].severity)


def test_clustering_by_cwe_and_keyword():
    ads = fetch_nvd("x", max_results=3, fetch=lambda url: NVD_PAGE, pause_s=0)
    cs = {c.key: c for c in cluster(ads, min_size=1)}
    check("groups by CWE when NVD gives one",
          len(cs.get("CWE-502").advisories) == 2 if cs.get("CWE-502") else False,
          str(sorted(cs)))
    check("falls back to a keyword bucket when the CWE is noinfo",
          "xxe" in cs, str(sorted(cs)))
    check("an unusable CWE is not treated as a class",
          "NVD-CWE-noinfo" not in cs, str(sorted(cs)))


def test_min_size_filters_one_offs():
    ads = fetch_nvd("x", max_results=3, fetch=lambda url: NVD_PAGE, pause_s=0)
    keys = {c.key for c in cluster(ads, min_size=2)}
    check("a class with a single CVE is not a pattern (min_size)",
          keys == {"CWE-502"}, str(keys))


GOOD_LLM = '''Here you go:
{"id": "unsafe_yaml", "vuln_class": "supply_chain", "severity": "critical",
 "description": "SnakeYAML without SafeConstructor instantiates attacker-named types.",
 "regex": "new\\\\s+Yaml\\\\s*\\\\(\\\\s*\\\\)", "guard": "SafeConstructor",
 "probe_kind": "deserialize", "probe_params": ["body"], "path_hint": ["/rest/"]}'''


def test_distill_extracts_pattern_and_provenance():
    c = AdvisoryCluster(key="CWE-502", advisories=[
        Advisory("CVE-2021-46364", "magnolia", "SnakeYAML RCE"),
        Advisory("CVE-2020-7961", "liferay", "JSONWS deser RCE")])
    p = distill(c, ask=lambda prompt: GOOD_LLM)
    check("distills a BugPattern", p is not None and p.id == "unsafe_yaml", str(p))
    check("severity is parsed", p and p.severity == Severity.CRITICAL, str(p.severity if p else None))
    check("PROVENANCE records the CVEs it was transferred from",
          p and p.provenance == ["CVE-2021-46364", "CVE-2020-7961"], str(p.provenance if p else None))


def test_distill_rejects_bad_llm_output():
    c = AdvisoryCluster(key="k", advisories=[Advisory("CVE-1", "x", "y")])
    check("no JSON in the answer -> None", distill(c, ask=lambda p: "sorry, I cannot") is None)
    check("malformed JSON -> None", distill(c, ask=lambda p: "{not json") is None)
    check("JSON missing required keys -> None",
          distill(c, ask=lambda p: '{"id":"x"}') is None)
    check("an LLM that raises -> None",
          distill(c, ask=lambda p: (_ for _ in ()).throw(RuntimeError("boom"))) is None)


def test_to_source_patterns_compiles_and_drops_bad_regex():
    good = BugPattern(id="ok", vuln_class="sqli", severity=Severity.HIGH,
                      description="d", regex=r"new\s+Yaml\s*\(", guard="SafeConstructor",
                      probe_kind="deserialize", provenance=["CVE-1"])
    bad = BugPattern(id="bad", vuln_class="sqli", severity=Severity.HIGH,
                     description="d", regex=r"(unclosed[", provenance=["CVE-2"])
    out = to_source_patterns([good, bad])
    check("a compilable pattern becomes a SourcePattern", len(out) == 1, str(len(out)))
    check("an uncompilable generated regex is dropped, not raised",
          out[0].id == "analogy:ok", out[0].id)
    check("the id is namespaced so generated patterns are distinguishable",
          out[0].id.startswith("analogy:"), out[0].id)
    check("provenance survives into the description a report will show",
          "CVE-1" in out[0].description, out[0].description)


def test_corpus_round_trip():
    p = BugPattern(id="rt", vuln_class="authz", severity=Severity.MEDIUM,
                   description="d", regex="x", probe_params=("a", "b"),
                   path_hint=("/rest/",), provenance=["CVE-9"])
    path = os.path.join(tempfile.mkdtemp(prefix="analogy_"), "p.json")
    save_patterns([p], path, meta={"corpus": "test"})
    back = load_patterns(path)
    check("corpus round-trips", len(back) == 1 and back[0].id == "rt", str(back))
    check("severity survives the round trip", back[0].severity == Severity.MEDIUM,
          str(back[0].severity))
    check("tuples survive the round trip", back[0].probe_params == ("a", "b"),
          str(back[0].probe_params))
    check("a missing corpus file is not fatal", load_patterns("/nope/nope.json") == [])


def test_shipped_corpus_is_well_formed():
    """The corpus committed to the repo must actually compile and be attributable."""
    pats = load_patterns()
    check("a corpus ships with the repo", len(pats) >= 5, str(len(pats)))
    check("every shipped pattern names the CVEs it came from",
          all(p.provenance for p in pats),
          str([p.id for p in pats if not p.provenance]))
    compiled = to_source_patterns(pats)
    check("every shipped pattern compiles", len(compiled) == len(pats),
          f"{len(compiled)}/{len(pats)}")


def test_broad_walk_reaches_non_rest_files():
    """The default walk only opens *Resource.java under rest/ — 125 of 7,779 files.
    A pattern aimed at XML/bundle/script code was silently unmatchable."""
    from deluluscan.sourcescan import SourceProvider
    root = tempfile.mkdtemp(prefix="broad_")
    rest = os.path.join(root, "./app-src/main/java/com/example/rest/a")
    other = os.path.join(root, "./app-src/main/java/com/example/rendering/velocity")
    os.makedirs(rest, exist_ok=True); os.makedirs(other, exist_ok=True)
    open(os.path.join(rest, "FooResource.java"), "w").write("class FooResource {}")
    open(os.path.join(other, "XmlTool.java"), "w").write("class XmlTool {}")
    prov = SourceProvider(local_root=root)
    narrow = {os.path.basename(p) for p, _ in prov.iter_source_files(max_files=50)}
    check("default walk sees only REST resources", narrow == {"FooResource.java"}, str(narrow))
    broad = {os.path.basename(p) for p, _ in
             prov.iter_source_files(max_files=50, accept=lambda fp: "velocity" in fp or "/rest/" in fp)}
    check("broad walk reaches non-REST files (XmlTool)", "XmlTool.java" in broad, str(broad))


def main():
    print("== deluluscan analogical vulnerability research ==")
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
