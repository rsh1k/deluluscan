"""Offline tests for dependency-confusion detection (injected registry check)."""
from __future__ import annotations

import os
import tempfile

from deluluscan.depconfusion import DepConfusionScan
from deluluscan.depconfusion.parsers import scan_tree, _parse_package_json, _parse_requirements
from deluluscan.models import VulnClass, Severity

_PASS = 0; _FAIL = 0
def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond: _PASS += 1; print(f"PASS  {name}")
    else: _FAIL += 1; print(f"FAIL  {name}  {detail}")


def _rc(table):
    return lambda eco, name: table.get(name)   # True/False/None


def _write(root, rel, content):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w").write(content)


def test_parsers():
    npm = _parse_package_json('{"dependencies":{"react":"^18","@myco/ui":"1.0"},"devDependencies":{"vitest":"^4"}}', "package.json")
    names = {d.name for d in npm}
    check("npm deps parsed", names == {"react", "@myco/ui", "vitest"}, names)
    check("scoped flag", any(d.name == "@myco/ui" and d.scoped for d in npm))
    pip = _parse_requirements("requests>=2.31\n# comment\ninternal-lib==1.2\n-e .\n", "requirements.txt")
    check("pip deps parsed", {d.name for d in pip} == {"requests", "internal-lib"}, {d.name for d in pip})


def test_private_registry_detected():
    with tempfile.TemporaryDirectory() as d:
        _write(d, ".npmrc", "@myco:registry=https://npm.internal.example/\n")
        _write(d, "package.json", '{"dependencies":{"@myco/secret":"1.0"}}')
        deps, private = scan_tree(d)
        check("private registry found", private == [".npmrc"], private)
        check("scoped dep found", any(x.name == "@myco/secret" for x in deps))


def test_absent_dep_flagged_high_with_private():
    with tempfile.TemporaryDirectory() as d:
        _write(d, ".npmrc", "registry=https://npm.internal.example/\n")
        _write(d, "package.json", '{"dependencies":{"internal-widget":"1.0","react":"^18"}}')
        finds = DepConfusionScan(registry_check=_rc({"internal-widget": False, "react": True})).scan_path(d)
        check("one finding", len(finds) == 1, [f.title for f in finds])
        f = finds[0]
        check("HIGH with private registry", f.severity == Severity.HIGH)
        check("supply_chain class", f.vuln_class == VulnClass.SUPPLY_CHAIN)
        check("firm/likely with private", f.confidence == "firm" and f.verdict == "likely_true_positive")
        check("names the private registry", ".npmrc" in f.detail["private_registries"])


def test_absent_dep_medium_without_private():
    with tempfile.TemporaryDirectory() as d:
        _write(d, "requirements.txt", "internal-corp-utils==1.0\nrequests>=2\n")
        finds = DepConfusionScan(registry_check=_rc({"internal-corp-utils": False, "requests": True})).scan_path(d)
        check("one finding (no private cfg)", len(finds) == 1, [f.title for f in finds])
        check("MEDIUM without private registry", finds[0].severity == Severity.MEDIUM)
        check("tentative/inconclusive", finds[0].confidence == "tentative" and finds[0].verdict == "inconclusive")


def test_unknown_lookup_not_flagged():
    with tempfile.TemporaryDirectory() as d:
        _write(d, "requirements.txt", "maybe-exists==1.0\n")
        # None = network/unknown -> must NOT flag (no false positive on a blip)
        finds = DepConfusionScan(registry_check=_rc({"maybe-exists": None})).scan_path(d)
        check("unknown -> no finding", finds == [], [f.title for f in finds])


def test_public_scoped_hint_skipped():
    with tempfile.TemporaryDirectory() as d:
        _write(d, "package.json", '{"devDependencies":{"@types/node":"^20"}}')
        called = {"n": 0}
        def rc(eco, name): called["n"] += 1; return False
        finds = DepConfusionScan(registry_check=rc).scan_path(d)
        check("@types/* not looked up or flagged", finds == [] and called["n"] == 0)


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
    print(f"\n{_PASS} passed, {_FAIL} failed")
    raise SystemExit(1 if _FAIL else 0)
