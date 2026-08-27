"""Java deserialization detector — proves a deserializer is reachable with
untrusted input (via Java deser-specific error signatures) without ever sending
a gadget, and grades it exploitability=conditional (RCE needs a classpath gadget,
verified out of band).

Verified offline against a fake client: a real deserializer errors on the
truncated stream but not on a plain-string baseline -> finding; a benign endpoint
that never deserializes -> no finding.

Run: python3 -m tests.test_deser
"""
from __future__ import annotations

import sys

from deluluscan.models import Endpoint, RequestRecord, VulnClass
from deluluscan.scanners.deser_scanner import DeserScanner

_checks = 0
_failures: list[str] = []


def check(cond, label):
    global _checks
    _checks += 1
    print(f"{'PASS' if cond else 'FAIL'}  {label}")
    if not cond:
        _failures.append(label)


class _Ident:
    def __init__(self, l): self._l = l; self.username = l; self.bearer_token = None
    def label(self): return self._l


class _Auth:
    def headers_for(self, ident): return {}


class _Client:
    def __init__(self, mode): self.mode = mode
    def request(self, method, path, *, identity_label="anonymous", headers=None,
                params=None, json_body=None, data=None, **kw):
        val = str(data or "")
        if params:
            val += " " + " ".join(str(v) for v in params.values())
        if isinstance(json_body, dict):
            val += " " + " ".join(str(v) for v in json_body.values())
        def rec(status, body):
            return RequestRecord(method=method, url=path, identity=identity_label,
                                 status=status, elapsed_ms=1.0, resp_headers={},
                                 resp_body=body, resp_len=len(body))
        # A real deserializer chokes on the truncated Java stream header (rO0AB…)
        # but treats a plain garbage string as ordinary input.
        if self.mode == "deser" and "rO0AB" in val:
            return rec(500, "java.io.InvalidClassException: local class incompatible; "
                            "at java.io.ObjectInputStream.readObject(...)")
        return rec(200, "{}")


def _scanner(mode):
    return DeserScanner(_Client(mode), _Auth(), config=None,
                        identities={"admin": _Ident("admin")})


EP = Endpoint("POST", "/api/v1/apps/import", "apps import", ["apps"])


def test_applies_scope():
    s = _scanner("benign")
    check(s.applies_to(EP), "applies to POST (body-accepting)")
    check(s.applies_to(Endpoint("GET", "/api/v1/x", query_params=[{"name": "q"}])),
          "applies to GET with query params")
    check(not s.applies_to(Endpoint("GET", "/api/v1/x")), "skips GET with no params")


def test_detects_reachable_deserializer():
    findings = list(_scanner("deser").run(EP))
    check(len(findings) == 1, f"emits one deser finding (got {len(findings)})")
    f = findings[0] if findings else None
    check(f and f.vuln_class == VulnClass.SUPPLY_CHAIN, "class supply_chain (A08 integrity)")
    check(f and f.exploitability == "conditional",
          "exploitability conditional (RCE needs a classpath gadget)")
    check(f and f.verdict == "likely_true_positive", "reachable sink -> likely_true_positive")
    check(f and "invalidclassexception" in " ".join(f.detail.get("signatures", [])),
          "records the deserialization error signature that proved reachability")


def test_no_finding_when_not_a_deserializer():
    findings = list(_scanner("benign").run(EP))
    check(not findings, "no finding when the endpoint never deserializes")


def test_sends_no_gadget():
    # The scanner must only ever send the benign/truncated markers, never a gadget.
    seen = []
    class Spy(_Client):
        def request(self, *a, **k):
            seen.append(str(k.get("data") or "") + str(k.get("params") or "") + str(k.get("json_body") or ""))
            return super().request(*a, **k)
    s = DeserScanner(Spy("benign"), _Auth(), config=None, identities={"admin": _Ident("admin")})
    list(s.run(EP))
    joined = " ".join(seen)
    check("CommonsCollections" not in joined and "ysoserial" not in joined,
          "never sends a ysoserial gadget chain")
    check("rO0AB" in joined, "does send the benign/truncated serialized marker")


def main():
    print("== java deserialization detector ==")
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
