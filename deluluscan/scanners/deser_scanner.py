"""Java deserialization detector.

the target is a Java application, so an endpoint that feeds request-controlled bytes
to ObjectInputStream is a classic RCE path (given a gadget on the classpath).
This scanner proves the *sink is reachable* without ever weaponizing it:

  * It never sends a ysoserial gadget chain. It sends only a BENIGN, valid Java
    serialized String ("deluluscan") and a TRUNCATED stream header — inputs that carry
    no code and cannot execute anything.
  * If the endpoint responds with Java deserialization-specific errors
    (InvalidClassException, StreamCorruptedException, ClassNotFoundException,
    "ObjectInputStream"/"readObject", "invalid stream header" …) that a plain
    garbage baseline does NOT produce, then the input reached a deserializer —
    the vulnerable pattern — and that is the finding.

Grading (deluluscan/knowledge.py supply_chain discipline): a reachable deserializer is
exploitability=conditional — real RCE additionally requires a usable gadget on
the classpath, which is verified out-of-band (e.g. ysoserial in a controlled
lab), never by this detector.
"""
from __future__ import annotations

from typing import Iterable, Optional

from ..models import Endpoint, Finding, Severity, VulnClass
from .base import Scanner, canary

# Benign, valid serialized java.lang.String "deluluscan" — deserializes to a String,
# carries no gadget. And a truncated stream header that makes a real deserializer
# throw immediately. Neither can execute code.
_MAGIC_VALID = "rO0ABXQABXJla29u"
_MAGIC_TRUNC = "rO0AB"

_DESER_SIGNS = (
    "invalidclassexception", "streamcorruptedexception", "optionaldataexception",
    "classnotfoundexception", "writeabortedexception", "objectinputstream",
    "readobject", "invalid stream header", "cannot be cast to java.io.serializable",
    "java.io.eofexception",
)

_SERIALIZED_CT = "application/x-java-serialized-object"


class DeserScanner(Scanner):
    name = "deser"
    vuln_classes = [VulnClass.SUPPLY_CHAIN.value]

    def applies_to(self, endpoint: Endpoint) -> bool:
        # Bounded: body-accepting verbs, or GET/DELETE that carry query params.
        m = (endpoint.method or "").upper()
        if m in ("POST", "PUT", "PATCH"):
            return True
        return bool(endpoint.query_params)

    def _actor(self):
        for label in ("admin", "backend", "publisher", "content_editor", "anonymous"):
            ident = self.identities.get(label)
            if ident:
                return ident
        return next(iter(self.identities.values()), None)

    @staticmethod
    def _signs(text: str) -> set:
        low = (text or "").lower()
        return {s for s in _DESER_SIGNS if s in low}

    def _slots(self, endpoint: Endpoint, ident):
        """Yield (label, sender) pairs. sender(value) -> RequestRecord|None.
        Bounded to a handful of high-signal injection points."""
        m = (endpoint.method or "GET").upper()
        path = self.concrete_path(endpoint)
        hdrs = dict(self.auth.headers_for(ident)) if ident else {}
        label = ident.label() if ident else "anonymous"

        def raw_body(value):
            h = dict(hdrs); h["Content-Type"] = _SERIALIZED_CT
            return self.client.request(m if m != "GET" else "POST", path,
                                       identity_label=label, headers=h, data=value)

        yield ("raw-serialized-body", raw_body)

        # existing query params (bounded to 2)
        for qp in (endpoint.query_params or [])[:2]:
            name = qp.get("name") if isinstance(qp, dict) else str(qp)
            if not name:
                continue
            def q(value, _n=name):
                return self.client.request(m, path, identity_label=label,
                                           headers=dict(hdrs), params={_n: value})
            yield (f"param:{name}", q)

        # a JSON body field for body-accepting verbs
        if m in ("POST", "PUT", "PATCH"):
            def jf(value):
                return self.client.request(m, path, identity_label=label,
                                           headers=dict(hdrs),
                                           json_body={"data": value, "value": value})
            yield ("json-field", jf)

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        ident = self._actor()
        for label, sender in self._slots(endpoint, ident):
            try:
                base = sender(canary())               # non-serialized garbage baseline
                trunc = sender(_MAGIC_TRUNC)           # truncated Java stream header
            except TypeError:
                # http client without a data=/params= kwarg for this slot — skip it
                continue
            if base is None or trunc is None:
                continue
            new = self._signs(trunc.resp_body) - self._signs(base.resp_body)
            if not new:
                continue
            # Reachable deserializer confirmed for this slot.
            valid = sender(_MAGIC_VALID)              # a benign valid object, for evidence
            ev = [r for r in (trunc, valid, base) if r is not None][:3]
            yield Finding(
                vuln_class=VulnClass.SUPPLY_CHAIN, severity=Severity.HIGH,
                title=f"Java deserialization of untrusted input ({label})",
                endpoint=f"{endpoint.method} {endpoint.path}",
                description=(
                    "The endpoint fed attacker-controlled bytes to a Java object "
                    f"deserializer via '{label}': a truncated serialized stream produced "
                    f"deserialization-specific errors ({', '.join(sorted(new))}) that a "
                    "plain string baseline did not. This is the classic Java "
                    "deserialization RCE pattern; the deserializer is reachable with "
                    "untrusted input. No gadget was sent — only a benign/truncated stream."),
                evidence=ev,
                detail={"test": "deser", "slot": label, "signatures": sorted(new),
                        "note": ("Reachable deserializer confirmed. RCE additionally requires "
                                 "a usable gadget on the classpath — verify OUT OF BAND in a "
                                 "controlled lab (e.g. ysoserial), never from this tool.")},
                verdict="likely_true_positive", exploitability="conditional",
                confidence="firm")
            return   # one reachable sink per endpoint is enough
