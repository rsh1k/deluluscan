"""Engagement memory — Deluluscan's cross-scan learning store.

The tool used to start every assessment from zero. Whatever we learned on the
last run against a target — which endpoint was actually exploitable, which filter
bypass worked, that this target build rotates its `rme` JWT so a stale token
yields false 401s — evaporated the moment the process exited, so the next run
re-derived it the hard way (this cost us a dozen rounds on #651 alone).

`EngagementMemory` persists that knowledge, keyed by the target's product+version
(so a learning follows a target build across environments, not just one URL), and
feeds it back into the next scan two ways:

  * targeting  — endpoints previously confirmed exploitable are re-probed FIRST,
    so a budget-capped run always re-checks known-vulnerable spots (mirrors how
    the Mantis corpus front-loads source-derived endpoints).
  * annotation — a finding that matches a prior one is tagged with what we knew
    (seen_before / prior verdict / regression-vs-fix), and a previously-exploitable
    endpoint that does NOT reproduce this run is surfaced as a regression-watch in
    meta — never as a finding, because the report may only assert what THIS scan
    observed.

Design mirrors `deluluscan/verify/validation.py`'s FalsePositiveMemory: stdlib only,
one JSON file, human-inspectable and diffable. No LLM, no network — it stays
inside the same authorization boundary as everything else in the tool.

Inspect a store:  python3 -m deluluscan.memory deluluscan-out/engagement_memory.json
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Optional

SCHEMA_VERSION = 1

# Verdicts/exploitability we consider "worth remembering as a real result".
_TRUE = ("true_positive", "likely_true_positive")
_EXPLOITABLE = ("exploitable", "conditional")


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _norm_endpoint(endpoint: str) -> str:
    """Normalise 'METHOD /path/with/123/ids' so the same endpoint hashes equal
    across runs even when a concrete id differs. Coarser than validation.py's
    per-finding signature on purpose: the question memory answers is 'is THIS
    endpoint still exploitable', which must not fragment on a changed uuid."""
    e = (endpoint or "").strip()
    e = re.sub(r"\b[0-9a-f]{8}-[0-9a-f-]{20,}\b", "{id}", e, flags=re.I)
    e = re.sub(r"/\d+\b", "/{id}", e)
    return e.strip()


def endpoint_key(vuln_class: str, endpoint: str) -> str:
    return f"{vuln_class}|{_norm_endpoint(endpoint)}"


def _host_of(base_url: str) -> str:
    return (re.sub(r"^\w+://", "", base_url or "").rstrip("/") or "unknown-target").lower()


def target_key(product: Optional[str], version: Optional[str], base_url: str) -> str:
    """A stable identity for the target.

      product + real version  -> 'product@version'  (shared across environments —
                                 a learning about this build follows it anywhere)
      product, no version      -> 'product@unknown:host'  (host-qualified so two
                                 different instances of an unversioned stack don't
                                 merge — a fix on one must not read as a regression
                                 on the other)
      no product               -> 'host:host'
    """
    if product and version:
        return f"{product}@{version}".lower()
    if product:
        return f"{product}@unknown:{_host_of(base_url)}".lower()
    return f"host:{_host_of(base_url)}"


def target_key_from_fingerprint(fingerprint, base_url: str) -> str:
    """Derive the key from a Fingerprint (or its to_dict()), preferring a CMS/
    framework detection that carries a version."""
    dets = []
    if fingerprint is None:
        dets = []
    elif hasattr(fingerprint, "detections"):
        dets = [{"tech": d.tech, "category": d.category, "version": d.version}
                for d in fingerprint.detections]
    elif isinstance(fingerprint, dict):
        dets = fingerprint.get("detections", []) or []
    # a versioned CMS/framework detection is the most stable identity
    best = None
    for d in dets:
        if d.get("version") and d.get("category") in ("cms", "framework", "language", "server"):
            best = d
            break
    if best is None and dets:
        best = dets[0]
    if best:
        return target_key(best.get("tech"), best.get("version"), base_url)
    return target_key(None, None, base_url)


# ---------------------------------------------------------------------------
@dataclass
class Recall:
    """What we know about a target, ready to influence a scan."""
    target_key: str
    known: bool = False
    findings: dict = field(default_factory=dict)   # endpoint_key -> record
    gotchas: dict = field(default_factory=dict)    # kind -> record
    bypasses: list = field(default_factory=list)
    base_url: str = ""
    version: str = ""
    last_seen: str = ""

    def is_empty(self) -> bool:
        return not (self.findings or self.gotchas or self.bypasses)

    def exploitable_endpoints(self) -> list[str]:
        """endpoint_keys previously confirmed exploitable/conditional — the spots
        a capped or hurried scan should re-check first."""
        return [k for k, r in self.findings.items()
                if r.get("exploitability") in _EXPLOITABLE
                and r.get("verdict") in _TRUE]

    def prior_for(self, vuln_class: str, endpoint: str) -> Optional[dict]:
        return self.findings.get(endpoint_key(vuln_class, endpoint))

    def has_gotcha(self, kind: str) -> bool:
        return kind in self.gotchas

    def summary_lines(self) -> list[str]:
        out = []
        ex = self.exploitable_endpoints()
        if ex:
            out.append(f"{len(ex)} endpoint(s) were exploitable last time: "
                       + ", ".join(k.split('|', 1)[-1] for k in ex[:6])
                       + (" …" if len(ex) > 6 else ""))
        for kind, rec in self.gotchas.items():
            out.append(f"gotcha [{kind}]: {rec.get('detail', '')}")
        if self.bypasses:
            out.append(f"{len(self.bypasses)} verified filter bypass(es) on record")
        return out


# ---------------------------------------------------------------------------
class EngagementMemory:
    """Persistent, per-target learning store. One JSON file, stdlib only."""

    def __init__(self, path: Optional[str] = None):
        self.path = path
        self.data: dict = {"schema": SCHEMA_VERSION, "targets": {}}
        if path and os.path.exists(path):
            try:
                loaded = json.load(open(path))
                if isinstance(loaded, dict) and "targets" in loaded:
                    self.data = loaded
                    self.data.setdefault("targets", {})
            except Exception:
                pass  # a corrupt store must never break a scan; start fresh

    # ---- recall -----------------------------------------------------------
    def recall(self, tkey: str) -> Recall:
        t = self.data.get("targets", {}).get(tkey)
        if not t:
            return Recall(target_key=tkey, known=False)
        return Recall(
            target_key=tkey, known=True,
            findings=dict(t.get("findings", {})),
            gotchas=dict(t.get("gotchas", {})),
            bypasses=list(t.get("bypasses", [])),
            base_url=t.get("base_url", ""),
            version=t.get("version", ""),
            last_seen=t.get("last_seen", ""))

    # ---- record -----------------------------------------------------------
    def _target(self, tkey: str) -> dict:
        t = self.data.setdefault("targets", {}).setdefault(tkey, {})
        t.setdefault("first_seen", _now())
        t.setdefault("findings", {})
        t.setdefault("gotchas", {})
        t.setdefault("bypasses", [])
        return t

    def record_gotcha(self, tkey: str, kind: str, detail: str) -> None:
        t = self._target(tkey)
        rec = t["gotchas"].get(kind, {"first_seen": _now(), "seen_count": 0})
        rec["seen_count"] = rec.get("seen_count", 0) + 1
        rec["detail"] = detail
        rec["last_seen"] = _now()
        t["gotchas"][kind] = rec

    def record_bypass(self, tkey: str, filter_desc: str, payload: str,
                      endpoint: str = "") -> None:
        t = self._target(tkey)
        for b in t["bypasses"]:
            if b.get("payload") == payload and b.get("filter") == filter_desc:
                b["seen_count"] = b.get("seen_count", 1) + 1
                b["last_seen"] = _now()
                return
        t["bypasses"].append({"filter": filter_desc, "payload": payload,
                              "endpoint": endpoint, "seen_count": 1,
                              "first_seen": _now(), "last_seen": _now()})

    def record_scan(self, tkey: str, base_url: str, version: str,
                    findings: list, meta: Optional[dict] = None) -> dict:
        """Ingest a completed scan's findings + derived gotchas. Returns stats.

        `findings` are Finding objects (or their .to_dict()). Only credible
        results are remembered; a false-positive is not learned as a truth, but a
        previously-exploitable endpoint that did NOT reproduce is flagged as a
        regression-watch so the operator can tell 'fixed' from 'not re-tested'."""
        t = self._target(tkey)
        t["base_url"] = base_url
        t["version"] = version or t.get("version", "")
        t["last_seen"] = _now()

        prior_exploitable = set(self.recall(tkey).exploitable_endpoints())
        seen_this_run: set[str] = set()
        recorded = 0
        for f in findings:
            d = f.to_dict() if hasattr(f, "to_dict") else dict(f)
            verdict = d.get("verdict") or "unverified"
            vc = d.get("vuln_class") or ""
            endpoint = d.get("endpoint") or ""
            if not endpoint or endpoint == "(client JS)":
                key = endpoint_key(vc, d.get("title", ""))
            else:
                key = endpoint_key(vc, endpoint)
            seen_this_run.add(key)
            # only remember credible results as truths
            if verdict not in _TRUE:
                continue
            rec = t["findings"].get(key, {"first_seen": _now(), "seen_count": 0})
            rec["seen_count"] = rec.get("seen_count", 0) + 1
            rec["vuln_class"] = vc
            rec["endpoint"] = endpoint
            rec["title"] = d.get("title", "")
            rec["verdict"] = verdict
            rec["exploitability"] = d.get("exploitability", "unknown")
            rec["severity"] = d.get("severity", "")
            rec["last_seen"] = _now()
            # harvest a session-riding note + any verified bypass from deep verify
            deep = (d.get("detail") or {}).get("deep") or {}
            sr = deep.get("session_riding") or {}
            if sr.get("verdict") == "weaponizable":
                rec["note"] = "session-ridable (cookie-authed; XSS-drivable)"
            ib = deep.get("injection_bypass") or {}
            if ib.get("verified_bypass") and ib.get("payload"):
                self.record_bypass(tkey, ib.get("filter", "input filter"),
                                   ib["payload"], endpoint)
            t["findings"][key] = rec
            recorded += 1

        # regression-watch: previously exploitable, not reproduced this run
        regressed_fixed = sorted(prior_exploitable - seen_this_run)

        # derive gotchas honestly from what the scan observed
        self._derive_gotchas(tkey, findings, meta or {})

        return {"target_key": tkey, "recorded": recorded,
                "possibly_fixed": regressed_fixed,
                "known_targets": len(self.data.get("targets", {}))}

    def _derive_gotchas(self, tkey: str, findings: list, meta: dict) -> None:
        """Record only gotchas the scan actually evidenced."""
        # token rotation: deep verify logs it when a fresh session login was
        # needed because a minted/stale token produced false 401s.
        for f in findings:
            d = f.to_dict() if hasattr(f, "to_dict") else dict(f)
            deep = (d.get("detail") or {}).get("deep") or {}
            sr = deep.get("session_riding") or {}
            for reason in sr.get("reasons", []) or []:
                if "rotat" in reason.lower() or "fresh login" in reason.lower():
                    self.record_gotcha(
                        tkey, "token_rotation",
                        "target rotates its session JWT — use a fresh login per "
                        "probe; a stale token yields false 401s")
                    break
        # working principal: which identity actually authenticated (build-dependent
        # in the target). Read from meta.identities.
        idents = (meta.get("identities") or {})
        ok_admin = [r for r, s in idents.items()
                    if isinstance(s, dict) and s.get("ok") and r in ("admin", "backend")]
        if ok_admin:
            self.record_gotcha(tkey, "working_principal",
                               f"authenticating identity/identities: {', '.join(sorted(ok_admin))}")

    def save(self) -> None:
        if not self.path:
            return
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            json.dump(self.data, open(self.path, "w"), indent=2, sort_keys=True)
        except Exception:
            pass  # persistence must never break a scan

    # ---- inspection -------------------------------------------------------
    def describe(self) -> str:
        lines = [f"engagement memory: {self.path or '(in-memory)'}",
                 f"schema v{self.data.get('schema')} · "
                 f"{len(self.data.get('targets', {}))} target(s)", ""]
        for tkey, t in sorted(self.data.get("targets", {}).items()):
            fs = t.get("findings", {})
            ex = [k for k, r in fs.items()
                  if r.get("exploitability") in _EXPLOITABLE]
            lines.append(f"■ {tkey}   ({t.get('base_url','?')})")
            lines.append(f"    last seen {t.get('last_seen','?')} · "
                         f"{len(fs)} remembered finding(s), {len(ex)} exploitable · "
                         f"{len(t.get('gotchas',{}))} gotcha(s) · "
                         f"{len(t.get('bypasses',[]))} bypass(es)")
            for k in ex[:8]:
                r = fs[k]
                lines.append(f"      ! [{r.get('exploitability')}] "
                             f"{r.get('endpoint') or k}"
                             + (f"  — {r['note']}" if r.get("note") else ""))
            for kind, rec in t.get("gotchas", {}).items():
                lines.append(f"      » {kind}: {rec.get('detail','')}")
        return "\n".join(lines)


def main(argv=None) -> int:
    import sys
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ("-h", "--help"):
        print("usage: python3 -m deluluscan.memory <engagement_memory.json>")
        return 0
    mem = EngagementMemory(args[0])
    print(mem.describe())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
