"""Iterable-identifier IDOR scanner.

Bugcrowd VRT: "Read/Modify Sensitive Information via Iterable Object Identifiers"
(Broken Access Control / IDOR), P2. Where an endpoint takes a *numeric* object id
(path or query), a low-privilege user requesting neighbouring ids (id-1, id+1, a
distant id) should not receive other principals' objects. We compare the
neighbour responses against the low-priv user's own object using the value-overlap
oracle: distinct real objects returned for ids the user shouldn't own == IDOR.

Read-only: it issues GETs with altered ids and compares responses; it never
writes or deletes.
"""
from __future__ import annotations

import re
from typing import Iterable, Optional

from .base import Scanner
from ..models import Endpoint, Finding, IdentityRole, Severity, VulnClass
from ..verify import evidence as E

_NUM_ID = re.compile(r"(\d{1,12})")

# Canonical low object/tenant ids. The first accounts, tenants and records in
# almost any system carry these — and they usually belong to SOMEONE ELSE (the
# vendor's own test tenant, an early signup, an admin) no matter how large the
# caller's own id is. Probing only the caller's neighbours misses cross-tenant
# IDOR whenever the id space is large and sparse; a fixed low corpus is what
# actually surfaces "read tenant #1's data as tenant #849213" (the pattern behind
# AI-fuzzed cross-tenant API breaches). Kept small to bound the request budget.
CANONICAL_CROSS_TENANT_IDS = (1, 2, 3, 100, 1000)


def candidate_ids(base_id: int, *, neighbours=(-1, 1, 7),
                  canonical=CANONICAL_CROSS_TENANT_IDS, limit: int = 8) -> list[int]:
    """The other object-ids to try for a caller whose own id is `base_id`.

    Neighbours first (they evidence a dense, sequential id space next to the
    caller's own object), then the canonical low ids (other tenants). Excludes
    base_id itself and any id < 1, de-duplicates, and caps at `limit` to keep the
    probe bounded. Pure + deterministic so it can be unit-tested directly.
    """
    out: list[int] = []
    seen: set[int] = set()

    def add(n: int) -> None:
        if n < 1 or n == base_id or n in seen:
            return
        seen.add(n)
        out.append(n)

    for d in neighbours:
        add(base_id + d)
    for n in canonical:
        add(n)
    return out[:limit]


class IterableIdorScanner(Scanner):
    name = "idor_iter"
    vuln_classes = [VulnClass.IDOR.value]

    def applies_to(self, e: Endpoint) -> bool:
        if e.method.upper() != "GET":
            return False
        # a standalone numeric path segment (an object id, not a version like v1)
        if any(seg.isdigit() for seg in (e.path or "").split("/")):
            return True
        names = {(p.get("name") or "").lower() for p in (e.query_params or [])}
        return bool(names & {"id", "userid", "user_id", "inode", "identifier", "cid", "eid"})

    def _ident(self):
        return self.identities.get(IdentityRole.BACKEND.value) or \
            self.identities.get(IdentityRole.ANON.value) or \
            next(iter(self.identities.values()), None)

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        ident = self._ident()
        if ident is None:
            return
        label = ident.label()
        headers = self.auth.headers_for(ident)
        path = self.concrete_path(endpoint)

        # find the LAST path segment that is purely numeric (the object id),
        # skipping version-like 'v1' segments where the digit is glued to letters
        segs = path.split("?")[0].split("/")
        id_idx = None
        for i in range(len(segs) - 1, -1, -1):
            if segs[i].isdigit():
                id_idx = i; break
        if id_idx is None:
            return
        base_id = int(segs[id_idx])

        def with_id(n: int) -> str:
            parts = segs[:]
            parts[id_idx] = str(n)
            q = ("?" + path.split("?", 1)[1]) if "?" in path else ""
            return "/".join(parts) + q

        own = self.client.request("GET", path, identity_label=label, headers=headers)
        if own is None or E.classify_response(own) != E.DISPOSITION_CONTENT:
            return

        hits = []
        for n in candidate_ids(base_id):
            rec = self.client.request("GET", with_id(n), identity_label=label, headers=headers)
            if rec is None or E.classify_response(rec) != E.DISPOSITION_CONTENT:
                continue
            # returned real content for a neighbouring id. Is it a DISTINCT object
            # (not just the same record echoed / same-shape self data)?
            res = E.served_protected_content(rec, own)
            distinct = self._distinct_object(own.resp_body, rec.resp_body)
            if distinct:
                hits.append((n, rec))

        if hits:
            n0, rec0 = hits[0]
            yield Finding(
                vuln_class=VulnClass.IDOR, severity=Severity.HIGH,
                title="IDOR via iterable numeric identifier",
                endpoint=endpoint.key,
                description=(f"Changing the numeric id from {base_id} to other values "
                             f"({', '.join(str(n) for n, _ in hits)} — neighbours and canonical "
                             f"low ids) returned distinct objects "
                             f"to a user who should only access their own. Iterable identifiers "
                             f"without an ownership check let an attacker enumerate and read "
                             f"other users' records. Enforce per-object authorization keyed to "
                             f"the caller. (Read-only probe; no data was modified.)"),
                evidence=[own, rec0],
                detail={"test": "bola_id_swap", "active": True, "base_id": base_id,
                        "accessed_ids": [n for n, _ in hits]}, confidence="firm")

    @staticmethod
    def _distinct_object(a: str, b: str) -> bool:
        """True if b looks like a real object that differs from a (not empty, not
        identical, not the same record echoed back)."""
        import json
        a = (a or "").strip(); b = (b or "").strip()
        if not b or b == a:
            return False
        try:
            av = E._scalar_values(json.loads(a)) if a else set()
            bv = E._scalar_values(json.loads(b)) if b else set()
        except Exception:
            return len(b) > 2 and b != a
        if av and bv:
            overlap = len(av & bv) / max(1, len(bv))
            return overlap < 0.9
        return len(b) > 2
