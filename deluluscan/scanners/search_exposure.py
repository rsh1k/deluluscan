"""Search-layer exposure — unauthenticated index access and query injection.

the target puts Elasticsearch behind several REST surfaces. Two distinct problems
were observed live on a 26.x instance:

  * /api/search and /api/search initialise with rejectWhenNoUser=false, so an
    ANONYMOUS caller can execute arbitrary Elasticsearch DSL. /api/search returns
    the raw ES response, including internal index names such as
    "cluster_target-production.live_20260726092543". Aggregations are computed by
    Elasticsearch *before* the target applies its per-contentlet permission filter,
    so bucket counts disclose inventory the caller cannot read.

  * /api/v1/page/search interpolates the `path` parameter straight into a
    query_string clause (only "/" is escaped), letting a caller add or negate
    clauses and escape the +basetype:5 restriction the endpoint relies on.

Both checks are read-only: they send searches, never writes, and never request
enough rows to be a load event.
"""
from __future__ import annotations

import json
from typing import Iterable, Optional

from ..models import Endpoint, Finding, Severity, VulnClass
from .base import Scanner

_MATCH_ALL = {"query": {"match_all": {}}, "size": 1}
# Aggregation over a keyword field: buckets are produced by ES before the target
# filters the hits, so they reveal what exists rather than what you may read.
_AGG = {"query": {"match_all": {}}, "size": 0,
        "aggs": {"types": {"terms": {"field": "contenttype", "size": 10}}}}

_RAW_PATHS = ("/api/search", "/api/search")
_INDEX_MARKERS = ("cluster_", ".live_", ".working_", "_index")


def _json(body: str):
    try:
        return json.loads(body or "")
    except (ValueError, TypeError):
        return None


class SearchExposureScanner(Scanner):
    """Anonymous Elasticsearch DSL execution and page-search query injection."""

    name = "search_exposure"
    vuln_classes = [VulnClass.AUTHZ.value, VulnClass.INFO_LEAK.value,
                    VulnClass.SQLI.value]

    def applies_to(self, endpoint: Endpoint) -> bool:
        p = endpoint.path
        return p in _RAW_PATHS or p == "/api/v1/page/search"

    def _post_json(self, path: str, label: str, payload: dict):
        ident = self.identities.get(label)
        if ident is None:
            return None
        headers = dict(self.auth.headers_for(ident))
        headers["Content-Type"] = "application/json"
        return self.client.request("POST", path, identity_label=label,
                                   headers=headers, data=json.dumps(payload))

    def _get(self, path: str, label: str, params: dict):
        ident = self.identities.get(label)
        if ident is None:
            return None
        return self.client.request("GET", path, identity_label=label,
                                   headers=dict(self.auth.headers_for(ident)),
                                   params=params)

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        path = endpoint.path
        if path in _RAW_PATHS:
            yield from self._check_raw_es(path)
        elif path == "/api/v1/page/search":
            yield from self._check_page_search()

    # ---- anonymous Elasticsearch DSL -------------------------------------
    def _check_raw_es(self, path: str) -> Iterable[Finding]:
        if "anonymous" not in self.identities:
            return
        rec = self._post_json(path, "anonymous", _MATCH_ALL)
        if rec is None or not (200 <= rec.status < 300):
            return
        body = rec.resp_body or ""
        parsed = _json(body)
        if parsed is None:
            return

        leaked_index = [m for m in _INDEX_MARKERS if m in body]
        sev = Severity.MEDIUM if leaked_index else Severity.LOW
        yield Finding(
            vuln_class=VulnClass.AUTHZ, severity=sev,
            title="Elasticsearch query API executes arbitrary DSL for unauthenticated callers",
            endpoint=f"POST {path}",
            description=(
                f"An anonymous POST of an Elasticsearch match_all query to {path} returned "
                f"HTTP {rec.status}. The endpoint accepts caller-supplied Elasticsearch DSL "
                f"without authentication"
                + (f", and the response exposes internal index naming ({', '.join(leaked_index)}), "
                   f"which reveals cluster and environment structure." if leaked_index
                   else ". ")
                + " Query DSL is a powerful interface: it permits arbitrary filtering, sorting "
                  "and aggregation over the index."),
            evidence=[rec],
            detail={"test": "anonymous_es_dsl", "leaked_index_markers": leaked_index,
                    "impact": ("Unauthenticated callers can interrogate the search index "
                               "directly, outside the application's own query surface."),
                    "remediation": ("Require authentication on the Elasticsearch REST surfaces "
                                    "(rejectWhenNoUser=true) and never return the raw ES "
                                    "response, which carries index metadata."),
                    "cwe": "CWE-306",
                    "auto_confirm": {
                        "confirmed": True, "kind": "differential_observation",
                        "exploitability": "exploitable",
                        "reason": (f"anonymous POST of Elasticsearch DSL to {path} returned "
                                   f"HTTP {rec.status}"),
                        "repro": f"POST {path} with no credentials and body "
                                 f'{{"query":{{"match_all":{{}}}}}}'}},
            confidence="firm", verdict="true_positive", exploitability="exploitable")

        # Aggregations are computed before the target filters hits by permission.
        agg = self._post_json(path, "anonymous", _AGG)
        if agg is None or not (200 <= agg.status < 300):
            return
        parsed_agg = _json(agg.resp_body) or {}
        buckets = (((parsed_agg.get("aggregations") or {}).get("types") or {})
                   .get("buckets") or [])
        if not isinstance(buckets, list) or not buckets:
            return
        hits = (((parsed_agg.get("hits") or {}).get("total") or {}))
        hit_count = hits.get("value") if isinstance(hits, dict) else hits
        names = [b.get("key") for b in buckets if isinstance(b, dict)][:8]
        yield Finding(
            vuln_class=VulnClass.INFO_LEAK, severity=Severity.LOW,
            title="Anonymous Elasticsearch aggregations disclose content inventory "
                  "(computed before permission filtering)",
            endpoint=f"POST {path}",
            description=(
                f"An anonymous terms aggregation returned {len(buckets)} bucket(s) "
                f"({names}) while the query reported {hit_count} hit(s). the target filters "
                f"returned contentlets by permission, but Elasticsearch computes "
                f"aggregations over the whole index first, so bucket names and document "
                f"counts describe content the caller is not entitled to read."),
            evidence=[agg],
            detail={"test": "anonymous_es_aggregation_leak", "buckets": names,
                    "impact": ("Discloses which content types exist and how many documents "
                               "each holds, to unauthenticated callers."),
                    "remediation": ("Apply the permission filter as a query clause so it "
                                    "constrains aggregations too, or disallow aggregations "
                                    "on the public search surface."),
                    "cwe": "CWE-200",
                    "auto_confirm": {
                        "confirmed": True, "kind": "differential_observation",
                        "exploitability": "exploitable",
                        "reason": (f"anonymous aggregation produced {len(buckets)} bucket(s) "
                                   f"naming content types"),
                        "repro": f"POST {path} anonymously with a terms aggregation on "
                                 f"'contenttype'"}},
            confidence="firm", verdict="true_positive", exploitability="exploitable")

    # ---- page-search Lucene injection ------------------------------------
    def _check_page_search(self) -> Iterable[Finding]:
        label = next((l for l in ("backend", "readonly", "content_editor", "admin")
                      if l in self.identities), None)
        if label is None:
            return
        base = self._get("/api/v1/page/search", label, {"path": "*"})
        if base is None or not (200 <= base.status < 300):
            return

        def count(rec) -> Optional[int]:
            d = _json(rec.resp_body) if rec else None
            if not isinstance(d, dict):
                return None
            ent = d.get("entity")
            return len(ent) if isinstance(ent, list) else None

        n_base = count(base)
        if n_base is None:
            return

        # A clause the endpoint's own +basetype:5 restriction should make
        # impossible to influence. If the count moves, our text became query
        # syntax rather than a literal path.
        narrowed = self._get("/api/v1/page/search", label,
                             {"path": "* +conhostName:deluluscan_no_such_host_zzz"})
        n_narrow = count(narrowed)
        broken = self._get("/api/v1/page/search", label, {"path": '/te"st'})

        injected = (n_narrow is not None and n_base > 0 and n_narrow == 0)
        syntax_leak = bool(broken is not None and broken.resp_body
                           and "Unable to parse" in (broken.resp_body or ""))
        if not (injected or syntax_leak):
            return
        why = []
        if injected:
            why.append(f"adding '+conhostName:<nonexistent>' changed the result count from "
                       f"{n_base} to {n_narrow}, so the parameter is parsed as query syntax")
        if syntax_leak:
            why.append("an unbalanced quote produced a query-parser error, confirming the "
                       "value reaches the query string unescaped")
        yield Finding(
            vuln_class=VulnClass.SQLI, severity=Severity.MEDIUM,
            title="Lucene/Elasticsearch query injection via the page-search 'path' parameter",
            endpoint="GET /api/v1/page/search",
            description=(
                "The 'path' parameter is interpolated into an Elasticsearch query_string "
                "clause with only '/' escaped, so a caller can inject additional or negated "
                "clauses: " + "; ".join(why) + ". This allows escaping the restriction the "
                "endpoint relies on (+basetype:5) and steering the search beyond pages."),
            evidence=[r for r in (base, narrowed, broken) if r],
            detail={"test": "page_search_lucene_injection",
                    "baseline_results": n_base, "narrowed_results": n_narrow,
                    "parser_error_leaked": syntax_leak,
                    "impact": ("A caller can alter the search predicate, reaching content "
                               "outside the intended base type and inferring the existence of "
                               "objects through result-count differences."),
                    "remediation": ("Escape the full Lucene special-character set or bind the "
                                    "value as a term query instead of concatenating it into "
                                    "query_string."),
                    "cwe": "CWE-943",
                    "auto_confirm": {
                        "confirmed": True, "kind": "differential_observation",
                        "exploitability": "exploitable",
                        "reason": "; ".join(why),
                        "repro": ("GET /api/v1/page/search?path=*%20%2BconhostName:nosuchhost "
                                  "and compare the result count with path=*")}},
            confidence="firm", verdict="true_positive", exploitability="exploitable")
