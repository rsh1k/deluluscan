"""Assessment — run the applicable modules against a target and MERGE their
findings into one deduplicated set + a report payload.

Each module keeps its own fetch contract (they differ), so the runner invokes
each engine with its own default fetch (or an injected one for tests) and
aggregates the results. Nothing is published — the payload is handed to
assess.report.write_reports for LOCAL multi-format export.
"""
from __future__ import annotations

import time
from typing import Callable, Optional

from ..models import Finding


def dedup(findings: list) -> list:
    """Drop duplicates that collide on (vuln_class, normalized title, endpoint)."""
    seen = set()
    out = []
    for f in findings:
        key = (f.vuln_class.value if hasattr(f.vuln_class, "value") else f.vuln_class,
               (f.title or "").strip().lower(), (f.endpoint or "").strip())
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


class Assessment:
    def __init__(self, target: str):
        self.target = target
        self.findings: list[Finding] = []
        self.modules_run: list[str] = []

    def add(self, findings, module: Optional[str] = None) -> "Assessment":
        self.findings.extend(findings or [])
        if module:
            self.modules_run.append(module)
        return self

    def payload(self, meta_extra: Optional[dict] = None, correlate_chains: bool = True) -> dict:
        deduped = dedup(self.findings)
        chains = []
        if correlate_chains:
            from ..correlate import correlate as _correlate
            sugg = _correlate(deduped)
            deduped = deduped + [s.to_finding() for s in sugg]   # surface chains in the report
            chains = [s.to_objective() for s in sugg]            # objectives for the agentic engine
        return {
            "findings": [f.to_dict() for f in deduped],
            "meta": {"target": self.target, "generated_at": time.time(),
                     "modules": self.modules_run, "finding_count": len(deduped),
                     "attack_chains": chains, "tool": "deluluscan", **(meta_extra or {})},
        }


def run_web_assessment(target: str, *, domain: Optional[str] = None,
                       graphql_url: Optional[str] = None,
                       modules: Optional[list] = None,
                       sast_path: Optional[str] = None,
                       spec_path: Optional[str] = None,
                       recon_fetch: Optional[Callable] = None,
                       header_fetch: Optional[Callable] = None,
                       secret_fetch: Optional[Callable] = None,
                       gql_fetch: Optional[Callable] = None) -> Assessment:
    """Live-run the web-facing modules (recon, headers, secrets, webapi) and merge.
    Pass the *_fetch args to run offline in tests."""
    mods = modules if modules is not None else (
        ["recon", "headers", "secrets"] + (["webapi"] if graphql_url else []))
    a = Assessment(target)

    if "recon" in mods:
        from ..recon.engine import ReconEngine, _default_fetch as rd
        eng = ReconEngine(fetch=recon_fetch or rd)
        prof = eng.run(target, domain=domain, do_subdomains=bool(domain))
        a.add(prof.to_findings(), "recon")

    if "headers" in mods:
        from ..headers.engine import HeaderScan
        a.add(HeaderScan().scan(header_fetch or HeaderScan.default_fetch, target), "headers")

    if "secrets" in mods:
        from ..secrets.engine import SecretScan
        a.add(SecretScan().scan_site(secret_fetch or SecretScan.default_fetch, target), "secrets")

    if "webapi" in mods and graphql_url:
        from ..webapi.engine import WebApiScan
        def _gql_default(url, body):
            import requests
            r = requests.post(url, json=body, timeout=15)
            try:
                return r.status_code, r.json()
            except Exception:
                return r.status_code, {}
        a.add(WebApiScan().graphql(gql_fetch or _gql_default, graphql_url), "webapi")

    # source + contract (offline; run whenever a path is supplied, independent of `mods`)
    if sast_path:
        from ..sast import SastScan
        a.add(SastScan().scan_path(sast_path), "sast")
    if spec_path:
        from ..apispec import ApiSpecScan
        a.add(ApiSpecScan().scan_file(spec_path), "apispec")
    return a
