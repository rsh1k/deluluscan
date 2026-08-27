"""deluluscan.recheck — the single-finding live re-test primitive.

This is the engine Claude drives in its find -> validate -> retest -> adjudicate
loop. Given ONE endpoint (and optionally a specific scanner), it re-runs that
scanner live against that endpoint and re-verifies the result, then prints a
structured JSON verdict. Claude calls this repeatedly while auditing: after the
initial scan surfaces candidates, Claude re-checks each one here to decide
true/false positive, and can re-run it again after a fix to confirm.

Usage (what Claude Code invokes):
    python3 -m deluluscan.recheck --config config.yaml \
        --method GET --path /api/categories --scanner sqli [--param orderby]
    python3 -m deluluscan.recheck --config config.yaml --from-results deluluscan-out/results.json --index 3

Output: a single JSON object on stdout:
    {"verdict": "...", "exploitability": "...", "confidence": "...",
     "findings": [...], "reasons": [...], "repro": "...", "retested": true}
"""
from __future__ import annotations

import argparse
import json
import sys

from .config import load_config
from .auth import AuthManager
from .http_client import HttpClient
from .models import Endpoint
from .scanners import SCANNER_REGISTRY


def _class_index() -> dict[str, list[str]]:
    """vuln_class -> [scanner names], derived from the registry (never hardcoded)."""
    idx: dict[str, list[str]] = {}
    for name, cls in SCANNER_REGISTRY.items():
        for vc in getattr(cls, "vuln_classes", []) or []:
            idx.setdefault(vc, []).append(name)
    return {k: sorted(v) for k, v in idx.items()}


# Scanners that fire on nearly every endpoint and would swamp a targeted
# re-test; only used when a class has no more specific scanner.
_BROAD = {"owasp", "passive", "auth_enum"}


def scanners_for_class(vuln_class: str) -> list[str]:
    """The best re-test scanners for a vuln class, most specific first."""
    cands = _class_index().get(vuln_class, [])
    focused = [c for c in cands if c not in _BROAD]
    return focused or cands


def _build_endpoint(method: str, path: str, param: str | None,
                    body_prop: str | None) -> Endpoint:
    query_params = [{"name": param}] if param else []
    body = {"type": "object", "properties": {body_prop: {"type": "string"}}} if body_prop else {}
    path_params = []
    import re
    for m in re.finditer(r"\{(\w+)\}", path):
        path_params.append(m.group(1))
    return Endpoint(method=method.upper(), path=path, query_params=query_params,
                    request_body_schema=body, path_params=path_params, source="recheck")


def recheck(cfg, endpoint: Endpoint, scanner_names: list[str]) -> dict:
    """Re-run the named scanner(s) live against a single endpoint and verify."""
    cfg.assert_target_allowed()
    # timeout_s lives on cfg.SCAN, not cfg — reading it off cfg silently pinned
    # every recheck to the 15.0s default and ignored the configured value.
    # getattr because recheck() is a documented programmatic entry point that
    # callers (ci_runner, tests) invoke with hand-built config objects.
    client = HttpClient(cfg.base_url, rate_limit_rps=cfg.scan.rate_limit_rps,
                        timeout_s=getattr(cfg.scan, "timeout_s", 15.0),
                        verify_tls=cfg.verify_tls)
    auth = AuthManager(client)

    findings = []
    # Evidence discipline: track exactly which scanners ran, which were skipped
    # (and why), and how much traffic each actually sent. A verdict that cannot
    # point at real probes is NOT a refutation — it is "not_tested".
    ran: list[str] = []
    skipped: dict[str, str] = {}
    unknown: list[str] = []
    for name in scanner_names:
        cls = SCANNER_REGISTRY.get(name)
        if cls is None:
            unknown.append(name)
            hint = ""
            if name in _class_index():
                hint = (f" — '{name}' is a vuln CLASS, not a scanner; "
                        f"use --vuln-class {name} (expands to "
                        f"{', '.join(scanners_for_class(name))})")
            skipped[name] = (f"scanner '{name}' is not registered{hint}. "
                             f"Known scanners: {', '.join(sorted(SCANNER_REGISTRY))}")
            continue
        scanner = cls(client, auth, cfg, cfg.identities)
        try:
            if not scanner.applies_to(endpoint):
                skipped[name] = ("scanner.applies_to() returned False for this endpoint "
                                 "— it sent no probes (e.g. the endpoint has no parameter "
                                 "of the shape this scanner targets). Supply --param/"
                                 "--body-prop, or pick a scanner suited to this endpoint.")
                continue
            before = client.request_count
            produced = list(scanner.run(endpoint) or [])
            findings.extend(produced)
            ran.append(name)
            if client.request_count == before:
                skipped[name] = ("scanner ran but sent zero HTTP requests — nothing was "
                                 "actually exercised on the target.")
                ran.remove(name)
        except Exception as exc:
            return {"error": f"scanner {name} failed: {exc}", "retested": True,
                    "probe_stats": client.probe_stats()}

    probe = client.probe_stats()
    tested = bool(ran) and probe["responses"] > 0

    # A verdict must be EARNED. With no scanner having actually probed the
    # target, we know nothing — emit not_tested rather than a false refutation.
    if not tested:
        why = "; ".join(f"{k}: {v}" for k, v in skipped.items()) or \
              "no scanner produced any traffic against this endpoint"
        return {
            "verdict": "not_tested",
            "exploitability": "unknown",
            "confidence": "none",
            "endpoint": f"{endpoint.method} {endpoint.path}",
            "scanners": scanner_names,
            "scanners_ran": ran, "scanners_skipped": skipped,
            "findings": [], "probe_stats": probe,
            "reasons": [
                "NOT TESTED — this endpoint was not actually exercised, so no "
                "conclusion can be drawn. This is NOT a false positive.",
                why,
            ],
            "repro": "", "retested": False,
        }

    verdict = "false_positive"   # a scanner really probed and nothing reproduced
    exploitability = "not_exploitable"
    confidence = "firm"
    reasons = []
    repro = ""
    out_findings = []
    if findings:
        # Re-verify the freshly-produced findings with the full differential
        # oracle. NOTE: the Verifier constructor takes the Config object as its
        # 4th arg (config=), matching orchestrator.py / agent.py. Passing an int
        # here used to raise AttributeError inside __init__, which was silently
        # swallowed — so verification never ran and recheck could only ever emit
        # false_positive/inconclusive, never true_positive. Surface any failure
        # instead of hiding it.
        from .verify import Verifier
        try:
            v = Verifier(client, auth, cfg.identities, cfg)
            v.verify_all(findings)
        except Exception as exc:
            return {"error": f"verification failed: {exc}", "retested": True,
                    "endpoint": f"{endpoint.method} {endpoint.path}",
                    "scanners": scanner_names,
                    "findings": [f.to_dict() for f in findings]}
        # aggregate: the strongest verdict among reproduced findings
        rank = {"true_positive": 5, "likely_true_positive": 4,
                "inconclusive": 2, "unverified": 1, "likely_false_positive": 1,
                "false_positive": 0}
        findings.sort(key=lambda f: rank.get(f.verdict, 0), reverse=True)
        top = findings[0]
        verdict = top.verdict if top.verdict != "unverified" else "inconclusive"
        exploitability = top.exploitability
        confidence = top.confidence
        # The verifier writes its reasoning under detail["verification"], not at
        # the top level of detail — read it from the right place.
        vdet = (top.detail or {}).get("verification", {})
        reasons = list(vdet.get("reasons", [])) or [top.description]
        repro = vdet.get("repro", "") or (top.detail or {}).get("repro", "")
        out_findings = [f.to_dict() for f in findings]
    else:
        reasons = [
            f"REFUTED — {', '.join(ran)} actively probed this endpoint "
            f"({probe['requests']} request(s) across identities "
            f"{', '.join(probe['identities'])}) and reproduced nothing. The original "
            f"candidate appears to be a FALSE POSITIVE (or has since been fixed)."]

    return {"verdict": verdict, "exploitability": exploitability, "confidence": confidence,
            "endpoint": f"{endpoint.method} {endpoint.path}",
            "scanners": scanner_names, "scanners_ran": ran, "scanners_skipped": skipped,
            "findings": out_findings, "probe_stats": probe,
            "reasons": reasons, "repro": repro, "retested": True}


def main(argv=None):
    p = argparse.ArgumentParser(description="Re-test a single endpoint and adjudicate it live.")
    p.add_argument("--config", help="path to the YAML config (required unless --list-scanners)")
    p.add_argument("--method", default="GET")
    p.add_argument("--path", help="endpoint path, e.g. /api/categories")
    p.add_argument("--scanner", help="scanner name, or comma-separated list "
                                     "(e.g. sqli / idor,privesc); default: infer from "
                                     "the --from-results finding's vuln_class")
    p.add_argument("--vuln-class", help="re-test with every scanner that handles this "
                                        "vuln class (e.g. authz, idor, sqli)")
    p.add_argument("--list-scanners", action="store_true",
                   help="list registered scanners and the vuln classes they cover, then exit")
    p.add_argument("--param", help="query parameter to target (e.g. orderby)")
    p.add_argument("--body-prop", help="request-body property to target")
    p.add_argument("--from-results", help="path to a results.json to pull a finding from")
    p.add_argument("--index", type=int, help="finding index within --from-results")
    args = p.parse_args(argv)

    if args.list_scanners:
        print(json.dumps({"scanners": {n: getattr(c, "vuln_classes", [])
                                       for n, c in sorted(SCANNER_REGISTRY.items())},
                          "by_vuln_class": _class_index()}, indent=2))
        return 0

    if not args.config:
        print(json.dumps({"error": "--config is required (or use --list-scanners)"}))
        return 1
    cfg = load_config(args.config)

    method, path, scanner, param, body_prop = (args.method, args.path, args.scanner,
                                               args.param, args.body_prop)
    if not scanner and args.vuln_class:
        matches = scanners_for_class(args.vuln_class)
        if not matches:
            print(json.dumps({"error": f"no scanner handles vuln_class '{args.vuln_class}'",
                              "known_classes": sorted(_class_index())}))
            return 1
        scanner = ",".join(matches)
    # if pulling from a prior results.json, reconstruct the target from the finding
    if args.from_results is not None and args.index is not None:
        try:
            data = json.load(open(args.from_results))
            f = data["findings"][args.index]
        except (OSError, KeyError, IndexError, json.JSONDecodeError) as exc:
            print(json.dumps({"error": f"cannot read finding: {exc}"})); return 1
        ep_str = f.get("endpoint", "")
        parts = ep_str.split(None, 1)
        if len(parts) == 2:
            method, path = parts[0], parts[1]
        detail = f.get("detail", {}) or {}
        param = param or detail.get("param")
        # Map vuln_class -> re-test scanner(s). Derived from the registry itself
        # so it can never drift out of sync (the old hardcoded dict mapped
        # "authz" -> a scanner name that does not exist, which silently produced
        # bogus false_positive verdicts).
        vc = f.get("vuln_class", "")
        if not scanner:
            matches = scanners_for_class(vc)
            if not matches:
                print(json.dumps({
                    "error": f"no scanner handles vuln_class '{vc}'",
                    "known_classes": sorted(_class_index())}))
                return 1
            scanner = ",".join(matches)

    if not path or not scanner:
        print(json.dumps({"error": "need --path and --scanner (or --from-results with --index)"}))
        return 1

    endpoint = _build_endpoint(method, path, param, body_prop)
    names = [s.strip() for s in scanner.split(",") if s.strip()]
    result = recheck(cfg, endpoint, names)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
