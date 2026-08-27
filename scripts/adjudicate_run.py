#!/usr/bin/env python3
"""adjudicate_run.py — one-off interactive-session adjudication driver.

Live re-tests (via deluluscan.recheck.recheck, the same engine the interactive
deluluscan-audit skill drives by hand) every finding that needs it:
  - anything not yet resolved by real traffic (inconclusive/tentative/
    unverified/conditional) — mirrors ci_runner.py's _NEEDS_ADJUDICATION set.
  - every critical/high finding regardless of current verdict, for a fresh
    confirm-to-proof pass and a richer reproduction trail before reporting.

Never invents a verdict: recheck() either returns real traffic evidence or
"not_tested", in which case the original verdict is left untouched (same
discipline as ci_runner.adjudicate_one). Writes results back into results.json
in place and a full audit trail to deluluscan-out/adjudication_log.json.
"""
from __future__ import annotations

import argparse
import copy
import json

from deluluscan.config import load_config
from deluluscan.recheck import _build_endpoint, recheck, scanners_for_class
from deluluscan.scanners import SCANNER_REGISTRY

NEEDS_ADJUDICATION = {"unverified", "tentative", "inconclusive", "conditional"}


def retest_scanners(finding: dict) -> list[str]:
    detail = finding.get("detail", {}) or {}
    named = detail.get("scanner") or finding.get("scanner")
    if named in SCANNER_REGISTRY:
        return [named]
    return [s for s in scanners_for_class(finding.get("vuln_class", "")) if s in SCANNER_REGISTRY]


def adjudicate_one(cfg, finding: dict) -> tuple[dict, dict]:
    f = copy.deepcopy(finding)
    ep_str = f.get("endpoint", "")
    parts = ep_str.split(None, 1)
    scanners = retest_scanners(f)
    log = {"endpoint": ep_str, "title": f.get("title"), "prior_verdict": f.get("verdict")}

    if len(parts) != 2 or not scanners:
        log["outcome"] = "no_retest_scanner"
        return f, log

    method, path = parts
    detail = f.get("detail", {}) or {}
    endpoint = _build_endpoint(method, path, detail.get("param"), None)
    try:
        retest = recheck(cfg, endpoint, scanners)
    except Exception as exc:  # pragma: no cover - defensive
        log["outcome"] = "recheck_error"
        log["error"] = str(exc)
        return f, log

    rv = retest.get("verdict")
    log["retest_verdict"] = rv
    log["reasons"] = retest.get("reasons")
    log["repro"] = retest.get("repro")
    if rv and rv != "not_tested":
        f["verdict"] = rv
        f["reverified"] = True
        f["reverify_reasons"] = retest.get("reasons")
        log["outcome"] = "reverified"
    else:
        log["outcome"] = "no_live_traffic"
    return f, log


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--config", default="config.dev.yaml")
    p.add_argument("--results", default="deluluscan-out/results.json")
    p.add_argument("--log-out", default="deluluscan-out/adjudication_log.json")
    p.add_argument("--include-severities", default="critical,high",
                    help="comma list of severities to force-reverify even if already live-verdicted")
    args = p.parse_args(argv)

    cfg = load_config(args.config)
    force_sev = {s.strip() for s in args.include_severities.split(",") if s.strip()}

    with open(args.results) as fh:
        data = json.load(fh)
    findings = data["findings"]

    logs = []
    updated = 0
    for i, f in enumerate(findings):
        verdict = f.get("verdict")
        sev = f.get("severity")
        needs = verdict in NEEDS_ADJUDICATION or sev in force_sev
        if not needs:
            continue
        new_f, log = adjudicate_one(cfg, f)
        log["index"] = i
        logs.append(log)
        if log["outcome"] == "reverified":
            findings[i] = new_f
            updated += 1
        print(f"[{i}] {log['outcome']:16s} {log.get('prior_verdict','?'):20s} -> "
              f"{new_f.get('verdict','?'):20s} {f.get('endpoint','')}")

    with open(args.results, "w") as fh:
        json.dump(data, fh, indent=2)
    with open(args.log_out, "w") as fh:
        json.dump(logs, fh, indent=2)

    print(f"\n[adjudicate_run] {len(logs)} finding(s) re-tested live, {updated} verdict(s) updated")
    print(f"[adjudicate_run] wrote {args.results} and {args.log_out}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
