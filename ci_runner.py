"""ci_runner.py — nightly CI adjudication glue.

Reads a deluluscan scan's results.json, live re-tests every finding deluluscan itself
left unresolved (deluluscan.recheck.recheck — a programmatic, non-interactive
re-test primitive, no human in the loop), then asks deluluscan's existing AI
analyst (deluluscan.ai.analyst.AIAnalyst, configured with ai.provider: bedrock in
config.ci.yaml) for a verdict via a single, bounded, tool-free call per
finding to AWS Bedrock's Converse API (Claude, via the org's existing
Bedrock setup — see deluluscan/ai/analyst.py's _bedrock()). Writes a dated
snapshot + latest.json for the calling workflow to publish (this repo has no
opinion on where results end up — target-aios's workflow uploads/downloads
this output as a build artifact and commits it to its own security-data
branch).

Safety boundary (deliberate): this script is READ-ONLY against deluluscan's own
source. It never edits a scanner, never runs an agentic Claude Code session,
and produces no side effects beyond the --out-dir it's given. If the AI
analyst's reasoning suggests a finding is a scanner artifact rather than
genuine target behavior, this script flags it (needs_scanner_review) for a
human to address later via the interactive deluluscan-audit skill, instead of
silently resolving or auto-fixing it.

Usage:
    python3 ci_runner.py --results deluluscan-out/results.json \
        --config config.ci.yaml --out-dir ci-out/data
"""
from __future__ import annotations

import argparse
import copy
import datetime
import json
import os

from deluluscan.ai.analyst import AIAnalyst
from deluluscan.config import load_config
from deluluscan.recheck import _build_endpoint, recheck, scanners_for_class
from deluluscan.scanners import SCANNER_REGISTRY

# The same set the interactive deluluscan-audit skill's step 2 targets.
_NEEDS_ADJUDICATION = {"unverified", "tentative", "inconclusive", "conditional"}

# Verdicts that came from real traffic against the live target. The AI may
# annotate these but must never overwrite them: a model reading stale evidence is
# not a stronger signal than a probe that just ran.
_LIVE_VERDICTS = {"true_positive", "likely_true_positive",
                  "false_positive", "likely_false_positive"}

# Phrases in the AI analyst's reasoning that point at a scanner artifact rather
# than genuine target behavior. These get flagged, not auto-resolved — fixing
# the scanner itself is a human/interactive-skill decision.
_SCANNER_BUG_MARKERS = (
    "malformed", "artifact", "false positive", "expected behavior",
    "before authorization", "not a vulnerability", "benign",
)


def _load_findings(raw) -> tuple[list[dict], dict]:
    """Accept either a bare findings list or {"findings"/"results": [...], "meta": {...}}."""
    if isinstance(raw, list):
        return raw, {}
    findings = raw.get("findings", raw.get("results", []))
    return findings, raw.get("meta", {})


def _build_ctx(finding: dict) -> dict:
    """Mirror the ctx shape deluluscan.ai.analyst.AIAnalyst.triage() already builds."""
    ev = (finding.get("evidence") or [None])[0] or {}
    return {
        "vuln_class": finding.get("vuln_class", ""),
        "title": finding.get("title", ""),
        "endpoint": finding.get("endpoint", ""),
        "description": finding.get("description", ""),
        "detail": finding.get("detail", {}),
        "evidence_status": ev.get("status"),
        "evidence_excerpt": (ev.get("resp_body") or "")[:600],
    }


def _retest_scanners(finding: dict) -> list[str]:
    """Which scanners can live re-test this finding, derived from the registry.

    Previously a hardcoded 6-entry vuln_class->scanner dict lived here, so ~30
    other classes (authz, privesc, csrf, injection, ...) were never live re-tested
    in CI and were adjudicated by the model alone. deluluscan.recheck.scanners_for_class()
    derives this from SCANNER_REGISTRY and cannot drift out of sync — the same
    reason deluluscan.recheck stopped hardcoding it.
    """
    detail = finding.get("detail", {}) or {}
    named = detail.get("scanner") or finding.get("scanner")
    if named in SCANNER_REGISTRY:
        return [named]
    return [s for s in scanners_for_class(finding.get("vuln_class", ""))
            if s in SCANNER_REGISTRY]


def adjudicate_one(cfg, ai: AIAnalyst, finding: dict) -> dict:
    """Live re-test a single finding, then let the AI annotate it.

    Verdict discipline, which is the whole point of this file: a verdict may only
    be set by traffic that actually ran. The AI is ADVISORY — it can flag a
    scanner artifact and it can move a finding that was never live-tested to
    'inconclusive', but it can never promote something to true_positive or
    overwrite a live re-test result. Returns a new dict; never mutates the input.
    """
    f = copy.deepcopy(finding)
    if f.get("verdict") not in _NEEDS_ADJUDICATION:
        return f

    ep_str = f.get("endpoint", "")
    parts = ep_str.split(None, 1)
    scanners = _retest_scanners(f)

    retested_live = False
    if len(parts) == 2 and scanners:
        method, path = parts
        detail = f.get("detail", {}) or {}
        endpoint = _build_endpoint(method, path, detail.get("param"), None)
        try:
            retest = recheck(cfg, endpoint, scanners)
        except Exception as exc:
            f["ai_notes"] = f"[ci_runner] recheck failed: {exc}"
            return f
        f["retest"] = {"verdict": retest.get("verdict"), "reasons": retest.get("reasons"),
                       "repro": retest.get("repro"), "scanners": scanners,
                       "probe_stats": retest.get("probe_stats")}
        rv = retest.get("verdict")
        # recheck() returns "not_tested" when nothing actually probed the target.
        # That is not a result — leave the original verdict alone rather than
        # recording a refutation no traffic earned.
        if rv and rv != "not_tested":
            f["verdict"] = rv
            retested_live = rv in _LIVE_VERDICTS
        else:
            f["retest_note"] = ("no live traffic reached this endpoint — verdict is "
                                "unchanged and remains unadjudicated")
    else:
        f["retest_note"] = ("no registered scanner covers this finding's vuln_class, "
                            "so it was NOT live re-tested")

    verdict_result = ai.analyze_evidence(_build_ctx(f))
    if verdict_result:
        is_real = verdict_result.get("is_real")
        reason = verdict_result.get("reason", "")
        if reason:
            f["ai_notes"] = reason
        f["ai_opinion"] = {"is_real": is_real, "reason": reason, "advisory": True}
        if is_real is False and any(m in reason.lower() for m in _SCANNER_BUG_MARKERS):
            # Worth a human's attention either way — flagging is not resolving.
            f["needs_scanner_review"] = True
        if retested_live:
            # A live probe already answered this. Record disagreement instead of
            # letting the model overrule the traffic.
            live_says_real = f["verdict"] in ("true_positive", "likely_true_positive")
            if is_real is not None and is_real != live_says_real:
                f["ai_disagrees_with_retest"] = True
        elif is_real is False:
            # Never live-confirmed and the model doubts it: the honest ceiling is
            # "inconclusive", not "false_positive". Nothing refuted it.
            f["verdict"] = "inconclusive"
    return f


def adjudicate(cfg, findings: list[dict], ai: AIAnalyst) -> list[dict]:
    return [adjudicate_one(cfg, ai, finding) for finding in findings]


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--results", default="deluluscan-out/results.json")
    p.add_argument("--config", default="config.ci.yaml")
    p.add_argument("--out-dir", default="ci-out/data")
    args = p.parse_args(argv)

    cfg = load_config(args.config)
    ai = AIAnalyst(cfg.ai)

    with open(args.results) as fh:
        raw = json.load(fh)
    findings, meta = _load_findings(raw)

    adjudicated = adjudicate(cfg, findings, ai)

    today = datetime.date.today().isoformat()
    scans_dir = os.path.join(args.out_dir, "scans")
    os.makedirs(scans_dir, exist_ok=True)
    snapshot = {"scan_date": today, "meta": meta, "findings": adjudicated}

    dated_path = os.path.join(scans_dir, f"{today}.json")
    latest_path = os.path.join(args.out_dir, "latest.json")
    with open(dated_path, "w") as fh:
        json.dump(snapshot, fh, indent=2)
    with open(latest_path, "w") as fh:
        json.dump(snapshot, fh, indent=2)

    flagged = sum(1 for f in adjudicated if f.get("needs_scanner_review"))
    print(f"[ci_runner] wrote {dated_path} and {latest_path} "
          f"({len(adjudicated)} findings, {flagged} flagged for scanner review)")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
