"""Command-line interface.

Usage:
    python -m deluluscan.cli --config config.yaml
    python -m deluluscan.cli --base-url http://localhost:8080 --scanners idor,xss
    python -m deluluscan.cli --config config.yaml --web   # launch the web UI

The CLI prints a live progress feed and writes results.json + results.html to
the configured output directory.
"""
from __future__ import annotations

import argparse
import json
import sys

from .config import load_config
from .orchestrator import Orchestrator
import os

from .reporting import write_html, write_json

_SEV_GLYPH = {"critical": "🟥", "high": "🟧", "medium": "🟨",
              "low": "🟦", "info": "⬜"}


def _progress(event: str, data: dict) -> None:
    if event == "start":
        print(f"[*] target: {data['target']}")
    elif event == "identity":
        ok = "ok" if data["ok"] else "FAIL"
        print(f"[auth] {data['role']:<9} {ok}: {data['msg']}")
    elif event == "discovery":
        print(f"[*] discovered {data['count']} endpoints from {data['source']}")
    elif event == "fingerprint":
        if data.get("error"):
            print(f"[!] fingerprint error: {data['error']}")
        else:
            dets = data.get("detections", [])
            if dets:
                print("[*] recon — technology fingerprint:")
                for d in dets:
                    v = f" {d['version']}" if d.get("version") else ""
                    print(f"      - {d['tech']}{v}  ({d['category']}, conf {d['confidence']})")
            else:
                print("[*] recon — no technology signatures matched (generic target)")
    elif event == "profile_gate":
        print(f"[*] skipped technology-specific scanners not matching the target: "
              f"{', '.join(data['skipped'])} — {data['reason']}")
    elif event == "fuzz":
        if data.get("error"):
            print(f"[!] fuzz error: {data['error']}")
        else:
            bk = ", ".join(f"{k}:{v}" for k, v in (data.get("by_kind") or {}).items())
            print(f"[*] fuzzing: {data.get('leads',0)} candidate lead(s) for human review"
                  f"{' ['+bk+']' if bk else ''} — these are leads, not confirmed vulnerabilities")
    elif event == "scanners_warning":
        print(f"\n[!] {len(data['disabled_high_value'])} HIGH-VALUE scanner(s) are DISABLED "
              f"by your config's scan.scanners list:")
        for name, desc in data["disabled_high_value"].items():
            print(f"      - {name:<14} ({desc})")
        print(f"    {data['hint']}\n")
    elif event == "scanners_active":
        print(f"[*] active scanners ({len(data['names'])}): {', '.join(data['names'])}")
    elif event == "sourcescan":
        if data.get("error"):
            print(f"[!] source scan error: {data['error']}")
        else:
            bc = ", ".join(f"{k}:{v}" for k, v in (data.get("by_class") or {}).items())
            mantis = f", {data['mantis_candidates']} from Mantis ({data['mantis_dir']})" \
                if data.get("mantis_dir") else ""
            print(f"[*] source scan ({data.get('mode')}): {data.get('candidates',0)} candidate(s)"
                  f"{' ['+bc+']' if bc else ''}{mantis}, "
                  f"{data.get('endpoints_added',0)} endpoint(s) queued for live probing")
            wh = {k: v for k, v in (data.get("mantis_withheld") or {}).items() if v}
            if wh:
                print(f"    withheld by Mantis's own triage: "
                      + ", ".join(f"{v} {k.replace('_', ' ')}" for k, v in wh.items()))
    elif event == "integration":
        print(f"[+] integration {data.get('name')}: "
              f"{ {k:v for k,v in data.items() if k!='name'} }")
    elif event == "endpoint":
        sys.stdout.write(f"\r[scan] {data['i']}/{data['total']} {data['key'][:60]:<60}")
        sys.stdout.flush()
    elif event == "deep_verify":
        if data.get("error"):
            print(f"[!] deep verification error: {data['error']}")
        else:
            print(f"[*] deep verification: {data.get('analysed',0)} finding(s) analysed, "
                  f"{data.get('exploitability_refined',0)} exploitability rating(s) refined "
                  f"(multi-identity + session-riding + filter-bypass)")
    elif event == "telemetry":
        phase = data.get("phase")
        if phase == "start":
            print(f"[*] observability: tapping {data.get('container')} — "
                  f"{', '.join(data.get('sources', []))} (grey-box: logs + memory/CPU)")
        elif phase in ("unavailable", "error"):
            print(f"[!] observability: {data.get('note') or data.get('error')}")
        elif phase == "analyze":
            print(f"\n[*] observability: correlated {data.get('events',0)} telemetry event(s) "
                  f"across {data.get('probe_windows',0)} probe window(s) — "
                  f"{data.get('exception_lines',0)} server exception line(s), "
                  f"{data.get('secret_lines',0)} secret line(s) -> {data.get('findings',0)} finding(s)")
    elif event == "memory":
        if data.get("error"):
            print(f"[!] engagement memory error: {data['error']}")
        elif data.get("phase") == "recall":
            if data.get("known"):
                print(f"[*] engagement memory: KNOWN target {data['target_key']} "
                      f"(last seen {data.get('last_seen','?')}) — "
                      f"{data.get('exploitable_endpoints',0)} exploitable endpoint(s), "
                      f"{len(data.get('gotchas',[]))} gotcha(s) on record")
                for line in data.get("lines", []):
                    print(f"      · {line}")
            else:
                print(f"[*] engagement memory: new target {data['target_key']} "
                      f"(no prior scans on record)")
        elif data.get("phase") == "prioritize":
            print(f"[*] engagement memory: re-probing {data['promoted']} endpoint(s) "
                  f"first — {data['reason']}")
        elif data.get("phase") == "annotate":
            print(f"[*] engagement memory: {data['matched']} finding(s) seen on this "
                  f"target before (recurring/regression tagged)")
        elif data.get("phase") == "record":
            rw = data.get("regression_watch") or []
            extra = (f"; {len(rw)} previously-exploitable endpoint(s) did NOT reproduce "
                     f"(possible fix — verify manually)" if rw else "")
            print(f"[*] engagement memory: recorded {data['recorded']} finding(s) to "
                  f"{data['file']}{extra}")
    elif event == "destructive_deferred":
        state = "will be probed in a final pass" if data.get("enabled") \
            else f"NOT probed — {data.get('reason')}"
        print(f"\n[*] {data['count']} destructive endpoint(s) held out of the main "
              f"sweep; {state}")
    elif event == "destructive_start":
        print(f"\n[*] destructive pass: probing {data['count']} endpoint(s) that can "
              f"take the target down (main sweep is complete)")
    elif event == "destructive_endpoint":
        sys.stdout.write(f"\r[destructive] {data['i']}/{data['total']} "
                         f"{data['key'][:52]:<52}")
        sys.stdout.flush()
    elif event == "destructive_outage":
        print(f"\n  [!] {data['endpoint']} — {data['note']}")
    elif event == "destructive_restart":
        print(f"\n  [*] target stopped answering — restarting: {data['command']}")
    elif event == "destructive_aborted":
        print(f"\n[!] destructive pass stopped: {data['reason']} "
              f"({data['unprobed']} endpoint(s) left unprobed — NOT 'clean')")
    elif event == "destructive_target_down":
        print(f"\n[!] target is still down after the destructive pass: {data['reason']}")
    elif event == "destructive_skipped":
        print(f"\n[*] destructive pass skipped ({data['count']} endpoint(s)): "
              f"{data['reason']}")
    elif event == "destructive_done":
        print(f"\n[*] destructive pass: {data['probed']} probed, "
              f"{data['skipped']} unprobed, {data['restarts']} restart(s), "
              f"{data['findings']} finding(s)")
    elif event == "finding":
        g = _SEV_GLYPH.get(data["severity"], "")
        print(f"\n  {g} [{data['class']}] {data['title']}")
    elif event == "error":
        print(f"\n  [!] {data['scanner']} error on {data['endpoint']}: {data['error']}")
    elif event == "done":
        print(f"\n[*] done in {data['duration_s']}s")


def _progress_agent(event: str, data: dict) -> None:
    if event == "agent_start":
        print(f"[agent] target {data['target']} · ai={data['ai']}")
    elif event == "plan":
        print(f"[plan] step {data['step']} -> {data['next']}")
    elif event == "plan_reason":
        if data.get("reason"):
            print(f"       reason: {data['reason']}")
    elif event == "identity":
        print(f"  [auth] {data['role']}: {'ok' if data['ok'] else 'FAIL'} ({data['msg']})")
    elif event == "discovery":
        print(f"  [discover] {data['count']} endpoints ({data['source']})")
    elif event == "finding":
        g = _SEV_GLYPH.get(data["severity"], "")
        print(f"  {g} [{data['class']}] {data['title']}")
    elif event == "report":
        print(f"  [report] {data}")
    elif event == "agent_error":
        print(f"  [!] {data['phase']}: {data['error']}")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="deluluscan",
        description="Authorized detection-focused API security scanner for your "
                    "own the target instance.")
    p.add_argument("--config", help="path to YAML config")
    p.add_argument("--base-url", help="override base URL")
    p.add_argument("--openapi-file", help="path to an OpenAPI spec saved from your browser")
    p.add_argument("--scanners", help="comma list: idor,xss,sqli,ssrf,owasp")
    p.add_argument("--max-endpoints", type=int, help="cap endpoints scanned")
    p.add_argument("--allow-state-changing", action="store_true",
                   help="enable scanners that write to the configured identity's "
                        "OWN resources (e.g. profile-field XSS detection)")
    p.add_argument("--allow-destructive", dest="allow_destructive",
                   action="store_true", default=None,
                   help="probe destructive operations too (shutdown, bulk delete, "
                        "reindex, DB dump). They run in a dedicated pass AFTER the "
                        "main sweep, restarting the target between probes, so they "
                        "cannot end the run early. Defaults to following "
                        "--allow-state-changing for loopback/RFC1918 targets")
    p.add_argument("--no-destructive", dest="allow_destructive",
                   action="store_false",
                   help="never probe destructive operations (they are reported as "
                        "deferred-and-unprobed rather than silently omitted)")
    p.add_argument("--restart-command",
                   help="shell command that brings the target back up when a "
                        "destructive probe takes it down "
                        "(e.g. 'docker compose restart target')")
    p.add_argument("--source-scan", action="store_true",
                   help="read the target source to find dangerous patterns and auto-generate "
                        "targeted live probes (source-informed scanning)")
    p.add_argument("--source-root", help="path to a local the target source clone (preferred); "
                                         "if omitted, specific files are fetched from GitHub")
    p.add_argument("--source-scan-ai", action="store_true",
                   help="run the optional AI review pass over source candidates")
    p.add_argument("--mantis-findings-dir",
                   help="workspace/ dir from a prior Mantis (google/mantis) code-scan "
                        "campaign against --source-root; each finding is mapped to its "
                        "the target's REST endpoint and merged into the targeted live-probe "
                        "plan (see .claude/skills/deluluscan-codescan)")
    p.add_argument("--memory-file",
                   help="engagement-memory JSON store (default: <output_dir>/"
                        "engagement_memory.json). Persists cross-scan learnings — "
                        "exploitable endpoints, verified bypasses, per-build gotchas — "
                        "and re-probes known-vulnerable endpoints first next run.")
    p.add_argument("--no-memory", action="store_true",
                   help="disable engagement memory for this run (no recall, no record)")
    p.add_argument("--fuzz", action="store_true",
                   help="fuzzing/anomaly detection: mutate inputs and surface candidate "
                        "unknown-bug LEADS for human investigation (not confirmed 0-days)")
    p.add_argument("--observe", action="store_true",
                   help="grey-box observability: tap the target container's own logs + "
                        "memory/CPU during the scan and correlate them with each probe "
                        "(server-log-confirmed injection, secrets-in-logs, unlogged "
                        "operations, heap growth). Fail-soft if Docker is unavailable.")
    p.add_argument("--observe-container",
                   help="container to observe for --observe (default: deluluscan-target-1)")
    p.add_argument("--observe-db",
                   help="optional DB container to also tail for --observe (e.g. deluluscan-db-1)")
    p.add_argument("--no-auto-corpus", action="store_true",
                   help="do not auto-detect the Mantis code-scan corpus at the "
                        "conventional workspace path")
    p.add_argument("--skip-freshness", action="store_true",
                   help="skip the pre-flight currency check of the target source clone, "
                        "docker image and Mantis corpus")
    p.add_argument("--require-current", action="store_true",
                   help="refuse to scan unless every input is confirmed current "
                        "(stale OR unverified both block)")
    p.add_argument("--freshness-container", default="deluluscan-target-1",
                   help="container whose image is checked for currency "
                        "(default: deluluscan-target-1)")
    p.add_argument("--web", action="store_true", help="launch the web UI instead")
    p.add_argument("--agent", action="store_true",
                   help="run the autonomous agentic engine (phase planner loop)")
    p.add_argument("--resume", action="store_true",
                   help="resume a previous agent session from output_dir/session.json")
    p.add_argument("--max-steps", type=int, default=20,
                   help="max planner steps in agent mode")
    p.add_argument("--ai", help="override AI provider: none|anthropic|openai|deepseek|"
                   "openai_compat|ollama|claude_code|codex|bedrock")
    p.add_argument("--ai-model", help="override the AI model id for the selected provider")
    p.add_argument("--ai-endpoint", help="override the base URL for an OpenAI-compatible "
                   "provider (openai|deepseek|openai_compat); e.g. a local vLLM/LM Studio gateway")
    p.add_argument("--formats", default="",
                   help="extra export formats, comma-separated: csv,xlsx,junit "
                        "(HTML + JSON are always written)")
    p.add_argument("--templates-dir", default=None,
                   help="directory of YAML detection templates (default: ./templates). "
                        "Inspect with: python3 -m deluluscan.templates")
    p.add_argument("--no-templates", action="store_true",
                   help="skip the YAML template scanner")
    p.add_argument("--plugins-dir", default=None,
                   help="directory of out-of-tree scanner plugins. Loading a plugin "
                        "EXECUTES it, so the directory must not be world-writable")
    p.add_argument("--allow-plugin-override", action="store_true",
                   help="permit a plugin to replace a built-in scanner of the same name")
    p.add_argument("--diff", metavar="BASELINE_JSON",
                   help="after scanning, diff against a previous results.json and "
                        "print what is new / fixed / changed")
    p.add_argument("--fail-on-new", action="store_true",
                   help="with --diff, exit non-zero when the scan introduces a NEW finding")
    p.add_argument("--notify", default="",
                   help="notify channels after the scan, comma-separated: "
                        "slack,discord,email (credentials come from the environment)")
    p.add_argument("--report-url", default="",
                   help="link included in notifications instead of any evidence")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    args = p.parse_args(argv)

    cfg = load_config(args.config)
    if args.base_url:
        cfg.base_url = args.base_url
    if args.openapi_file:
        cfg.openapi_file = args.openapi_file
    if args.scanners:
        cfg.scan.scanners = [s.strip() for s in args.scanners.split(",")]
    if args.max_endpoints:
        cfg.scan.max_endpoints = args.max_endpoints
    if args.allow_state_changing:
        cfg.scan.allow_state_changing = True
    if args.allow_destructive is not None:
        cfg.scan.destructive.enabled = args.allow_destructive
    if args.restart_command:
        cfg.scan.destructive.restart_command = args.restart_command
    if args.observe:
        cfg.observe.enabled = True
    if getattr(args, "observe_container", None):
        cfg.observe.enabled = True
        cfg.observe.container = args.observe_container
    if getattr(args, "observe_db", None):
        cfg.observe.db_container = args.observe_db
    if args.source_scan:
        cfg.enable_source_scan = True
    if args.source_root:
        cfg.enable_source_scan = True
        cfg.source_root = args.source_root
    if args.source_scan_ai:
        cfg.source_scan_ai = True
    if args.mantis_findings_dir:
        cfg.enable_source_scan = True
        cfg.mantis_findings_dir = args.mantis_findings_dir
    elif not args.no_auto_corpus:
        # Auto-connect the code-scan corpus. Previously the deluluscan-codescan ->
        # deluluscan-audit pipeline only engaged if the operator remembered
        # --mantis-findings-dir, so a 20-finding corpus sat on disk contributing
        # NOTHING to consecutive full-surface scans (source_scan enabled=False,
        # candidates=0) while the report gave no hint it had been ignored.
        import os as _os
        for _cand in (".target-src/mantis-workspace/workspace",
                      "mantis-workspace/workspace"):
            if _os.path.isdir(_os.path.join(_cand, "findings")):
                cfg.enable_source_scan = True
                cfg.mantis_findings_dir = _cand
                _n = len([f for f in _os.listdir(_os.path.join(_cand, "findings"))
                          if f.endswith(".json")])
                print(f"[*] using Mantis corpus at {_cand} ({_n} findings) — "
                      f"pass --no-auto-corpus to skip")
                break
    if getattr(args, "fuzz", False):
        cfg.fuzz = True
    if getattr(args, "no_memory", False):
        cfg.memory_enabled = False
    if getattr(args, "memory_file", None):
        cfg.memory_file = args.memory_file
    if args.ai:
        cfg.ai.provider = args.ai
    if getattr(args, "ai_model", None):
        cfg.ai.model = args.ai_model
    if getattr(args, "ai_endpoint", None):
        cfg.ai.endpoint = args.ai_endpoint

    # Pre-flight: is what we are about to test actually current? A stale target
    # yields findings upstream already fixed, or — worse — a clean report for a
    # build nobody runs. Recorded either way; only --require-current stops us.
    freshness = None
    if not args.skip_freshness:
        from .freshness import check_all
        freshness = check_all(
            clone_dir=getattr(cfg, "source_root", None) or ".target-src/core",
            container=args.freshness_container,
            mantis_state=(f"{cfg.mantis_findings_dir}/.mantis_state.json"
                          if getattr(cfg, "mantis_findings_dir", None) else None))
        for c in freshness.checks:
            print(f"[*] freshness: {c.state.upper():8} {c.name} — {c.detail}")
        for m in freshness.messages():
            print(f"[!] {m}")
        if args.require_current and (freshness.stale or freshness.unknown):
            print("[x] refusing to scan: --require-current was given and one or more "
                  "inputs are stale or unverified (see above).")
            return 3

    if args.web:
        from .web.app import serve
        serve(cfg, host=args.host, port=args.port)
        return 0

    if args.agent:
        from .agent import Agent
        agent = Agent(cfg, progress=_progress_agent)
        if args.resume and agent.resume():
            print("[*] resumed prior session")
        result = agent.run(max_steps=args.max_steps)
        crit = sum(1 for f in result["findings"]
                   if f["severity"] in ("critical", "high"))
        print(f"[*] agent finished — {len(result['findings'])} findings, "
              f"reports in {cfg.output_dir}")
        return 2 if crit else 0

    orch = Orchestrator(cfg, progress=_progress)
    result = orch.run()
    # Record what was tested against, so the report states the provenance of its
    # own conclusions rather than implying the target was current.
    if freshness is not None:
        result.setdefault("meta", {})["freshness"] = freshness.to_dict()
    jp = write_json(result, cfg.output_dir)
    hp = write_html(result, cfg.output_dir)
    if getattr(orch, "coverage", None):
        from .reporting.coverage import write_coverage
        cj, ch, summary = write_coverage(orch.coverage.as_dict(), cfg.output_dir)
        print(f"[*] wrote {cj}")
        print(f"[*] wrote {ch}")
        print(f"[*] coverage: {summary['endpoints']} endpoints, "
              f"{len(summary['untouched_endpoints'])} untouched by any scanner")
        for s, pct in summary["per_scanner_pct"].items():
            print(f"      {s:18} {pct}%")
    print(f"[*] wrote {jp}")
    print(f"[*] wrote {hp}")

    # --- extra export formats ------------------------------------------------
    for fmt in [f.strip().lower() for f in (args.formats or "").split(",") if f.strip()]:
        from .reporting import exporters
        ext = {"junit": "xml"}.get(fmt, fmt)
        path = os.path.join(cfg.output_dir, f"results.{ext}")
        try:
            exporters.export(result, fmt, path)
            print(f"[*] wrote {path}")
        except Exception as exc:
            # An export problem must not discard a completed scan.
            print(f"[!] {fmt} export failed: {exc}")

    # --- diff against a baseline --------------------------------------------
    new_findings = 0
    if args.diff:
        from . import scandiff
        try:
            with open(args.diff) as fh:
                baseline = json.load(fh)
            d = scandiff.diff(baseline, result)
            print()
            print(scandiff.render(d))
            dp = os.path.join(cfg.output_dir, "scan-diff.json")
            with open(dp, "w") as fh:
                json.dump(d, fh, indent=2)
            print(f"[*] wrote {dp}")
            new_findings = d["summary"]["new"]
        except Exception as exc:
            print(f"[!] diff against {args.diff} failed: {exc}")

    # --- notifications --------------------------------------------------------
    channels = [c.strip() for c in (args.notify or "").split(",") if c.strip()]
    if channels:
        from . import notify as _notify
        for channel, (ok, msg) in _notify.notify(
                result, channels, report_url=args.report_url).items():
            print(f"[*] notify {channel}: {'ok' if ok else 'FAILED'} — {msg}")

    crit = sum(1 for f in result["findings"] if f["severity"] in ("critical", "high"))
    if args.fail_on_new and new_findings:
        print(f"[!] {new_findings} NEW finding(s) since the baseline")
        return 3
    return 2 if crit else 0


if __name__ == "__main__":
    raise SystemExit(main())
