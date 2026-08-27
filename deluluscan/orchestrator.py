"""Scan orchestrator.

Pipeline:
  1. safety gate (assert target is loopback/private unless explicitly allowed)
  2. authenticate the three identities and verify them
  3. discover endpoints (openapi.json or seed list)
  4. AI prioritization (optional) so the budget hits the best targets first
  5. run each enabled scanner over each applicable endpoint
  6. run opt-in third-party integrations (nuclei sweep, sqlmap confirmation of
     SQLi candidates)
  7. AI triage of findings (optional)
  8. hand the findings to the reporter

A callback hook lets the web UI stream progress.
"""
from __future__ import annotations

import os
import time
from typing import Callable, Optional

from .ai.analyst import AIAnalyst
from .auth import AuthManager
from .config import Config
from .discovery import discover
from .http_client import HttpClient
from .integrations import InteractshClient, NucleiRunner, SqlmapRunner
from .models import Finding, IdentityRole, Severity, VulnClass
from .safety import (DestructivePolicy, destructive_reason, is_lifecycle,
                     split_destructive)
from .scanners import SCANNER_REGISTRY
from .scanners.ssrf import SsrfScanner
from .scanners.injection_scanner import InjectionScanner

ProgressFn = Callable[[str, dict], None]


class Orchestrator:
    def __init__(self, cfg: Config, progress: Optional[ProgressFn] = None):
        self.cfg = cfg
        self.progress = progress or (lambda ev, data: None)
        # Destructive ops are classified and DEFERRED, not banned: the policy
        # refuses them at the HTTP layer during the main sweep, then _destructive_pass()
        # flips the phase and probes them with the target restartable. Enforcement
        # sits in HttpClient so it covers every scanner, not just the ones that
        # remember to ask (see deluluscan/safety.py).
        dest_enabled, self._dest_why_not = cfg.destructive_enabled()
        self.destructive_policy = DestructivePolicy(enabled=dest_enabled)
        self.client = HttpClient(
            cfg.base_url, rate_limit_rps=cfg.scan.rate_limit_rps,
            timeout_s=cfg.scan.timeout_s, verify_tls=cfg.verify_tls,
            destructive_policy=self.destructive_policy)
        self.auth = AuthManager(self.client)
        self.ai = AIAnalyst(cfg.ai)
        self.findings: list[Finding] = []
        self.meta: dict = {}
        self.source_plan: list = []
        self.fingerprint = None

    @staticmethod
    def _dedup_findings(findings: list):
        """Group findings by (vuln_class, test, normalized title) and keep one
        representative per group, annotated with occurrence count + affected
        endpoints. Distinct issue types are never merged."""
        import re as _re

        def norm_title(t: str) -> str:
            t = _re.sub(r"'[^']*'", "'X'", t or "")
            t = _re.sub(r"\b[0-9a-f]{8}-[0-9a-f-]{20,}\b", "ID", t, flags=_re.I)
            t = _re.sub(r"\d+", "N", t)
            return t.strip().lower()

        _V = {"true_positive": 4, "likely_true_positive": 3, "inconclusive": 2,
              "unverified": 2, "likely_false_positive": 1, "false_positive": 0}
        groups: dict = {}
        order: list = []
        for f in findings:
            sig = (f.vuln_class.value, (f.detail or {}).get("test", ""),
                   f.verdict or "unverified", f.exploitability or "unknown",
                   norm_title(f.title))
            if sig not in groups:
                groups[sig] = []; order.append(sig)
            groups[sig].append(f)

        deduped, removed = [], 0
        for sig in order:
            grp = groups[sig]
            if len(grp) == 1:
                deduped.append(grp[0]); continue
            rep = max(grp, key=lambda f: (f.severity.rank, _V.get(f.verdict, 2),
                                          len(f.evidence or [])))
            endpoints = sorted({g.endpoint for g in grp})
            rep.detail = dict(rep.detail or {})
            rep.detail["occurrences"] = len(grp)
            rep.detail["affected_endpoints"] = endpoints[:25]
            rep.detail["affected_count"] = len(endpoints)
            if "\u00d7" not in rep.title:
                rep.title = f"{rep.title}  (\u00d7{len(endpoints)} endpoints)"
            deduped.append(rep)
            removed += len(grp) - 1
        return deduped, removed

    def _target_alive(self) -> bool:
        """Is the target still answering? Any HTTP status counts — 401/403/404 all
        prove a live server. Only a transport failure means it went away."""
        rec = self.client.status_probe(
            "GET", self.cfg.scan.destructive.health_path,
            identity_label="anonymous", read_timeout=5.0, max_bytes=256)
        return bool(rec) and rec.status > 0

    def _target_settled(self, checks: int = 3, gap_s: float = 2.0) -> bool:
        """Is the target alive AND staying alive?

        A graceful shutdown keeps accepting connections while it winds down, so a
        single probe immediately after a destructive call can answer 200 for a
        server that is already on its way out. That made the pass march on to the
        next endpoint against a dying target and report a clean finish over a
        corpse. Require several consecutive answers instead.
        """
        for i in range(max(checks, 1)):
            if not self._target_alive():
                return False
            if i < checks - 1:
                time.sleep(gap_s)
        return True

    def _wait_for_target(self, timeout_s: int) -> bool:
        deadline = time.time() + max(timeout_s, 1)
        while time.time() < deadline:
            if self._target_alive():
                return True
            time.sleep(3)
        return False

    def _restart_target(self) -> tuple[bool, str]:
        """Bring the target back after a destructive probe took it down."""
        cmd = (self.cfg.scan.destructive.restart_command or "").strip()
        if not cmd:
            return False, ("target is down and no scan.destructive.restart_command "
                           "is configured — remaining destructive endpoints cannot "
                           "be probed")
        import subprocess
        self.progress("destructive_restart", {"command": cmd})
        try:
            proc = subprocess.run(cmd, shell=True, capture_output=True,
                                  text=True, timeout=self.cfg.scan.destructive.wait_timeout_s)
        except subprocess.TimeoutExpired:
            return False, f"restart command timed out: {cmd}"
        except Exception as exc:
            return False, f"restart command failed to launch: {str(exc)[:160]}"
        if proc.returncode != 0:
            return False, (f"restart command exited {proc.returncode}: "
                           f"{(proc.stderr or proc.stdout or '').strip()[:200]}")
        if not self._wait_for_target(self.cfg.scan.destructive.wait_timeout_s):
            return False, (f"restart command succeeded but the target did not become "
                           f"reachable within {self.cfg.scan.destructive.wait_timeout_s}s")
        # Sessions do not survive a restart; re-authenticate before probing on.
        for label, ident in self.cfg.identities.items():
            if label != "anonymous":
                try:
                    self.auth.refresh(ident)
                except Exception:
                    pass
        return True, ""

    def _destructive_pass(self, endpoints: list, scanners: list) -> dict:
        """Probe the deferred destructive endpoints, last, with the target
        restartable between them.

        This is the whole point of deferring rather than banning: the shutdown
        endpoint's authorization verdict is worth having, it just cannot be
        collected in the middle of a 740-endpoint sweep. Here the sweep is already
        done, so if a probe takes the target down we restart and continue.
        """
        report = {"endpoints": [f"{e.method} {e.path}" for e in endpoints],
                  "probed": [], "skipped": [], "restarts": 0,
                  "findings": 0, "aborted_reason": "",
                  # Endpoints whose probe actually took the target down. Direct
                  # evidence the operation is reachable and works, and the reason
                  # the pass needed a restart.
                  "caused_outage": []}
        if not endpoints:
            return report
        if not self.destructive_policy.enabled:
            report["skipped"] = report["endpoints"]
            report["aborted_reason"] = self._dest_why_not
            self.progress("destructive_skipped", {
                "count": len(endpoints), "reason": self._dest_why_not})
            return report

        self.progress("destructive_start", {"count": len(endpoints)})
        self.destructive_policy.begin_destructive_phase()
        before = len(self.findings)
        try:
            for i, ep in enumerate(endpoints, 1):
                if not self._target_alive():
                    ok, why = self._restart_target()
                    if not ok:
                        remaining = [f"{e.method} {e.path}" for e in endpoints[i - 1:]]
                        report["skipped"] = remaining
                        report["aborted_reason"] = why
                        self.progress("destructive_aborted",
                                      {"reason": why, "unprobed": len(remaining)})
                        break
                    report["restarts"] += 1

                self.progress("destructive_endpoint",
                              {"i": i, "total": len(endpoints), "key": ep.key})
                for sc in scanners:
                    if not sc.applies_to(ep):
                        self.coverage.record(ep.key, sc.name, False, "not applicable")
                        continue
                    self.coverage.record(ep.key, sc.name, True)
                    try:
                        for f in sc.run(ep):
                            d = dict(f.detail or {})
                            d["destructive_pass"] = True
                            d["destructive_reason"] = destructive_reason(ep.method, ep.path)
                            f.detail = d
                            self.findings.append(f)
                            self.progress("finding", {"title": f.title,
                                                      "severity": f.severity.value,
                                                      "class": f.vuln_class.value})
                    except Exception as exc:
                        self.coverage.record(ep.key, sc.name, False, f"error: {exc}")
                        self.progress("error", {"scanner": sc.name, "endpoint": ep.key,
                                                "error": str(exc)})
                report["probed"].append(f"{ep.method} {ep.path}")
                # Settled, not merely answering: a graceful shutdown replies for a
                # while after it has decided to exit. Lifecycle ops therefore get a
                # much longer window, or the outage is blamed on the NEXT endpoint —
                # observed live: the target answered through a 6s window after
                # DELETE /maintenance/_shutdown and died during the following probe.
                lifecycle = is_lifecycle(ep.method, ep.path)
                if not self._target_settled(checks=15 if lifecycle else 3,
                                            gap_s=2.0):
                    report["caused_outage"].append(f"{ep.method} {ep.path}")
                    self.progress("destructive_outage",
                                  {"endpoint": ep.key,
                                   "note": "probing this endpoint took the target down — "
                                           "the operation is reachable and it worked"})
        finally:
            self.destructive_policy.end_destructive_phase()
            # Leave the target usable for verification, the pivot, and the
            # integrity check, all of which still need to talk to it.
            if not self._target_settled():
                ok, why = self._restart_target()
                if ok:
                    report["restarts"] += 1
                else:
                    report["post_pass_warning"] = why
                    self.progress("destructive_target_down", {"reason": why})

        report["findings"] = len(self.findings) - before
        self.progress("destructive_done", {
            "probed": len(report["probed"]), "skipped": len(report["skipped"]),
            "restarts": report["restarts"], "findings": report["findings"]})
        return report

    def _crawl_and_augment(self, endpoints: list) -> None:
        """Mine the SPA/JS for hidden API paths (added as GET endpoints) and
        leaked secrets (recorded as findings)."""
        from .active.crawler import SpaCrawler, render_crawl
        from .models import Endpoint, Finding, Severity, VulnClass, RequestRecord

        def fetch_text(path: str) -> str:
            rec = self.client.request("GET", path, identity_label="anonymous")
            return (rec.resp_body or "") if rec else ""

        result = SpaCrawler(fetch_text).static_crawl()
        try:
            admin = self.cfg.identities.get(IdentityRole.ADMIN.value) or \
                self.cfg.identities.get(IdentityRole.BACKEND.value)
            hdrs = self.auth.headers_for(admin) if admin else {}
            r2 = render_crawl(self.cfg.base_url, extra_headers=hdrs)
            result.paths |= r2.paths
            result.secrets += r2.secrets
        except Exception:
            pass

        existing = {e.path for e in endpoints}
        added = 0
        for p in sorted(result.paths):
            if p not in existing and p.startswith("/") and len(p) < 120:
                endpoints.append(Endpoint(method="GET", path=p, tags=["crawler"]))
                existing.add(p); added += 1
        seen = set()
        for kind, val in result.secrets:
            if (kind, val) in seen:
                continue
            seen.add((kind, val))
            rec = RequestRecord(method="GET", url=self.cfg.base_url, identity="anonymous",
                                status=200, elapsed_ms=0.0, resp_headers={},
                                resp_body=f"{kind}: {val}", resp_len=len(val))
            f = Finding(vuln_class=VulnClass.INFO_LEAK, severity=Severity.HIGH,
                        title=f"Secret material exposed in client JavaScript ({kind})",
                        endpoint="(client JS)",
                        description=(f"A {kind} was found in front-end JavaScript/HTML served to "
                                     f"anonymous users. Secrets in client code are readable by "
                                     f"anyone; rotate it and move it server-side."),
                        evidence=[rec], detail={"test": "js_secret", "kind": kind},
                        confidence="firm")
            f.verdict = "true_positive"; f.exploitability = "exploitable"
            f.detail["verification"] = {"verdict": "true_positive", "exploitability": "exploitable",
                                        "confidence_score": 0.8, "probes": 0,
                                        "reasons": ["secret observed directly in client-served JS"],
                                        "repro": "Fetch the JS bundle and grep for the value."}
            self.findings.append(f)
        self.progress("crawl", {"endpoints_added": added, "secrets": len(seen),
                                "mode": result.mode, "scripts": result.scripts_scanned})

    def _run_fingerprint(self, endpoints: list) -> None:
        """Fingerprint the stack from the root page + a few default-file probes,
        so downstream checks are chosen for the technology actually present."""
        from .fingerprint import fingerprint, default_file_probes
        recs = []
        # root page (anonymous)
        anon = self.cfg.identities.get("anonymous")
        try:
            root = self.client.request("GET", "/", identity_label="anonymous",
                                       headers=(self.auth.headers_for(anon) if anon else {}))
            if root:
                recs.append(root)
        except Exception:
            pass
        # a bounded set of default-file probes to strengthen detection
        for _tech, path in default_file_probes()[:12]:
            try:
                r = self.client.request("GET", path, identity_label="anonymous",
                                        headers=(self.auth.headers_for(anon) if anon else {}))
                if r and r.status < 500:
                    recs.append(r)
            except Exception:
                continue
        known_paths = [e.path for e in endpoints[:200]]
        fp = fingerprint(recs, extra_paths=known_paths)
        self.fingerprint = fp
        self.progress("fingerprint", {
            "detections": [{"tech": d.tech, "category": d.category, "version": d.version,
                            "confidence": d.confidence} for d in fp.detections],
            "relevant_scanners": sorted(fp.relevant_scanners())})

    def _run_source_scan(self, endpoints: list) -> None:
        """Read the target source, find dangerous patterns, and target the endpoints
        behind them. Source-derived endpoints are added to the scan set (so the
        existing safety-gated scanners confirm them live), and each candidate is
        recorded as a lead in meta['source_plan']."""
        from .sourcescan import (SourceProvider, SourceAnalyzer, candidates_to_probe_plan,
                                 load_mantis_findings)
        from .models import Endpoint

        def fetch_text(url: str):
            # network egress still routes through the one controlled client
            rec = self.client.request("GET", url, identity_label="anonymous")
            return (rec.resp_body or "") if rec and rec.status == 200 else None

        provider = SourceProvider(
            local_root=(self.cfg.source_root or None),
            fetch_text=fetch_text)
        mode = "local-clone" if provider.local_root else "github-fetch"
        analyzer = SourceAnalyzer(provider, analyst=self.ai,
                                  use_ai=getattr(self.cfg, "source_scan_ai", False))
        candidates = analyzer.analyze(max_files=getattr(self.cfg, "source_max_files", 60))

        mantis_dir = getattr(self.cfg, "mantis_findings_dir", "")
        mantis_candidates = []
        if mantis_dir:
            # a prior Mantis code-scan campaign's findings (see the
            # deluluscan-codescan skill), mapped to the same probe shape as the
            # regex patterns above. Deterministic read — Mantis isn't invoked
            # here, only its already-written workspace/findings/*.json.
            mantis_candidates = load_mantis_findings(mantis_dir, provider.local_root)
            candidates = candidates + mantis_candidates

        plan = candidates_to_probe_plan(candidates)
        self.source_plan = plan

        # merge source-derived endpoints (with the params to fuzz) into the scan set
        existing = {(e.method.upper(), e.path) for e in endpoints}
        added = 0
        for item in plan:
            path = item["endpoint_path"]
            if "{" in path:   # keep concrete templated ids for the scanners' filler
                pass
            qp = [{"name": n} for n in item.get("params", [])]
            for m in item.get("methods", ["GET"]):
                key = (m.upper(), path)
                if key in existing or not path.startswith("/"):
                    continue
                endpoints.append(Endpoint(method=m.upper(), path=path,
                                          tags=["sourcescan", item["pattern_id"]],
                                          query_params=qp))
                existing.add(key); added += 1

        by_class = {}
        for it in plan:
            by_class[it["vuln_class"]] = by_class.get(it["vuln_class"], 0) + 1
        # What the Mantis corpus contributed AND what it withheld. A finding the
        # ingest declined (Mantis marked it a false positive / test-only / not
        # remotely reachable) must be visible, or "not tested" reads as "clean".
        from .sourcescan import candidates_skipped as _mantis_skipped
        self._mantis_withheld = dict(_mantis_skipped)
        self.progress("sourcescan", {"mode": mode, "candidates": len(plan),
                                     "endpoints_added": added, "by_class": by_class,
                                     "ai_review": getattr(self.cfg, "source_scan_ai", False),
                                     "mantis_dir": mantis_dir or None,
                                     "mantis_candidates": len(mantis_candidates),
                                     "mantis_withheld": self._mantis_withheld})

    def run(self) -> dict:
        t0 = time.time()
        self.cfg.assert_target_allowed()
        self.progress("start", {"target": self.cfg.base_url})

        # Grey-box observability (opt-in): tap the target container's own logs +
        # resource usage DURING the scan and correlate them with each probe
        # (deluluscan/telemetry). Started now so the pre-sweep period serves as a
        # baseline. Fail-soft: if no source attaches (no Docker / wrong container)
        # the run proceeds black-box, unchanged.
        self._telemetry = None
        self._telemetry_sources = []
        self._telemetry_baseline_end = 0.0
        self._telemetry_summary = {}
        _obs = getattr(self.cfg, "observe", None)
        if _obs is not None and _obs.enabled:
            try:
                from .telemetry import Recorder, build_sources
                self._telemetry = Recorder()
                started = []
                for s in build_sources(_obs):
                    if s.start(self._telemetry):
                        started.append(s.name); self._telemetry_sources.append(s)
                if started:
                    self.client.enable_probe_log()
                    self.progress("telemetry", {"phase": "start",
                                                "container": _obs.container, "sources": started})
                else:
                    self._telemetry = None
                    self.progress("telemetry", {"phase": "unavailable",
                        "note": "no telemetry source attached (Docker missing or container "
                                f"'{_obs.container}' not running) — scanning black-box"})
            except Exception as exc:
                self._telemetry = None
                self.progress("telemetry", {"phase": "error", "error": str(exc)[:160]})

        # identities — verify every configured identity. A CONFIGURED non-anon
        # identity that fails to authenticate is load-bearing: differential
        # authorization testing silently degrades it to anonymous, so surface it
        # as a prominent warning (not just a status line) rather than proceeding
        # as if the multi-identity matrix were intact.
        identity_status = {}
        unusable = []
        for role in IdentityRole:
            ident = self.cfg.identities.get(role.value)
            if not ident:
                continue
            ok, msg = self.auth.verify(ident)
            identity_status[role.value] = {"ok": ok, "message": msg}
            self.progress("identity", {"role": role.value, "ok": ok, "msg": msg})
            configured = bool(getattr(ident, "username", None) or
                              getattr(ident, "bearer_token", None))
            if role is not IdentityRole.ANON and configured and not ok:
                unusable.append(role.value)
        if unusable:
            self.progress("identity_warning", {
                "unusable": unusable,
                "message": (f"{len(unusable)} configured identity/identities could not "
                            f"authenticate {unusable} — they will scan AS ANONYMOUS, so "
                            f"any 'reachable as {unusable[0]}' result is unreliable. Check "
                            f"credentials / re-run provisioning before trusting the report.")})

        self._integrity = None   # product-specific identity-drift guard removed

        # discovery (try authenticated too — 26.x gates the spec behind auth)
        auth_attempts = []
        for role in IdentityRole:
            if role is IdentityRole.ANON:
                continue
            ident = self.cfg.identities.get(role.value)
            if ident and (ident.username or ident.bearer_token):
                auth_attempts.append({"label": role.value,
                                      "headers": self.auth.headers_for(ident)})
        endpoints, source = discover(self.client, self.cfg.openapi_path,
                                     self.cfg.scan.methods, auth_attempts,
                                     local_file=self.cfg.openapi_file)
        self.progress("discovery", {"count": len(endpoints), "source": source})

        # RECON: fingerprint the target technology stack (server, language,
        # framework, CMS, API style, WAF). This drives which technology-specific
        # checks are relevant and is reported as recon output.
        self.fingerprint = None
        try:
            self._run_fingerprint(endpoints)
        except Exception as exc:
            self.progress("fingerprint", {"error": str(exc)[:140]})

        # Engagement memory: recall what prior scans learned about THIS target
        # (keyed by product+version) so we test smarter — re-probe endpoints that
        # were exploitable last time first, and annotate repeats/regressions.
        self._recall = None
        self._mem = None
        self._tkey = ""
        if getattr(self.cfg, "memory_enabled", True):
            try:
                self._load_memory()
            except Exception as exc:
                self.progress("memory", {"error": str(exc)[:160]})

        # SPA/JS crawler: mine the front end for hidden endpoints + leaked secrets
        if getattr(self.cfg.scan, "enable_crawler", True):
            try:
                self._crawl_and_augment(endpoints)
            except Exception as exc:
                self.progress("crawl", {"error": str(exc)[:120]})

        # Source-informed scanning: read the target source, find dangerous patterns,
        # and target the endpoints they sit behind. Adds source-derived endpoints
        # to the scan set so the existing (safety-gated) scanners confirm them live.
        self.source_plan = []
        if getattr(self.cfg, "enable_source_scan", False):
            try:
                self._run_source_scan(endpoints)
            except Exception as exc:
                self.progress("sourcescan", {"error": str(exc)[:160]})

        # AI prioritization
        endpoints = self.ai.prioritize(endpoints)
        # Memory-informed prioritization: float endpoints that were exploitable on
        # a prior scan to the front, so a budget-capped run always re-checks the
        # known-vulnerable spots before spending the cap elsewhere.
        endpoints = self._apply_recall_priority(endpoints)
        if self.cfg.scan.max_endpoints:
            endpoints = endpoints[: self.cfg.scan.max_endpoints]

        # optional OOB channel for SSRF / XXE / command injection
        oob = None
        if self.cfg.integrations.enable_interactsh:
            oob = InteractshClient(self.cfg)
            if oob.start():
                self.progress("integration", {"name": "interactsh",
                                               "domain": oob.base_domain})
            else:
                oob = None
                self.progress("integration", {"name": "interactsh",
                                               "status": "unavailable",
                                               "note": "no reachable interactsh server; "
                                               "falling back to local OAST if the target is loopback"})
        # Local OAST fallback: confirms HTTP out-of-band (e.g. blind SSRF) when the
        # target is loopback/private. Auto-enabled for in-scope local targets since
        # interactsh needs an external collaborator the tool may not be able to reach.
        if oob is None:
            from urllib.parse import urlparse as _up
            import ipaddress as _ip
            import socket as _sock
            want_local = getattr(self.cfg.integrations, "enable_local_oast", False)
            if not want_local:
                try:
                    _host = _up(self.cfg.base_url).hostname or ""
                    _addr = _ip.ip_address(_sock.gethostbyname(_host))
                    want_local = bool(_addr.is_loopback or _addr.is_private)
                except Exception:
                    want_local = False
            if want_local:
                from .integrations.local_oast import LocalOastListener
                local = LocalOastListener(self.cfg)
                if local.start():
                    oob = local
                    self.progress("integration", {"name": "local_oast",
                                                   "domain": local.base_domain,
                                                   "note": "loopback-only; confirms HTTP OOB from the local target"})
                else:
                    self.progress("integration", {"name": "local_oast", "status": "unavailable",
                                                   "note": "could not bind local OAST listener; "
                                                   "blind-OOB findings will stay unconfirmed"})

        # technology-profile gating: some scanners are specific to a product.
        # They run only when that technology is fingerprinted (or when fingerprint
        # was inconclusive → fail open to coverage, or the user named them). This
        # is what makes the tool general rather than tied to one platform.
        _PROFILE_SCANNERS = {}   # no product-specific scanners; all run generically
        detected = set(self.fingerprint.techs()) if self.fingerprint else set()

        def _profile_ok(name: str) -> bool:
            tech = _PROFILE_SCANNERS.get(name)
            if tech is None:
                return True                      # not a product-specific scanner
            # A product-specific scanner runs ONLY when that product is actually
            # fingerprinted. It is never gated-in merely by being in the default
            # scanner list (which always contains the product-specific names).
            return tech in detected

        skipped_profiles = []
        # build scanners
        from .scanners.log_injection_scanner import LogInjectionScanner
        from .scanners.resource_consumption_scanner import ResourceConsumptionScanner
        oob_aware = (SsrfScanner, InjectionScanner)
        # Telemetry-aware scanners need the observability recorder (grey-box). It
        # is None on a black-box run, and each such scanner no-ops without it.
        telemetry_aware = (LogInjectionScanner, ResourceConsumptionScanner)

        def _construct(cls):
            if cls in oob_aware:
                return cls(self.client, self.auth, self.cfg, self.cfg.identities, oob=oob)
            if cls in telemetry_aware:
                return cls(self.client, self.auth, self.cfg, self.cfg.identities,
                           recorder=getattr(self, "_telemetry", None))
            return cls(self.client, self.auth, self.cfg, self.cfg.identities)

        scanners = []
        for name in self.cfg.scan.scanners:
            cls = SCANNER_REGISTRY.get(name)
            if not cls:
                continue
            if not _profile_ok(name):
                skipped_profiles.append(name); continue
            scanners.append(_construct(cls))
        # always include the broad OWASP sweep + generic packs (advisories
        # only when relevant per the profile gate)
        for extra in ("owasp", "bopla", "bodyfuzz"):
            if extra not in self.cfg.scan.scanners and _profile_ok(extra):
                scanners.append(_construct(SCANNER_REGISTRY[extra]))
        if skipped_profiles:
            self.progress("profile_gate", {
                "skipped": skipped_profiles,
                "reason": f"technology not fingerprinted (detected: {sorted(detected) or 'none'})"})

        # warn if high-value detectors are absent from the configured set — a
        # stale scanners: list in config.yaml silently disables them.
        _HIGH_VALUE = {"xss": "stored/reflected XSS",
                       "sqli": "SQL injection", "injection": "SSRF/SSTI/traversal/cmd/XXE",
                       "oauth": "OAuth ATO",
                       "idor_iter": "iterable-id IDOR", "authflow": "password-reset ATO",
                       "fileupload": "malicious file upload"}
        active = {sc.name for sc in scanners}
        missing = {k: v for k, v in _HIGH_VALUE.items() if k not in active}
        if missing:
            self.progress("scanners_warning", {
                "active_count": len(scanners),
                "disabled_high_value": missing,
                "hint": "Your config.yaml has an explicit scan.scanners list that omits these. "
                        "Comment it out to run the full set, or add these names."})
        self.progress("scanners_active", {"names": sorted(active)})

        # scan loop
        from .reporting.coverage import CoverageTracker
        self.coverage = CoverageTracker()
        # Hold destructive endpoints back for a dedicated pass AFTER the sweep.
        # They are in scope; sending one at endpoint 50 of 740 just costs us the
        # other 690 (see deluluscan/safety.py for the incident this encodes).
        endpoints, destructive_endpoints = split_destructive(endpoints)
        if destructive_endpoints:
            self.progress("destructive_deferred", {
                "count": len(destructive_endpoints),
                "endpoints": [f"{e.method} {e.path}" for e in destructive_endpoints],
                "enabled": self.destructive_policy.enabled,
                "reason": self._dest_why_not or
                          "deferred to a dedicated pass after the main sweep"})
        total = len(endpoints)
        # Checkpointing. Results were previously serialised only after the whole
        # loop finished, so a long scan that was killed produced NOTHING — a
        # 740-endpoint run died at 502 (timeout/OOM) and ~90 minutes of probing
        # was unrecoverable. Flush partial results periodically so an interrupted
        # scan still yields everything it had established.
        import os as _os
        _ckpt_path = _os.path.join(self.cfg.output_dir, "results.partial.json")
        _ckpt_every = 25

        def _checkpoint(done: int) -> None:
            try:
                _os.makedirs(self.cfg.output_dir, exist_ok=True)
                import json as _json
                with open(_ckpt_path, "w") as fh:
                    _json.dump({
                        "meta": {"partial": True, "endpoints_done": done,
                                 "endpoints_total": total,
                                 "target": self.cfg.base_url,
                                 "note": ("Partial results from an in-progress or interrupted "
                                          "scan. Coverage is incomplete: absence of a finding "
                                          "here does NOT mean the endpoint is clean.")},
                        "findings": [f.to_dict() for f in self.findings],
                    }, fh, indent=2)
            except Exception:
                pass          # checkpointing must never break a scan

        # Everything observed before this instant is the target's baseline
        # (startup/idle) noise — the correlator subtracts it so a pre-existing
        # exception or heap level is never blamed on a probe.
        if self._telemetry is not None:
            self._telemetry_baseline_end = time.time()
            self.progress("telemetry", {"phase": "baseline",
                                        "note": "sweep starting; correlating from here"})

        for i, ep in enumerate(endpoints, 1):
            self.progress("endpoint", {"i": i, "total": total, "key": ep.key})
            if i % _ckpt_every == 0:
                _checkpoint(i)
            for sc in scanners:
                if not sc.applies_to(ep):
                    self.coverage.record(ep.key, sc.name, False, "not applicable")
                    continue
                self.coverage.record(ep.key, sc.name, True)
                try:
                    for f in sc.run(ep):
                        self.findings.append(f)
                        self.progress("finding", {"title": f.title,
                                                  "severity": f.severity.value,
                                                  "class": f.vuln_class.value})
                except Exception as exc:
                    self.coverage.record(ep.key, sc.name, False, f"error: {exc}")
                    self.progress("error", {"scanner": sc.name, "endpoint": ep.key,
                                            "error": str(exc)})

        # Destructive pass: now that the full surface has been swept, probe the
        # operations that can take the target down — restarting it between probes.
        # Held on self, not self.meta: meta is rebuilt wholesale further down.
        self._destructive_report = self._destructive_pass(
            destructive_endpoints, scanners)

        # fuzzing / anomaly detection: surface CANDIDATE unknown-bug leads by
        # mutating inputs and flagging behaviour that deviates from baseline.
        # Opt-in; leads are rated tentative/unverified (never "confirmed 0-day").
        if getattr(self.cfg, "fuzz", False):
            try:
                from .fuzzer import Fuzzer, FuzzConfig
                fz = Fuzzer(self.client, self.auth, self.cfg, self.cfg.identities,
                            FuzzConfig(enabled=True,
                                       max_endpoints=getattr(self.cfg, "fuzz_max_endpoints", 40)))
                leads = fz.run(endpoints)
                self.findings.extend(leads)
                by_kind: dict = {}
                for f in leads:
                    k = f.detail.get("kind", "?")
                    by_kind[k] = by_kind.get(k, 0) + 1
                self.progress("fuzz", {"leads": len(leads), "by_kind": by_kind})
            except Exception as exc:
                self.progress("fuzz", {"error": str(exc)[:140]})

        # nuclei sweep
        if self.cfg.integrations.enable_nuclei:
            nf = NucleiRunner(self.cfg).run()
            self.findings.extend(nf)
            self.progress("integration", {"name": "nuclei", "findings": len(nf)})

        # sqlmap confirmation of SQLi candidates
        if self.cfg.integrations.enable_sqlmap:
            runner = SqlmapRunner(self.cfg, auth=self.auth)
            for f in [x for x in self.findings if x.vuln_class is VulnClass.SQLI]:
                res = runner.confirm(f)
                f.detail["sqlmap"] = res
                if res.get("confirmed"):
                    f.confidence = "confirmed"
                self.progress("integration", {"name": "sqlmap",
                                              "endpoint": f.endpoint, "result": res})

        # verification: corroborate findings, detect compensating controls,
        # rate exploitability, and cut false positives (detection-only).
        if self.cfg.scan.verify and self.findings:
            from .verify import Verifier
            verifier = Verifier(self.client, self.auth, self.cfg.identities,
                                self.cfg, analyst=self.ai)
            verifier.verify_all(self.findings)
            self.progress("verify", {
                "verified": len(self.findings),
                "true_positive": sum(1 for f in self.findings
                                     if f.verdict in ("true_positive", "likely_true_positive")),
                "false_positive": sum(1 for f in self.findings
                                      if f.verdict in ("false_positive", "likely_false_positive")),
            })

            # DEEP verification: for every credible finding, go beyond the single
            # differential probe — re-test across identities, probe the endpoint
            # every auth way (session-riding), and compute filter bypasses. Read-only;
            # refines exploitability only with concrete evidence. See deluluscan/verify/deep.py.
            try:
                from .verify.deep import DeepContext, DeepVerifier
                dstats = DeepVerifier(DeepContext(
                    self.client, self.auth, self.cfg, self.cfg.identities)).run(self.findings)
                self.progress("deep_verify", dstats)
            except Exception as exc:
                self.progress("deep_verify", {"error": str(exc)[:160]})

            # exploit-chain analysis: correlate findings into higher-severity
            # attack chains (one bug enabling another).
            from .verify.chains import ChainAnalyzer
            chain_findings = ChainAnalyzer(analyst=self.ai).analyze(self.findings)
            if chain_findings:
                self.findings.extend(chain_findings)
                self.progress("chains", {"chains": len(chain_findings)})

            # adversarial validation: confidence + lifecycle state + learning
            # false-positive memory (auto-suppress known-harmless patterns).
            from .verify.validation import ConfidenceEngine, FalsePositiveMemory
            fp_path = os.path.join(self.cfg.output_dir, "fp_memory.json")
            memory = FalsePositiveMemory(fp_path)
            engine = ConfidenceEngine(memory)
            dismissed = 0
            for f in self.findings:
                vs = engine.evaluate(f.to_dict())
                f.detail["validation"] = vs.to_dict()
                if vs.state == "dismissed":
                    dismissed += 1
            memory.save()
            self.progress("validate", {"dismissed": dismissed,
                                       "reviewed": sum(1 for f in self.findings
                                       if f.detail.get("validation", {}).get("state") == "reviewed")})

            # Engagement-memory annotation: tag findings we've seen on this target
            # before (regression vs. first sighting), so the report can say "still
            # exploitable since <date>" rather than treating each run as day zero.
            try:
                self._annotate_from_memory()
            except Exception as exc:
                self.progress("memory", {"error": str(exc)[:160]})

        # Grey-box correlation: turn the observed telemetry timeline into findings
        # (server-log-confirmed injection, secrets in logs, unlogged operations,
        # heap growth), then stop the sources. Runs regardless of the verify flag —
        # telemetry can surface findings the black-box sweep never produced.
        if self._telemetry is not None:
            try:
                self._run_telemetry_analysis()
            except Exception as exc:
                self.progress("telemetry", {"phase": "error", "error": str(exc)[:160]})
            finally:
                for s in self._telemetry_sources:
                    try:
                        s.stop()
                    except Exception:
                        pass

        # AI triage
        if self.ai.enabled:
            for f in self.findings:
                f.ai_notes = self.ai.triage(f)

        if oob:
            oob.stop()

        # collapse near-identical findings (same class/test/normalized-title across
        # many endpoints) into one representative carrying an occurrence count and
        # the affected-endpoint list — so the report leads with distinct issues
        # instead of, e.g., 142 identical verbose-error rows.
        self.findings, dedup_removed = self._dedup_findings(self.findings)

        _EXPL_RANK = {"exploitable": 4, "conditional": 3, "mitigated": 2,
                      "unknown": 1, "not_exploitable": 0}
        _VERDICT_RANK = {"true_positive": 4, "likely_true_positive": 3,
                         "inconclusive": 2, "unverified": 2,
                         "likely_false_positive": 1, "false_positive": 0}
        self.findings.sort(key=lambda f: (
            f.severity.rank,
            _EXPL_RANK.get(f.exploitability, 1),
            _VERDICT_RANK.get(f.verdict, 2),
        ), reverse=True)
        self.meta = {
            "target": self.cfg.base_url,
            "source": source,
            "endpoints_scanned": total + len(destructive_endpoints),
            "identities": identity_status,
            # What the destructive pass reached, and what it could not. A reader
            # must be able to tell "shutdown authorization was tested" from
            # "shutdown was never probed".
            "destructive_pass": getattr(self, "_destructive_report", {}),
            "destructive_policy": self.destructive_policy.to_dict(),
            "duration_s": round(time.time() - t0, 1),
            "ai_provider": self.cfg.ai.provider,
            "distinct_findings": len(self.findings),
            "duplicates_collapsed": dedup_removed,
            "verification": {
                "enabled": self.cfg.scan.verify,
                "true_positive": sum(1 for f in self.findings
                                     if f.verdict in ("true_positive", "likely_true_positive")),
                "false_positive": sum(1 for f in self.findings
                                      if f.verdict in ("false_positive", "likely_false_positive")),
                "exploitable": sum(1 for f in self.findings
                                   if f.exploitability == "exploitable"),
            },
            "integrations": {
                "nuclei": self.cfg.integrations.enable_nuclei,
                "sqlmap": self.cfg.integrations.enable_sqlmap,
                "interactsh": bool(oob),
                "oob_channel": (type(oob).__name__ if oob else "none"),
            },
            "source_scan": {
                "enabled": getattr(self.cfg, "enable_source_scan", False),
                "candidates": len(getattr(self, "source_plan", []) or []),
                "plan": getattr(self, "source_plan", []),
                # Findings the Mantis ingest declined (its own triage rejected
                # them, or they are not reachable over HTTP). Recorded so the
                # report can never present partial coverage as full coverage.
                "mantis_withheld": getattr(self, "_mantis_withheld", {}),
            },
            "fingerprint": (self.fingerprint.to_dict() if self.fingerprint else {"detections": []}),
        }
        # Probe telemetry: what this scan ACTUALLY sent. Without it a reader
        # cannot distinguish "tested and clean" from "never tested".
        try:
            self.meta["probe_stats"] = self.client.probe_stats()
        except Exception:
            self.meta["probe_stats"] = {}

        # Grey-box observability summary (what the telemetry plane saw), so a
        # reader can tell an --observe run from a black-box one.
        if getattr(self, "_telemetry_summary", None):
            self.meta["telemetry"] = self._telemetry_summary


        # Coverage summary belongs IN the report, not only in a side file: a
        # report that omits coverage invites "no findings" to be read as "clean".
        try:
            if getattr(self, "coverage", None):
                from .reporting.coverage import _summarize
                cov = self.coverage.as_dict()
                summary = _summarize(cov)
                tested_eps = sum(
                    1 for row in cov["matrix"].values()
                    if any(v == "tested" for v in row.values()))
                total_eps = len(cov["matrix"])
                self.meta["coverage"] = {
                    "endpoints_discovered": total_eps,
                    "endpoints_probed": tested_eps,
                    "endpoints_probed_pct": (round(100 * tested_eps / total_eps, 1)
                                             if total_eps else 0.0),
                    "untested_endpoints": summary["untouched_endpoints"],
                    "scanners_run": cov["scanners"],
                    "per_scanner_pct": summary["per_scanner_pct"],
                }
        except Exception as exc:
            self.meta["coverage"] = {"error": str(exc)}

        # The effective authorization spec, recorded so a reader can audit what
        # "conformant" meant for this run.
        try:
            from .entitlements import spec_summary
            self.meta["entitlement_spec"] = spec_summary()
        except Exception:
            pass

        # Derive each finding's pentest-report block from its captured evidence.
        # Prose is a view over evidence — never hand-authored per finding.
        try:
            from .reporting import attach_reports
            attach_reports(self.findings, base_url=self.cfg.base_url)
        except Exception as exc:                     # never fail a scan over reporting
            self.progress("report_derive_failed", {"error": str(exc)})

        # Engagement memory: persist what THIS scan established so the next run
        # against this build starts informed. Records only credible results and
        # scan-evidenced gotchas; surfaces previously-exploitable endpoints that
        # did not reproduce as a regression-watch (never as a finding).
        try:
            self._record_memory()
        except Exception as exc:
            self.meta["memory"] = {"error": str(exc)[:160]}
            self.progress("memory", {"error": str(exc)[:160]})

        self.progress("done", self.meta)
        return {"meta": self.meta,
                "findings": [f.to_dict() for f in self.findings]}

    # ---- grey-box telemetry -----------------------------------------------
    def _run_telemetry_analysis(self) -> None:
        """Correlate the observed telemetry timeline with the probe windows the
        HttpClient captured, and append the resulting findings."""
        import os as _os
        from .telemetry import Correlator, probe_windows_from

        windows = probe_windows_from(list(self.client.probe_log or []))
        corr = Correlator(self._telemetry, self._telemetry_baseline_end)
        tfindings: list = []
        tfindings += corr.analyze_trace_leaks(windows)
        tfindings += corr.analyze_secrets_in_logs()
        # Detection-gap only over security-relevant successful operations — a
        # state-changing request that returned 2xx is exactly what should be audited.
        gap_windows = [w for w in windows
                       if w.method.upper() in ("POST", "PUT", "DELETE", "PATCH")
                       and 200 <= w.status < 300]
        tfindings += corr.analyze_detection_gap(gap_windows)
        tfindings += corr.analyze_memory()
        for f in tfindings:
            f.detail = dict(f.detail or {})
            f.detail.setdefault("source", "telemetry")
        self.findings.extend(tfindings)

        try:
            _os.makedirs(self.cfg.output_dir, exist_ok=True)
            self._telemetry.persist(_os.path.join(self.cfg.output_dir, "telemetry.jsonl"))
        except Exception:
            pass
        summary = corr.summary()
        summary["findings"] = len(tfindings)
        summary["probe_windows"] = len(windows)
        self._telemetry_summary = summary
        self.progress("telemetry", {"phase": "analyze", **summary})

    # ---- engagement memory ------------------------------------------------
    def _memory_path(self) -> str:
        import os as _os
        return (getattr(self.cfg, "memory_file", "") or
                _os.path.join(self.cfg.output_dir, "engagement_memory.json"))

    def _load_memory(self) -> None:
        from .memory import EngagementMemory, target_key_from_fingerprint
        self._mem = EngagementMemory(self._memory_path())
        self._tkey = target_key_from_fingerprint(self.fingerprint, self.cfg.base_url)
        self._recall = self._mem.recall(self._tkey)
        if self._recall and self._recall.known and not self._recall.is_empty():
            self.progress("memory", {
                "phase": "recall", "target_key": self._tkey,
                "known": True, "last_seen": self._recall.last_seen,
                "exploitable_endpoints": len(self._recall.exploitable_endpoints()),
                "gotchas": list(self._recall.gotchas.keys()),
                "bypasses": len(self._recall.bypasses),
                "lines": self._recall.summary_lines()})
        else:
            self.progress("memory", {"phase": "recall", "target_key": self._tkey,
                                     "known": False})

    def _apply_recall_priority(self, endpoints: list) -> list:
        rec = getattr(self, "_recall", None)
        if not rec or not rec.known:
            return endpoints
        from .memory import endpoint_key
        hot = set(rec.exploitable_endpoints())
        if not hot:
            return endpoints
        hot_paths = {k.split("|", 1)[-1] for k in hot}
        front, rest = [], []
        for e in endpoints:
            # match on normalized "METHOD /path", ignoring the remembered class
            ep_path = endpoint_key("", f"{e.method} {e.path}").split("|", 1)[-1]
            (front if ep_path in hot_paths else rest).append(e)
        if front:
            self.progress("memory", {"phase": "prioritize",
                                     "promoted": len(front),
                                     "reason": "exploitable on a prior scan"})
        return front + rest

    def _annotate_from_memory(self) -> None:
        rec = getattr(self, "_recall", None)
        if not rec or not rec.known:
            return
        annotated = 0
        for f in self.findings:
            prior = rec.prior_for(f.vuln_class.value, f.endpoint)
            if not prior:
                continue
            d = dict(f.detail or {})
            d["memory"] = {
                "seen_before": True,
                "first_seen": prior.get("first_seen"),
                "prior_verdict": prior.get("verdict"),
                "prior_exploitability": prior.get("exploitability"),
                "seen_count": prior.get("seen_count", 1) + 1,
                "note": ("recurring: exploitable on a prior scan and still present"
                         if prior.get("exploitability") in ("exploitable", "conditional")
                         and f.verdict in ("true_positive", "likely_true_positive")
                         else "previously observed on this target"),
            }
            f.detail = d
            annotated += 1
        if annotated:
            self.progress("memory", {"phase": "annotate", "matched": annotated})

    def _record_memory(self) -> None:
        mem = getattr(self, "_mem", None)
        if mem is None:
            self.meta["memory"] = {"enabled": False}
            return
        version = ""
        for det in (self.fingerprint.detections if self.fingerprint else []):
            if det.version:
                version = det.version
                break
        stats = mem.record_scan(self._tkey, self.cfg.base_url, version,
                                self.findings, self.meta)
        mem.save()
        # regression-watch belongs in meta, not as a finding: the report may only
        # assert what THIS scan observed, and "no longer reproduced" is an absence.
        self.meta["memory"] = {
            "enabled": True, "file": self._memory_path(),
            "target_key": self._tkey,
            "recorded": stats["recorded"],
            "known_targets": stats["known_targets"],
            "regression_watch": stats["possibly_fixed"],
        }
        self.progress("memory", {"phase": "record", **self.meta["memory"]})
