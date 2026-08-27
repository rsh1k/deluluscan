# Deluluscan — AI-augmented security auditor (Claude-driven)

Deluluscan is a security auditor for authorized testing of web, API, container, application, LLM, and cloud targets. It is
designed to be run by Claude Code as an interactive **find → validate → retest →
adjudicate → report** loop, not just a one-shot scanner.

## How to run an assessment

Use the **`deluluscan-audit` skill** (`.claude/skills/deluluscan-audit/SKILL.md`). It is the
authoritative workflow. In short: scan → re-test every candidate finding live to
decide true/false positive → dig deeper on confirmed ones → fix the tool when it
produces a false positive (with a regression test) → regenerate the dashboard.

To refresh the source-informed targeting corpus (clone the latest target source, run a
full Mantis autonomous code-scan campaign against it), use the **`deluluscan-codescan`
skill** (`.claude/skills/deluluscan-codescan/SKILL.md`) — a separate, occasionally-run
step, not part of every audit. `deluluscan-audit` picks up its output automatically
via `--mantis-findings-dir` when the corpus exists.

## Commands

- Stand up via **docker-compose** (preferred — provisions multi-role test users + auto-fetches OpenAPI):
  `./up-compose.sh [docker-compose.yml]` then use `config.dev.yaml`.
  Tear down: `docker compose down`.
- Stand up ephemeral all-in-one dev image (simpler, no user provisioning): `./up-target.sh [TAG]`
  then use `config.dev.yaml`. Tear down: `docker rm -f target-audit`.
- Full scan (with OpenAPI spec for full endpoint coverage):
  `python3 -m deluluscan.cli --config config.dev.yaml --openapi-file openapi.json --allow-state-changing --fuzz`
  Destructive operations (shutdown, bulk delete, reindex, DB dump) are **in
  scope** and follow `--allow-state-changing` for loopback/RFC1918 targets. They
  are held out of the main sweep and probed in a dedicated pass afterwards, with
  the target restarted between probes — sending one mid-sweep would end the run.
  Force either way with `--allow-destructive` / `--no-destructive`, and set the
  restart hook via `--restart-command` or `scan.destructive.restart_command`
  (config.dev.yaml already sets `docker compose restart target`).
- Scan without a local spec (auto-fetches openapi.json with admin auth during startup):
  `python3 -m deluluscan.cli --config config.dev.yaml --allow-state-changing --fuzz`
- Grey-box observability (`--observe`): tap the target **container's own logs +
  memory/CPU** during the scan and correlate each event with the exact probe that
  caused it (`deluluscan/telemetry/`). Adds server-log-**confirmed** injection
  (a probe that provokes `PSQLException`/`freemarker.core` in the log is SQLi/SSTI
  even on a bland HTTP 500), secrets-in-logs (CWE-532, redacted at ingest),
  detection-gap (OWASP A09 — a successful state-changing op that leaves no audit
  trail), and heap-growth/OOM leads. Opt-in, **fail-soft** (no Docker → the run is
  black-box, unchanged), and **local-only** (same authorization boundary as every
  probe — the container is on the owned host). `python3 -m deluluscan.cli --config
  config.dev.yaml --allow-state-changing --observe` (container defaults to
  `deluluscan-target-1`; override with `--observe-container` / add `--observe-db`, or the
  `observe:` block in config). Timeline is written to `deluluscan-out/telemetry.jsonl`;
  a summary lands in `meta.telemetry`, and the dashboard grows a **Behavioral** tab.
  Three grey-box scanners ship alongside the passive correlation: `memory_disclosure`
  (black-box — heap/thread-dump & actuator/JMX reachability; a bare 200/SPA-index is
  NOT a finding), `log_injection` (telemetry-aware — CRLF forged-line canary,
  confirmed by log read-back; no-op without `--observe`), and `resource_consumption`
  (telemetry-aware + `--allow-state-changing` — bounded amplification payloads with a
  MEASURED docker-stats memory delta; measures amplification, never weaponizes DoS).
- Re-test ONE endpoint live (adjudication primitive):
  `python3 -m deluluscan.recheck --config config.yaml --from-results deluluscan-out/results.json --index <N>`
  or `python3 -m deluluscan.recheck --config config.yaml --method GET --path /api/v1/categories --scanner sqli --param orderby`
- Dashboard: `python3 -m deluluscan.dashboard deluluscan-out/results.json deluluscan-out/dashboard.html`
  - The UI is the **React + TypeScript app in `dashboard/`** (Vite + Tailwind),
    built into ONE self-contained HTML file and vendored as
    `deluluscan/assets/dashboard_bundle.html`. Python only injects the scan payload at
    the `/*__DATA__*/` marker — it renders no markup. Generating a report needs no
    Node toolchain; that is the point of vendoring the built asset.
  - After changing anything under `dashboard/src`, run **`./scripts/build_dashboard.sh`**
    and commit the regenerated asset. `./scripts/build_dashboard.sh --check` fails
    if the committed asset is stale (use it in CI).
  - Dashboard tests: `cd dashboard && npm test` (vitest/jsdom — component and
    report-integrity behaviour) and `npm run smoke -- <generated.html> plaintext`
    (loads a *generated* report in jsdom and asserts it actually mounts and
    renders; add `encrypted <passphrase>` to exercise the decryption gate).
  - Password-protect (AES-GCM, in-browser decrypt): add `--password PASS` (50-128
    chars, enforced) or `--generate-password` (makes + prints a strong one), or
    set `DELULUSCAN_DASHBOARD_PASSWORD`. Evidence secrets (cookies/JWTs) are redacted
    regardless; the password protects the whole report at rest.
  - Change the password without a re-scan: `python3 -m deluluscan.dashboard --rekey
    docs/dashboard.html --old-password OLD --generate-password` (or `--password NEW`).
    Turnkey rotate + publish: `./scripts/rotate_dashboard_password.sh <current-pw> [new-pw]`.
    The password lives ONLY in the team vault, never in the repo — the published
    file is a public URL (target.github.io/deluluscan/dashboard.html), so the passphrase
    is the boundary. Published dashboard: `docs/dashboard.html` (served via Pages).
- Engagement memory (cross-scan learning): every scan records what it established
  — which endpoints were exploitable, verified filter bypasses, per-build gotchas
  (e.g. JWT rotation, the authenticating principal) — to a local JSON store keyed
  by target **product+version**, and the next scan reads it back to test smarter:
  endpoints exploitable last time are re-probed FIRST, repeats are annotated
  (`detail["memory"]`: recurring vs. first sighting), and a previously-exploitable
  endpoint that does NOT reproduce is surfaced as `meta["memory"].regression_watch`
  (a possible fix — never emitted as a finding, since the report may only assert
  what THIS scan observed). On by default; `--no-memory` disables it,
  `--memory-file PATH` relocates the store (default
  `<output_dir>/engagement_memory.json`). Inspect it:
  `python3 -m deluluscan.memory deluluscan-out/engagement_memory.json`. Stays local — one
  JSON file, no network — inside the same authorization boundary as everything else.
- Tests: `python3 -m tests.<suite>` (e.g. `test_verify`, `test_sqli`, `test_fingerprint`).
  Run the relevant suite after any change to `deluluscan/`.
- Clone the latest target source for code-scanning: `./scripts/clone_target_source.sh
  [branch] [dest]` (default `master` → `.target-src/core`). Feeds
  `--source-root` for `deluluscan/sourcescan.py` and CODE_ROOT for a Mantis campaign
  (see `deluluscan-codescan` skill). Add `--source-scan` (or `--mantis-findings-dir
  <mantis workspace>/workspace` once a Mantis campaign has run) to
  `deluluscan.cli` to turn source-derived candidates into targeted live probes —
  every endpoint is still scanned as before, these just add deeper,
  vuln-class-specific probes on top for the ones a source finding maps to.

- `deluluscan/assess/` — unified assessment + multi-format LOCAL report (WS-glue):
  `runner.py` (`Assessment`/`run_web_assessment`: run recon [auto-folds platform
  intelligence + version-gated CVEs + passive edge detection] + headers + secrets +
  netscan [WAF/CDN + honeypot + IDS; ports opt-in via `--netscan-ports`] + passive
  [response-body analysis] + webapi, merge + dedup findings -> payload),
  `report.py` (`write_reports`: JSON/Markdown/
  self-contained HTML + CSV/XLSX/JUnit via reporting.exporters + SARIF; local files
  only, no publishing). CLI: `python3 -m deluluscan.assess --url … [--sast-path ./src] [--spec openapi.json]
  --formats md,html,json` (merges live web + source SAST + API-spec findings).
  `tests/test_assess.py`.
- `deluluscan/sast/` — source-code SAST: `rules.py` (dangerous-pattern rules per
  language — eval/exec/os.system/shell, pickle/yaml/ObjectInputStream deser, SQL
  concat, weak crypto, XSS sinks, TLS verify=False), `engine.py` (`SastScan.scan_path`:
  walk tree + rules by ext + reuse `secrets.scan_text`; file:line evidence). CLI:
  `python3 -m deluluscan.sast --path ./src`. `tests/test_sast.py`.
- `deluluscan/apispec/` — OpenAPI 3.x / Swagger 2.0 security linter: `linter.py`
  (`lint_spec`: state-changing ops without auth, whole-API-unauthenticated, secrets in
  query/path params, apiKey-in-query, http servers, mass-assignment schemas, deprecated
  ops; operation `security` overrides global, `[]` = deliberately open). CLI:
  `python3 -m deluluscan.apispec --spec openapi.json`. `tests/test_apispec.py`.
- `deluluscan/correlate/` — attack-chain correlation: `chains.py` (rules combining
  findings — SSRF+IMDS->cloud creds, XSS+non-HttpOnly->session hijack, IDOR+admin->
  privesc, leaked-secret->access, SQLi+data->exfil, GraphQL surface->mass abuse),
  `engine.py` (`correlate`/`chain_findings`/`objectives`: hypotheses stay tentative,
  feed WS-2 objectives). CLI: `python3 -m deluluscan.correlate --results results.json`.
  `tests/test_correlate.py`.
## Conventions

- Install deps: `pip install -r requirements.txt --break-system-packages`.
- Findings carry `verdict` (true_positive/…/false_positive), `exploitability`, and
  `confidence`. A verdict is only trustworthy after a live re-test via `recheck`.
- **The report may only state what the scan observed.** Never synthesize evidence
  for an identity that was not probed, and never hand-author narrative that
  asserts a finding (an attack chain, a "dominant theme") independent of the data
  — derive it from `meta.escalation_pivot` / the findings, or omit it. An untested
  surface must read as untested, not as clean. An AI verdict is advisory and must
  never overwrite a live re-test result.
- Destructive operations are **deferred, not banned** (`deluluscan/safety.py`).
  `is_destructive()` classifies; `DestructivePolicy` decides whether to send now.
  Enforcement lives in `HttpClient` — the one choke point every scanner uses — so
  it holds for scanners that have never heard of `deluluscan.safety`.
- This is a target-only build: target-specific scanners (`known_cve`,
  `advisories`, `es_exposure`) run only when the target is fingerprinted.
- Authorization boundary is a feature: loopback/RFC1918 only unless the config
  asserts `allow_remote` for a target the user is authorized to test. Do not
  remove or bypass it.
- Never weaponize findings — confirm to proof, then report.
- **Verify deep, not on the surface — for EVERY class.** After the differential
  `Verifier`, `deluluscan/verify/deep.py` (`DeepVerifier` + pluggable `DeepStrategy`s)
  runs researcher-grade depth on every credible finding: `IdentityMatrix` re-probes
  the endpoint as each identity (who really gets in?), `SessionRiding` probes it
  anon/cookie/Bearer/Basic + reads cookie flags to decide XSS/CSRF-drivability, and
  `InjectionBypass` computes verified filter bypasses. It refines `exploitability`
  ONLY on concrete evidence and never flips a live verdict. Add a strategy here to
  deepen a new class rather than bolting logic onto a scanner.
- **Verify deep, not on the surface.** A reflected/echoed value is a *lead*, not a
  finding. Before asserting one, the deep-verification layer (`deluluscan/verify/` +
  `deluluscan/active/filter_bypass.py`) must: (a) try filter **bypasses** — field-split a
  payload so each fragment evades a per-field blocklist, verified against the real
  filter regex; (b) read a stored value back through **every** echo surface and
  classify each render context — a raw value in a **JSON API is a precondition, NOT
  execution** (only a raw render in an HTML sink executes); (c) probe an endpoint
  **multiple auth ways** (anon / session-cookie / Bearer / Basic) — the same JWT is
  often rejected as a cookie but accepted as a Bearer header, and cookie-auth means
  a same-origin XSS can session-ride it; (d) analyse **weaponizability** from the
  credential surface (HttpOnly hides a cookie from JS but the browser still *sends*
  it; a token in web storage is JS-readable). Grade honestly: `served_raw_api` +
  session-ridable target is `conditional` pending one browser-render confirmation,
  not a hard `exploitable`. Use fresh credentials per probe — the target rotates the
  `rme` JWT, and a stale token yields false 401s.

## Layout

- `deluluscan/cli.py` — scan entrypoint · `deluluscan/recheck.py` — single-endpoint re-test
- `deluluscan/dashboard.py` — payload injection + AES-GCM (no markup) ·
  `dashboard/` — the React report UI · `deluluscan/assets/dashboard_bundle.html` — its built shell
- `deluluscan/orchestrator.py` — pipeline
- `deluluscan/ai/` — pluggable AI layer (advisory): `providers.py` (one `AIProvider`
  interface → anthropic/openai/deepseek/openai_compat/ollama/claude_code/codex/bedrock,
  fail-soft, secret-redaction-before-send, multi-turn `chat()`), `analyst.py`
  (prioritize/triage/analyze, delegates to the provider). `tests/test_ai_providers.py`,
  `tests/test_bedrock_provider.py`. AI is advisory — the live verifier stays authoritative.
- `deluluscan/llm/` — LLM/AI-system pentest pack (WS-3): `target.py` (LLMTarget: any
  chat endpoint via presets/response-path, or a WS-1 provider), `probes.py` (benign
  canary-based OWASP LLM Top 10 corpus incl. multi-turn crescendo), `engine.py`
  (reproduction-gated, evidence-first grading). CLI: `python3 -m deluluscan.llm`.
  `tests/test_llm_pentest.py`.
- `deluluscan/recon/` — advanced reconnaissance: `signatures.py` (web/JS-lib
  fingerprints + known-vulnerable-library rules + content wordlists), `engine.py`
  (ReconEngine → web fingerprint, crt.sh subdomains, content discovery → ReconProfile
  → Finding[]). CLI: `python3 -m deluluscan.recon`. `tests/test_recon.py`.
  ReconEngine auto-folds platform intelligence (below) into `ReconProfile.platform`.
  `jsanalysis.py` (`extract_endpoints`) statically pulls API endpoints from client
  JS — fetch/axios/$.ajax/XHR calls + API-shaped literals, template params
  normalized to `{param}` — recovering shadow/undocumented surface (OWASP API9)
  without a headless browser; ReconEngine follows same-origin `<script>` bundles
  (`do_js`, bounded by `max_scripts`) → `ReconProfile.js_endpoints` + an INVENTORY
  finding. `tests/test_jsanalysis.py`.
- `deluluscan/platforms/` — platform intelligence (know what the target *is*):
  `profiles.py` (data-driven `PlatformProfile`s — WordPress/Drupal/Joomla/Ghost +
  AWS/GCP/Azure hosting — each carrying fingerprint `Signal`s, API base+style, auth
  model, user-enum + version-disclosure surfaces, relevant vuln classes), `engine.py`
  (`PlatformScan.identify` → best-scoring profile + confidence; `.assess` →
  platform-specific findings: unauth user enumeration `/wp-json/wp/v2/users` &
  `/jsonapi/user/user`, version disclosure `CHANGELOG.txt`/`joomla.xml`, exposed
  `/xmlrpc.php` & `/administrator/`). Detection only; offline-testable via injected
  `fetch`. CLI: `python3 -m deluluscan.platforms --url … [--json]`.
  Docs: `docs/PLATFORM_INTELLIGENCE.md` (+ Nessus/Burp/ZAP capability map).
  `tests/test_platforms.py`. Add a platform = append a profile (data, not code).
  Ships 23 profiles (WordPress/Drupal/Joomla/Ghost, Laravel/Django/Rails/Express/
  Spring-Boot/Tomcat, Magento/Shopify, Jenkins/GitLab/Grafana/Kibana/phpMyAdmin/
  Atlassian, Elasticsearch/Kubernetes-API, AWS/GCP/Azure hosting). `exposed_checks`
  on a profile = data-driven live probes of its high-risk surfaces (Spring
  `/actuator/heapdump`, Jenkins `/script`, ES `/_cat/indices`, Laravel `/.env`).
  `cves.py` = version-gated known-CVE corpus (Nessus-plugin model): once a version
  is fingerprinted, `match_cves` maps it to CVEs whose affected range it's in
  (`version_in_range` supports `>=8.0,<8.3.1` specs). Graded firm/likely_true_positive
  but **exploitability="unknown"** — version-inference is a LEAD, not proof; the
  report says "running version is in the affected range", never "exploitable", until
  a live probe confirms. Add a CVE = append a `CveRule`.
- `deluluscan/netscan/` — edge & network reconnaissance (WAF/CDN/proxy, ports,
  honeypot, IDS/IPS): `signatures.py` (data-driven vendor DB — 18 WAF/CDN edges
  incl. Cloudflare/Akamai/Fastly/Imperva/Sucuri/AWS/Azure via cf-ray/x-amz-cf-id/
  x-iinfo/… + cookies + block-body; honeypot markers; port→service map;
  dangerous-port list), `waf.py` (`WafScan`: wafw00f-style passive header pass +
  active harmless block-probe; confidence scales with independent signals),
  `ports.py` (`PortScan`: bounded TCP-connect + banner-grab + service fingerprint,
  injectable `connect` for offline tests), `honeypot.py` (conservative *tentative*
  leads — known deception banners + implausible multi-service spread), `engine.py`
  (`NetScan`: composes all + IDS/IPS inference from a dropped malicious probe →
  `NetProfile`/Findings). Detection only; active passes gated to loopback/RFC1918.
  ReconEngine folds PASSIVE edge detection in automatically (`do_edge`, header-only).
  CLI: `python3 -m deluluscan.netscan --url … [--no-ports] [--json]`. `tests/test_netscan.py`.
- `deluluscan/passive/` — passive response analysis (ZAP passive-scan parity, no
  extra requests): `rules.py` (14 high-precision `PassiveRule`s over body/header/url
  — Java/Python/PHP/Ruby/.NET/Node stack traces + SQL errors (CWE-209), Werkzeug/
  Whoops/Django debug consoles (CWE-489), directory listing (CWE-548), internal-IP
  disclosure (CWE-200), secrets-in-URL (CWE-598), HTML-comment leaks (CWE-615)),
  `engine.py` (`PassiveScan.analyze(status,url,headers,body)` / `.analyze_record` —
  runs rules + folds in `secrets.scan_text`; covers what headers/ & secrets/ don't).
  Runs over responses already captured, so it can analyze every response for free.
  CLI: `python3 -m deluluscan.passive --url … | --stdin`. `tests/test_passive.py`.
  Wired two ways: (1) `deluluscan/assess/runner.py` runs it as a `passive` module;
  (2) the in-scan `scanners/passive.py` `PassiveScanner` folds these body rules over
  every collected response during a full orchestrator scan (deduped once per rule).
- `deluluscan/agentic/` — exploitation-chain agent (WS-2): `capabilities.py`
  (allowlisted safe primitives via injected toolbox), `agent.py` (`ExploitChainAgent`:
  bounded observe->act->verify loop, step budget, state-changing opt-in + approval gate,
  deterministic proof), `chain.py` (AttackChain -> confirmed Finding only when proven).
  AI proposes; tools execute; a verify fn decides truth. `tests/test_agentic.py`.
- `deluluscan/container/` — container/K8s security (WS-4): `analyzers.py`
  (Dockerfile/Kubernetes/docker-compose misconfig checks — privileged, host ns,
  docker-socket escape, caps, root, secrets, unpinned), `engine.py` (`ContainerScan`:
  dir auto-detect + exposed-control-plane probe). CLI: `python3 -m deluluscan.container`.
  `tests/test_container.py`.
- `deluluscan/cloud/` — cloud posture/CSPM (WS-5): `checks.py` (AWS/GCP/Azure
  inventory checks — public storage, open SGs, over-permissive IAM, root keys,
  unencrypted/public DBs, no CloudTrail), `imds.py` (SSRF->metadata->credential
  exposure, values redacted), `engine.py` (`CloudScan`). CLI: `python3 -m deluluscan.cloud`.
  `tests/test_cloud.py`.
- `deluluscan/kb/` — knowledge base / RAG (WS-6): `index.py` (offline BM25
  `KnowledgeIndex` over CVEs/advisories/prior findings/Mantis), `mantis.py` (ingest
  Google Mantis findings -> docs + vuln-class probe hints), `retriever.py`
  (`ground`/`augment_system` — advisory grounding). CLI: `python3 -m deluluscan.kb`.
  Distinct from `knowledge.py` (standing methodology). `tests/test_kb.py`.
- `deluluscan/webapi/` — deeper web/API surface (WS-7): `graphql.py` (introspection
  -> surface map + findings), `websocket.py` (CSWSH), `grpc.py` (server reflection).
  CLI: `python3 -m deluluscan.webapi --graphql <url>`. `tests/test_webapi.py`.
- `deluluscan/headers/` — HTTP security-header / CORS / cookie analysis: `analyzer.py`
  (CSP/HSTS/nosniff/clickjacking/referrer, CORS wildcard+reflected-origin-with-credentials,
  insecure cookie flags, version disclosure), `engine.py` (`HeaderScan` + CORS reflection
  probe). CLI: `python3 -m deluluscan.headers --url`. `tests/test_headers.py`.
- `deluluscan/memory.py` — engagement memory (cross-scan learning store): `EngagementMemory`
  (JSON, per-target `record_scan`/`recall`/`save`), `Recall`, `target_key_from_fingerprint`.
  Wired into the orchestrator (recall after fingerprint → prioritize → annotate →
  record at end); `python3 -m deluluscan.memory <store.json>` inspects it. `tests/test_memory.py`.
- `deluluscan/knowledge.py` — security knowledge base (the standing per-class methodology,
  Deluluscan's "skills"): `METHODOLOGY` (per-VulnClass `ClassKnowledge`: summary, how_tested,
  deep-verify discipline, remediation, OWASP-2025/API-Top-10/CWE), `methodology_for`,
  `verification_steps`, `remediation_for`, `taxonomy_for`. Memory = *what we found here*;
  knowledge = *how to test & verify each class*. Wired into `reporting/evidence_report.py`
  `build_report` (fills each finding's remediation + `verify_steps` + taxonomy references
  from the corpus). Inspect: `python3 -m deluluscan.knowledge`. `tests/test_knowledge.py`.
- `deluluscan/telemetry/` — grey-box observability plane (`--observe`): `sources.py`
  (fail-soft `DockerLogSource`/`DockerStatsSource`, tap the target container's
  logs/mem/CPU — no agent inside it), `recorder.py` (`Recorder`: thread-safe,
  redacts secrets AT INGEST, wall-clock timeline), `signatures.py` (exception→
  vuln-class trace map, secret patterns, log-forgery detection), `correlator.py`
  (`Correlator` joins probe windows to the timeline → trace-leak / secrets-in-logs
  / detection-gap / memory findings). Probe windows are captured at the one choke
  point (`HttpClient.enable_probe_log`). Wired into the orchestrator (start sources
  → baseline at sweep start → correlate after verify → `meta.telemetry`).
  Active grey-box scanners: `scanners/memory_disclosure_scanner.py`,
  `scanners/log_injection_scanner.py`, `scanners/resource_consumption_scanner.py`
  (the last two are telemetry-aware — the orchestrator injects the recorder via a
  `telemetry_aware` construction branch). Dashboard: `dashboard/src/components/TelemetryView.tsx`
  (the Behavioral tab). `tests/test_telemetry.py` + `tests/test_grey_scanners.py`
  (offline: synthetic timeline + windows + fake recorder, no Docker).
- `deluluscan/scanners/` — the scanner arsenal · `deluluscan/verify/` — differential verifier
- Deep-verification layer: `deluluscan/verify/deep.py` (generalised `DeepVerifier` +
  strategies, runs on all classes) · `deluluscan/active/filter_bypass.py` (filter-evasion
  mutations + verifiers) · `deluluscan/verify/readback.py` (read stored values back across
  every sink; HTML-execution vs JSON-precondition) · `deluluscan/verify/exploitability.py`
  (auth-matrix + credential-surface → weaponizable vs contained) ·
  `deluluscan/verify/deep_chain.py` (composes them: bypass→store→read-back→weaponize?→
  restore) · `deluluscan/scanners/deep_stored_xss.py` (live wiring for the name sink)
- Report UI is editable: `dashboard/src/components/PentestReportView.tsx` +
  `dashboard/src/lib/report-edits.ts` (per-scan overrides in localStorage) +
  `dashboard/src/lib/markdown.tsx` (self-contained, HTML-escaping renderer). The
  generated report is always the default; edits shadow it and Reset reveals it.
- `scripts/verify_known_cves.py` — targeted verifier for the #642/#651 chains
- `deluluscan/fingerprint.py` · `deluluscan/discovery.py` · `tests/` — one suite per area
  (`tests/test_deep_verify.py` covers the deep-verification layer)
