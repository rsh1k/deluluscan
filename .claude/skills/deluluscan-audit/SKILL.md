---
name: deluluscan-audit
description: >
  Drive an authorized security assessment with Deluluscan: run the scan, then
  for each candidate finding re-test the live API to adjudicate true vs. false
  positive, dig deeper on confirmed issues, fix scanner false positives in place,
  and generate the HTML dashboard. Use when the user asks to audit / scan / test
  their target instance, or to verify or triage Deluluscan findings.
---

# Deluluscan audit — the adjudication loop

You are driving Deluluscan, an authorized-testing security auditor, as an
interactive loop. Deluluscan does the mechanical scanning; YOU do the judgment:
re-test each candidate live, decide true/false positive, dig deeper, and fix the
tool when it is wrong.

## Preconditions (check first, every time)

1. Confirm the target in `config.yaml` is a target instance the user OWNS or is
   explicitly authorized to test (their own instance, or a confirmed in-scope
   bug-bounty asset that permits automated scanning). If this is not clearly
   established, STOP and ask — do not scan an unconfirmed third-party target.
2. Confirm `config.yaml` has `base_url` and identities set.

## The loop

### 0. Stand up the target (ephemeral, loopback)
If the user wants to audit a fresh the target release (rather than an already-running
instance), bring one up yourself on THIS host using docker-compose (preferred):
```
./up-compose.sh          # uses docker-compose.yml; provisions 6 test identities
                                # and auto-fetches openapi.json with admin auth
```
This starts Postgres + OpenSearch + the target via docker-compose, waits until
the target answers, then calls `scripts/provision_users.py` to create the test users
(backend, content_editor, readonly, api_user) and saves the authenticated
OpenAPI spec to `openapi.json`. First startup can take 3–5 minutes.

Tear down:  `docker compose down`

Alternatively for a quick single-container test (no user provisioning):
```
./up-target.sh [TAG]        # all-in-one dev image; admin@example.com / admin
```
Tear down: `docker rm -f target-audit`

Either way: use `config.dev.yaml` (base_url auto-updated by provisioning;
verify_tls off, admin@example.com/admin).

If the user is auditing their OWN already-running instance, skip this step
and point `config.yaml` at it (only with their confirmation it is authorized).

### 0.5. (optional) Point at a code-scan corpus
If a Mantis code-scan corpus already exists at `.target-src/mantis-workspace/workspace`
(see the **deluluscan-codescan** skill), add `--source-root .target-src/core
--mantis-findings-dir .target-src/mantis-workspace/workspace` to the scan
command below. Every endpoint still gets the full scanner suite regardless —
this only adds extra, vuln-class-specific probes on top for the endpoints a
source-level finding maps to, so higher-risk surfaces get deeper testing
without narrowing overall coverage. Don't clone the target or run Mantis yourself
here — that's a separate, occasionally-refreshed step (`deluluscan-codescan`), not
part of a routine audit; if no corpus exists yet, just skip this and scan
without it.

### 1. Scan
Run the full scan and capture structured output:
```
python3 -m deluluscan.cli --config config.dev.yaml --openapi-file openapi.json --allow-state-changing --fuzz
```
`openapi.json` is saved by `up-compose.sh`. If it is absent the scanner
auto-fetches the spec with admin auth during startup (the target build 26.x gates the spec
behind authentication). Drop `--allow-state-changing` for a read-only first pass.

The scan now tests six identities: anonymous, admin, backend, content_editor,
readonly, and api_user. Each finding's evidence records which identity made each
request, so the dashboard's "View as" switcher shows per-role HTTP traffic.

Read `deluluscan-out/results.json`.

### 2. Triage & adjudicate each candidate
For every finding whose `verdict` is `unverified`, `tentative`, `inconclusive`,
or `conditional`, RE-TEST it live to decide the truth, using the recheck engine:
```
python3 -m deluluscan.recheck --config config.yaml --from-results deluluscan-out/results.json --index <N>
```
Read the JSON verdict it prints:
- `verdict: false_positive` / no findings reproduced → it did NOT re-fire. Treat
  as a **false positive**. If it is a false positive caused by a tool bug (e.g. a
  soft-404 catch-all, a fingerprint mismatch, a scanner that flags benign
  behaviour), FIX the responsible scanner/module in `deluluscan/`, add or update a test
  under `tests/`, run the affected test suite, and re-run the recheck to confirm
  the fix silences it without hiding real issues.
- `verdict: true_positive` / `likely_true_positive` / `exploitable` → **confirmed**.
  Dig deeper: re-test adjacent parameters/endpoints (call recheck again with a
  different `--param` or `--path`) to map the blast radius, and record a concrete
  reproduction.
- `conditional` / `inconclusive` → note exactly what additional condition or
  manual step is needed; do not overclaim.

Do this per finding. Keep the noisy re-test traffic in a subagent when a finding
needs many probes, and bring back only the verdict + evidence.

### 3. Re-scan after fixes
If you changed any scanner code, re-run the full scan (step 1) so the results
reflect the fixed tool, then re-adjudicate anything that changed.

### 4. Report
Regenerate the dashboard from the adjudicated results:
```
python3 -m deluluscan.dashboard deluluscan-out/results.json deluluscan-out/dashboard.html
```
Confirmed false positives are excluded from the headline counts automatically.

## Rules

- Every verdict must come from an actual live re-test (recheck), never from the
  finding's title alone. A scanner hit is a hypothesis until re-tested.
- When you fix a false-positive-producing bug, always add a regression test so it
  cannot come back, and run the suite before moving on.
- Never weaponize a confirmed finding (no data exfiltration, RCE payloads, or
  persistence). Confirm up to proof, then stop and report — this is an auditing
  tool.
- Keep the authorization boundary: loopback/RFC1918 unless the user has asserted
  `allow_remote` for a target they are authorized to test.
