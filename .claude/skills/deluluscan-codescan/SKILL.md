---
name: deluluscan-codescan
description: >
  Refresh Deluluscan's source-informed scanning corpus: clone the latest target source,
  run a full Mantis (github.com/google/mantis) autonomous code-scan campaign
  against it, and leave the resulting findings ready for deluluscan-audit to consume
  via --mantis-findings-dir. Use when the user wants to (re)generate or update
  the code-scan corpus, not for running a routine API audit itself.
---

# Deluluscan code-scan refresh — clone the target + Mantis campaign

This skill produces the input `deluluscan-audit` uses to target its live API testing
at the endpoints most likely to have a real vulnerability behind them, per a
Mantis static/semantic code-scan of the actual target source. It is a separate,
occasionally-run refresh step — NOT part of every audit. Mantis's own campaign
is a long-running, multi-pass process (potentially many subagents and a large
token budget); run it when you want a fresh corpus, then reuse the cached
findings across many subsequent `deluluscan-audit` runs until you refresh again.

**Scope note:** the target source is one you are authorized to review, so cloning and statically
auditing it needs no separate authorization beyond what's already established
for testing the user's own the target instance. The whole point of this pipeline is
defensive: findings only ever inform which of the user's OWN authorized
endpoints to test more deeply. Never act on a Mantis finding against any
instance other than the one already confirmed in scope (CLAUDE.md's
authorization boundary applies identically here) — Mantis's exploit/reproduce
stages are for validating the finding is real in a private sandbox copy of the
source, never against a live target.

## Step 1 — clone the latest source

```
./scripts/clone_target_source.sh                 # master branch -> .target-src/core
./scripts/clone_target_source.sh master           # re-run any time to refresh to HEAD
```

This is a shallow clone, refreshed in place on re-run (fetch + hard reset), so
"latest" always means current upstream `master` at the time you run it. Note
the printed commit SHA — it's the provenance for this pass's findings.

## Step 2 — stand up a Mantis workspace (sibling, never nested)

Mantis's meta-agent refuses to pin snapshots when `state_root` resolves inside
`CODE_ROOT` (it would corrupt the snapshot boundary). Put the workspace
alongside the clone, not inside it:

```
mkdir -p .target-src/mantis-workspace/workspace
```

So you'll have:
```
.target-src/core/                 <- CODE_ROOT (the target clone)
.target-src/mantis-workspace/      <- state_root (workspace/, findings/, kb/, .mantis_snapshots/)
```

## Step 3 — run the full Mantis campaign

Per the user's standing choice for this project: run the **full autonomous
campaign** via `mantis-meta-agent` (not a single lightweight pass) — deeper
coverage across the target's whole codebase, not just the REST-facing layer,
because a source-level auth bypass or unsafe deserialization can originate in
a shared library and only surface at a REST boundary several calls away.

1. Install the skills once: `npx skills add google/mantis` (Mantis ships NO
   executable — it is 18 SKILL.md prompt files + schema.json that a coding agent
   follows, so every stage below is a slash command inside the agent).
2. Build the knowledge base first (once, or whenever the snapshot changes), in
   the upstream order — `structural-index` is what generates
   `workspace/kb/structural_index/` + the query helper the researcher relies on,
   so skipping it degrades every later stage:
   `/mantis-history` -> `/mantis-structural-index` -> `/mantis-summarize` ->
   `/mantis-architecture` -> `/mantis-threat-model`, all pointed at
   `--snapshot_root=.target-src/core --state_root=.target-src/mantis-workspace`.
3. Launch the supervisor to drive the continuous review loop:
   ```
   /mantis-meta-agent --sync --state_root=<absolute path to .target-src/mantis-workspace>
   ```
   `--sync` is required here — it's what makes the meta-agent pin an immutable
   snapshot of `.target-src/core` for this pass and record `discovery_commit`
   on every finding, so later `deluluscan-audit` runs can tell which source revision
   a finding came from. Because this is a long-running, multi-pass supervisor
   loop (not a single quick call), run it as a **background** Agent/Task and
   check in periodically rather than blocking on it — a thorough campaign over
   a codebase this size can run for a long time and spawn many subagents.
3. Let it run passes until the findings stabilize (consecutive passes surface
   nothing new) or you decide you have enough signal for this refresh. There
   is no fixed pass count — that's the meta-agent's own loop-until-dry
   behavior; don't cut it short after just one pass if it's still finding new
   issues.
4. Optionally run `mantis-chain` (exploit-chain construction across findings)
   and `mantis-calibrate` (final risk scoring) before treating the corpus as
   final — both read `workspace/findings/*.json` in place, no extra plumbing.

Findings land in `.target-src/mantis-workspace/workspace/findings/*.json`
(active) and `.target-src/mantis-workspace/workspace/archive/findings_pass_*/`
(prior passes) — exactly what `deluluscan.sourcescan.load_mantis_findings()` reads.

## Step 3b — run it as a RESUMABLE campaign, a slice at a time

A full sweep of the target source does not fit in one session. The first attempt at all
125 REST resources launched 6 parallel researchers over ~11k-line files and every
one died on the account token budget, writing **zero** findings. Don't repeat it:
run 2 agents over ~10 files per session and let the queue carry the state.

```bash
./scripts/mantis_queue.sh status        # how far the campaign has got
./scripts/mantis_queue.sh next 10       # carve the next slice (highest-yield first)
#   ... run 2 agents over kb/slice_current.txt following mantis-researcher ...
./scripts/mantis_queue.sh done          # mark the slice audited; re-rank the rest
```

`kb/audited.txt` is the resume marker, so a slice is never re-audited and the
campaign survives across sessions. Ranking weights `init(..., false, ...)`
(rejectWhenNoUser=false) 10x, then write verbs, then reads — that shape is what
produced this campaign's one confirmed finding, so a partial campaign is still a
useful one.

**Pre-filter before spending LLM budget.** Let the free deterministic pass pick
the targets and have Mantis adjudicate only where there is already signal:

```bash
python3 -c "from deluluscan.sourcescan import *;   print(len(SourceAnalyzer(SourceProvider(local_root='.target-src/core')).analyze(max_files=4000)))"
```

Measured on @94c5c8cf: 19 of 20 pre-filtered leads were refuted by the LLM pass —
so its real value is *rejecting* candidates a regex cannot judge (guards that live
downstream in a Paginator/Factory, or matches inside javadoc). Tell the agents
that refuting a lead counts as success and zero findings is a legitimate outcome,
or they will manufacture noise to look productive.

## Step 4 — hand the corpus to deluluscan-audit

No conversion step is needed — `deluluscan/sourcescan.py` reads Mantis's finding
JSON directly, resolves each `code_paths` entry (`relative/path.java:145`)
back to the enclosing target REST method and its live `@Path`, and merges it
into the same targeted-probe plan the regex-pattern static analysis already
produces (`deluluscan/sourcescan.py`'s `_PATTERNS`) — so both fire the SAME
scanners against the SAME live target, they just differ in how the candidate
was found. A finding whose `code_paths` file can't be re-read (renamed/moved
since the scan) is skipped, never guessed at.

Point the next `deluluscan-audit` run at this refreshed corpus:
```
python3 -m deluluscan.cli --config config.dev.yaml --openapi-file openapi.json \
  --allow-state-changing --fuzz \
  --source-root .target-src/core \
  --mantis-findings-dir .target-src/mantis-workspace/workspace
```

Every discovered endpoint still gets the full normal scanner suite — this
doesn't narrow coverage. Endpoints behind a Mantis (or regex-pattern) finding
additionally get the specific targeted probe for that finding's vuln class, so
higher-risk surfaces get deeper, more specific testing on top of the baseline
that already covers everything.

The dashboard's per-finding "why"/evidence already carries `evidence_file` as
`path:line` and (via `ai_verdict: "confirmed"`) flags these as pre-reviewed by
Mantis's own review/critic/calibrate stages — still re-test every one live via
`deluluscan.recheck` per the `deluluscan-audit` adjudication loop before trusting a
verdict; Mantis confirming a *code-level* pattern is not the same as it being
live-exploitable on this specific running instance.
