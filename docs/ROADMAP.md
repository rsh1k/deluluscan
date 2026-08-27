# Deluluscan Roadmap — from single-product auditor to broad AI-augmented offensive-security platform

> **Update — all workstreams (WS-1..WS-7 + WS-R) are now SHIPPED and tested.** The
> sections below record scope and status; each ✅ links to real, tested code.
>
> Status: strategic plan. This document sets the direction; it does not claim any
> capability below is implemented yet. Everything here is bounded by Deluluscan's
> non-negotiable rules: **authorized targets only** (the loopback/RFC1918 scope gate
> stays), **evidence-first** (a finding is only asserted after a live differential
> re-test), and **augment, don't replace** the human tester.

## 1. Vision

Deluluscan should find **actually exploitable** vulnerabilities across **any target a
modern engagement touches** — websites, APIs, applications, containers/Kubernetes,
cloud accounts, and **LLM/AI systems** — and it should get there by combining
deterministic scanners (fast, reproducible, low-false-positive) with an **AI
reasoning layer** that plans, chains, and confirms the way a human red-teamer does.

Three ideas drive the plan:

1. **AI as a force multiplier, not a black box.** The AI proposes hypotheses and next
   actions; deterministic tools execute them; the differential verifier decides truth.
   The model never overwrites a live re-test result. This is the lesson of the strong
   agentic pentest systems: PentestGPT's observe→hypothesize→select-tool→execute→refine
   reasoning loop ([USENIX Security 2024](https://github.com/greydgl/pentestgpt)), and
   XBOW reaching #1 on HackerOne with 1,060+ validated submissions by *validating*
   every exploit rather than reporting guesses.
2. **Pluggable intelligence.** The engagement should run against whatever model the
   operator has — an agentic coding tool (Claude Code, Codex), a hosted API
   (Anthropic, OpenAI, DeepSeek), or a **local Ollama model** for air-gapped/sensitive
   work — behind one provider interface.
3. **Depth through safe, sandboxed exploitation.** "Confirm to proof" grows from a
   single differential probe into a bounded exploit chain executed in an isolated
   sandbox / digital-twin, so we can prove *exploitability* without weaponizing against
   production (cf. digital-twin risk-mitigated exploitation,
   [arXiv:2604.22427](https://arxiv.org/pdf/2604.22427)).

## 2. Where we are today (the foundation to build on)

- **40+ scanners** across the OWASP API/Web Top 10, self-registering via `SCANNER_REGISTRY`.
- **Deep differential verification** (`deluluscan/verify/`): identity matrix, session-riding,
  filter-bypass, read-back sink classification, weaponizability grading.
- **Grey-box telemetry** (`deluluscan/telemetry/`): taps the target container's logs/mem/CPU
  and correlates each server event to the probe that caused it — server-confirmed injection.
- **Engagement memory** + **knowledge base** (`deluluscan/memory.py`, `deluluscan/knowledge.py`):
  cross-scan learning and standing per-class methodology.
- **Source-informed scanning** + a **Google [Mantis](https://github.com/google/mantis)**
  autonomous code-scan corpus hook (`--mantis-findings-dir`).
- **AI analyst** (`deluluscan/ai/analyst.py`): a single bounded model call per finding today
  — the seed of the provider abstraction below.
- **Reporting**: HTML dashboard, JSON/SARIF/CSV/XLSX/JUnit, CVSS v3.1, compliance mapping,
  cross-scan diffing.

## 3. Target architecture

```
                    ┌────────────────────────────────────────────┐
                    │              Orchestrator                    │
                    │  scope gate · scheduling · safety policy     │
                    └───────────────┬──────────────────────────────┘
        ┌───────────────────────────┼───────────────────────────┐
        ▼                           ▼                           ▼
 ┌────────────┐            ┌─────────────────┐          ┌───────────────┐
 │ Target-type │            │  AI reasoning    │          │  Knowledge /  │
 │  adapters   │            │  layer (agent)   │◄────────►│  corpus (RAG) │
 │  web/api    │            │  plan→act→verify │          │ CVEs, exploits│
 │  container  │◄──────────►│  multi-backend   │          │ advisories,   │
 │  cloud      │            │  provider iface  │          │ Mantis findings│
 │  llm/agent  │            └────────┬─────────┘          └───────────────┘
 └─────┬───────┘                     ▼
       ▼                    ┌──────────────────┐
 ┌────────────┐            │  Exploitation     │
 │ Deterministic│──────────►│  sandbox / twin   │
 │  scanners    │           │  proof capture    │
 └─────┬────────┘           └──────────────────┘
       ▼
 ┌──────────────────────────────────────────────┐
 │ Differential verifier (source of truth)        │
 └──────────────────────────────────────────────┘
```

Two new abstractions are the backbone:

- **`TargetAdapter`** — knows how to enumerate and probe one *class* of target (an HTTP
  app, a container image, a cloud account, an LLM endpoint). Adapters feed the same
  scanner/verifier pipeline, so reporting/verification stay uniform.
- **`AIProvider`** — one interface, many backends (below). The agent loop talks only to
  this interface.

## 4. Workstreams

### WS-1 — Pluggable AI backends (foundation) — ✅ SHIPPED
Implemented in `deluluscan/ai/providers.py` (+ `tests/test_ai_providers.py`): one
`AIProvider` interface with adapters for **anthropic, openai, deepseek, openai_compat
(vLLM/LM Studio/OpenRouter/…), ollama (offline), claude_code, codex, and bedrock** —
all fail-soft, with **secret redaction before send** (shared with the telemetry log
plane) and a multi-turn `chat()` primitive for the WS-2 agent loop. Config: `ai.provider`,
`ai.model`, `ai.endpoint`, `ai.api_key_env`, `ai.redact_prompts`; CLI: `--ai`, `--ai-model`,
`--ai-endpoint`. The analyst delegates to it; the live verifier stays authoritative.

Original scope:
Generalize `deluluscan/ai/analyst.py` into an `AIProvider` interface with adapters:
- **Agentic coding tools**: Claude Code, Codex (drive them as sub-agents for code-aware tasks).
- **Hosted APIs**: Anthropic, OpenAI, **DeepSeek** (OpenAI-compatible), Bedrock (exists).
- **Local**: **Ollama** (`/api/chat`) for air-gapped/sensitive engagements — no data leaves the host.
- Config: `ai.provider`, `ai.model`, `ai.endpoint`, cost/latency budget, redaction-before-send.
- Keep the current guarantee: **advisory only**; the live verifier is authoritative.

### WS-2 — Agentic exploitation loop (go deeper) — ✅ SHIPPED
Implemented in `deluluscan/agentic/` (+ `tests/test_agentic.py`): `ExploitChainAgent`
runs a bounded observe->hypothesize->act->verify loop that deepens ONE lead into a
DEMONSTRATED, chained exploit. Safety is enforced and tested: **allowlist-only**
action space (`build_capabilities` wraps safe primitives — probe/reachability/
read_back/follow_oob/escalate; an off-list AI action is rejected), a **step budget**,
**state-changing opt-in + human-in-the-loop approval gate**, and **deterministic**
objective verification (the model proposes, tools execute, a `verify` fn decides truth
— never the model). A proven chain becomes a confirmed `Finding`; an unproven one
emits nothing. Fail-soft to a fixed ordering when AI is off. No shell, no payloads,
never weaponizes.

Original scope:
An opt-in agent that turns *leads* into *proven* findings via a bounded reasoning loop
(observe → hypothesize → select tool → execute in sandbox → verify → refine), modeled on
[PentestGPT](https://github.com/greydgl/pentestgpt) and
[HackingBuddyGPT](https://github.com/greydgl/pentestgpt)'s `UseCase→Agent→Capability`
structure. Capabilities are the *existing* scanners/integrations exposed as tools. Every
step runs under the scope gate and a step budget; destructive actions require
human-in-the-loop (§6). Chaining (e.g. SSRF→metadata→cloud creds; IDOR→privesc→RCE) is
where real exploitability lives.

### WS-3 — LLM / AI-system pentest (new target class) — ✅ SHIPPED
Implemented in `deluluscan/llm/` (+ `tests/test_llm_pentest.py`): a bring-your-own-target
engine — `LLMTarget` (any chat endpoint via presets/response-path, or a WS-1 provider
directly) + a benign, canary-based probe corpus mapped to the OWASP LLM Top 10
(LLM01 direct/delimiter/jailbreak/**crescendo** multi-turn, LLM02, LLM05, LLM06, LLM07)
+ an evidence-first engine with reproduction-gated grading (confirmed vs. tentative,
LLM05 as a precondition). CLI: `python3 -m deluluscan.llm --url … --preset openai` or
`--provider ollama`. Scope-gated (loopback/RFC1918 unless `--allow-remote`).

Original scope:
A first-class `llm` adapter + scanner pack mapped to the **OWASP Top 10 for LLM
Applications (2025)** and the new **OWASP Top 10 for Agentic Applications** (Black Hat
EU 2025). Draw technique coverage from the reference red-team tools —
[garak](https://github.com/NVIDIA/garak) (NVIDIA; hundreds of probes),
[PyRIT](https://github.com/Azure/PyRIT) (Microsoft; multi-turn *crescendo*/TAP),
[Promptfoo](https://www.promptfoo.dev/docs/red-team/owasp-agentic-ai/) (50+ vuln types,
CI/CD), and DeepTeam. Probes: direct + **indirect** prompt injection (poisoned
docs/RAG/tickets), jailbreaks, multi-turn escalation, system-prompt/data leakage,
tool/function-call abuse, excessive-agency and over-broad permissions, insecure output
handling. Same discipline: a model saying something bad once is a *lead*; confirm with a
reproducible, scored probe before asserting.

### WS-4 — Containers & Kubernetes (new target class) — ✅ SHIPPED
Implemented in `deluluscan/container/` (+ `tests/test_container.py`): static analyzers for
**Dockerfile** (root user, :latest, pipe-to-shell, ADD-from-URL, secrets in ENV/ARG),
**Kubernetes manifests** (privileged, host namespaces, docker-socket/sensitive hostPath =
escape, dangerous capabilities, runAsRoot, plaintext env secrets, no limits, SA-token
automount, unpinned images), and **docker-compose** (privileged, host net/pid, docker.sock
mount, cap_add, unconfined, secrets). Plus an **exposed-control-plane probe** (Docker API
2375 / kubelet 10250 / etcd 2379 / insecure API 8080 / registry 5000). Emits graded
`Finding`s (misconfig/info_leak/supply_chain). CLI: `python3 -m deluluscan.container --path
./deploy [--host 127.0.0.1]`, scope-gated.

Original scope:
A `container` adapter wrapping/emulating the [Trivy](https://github.com/aquasecurity/trivy)
model — image CVEs, IaC misconfig (Terraform/CloudFormation/K8s manifests), SBOM,
exposed secrets — plus runtime/cluster checks (kube-hunter/kubescape-style) and
container-escape / privileged-pod / RBAC-abuse leads. Findings flow into the same
verifier and report.

### WS-5 — Cloud (new target class) — ✅ SHIPPED
Implemented in `deluluscan/cloud/` (+ `tests/test_cloud.py`): CSPM checks over a
collected inventory (AWS/GCP/Azure — public storage, world-open security groups on
sensitive ports, over-permissive IAM `Action:* Resource:*`, users without MFA, root
access keys, public/unencrypted RDS, disabled CloudTrail; GCP public GCS + open
firewalls; Azure public blob + open NSG), plus **SSRF->IMDS->credentials** detection
(`imds.py`: AWS/GCP/Azure metadata credential reachability, **values redacted**). No
cloud SDK needed — feed `aws describe-*` / Prowler / Terraform JSON. CLI:
`python3 -m deluluscan.cloud --inventory aws.json --provider aws [--check-imds]`.

Original scope:
A `cloud` adapter for CSPM + cloud exploitation across AWS/Azure/GCP, modeled on
[Prowler](https://github.com/prowler-cloud/prowler) (600+ checks, 40+ frameworks),
ScoutSuite, and [Pacu](https://github.com/RhinoSecurityLabs/pacu) for AWS exploitation.
Read-only posture assessment by default; state-changing/exploitation gated exactly like
the existing destructive policy. Ties into WS-2 chaining (a leaked key becomes an
exploitation path, proven in an isolated account).

### WS-6 — Knowledge & autonomous discovery corpus — ✅ SHIPPED
Implemented in `deluluscan/kb/` (+ `tests/test_kb.py`): an **offline BM25** knowledge
index (no embeddings API — runs on the low-end device) that ingests CVEs, advisories,
prior-scan findings, and **Google Mantis** code-scan findings, and grounds the AI layer
(`ground()` / `augment_system()` — advisory; the live verifier stays authoritative).
`mantis.py` parses a Mantis workspace into KB docs AND vuln-class-mapped **probe hints**
the live scanner can turn into targeted probes (deepening `--mantis-findings-dir`). CLI:
`python3 -m deluluscan.kb --build <dir> --out kb.json` / `--query "…" --index kb.json`.

Original scope:
Feed the AI scanner real knowledge, RAG-style: a local index of CVEs, vendor advisories,
public exploits/PoCs, and prior findings, queried during hypothesis generation (extends
the existing analogical-research and `knowledge.py` work). Deepen the
[Mantis](https://github.com/google/mantis) hook into a first-class autonomous
source-review campaign whose output (find→reproduce→patch candidates) seeds targeted live
probes — the same idea that let Project Zero's "Big Sleep" find a novel exploitable
memory-safety bug in SQLite that fuzzing missed. Auto-generate detection templates from
CVE text (as Nuclei now does) to keep coverage current.

### WS-R — Advanced reconnaissance — ✅ SHIPPED
Implemented in `deluluscan/recon/` (+ `tests/test_recon.py`): a recon pass that
builds a target profile before/while scanning — **web/tech + JS-library fingerprint
with versions and known-vulnerable-library flagging** (jQuery/Bootstrap/Lodash/
Moment/AngularJS-EOL → CVEs), **CT-log (crt.sh) subdomain enumeration** with live
resolution, and **content discovery** (.git/.env/actuator/swagger/admin + a dir
wordlist). Emits `Finding`s (vulnerable lib → supply_chain, exposed .git/.env →
info_leak, admin/actuator → misconfig) that feed the report. CLI:
`python3 -m deluluscan.recon --url … --domain …`, scope-gated. Next: wire the profile
into the orchestrator so scanners prioritise by detected stack.

### WS-7 — Broader web/API depth — ✅ SHIPPED
Implemented in `deluluscan/webapi/` (+ `tests/test_webapi.py`): **GraphQL introspection**
attack-surface mapping (enumerates queries/mutations/types, flags dangerous mutations
delete/admin/password and sensitive fields, reports introspection-enabled), **WebSocket
CSWSH** (foreign-Origin-accepted detection with auth-aware grading), and **gRPC server
reflection** exposure. Scope-gated CLI: `python3 -m deluluscan.webapi --graphql <url>`.

Original scope:
gRPC, WebSocket, and GraphQL-introspection-driven attack surface; smarter auth/session
state machines; and tighter optional hand-off to best-in-class tools already integrated
philosophically here — [nuclei](https://github.com/projectdiscovery/nuclei),
sqlmap, Metasploit, interactsh — host-allowlisted and opt-in.

## 5. Making findings *actually exploitable* (depth)
- **Chaining engine**: represent findings as nodes and search for exploit paths (SSRF→IMDS→cloud,
  IDOR→account-takeover, upload→RCE). The AI proposes candidate chains; the sandbox proves them.
- **Sandbox / digital-twin execution**: clone the target (compose/container snapshot) and run the
  proof there, so exploitability is demonstrated without harming production
  ([arXiv:2604.22427](https://arxiv.org/pdf/2604.22427)).
- **Proof capture**: every confirmed exploit carries a replayable request sequence + captured
  evidence, feeding the report and the regression corpus.
- **OAST everywhere**: extend the existing interactsh/local-OAST for blind SSRF/XXE/RCE across all
  adapters.

## 6. Safety, authorization & responsible use (hard requirements)
Autonomy raises the stakes, so the guardrails grow with the capability:
- **Scope gate stays absolute** — loopback/RFC1918 unless `allow_remote` asserts written authorization.
- **Human-in-the-loop for destructive/state-changing agent actions** — dry-run plan first, explicit approval, full audit log of every AI-initiated action.
- **Never weaponize** — confirm to proof, in a sandbox; no exfiltration, persistence, or DoS.
- **Redaction before send** — secrets/PII stripped before any prompt leaves the host; local Ollama for the most sensitive targets.
- **Prompt-injection-aware agent** — the target's content is untrusted input to *our* agent too (OWASP LLM01); treat scraped/tool output as data, never instructions.

## 7. Evaluation
Track real numbers, not vibes: run against public benchmarks (the XBOW validation suite,
CTF-style ranges, deliberately-vulnerable apps), and report **success rate, false-positive
rate, and mean-time-to-proof** per release — the metrics the leading agents publish
(PentestGPT ~86.5% on the XBOW suite; XBOW ~85% self-reported). Every confirmed finding
becomes a regression test.

## Running the AI locally
See **[LOCAL_MODELS.md](LOCAL_MODELS.md)** for running a model on a low-capacity/WSL/
non-NVIDIA device (CPU quantization, MoE disk-streaming via `potatomaxx`, and the
`--ai ollama` / `--ai openai_compat` wiring).

## 8. Suggested sequencing
1. **WS-1** AI provider interface (unblocks everything) + **WS-6** knowledge index.
2. **WS-2** agentic loop over existing scanners as tools + sandbox.
3. **WS-3** LLM/AI pentest pack (high demand, self-contained).
4. **WS-4 / WS-5** container + cloud adapters.
5. **WS-7** deeper web/API + chaining engine hardening.

## References
- Google Mantis — agentic security-review skills for AI coding agents: https://github.com/google/mantis · https://cloud.google.com/blog/topics/threat-intelligence/staying-ahead-of-adversarial-ai-through-agentic-source-code-review
- PentestGPT (USENIX Security 2024): https://github.com/greydgl/pentestgpt
- OWASP Top 10 for LLM Applications (2025) & Agentic Apps: https://genai.owasp.org/llm-top-10/ · https://www.promptfoo.dev/docs/red-team/owasp-agentic-ai/
- LLM red-team tooling — garak / PyRIT / Promptfoo / DeepTeam: https://threatclaw.io/en/blog/llm-red-team-tools-garak-pyrit-promptfoo
- Autonomous offensive agents survey (XBOW, Strix, Nebula, PentAGI…): https://www.resecurity.com/blog/article/when-ai-becomes-the-attacker-understanding-autonomous-offensive-security-agents · https://appsecsanta.com/research/ai-pentesting-agents-2026
- Cloud/container tooling — Prowler, ScoutSuite, Trivy, Pacu: https://redteamguide.com/tools/cloud-pentesting-tools-2026/ · https://www.invicti.com/blog/web-security/iac-security-scanning-tools
- DAST/exploitation landscape — nuclei, sqlmap, Metasploit, Caido: https://plextrac.com/the-most-popular-penetration-testing-tools-this-year/
- Digital-twin risk-mitigated exploitation: https://arxiv.org/pdf/2604.22427
- VMS: LLM agent & eval framework for autonomous pentest: https://arxiv.org/pdf/2507.21113
