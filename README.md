# Deluluscan

**AI-augmented, evidence-first security auditor** for **authorized** testing across
web, API, application, container/Kubernetes, cloud, and **LLM/AI-system** targets.

[![PyPI](https://img.shields.io/pypi/v/deluluscan.svg)](https://pypi.org/project/deluluscan/)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776ab.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-73_suites_green-brightgreen.svg)](tests/)
[![Local AI](https://img.shields.io/badge/AI-Claude%20%7C%20OpenAI%20%7C%20DeepSeek%20%7C%20Ollama-8a2be2.svg)](docs/LOCAL_MODELS.md)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

Deluluscan automates the mechanical phases of an assessment — discovery, fingerprinting,
active/passive scanning, known-CVE checks, and **evidence-based verification** — and
produces a triaged, reproducible report. It is built to *augment* a security engineer:
it does the repeatable parts thoroughly with low false positives, **verifies findings up
to proof before asserting them**, and can reason with a **local, offline LLM** so nothing
leaves your host.

> ### ⚠️ Authorization & scope
> Deluluscan enforces a **scope gate**: by default it only targets **loopback / RFC1918**
> (private) hosts. Testing any other host requires explicitly asserting authorization
> (`allow_remote` in config, or `--allow-remote` on the domain tools). **Only test
> systems you own or have written permission to assess.** Unauthorized scanning is illegal
> in most jurisdictions (CFAA, Computer Misuse Act, …). Deluluscan **confirms to proof but
> never weaponizes** — no exfiltration, no persistence, no DoS.

---

## Why Deluluscan

- **Evidence-first.** Every finding is re-tested with a differential oracle before it's
  rated; a bare `200`/`400`/`500` is never treated as proof. Findings carry an honest
  verdict (confirmed / likely / conditional / inconclusive / false-positive), a
  reproducible **CVSS v3.1** vector, and **compliance mappings** (PCI-DSS / SOC 2 / ISO 27001).
- **AI as a force multiplier, not a black box.** The AI *proposes*; deterministic tools
  *execute*; the live verifier *decides truth*. It never overwrites a re-test result.
- **Runs on your terms.** Pluggable AI backends — Anthropic, OpenAI, **DeepSeek**, **Ollama
  (fully offline)**, Claude Code, Codex, Bedrock — with **secret redaction before send**.
- **Knows what it's testing.** Fingerprints the platform (23 profiles — WordPress/Drupal/
  Joomla, Laravel/Django/Rails/Spring/Tomcat, Jenkins/GitLab/Grafana/Kibana, Elasticsearch/
  Kubernetes, …) and tests it accordingly: its API shape, auth model, sensitive surfaces,
  and **version-gated known CVEs** (Nessus-plugin model). Detects the **edge** too — WAF/CDN
  (18 vendors: Cloudflare/Akamai/Fastly/Imperva/…), open ports/services, honeypot & IDS/IPS.
- **Broad coverage, one tool.** Web · API (REST/GraphQL/WebSocket/gRPC) · headers/CORS/cookies
  · secrets · **passive analysis (ZAP-style)** · **JS/SPA endpoint discovery (static + optional
  headless-browser crawl)** · **TLS/SSL · DNS/email · subdomain takeover · HTTP request
  smuggling (timing-only) · SMB/LDAP posture** · **LLM/AI systems (OWASP LLM Top 10)** ·
  containers/K8s · cloud (CSPM) · source (SAST) · API specs.
- **Prioritized like modern ASPM.** Every finding is ranked by real-world risk — **EPSS**
  exploit probability, **CISA KEV** (confirmed exploited), a combined **0–100 priority score**,
  and **MITRE ATT&CK** technique tags — so you fix what matters first, not just what scores high.

## Install

```bash
pip install deluluscan            # from PyPI
# optional extras: bedrock (AWS), web (FastAPI UI), xlsx (Excel export),
#   crawler (headless-browser dynamic crawl), or everything:
pip install "deluluscan[all]"
# the crawler extra also needs a browser binary:  playwright install chromium
```

Or from source:

```bash
git clone https://github.com/rsh1k/deluluscan && cd deluluscan
pip install -e . --break-system-packages
```

## Quickstart

```bash
# unified assessment of an authorized target -> local report files (no publishing)
python3 -m deluluscan.assess --url http://127.0.0.1:8080/ \
    --sast-path ./src --spec openapi.json \
    --formats md,html,json,sarif --out-dir ./report

# full active scan with an OpenAPI spec
python3 -m deluluscan.cli --config config.yaml --openapi-file openapi.json --allow-state-changing

# reason with a local, offline model (no data leaves your host)
python3 -m deluluscan.cli --config config.yaml --ai ollama --ai-model qwen2.5:7b
```

Copy `config.example.yaml` → `config.yaml`, set your target and identities, and leave the
`scan.scanners` list commented out to run the full set. See **[docs/LOCAL_MODELS.md](docs/LOCAL_MODELS.md)**
for running a model on a low-RAM / WSL / non-NVIDIA machine.

## Capabilities

| Domain | Module | What it does |
|---|---|---|
| **Web / API scanning** | `scanners/`, `verify/` | 43 checks across the OWASP API/Web Top 10, with a deep differential verification layer (identity matrix, filter-bypass, read-back sink classification, weaponizability grading). Burp-style Intruder (sniper/battering-ram/pitchfork/cluster-bomb). |
| **Reconnaissance** | `recon/` | Tech/JS-library fingerprint (+ known-vulnerable versions), CT-log subdomain enumeration, content discovery, and **static JS endpoint extraction** (fetch/axios/XHR → shadow API surface). |
| **Platform intelligence** | `platforms/` | Fingerprints **23 platforms** (WordPress/Drupal/Joomla, Laravel/Django/Rails/Spring/Tomcat, Jenkins/GitLab/Grafana/Kibana, Elasticsearch/Kubernetes, …) → API shape, auth model, sensitive surfaces, user-enum & version disclosure, plus **version-gated known CVEs** (Nessus-plugin model). |
| **Edge / network recon** | `netscan/` | WAF/CDN/proxy detection (**18 vendors**, wafw00f-style passive+active), TCP port/service scan + banner grab, **TLS/SSL config** (deprecated protocols, weak/expired/mismatched certs, no-PFS), honeypot heuristics, IDS/IPS inference, **SMB/LDAP posture** (signing, SMBv1, anonymous bind). |
| **OSINT & takeover** | `recon/` | DNS/email intel (**SPF/DMARC/AXFR** + email harvest), **subdomain-takeover** fingerprints (14 providers, CNAME-corroborated). |
| **Prioritization** | `epss/`,`kev/`,`priority/`,`attack/` | Ranks findings by real-world risk: **EPSS** exploit probability, **CISA KEV** (confirmed exploited), a combined **0–100 priority score**, and **MITRE ATT&CK** technique tagging. |
| **Passive analysis** | `passive/` | ZAP-style, no extra requests — stack traces / SQL errors, debug consoles (Werkzeug/Whoops/Django), directory listing, internal-IP & secrets-in-URL, HTML-comment leaks. Runs over every collected response. |
| **Dynamic crawl** | `crawler/` | Optional headless-browser (Playwright) AJAX-spider: renders JS-heavy apps and captures the API calls the client actually makes — the dynamic surface a static parse can't resolve. |
| **HTTP hardening** | `headers/` | Security headers, CORS (wildcard / reflected-origin-with-credentials), cookie flags. |
| **Secrets** | `secrets/` | Credential exposure in responses & JS (AWS/GitHub/Google/Slack/Stripe/… + entropy-gated generic), matched **masked**. |
| **Deeper web/API** | `webapi/` | GraphQL introspection → surface map, WebSocket CSWSH, gRPC reflection. |
| **API spec** | `apispec/` | OpenAPI/Swagger security lint (missing auth, secrets in query, http servers, mass-assignment). |
| **Source (SAST)** | `sast/` | Dangerous patterns per language (eval/exec, deserialization, SQL concat, weak crypto, XSS sinks) + secrets, `file:line`. |
| **LLM / AI systems** | `llm/` | Bring-your-own-target OWASP LLM Top 10 pentest — prompt injection, jailbreaks, multi-turn crescendo, system-prompt leakage. |
| **Containers / K8s** | `container/` | Dockerfile / Kubernetes / compose misconfig (privileged, host ns, docker-socket escape, caps, secrets) + exposed control planes. |
| **Cloud (CSPM)** | `cloud/` | AWS/GCP/Azure posture over a collected inventory + SSRF→IMDS→credentials (values redacted). |
| **Agentic exploitation** | `agentic/` | Bounded observe→act→verify loop over an allowlist of safe capabilities; human-in-the-loop for state changes; deterministic proof. |
| **Correlation** | `correlate/` | Combine findings into attack chains (SSRF+metadata→cloud creds, XSS+cookie→session hijack) and feed the agent objectives to prove. |
| **AI layer** | `ai/`, `kb/` | Pluggable providers + an offline BM25 knowledge index (CVEs/advisories/Mantis) that grounds the AI. |
| **Grey-box** | `telemetry/` | Tap the target container's logs/mem/CPU (`--observe`) and correlate server events to the exact probe. |
| **Reporting** | `assess/`, `reporting/` | Merge findings → local **Markdown / HTML / JSON / SARIF / CSV / XLSX / JUnit**. No online publishing. |

Each capability also has a standalone CLI, e.g. `python3 -m deluluscan.recon --url …`,
`python3 -m deluluscan.platforms --url …`, `python3 -m deluluscan.netscan --url …`,
`python3 -m deluluscan.passive --url …`, `python3 -m deluluscan.crawler --url …`,
`python3 -m deluluscan.container --path ./deploy`, `python3 -m deluluscan.llm --provider ollama …`.
See **[docs/PLATFORM_INTELLIGENCE.md](docs/PLATFORM_INTELLIGENCE.md)** for the platform/edge
detection design and a Nessus/Burp/ZAP capability map.

## Design principles

- **The report may only state what the scan observed.** Untested surfaces read as untested;
  no synthesized evidence. Attack chains are *hypotheses* until the agent proves them.
- **Confirm to proof, never weaponize.** Heavy exploitation is delegated to opt-in,
  host-allowlisted third-party tools (nuclei, sqlmap without `--dump`, interactsh).
- **The authorization boundary is a feature**, not a limitation.

## Extending

- **Signatures** live in `deluluscan/fingerprint.py`; **scanners** in `deluluscan/scanners/`
  (self-register via `SCANNER_REGISTRY`).
- **Out-of-tree plugins** load from a directory (`deluluscan/plugins.py`); **Nuclei-style YAML
  templates** drop into `templates/` (`deluluscan/templates.py`) with no code.
- Run the tests: `python3 -m tests.<suite>` (e.g. `test_verify`, `test_llm_pentest`, `test_recon`).

## Contributing

**Contributions are very welcome** — Deluluscan gets better every time someone adds
a platform signature, a detection rule, a known CVE, or a scanner. Many additions
are **just data** (no engine code): a platform profile, a WAF/CDN signature, a CVE,
a passive rule, a Nuclei-style YAML template. See **[CONTRIBUTING.md](CONTRIBUTING.md)**
for the extension points, dev setup, and how to run the tests.

- New here? Look for [`good first issue`](https://github.com/rsh1k/deluluscan/labels/good%20first%20issue)
  and [`help wanted`](https://github.com/rsh1k/deluluscan/labels/help%20wanted).
- Found a bug or have an idea? [Open an issue](https://github.com/rsh1k/deluluscan/issues/new/choose).
- Every contribution must keep Deluluscan **defensive and authorized-testing only** —
  the authorization boundary stays, and we *confirm to proof, never weaponize*.
- Found a security issue **in Deluluscan itself**? Please report it privately — see
  **[SECURITY.md](SECURITY.md)**.
- Participation is governed by our **[Code of Conduct](CODE_OF_CONDUCT.md)**.

## License

**GNU Affero General Public License v3.0** — see [LICENSE](LICENSE). If you run a modified
version as a network service, the AGPL requires you to offer that version's source to its users.

Provided for authorized security testing and educational use only. You are responsible for
ensuring you have permission to test any target. The authors assume no liability for misuse.
