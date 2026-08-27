# Platform Intelligence — teaching Deluluscan to *understand* its target

A good tester does not fire the same payloads at every host. They first work out
**what the system is** — its stack, where its API lives and what shape it takes,
how it authenticates, and which surfaces leak the most — and *then* pick tests
that fit. `deluluscan/platforms/` gives Deluluscan that first step.

## What it does

`PlatformScan` runs two phases (both offline-testable via an injected
`fetch(url) -> (status, headers, body)`):

1. **`identify(base_url)`** — probes each profile's fingerprint *signals* (paths,
   headers, `<meta generator>`, body markers, API-discovery JSON), scores them,
   and returns the best-scoring platform above threshold with a confidence band
   (`tentative` / `firm` / `confirmed`). This is grounded in OWASP WSTG
   fingerprinting: the `generator` meta tag is the most explicit tell, asset
   paths (`/wp-content/`, `/sites/default/`, `/media/system/`) and response
   headers (`x-pingback`, `x-generator`, `x-amz-request-id`) corroborate it.

2. **`assess(base_url, detection)`** — runs the high-signal, *platform-specific*
   checks that generic scanners miss, each with the exact request/response as
   evidence:
   - **Unauthenticated user enumeration** — WordPress `/wp-json/wp/v2/users`,
     Drupal `/jsonapi/user/user` (leaks valid usernames/slugs → credential
     stuffing, targeted phishing). `INFO_LEAK`.
   - **Version disclosure** — Drupal `/CHANGELOG.txt`, Joomla `joomla.xml`
     (pins the exact build to public CVEs). `INFO_LEAK`.
   - **Exposed control / RPC surfaces** — WordPress `/xmlrpc.php` (pingback SSRF,
     `system.multicall` amplified brute-force), Joomla `/administrator/`.
     `MISCONFIG`.

A detected profile also carries the platform's **API base + style**, **auth
model**, **sensitive paths**, and the **vuln classes that matter most** for it —
so the rest of the scan (and the human) knows the system it is looking at.

## Profiles shipped

| Platform | Category | API | Auth | Signature highlights |
|---|---|---|---|---|
| WordPress | cms | `/wp-json` REST | cookie / app-password / JWT | `/wp-login.php`, `wp/v2` JSON, `x-pingback`, generator meta |
| Drupal | cms | `/jsonapi` JSON:API | cookie / Basic / API-key / JWT | `CHANGELOG.txt`, `x-generator`, `/sites/default/` |
| Joomla | cms | `/api/index.php/v1` REST | cookie / token | generator meta, `/administrator/`, `/media/system/` |
| Ghost | cms | `/ghost/api` REST | bearer / API-key | `/ghost/api/content/…`, generator |
| AWS (S3/CloudFront) | hosting | — | — | `Server: AmazonS3`, `x-amz-request-id`, CloudFront `via` |
| Google Cloud (GCS/GCLB) | hosting | — | — | `x-goog-generation`, `UploadServer` |
| Microsoft Azure | hosting | — | — | `x-azure-ref`, `x-ms-request-id` |

Beyond the CMS/hosting profiles above, the corpus now covers **web frameworks**
(Laravel, Django, Ruby on Rails, Express, Spring Boot, Apache Tomcat),
**e-commerce** (Magento, Shopify), **DevOps/infra consoles** (Jenkins, GitLab,
Grafana, Kibana, phpMyAdmin, Atlassian Jira/Confluence), and **data-store control
planes** (Elasticsearch, Kubernetes API) — **23 profiles** in total. Each declares
`exposed_checks`: data-driven live probes of its highest-risk surfaces, graded by
what a reachable response means:

| Platform | Exposed-surface check | If reachable |
|---|---|---|
| Spring Boot | `/actuator/heapdump` | **critical** — full process memory (tokens, creds) |
| Spring Boot | `/actuator/env` | high — config + often decrypted secrets |
| Jenkins | `/script` | **critical** — Groovy console = RCE |
| Elasticsearch | `/_cat/indices` | **critical** — unauth full-data exposure |
| Kubernetes API | `/api/v1/…/pods` | **critical** — anonymous-auth ⇒ cluster takeover |
| Laravel | `/.env`, `/telescope`, Ignition | critical/high — secrets + RCE surface |
| Magento | `/app/etc/local.xml` | critical — DB creds + crypt key |
| Tomcat | `/manager/html` | high — WAR deploy = RCE |
| Grafana | `/api/datasources` | high — path-traversal / SSRF history |

A 401/403 on such a path is reported as INFO ("present but access-controlled" — a
brute-force / auth-bypass target), not a hit.

## Version-gated CVEs (`cves.py`) — the Nessus plugin model

Once a profile fingerprints an **exact version** (via `version_path`/
`version_regex`), `match_cves(platform, version)` maps it to publicly-known CVEs
whose affected range it falls in. `version_in_range` supports composite specs
(`>=8.0.0,<8.3.1`). Shipped corpus (15 real CVEs) covers Drupal (Drupalgeddon2,
REST RCE), Joomla, Tomcat (Ghostcat), Spring (Spring4Shell), Jenkins
(CVE-2024-23897), GitLab (ExifTool RCE, CVE-2023-7028 ATO), Grafana
(CVE-2021-43798), Confluence (OGNL RCE, CVE-2023-22515), Elasticsearch,
Kubernetes (CVE-2018-1002105), and Magento.

**Honesty contract (critical):** a version match is a *lead, not proof*. These are
graded `confidence=firm` / `verdict=likely_true_positive` but
**`exploitability=unknown`** — the report says "the running version is in the
affected range for CVE-X", never "the target is exploitable via CVE-X", until a
live probe confirms it. This is exactly how a credentialed Nessus check reports a
version-inferred finding. Add a CVE = append a `CveRule` (data, not code). Adding a platform is **data, not
code**: append a `PlatformProfile` to `deluluscan/platforms/profiles.py`. Cloud
*posture* (CSPM, IMDS→credential SSRF) is handled by `deluluscan/cloud/`; these
hosting profiles only flag *where* an app is served so the cloud module can be
pointed at it.

---

# Edge & network reconnaissance — `deluluscan/netscan/`

Knowing the app is only half of situational awareness; a tester also needs to know
what sits *in front of* it and *around* it. `netscan` adds four detections, all
detection-only and (for the active passes) gated to the loopback/RFC1918
authorization boundary.

## WAF / CDN / reverse-proxy detection (`WafScan`, wafw00f-style)

Two passes, mirroring [EnableSecurity/wafw00f](https://github.com/EnableSecurity/wafw00f):

1. **Passive** — a normal request; inspect the response surface for vendor markers.
   Vendor-specific headers are near-definitive: `cf-ray` (Cloudflare), `x-amz-cf-id`
   (CloudFront), `x-iinfo` (Imperva), `x-sucuri-id` (Sucuri), `x-akamai-*`,
   `x-datadome`, plus Server strings and cookie names (`__cf_bm`, `visid_incap_`,
   `TS…` for F5). **Confidence scales with independent signals** — a lone `Server:`
   is weak; `Server` + `cf-ray` + `__cf_bm` is `confirmed`.
2. **Active** — one deliberately-suspicious (but harmless) request. If the response
   now blocks (403/406/429 + block body) or a vendor marker appears that was absent
   on clean traffic, an inline WAF is confirmed — even one invisible on normal
   traffic. If the block can't be attributed, it's reported as *Generic WAF
   (unattributed)*.

**18 vendors** shipped: Cloudflare, CloudFront, AWS WAF, Akamai, Fastly, Imperva
Incapsula, Sucuri, F5 BIG-IP ASM, Barracuda, FortiWeb, DDoS-Guard, DataDome, Azure
Front Door, ModSecurity, Wordfence, Varnish, nginx, Envoy. Add one = append an
`EdgeSig`.

Why it matters: an edge WAF/CDN **shapes how every other finding must be read** —
blocks and rate-limits can mask real vulnerabilities, and CDN caching changes what
"the server said". It is reported as INFO context, not a vulnerability.

## Port / service discovery (`PortScan`, nmap-`-sV`-lite)

A bounded TCP-connect scan over ~40 curated common ports with a short banner read
and `(port, banner)` service fingerprinting. Not an nmap replacement — a fast,
in-scope pass so the engagement knows which services are exposed. **Dangerous
exposures become HIGH findings**: unencrypted Docker API (2375), Redis (6379),
Elasticsearch (9200/9300), Memcached (11211), MongoDB (27017), raw DB ports
(3306/5432/1433), Kubernetes API (6443). Opens real sockets, so it's gated to
loopback/RFC1918; the `connect` fn is injected in tests.

## Honeypot / deception heuristics (`honeypot`)

Honeypot detection is genuinely hard — the literature treats it probabilistically
([Shodan Honeyscore](https://www.mdpi.com/1999-5903/18/4/190)) — so this module
emits only **tentative** leads, never a verdict, from: known deception-framework
banners (Cowrie/Kippo, Dionaea, Glastopf, Conpot), an implausible multi-service
spread on one host (Dionaea-style emulation), and banner/header inconsistency.

## IDS/IPS inference

A malicious probe that gets the connection **dropped/reset** while a clean request
succeeds implies an *inline* IPS silently dropping traffic — distinct from a WAF's
HTTP 403. Reported tentatively; passive inline sensors are, by nature, not always
observable from the outside.

```bash
python3 -m deluluscan.netscan --url http://127.0.0.1:8080 --json   # add --no-ports to skip the socket scan
```

Tests: `python3 -m tests.test_netscan` (offline — injected `fetch` + `connect`).

## How it's wired

`ReconEngine.run()` calls it automatically (`do_platform=True`, fail-soft) and
folds the result into `ReconProfile.platform` and the emitted `Finding`s, so a
normal scan surfaces platform intelligence with no extra flag. Standalone:

```bash
python3 -m deluluscan.platforms --url http://127.0.0.1:8080 --json
```

Tests: `python3 -m tests.test_platforms` (offline, synthetic fetch) and the
`test_platform_intelligence_folded_in` case in `tests/test_recon.py`.

---

# Capability research — Nessus / Burp Suite / OWASP ZAP, mapped to Deluluscan

Where the market-leading tools invest, what Deluluscan already covers, and what is
worth building next. Each item stays inside the tool's rules: **authorized targets
only**, **evidence-first**, **augment the human**.

## What each tool is strongest at

- **OWASP ZAP** (free, open-source) — an intercepting proxy with **passive** and
  **active** scan rules, a traditional **spider** + **AJAX spider** (headless
  browser) for JS-heavy apps, a **fuzzer**, scriptable rules, and an automation/REST
  API. Its passive rules (headers, cookies, info leaks) are a strong model for
  low-noise, always-on checks.
- **Burp Suite** — the interception **proxy** plus **Scanner**, **Intruder**
  (position-based fuzzing with attack types: sniper/battering-ram/pitchfork/cluster
  bomb), **Repeater**, and a rich **extension** ecosystem (BApp store). Its strength
  is operator-in-the-loop workflows.
- **Nessus** — **plugin-driven** vulnerability management: tens of thousands of
  version/CVE checks, **credentialed** (authenticated) scanning for local patch
  state, asset discovery, and compliance/audit policies. Its strength is breadth of
  known-vuln coverage and asset management.

## Deluluscan coverage today (the honest map)

| Capability | Nessus | Burp | ZAP | Deluluscan |
|---|:---:|:---:|:---:|---|
| Passive header/cookie/CORS rules | ~ | ✓ | ✓ | ✓ `headers/` |
| Active injection (SQLi/XSS/SSTI/SSRF) | ~ | ✓ | ✓ | ✓ `scanners/` + differential `verify/` |
| Spider / content discovery | ✓ | ✓ | ✓ | ✓ `recon/` (paths+wordlist) — **no JS crawler yet** |
| Fuzzing / Intruder-style | — | ✓ | ✓ | ~ `--fuzz` per-param — **no attack-type matrix yet** |
| Plugin/CVE version checks | ✓ | ~ | ~ | ~ `recon` vuln-lib rules + `kb/` — **no large CVE plugin corpus** |
| Credentialed / multi-identity scan | ✓ | ✓ | ~ | ✓ identity matrix in `verify/deep.py` |
| API awareness (OpenAPI/GraphQL) | ~ | ✓ | ✓ | ✓ `apispec/` + `webapi/` |
| Platform fingerprint → tailored tests | ~ | ~ | ~ | ✓ **`platforms/` (this doc)** |
| WAF/CDN/proxy detection (wafw00f-style) | ~ | ~ | ~ | ✓ **`netscan/waf.py`** (18 vendors, passive+active) |
| Port/service discovery + banner grab | ✓ | — | — | ✓ **`netscan/ports.py`** (bounded, in-scope) |
| Honeypot / IDS-IPS awareness | — | — | — | ✓ **`netscan/`** (tentative heuristics) |
| Cloud posture (CSPM) | ~ | — | — | ✓ `cloud/` |
| Container/K8s misconfig | ~ | — | — | ✓ `container/` |
| LLM/AI-system testing | — | — | — | ✓ `llm/` |
| AI reasoning / exploit chaining | — | ~ | — | ✓ `ai/` + `agentic/` |
| Grey-box telemetry correlation | — | — | — | ✓ `telemetry/` (`--observe`) |

`✓` solid · `~` partial · `—` not a focus.

## Where Deluluscan should invest next (research-backed)

1. **JS-aware crawler (ZAP AJAX-spider parity).** Modern SPAs hide most of their
   surface behind client-side routing; a headless-browser crawl would find
   endpoints the path-wordlist never sees. Highest-leverage gap. → extend `recon/`.
2. **Intruder-style attack-type matrix.** Generalize `--fuzz` into
   sniper/pitchfork/cluster-bomb position sets with a shared payload library, so
   multi-parameter logic/auth bugs become reachable. → new `deluluscan/fuzz/`.
3. **Plugin-style CVE corpus per platform.** The `platforms/` profiles already know
   the product; attach a data-driven, version-ranged CVE check set (Nessus's model)
   per profile, verified live before asserting. → extend `platforms/` + `kb/`.
4. **Passive-rule engine as a first-class pass.** A ZAP-like always-on passive
   analyzer over every response (not just the header module) — info leaks, verbose
   errors, mixed content, secret patterns — feeding low-severity, high-precision
   findings. → generalize `headers/` + `telemetry/signatures.py`.

## Methodology grounding

The workflow follows **PTES** (pre-engagement → intelligence gathering → threat
modeling → vuln analysis → exploitation → post-exploitation → reporting): the
`platforms/` module is *intelligence gathering + threat modeling* (know the system,
know which classes matter), feeding the existing scan/verify/report stages. Findings
map to **OWASP Top 10 / API Top 10** taxonomies (via `knowledge.py`), and the
exploit-chain agent's observe→act→verify loop mirrors **MITRE ATT&CK**-style
technique chaining — always gated by the differential verifier so nothing is
asserted without live proof.
