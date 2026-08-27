# Contributing to Deluluscan

First off — **thank you** for considering a contribution. Deluluscan is an
open-source, AI-augmented, evidence-first security auditor, and it gets better
every time someone adds a platform signature, a detection rule, a known CVE, or a
scanner. Contributions of all sizes are welcome, from a one-line signature to a
whole new module.

New here? Issues labelled [`good first issue`](https://github.com/rsh1k/deluluscan/labels/good%20first%20issue)
and [`help wanted`](https://github.com/rsh1k/deluluscan/labels/help%20wanted) are
a great place to start.

By participating, you're expected to uphold our
[Code of Conduct](CODE_OF_CONDUCT.md).

## Ground rules (non-negotiable)

Deluluscan is a **defensive / authorized-testing** tool. Every contribution must
keep that true:

1. **Authorization boundary stays.** The scope gate (loopback / RFC1918 only,
   unless the operator explicitly asserts authorization) is a feature, not a
   limitation — don't remove or weaken it.
2. **Detection, not weaponization.** We *confirm to proof, then report*. No
   exfiltration, no persistence, no DoS, no destructive payloads. Heavy
   exploitation is delegated to opt-in, host-allowlisted third-party tools.
3. **Evidence-first.** A finding is only asserted after a live re-test; the report
   may only state what the scan observed. Don't synthesize evidence or hard-code a
   verdict.
4. **No real targets or third-party data** in code, tests, fixtures, comments, or
   commit messages. Use neutral, synthetic examples.

Contributions that turn Deluluscan into an attack framework, add mass/unauthorized
targeting, or bypass the safety gate will be declined.

## The easiest wins are just data

A lot of the tool is **data-driven** — you can extend it without touching engine
logic:

| Want to add… | Edit | Shape |
|---|---|---|
| A platform to fingerprint | `deluluscan/platforms/profiles.py` | append a `PlatformProfile` |
| A known CVE for a platform | `deluluscan/platforms/cves.py` | append a `CveRule` |
| A WAF/CDN/edge vendor | `deluluscan/netscan/signatures.py` | append an `EdgeSig` |
| A passive-analysis rule | `deluluscan/passive/rules.py` | append a `PassiveRule` |
| A tech/JS-library fingerprint | `deluluscan/recon/signatures.py` | append to `TECH_SIGS` |
| A Nuclei-style YAML template | `templates/` | drop in a `.yaml`, no code |

Each of these ships with a test file — add a case that proves your entry fires.

## Development setup

```bash
git clone https://github.com/rsh1k/deluluscan && cd deluluscan
pip install -r requirements.txt --break-system-packages
pip install -e . --break-system-packages
```

Optional extras: `pip install "deluluscan[all]"` (Bedrock, FastAPI UI, XLSX export,
and the Playwright crawler — the crawler also needs `playwright install chromium`).

### Running tests

Tests are self-contained and run offline (every network/browser boundary is
dependency-injected):

```bash
python3 -m tests.test_platforms      # one suite
python3 -m tests.test_netscan
# … run the suite(s) relevant to what you changed
```

Please run the suite for any area you touch, and add tests for new behaviour.
Offline-testability is a hard requirement: inject the `fetch` / `connect` /
driver rather than reaching the network in a test.

### The dashboard (React UI)

If you change anything under `dashboard/src`, rebuild the vendored asset and
commit it:

```bash
cd dashboard && npm install && npm test      # vitest/jsdom
cd .. && ./scripts/build_dashboard.sh         # regenerates deluluscan/assets/dashboard_bundle.html
```

`./scripts/build_dashboard.sh --check` fails if the committed asset is stale.

## Submitting a change

1. **Fork** and create a branch (`git checkout -b my-feature`).
2. Make your change; keep it focused. Match the surrounding code's style, comment
   density, and naming.
3. **Add or update tests** and run the relevant suites — everything green.
4. Write a clear commit message explaining the *why*.
5. Open a **pull request** describing what changed and how you verified it. Link
   any related issue.

We review with an eye to: correctness, false-positive discipline (does a finding
survive a live re-test?), test coverage, and the ground rules above.

## Reporting bugs & requesting features

- **Bugs / features:** open a [GitHub issue](https://github.com/rsh1k/deluluscan/issues)
  using the templates.
- **Security vulnerabilities in Deluluscan itself:** please do **not** open a
  public issue — see [SECURITY.md](SECURITY.md) for responsible disclosure.

## License

By contributing, you agree that your contributions are licensed under the project's
**GNU Affero General Public License v3.0** ([LICENSE](LICENSE)).

Thanks again — happy (authorized) hacking. 🛡️
