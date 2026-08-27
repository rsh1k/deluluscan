# Deluluscan dashboard behind Google Workspace SSO (Apps Script)

Serve the dashboard from a Google Apps Script web app behind **three** gates,
all enforced server-side before a single byte of the report is sent:

| Layer | What it does |
|---|---|
| **1. SSO** | `access: DOMAIN` — Google demands a target Workspace login before the script runs |
| **2. Allowlist** | being in the domain isn't enough; the address must be in `ALLOWED_EMAILS` |
| **3. OTP** | a 6-digit code is emailed and must be entered; good for `SESSION_HOURS` |

Everything **fails closed** — if the viewer's identity can't be determined,
access is refused. `getDashboardHtml()` re-checks all three layers, so the gate
page is UI, not the control.

## Entry point

`https://target.github.io/deluluscan/dashboard.html` is a **public redirect stub**
(no findings in it) that forwards to the SSO-gated app — so the memorable URL
still works. The real link is in `.deployment-id`.

## Managing who has access

Add or remove people **without a redeploy**: Apps Script editor → **Project
Settings → Script Properties** →

```
ALLOWED_EMAILS = rashik.adhikari@example.com, mehdi.karimi@example.com
```

Takes effect on the next page load. If that property is unset, the
`DEFAULT_ALLOWED` list in `Code.gs` applies. Run `showAllowlist()` from the
editor to print who is currently authorised.

> **On the emailed OTP, honestly:** it is a real second step and it creates an
> alerting trail ("someone opened the security report"), but because the code is
> delivered to the same Google mailbox that the SSO session already unlocks, it
> adds little against a *compromised Google account*. The strong control for
> that is enforcing 2-Step Verification in Google Workspace Admin (TOTP or a
> security key). Use both; don't treat the OTP as a substitute.

---

Original design note — Google forces a company Workspace login *before* the
page is served, so:

* access is **per-person identity**, not a shared passphrase — it dies when the
  Google account is suspended, with no secret to rotate;
* you get an **audit trail** of who opened the report (Apps Script → Executions);
* **no GCP project, no billing account, no credit card, no container, no DNS.**

Everything lives in this repo. Nothing is required from another team.

> **Why not just gate the existing GitHub Pages copy?** You can't. On the `team`
> plan a Pages site published from a private repo is *always public* (private
> Pages is Enterprise-Cloud only), and a proxy in front doesn't help either:
> Pages serves from public anycast IPs keyed on the `Host` header, so
> `curl --resolve yourdomain:443:185.199.108.153 https://yourdomain/` returns the
> content without ever touching the proxy. The file has to move; that is what
> this package does.

---

## One-time setup (~10 minutes)

**1. Enable the Apps Script API** for your account (one click, once ever):
<https://script.google.com/home/usersettings> → turn **Google Apps Script API** ON.

**2. Log in with your target Google account:**

```bash
npx --yes @google/clasp login
```

**3. Create the project** (run from this folder):

```bash
cd deploy/dashboard-appsscript
npx --yes @google/clasp create-script --type standalone --title "Deluluscan Security Dashboard" --rootDir .
```

That writes a local `.clasp.json` (git-ignored — it holds your scriptId).

> **`--type webapp` does not exist in clasp 3.x** (its own `--help` text is stale).
> Valid values are `standalone` (default), `docs`, `forms`, `sheets`, `slides`.
> This is fine: the web-app behaviour comes entirely from the `webapp` block in
> `appsscript.json`, not from the project type.

**3a. Restore the two files clasp just clobbered.** After creating the project,
clasp *pulls* Google's starter files, overwriting the local `Code.gs` and
`appsscript.json` — including the `access: DOMAIN` gate. Both are committed, so:

```bash
cd ../.. && git checkout deploy/dashboard-appsscript/Code.gs \
                        deploy/dashboard-appsscript/appsscript.json
```

Verify the gate survived before deploying:

```bash
grep -A3 '"webapp"' deploy/dashboard-appsscript/appsscript.json   # must show "access": "DOMAIN"
```

**4. Publish:**

```bash
./push.sh
```

**5. Lock the access setting.** Open the project (`npx --yes @google/clasp open-script`)
→ **Deploy → Manage deployments → ✏️ → Web app** and confirm:

| Setting | Value |
|---|---|
| Execute as | **Me** (your target account) |
| Who has access | **Anyone within the target** ← *this is the SSO gate* |

Never set this to "Anyone" — that publishes the findings to the internet.

**6. The URL is already stable.** On the first deploy `push.sh` records the
deployment id in `.deployment-id` (git-ignored) and reuses it forever, so every
later refresh updates the **same link** instead of minting a new one. Override
with `DEPLOY_ID=...` only if you deliberately want a different deployment.

Verify the gate yourself — an anonymous request must never see the report:

```bash
curl -s -o /dev/null -w '%{http_code} -> %{redirect_url}\n' \
  "https://script.google.com/macros/s/$(cat deploy/dashboard-appsscript/.deployment-id)/exec"
# expect: 302 -> https://accounts.google.com/ServiceLogin?...
```

---

## Refresh after each scan

```bash
./deploy/dashboard-appsscript/push.sh deluluscan-out/results.json
```

Regenerates the report from the scan and updates the same URL. Share that link
with the team — anyone signed in with a target Google account sees it; anyone
else gets Google's login wall.

**Optional:** add the link as a tile in the Google apps launcher (the ⋮⋮⋮ grid
next to Gmail) via Admin console → Apps → Web and mobile apps, so people find it
where they expect.

---

## Known limitations (test these first)

Apps Script renders the page inside a **sandboxed iframe**. Verify these after
your first deploy; if any is a dealbreaker, the fallback with identical login UX
is Cloud Run + IAP.

| Feature | Risk |
|---|---|
| **Saved triage / report / attestation edits** | Uses `localStorage`. Browsers partition third-party storage, and the iframe origin differs from the top page, so persistence *may* not survive a reload. The code fails soft — edits work in-session and simply don't persist. **Test this.** |
| **Print / PDF export** | `window.print()` from inside an iframe can behave differently per browser. |
| **Deep links** (`#findings/<id>`) | Hash routing works inside the frame, but the outer URL won't carry the fragment, so a copied link lands on the default tab. |
| **File size** | 444 KB inline. Google documents no hard `HtmlService` cap; this is comfortably within observed practice, but it is untested rather than certified. |

## Files

| File | Purpose |
|---|---|
| `Code.gs` | `doGet()` serves `Index.html`; logs the viewer's email for audit |
| `appsscript.json` | Manifest — `access: DOMAIN` is the SSO gate |
| `push.sh` | Generate the dashboard → `clasp push` → deploy |
| `.claspignore` | Only `Code.gs` / `appsscript.json` / `Index.html` reach Google |
| `Index.html` | **Generated, never committed** — it carries live findings |

## After this is working

Retire the public GitHub Pages copy, or the SSO front door is decorative while
the back door stays open — `docs/dashboard.html` is currently served to the
whole internet. That touches `docs/dashboard.html`, `.github/workflows/nightly-scan.yml`,
`scripts/store_dashboard_password.sh`, and `scripts/rotate_dashboard_password.sh`.
