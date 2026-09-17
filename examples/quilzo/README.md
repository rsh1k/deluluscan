# Testing Quilzo with Deluluscan

A reusable harness for pentesting [Quilzo](https://github.com/Quilzo/Quilzo) — a
security-hardened Go CMS — with Deluluscan. Deluluscan already **fingerprints
Quilzo** (see `deluluscan/platforms/profiles.py`), so it recognizes the target and
knows its shape automatically. This directory adds the turnkey stand-up and the
route spec the arsenal needs.

## Quick start

```bash
./setup_quilzo.sh          # builds the image, provisions a demo store + identities,
                           # starts admin (127.0.0.1:9080) and site (127.0.0.1:9081)

# fingerprint (Deluluscan recognizes Quilzo on its own)
python3 -m deluluscan.platforms --url http://127.0.0.1:9080

# deep, multi-identity scan seeded with Quilzo's real routes
python3 -m deluluscan.cli --config config.quilzo.yaml \
    --openapi-file quilzo_openapi.json \
    --observe --observe-container quilzo_admin

# tear down
docker rm -f quilzo_admin quilzo_site && docker volume rm quilzo_store quilzo_tpl
```

`setup_quilzo.sh` writes `config.quilzo.yaml` (with fresh tokens) and `tokens.txt`.

## How Quilzo works (what to test, and what not to)

Quilzo removes whole vulnerability classes **by construction**, so a scan should
spend its effort where the real risk is — access control — not on injection.

| Property | Consequence for testing |
|----------|-------------------------|
| Content is immutable + content-addressed; publishing moves a pointer | No IDOR by incrementing id; no write-then-execute |
| No query language over content (page lookups are keyed) | **No SQLi surface** — do not chase it |
| Non-executing template language | **No SSTI**; content fields are HTML-escaped on render |
| Bearer-token auth only (no passwords) | No credential stuffing / reset abuse; test **token** security instead |
| Public site sets `script-src 'none'` | Even a stored payload cannot execute — XSS is doubly mitigated |

### Surfaces & auth model

- **Admin** (`:8080`): the sensitive interface. ~125 routes; every write consults a
  role gate. Sign-in is pasting a bearer token (`qz_…`) or the `quilzo_token`
  cookie (`HttpOnly; SameSite=Strict; Secure` under TLS).
- **Public site** (`:8081`): serves published HTML anonymously; its `/api/v1` content
  API is **token-gated** (anon → 401 by design). Read-only unless `--api-writable`.
- **Telegram Mini App** (`:8082`): authenticates launches via `initData` HMAC.
- **Roles:** `reader → author → publisher → admin`, narrowable with `--read-only`
  and `--on <path>` (scope). Content-type edits require **publisher, not author**.
- **JSON API:** `/api/v1/pages`, `/collections`, `/records/{id}`,
  `/replica/object/{id}`, `/replica/ref/{ref}`, `/search/vector`, `/similar/{id}`,
  and `/graphql` (off by default).

### The controls to verify (defense in depth)

1. **RBAC / BFLA matrix** — every admin-only write must 403 for reader/author/publisher.
2. **Token narrowing** — `--read-only` refuses all writes; `--on /blog` refuses action outside `/blog`.
3. **CSRF** — `SameSite=Strict` cookie + a `Sec-Fetch-Site`/`Origin` middleware.
4. **SSRF** — the `media get` fetch: HTTPS-only + IP denylist (loopback/private/link-local/metadata) + connect-time recheck (DNS-rebinding).
5. **Auth throttle** — 5 free failures then exponential backoff, per source (this will rate-limit anonymous probing — see below).
6. **Passkey (WebAuthn)** — server-side single-use expiring challenges; constant-time compares; origin/RP-ID/type binding; clone-detection counter.
7. **OIDC** — algorithm taken from provider discovery (defeats `alg:none`/HS256 confusion); state (CSRF) single-use; PKCE verifier server-side.
8. **Integrity gates** — provenance + a11y gates refuse a bad publish; audit log (SIEM export) records every action.

A prior full assessment found **no exploitable vulnerability** against these
controls; see `Quilzo-Pentest-Report.md` from that engagement for the evidence.

## Notes & gotchas

- **The auth throttle will rate-limit the scanner.** Anonymous/bad-credential probes
  hit `429` after 5 failures (per source), which can mask surface and confuse
  content-discovery (a `429` is not a real endpoint). Prefer **authenticated** testing
  (valid tokens don't count as failures); restart `quilzo_admin` to clear the
  in-memory limiter between passes. This is a *control working*, not a bug.
- **Test-fixture secrets:** `internal/**/**_test.go` contains fake AWS/GitHub keys
  (`AKIAIOSFODNN7EXAMPLE`, etc.) that exercise Quilzo's own secret scanner — a
  secrets scan will flag them; they are not real credentials.
- **Passkeys need a hostname, not an IP.** Use `Host: localhost:<port>` for the
  WebAuthn flows (RP ID = `localhost`); a bare IP is refused (browsers reject it).
- **OIDC discovery goes through the SSRF guard**, so a mock IdP on a private/loopback
  address is refused — use a public issuer or adjust egress policy for that host.
- Writes create drafts (immutable model), so `allow_state_changing: true` is safe on
  a throwaway local store and unlocks the mass-assignment / race probes.
