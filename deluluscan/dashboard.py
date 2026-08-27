"""deluluscan.dashboard — enterprise vulnerability tracking dashboard.

Matches the VulnerabilityDashboard reference design:
  - #18186D primary brand (dark indigo)
  - 340px left sidebar with multi-section filters
  - Risk Index circular gauge + 5-column KPI severity cards
  - Charts row: Verification donut, Exploitability bars, Category bars
  - Findings table (checkbox | severity | title | category | exploit | conf | status)
  - Per-identity HTTP evidence viewer in detail drawer
  - Triage: Confirm/Dismiss + Status/Assignee selects → localStorage

Usage:
    python3 -m deluluscan.dashboard deluluscan-out/results.json deluluscan-out/dashboard.html
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import sys
import time

try:
    from .http_client import redact_headers as _redact_headers, redact_body as _redact_body
except Exception:  # dashboard can be run standalone; degrade gracefully
    def _redact_headers(h):
        return dict(h or {})

    def _redact_body(b):
        return b

def _required_tier(method, path):
    return 1  # generic default (product-specific entitlement model removed)

_SEV_RANK  = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# ---------------------------------------------------------------------------
# Data helpers
# ---------------------------------------------------------------------------

def _load(path: str) -> dict:
    with open(path) as f:
        data = json.load(f)
    if isinstance(data, list):
        return {"findings": data, "meta": {}}
    if "results" in data and "findings" not in data:
        data["findings"] = data.pop("results")
    data.setdefault("findings", [])
    data.setdefault("meta", {})
    return data


def _extract_version(scan: dict) -> str | None:
    for f in scan.get("findings", []):
        m = re.search(r"(\d+\.\d+[\.\d]*)", f.get("title", ""))
        if m and "fingerprint" in f.get("title", "").lower():
            return m.group(1)
    for det in scan.get("meta", {}).get("fingerprint", {}).get("detections", []):
        if det.get("tech") == "the target" and det.get("version"):
            return det["version"]
    return None


# NOTE: _status_resp_body() and _extract_identity_status() lived here. They
# existed only to fabricate evidence — inventing a response body for a guessed
# status code, and scraping a status code out of prose to attribute to an
# identity we may never have probed. Both are deleted; evidence comes from
# captured RequestRecords or it does not exist.


# OWASP Top 10 (2021) categorization. Maps a finding's vuln_class (with a few
# title/detail refinements) to the standard category, so the dashboard can group
# and label findings by OWASP Top 10 as the reviewer expects.
_OWASP_BY_CLASS = {
    "authz":          ("A01", "Broken Access Control"),
    "idor":           ("A01", "Broken Access Control"),
    "bopla":          ("A01", "Broken Access Control"),
    "crypto":         ("A02", "Cryptographic Failures"),
    "sqli":           ("A03", "Injection"),
    "xss":            ("A03", "Injection"),
    "ssti":           ("A03", "Injection"),
    "injection":      ("A03", "Injection"),
    "business_logic": ("A04", "Insecure Design"),
    "rate_limit":     ("A04", "Insecure Design"),
    "misconfig":      ("A05", "Security Misconfiguration"),
    "graphql":        ("A05", "Security Misconfiguration"),
    "error_handling": ("A05", "Security Misconfiguration"),
    "info_leak":      ("A05", "Security Misconfiguration"),
    "fingerprint":    ("A06", "Vulnerable and Outdated Components"),
    "supply_chain":   ("A08", "Software and Data Integrity Failures"),
    "inventory":      ("A09", "Security Logging and Monitoring Failures"),
    "ssrf":           ("A10", "Server-Side Request Forgery"),
}


def _owasp_category(vuln_class: str, title: str, detail: dict) -> dict:
    """Return {code, name} OWASP Top 10 (2021) category for a finding."""
    cls = (vuln_class or "").lower()
    t = (title or "").lower()
    # title/detail refinements that override the coarse class mapping
    if "cve" in t or detail.get("cve") or detail.get("kev") is not None:
        code, name = "A06", "Vulnerable and Outdated Components"
    elif cls == "info_leak" and any(k in t for k in
                                    ("password", "secret", "token", "key", "credential")):
        code, name = "A02", "Cryptographic Failures"   # sensitive-data exposure
    elif any(k in t for k in ("session fixation", "user enumeration", "brute",
                              "rate limit", "login", "authentication", "jwt", "token")) \
            and cls in ("authz", "misconfig", "rate_limit", "info_leak", "crypto"):
        code, name = "A07", "Identification and Authentication Failures"
    else:
        code, name = _OWASP_BY_CLASS.get(cls, ("A05", "Security Misconfiguration"))
    return {"code": code, "name": name}


def _normalize_evidence(findings: list) -> list:
    """Normalise the shape of captured evidence. Never invent any.

    1. Legacy records using body_snippet instead of resp_body → rename.
    2. Missing req/resp header fields → fill with empty defaults so
       renderEvHttp() always has something to iterate.
    3. Findings with no evidence stay with no evidence, flagged
       `evidence_missing` so the report can say so explicitly.

    Additionally assigns a stable string id to every finding that lacks one
    (or has a non-string id) so openDrawer()'s strict === match always works.

    (3) used to SYNTHESISE request/response records — guessing `backend: 200` /
    `anonymous: 401` for anything whose title merely contained "idor" or "bfla",
    with a fabricated body from _status_resp_body(). Those records rendered in the
    Evidence tab indistinguishably from real captured traffic, and buildAccessMatrix()
    read their invented status codes to conclude "privilege escalation". A report
    that manufactures the evidence for its own conclusions is worse than one with
    a gap in it, so the gap is now shown as a gap.
    """
    result = []
    for f in findings:
        f = dict(f)
        ev = f.get("evidence") or []

        if not ev:
            # No captured traffic. Say so — do not manufacture any.
            f["evidence_missing"] = True
        else:
            # ── Normalise existing evidence records ────────────────────────────
            normed = []
            for e in ev:
                if not isinstance(e, dict):
                    normed.append(e)
                    continue
                en = dict(e)
                # body_snippet is a legacy field name; rename it
                if "body_snippet" in en:
                    if "resp_body" not in en:
                        en["resp_body"] = en.pop("body_snippet")
                    else:
                        del en["body_snippet"]
                # Empty, not plausible-looking defaults: an invented
                # "User-Agent/Accept/Connection" trio on a record that captured no
                # headers is still fabricated evidence, just subtler.
                en.setdefault("req_headers", {})
                en.setdefault("req_body", None)
                en.setdefault("resp_headers", {})
                en.setdefault("resp_body", "")
                en.setdefault("resp_len", len(en["resp_body"] or ""))
                # Defense-in-depth: scrub credential values from headers AND
                # bodies even if the results.json was produced before
                # http_client redaction existed (older scans embedded live
                # JSESSIONID/JWT Set-Cookie values and issued-token JWTs in
                # response bodies). Never publish a dashboard with real tokens.
                en["req_headers"] = _redact_headers(en.get("req_headers"))
                en["resp_headers"] = _redact_headers(en.get("resp_headers"))
                en["req_body"] = _redact_body(en.get("req_body"))
                en["resp_body"] = _redact_body(en.get("resp_body"))
                normed.append(en)
            ev = normed

        f["evidence"] = ev

        # ── Annotate the endpoint's required privilege tier (0=public,1=back-end,
        # 3=admin) from the target entitlement model, so the access matrix can
        # judge each identity's access as expected-vs-violation by tier. ────────
        ep = f.get("endpoint") or ""
        method, _, path = ep.partition(" ")
        if not path:
            method, path = "GET", ep
        try:
            f["required_tier"] = _required_tier(method, path)
        except Exception:
            f["required_tier"] = 1

        # ── OWASP Top 10 (2021) categorization ─────────────────────────────────
        f["owasp"] = _owasp_category(f.get("vuln_class", ""), f.get("title", ""),
                                     f.get("detail") or {})

        # ── Hoist the evidence-derived report block to the top level ──────────
        # deluluscan.reporting.attach_reports() writes the derived report under
        # detail["report"], but every renderer (renderReport, buildMarkdown,
        # remediationPlan) reads f.report. Without this hoist a scan-produced
        # finding rendered ONLY the "What was tested" section — and that from the
        # plain description fallback — leaving Where / How / Steps /
        # Reproduction / Outcome / Impact / Remediation blank, even though all
        # eight sections had been generated from real captured evidence.
        det = f.get("detail") or {}
        if not f.get("report") and isinstance(det.get("report"), dict):
            f["report"] = det["report"]
        # A hand-authored partial block must not mask the derived one: merge the
        # derived sections underneath whatever was set explicitly.
        elif isinstance(f.get("report"), dict) and isinstance(det.get("report"), dict):
            merged = dict(det["report"])
            merged.update({k: v for k, v in f["report"].items() if v})
            f["report"] = merged

        # ── Assign a stable string id ──────────────────────────────────────────
        fid = f.get("id")
        if fid is None or not isinstance(fid, str) or fid == "":
            raw = f"{len(result)}:{f.get('endpoint', '')}:{f.get('title', '')}"
            f["id"] = f"f{len(result):04d}_{hashlib.md5(raw.encode()).hexdigest()[:8]}"

        result.append(f)
    return result


# NOTE: there was an _augment_evidence() here. For any finding lacking an admin
# record it INVENTED one — status, response body, resp_len, and an elapsed_ms
# back-computed as anon.elapsed_ms * 0.9 to look measured. That synthetic record
# was prepended to the evidence list, rendered as real captured traffic, and read
# by buildAccessMatrix() as a genuine "admin was granted" observation.
#
# It is deleted rather than fixed: there is no correct way to guess what an
# identity we never probed would have received. Findings that lack an identity's
# record now simply lack it, and the access matrix shows that column as untested.


def _digest(findings: list) -> str:
    """Content fingerprint for a set of findings, used to dedupe history snapshots."""
    blob = json.dumps(findings, sort_keys=True, default=str).encode()
    return hashlib.sha1(blob).hexdigest()[:12]


def _history_dir(src_path: str) -> str:
    return os.path.join(os.path.dirname(os.path.abspath(src_path)) or ".", "history")


def _archive_snapshot(src_path: str, snapshot: dict, digest: str) -> None:
    """Persist this scan's findings under history/ so a later, different scan
    can list it as a real past run. No-op if this exact content is already
    archived (keeps re-running the dashboard on unchanged results.json from
    piling up duplicate history entries)."""
    hist_dir = _history_dir(src_path)
    try:
        os.makedirs(hist_dir, exist_ok=True)
        if any(fn.endswith(f"_{digest}.json") for fn in os.listdir(hist_dir)):
            return
        mtime = os.path.getmtime(src_path) if os.path.exists(src_path) else time.time()
        stamp = datetime.datetime.fromtimestamp(mtime, datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = os.path.join(hist_dir, f"{stamp}_{digest}.json")
        with open(path, "w") as fh:
            json.dump(snapshot, fh, default=str)
    except OSError:
        pass  # history is a convenience, not load-bearing — never fail the render over it


def _load_history(src_path: str, exclude_digest: str) -> list[tuple[str, dict]]:
    """Real past scan snapshots (newest first), skipping the one matching the
    current run so it isn't listed twice."""
    hist_dir = _history_dir(src_path)
    entries = []
    if not os.path.isdir(hist_dir):
        return entries
    for fname in sorted(os.listdir(hist_dir), reverse=True):
        if not fname.endswith(".json"):
            continue
        digest = fname[:-len(".json")].split("_")[-1]
        if digest == exclude_digest:
            continue
        try:
            with open(os.path.join(hist_dir, fname)) as fh:
                entries.append((fname, json.load(fh)))
        except (OSError, json.JSONDecodeError):
            continue
    return entries


def _build_scans(result: dict, src_path: str | None = None) -> list[dict]:
    version  = _extract_version(result) or "unknown"
    target   = result.get("meta", {}).get("target", "https://127.0.0.1:8443")
    meta     = result.get("meta", {})
    enriched = _normalize_evidence(result.get("findings", []))
    digest   = _digest(enriched)

    # The "current" scan label always reflects the dashboard generation date so
    # it updates every time the report is regenerated.
    scan_date = datetime.date.today().isoformat()

    scans = [{
        "id": "scan_current",
        "label": f"{scan_date}  —  the target v{version}  (latest)",
        "date": f"{scan_date}T12:00:00Z",
        "version": version, "target": target,
        "findings": enriched, "meta": meta,
        "identities": list(meta.get("identities", {}).keys()),
    }]

    if src_path:
        _archive_snapshot(src_path, {"findings": enriched, "meta": meta}, digest)
        for fname, hs in _load_history(src_path, digest):
            hm = hs.get("meta", {}) or {}
            hv = _extract_version(hs) or version
            stamp = fname.split("_")[0]
            try:
                d = datetime.datetime.strptime(stamp, "%Y%m%dT%H%M%SZ")
                label_date, iso = d.strftime("%Y-%m-%d"), d.isoformat() + "Z"
            except ValueError:
                label_date, iso = stamp, ""
            # Re-normalise (and redact headers on) archived findings: older
            # snapshots on disk may predate secret-redaction and still carry
            # live Set-Cookie/JWT values. Never let history reintroduce a leak.
            hist_findings = _normalize_evidence(hs.get("findings", []))
            hids = list(hm.get("identities", {}).keys()) or sorted({
                e.get("identity") for f in hist_findings for e in f.get("evidence", [])
                if e.get("identity")
            })
            scans.append({
                "id": f"scan_hist_{fname}",
                "label": f"{label_date}  —  the target v{hv}",
                "date": iso, "version": hv,
                "target": hm.get("target", target),
                "findings": hist_findings, "meta": hm,
                "identities": hids,
            })
    return scans


# ---------------------------------------------------------------------------
# Rendering shell
# ---------------------------------------------------------------------------
#
# The report UI is the React/TypeScript app in dashboard/, built by Vite into ONE
# self-contained HTML file (dashboard/dist/index.html) and vendored here as
# deluluscan/assets/dashboard_bundle.html. Python injects the scan payload at the
# /*__DATA__*/ marker; it renders no markup itself.
#
# Vendored rather than built on demand because a scan must not require a Node
# toolchain: `python3 -m deluluscan.dashboard results.json out.html` has to work on a
# machine that has never seen npm. Rebuild with `cd dashboard && npm run build`
# and copy dist/index.html over the asset (scripts/build_dashboard.sh does both).

_BUNDLE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "assets", "dashboard_bundle.html")
_DATA_MARKER = "/*__DATA__*/"


def _load_bundle() -> str:
    try:
        with open(_BUNDLE_PATH, encoding="utf-8") as fh:
            shell = fh.read()
    except OSError as exc:
        raise SystemExit(
            f"[abort] dashboard bundle missing at {_BUNDLE_PATH}: {exc}\n"
            "        Rebuild it with: ./scripts/build_dashboard.sh") from exc
    if _DATA_MARKER not in shell:
        raise SystemExit(
            f"[abort] dashboard bundle at {_BUNDLE_PATH} has no {_DATA_MARKER} "
            "injection marker, so the scan payload cannot be embedded. "
            "Rebuild it with: ./scripts/build_dashboard.sh")
    return shell


# Read once at import. Kept under the historical name because the test suite and
# --rekey both reason about the shell's text.
_TMPL = _load_bundle()


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------

def _js_safe(s: str) -> str:
    """Neutralise the sequences that let embedded JSON break out of the <script>
    element or the JS parser: `<` (so `</script>` can't close the tag) and the
    U+2028/U+2029 line separators (illegal in JS string literals). The result is
    still valid JSON — these become \\u-escapes inside string values."""
    return (s.replace("<", "\\u003c")
             .replace(" ", "\\u2028")
             .replace(" ", "\\u2029"))


# The dashboard is a public, offline-brute-forceable file, so the passphrase is
# the real boundary — require a long, complex one (>=50 chars, all char classes).
_MIN_PW, _MAX_PW = 50, 128
_PW_SPECIAL = "!@#$%^&*()-_=+[]{};:,.?"


def _validate_password(pw: str) -> None:
    """Raise ValueError unless the password is 50–128 chars and includes an
    uppercase letter, a lowercase letter, a digit, and a special character."""
    pw = pw or ""
    n = len(pw)
    if n < _MIN_PW or n > _MAX_PW:
        raise ValueError(f"dashboard password must be {_MIN_PW}–{_MAX_PW} characters "
                         f"(got {n}). Use --generate-password to make a compliant one.")
    missing = []
    if not any(c.isupper() for c in pw):            missing.append("uppercase letter")
    if not any(c.islower() for c in pw):            missing.append("lowercase letter")
    if not any(c.isdigit() for c in pw):            missing.append("digit")
    if not any(c in _PW_SPECIAL for c in pw):       missing.append("special character")
    if missing:
        raise ValueError("dashboard password must include a " + ", a ".join(missing)
                         + ". Use --generate-password to make a compliant one.")


def generate_password(length: int = 60) -> str:
    """Generate a strong password (default 60 chars) guaranteed to satisfy the
    complexity policy: >=50 chars with upper, lower, digit and special classes.
    Uses an unambiguous alphabet (no O/0/l/1/I) plus a safe special set."""
    import secrets
    length = max(_MIN_PW, min(_MAX_PW, length))
    upper = "ABCDEFGHJKMNPQRSTUVWXYZ"
    lower = "abcdefghijkmnpqrstuvwxyz"
    digit = "23456789"
    alphabet = upper + lower + digit + _PW_SPECIAL
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        try:
            _validate_password(pw)
            return pw
        except ValueError:
            continue  # regenerate until every required class is present


def _encrypt_payload(plaintext: str, password: str) -> dict:
    """Encrypt the findings payload with AES-256-GCM under a key derived from
    `password` via PBKDF2-HMAC-SHA256. The browser decrypts it with Web Crypto
    using the same parameters, so the plaintext never exists in the file until
    the correct password is entered (a wrong password fails the GCM auth tag).
    This protects confidentiality of the report at rest; it is brute-forceable
    offline, so a strong passphrase and a private repo remain the real boundary."""
    import base64
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    _validate_password(password)
    iters = 210_000
    salt = os.urandom(16)
    iv = os.urandom(12)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=iters).derive(password.encode())
    ct = AESGCM(key).encrypt(iv, plaintext.encode(), None)   # tag appended
    b64 = lambda b: base64.b64encode(b).decode()
    return {"v": 1, "iter": iters, "salt": b64(salt), "iv": b64(iv), "ct": b64(ct)}


def _decrypt_payload(blob: dict, password: str) -> str:
    """Decrypt an __ENC__ blob (inverse of _encrypt_payload). Used to rotate the
    password on an already-published dashboard without re-running a scan."""
    import base64
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    d = base64.b64decode
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=d(blob["salt"]),
                     iterations=blob.get("iter", 210_000)).derive(password.encode())
    return AESGCM(key).decrypt(d(blob["iv"]), d(blob["ct"]), None).decode()


def rekey_dashboard(path: str, old_password: str, new_password: str) -> None:
    """Change the password on an existing encrypted dashboard file in place:
    decrypt the payload with the old password and re-encrypt with the new one.
    Nothing else in the file changes. Raises on a wrong old password or a
    non-compliant new password."""
    _validate_password(new_password)
    html = open(path, encoding="utf-8").read()
    m = re.search(r"var __ENC__=(\{.*?\});", html)
    if not m or "var SCANS=null" not in html:
        raise ValueError(f"{path} is not a password-protected dashboard (no __ENC__ payload)")
    blob = json.loads(m.group(1))
    plaintext = _decrypt_payload(blob, old_password)   # raises if old password wrong
    new_blob = _encrypt_payload(plaintext, new_password)
    html = html.replace(m.group(0), f"var __ENC__={json.dumps(new_blob)};", 1)
    open(path, "w", encoding="utf-8").write(html)


def build_html(result: dict, src_path: str | None = None,
               password: str | None = None) -> str:
    """Render the dashboard. Pass src_path (the results.json this `result` was
    loaded from) to enable real scan-history browsing — each distinct scan
    gets archived under history/ next to it, and prior archives are folded
    back in as browsable past scans. Without src_path (e.g. in unit tests),
    only the current scan is rendered.

    If `password` is given, the findings payload is AES-GCM encrypted and the
    page prompts for the password to decrypt in-browser; otherwise it is
    embedded in plaintext (with `<`/line-separator escaping to prevent a
    </script> breakout)."""
    scans      = _build_scans(result, src_path)
    scans_json = json.dumps(scans, ensure_ascii=False, separators=(",", ":"))
    if password:
        blob = _encrypt_payload(scans_json, password)
        data_js = f"var SCANS=null; var __ENC__={json.dumps(blob)};"
    else:
        data_js = f"var SCANS={_js_safe(scans_json)}; var __ENC__=null;"
    return _TMPL.replace("/*__DATA__*/", data_js)


def main(argv=None):
    import argparse
    p = argparse.ArgumentParser(description="Generate (or re-key) the Deluluscan dashboard.")
    p.add_argument("src", nargs="?", help="results.json (omit when using --rekey)")
    p.add_argument("out", nargs="?", default="dashboard.html", help="output HTML path")
    p.add_argument("--password", help="encrypt with this password (AES-GCM); "
                   "must be 50-128 chars incl. upper/lower/digit/special. Overrides $DELULUSCAN_DASHBOARD_PASSWORD.")
    p.add_argument("--generate-password", action="store_true",
                   help="generate a strong 50+ char password (all char classes), use it, and print it")
    p.add_argument("--rekey", metavar="DASHBOARD.html",
                   help="change the password on an existing dashboard in place "
                        "(decrypt with --old-password, re-encrypt with the new one). "
                        "No re-scan needed.")
    p.add_argument("--old-password", help="current password (for --rekey); "
                   "overrides $DELULUSCAN_DASHBOARD_OLD_PASSWORD")
    args = p.parse_args(argv if argv is not None else sys.argv[1:])

    # ---- change-password (rotate) mode -------------------------------------
    if args.rekey:
        old = args.old_password or os.environ.get("DELULUSCAN_DASHBOARD_OLD_PASSWORD")
        if not old:
            print("--rekey needs --old-password (or $DELULUSCAN_DASHBOARD_OLD_PASSWORD)")
            return 1
        new = args.password or os.environ.get("DELULUSCAN_DASHBOARD_PASSWORD")
        if args.generate_password:
            new = generate_password()
        if not new:
            print("--rekey needs a new --password (50-128 chars, all char classes) or --generate-password")
            return 1
        try:
            _validate_password(new)
            rekey_dashboard(args.rekey, old, new)
        except ValueError as exc:
            print(f"rekey failed: {exc}"); return 1
        except Exception:
            print("rekey failed: could not decrypt with the old password "
                  "(is --old-password correct?)"); return 1
        print(f"password changed on {args.rekey}")
        if args.generate_password:
            print(f"  NEW PASSWORD: {new}\n  (store it in the team vault; it is NOT saved anywhere else)")
        return 0

    # ---- generate mode ------------------------------------------------------
    if not args.src:
        print("usage: python -m deluluscan.dashboard <results.json> [out.html] [--password ... | --generate-password]")
        return 1
    password = args.password or os.environ.get("DELULUSCAN_DASHBOARD_PASSWORD") or None
    if args.generate_password:
        password = generate_password()
    if password is not None:
        try:
            _validate_password(password)
        except ValueError as exc:
            print(f"error: {exc}"); return 1
    try:
        result = _load(args.src)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"cannot read {args.src}: {exc}")
        return 1
    open(args.out, "w").write(build_html(result, src_path=args.src, password=password))
    print(f"wrote {args.out}" + ("  (password-protected, AES-GCM)" if password else ""))
    if args.generate_password:
        print(f"  PASSWORD: {password}\n  (store it in the team vault; it is NOT saved anywhere else)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
