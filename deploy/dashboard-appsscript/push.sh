#!/usr/bin/env bash
# push.sh — regenerate the dashboard and publish it to the SSO-gated Apps Script
# web app. This is the "refresh after each scan" step.
#
# Usage:
#   ./deploy/dashboard-appsscript/push.sh [results.json]
#
# Env:
#   RESULTS   path to the scan results (default: deluluscan-out/results.json)
#   DEPLOY_ID existing deployment id -> update it in place so the URL is STABLE.
#             Without it, a new deployment (and a NEW url) is created; see README.
#
# No AES --password is used here on purpose: Google Workspace SSO is the
# boundary, so the report is served in plaintext to an already-authenticated
# company account. That is the whole point of moving off the public Pages copy.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
RESULTS="${1:-${RESULTS:-$ROOT/deluluscan-out/results.json}}"
CLASP="npx --yes @google/clasp"

[ -f "$RESULTS" ] || { echo "[!] results not found: $RESULTS" >&2; exit 1; }
[ -f "$HERE/.clasp.json" ] || {
    echo "[!] no .clasp.json here — run the one-time setup in README.md first" >&2
    exit 1
}

# The SSO gate lives in the manifest, and `clasp create-script` overwrites it
# with Google's starter file. Refuse to publish a report full of live findings
# unless the domain restriction is actually present.
grep -q '"access"[[:space:]]*:[[:space:]]*"DOMAIN"' "$HERE/appsscript.json" || {
    echo "[!] appsscript.json is missing  \"access\": \"DOMAIN\"  — refusing to deploy." >&2
    echo "    Without it the web app may be published without the Workspace login." >&2
    echo "    Restore it:  git checkout deploy/dashboard-appsscript/appsscript.json" >&2
    exit 1
}

echo "[1/3] generating the dashboard from $RESULTS"
python3 -m deluluscan.dashboard "$RESULTS" "$HERE/Index.html"
echo "      $(wc -c < "$HERE/Index.html") bytes -> Index.html (not committed: carries findings)"

# The sign-in page carries the real the target brand mark — that is what makes it
# read as legitimate rather than as a phishing prompt. Copy it from the single
# source of truth so it can never drift from the dashboard's own logo.
LOGO="$ROOT/dashboard/public/logo-dark.svg"
if [ -f "$LOGO" ]; then
    cp "$LOGO" "$HERE/Logo.html"
    echo "      brand mark -> Logo.html"
else
    printf '<span></span>\n' > "$HERE/Logo.html"
    echo "      [!] $LOGO missing — sign-in page will render without the logo" >&2
fi

echo "[2/3] pushing to the Apps Script project"
cd "$HERE"
$CLASP push --force

echo "[3/3] deploying"
# The deployment id IS the URL. Remember it after the first deploy so every
# later refresh updates the SAME link — otherwise each scan mints a new URL and
# the one you shared with the team quietly goes stale.
ID_FILE="$HERE/.deployment-id"
DEPLOY_ID="${DEPLOY_ID:-$(cat "$ID_FILE" 2>/dev/null || true)}"

if [ -n "$DEPLOY_ID" ]; then
    $CLASP create-deployment --deploymentId "$DEPLOY_ID" \
        --description "deluluscan $(date -u +%Y-%m-%dT%H:%MZ)"
else
    OUT="$($CLASP create-deployment --description "deluluscan $(date -u +%Y-%m-%dT%H:%MZ)" 2>&1)"
    echo "$OUT"
    DEPLOY_ID="$(printf '%s' "$OUT" | grep -oE 'AKfyc[A-Za-z0-9_-]+' | head -1)"
    [ -n "$DEPLOY_ID" ] && printf '%s\n' "$DEPLOY_ID" > "$ID_FILE" \
        && echo "      remembered deployment id -> .deployment-id (reused from now on)"
fi

if [ -n "$DEPLOY_ID" ]; then
    echo
    echo "done — live for signed-in the target accounts at:"
    echo "  https://script.google.com/macros/s/$DEPLOY_ID/exec"
fi
