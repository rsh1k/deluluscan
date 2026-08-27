#!/usr/bin/env bash
# rotate_dashboard_password.sh — change the published dashboard's password.
#
# Anyone with the CURRENT password + repo push access can rotate it. It decrypts
# docs/dashboard.html with the old password and re-encrypts with a new one
# (50-128 chars, incl. upper/lower/digit/special — enforced by deluluscan.dashboard)
# IN PLACE — no re-scan needed — then commits and pushes so GitHub Pages rebuilds.
#
# Passwords are read from STDIN or the environment, never argv: an argument would
# be visible in `ps` and in shell history for every user on the box. (This is the
# same rule scripts/store_dashboard_password.sh already follows.)
#
# Usage:
#   # generate the new password (recommended):
#   ./scripts/rotate_dashboard_password.sh            # prompts for the current one
#
#   # supply your own:
#   DELULUSCAN_DASHBOARD_OLD_PASSWORD=... DELULUSCAN_DASHBOARD_PASSWORD=... \
#     ./scripts/rotate_dashboard_password.sh
#
# Store the new password in the team vault (1Password / target-vault) — it is
# NOT saved in the repo or anywhere else.
set -euo pipefail

DASH="docs/dashboard.html"
[ -f "$DASH" ] || { echo "[!] $DASH not found (run from the repo root)"; exit 1; }

if [ "$#" -gt 0 ]; then
    echo "[!] refusing to take passwords as arguments — they leak via \`ps\` and shell history." >&2
    echo "    Run with no arguments to be prompted, or export DELULUSCAN_DASHBOARD_OLD_PASSWORD" >&2
    echo "    (and optionally DELULUSCAN_DASHBOARD_PASSWORD) instead." >&2
    exit 2
fi

OLD="${DELULUSCAN_DASHBOARD_OLD_PASSWORD:-}"
if [ -z "$OLD" ]; then
    read -r -s -p "Current dashboard password: " OLD; echo
fi
[ -n "$OLD" ] || { echo "[!] no current password given"; exit 1; }
export DELULUSCAN_DASHBOARD_OLD_PASSWORD="$OLD"

NEW="${DELULUSCAN_DASHBOARD_PASSWORD:-}"
if [ -n "$NEW" ]; then
    # Passed via env by deluluscan.dashboard's own $DELULUSCAN_DASHBOARD_PASSWORD lookup.
    python3 -m deluluscan.dashboard --rekey "$DASH"
else
    OUT=$(python3 -m deluluscan.dashboard --rekey "$DASH" --generate-password)
    echo "$OUT"
fi
unset DELULUSCAN_DASHBOARD_OLD_PASSWORD

git add "$DASH"
git commit -m "chore: rotate dashboard password"
git push
echo ""
echo "[*] Rotated and pushed. GitHub Pages rebuilds in ~30s."
echo "[*] Put the new password in the team vault so authorized viewers can find it."
