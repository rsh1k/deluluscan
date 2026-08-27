#!/usr/bin/env bash
# store_dashboard_password.sh — stash a Deluluscan dashboard passphrase in Bitwarden
# and print ONLY a reference to it (id|name) on stdout — never the value.
#
# The passphrase is read from STDIN (so it never lands in argv / `ps` / shell
# history). Requires the `bw` CLI, already unlocked, with the session key in
# ~/.config/deluluscan/bw-session (0600). Pairs with the Slack-ping step that the
# caller runs on the printed reference.
#
#   python3 -m deluluscan.dashboard ... --generate-password \
#     | grep -oP 'password: \K.*' | scripts/store_dashboard_password.sh "Deluluscan Dashboard"
#
set -euo pipefail

SESSION_FILE="${BW_SESSION_FILE:-$HOME/.config/deluluscan/bw-session}"
LABEL="${1:-Deluluscan Dashboard}"
URL="${DELULUSCAN_DASHBOARD_URL:-https://target.github.io/deluluscan/dashboard.html}"

[ -s "$SESSION_FILE" ] || { echo "no bw session at $SESSION_FILE — run: bw unlock --raw > $SESSION_FILE" >&2; exit 1; }
export BW_SESSION
BW_SESSION="$(cat "$SESSION_FILE")"

pw="$(cat)"                      # passphrase from stdin
[ -n "$pw" ] || { echo "empty passphrase on stdin" >&2; exit 1; }

name="$LABEL — $(date +%Y-%m-%d)"

# Build the item JSON with the passphrase passed via env (not argv).
item="$(name="$name" url="$URL" ts="$(date -u +%FT%TZ)" pw="$pw" python3 - <<'PY'
import os, json
print(json.dumps({
    "type": 1,  # login
    "name": os.environ["name"],
    "notes": "Deluluscan dashboard decryption passphrase. Auto-stored " + os.environ["ts"]
             + ". Do not share outside the team.",
    "login": {
        "username": os.environ["url"],
        "password": os.environ["pw"],
        "uris": [{"uri": os.environ["url"]}],
    },
}))
PY
)"

id="$(printf '%s' "$item" | bw encode | bw create item | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
bw sync >/dev/null 2>&1 || true

printf '%s|%s\n' "$id" "$name"
