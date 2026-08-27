#!/usr/bin/env bash
# build_dashboard.sh — build the React dashboard and vendor it for the Python generator.
#
# The report UI lives in dashboard/ (React + TypeScript + Tailwind, built by Vite
# into ONE self-contained HTML file). deluluscan/dashboard.py injects the scan payload
# into that file at the /*__DATA__*/ marker.
#
# The built shell is committed as deluluscan/assets/dashboard_bundle.html so that
# running a scan never needs a Node toolchain — `python3 -m deluluscan.dashboard
# results.json out.html` must work on a machine that has never seen npm. Run this
# whenever anything under dashboard/src changes, and commit the updated asset.
#
# Usage:  ./scripts/build_dashboard.sh [--check]
#           --check  fail if the committed asset is stale (for CI)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP="$ROOT/dashboard"
ASSET="$ROOT/deluluscan/assets/dashboard_bundle.html"
BUILT="$APP/dist/index.html"
CHECK=0
[ "${1:-}" = "--check" ] && CHECK=1

command -v npm >/dev/null 2>&1 || {
    echo "[!] npm not found. Install Node 20+ (the vendored asset means you only" >&2
    echo "    need this to CHANGE the dashboard, not to run a scan)." >&2
    exit 1
}

cd "$APP"
[ -d node_modules ] || { echo "[*] installing dashboard deps..."; npm install; }

echo "[*] type-checking and building the dashboard..."
npm run build

[ -f "$BUILT" ] || { echo "[!] build produced no $BUILT" >&2; exit 1; }

# The build itself asserts that /*__DATA__*/ survived and that nothing dangles,
# but re-check here so a hand-edited asset can never ship either.
grep -q '/\*__DATA__\*/' "$BUILT" || {
    echo "[!] built bundle has no /*__DATA__*/ marker — deluluscan/dashboard.py could" >&2
    echo "    not inject the scan payload into it." >&2
    exit 1
}

mkdir -p "$(dirname "$ASSET")"
if [ "$CHECK" -eq 1 ]; then
    if ! cmp -s "$BUILT" "$ASSET"; then
        echo "[!] $ASSET is STALE: dashboard/src has changed since it was built." >&2
        echo "    Run ./scripts/build_dashboard.sh and commit the result." >&2
        exit 1
    fi
    echo "[*] committed dashboard asset is up to date."
else
    cp "$BUILT" "$ASSET"
    echo "[*] vendored $(wc -c <"$ASSET" | tr -d ' ') bytes -> ${ASSET#"$ROOT/"}"
    echo "[*] commit that file along with your dashboard/src changes."
fi
