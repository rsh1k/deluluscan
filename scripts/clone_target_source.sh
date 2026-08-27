#!/usr/bin/env bash
# Shallow-clone (or fast-forward update) the latest the target source source into a
# local cache dir, for use as --source-root with deluluscan's source-informed
# scanning (deluluscan/sourcescan.py) and as the CODE_ROOT for a Mantis code-scan
# pass (see .claude/skills/deluluscan-codescan).
#
# Usage: ./scripts/clone_target_source.sh [branch] [dest]
#   branch  - the target source branch/tag to track (default: master)
#   dest    - destination dir (default: .target-src/core)
#
# Prints the resolved absolute path and commit SHA on success.
set -euo pipefail

REPO_URL="https://github.com/the target source.git"
DEST="${2:-.target-src/core}"

# Resolve the branch from the REMOTE's own HEAD rather than hardcoding one.
# the target source renamed its default branch master -> main, which silently broke
# this script (and every Mantis campaign downstream of it) with
# "Remote branch master not found". Asking the remote can't go stale.
if [ -n "${1:-}" ]; then
  BRANCH="$1"
else
  BRANCH="$(git ls-remote --symref "$REPO_URL" HEAD 2>/dev/null \
            | sed -n 's#^ref: refs/heads/\([^\t ]*\).*#\1#p' | head -1)"
  BRANCH="${BRANCH:-main}"
  echo "[*] resolved default branch from remote: $BRANCH"
fi

mkdir -p "$(dirname "$DEST")"

if [ -d "$DEST/.git" ]; then
  echo "[*] updating existing clone at $DEST (branch $BRANCH)"
  git -C "$DEST" fetch --depth 1 origin "$BRANCH"
  git -C "$DEST" checkout -q "$BRANCH" 2>/dev/null || git -C "$DEST" checkout -q -B "$BRANCH" "origin/$BRANCH"
  git -C "$DEST" reset --hard "origin/$BRANCH"
else
  echo "[*] cloning $REPO_URL (branch $BRANCH, depth 1) into $DEST"
  git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$DEST"
fi

ABS_DEST="$(cd "$DEST" && pwd)"
SHA="$(git -C "$DEST" rev-parse --short HEAD)"
echo "[*] the target source @ $SHA ready at: $ABS_DEST"
echo "$ABS_DEST"
