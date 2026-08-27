#!/usr/bin/env bash
# mantis_queue.sh — resumable work queue for a Mantis code-scan campaign.
#
# A full campaign over the target source does not fit in one session (the first attempt
# at all 125 REST resources exhausted the account's token budget mid-flight and
# wrote zero findings). This keeps the campaign as durable state on disk so it can
# be run a slice at a time, across sessions, without re-auditing anything.
#
# State lives in the Mantis workspace, next to the findings it produces:
#   kb/rest_targets.txt   every REST resource in the pinned snapshot
#   kb/queue_ranked.txt   remaining targets, highest attack surface first
#   kb/audited.txt        completed — the resume marker
#
# Ranking weights the shape that produced this campaign's one confirmed finding
# (`init(..., false, ...)` = rejectWhenNoUser false) 10x, then write verbs, then
# reads — so the highest-yield files come first and a partial campaign is still
# a useful campaign.
#
# Usage:
#   ./scripts/mantis_queue.sh status
#   ./scripts/mantis_queue.sh next 10          # carve the next slice
#   ./scripts/mantis_queue.sh done <path>...   # mark audited (after an agent runs)
#   ./scripts/mantis_queue.sh rank             # rebuild the ranking
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${CODE_ROOT:-$ROOT/.target-src/core}"
KB="${MANTIS_WS:-$ROOT/.target-src/mantis-workspace/workspace}/kb"
CMD="${1:-status}"

[ -d "$KB" ] || { echo "[!] no Mantis workspace at $KB — see the deluluscan-codescan skill" >&2; exit 1; }
touch "$KB/audited.txt"

rank() {
    [ -d "$SRC" ] || { echo "[!] no source clone at $SRC" >&2; exit 1; }
    find "$SRC" -name '*Resource.java' -path '*src/main*' \
        | sed "s|^$SRC/||" | sort > "$KB/rest_targets.txt"
    comm -23 "$KB/rest_targets.txt" <(sort -u "$KB/audited.txt") > "$KB/.queue.tmp"
    SRC="$SRC" python3 - "$KB/.queue.tmp" > "$KB/queue_ranked.txt" <<'PY'
import os, re, sys
root = os.environ["SRC"]
rows = []
for rel in open(sys.argv[1]).read().split():
    try:
        t = open(os.path.join(root, rel), encoding="utf-8", errors="replace").read()
    except OSError:
        continue
    anon = len(re.findall(r"init\([^)]*,\s*false\s*,", t))      # the confirmed shape
    write = len(re.findall(r"@(POST|PUT|DELETE|PATCH)\b", t))
    read = len(re.findall(r"@GET\b", t))
    # Weight anonymous init by READ surface, not raw count. Measured in slice 2:
    # v1 FieldResource scored top on anon_init=9, but its anonymous WRITES are
    # refused 403 by permissionAPI.checkPermission downstream — only the READ
    # paths were actually exposed, because nothing re-checks permissions there.
    rows.append((anon * min(read, 6) * 3 + write * 2 + read, anon, write, read, rel))
rows.sort(reverse=True)
for score, anon, write, read, rel in rows:
    print(f"{rel}\t{score}\tanon_init={anon} write={write} read={read}")
PY
    rm -f "$KB/.queue.tmp"
    echo "[*] ranked $(wc -l < "$KB/queue_ranked.txt") remaining target(s)"
}

case "$CMD" in
  rank) rank ;;
  status)
    [ -s "$KB/queue_ranked.txt" ] || rank
    TOT=$(wc -l < "$KB/rest_targets.txt"); DONE=$(sort -u "$KB/audited.txt" | grep -c . || true)
    LEFT=$(wc -l < "$KB/queue_ranked.txt")
    echo "campaign: $DONE/$TOT REST resources audited, $LEFT queued"
    echo "findings so far: $(ls -1 "$KB/../findings"/*.json 2>/dev/null | wc -l)"
    echo
    echo "next up:"
    head -5 "$KB/queue_ranked.txt" | awk -F'\t' '{printf "  %-72s %s\n", $1, $3}'
    ;;
  next)
    N="${2:-10}"
    [ -s "$KB/queue_ranked.txt" ] || rank
    head -n "$N" "$KB/queue_ranked.txt" | cut -f1 > "$KB/slice_current.txt"
    echo "[*] $(wc -l < "$KB/slice_current.txt") target(s) -> $KB/slice_current.txt"
    cat "$KB/slice_current.txt"
    ;;
  done)
    shift
    if [ "$#" -eq 0 ]; then
        [ -s "$KB/slice_current.txt" ] || { echo "[!] nothing to mark" >&2; exit 1; }
        cat "$KB/slice_current.txt" >> "$KB/audited.txt"
    else
        printf '%s\n' "$@" >> "$KB/audited.txt"
    fi
    sort -u "$KB/audited.txt" -o "$KB/audited.txt"
    rank
    echo "[*] audited now: $(grep -c . "$KB/audited.txt")"
    ;;
  *) echo "usage: $0 {status|next [N]|done [path...]|rank}" >&2; exit 1 ;;
esac
