"""Secret scanning across git HISTORY, not just the working tree.

`secrets/` scans live responses and JS; this scans every blob in a repo's git
history — so a credential that was committed and later "removed" (still reachable
via old commits) is caught. Removing a secret from HEAD does not remove it from
history; the fix is always to ROTATE it, which this finding makes explicit.

Reuses the existing secret patterns (`secrets.scan_text`). Git access is injected
(`list_blobs` / `read_blob`) so the engine is fully offline-testable with canned
blobs; the defaults shell out to `git`. Read-only — it never writes to the repo.
Findings are de-duplicated per unique secret so one leaked key committed across
many blobs is reported once, with the paths it appears in.
"""
from __future__ import annotations

import subprocess
from typing import Callable, Optional

from ..secrets.scanner import scan_text


def _run(repo: str, args: list, _input: Optional[str] = None) -> str:
    return subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True,
                          input=_input, timeout=120).stdout


def _default_list_blobs(repo: str) -> list:
    """Return [(blob_sha, representative_path)] for every blob in all history."""
    out = _run(repo, ["rev-list", "--all", "--objects"])
    pairs, order = {}, []
    for line in out.splitlines():
        parts = line.split(" ", 1)
        if len(parts) == 2 and parts[1]:
            sha, path = parts
            if sha not in pairs:
                pairs[sha] = path
                order.append(sha)
    if not order:
        return []
    # keep only blobs (rev-list --objects also lists trees with a path)
    check = _run(repo, ["cat-file", "--batch-check"], _input="\n".join(order))
    blobs = []
    for line in check.splitlines():
        f = line.split()
        if len(f) >= 2 and f[1] == "blob":
            blobs.append((f[0], pairs.get(f[0], "")))
    return blobs


def _default_read_blob(repo: str, sha: str) -> str:
    try:
        r = subprocess.run(["git", "-C", repo, "cat-file", "blob", sha],
                           capture_output=True, timeout=30)
        return r.stdout.decode("utf-8", "replace")
    except Exception:
        return ""


class GitSecretScan:
    def __init__(self, list_blobs: Optional[Callable] = None,
                 read_blob: Optional[Callable] = None, max_blobs: int = 20000,
                 max_bytes: int = 1_000_000):
        self.list_blobs = list_blobs or _default_list_blobs
        self.read_blob = read_blob or _default_read_blob
        self.max_blobs = max_blobs
        self.max_bytes = max_bytes

    def scan_repo(self, repo: str) -> list:
        try:
            blobs = self.list_blobs(repo) or []
        except Exception:
            return []
        merged: dict = {}          # (rule, masked) -> Finding (first), paths accumulate
        for i, (sha, path) in enumerate(blobs):
            if i >= self.max_blobs:
                break
            try:
                content = self.read_blob(repo, sha) or ""
            except Exception:
                continue
            if not content or len(content) > self.max_bytes or "\x00" in content[:1024]:
                continue           # skip empty / huge / binary
            for f in scan_text(content, source=path or sha[:12]):
                key = (f.detail.get("rule"), f.detail.get("masked"))
                if key in merged:
                    d = merged[key].detail
                    locs = d.setdefault("history_locations", [])
                    if path and path not in locs and len(locs) < 20:
                        locs.append(path)
                    continue
                # first sighting of this secret in history — annotate + keep
                f.detail["source"] = "githistory"
                f.detail["blob"] = sha
                f.detail["history_locations"] = [path] if path else []
                f.description = ("Committed secret found in GIT HISTORY (blob "
                                 f"{sha[:12]}, path '{path}'). It is reachable via old commits even "
                                 "if deleted from the current tree — ROTATE it now; removing the file "
                                 "does not invalidate the credential. " + f.description)
                f.detail.setdefault("remediation",
                    "Rotate the exposed credential immediately, then purge it from history "
                    "(git filter-repo) and force-push; add a pre-commit secret scan.")
                merged[key] = f
        return list(merged.values())
