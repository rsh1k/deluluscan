"""deluluscan.freshness — is what we are testing actually current?

An assessment is only as good as the thing it was run against. Three inputs go
stale silently:

  * the target SOURCE clone that drives source-informed targeting — a pinned
    snapshot keeps producing findings for code that upstream has already changed;
  * the target DOCKER IMAGE under test — "target/target:latest" is a moving tag,
    so a locally cached copy can be weeks behind while still calling itself
    latest (observed here: a local image built 2026-06-11 still tagged latest);
  * the MANTIS code-scanner that produced the finding corpus.

Testing a stale target produces two failure modes, and the second is worse:
findings that upstream already fixed (noise), and a clean report for a build
nobody runs (false assurance).

So this runs BEFORE a scan and reports each input as current / stale / unknown.
"unknown" is never reported as "current" — if the check could not be performed
the report says so, because an unverified claim of freshness is exactly the kind
of comfortable non-fact this tool exists to avoid.

Staleness does not block a scan by default: an operator may deliberately test a
pinned build. It is recorded in the report so the reader knows what was tested.
Pass require_current=True (CLI: --require-current) to fail closed instead.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from typing import Optional

CURRENT, STALE, UNKNOWN = "current", "stale", "unknown"

_TARGET_REPO = "https://github.com/the target source.git"
_MANTIS_REPO = "https://github.com/google/mantis.git"


def _run(cmd: list[str], timeout: float = 30.0) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        return 1, str(exc)


@dataclass
class Check:
    name: str
    state: str = UNKNOWN
    local: str = ""
    remote: str = ""
    detail: str = ""
    remediation: str = ""

    def to_dict(self) -> dict:
        return {"name": self.name, "state": self.state, "local": self.local,
                "remote": self.remote, "detail": self.detail,
                "remediation": self.remediation}


@dataclass
class FreshnessReport:
    checks: list[Check] = field(default_factory=list)

    @property
    def stale(self) -> list[Check]:
        return [c for c in self.checks if c.state == STALE]

    @property
    def unknown(self) -> list[Check]:
        return [c for c in self.checks if c.state == UNKNOWN]

    @property
    def all_current(self) -> bool:
        return all(c.state == CURRENT for c in self.checks)

    def to_dict(self) -> dict:
        return {
            "all_current": self.all_current,
            "stale": [c.name for c in self.stale],
            "unknown": [c.name for c in self.unknown],
            "checks": [c.to_dict() for c in self.checks],
            "messages": self.messages(),
        }

    def messages(self) -> list[str]:
        out = []
        for c in self.stale:
            out.append(f"STALE — {c.name}: {c.detail} {c.remediation}".strip())
        for c in self.unknown:
            out.append(f"UNVERIFIED — {c.name}: {c.detail} This is NOT a statement that it "
                       f"is up to date; freshness could not be confirmed.".strip())
        return out


def check_source(clone_dir: str, branch: str = "master") -> Check:
    """Local the target source clone vs upstream branch head."""
    c = Check(name="the target source clone",
              remediation=f"Refresh with ./scripts/clone_target_source.sh {branch}")
    rc, out = _run(["git", "-C", clone_dir, "rev-parse", "HEAD"])
    if rc != 0:
        c.detail = f"no readable clone at {clone_dir}"
        c.remediation = "Clone it with ./scripts/clone_target_source.sh"
        return c
    c.local = out.strip()[:40]
    rc, out = _run(["git", "ls-remote", _TARGET_REPO, f"refs/heads/{branch}"])
    if rc != 0 or not out.strip():
        c.detail = f"could not reach {_TARGET_REPO} to read {branch}"
        return c
    c.remote = out.split()[0][:40]
    if c.local == c.remote:
        c.state = CURRENT
        c.detail = f"clone matches upstream {branch} ({c.local[:12]})"
    else:
        c.state = STALE
        c.detail = (f"clone is at {c.local[:12]} but upstream {branch} is at "
                    f"{c.remote[:12]}")
    return c


def check_image(image: str = "target/target:latest",
                container: Optional[str] = None) -> Check:
    """Local image digest vs the digest the registry currently serves for that tag.

    A moving tag like :latest is the trap here — the local copy keeps the name
    long after the registry has moved on.
    """
    c = Check(name="the target docker image",
              remediation=f"Pull the current image: docker pull {image} "
                          f"&& docker compose up -d --force-recreate")
    if container:
        rc, out = _run(["docker", "inspect", container, "--format", "{{.Config.Image}}"])
        if rc == 0 and out.strip():
            image = out.strip()
            c.remediation = (f"Pull the current image: docker pull {image} "
                             f"&& docker compose up -d --force-recreate")
    rc, out = _run(["docker", "image", "inspect", image, "--format",
                    "{{index .RepoDigests 0}}|{{.Created}}"])
    if rc != 0 or "|" not in out:
        c.detail = f"image {image} is not present locally, or has no registry digest"
        return c
    digest, created = out.strip().split("|", 1)
    c.local = digest.split("@")[-1][:23]
    created = created.strip()[:10]

    # Ask the registry what that tag points at now.
    #
    # The digest MUST be the manifest-LIST (index) digest, because that is what
    # RepoDigests records locally. `docker manifest inspect --verbose` returns
    # PER-PLATFORM manifest digests instead (amd64, arm64, ...), which are a
    # different kind of digest and can never equal RepoDigests — comparing them
    # made this check report STALE permanently, even immediately after a fresh
    # pull. A check that always cries wolf is as useless as one that never does.
    remote_digest = ""
    rc, out = _run(["docker", "buildx", "imagetools", "inspect", image,
                    "--format", "{{json .Manifest.Digest}}"], timeout=45.0)
    if rc == 0 and out.strip():
        remote_digest = out.strip().strip('"')
    if not remote_digest:
        # Fallback: the Ref line of the index carries the list digest for some
        # docker versions; never fall back to a per-platform Descriptor digest.
        rc2, out2 = _run(["docker", "buildx", "imagetools", "inspect", image], timeout=45.0)
        if rc2 == 0:
            for line in out2.splitlines():
                if line.strip().startswith("Digest:"):
                    remote_digest = line.split(":", 1)[1].strip()
                    break
    if not remote_digest:
        c.detail = (f"local image built {created} (digest {c.local}); registry digest "
                    f"unreadable, so currency is unconfirmed")
        return c
    c.remote = remote_digest[:23]
    if c.local and c.local == c.remote:
        c.state = CURRENT
        c.detail = f"local image matches the registry digest for {image}"
    else:
        c.state = STALE
        c.detail = (f"local image (built {created}, {c.local}) differs from the digest the "
                    f"registry now serves for {image} ({c.remote}). A moving tag such as "
                    f"':latest' does not update itself.")
    return c


# Conventional locations written by the deluluscan-codescan skill.
_MANTIS_STATE_CANDIDATES = (
    ".target-src/mantis-workspace/workspace/.mantis_state.json",
    "mantis-workspace/workspace/.mantis_state.json",
)


def _discover_mantis_state() -> Optional[str]:
    import os
    for c in _MANTIS_STATE_CANDIDATES:
        if os.path.isfile(c):
            return c
    return None


def check_mantis(state_file: Optional[str] = None) -> Check:
    """Mantis scanner revision used for the corpus vs upstream head.

    The state file is auto-discovered at the conventional workspace path when the
    caller does not name one. Previously this was only consulted if the operator
    remembered --mantis-findings-dir, so a corpus that DID record its revision
    still reported UNKNOWN, and the message blamed the corpus for an omission
    that was actually ours.
    """
    import os
    if not state_file:
        state_file = _discover_mantis_state()
    elif os.path.isdir(state_file):
        state_file = os.path.join(state_file, ".mantis_state.json")
    c = Check(name="Mantis code scanner",
              remediation="Update the Mantis plugin/skills and re-run the deluluscan-codescan "
                          "campaign so the corpus reflects the current scanner.")
    rc, out = _run(["git", "ls-remote", _MANTIS_REPO, "refs/heads/main"])
    if rc == 0 and out.strip():
        c.remote = out.split()[0][:40]
    else:
        c.detail = f"could not reach {_MANTIS_REPO}"
        return c
    recorded = ""
    if not state_file:
        c.detail = ("no Mantis workspace found at the conventional path "
                    f"({_MANTIS_STATE_CANDIDATES[0]}); upstream head is "
                    f"{c.remote[:12]}. Run the deluluscan-codescan skill to build a corpus.")
        c.remediation = ("Build a corpus with the deluluscan-codescan skill, then pass "
                         "--mantis-findings-dir so its findings inform the scan.")
        return c
    if state_file:
        try:
            with open(state_file) as fh:
                recorded = (json.load(fh) or {}).get("mantis_revision", "") or ""
        except (OSError, ValueError, TypeError):
            recorded = ""
    if not recorded:
        c.detail = (f"the corpus does not record which Mantis revision produced it "
                    f"(upstream head is {c.remote[:12]}), so it cannot be compared")
        return c
    c.local = recorded[:40]
    if c.local == c.remote:
        c.state = CURRENT
        c.detail = f"corpus was produced by the current Mantis revision ({c.local[:12]})"
    else:
        c.state = STALE
        c.detail = (f"corpus was produced by Mantis {c.local[:12]} but upstream head is "
                    f"{c.remote[:12]}")
    return c


def check_all(*, clone_dir: str = ".target-src/core", branch: str = "master",
              image: str = "target/target:latest", container: Optional[str] = None,
              mantis_state: Optional[str] = None) -> FreshnessReport:
    return FreshnessReport(checks=[
        check_source(clone_dir, branch),
        check_image(image, container),
        check_mantis(mantis_state),
    ])
