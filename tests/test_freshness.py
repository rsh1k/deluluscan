"""Pre-flight currency checks — never call an unverified input "current".

An assessment is only as good as the build it ran against. Two failure modes
follow from a stale target, and the second is the dangerous one: findings
upstream already fixed (noise), and a clean report for a build nobody runs
(false assurance).

Observed live on this project: the container was running target/target:latest,
but the local image had been built 2026-06-11 while the registry had long since
moved the tag. A moving tag does not update itself, and nothing in the scan
output said so.

The invariant enforced here: UNKNOWN must never be reported as CURRENT.

Run: python3 -m tests.test_freshness
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

from deluluscan import freshness as F

_checks = 0
_failures: list[str] = []


def check(cond: bool, label: str) -> None:
    global _checks
    _checks += 1
    print(f"{'PASS' if cond else 'FAIL'}  {label}")
    if not cond:
        _failures.append(label)


class _FakeRun:
    """Scripted replacement for freshness._run."""

    def __init__(self, table):
        self.table = table
        self.calls: list[list[str]] = []

    def __call__(self, cmd, timeout=30.0):
        self.calls.append(cmd)
        for key, val in self.table.items():
            if key in " ".join(cmd):
                return val
        return (1, "")


def _with(table, fn):
    orig = F._run
    F._run = _FakeRun(table)
    try:
        return fn()
    finally:
        F._run = orig


LOCAL = "e0e83bd40d370b8eb58e0fc987928a5ee567a947"
REMOTE = "ffffffffffffffffffffffffffffffffffffffff"


def test_source_current_and_stale():
    r = _with({"rev-parse": (0, LOCAL + "\n"),
               "ls-remote": (0, f"{LOCAL}\trefs/heads/master\n")},
              lambda: F.check_source("/tmp/clone"))
    check(r.state == F.CURRENT, f"matching clone reads CURRENT (got {r.state})")

    r = _with({"rev-parse": (0, LOCAL + "\n"),
               "ls-remote": (0, f"{REMOTE}\trefs/heads/master\n")},
              lambda: F.check_source("/tmp/clone"))
    check(r.state == F.STALE, f"diverged clone reads STALE (got {r.state})")
    check("clone-target-source" in r.remediation or "clone_target_source" in r.remediation,
          "stale clone names the refresh script")


def test_unreachable_upstream_is_unknown_not_current():
    """The cardinal rule: inability to check is never a pass."""
    r = _with({"rev-parse": (0, LOCAL + "\n"), "ls-remote": (1, "network down")},
              lambda: F.check_source("/tmp/clone"))
    check(r.state == F.UNKNOWN, f"unreachable upstream reads UNKNOWN (got {r.state})")
    check(r.state != F.CURRENT, "unreachable upstream must NEVER read CURRENT")

    r = _with({"rev-parse": (1, "not a repo")}, lambda: F.check_source("/nope"))
    check(r.state == F.UNKNOWN, "missing clone reads UNKNOWN")


def test_moving_tag_staleness_is_detected():
    """target/target:latest keeps its name after the registry moves on."""
    local = "docker.io/target/target@sha256:aaaa1111|2026-06-11T20:00:27Z"
    r = _with({"image inspect": (0, local),
               "imagetools inspect": (0, '"sha256:bbbb2222"')},
              lambda: F.check_image("target/target:latest"))
    check(r.state == F.STALE, f"digest mismatch reads STALE (got {r.state})")
    check("2026-06-11" in r.detail, "detail states when the local image was built")
    check("does not update itself" in r.detail,
          "detail explains that a moving tag is the trap")
    check("docker pull" in r.remediation, "remediation gives the pull command")

    same = "docker.io/target/target@sha256:bbbb2222|2026-07-27T00:00:00Z"
    r = _with({"image inspect": (0, same),
               "imagetools inspect": (0, '"sha256:bbbb2222"')},
              lambda: F.check_image("target/target:latest"))
    check(r.state == F.CURRENT, f"matching digest reads CURRENT (got {r.state})")


def test_compares_manifest_list_digest_not_per_platform():
    """RepoDigests holds the manifest-LIST digest; comparing a per-platform
    manifest digest against it can never match, which made this check report
    STALE permanently — even straight after a fresh pull."""
    listed = "sha256:9905cb79"          # what RepoDigests records
    per_platform = "sha256:d9fcce30"    # what `manifest inspect --verbose` returns
    local = f"docker.io/target/target@{listed}|2026-07-21T18:49:01Z"
    r = _with({"image inspect": (0, local),
               "imagetools inspect": (0, f'"{listed}"')},
              lambda: F.check_image("target/target:latest"))
    check(r.state == F.CURRENT,
          f"freshly pulled image reads CURRENT, not STALE (got {r.state})")
    check(per_platform[:16] not in (r.remote or ""),
          "the per-platform manifest digest is never used for the comparison")


def test_registry_unreachable_is_unknown():
    local = "docker.io/target/target@sha256:aaaa1111|2026-06-11T20:00:27Z"
    r = _with({"image inspect": (0, local), "imagetools inspect": (1, "no network")},
              lambda: F.check_image("target/target:latest"))
    check(r.state == F.UNKNOWN, "unreadable registry reads UNKNOWN")
    check("unconfirmed" in r.detail, "detail says currency is unconfirmed")
    check(r.state != F.CURRENT, "unreadable registry must NEVER read CURRENT")


def test_mantis_revision_comparison():
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        json.dump({"mantis_revision": LOCAL}, open(path, "w"))
        r = _with({"ls-remote": (0, f"{LOCAL}\trefs/heads/main\n")},
                  lambda: F.check_mantis(path))
        check(r.state == F.CURRENT, f"matching Mantis revision reads CURRENT (got {r.state})")

        r = _with({"ls-remote": (0, f"{REMOTE}\trefs/heads/main\n")},
                  lambda: F.check_mantis(path))
        check(r.state == F.STALE, f"diverged Mantis revision reads STALE (got {r.state})")

        json.dump({}, open(path, "w"))
        r = _with({"ls-remote": (0, f"{REMOTE}\trefs/heads/main\n")},
                  lambda: F.check_mantis(path))
        check(r.state == F.UNKNOWN, "corpus with no recorded revision reads UNKNOWN")
        check("does not record" in r.detail, "detail explains the corpus lacks a revision")
    finally:
        os.unlink(path)


def test_report_never_claims_unknown_is_fine():
    rep = F.FreshnessReport(checks=[
        F.Check(name="a", state=F.CURRENT),
        F.Check(name="b", state=F.UNKNOWN, detail="could not reach registry"),
    ])
    check(rep.all_current is False, "a single UNKNOWN prevents all_current")
    msgs = " ".join(rep.messages())
    check("UNVERIFIED" in msgs, "unknown checks are surfaced as UNVERIFIED")
    check("NOT a statement that it is up to date" in msgs,
          "report explicitly refuses to imply an unverified input is current")
    d = rep.to_dict()
    check(d["unknown"] == ["b"] and d["stale"] == [], "dict separates unknown from stale")


def main() -> int:
    print("== pre-flight freshness ==")
    test_source_current_and_stale()
    test_unreachable_upstream_is_unknown_not_current()
    test_moving_tag_staleness_is_detected()
    test_compares_manifest_list_digest_not_per_platform()
    test_registry_unreachable_is_unknown()
    test_mantis_revision_comparison()
    test_report_never_claims_unknown_is_fine()
    print()
    if _failures:
        print(f"{len(_failures)} FAILED of {_checks} checks:")
        for f in _failures:
            print("  -", f)
        return 1
    print(f"{_checks}/{_checks} checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
