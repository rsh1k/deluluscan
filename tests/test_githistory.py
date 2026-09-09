"""Offline tests for git-history secret scanning (injected git access)."""
from __future__ import annotations

from deluluscan.githistory import GitSecretScan
from deluluscan.models import VulnClass, Severity

_PASS = 0; _FAIL = 0
def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond: _PASS += 1; print(f"PASS  {name}")
    else: _FAIL += 1; print(f"FAIL  {name}  {detail}")


_AWS = "AKIAIOSFODNN7EXAMPLE"


def _scan(blobs, content, **kw):
    return GitSecretScan(list_blobs=lambda r: blobs,
                         read_blob=lambda r, s: content.get(s, ""), **kw).scan_repo("/x")


def test_finds_committed_secret():
    finds = _scan([("a", "config.py"), ("b", "README.md")],
                  {"a": f'AWS_KEY = "{_AWS}"', "b": "just docs"})
    check("one secret found", len(finds) == 1, [f.title for f in finds])
    check("it's the AWS key", "AWS" in finds[0].title, finds[0].title)
    check("source tagged githistory", finds[0].detail.get("source") == "githistory")
    check("description says rotate", "ROTATE" in finds[0].description)
    check("blob recorded", finds[0].detail.get("blob") == "a")


def test_secret_removed_from_head_still_caught():
    # 'a' introduced the key; 'b' removed it — still reachable in history via 'a'
    finds = _scan([("a", "config.py"), ("b", "config.py")],
                  {"a": f'KEY="{_AWS}"', "b": "# key removed"})
    check("removed-from-HEAD secret still caught", len(finds) == 1)


def test_dedup_across_blobs():
    # same secret in three blobs/paths -> one finding, paths accumulated
    finds = _scan([("a", "x.py"), ("b", "y.py"), ("c", "z.py")],
                  {"a": f'K="{_AWS}"', "b": f'K="{_AWS}"', "c": f'K="{_AWS}"'})
    check("deduped to one finding", len(finds) == 1, len(finds))
    locs = finds[0].detail.get("history_locations", [])
    check("all paths accumulated", set(locs) == {"x.py", "y.py", "z.py"}, locs)


def test_clean_repo_no_findings():
    finds = _scan([("a", "main.py")], {"a": "print('hello world')"})
    check("clean repo -> no findings", finds == [])


def test_binary_and_huge_skipped():
    finds = _scan([("a", "img.png"), ("b", "big.txt")],
                  {"a": "\x00\x01binary" + _AWS, "b": _AWS + "x" * 2_000_000}, max_bytes=1_000_000)
    check("binary + oversized blobs skipped", finds == [], [f.title for f in finds])


def test_list_blobs_error_failsoft():
    def boom(r): raise OSError("not a git repo")
    sc = GitSecretScan(list_blobs=boom)
    check("list error -> no crash, no findings", sc.scan_repo("/x") == [])


def test_max_blobs_bound():
    blobs = [(str(i), f"f{i}.py") for i in range(100)]
    content = {"5": f'K="{_AWS}"'}   # secret is in blob #5
    finds = _scan(blobs, content, max_blobs=3)   # stops before reaching #5
    check("max_blobs bound respected", finds == [], [f.title for f in finds])


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
    print(f"\n{_PASS} passed, {_FAIL} failed")
    raise SystemExit(1 if _FAIL else 0)
