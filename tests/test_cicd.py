"""Offline tests for GitHub Actions workflow security analysis."""
from __future__ import annotations

import os, tempfile

from deluluscan.cicd import CicdScan
from deluluscan.cicd.github_actions import analyze_workflow
from deluluscan.models import VulnClass, Severity

_PASS = 0; _FAIL = 0
def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond: _PASS += 1; print(f"PASS  {name}")
    else: _FAIL += 1; print(f"FAIL  {name}  {detail}")

def rules(f): return {x.detail["rule"] for x in f}

D = "${{"; E = "}}"   # avoid literal ${{ confusing any tooling


def test_script_injection():
    wf = ("on: issues\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
          f"      - run: echo \"title is {D} github.event.issue.title {E}\"\n")
    f = analyze_workflow(wf, "ci.yml")
    si = next((x for x in f if x.detail["rule"] == "gha-script-injection"), None)
    check("script injection flagged HIGH", si and si.severity == Severity.HIGH, rules(f))
    check("cwe-94", si and si.detail["cwe"] == "CWE-94")


def test_safe_env_var_not_flagged():
    # the recommended pattern (context -> env -> "$VAR") must NOT trip
    wf = ("on: issues\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
          f"      - env: {{ T: {D} github.event.issue.title {E} }}\n"
          "        run: echo \"$T\"\n")
    check("env-var pattern not flagged as injection", "gha-script-injection" not in rules(analyze_workflow(wf, "ci.yml")))


def test_unpinned_action():
    wf = ("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
          "      - uses: some-org/action@main\n"
          "      - uses: actions/checkout@v4\n"
          "      - uses: pinned/act@abcdef1234567890abcdef1234567890abcdef12\n")
    f = analyze_workflow(wf, "ci.yml")
    unpinned = [x for x in f if x.detail["rule"] == "gha-unpinned-action"]
    actions = {x.detail["action"] for x in unpinned}
    check("third-party @main flagged MEDIUM supply_chain",
          any(x.detail["action"] == "some-org/action@main" and x.severity == Severity.MEDIUM
              and x.vuln_class == VulnClass.SUPPLY_CHAIN for x in unpinned), actions)
    check("first-party actions/checkout@v4 flagged LOW", any(
          x.detail["action"] == "actions/checkout@v4" and x.severity == Severity.LOW for x in unpinned))
    check("SHA-pinned action NOT flagged", "pinned/act@abcdef1234567890abcdef1234567890abcdef12" not in actions)


def test_pwn_request():
    wf = ("on: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
          "      - uses: actions/checkout@v4\n        with:\n"
          f"          ref: {D} github.event.pull_request.head.sha {E}\n")
    f = analyze_workflow(wf, "ci.yml")
    pr = next((x for x in f if x.detail["rule"] == "gha-pwn-request"), None)
    check("pwn request flagged HIGH supply_chain", pr and pr.severity == Severity.HIGH
          and pr.vuln_class == VulnClass.SUPPLY_CHAIN, rules(f))


def test_write_all_and_pipe_to_shell():
    wf = ("on: push\npermissions: write-all\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
          "      - run: curl https://get.example.sh | bash\n")
    r = rules(analyze_workflow(wf, "ci.yml"))
    check("write-all flagged", "gha-write-all" in r, r)
    check("pipe-to-shell flagged", "gha-pipe-to-shell" in r, r)


def test_clean_workflow():
    wf = ("on: push\npermissions: { contents: read }\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
          "      - uses: actions/checkout@abcdef1234567890abcdef1234567890abcdef12\n"
          "      - run: make test\n")
    check("clean workflow -> no findings", analyze_workflow(wf, "ci.yml") == [],
          [x.title for x in analyze_workflow(wf, "ci.yml")])


def test_engine_scans_workflows_dir():
    with tempfile.TemporaryDirectory() as d:
        wfdir = os.path.join(d, ".github", "workflows")
        os.makedirs(wfdir)
        open(os.path.join(wfdir, "ci.yml"), "w").write(
            "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: x/y@main\n")
        f = CicdScan().scan_path(d)
        check("engine finds workflow issues", any(x.detail["rule"] == "gha-unpinned-action" for x in f), rules(f))


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
    print(f"\n{_PASS} passed, {_FAIL} failed")
    raise SystemExit(1 if _FAIL else 0)
