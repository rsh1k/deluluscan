"""tests.test_plugins_notify — out-of-tree scanners and scan notifications.

Plugin loading executes code, so the tests centre on the two ways that becomes
a liability: a world-writable directory (anyone on the box gets code execution
in this process) and a plugin silently shadowing a built-in scanner.

Notification tests centre on what must never leave the machine — evidence,
credentials, request bodies — and on the count being honest: an observation or
a refuted candidate must never inflate the headline.

No network: transports are exercised through injected fakes.

Run: python3 -m tests.test_plugins_notify
"""
from __future__ import annotations

import os
import stat
import sys
import tempfile

from deluluscan import notify as nf
from deluluscan import plugins as pl

_checks = 0
_failures: list[str] = []


def check(cond: bool, label: str) -> None:
    global _checks
    _checks += 1
    if cond:
        print(f"PASS  {label}")
    else:
        _failures.append(label)
        print(f"FAIL  {label}")


GOOD_PLUGIN = '''
from deluluscan.scanners.base import Scanner

class MyCheckScanner(Scanner):
    name = "my_check"
    vuln_classes = ["misconfig"]
    def run(self, endpoint):
        return []
'''

SHADOWING_PLUGIN = '''
from deluluscan.scanners.base import Scanner

class FakeSqli(Scanner):
    name = "sqli"
    vuln_classes = ["sqli"]
    def run(self, endpoint):
        return []
'''

NO_RUN_PLUGIN = '''
from deluluscan.scanners.base import Scanner

class Incomplete(Scanner):
    name = "incomplete"
'''

IMPORTS_BUILTIN = '''
from deluluscan.scanners.base import Scanner
from deluluscan.scanners.sqli import SqliScanner   # imported, not defined here
'''


def write(d, name, text):
    path = os.path.join(d, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


# --- plugins ---------------------------------------------------------------
def test_loads_a_valid_plugin():
    with tempfile.TemporaryDirectory() as d:
        write(d, "good.py", GOOD_PLUGIN)
        r = pl.load(d)
        check(len(r.plugins) == 1, "a valid plugin is loaded")
        check(r.plugins[0].name == "my_check", "the plugin registers under its declared name")
        check(not r.errors, f"no errors for a valid plugin ({r.errors})")


def test_world_writable_directory_is_refused():
    """Loading executes code; a directory anyone can write to is a code-exec path."""
    with tempfile.TemporaryDirectory() as d:
        write(d, "good.py", GOOD_PLUGIN)
        os.chmod(d, os.stat(d).st_mode | stat.S_IWOTH)
        r = pl.load(d)
        check(not r.plugins, "nothing loads from a world-writable directory")
        check(any("world-writable" in e for e in r.errors),
              "the refusal explains that loading a plugin executes it")
        r2 = pl.load(d, allow_world_writable=True)
        check(len(r2.plugins) == 1, "the check can be overridden deliberately")


def test_plugin_cannot_silently_shadow_a_builtin():
    with tempfile.TemporaryDirectory() as d:
        write(d, "shadow.py", SHADOWING_PLUGIN)
        r = pl.load(d)
        check(not r.plugins, "a plugin claiming a built-in name is not registered")
        check(any("built-in scanner" in e for e in r.errors),
              "the collision is reported with the reason")
        r2 = pl.load(d, allow_override=True)
        check(len(r2.plugins) == 1, "overriding a built-in is possible when explicit")


def test_broken_plugin_does_not_break_the_load():
    with tempfile.TemporaryDirectory() as d:
        write(d, "good.py", GOOD_PLUGIN)
        write(d, "broken.py", "import nonexistent_module_xyz\n")
        write(d, "syntaxerr.py", "def (:\n")
        r = pl.load(d)
        check(len(r.plugins) == 1, "a good plugin still loads alongside broken ones")
        check(len(r.errors) == 2, "both broken plugins are reported")
        check(all("broken.py" in e or "syntaxerr.py" in e for e in r.errors),
              "errors name the offending files")


def test_plugin_without_run_is_rejected():
    with tempfile.TemporaryDirectory() as d:
        write(d, "norun.py", NO_RUN_PLUGIN)
        r = pl.load(d)
        check(not r.plugins, "a Scanner subclass without run() is not registered")
        check(any("does not implement run()" in e for e in r.errors),
              "the missing run() is reported")


def test_imported_builtin_is_not_reregistered():
    with tempfile.TemporaryDirectory() as d:
        write(d, "imports.py", IMPORTS_BUILTIN)
        r = pl.load(d)
        check(not r.plugins, "importing a built-in scanner does not re-register it")
        check(any("no Scanner subclass" in s for s in r.skipped),
              "the file is skipped rather than erroring")


def test_private_and_non_python_files_ignored():
    with tempfile.TemporaryDirectory() as d:
        write(d, "_private.py", GOOD_PLUGIN)
        write(d, "notes.txt", "hello")
        r = pl.load(d)
        check(not r.plugins and not r.errors,
              "underscore-prefixed and non-.py files are ignored")


def test_no_directory_is_a_no_op():
    r = pl.load(None)
    check(not r.plugins and not r.errors, "no plugin directory configured is not an error")
    r2 = pl.load("/nonexistent/xyz")
    check(any("not found" in e for e in r2.errors), "a missing directory is reported")


def test_merged_registry_layers_over_builtins():
    from deluluscan.scanners import SCANNER_REGISTRY
    with tempfile.TemporaryDirectory() as d:
        write(d, "good.py", GOOD_PLUGIN)
        reg, r = pl.merged_registry(d)
        check("my_check" in reg, "the plugin appears in the merged registry")
        check(len(reg) == len(SCANNER_REGISTRY) + 1,
              "the merged registry keeps every built-in scanner")


# --- notifications ---------------------------------------------------------
def payload():
    return {
        "target": "http://127.0.0.1:8080",
        "meta": {"report_include": {"ids": ["r1"]},
                 "coverage": {"endpoints_probed": 725, "endpoints_discovered": 745}},
        "findings": [
            {"id": "r1", "title": "Real finding", "severity": "high", "detail": {
                "report": {"exchanges": [{"curl": "curl -u admin:hunter2 http://x",
                                          "response": {"body": "SECRET-TOKEN-abc"}}]}}},
            {"id": "o1", "title": "Observation", "severity": "medium",
             "detail": {"observation": True}},
            {"id": "f1", "title": "Refuted", "severity": "info",
             "detail": {"refuted": True}},
        ],
    }


def test_summary_counts_only_reported_findings():
    s = nf.summarise(payload())
    check(s.reported == 1, "only findings in report_include are counted as reported")
    check(s.observations == 1, "observations are counted separately")
    check(s.refuted == 1, "refuted candidates are counted separately")
    check("1 reported finding(s): 1 high" in s.headline(),
          "the headline reflects the reported set only")


def test_summary_never_carries_evidence_or_credentials():
    """Chat and mail are broadly readable; evidence must stay in the report."""
    text = nf.summarise(payload(), report_url="https://x/report").as_text()
    for secret in ("hunter2", "SECRET-TOKEN-abc", "curl -u", "Authorization"):
        check(secret not in text, f"the summary does not leak {secret!r}")
    check("Real finding" in text, "the summary still names the finding")
    check("https://x/report" in text, "the summary points at the report instead")


def test_zero_findings_reads_correctly():
    p = payload()
    p["meta"]["report_include"]["ids"] = []
    p["findings"] = [f for f in p["findings"] if f["id"] != "r1"]
    s = nf.summarise(p)
    check(s.reported == 0, "no reported findings")
    check("No exploitable vulnerabilities reported" in s.headline(),
          "a clean scan says so plainly rather than showing an empty list")


def test_unadjudicated_payload_still_summarises():
    p = {"target": "t", "findings": [{"id": "a", "title": "Cand", "severity": "low"}]}
    s = nf.summarise(p)
    check(s.reported == 1, "a payload with no report_include still produces a count")


def test_coverage_is_included():
    check("725/745" in nf.summarise(payload()).coverage,
          "coverage is surfaced so a partial scan is visible in the notification")


def test_unknown_channel_is_reported_not_raised():
    out = nf.notify(payload(), ["carrier-pigeon"])
    ok, msg = out["carrier-pigeon"]
    check(ok is False and "unknown channel" in msg,
          "an unknown channel returns an error rather than raising")


def test_missing_webhook_is_reported_not_raised():
    saved = os.environ.pop("DELULUSCAN_SLACK_WEBHOOK", None)
    try:
        ok, msg = nf.send_slack(nf.summarise(payload()))
        check(ok is False and "no Slack webhook" in msg,
              "a missing webhook is reported, not raised")
    finally:
        if saved:
            os.environ["DELULUSCAN_SLACK_WEBHOOK"] = saved


def test_transport_failure_never_raises():
    """A webhook outage must not lose the scan."""
    original = nf._post_json
    nf._post_json = lambda url, body: (_ for _ in ()).throw(RuntimeError("network down"))
    try:
        out = nf.notify(payload(), ["slack"], webhook="https://hooks.slack.com/x")
        ok, msg = out["slack"]
        check(ok is False, "a transport exception is caught")
        check("RuntimeError" in msg or "network down" in msg,
              "the failure reason is reported back to the caller")
    finally:
        nf._post_json = original


def test_slack_payload_shape():
    sent = {}
    original = nf._post_json
    nf._post_json = lambda url, body: (sent.update({"url": url, "body": body}), (True, "ok"))[1]
    try:
        ok, _ = nf.send_slack(nf.summarise(payload(), report_url="https://x/r"),
                              webhook="https://hooks.slack.com/x")
        check(ok, "slack send reports success")
        blob = str(sent["body"])
        check("Deluluscan scan complete" in blob, "the Slack payload carries a header")
        check("hunter2" not in blob and "SECRET-TOKEN" not in blob,
              "the Slack payload carries no evidence")
    finally:
        nf._post_json = original


def test_configured_channels_reads_environment():
    saved = os.environ.get("DELULUSCAN_DISCORD_WEBHOOK")
    os.environ["DELULUSCAN_DISCORD_WEBHOOK"] = "https://discord.com/api/webhooks/x"
    try:
        check("discord" in nf.configured_channels(),
              "a channel with credentials present is reported as configured")
    finally:
        if saved is None:
            os.environ.pop("DELULUSCAN_DISCORD_WEBHOOK", None)
        else:
            os.environ["DELULUSCAN_DISCORD_WEBHOOK"] = saved


def main() -> int:
    print("== plugins & notifications ==")
    for fn in (test_loads_a_valid_plugin,
               test_world_writable_directory_is_refused,
               test_plugin_cannot_silently_shadow_a_builtin,
               test_broken_plugin_does_not_break_the_load,
               test_plugin_without_run_is_rejected,
               test_imported_builtin_is_not_reregistered,
               test_private_and_non_python_files_ignored,
               test_no_directory_is_a_no_op,
               test_merged_registry_layers_over_builtins,
               test_summary_counts_only_reported_findings,
               test_summary_never_carries_evidence_or_credentials,
               test_zero_findings_reads_correctly,
               test_unadjudicated_payload_still_summarises,
               test_coverage_is_included,
               test_unknown_channel_is_reported_not_raised,
               test_missing_webhook_is_reported_not_raised,
               test_transport_failure_never_raises,
               test_slack_payload_shape,
               test_configured_channels_reads_environment):
        fn()
    print()
    if _failures:
        print(f"{len(_failures)} FAILED of {_checks} checks:")
        for x in _failures:
            print("  -", x)
        return 1
    print(f"{_checks}/{_checks} checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
