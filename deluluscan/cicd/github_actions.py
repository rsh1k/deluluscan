"""GitHub Actions workflow security analysis.

CI pipelines run with write tokens and secrets, so a workflow flaw is a
supply-chain foothold. This flags the well-known GitHub Actions attack classes:

  - Script injection: a `run:` step interpolating an attacker-controlled context
    (`github.event.issue.title`, PR body, `github.head_ref`, commit message, …)
    straight into a shell command → command execution in CI (CWE-94).
  - "Pwn request": `pull_request_target` / `workflow_run` that checks out and runs
    UNtrusted PR code while holding the base repo's write token + secrets.
  - Unpinned actions: `uses: owner/action@v4` / `@main` (a mutable ref) instead of
    a full commit SHA → the action can be repointed to malicious code.
  - Overly broad token permissions (`permissions: write-all`).
  - Piping remote code into a shell (`curl … | bash`).

YAML parsed with PyYAML; detection only, offline.
"""
from __future__ import annotations

import re

from ..models import Finding, RequestRecord, Severity, VulnClass

_SEV = {"info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
        "high": Severity.HIGH, "critical": Severity.CRITICAL}

# attacker-controllable expression contexts (a non-exhaustive high-signal set)
_UNTRUSTED = [
    "github.event.issue.title", "github.event.issue.body", "github.event.pull_request.title",
    "github.event.pull_request.body", "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label", "github.event.comment.body",
    "github.event.review.body", "github.event.review_comment.body",
    "github.event.commits", "github.event.head_commit.message", "github.event.head_commit.author",
    "github.event.pages", "github.event.discussion.title", "github.event.discussion.body",
    "github.head_ref", "github.event.workflow_run.head_branch",
    "github.event.pull_request.head.repo.default_branch",
]
_EXPR = re.compile(r"\$\{\{\s*([^}]+?)\s*\}\}")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_PIPE_SH = re.compile(r"(?i)(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba)?sh\b")


def _f(sev, title, desc, source, job, rule, vc=VulnClass.MISCONFIG, cwe="", extra=None):
    ep = f"{source}:{job}" if job else source
    return Finding(vuln_class=vc, severity=_SEV[sev], title=title, endpoint=ep, description=desc,
                   evidence=[RequestRecord(method="CI", url=ep, identity="anon", status=0, elapsed_ms=0.0)],
                   confidence="firm", verdict="likely_true_positive", exploitability="conditional",
                   detail={"rule": rule, "cwe": cwe, "file": source, "job": job,
                           "source": "cicd.github_actions", **(extra or {})})


def _triggers(on) -> set:
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {str(x) for x in on}
    if isinstance(on, dict):
        return set(on.keys())
    return set()


def analyze_workflow(text: str, source: str = "workflow.yml") -> list:
    try:
        import yaml
        wf = yaml.safe_load(text)
    except Exception:
        return []
    if not isinstance(wf, dict):
        return []
    out: list = []
    # PyYAML parses the `on:` key as the boolean True — handle both.
    on = wf.get("on", wf.get(True))
    triggers = _triggers(on)
    risky_trigger = triggers & {"pull_request_target", "workflow_run"}

    # top-level broad permissions
    perms = wf.get("permissions")
    if perms == "write-all" or (isinstance(perms, str) and perms == "write-all"):
        out.append(_f("medium", "Workflow grants write-all token permissions",
            "permissions: write-all gives the GITHUB_TOKEN full write access to the repo — scope it "
            "down to the minimum each job needs.", source, "", "gha-write-all", cwe="CWE-250"))

    jobs = wf.get("jobs") or {}
    for job_name, job in (jobs.items() if isinstance(jobs, dict) else []):
        if not isinstance(job, dict):
            continue
        steps = job.get("steps") or []
        checks_out_untrusted = False
        for step in steps if isinstance(steps, list) else []:
            if not isinstance(step, dict):
                continue
            uses = step.get("uses", "")
            run = step.get("run", "")

            # unpinned third-party action
            if isinstance(uses, str) and uses and not uses.startswith(("./", ".github/")):
                ref = uses.split("@", 1)[1] if "@" in uses else ""
                if not _SHA.match(ref):
                    sev = "low" if uses.startswith(("actions/", "github/")) else "medium"
                    out.append(_f(sev, f"Unpinned action: {uses}",
                        f"'{uses}' is pinned to a mutable ref ('{ref or 'none'}') not a full commit SHA — "
                        "if that action (or its tag) is repointed to malicious code, it runs in your "
                        "pipeline. Pin to a 40-char commit SHA.", source, job_name, "gha-unpinned-action",
                        vc=VulnClass.SUPPLY_CHAIN, cwe="CWE-1357", extra={"action": uses}))
                # checkout of untrusted PR head under a risky trigger
                if uses.startswith("actions/checkout") and risky_trigger:
                    ref_in = str((step.get("with") or {}).get("ref", ""))
                    if "head" in ref_in or "pull_request" in ref_in:
                        checks_out_untrusted = True

            # script injection via untrusted context in a run step
            if isinstance(run, str) and run:
                for m in _EXPR.finditer(run):
                    expr = m.group(1)
                    if any(u in expr for u in _UNTRUSTED):
                        out.append(_f("high", "GitHub Actions script injection",
                            f"A run step interpolates attacker-controlled context ${{{{ {expr} }}}} "
                            "directly into a shell command — an attacker sets that value to inject "
                            "commands that run in CI with the workflow's token/secrets. Pass it via an "
                            "env: var and reference \"$VAR\" instead.", source, job_name,
                            "gha-script-injection", cwe="CWE-94", extra={"expression": expr[:80]}))
                        break
                if _PIPE_SH.search(run):
                    out.append(_f("medium", "Pipe-to-shell of remote code in CI",
                        "A run step pipes a downloaded script straight into a shell (curl … | bash) — "
                        "unpinned remote code executes in the pipeline. Download, verify a checksum, "
                        "then run.", source, job_name, "gha-pipe-to-shell", vc=VulnClass.SUPPLY_CHAIN,
                        cwe="CWE-494"))

        if checks_out_untrusted:
            out.append(_f("high", "Pwn request: untrusted PR code runs with a privileged trigger",
                f"Job '{job_name}' runs under {sorted(risky_trigger)} and checks out the PR head "
                "(untrusted code) — that code then runs with the base repo's write token and secrets. "
                "Use pull_request, or split into a privileged workflow_run that never checks out PR code.",
                source, job_name, "gha-pwn-request", vc=VulnClass.SUPPLY_CHAIN, cwe="CWE-668"))
    return out
