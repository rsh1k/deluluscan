"""Deep stored-XSS→privileged-action chain verifier.

This composes the three deep primitives into the exact investigation the manual
session ran, end to end, and grades it — replacing the surface check
("did my canary reflect?") with a proof chain:

  1. BYPASS   — compute a field-split that beats the server's input filter
                (deluluscan.active.filter_bypass), not just fire one canonical payload.
  2. STORE    — write the fragments to the writable fields.
  3. READ BACK — pull the stored value from EVERY echo surface and classify each
                (deluluscan.verify.readback); one raw render in an HTML sink = a real
                execution sink, however many other surfaces escape it.
  4. WEAPONIZE? — if it executes in an authenticated surface, decide whether that
                JavaScript can actually perform a privileged action
                (deluluscan.verify.exploitability): probe the target endpoint every auth
                way, weigh the credential surface (HttpOnly / storage), and grade
                weaponizable vs contained.
  5. RESTORE  — always revert the stored value.

Every side effect (write/read/probe/restore) is injected, so the logic is unit-
tested without a live target and the same object drives a real scan. Detection
and analysis only: it plants an INERT marker payload and reasons about auth; it
never performs the privileged action or a weaponized payload.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from ..active.filter_bypass import (TARGET_XSS_REGEX, SplitPlan, is_attr_unquoted_safe,
                                    marker_img, mutations, split_for_concat)
from .exploitability import (AuthMatrix, CredentialSurface, ExploitAssessment,
                             analyze_set_cookie, assess_privileged_action_via_xss,
                             probe_auth_matrix)
from .readback import (ReadbackReport, detect_concat_reassembly,
                       readback_across_sinks)


@dataclass
class DeepChainResult:
    bypass: Optional[dict] = None           # chosen bypass technique + fragments
    readback: Optional[ReadbackReport] = None
    execution: str = "untested"             # served_raw | neutralised | not_reflected | untested
    execution_reason: str = ""
    exploit: Optional[ExploitAssessment] = None
    steps: list[str] = field(default_factory=list)

    def summary(self) -> dict:
        return {
            "bypass": self.bypass,
            "execution": self.execution,
            "execution_reason": self.execution_reason,
            "readback": [
                {"sink": r.sink, "status": r.status, "render": r.classification,
                 "dangerous": r.dangerous}
                for r in (self.readback.results if self.readback else [])
            ],
            "exploit": self.exploit.to_dict() if self.exploit else None,
            "steps": self.steps,
        }

    def verdict(self) -> tuple[str, str, str]:
        """(verdict, exploitability, headline) — feeds a Finding.

        Two axes, kept separate on purpose:
          * DID IT EXECUTE — only a raw render in an HTML sink (served_raw_html)
            proves execution; raw in a JSON API (served_raw_api) is a precondition
            whose execution still needs an HTML render sink confirmed.
          * WHAT CAN IT REACH — the exploitability assessment of the target
            privileged endpoint (session-ridable? etc.), which sets severity.
        """
        weap = self.exploit and self.exploit.verdict == "weaponizable"
        contained = self.exploit and self.exploit.verdict == "contained"

        if self.execution == "served_raw_html":
            if weap:
                return ("true_positive", "exploitable",
                        "stored XSS EXECUTES in an authenticated HTML surface AND can "
                        "drive a privileged action: " + "; ".join(self.exploit.reasons[:2]))
            if contained:
                return ("true_positive", "conditional",
                        "stored XSS executes in an authenticated surface, but the app's "
                        "credential handling blocks the privileged action: "
                        + "; ".join(self.exploit.reasons[:2]))
            return ("true_positive", "conditional",
                    "stored XSS executes in an authenticated surface; privileged-action "
                    "reach needs manual confirmation")

        if self.execution == "served_raw_api":
            # filter beaten + value served raw, but no HTML sink was rendered here
            # (headless can't run the DOM). Severity is driven by whether the target
            # is reachable IF it renders — which is the amplifier.
            if weap:
                return ("likely_true_positive", "conditional",
                        "input filter beaten (field-split) and value STORED+SERVED RAW; "
                        "the privileged endpoint is session-ridable, so this is "
                        "RCE-grade IF the value renders unescaped in any admin HTML "
                        "surface — confirm that one render (browser). "
                        + "; ".join(self.exploit.reasons[:1]))
            return ("likely_true_positive", "conditional",
                    "input filter beaten and value stored+served raw (stored-XSS "
                    "precondition); confirm an unescaped admin HTML render to complete "
                    "the proof")

        if self.execution == "neutralised":
            return ("likely_false_positive", "not_exploitable",
                    "stored value is echoed but escaped/stripped in every surface "
                    "tested — not an executable stored XSS")
        if self.execution == "not_reflected":
            return ("inconclusive", "unknown",
                    "stored value was not echoed back by any surface tested")
        return ("inconclusive", "unknown", "chain not fully exercised")


class DeepStoredXssChain:
    """Drives the 5-step chain with injected I/O.

    write(field_values: dict[str,str]) -> None
    fetch(path: str) -> (status:int, body:str)
    restore() -> None
    auth_probe(vector: str) -> status:int        # for the privileged endpoint
    """

    def __init__(self, *, fields: list[str], read_sinks: list[tuple[str, str]],
                 write: Callable[[dict], None], fetch: Callable[[str], tuple[int, str]],
                 restore: Callable[[], None],
                 html_sinks: Optional[set[str]] = None,
                 separator: str = " ", filter_regex: str = TARGET_XSS_REGEX):
        self.fields = fields
        self.read_sinks = read_sinks
        self.write = write
        self.fetch = fetch
        self.restore = restore
        self.html_sinks = html_sinks
        self.separator = separator
        self.filter_regex = filter_regex

    def run(self, *, marker_url: str,
            target_endpoint: str = "",
            auth_probe: Optional[Callable[[str], int]] = None,
            set_cookie_lines: Optional[list[str]] = None,
            storage_tokens: Optional[list[str]] = None) -> DeepChainResult:
        res = DeepChainResult()
        markup = marker_img(marker_url)

        # 1) BYPASS: prefer a verified field-split that beats the real filter.
        plan: Optional[SplitPlan] = split_for_concat(
            markup, separator=self.separator, max_fields=len(self.fields),
            filter_regex=self.filter_regex)
        if plan:
            res.bypass = {"technique": "field-split", "fields": plan.fragments,
                          "separator": self.separator, "reassembled": plan.reassembled,
                          "evades_filter": True,
                          "attr_safe": is_attr_unquoted_safe(markup)}
            fragments = plan.fragments
            res.steps.append(f"filter bypass: split into {len(fragments)} field(s), "
                             f"each evades {self.filter_regex!r}")
        else:
            # fall back to the strongest single-field mutation
            muts = mutations(markup, separators=(self.separator,),
                             max_fields=len(self.fields), filter_regex=self.filter_regex)
            best = muts[0]
            res.bypass = best
            fragments = best["fields"]
            res.steps.append(f"no field-split beat the filter; using "
                             f"{best['technique']} (evades={best['evades_filter']})")

        # map fragments onto the available fields (pad the rest empty)
        field_values = {f: "" for f in self.fields}
        for fld, frag in zip(self.fields, fragments):
            field_values[fld] = frag

        try:
            # 2) STORE
            self.write(field_values)
            res.steps.append(f"stored fragments into {list(field_values)}")

            # 3) READ BACK across every sink
            res.readback = readback_across_sinks(
                markup, self.read_sinks, self.fetch, html_sinks=self.html_sinks)
            state, reason = res.readback.verdict()
            res.execution, res.execution_reason = state, reason
            res.steps.append(f"read-back across {len(self.read_sinks)} sink(s): {state}")

            # 4) WEAPONIZE? whenever the value is served raw (executes, or precondition
            # met) — the target's reachability is what sets severity either way.
            if state in ("served_raw_html", "served_raw_api") and target_endpoint and auth_probe:
                auth = probe_auth_matrix(target_endpoint, auth_probe)
                creds = CredentialSurface(
                    cookies=analyze_set_cookie(set_cookie_lines or []),
                    storage_tokens=list(storage_tokens or []))
                res.exploit = assess_privileged_action_via_xss(auth, creds)
                res.steps.append(f"weaponizability vs {target_endpoint}: "
                                 f"{res.exploit.verdict}")
        finally:
            try:
                self.restore()
                res.steps.append("restored stored value")
            except Exception as exc:
                res.steps.append(f"RESTORE FAILED: {str(exc)[:120]}")
        return res
