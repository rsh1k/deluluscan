"""Vanity-URL redirect abuse — open redirect and server-side fetch.

the target vanity URLs map an incoming path to a target. The target is applied
without any host allowlist (VanityUrlAPIImpl), so:

  * action 301/302 with an off-host target is an OPEN REDIRECT that any visitor
    follows, usable for phishing and for stealing tokens carried in the URL.
  * action 200 with a target containing "//" makes the SERVER fetch the target
    and stream it to the client — an author-controlled server-side request,
    reachable anonymously through the vanity path.
  * Regex capture groups from the request URI are substituted into the target,
    so the requester controls part of it.

Who may author a vanity URL decides whether this is a vulnerability at all. On a
default 26.x instance the Vanityurl content type is admin-restricted
(content_editor, publisher, backend and readonly are all denied by content-type
permissions), which makes the missing host allowlist a defence-in-depth gap
rather than a privilege boundary failure. Where authoring IS delegated below
administrator it becomes a genuine open redirect, so this scanner tries the
least-privileged identity first and rates the finding by who succeeded.

This check must CREATE a vanity URL to prove the platform accepts an off-host
target. Everything it creates is registered with deluluscan.artifacts and removed
afterwards, with the removal verified — an abandoned open redirect would be a
live vulnerability introduced by the assessment itself.
"""
from __future__ import annotations

import json
from typing import Iterable, Optional

from ..artifacts import ArtifactRegistry
from ..models import Endpoint, Finding, Severity, VulnClass
from .base import Scanner, canary

# Deliberately unroutable and obviously ours, so a leaked artifact is
# identifiable and cannot silently serve real traffic anywhere useful.
_OFFHOST = "https://deluluscan-openredirect-probe.invalid/landing"


class VanityRedirectScanner(Scanner):
    """Prove whether the target accepts an off-host vanity redirect target."""

    name = "vanity_redirect"
    vuln_classes = [VulnClass.MISCONFIG.value, VulnClass.SSRF.value]

    def applies_to(self, endpoint: Endpoint) -> bool:
        # One probe per scan, anchored on the workflow fire endpoint used to
        # author content. Requires explicit permission to change state.
        return (endpoint.path.startswith("/api/v1/workflow/actions/default/fire")
                and getattr(self.config.scan, "allow_state_changing", False))

    # -- helpers ------------------------------------------------------------
    def _fire(self, label: str, action: str, body: Optional[dict] = None,
              params: Optional[dict] = None):
        ident = self.identities.get(label)
        if ident is None:
            return None
        headers = dict(self.auth.headers_for(ident))
        headers["Content-Type"] = "application/json"
        return self.client.request(
            "PUT", f"/api/v1/workflow/actions/default/fire/{action}",
            identity_label=label, headers=headers, params=params,
            data=json.dumps(body) if body is not None else None)

    def _site_id(self, label: str) -> Optional[str]:
        ident = self.identities.get(label)
        if ident is None:
            return None
        rec = self.client.request("GET", "/api/v1/site/currentSite",
                                  identity_label=label,
                                  headers=dict(self.auth.headers_for(ident)))
        if rec is None or rec.status != 200:
            return None
        try:
            return (json.loads(rec.resp_body or "{}").get("entity") or {}).get("identifier")
        except (ValueError, TypeError, AttributeError):
            return None

    def _identifier_of(self, rec) -> Optional[str]:
        if rec is None or not (200 <= rec.status < 300):
            return None
        try:
            body = json.loads(rec.resp_body or "{}")
        except (ValueError, TypeError):
            return None

        found: list[str] = []

        def walk(o):
            if isinstance(o, dict):
                if o.get("identifier"):
                    found.append(o["identifier"])
                for v in o.values():
                    walk(v)
            elif isinstance(o, list):
                for v in o:
                    walk(v)
        walk(body)
        return found[0] if found else None

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        site = self._site_id("admin") or next(
            (self._site_id(l) for l in self.identities if self._site_id(l)), None)
        if not site:
            return

        marker = canary("vr")
        uri = f"/deluluscan-vanity-{marker}"
        registry = ArtifactRegistry()
        findings: list[Finding] = []

        try:
            # Try the LEAST privileged author first. Who can create the redirect
            # decides whether this is a vulnerability or a hardening note: an
            # administrator authoring one is unremarkable (they can do anything),
            # whereas a content-editor doing so is a real privilege problem.
            created, author, denied = None, None, []
            for candidate in ("content_editor", "publisher", "backend", "readonly", "admin"):
                if candidate not in self.identities:
                    continue
                rec = self._fire(candidate, "PUBLISH", {
                    "contentlet": {"contentType": "Vanityurl",
                                   "title": f"deluluscan-probe-{marker}", "site": site,
                                   "uri": uri, "action": 302,
                                   "forwardTo": _OFFHOST, "order": 1}})
                if self._identifier_of(rec):
                    created, author = rec, candidate
                    break
                denied.append(candidate)
            ident_id = self._identifier_of(created)
            if not ident_id:
                return          # nobody could author one: nothing to report

            def _delete() -> bool:
                for act in ("UNPUBLISH", "ARCHIVE", "DELETE"):
                    self._fire("admin" if "admin" in self.identities else author,
                               act, params={"identifier": ident_id})
                return True

            def _gone() -> Optional[bool]:
                rec = self.client.request("GET", uri, identity_label="anonymous",
                                          headers={})
                return None if rec is None else rec.status not in (301, 302, 200)

            registry.track("vanityurl", ident_id,
                           description=f"probe vanity {uri} -> {_OFFHOST}",
                           delete=_delete, verify_gone=_gone,
                           manual_hint=(f"fire UNPUBLISH, ARCHIVE then DELETE on identifier "
                                        f"{ident_id} (PUT /api/v1/workflow/actions/default/"
                                        f"fire/DELETE?identifier={ident_id})"))

            # Does an unauthenticated visitor get redirected off-host?
            hit = self.client.request("GET", uri, identity_label="anonymous", headers={})
            location = ""
            if hit is not None:
                location = (hit.resp_headers or {}).get("Location") or \
                           (hit.resp_headers or {}).get("location") or ""
            if hit is not None and hit.status in (301, 302) and \
                    "deluluscan-openredirect-probe.invalid" in location:
                admin_only = (author == "admin")
                sev = Severity.LOW if admin_only else Severity.HIGH
                who = (
                    f"Only the administrator could author it — {', '.join(denied)} "
                    f"{'was' if len(denied) == 1 else 'were'} denied by content-type "
                    f"permissions. Authoring is therefore correctly restricted on this "
                    f"instance, so this is a defence-in-depth gap (no host allowlist on the "
                    f"target) rather than a privilege boundary failure. It becomes serious if "
                    f"vanity authoring is ever delegated below administrator."
                    if admin_only else
                    f"It was authored by the '{author}' identity, which is NOT an "
                    f"administrator, so anyone with that level of content rights can publish a "
                    f"redirect from a trusted site path to an arbitrary external origin.")
                findings.append(Finding(
                    vuln_class=VulnClass.MISCONFIG, severity=sev,
                    title=("Vanity URL accepts an off-host redirect target (open redirect)"
                           if not admin_only else
                           "Vanity URL targets are not restricted to the site's own hosts "
                           "(admin-only authoring)"),
                    endpoint="GET /{vanity-path}",
                    description=(
                        f"A vanity URL with an off-host target was served to an "
                        f"unauthenticated visitor as HTTP {hit.status} with Location: "
                        f"{location}. the target applies the configured target with no host "
                        f"allowlist. {who} Request-URI capture groups are also substituted "
                        f"into the target, so the visitor controls part of the destination."),
                    evidence=[r for r in (created, hit) if r],
                    detail={"test": "vanity_open_redirect", "probe_uri": uri,
                            "location": location, "authored_as": author,
                            "authoring_denied_to": denied,
                            "admin_only_authoring": admin_only,
                            "impact": ("Phishing from a trusted origin, and leakage of any "
                                       "token carried in the URL or Referer to an "
                                       "attacker-chosen host. With action=200 the same "
                                       "mechanism makes the server fetch the target and "
                                       "stream it, giving an author-controlled server-side "
                                       "request reachable anonymously."),
                            "remediation": ("Restrict vanity targets to the site's own hosts "
                                            "(or an explicit allowlist), and validate the "
                                            "result after capture-group substitution rather "
                                            "than before."),
                            "cwe": "CWE-601",
                            "auto_confirm": {
                                "confirmed": True, "kind": "differential_observation",
                                "exploitability": ("conditional" if admin_only
                                                   else "exploitable"),
                                "reason": (f"anonymous GET {uri} returned {hit.status} with "
                                           f"Location {location}; authored as '{author}'"),
                                "repro": (f"Author a Vanityurl with forwardTo set to an external "
                                          f"origin, then request its uri unauthenticated.")}},
                    confidence="firm", verdict="true_positive",
                    exploitability=("conditional" if admin_only else "exploitable")))
        finally:
            report = registry.cleanup()
            if not report["clean"]:
                # Never leave this silent: the tool created a live open redirect.
                findings.append(Finding(
                    vuln_class=VulnClass.MISCONFIG, severity=Severity.HIGH,
                    title="Scan artifact could not be removed (assessment left an object behind)",
                    endpoint="(scanner)",
                    description=("This scanner created content to prove a finding and could not "
                                 "remove it afterwards. The object was introduced by the "
                                 "assessment and may itself be exploitable. "
                                 + " ".join(report.get("messages", []))),
                    evidence=[],
                    detail={"test": "artifact_leak", "artifacts": report["artifacts"]},
                    confidence="firm", verdict="true_positive",
                    exploitability="exploitable"))

        yield from findings
