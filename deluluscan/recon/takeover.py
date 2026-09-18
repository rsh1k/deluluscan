"""Subdomain takeover detection (dangling-DNS fingerprints).

When a subdomain's DNS still points (CNAME) at a third-party service that no
longer hosts it — an unclaimed S3 bucket, a deleted GitHub Pages site, a released
Heroku app — an attacker can register that resource and serve content on the
victim's subdomain. Recon already enumerates subdomains (crt.sh); this checks each
live one for the tell-tale "unclaimed resource" response of a known provider.

Data-driven: each `TakeoverSig` is (provider, body/CNAME markers, confidence).
Detection only — we fingerprint the dangling response, we never claim the
resource. Grounded in the public can-i-take-over-xyz corpus.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional

from ..models import Finding, RequestRecord, Severity, VulnClass


@dataclass
class TakeoverSig:
    provider: str
    body_re: str                     # unclaimed-resource marker in the HTTP body
    cname_re: str = ""               # provider CNAME target (corroborating)
    confidence: str = "firm"         # firm | tentative (some providers are ambiguous)


# The high-signal subset of the can-i-take-over-xyz fingerprints.
TAKEOVER_SIGS: list[TakeoverSig] = [
    TakeoverSig("AWS S3", r"(?i)NoSuchBucket|The specified bucket does not exist",
                r"s3[.-][\w.-]*amazonaws\.com"),
    TakeoverSig("GitHub Pages", r"(?i)There isn't a GitHub Pages site here|404.*not found",
                r"github\.io", confidence="tentative"),
    TakeoverSig("Heroku", r"(?i)No such app|herokucdn\.com/error-pages/no-such-app",
                r"herokuapp\.com|herokudns\.com"),
    TakeoverSig("Amazon CloudFront", r"(?i)The request could not be satisfied|ERROR: The request could not",
                r"cloudfront\.net", confidence="tentative"),
    TakeoverSig("Fastly", r"(?i)Fastly error: unknown domain", r"fastly\.net"),
    TakeoverSig("Shopify", r"(?i)Sorry, this shop is currently unavailable", r"myshopify\.com"),
    TakeoverSig("Bitbucket", r"(?i)Repository not found", r"bitbucket\.io"),
    TakeoverSig("Ghost", r"(?i)The thing you were looking for is no longer here",
                r"ghost\.io"),
    TakeoverSig("Pantheon", r"(?i)The gods are wise|404 error unknown site", r"pantheonsite\.io"),
    TakeoverSig("Tumblr", r"(?i)Whatever you were looking for doesn't currently exist",
                r"domains\.tumblr\.com"),
    TakeoverSig("Surge.sh", r"(?i)project not found", r"surge\.sh"),
    TakeoverSig("Zendesk", r"(?i)Help Center Closed|this help center no longer exists",
                r"zendesk\.com", confidence="tentative"),
    TakeoverSig("Readthedocs", r"(?i)unknown to Read the Docs", r"readthedocs\.io"),
    TakeoverSig("Netlify", r"(?i)Not Found - Request ID|Not found.*netlify",
                r"netlify\.(app|com)", confidence="tentative"),
]


def classify(body: str, cname: str = "") -> Optional[TakeoverSig]:
    """Return the matching takeover signature for a dangling response, or None."""
    body = body or ""
    for sig in TAKEOVER_SIGS:
        if re.search(sig.body_re, body):
            # if we have the CNAME, require it to corroborate (kills body-only FPs)
            if cname and sig.cname_re and not re.search(sig.cname_re, cname):
                continue
            return sig
    return None


def provider_for_cname(cname: str) -> Optional[TakeoverSig]:
    """The claimable-service signature a CNAME target belongs to, or None."""
    cname = cname or ""
    for sig in TAKEOVER_SIGS:
        if sig.cname_re and re.search(sig.cname_re, cname):
            return sig
    return None


def _default_resolve_cname(host: str) -> str:
    """Best-effort CNAME target of a host. Uses dnspython when present (the only
    way to read a CNAME whose *target* no longer resolves — the dangling case);
    fails soft to '' otherwise, so the fingerprint path still runs."""
    try:
        import dns.resolver  # type: ignore
        ans = dns.resolver.resolve(host, "CNAME", raise_on_no_answer=False)
        return str(ans[0].target).rstrip(".") if ans and len(ans) else ""
    except Exception:
        return ""


def check_dangling(subdomains: list, *, resolve_cname: Callable, resolve_host: Callable,
                   max_checks: int = 40) -> list:
    """A CNAME still pointing at a target that NO LONGER RESOLVES is claimable even
    with no HTTP fingerprint — the classic 'CNAME to a deleted S3 bucket / released
    Heroku app'. The dangling response never loads, so `check_subdomains` misses it;
    this catches it from DNS alone. HIGH+firm when the dead target is a known
    claimable service, MEDIUM+tentative for a generic non-resolving external target.
    """
    out: list = []
    checked = 0
    for entry in subdomains:
        if checked >= max_checks:
            break
        name = entry.get("name") if isinstance(entry, dict) else entry
        if not name:
            continue
        checked += 1
        try:
            cname = (resolve_cname(name) or "").strip().lower()
        except Exception:
            cname = ""
        if not cname or cname.rstrip(".") == name.rstrip("."):
            continue                              # no CNAME (an A record is not dangling here)
        try:
            if resolve_host(cname):
                continue                          # target still lives -> not dangling
        except Exception:
            continue                              # can't tell -> don't guess
        sig = provider_for_cname(cname)
        rec = RequestRecord(method="DNS", url=name, identity="anon", status=0,
                            elapsed_ms=0.0, resp_body=f"CNAME {name} -> {cname} (NXDOMAIN)",
                            resp_len=0)
        if sig:
            out.append(Finding(
                vuln_class=VulnClass.MISCONFIG, severity=Severity.HIGH,
                title=f"Dangling DNS takeover: {name} ({sig.provider})",
                endpoint=name,
                description=(f"{name} has a CNAME to {cname} — a {sig.provider} resource that "
                             "no longer resolves. The DNS record still delegates the subdomain "
                             "to a service where the resource has been released, so an attacker "
                             "can register it and serve content on this subdomain (phishing, "
                             "cookie theft, OAuth-redirect abuse). No live response to fingerprint "
                             "— the takeover is inferred from the dangling delegation."),
                evidence=[rec], confidence="firm", verdict="likely_true_positive",
                exploitability="conditional",
                detail={"subdomain": name, "provider": sig.provider, "cname": cname,
                        "dangling": True, "source": "recon.takeover",
                        "remediation": ("Delete the dangling CNAME, or reclaim the resource on "
                                        f"{sig.provider} before an attacker does.")}))
        else:
            out.append(Finding(
                vuln_class=VulnClass.MISCONFIG, severity=Severity.MEDIUM,
                title=f"Dangling CNAME (non-resolving target): {name}",
                endpoint=name,
                description=(f"{name} has a CNAME to {cname}, which does not resolve. A dangling "
                             "delegation to an external target can be a takeover if that target "
                             "is claimable — verify whether the CNAME points at a registrable "
                             "resource before reporting."),
                evidence=[rec], confidence="tentative", verdict="inconclusive",
                exploitability="conditional",
                detail={"subdomain": name, "cname": cname, "dangling": True,
                        "source": "recon.takeover",
                        "remediation": "Remove the dangling CNAME or confirm the target is not "
                                       "claimable; monitor for CNAMEs to retired services."}))
    return out


def check_all(fetch: Callable, subdomains: list, *, resolve_cname=None,
              resolve_host=None, max_checks: int = 40) -> list:
    """Both takeover paths — live unclaimed-resource fingerprints and dangling
    (NXDOMAIN-target) CNAMEs — deduplicated to at most one finding per subdomain
    (the fingerprint path wins, being a live confirmation)."""
    resolve_cname = resolve_cname or _default_resolve_cname
    findings = check_subdomains(fetch, subdomains, resolve_cname=resolve_cname,
                                max_checks=max_checks)
    if resolve_host is not None:
        seen = {f.detail.get("subdomain") for f in findings}
        for f in check_dangling(subdomains, resolve_cname=resolve_cname,
                                resolve_host=resolve_host, max_checks=max_checks):
            if f.detail.get("subdomain") not in seen:
                findings.append(f)
    return findings


def check_subdomains(fetch: Callable, subdomains: list, *, resolve_cname=None,
                     max_checks: int = 40) -> list:
    """subdomains: list[{name, live}]. fetch(url)->(status,headers,body).
    resolve_cname(name)->str is optional (corroborates the provider). Returns Findings."""
    out: list = []
    checked = 0
    for entry in subdomains:
        if checked >= max_checks:
            break
        name = entry.get("name") if isinstance(entry, dict) else entry
        if not name:
            continue
        # only worth checking ones that resolve; if liveness unknown, still try
        if isinstance(entry, dict) and entry.get("live") is False:
            continue
        checked += 1
        cname = ""
        if resolve_cname:
            try:
                cname = resolve_cname(name) or ""
            except Exception:
                cname = ""
        try:
            status, headers, body = fetch(f"http://{name}/")
        except Exception:
            continue
        sig = classify(body, cname)
        if sig is None:
            continue
        rec = RequestRecord(method="GET", url=f"http://{name}/", identity="anon",
                            status=status, elapsed_ms=0.0, resp_body=(body or "")[:800],
                            resp_len=len(body or ""))
        sev = Severity.HIGH if sig.confidence == "firm" else Severity.MEDIUM
        out.append(Finding(
            vuln_class=VulnClass.MISCONFIG, severity=sev,
            title=f"Possible subdomain takeover: {name} ({sig.provider})",
            endpoint=name,
            description=(f"{name} appears to point at an unclaimed {sig.provider} resource"
                         + (f" (CNAME {cname})" if cname else "")
                         + ". An attacker who registers that resource can serve content on this "
                         "subdomain (phishing, cookie theft, OAuth-redirect abuse). "
                         + ("Confirmed unclaimed-resource fingerprint." if sig.confidence == "firm"
                            else "Fingerprint is ambiguous — verify manually before reporting.")),
            evidence=[rec], confidence=sig.confidence,
            verdict="likely_true_positive" if sig.confidence == "firm" else "inconclusive",
            exploitability="conditional",
            detail={"subdomain": name, "provider": sig.provider, "cname": cname,
                    "source": "recon.takeover",
                    "remediation": ("Remove the dangling DNS record, or reclaim the referenced "
                                    "resource on the provider before an attacker does; "
                                    "continuously monitor for dangling CNAMEs to retired services.")}))
    return out
