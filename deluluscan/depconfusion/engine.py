"""DepConfusionScan — flag dependencies absent from their public registry."""
from __future__ import annotations

from typing import Callable, Optional

from ..models import Finding, RequestRecord, Severity, VulnClass
from .parsers import scan_tree, Dependency

# packages that are namespaced/first-party-ish and safe to skip lookups for
_NPM_PUBLIC_HINT = ("@types/", "@babel/", "@vitejs/", "@testing-library/", "@tailwindcss/")


def _default_registry_check(ecosystem: str, name: str, timeout: int = 8) -> Optional[bool]:
    """True=exists on public registry, False=absent, None=unknown (network/other)."""
    import urllib.request
    import urllib.parse
    urls = {
        "npm": f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@/')}",
        "pip": f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json",
        "composer": f"https://repo.packagist.org/p2/{urllib.parse.quote(name, safe='/')}.json",
        "rubygems": f"https://rubygems.org/api/v1/gems/{urllib.parse.quote(name)}.json",
    }
    url = urls.get(ecosystem)
    if not url:
        return None
    try:
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": "deluluscan-depconf"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return 200 <= r.status < 300
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False            # definitively not published
        return None                 # 403/5xx/rate-limit -> unknown, don't flag
    except Exception:
        return None


class DepConfusionScan:
    def __init__(self, registry_check: Optional[Callable] = None, max_lookups: int = 200):
        self.registry_check = registry_check or _default_registry_check
        self.max_lookups = max_lookups

    def scan_path(self, root: str) -> list:
        deps, private = scan_tree(root)
        return self._assess(deps, private)

    def _assess(self, deps: list, private_registries: list) -> list:
        out: list = []
        has_private = bool(private_registries)
        checked = 0
        for d in deps:
            if checked >= self.max_lookups:
                break
            if d.ecosystem == "npm" and d.name.startswith(_NPM_PUBLIC_HINT):
                continue
            checked += 1
            exists = self.registry_check(d.ecosystem, d.name)
            if exists is not False:      # True or None -> not a confirmed finding
                continue
            sev = Severity.HIGH if has_private else Severity.MEDIUM
            rec = RequestRecord(method="GET", url=f"{d.ecosystem}:{d.name}", identity="anon",
                                status=404, elapsed_ms=0.0)
            desc = (f"'{d.name}' ({d.ecosystem}), declared in {d.manifest}, is NOT published on the "
                    f"public {d.ecosystem} registry. ")
            if has_private:
                desc += (f"A private registry is configured ({', '.join(private_registries[:2])}), so "
                         "this package resolves internally — an attacker who publishes a public "
                         "package of the same name (with a higher version) can hijack the build "
                         "(dependency confusion → build-time RCE).")
            else:
                desc += ("It may be an internal package (dependency-confusion candidate) or a typo. "
                         "Confirm whether it is meant to resolve from a private source, and reserve "
                         "the name on the public registry if so.")
            out.append(Finding(
                vuln_class=VulnClass.SUPPLY_CHAIN,
                severity=sev, title=f"Dependency confusion risk: {d.name} ({d.ecosystem})",
                endpoint=d.manifest, description=desc, evidence=[rec],
                confidence="firm" if has_private else "tentative",
                verdict="likely_true_positive" if has_private else "inconclusive",
                exploitability="conditional",
                detail={"package": d.name, "ecosystem": d.ecosystem, "manifest": d.manifest,
                        "public_registry": False, "private_registry_configured": has_private,
                        "private_registries": private_registries,
                        "remediation": ("Reserve the package name on the public registry, pin to a "
                                        "scoped/namespaced private name, and enforce registry "
                                        "allow-listing (e.g. scoped .npmrc, --index-url pinning)."),
                        "source": "depconfusion"}))
        return out
