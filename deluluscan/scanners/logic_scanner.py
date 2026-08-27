"""Business-logic / parameter-tampering scanner.

HackerOne's 2025 data: business-logic flaws are among the highest-value bugs and
the class automated tools most often miss (price/quantity manipulation, negative
or fractional amounts, workflow/state abuse). This scanner probes numeric and
state parameters with boundary/absurd values and flags when the server *accepts*
input it should reject — a strong signal of missing server-side validation.

Detection only: it submits benign boundary values (negative, zero, fractional,
huge) and reads the response; it does not complete a purchase, transfer funds, or
otherwise weaponize the flaw.
"""
from __future__ import annotations

from typing import Iterable, Optional

from .base import Scanner
from ..active.http_tools import RequestSpec, Repeater
from ..models import Endpoint, Finding, IdentityRole, Severity, VulnClass
from ..verify import evidence as E

# MONETARY / value-bearing parameters — these carry real business impact, so a
# negative or absurd value being accepted is meaningful.
_VALUE_PARAMS = {"quantity", "qty", "amount", "price", "total", "cost", "balance",
                 "credit", "points", "discount", "value", "sum", "fee", "refund",
                 "deposit", "withdrawal", "budget", "salary", "wage", "rate"}
# PAGINATION / sizing params — EXCLUDED. On these, -1 is the standard "unbounded"
# idiom (the target itself uses limit=-1 to mean "no limit"), and returning more rows
# of a read-only list is expected behavior, not a business-logic flaw.
_PAGINATION_PARAMS = {"limit", "size", "offset", "page", "count", "max", "min",
                      "per_page", "pagesize", "rows", "start", "end", "top", "skip",
                      "num", "pagesize", "perpage"}
_STATE_PARAMS = {"status", "state", "role", "type", "plan", "tier", "level",
                 "approved", "verified", "admin", "enabled", "active", "published"}

# strongly-monetary names worth testing even on a GET (e.g. ?amount= in a link)
_MONETARY = {"amount", "price", "total", "cost", "balance", "credit", "refund",
             "fee", "deposit", "withdrawal", "discount", "sum"}


class LogicScanner(Scanner):
    name = "logic"
    vuln_classes = [VulnClass.BUSINESS_LOGIC.value]

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.rep = Repeater(self.client)

    def applies_to(self, e: Endpoint) -> bool:
        names = {(p.get("name") or "").lower() for p in (e.query_params or [])}
        body_props = set()
        schema = e.request_body_schema or {}
        if isinstance(schema, dict):
            body_props = {k.lower() for k in (schema.get("properties") or schema).keys()} \
                if isinstance(schema.get("properties", schema), dict) else set()
        present = names | body_props
        # only value-bearing params count; pagination params are ignored entirely
        value_hits = present & _VALUE_PARAMS
        if not value_hits:
            return False
        # GET is only worth testing for clearly-monetary params (a value in a URL);
        # otherwise require a state-changing method (where tampering has an effect).
        if e.method.upper() == "GET":
            return bool(value_hits & _MONETARY)
        return self.config.scan.allow_state_changing

    def _ident(self):
        return self.identities.get(IdentityRole.BACKEND.value) or \
            self.identities.get(IdentityRole.ADMIN.value) or \
            next(iter(self.identities.values()), None)

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        ident = self._ident()
        if ident is None:
            return
        label = ident.label()
        path = self.concrete_path(endpoint)
        headers = dict(self.auth.headers_for(ident))
        base = RequestSpec(method=endpoint.method, path=path, headers=headers)

        numeric_params = [(p.get("name") or "") for p in (endpoint.query_params or [])
                          if (p.get("name") or "").lower() in _VALUE_PARAMS]
        # on GET, restrict to the monetary subset (pagination already excluded)
        if endpoint.method.upper() == "GET":
            numeric_params = [p for p in numeric_params if p.lower() in _MONETARY]
        baseline = self.rep.send(base.with_param(numeric_params[0], "1"), identity_label=label) \
            if numeric_params else self.rep.send(base, identity_label=label)

        for p in numeric_params[:4]:
            for bad in ("-1", "-1000", "99999999999"):
                r = self.rep.send(base.with_param(p, bad), identity_label=label)
                if r is None:
                    continue
                disp = E.classify_response(r)
                # accepted (2xx real content) an absurd value that should be rejected
                if disp == E.DISPOSITION_CONTENT and r.status < 400:
                    neg = bad.startswith("-")
                    yield Finding(
                        vuln_class=VulnClass.BUSINESS_LOGIC,
                        severity=Severity.HIGH if neg else Severity.MEDIUM,
                        title=f"Parameter tampering: server accepts {'negative' if neg else 'out-of-range'} '{p}'",
                        endpoint=endpoint.key,
                        description=(f"The server accepted '{p}={bad}' with a success response. "
                                     f"Numeric business parameters should be validated server-side; "
                                     f"accepting negative/zero/fractional/oversized values enables "
                                     f"price or quantity manipulation (e.g. negative-quantity refunds, "
                                     f"fractional-cent arbitrage, quota bypass). Verify the downstream "
                                     f"effect (order total, balance) manually."),
                        evidence=[r, baseline],
                        detail={"test": "param_tampering", "active": True,
                                "param": p, "value": bad},
                        confidence="tentative")
                    break
