"""Finding verification layer.

Scanners in deluluscan are *detectors*: they emit candidates. This package answers
the three questions a human triager would otherwise have to answer by hand:

  1. Is this candidate real, or a false positive? (corroborate with independent,
     benign signals; actively test the known FP confounders — error pages, WAF
     block pages, response jitter, static echoes.)
  2. What compensating / mitigating controls are in front of it? (CSP, WAF,
     nosniff, auth requirement, cookie flags, CORS credential rules.)
  3. Given those controls, is it actually exploitable — or only theoretical?

Design constraint (unchanged from the rest of the tool): verification is
DETECTION-ONLY. It re-issues the same class of benign probes the scanners
already send, adds *control* requests (a benign value, a bogus id) to rule out
false positives, and reasons about response/headers. It never weaponizes a
finding: no working XSS payload, no data-exfiltration query, no auth bypass, no
SSRF pivot. Where human confirmation is still required it emits a plain-language
manual reproduction step, not an exploit.
"""
from .verifier import Verifier
from .models import Verification, ControlObservation

__all__ = ["Verifier", "Verification", "ControlObservation"]
