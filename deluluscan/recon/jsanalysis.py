"""Static JS endpoint extraction — the AJAX-spider's payoff without a browser.

Modern SPAs hide most of their API surface behind client-side code, so a
path-wordlist never sees it. Rather than drive a headless browser (heavy, and
untestable offline), this statically parses JavaScript — inline scripts and
linked bundles — for the endpoints the client calls: fetch()/axios/$.ajax/
XMLHttpRequest targets, and API-shaped path literals. It recovers the "shadow"
surface (OWASP API9: improper inventory) that isn't in the OpenAPI spec.

Pure string analysis, no execution. Template-literal params like `/users/${id}`
are normalized to `/users/{id}`. Offline-testable: give it JS text.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# fetch("...") / fetch(`...`)  and axios("..."), axios.get("..."), etc.
_FETCH = re.compile(r"""\bfetch\s*\(\s*['"`]([^'"`]+)['"`]""")
_AXIOS = re.compile(r"""\baxios\s*(?:\.\s*(get|post|put|patch|delete|head|options)\s*)?\(\s*['"`]([^'"`]+)['"`]""", re.I)
# $.ajax({url:"..."}), $.get("..."), $.post("...")
_JQ_AJAX_URL = re.compile(r"""\.\s*ajax\s*\(\s*\{[^}]*?\burl\s*:\s*['"`]([^'"`]+)['"`]""", re.I | re.S)
_JQ_SHORT = re.compile(r"""\$\s*\.\s*(get|post|getJSON)\s*\(\s*['"`]([^'"`]+)['"`]""", re.I)
# XMLHttpRequest: x.open("GET", "...")
_XHR = re.compile(r"""\.\s*open\s*\(\s*['"`]([A-Z]+)['"`]\s*,\s*['"`]([^'"`]+)['"`]""")
# bare API-shaped path literals: "/api/...", "/v1/...", "/graphql", "/rest/..."
_API_PATH = re.compile(r"""['"`](/(?:api|rest|graphql|v\d+|internal|admin|auth|oauth|users?|account|search|upload|webhook)s?(?:/[A-Za-z0-9_\-./${}:]*)?)['"`]""")

_TEMPLATE_PARAM = re.compile(r"\$\{[^}]+\}")
_METHOD_HINT = re.compile(r"(?i)\b(get|post|put|patch|delete)\b")


@dataclass
class JsEndpoint:
    path: str
    method: str = ""          # inferred when the call carries one
    kind: str = ""            # fetch | axios | jquery | xhr | literal
    evidence: str = ""


def _normalize(path: str) -> str:
    # collapse template-literal params and JS concatenation markers to {param}
    path = _TEMPLATE_PARAM.sub("{param}", path)
    path = path.split("?", 1)[0].split("#", 1)[0]
    return path.strip()


def _plausible(path: str) -> bool:
    if not path or len(path) > 200:
        return False
    # keep root-relative or absolute-URL API-ish targets; drop assets & junk
    if not (path.startswith("/") or re.match(r"https?://", path)):
        return False
    if re.search(r"\.(?:js|css|png|jpe?g|gif|svg|woff2?|ttf|ico|map|mp4|webp)(?:$|[?#])", path, re.I):
        return False
    if path in ("/", "//") or path.startswith("//") and "." not in path.split("/")[2:3][:1] and False:
        return False
    return True


def extract_endpoints(js_text: str, *, source: str = "") -> list:
    """Return de-duplicated JsEndpoint[] found in one blob of JS/HTML-inline JS."""
    if not js_text:
        return []
    found: dict[tuple, JsEndpoint] = {}
    seen_paths: set = set()

    def add(path, method, kind, ev):
        path = _normalize(path)
        if not _plausible(path):
            return
        # a bare "literal" match is only useful if nothing more specific (a real
        # fetch/axios/xhr call, which carries a method + call site) already found it
        if kind == "literal" and path in seen_paths:
            return
        key = (method.upper(), path)
        if key not in found:
            found[key] = JsEndpoint(path=path, method=method.upper(), kind=kind,
                                    evidence=(ev or "")[:120])
        seen_paths.add(path)

    for m in _FETCH.finditer(js_text):
        # try to infer method from a nearby method: "..." within the same call area
        seg = js_text[m.end():m.end() + 120]
        meth = ""
        mm = re.search(r"""method\s*:\s*['"`]([A-Za-z]+)['"`]""", seg)
        if mm:
            meth = mm.group(1)
        add(m.group(1), meth, "fetch", m.group(0))
    for m in _AXIOS.finditer(js_text):
        add(m.group(2), m.group(1) or "", "axios", m.group(0))
    for m in _JQ_AJAX_URL.finditer(js_text):
        add(m.group(1), "", "jquery", m.group(0)[:80])
    for m in _JQ_SHORT.finditer(js_text):
        meth = "POST" if m.group(1).lower() == "post" else "GET"
        add(m.group(2), meth, "jquery", m.group(0))
    for m in _XHR.finditer(js_text):
        add(m.group(2), m.group(1), "xhr", m.group(0))
    for m in _API_PATH.finditer(js_text):
        add(m.group(1), "", "literal", m.group(0))

    return list(found.values())
