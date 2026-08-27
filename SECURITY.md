# Security Policy

Deluluscan is a security tool, so we take the security of the tool itself
seriously.

## Reporting a vulnerability

If you find a security vulnerability **in Deluluscan** (for example: a way to make
it send traffic outside its authorization boundary, an injection in how it parses
a target's response, a secret-redaction bypass, or unsafe handling of a scan
artifact), please report it privately:

- Use **[GitHub Security Advisories](https://github.com/rsh1k/deluluscan/security/advisories/new)**
  ("Report a vulnerability"), **or**
- Open a minimal issue asking for a private contact channel — **without** the
  vulnerability details.

Please **do not** open a public issue or PR that discloses the vulnerability
before it's fixed.

Include, if you can: affected version, a description, reproduction steps, and the
impact. We'll acknowledge your report, work on a fix, and credit you (if you'd
like) in the release notes.

## Scope

- **In scope:** the Deluluscan codebase, its published PyPI package, the dashboard
  build, and its documentation.
- **Out of scope:** vulnerabilities you discover **in a target** by running
  Deluluscan — those belong to that target's own disclosure process, and you must
  only test systems you are authorized to test.

## Supported versions

Deluluscan is pre-1.0 and moves quickly; fixes land on the latest release. Please
upgrade to the newest version (`pip install -U deluluscan`) before reporting.

## A note on responsible use

Deluluscan enforces an authorization boundary (loopback / RFC1918 by default) and
**confirms to proof but never weaponizes**. Using it — or any part of it — against
systems you do not own or have written permission to assess is prohibited and, in
most jurisdictions, illegal. Please test responsibly.
