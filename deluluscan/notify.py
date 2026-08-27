"""deluluscan.notify — send a scan summary to Slack, Discord or email.

A scan that finishes at 03:00 in CI is only useful if someone learns about it.
This module posts a short, accurate summary to the channels a team already
watches.

What it deliberately does NOT do:

* **It never sends evidence.** A notification carries counts, titles, severities
  and a pointer to the report — never request/response bodies, never
  credentials, never the finding detail. Chat channels and mailboxes are
  broadly readable and frequently archived to third parties; the report itself
  stays where access is controlled. This is the same reasoning that keeps the
  published dashboard behind a passphrase.
* **It never counts an observation or a refuted candidate as a finding.** The
  headline number is the reported, exploitable set. A notification that says
  "23 findings" when 14 are documented false positives trains people to ignore
  it.
* **It never fails a scan.** Delivery problems are returned, not raised: losing
  a webhook must not lose the scan results.

Webhook URLs and SMTP passwords are read from the environment, never from the
results file or the repo:

    DELULUSCAN_SLACK_WEBHOOK     https://hooks.slack.com/services/...
    DELULUSCAN_DISCORD_WEBHOOK   https://discord.com/api/webhooks/...
    DELULUSCAN_SMTP_HOST / _PORT / _USER / _PASSWORD / _FROM / _TO
"""
from __future__ import annotations

import json
import os
import smtplib
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from email.message import EmailMessage

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_TIMEOUT = 15


@dataclass
class Summary:
    """The facts a notification is allowed to carry."""

    target: str = ""
    scan_date: str = ""
    reported: int = 0
    observations: int = 0
    refuted: int = 0
    by_severity: dict[str, int] = field(default_factory=dict)
    top_titles: list[str] = field(default_factory=list)
    report_url: str = ""
    coverage: str = ""

    def headline(self) -> str:
        if self.reported == 0:
            return "No exploitable vulnerabilities reported"
        bits = [f"{self.by_severity[s]} {s}" for s in SEVERITY_ORDER
                if self.by_severity.get(s)]
        return f"{self.reported} reported finding(s): " + ", ".join(bits)

    def as_text(self) -> str:
        lines = [f"Deluluscan scan — {self.target or 'target'}", self.headline()]
        if self.observations or self.refuted:
            lines.append(
                f"Also: {self.observations} observation(s) not counted as findings, "
                f"{self.refuted} candidate(s) refuted as false positives.")
        if self.coverage:
            lines.append(f"Coverage: {self.coverage}")
        if self.top_titles:
            lines.append("")
            lines += [f"  • {t}" for t in self.top_titles]
        if self.report_url:
            lines += ["", f"Report: {self.report_url}"]
        return "\n".join(lines)


def summarise(payload: dict, *, report_url: str = "", max_titles: int = 8) -> Summary:
    """Build a Summary from a results payload.

    Only findings in `meta.report_include` count as reported. When that key is
    absent (a raw, unadjudicated scan), everything that is not explicitly an
    observation or refuted counts — but the notification says so, because an
    unadjudicated count is a candidate count, not a finding count.
    """
    meta = payload.get("meta") or {}
    findings = payload.get("findings") or []
    include = set((meta.get("report_include") or {}).get("ids") or [])

    observations = [f for f in findings
                    if (f.get("detail") or {}).get("observation") and f["id"] not in include]
    refuted = [f for f in findings if (f.get("detail") or {}).get("refuted")]
    if include:
        reported = [f for f in findings if f.get("id") in include]
    else:
        reported = [f for f in findings
                    if not (f.get("detail") or {}).get("observation")
                    and not (f.get("detail") or {}).get("refuted")]

    by_sev: dict[str, int] = {}
    for f in reported:
        sev = (f.get("severity") or "info").lower()
        by_sev[sev] = by_sev.get(sev, 0) + 1

    ranked = sorted(reported, key=lambda f: SEVERITY_ORDER.index(
        (f.get("severity") or "info").lower())
        if (f.get("severity") or "info").lower() in SEVERITY_ORDER else 9)

    cov = meta.get("coverage") or {}
    coverage = ""
    if cov.get("endpoints_probed") and cov.get("endpoints_discovered"):
        coverage = (f"{cov['endpoints_probed']}/{cov['endpoints_discovered']} endpoints probed")

    return Summary(
        target=payload.get("target") or meta.get("target") or "",
        scan_date=payload.get("date") or "",
        reported=len(reported), observations=len(observations), refuted=len(refuted),
        by_severity=by_sev,
        top_titles=[f"[{(f.get('severity') or 'info').upper()}] {f.get('title', '')}"
                    for f in ranked[:max_titles]],
        report_url=report_url, coverage=coverage,
    )


# --------------------------------------------------------------------------
# transports
# --------------------------------------------------------------------------
def _post_json(url: str, body: dict) -> tuple[bool, str]:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            if 200 <= resp.status < 300:
                return True, f"delivered (HTTP {resp.status})"
            return False, f"HTTP {resp.status}"
    except urllib.error.HTTPError as exc:
        return False, f"HTTP {exc.code}: {exc.reason}"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def _colour(summary: Summary) -> str:
    if summary.by_severity.get("critical") or summary.by_severity.get("high"):
        return "#991B1B"
    if summary.reported:
        return "#A16207"
    return "#15803D"


def send_slack(summary: Summary, webhook: str | None = None) -> tuple[bool, str]:
    url = webhook or os.environ.get("DELULUSCAN_SLACK_WEBHOOK", "")
    if not url:
        return False, "no Slack webhook configured (DELULUSCAN_SLACK_WEBHOOK)"
    blocks = [
        {"type": "header",
         "text": {"type": "plain_text", "text": "Deluluscan scan complete"}},
        {"type": "section",
         "text": {"type": "mrkdwn",
                  "text": f"*{summary.headline()}*\n`{summary.target}`"}},
    ]
    context = []
    if summary.coverage:
        context.append(summary.coverage)
    if summary.observations or summary.refuted:
        context.append(f"{summary.observations} observations · "
                       f"{summary.refuted} refuted")
    if context:
        blocks.append({"type": "context",
                       "elements": [{"type": "mrkdwn", "text": " | ".join(context)}]})
    if summary.top_titles:
        blocks.append({"type": "section",
                       "text": {"type": "mrkdwn",
                                "text": "\n".join(f"• {t}" for t in summary.top_titles)}})
    if summary.report_url:
        blocks.append({"type": "section",
                       "text": {"type": "mrkdwn", "text": f"<{summary.report_url}|Open report>"}})
    return _post_json(url, {"text": summary.headline(),
                            "attachments": [{"color": _colour(summary), "blocks": blocks}]})


def send_discord(summary: Summary, webhook: str | None = None) -> tuple[bool, str]:
    url = webhook or os.environ.get("DELULUSCAN_DISCORD_WEBHOOK", "")
    if not url:
        return False, "no Discord webhook configured (DELULUSCAN_DISCORD_WEBHOOK)"
    fields = []
    if summary.coverage:
        fields.append({"name": "Coverage", "value": summary.coverage, "inline": True})
    if summary.observations or summary.refuted:
        fields.append({"name": "Not counted as findings",
                       "value": (f"{summary.observations} observations, "
                                 f"{summary.refuted} refuted"), "inline": True})
    if summary.top_titles:
        fields.append({"name": "Findings",
                       "value": "\n".join(f"• {t}" for t in summary.top_titles)[:1024]})
    embed = {
        "title": "Deluluscan scan complete",
        "description": f"**{summary.headline()}**\n`{summary.target}`",
        "color": int(_colour(summary).lstrip("#"), 16),
        "fields": fields,
    }
    if summary.report_url:
        embed["url"] = summary.report_url
    return _post_json(url, {"embeds": [embed]})


def send_email(summary: Summary, *, host: str | None = None, port: int | None = None,
               user: str | None = None, password: str | None = None,
               sender: str | None = None, recipients: list[str] | None = None,
               use_tls: bool = True) -> tuple[bool, str]:
    host = host or os.environ.get("DELULUSCAN_SMTP_HOST", "")
    if not host:
        return False, "no SMTP host configured (DELULUSCAN_SMTP_HOST)"
    port = int(port or os.environ.get("DELULUSCAN_SMTP_PORT", 587))
    user = user if user is not None else os.environ.get("DELULUSCAN_SMTP_USER", "")
    password = password if password is not None else os.environ.get("DELULUSCAN_SMTP_PASSWORD", "")
    sender = sender or os.environ.get("DELULUSCAN_SMTP_FROM", user or "deluluscan@localhost")
    if recipients is None:
        raw = os.environ.get("DELULUSCAN_SMTP_TO", "")
        recipients = [r.strip() for r in raw.split(",") if r.strip()]
    if not recipients:
        return False, "no recipients configured (DELULUSCAN_SMTP_TO)"

    msg = EmailMessage()
    msg["Subject"] = f"Deluluscan: {summary.headline()} — {summary.target}"
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg.set_content(summary.as_text())
    try:
        if use_tls:
            with smtplib.SMTP(host, port, timeout=_TIMEOUT) as srv:
                srv.starttls(context=ssl.create_default_context())
                if user:
                    srv.login(user, password)
                srv.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=_TIMEOUT) as srv:
                if user:
                    srv.login(user, password)
                srv.send_message(msg)
        return True, f"delivered to {len(recipients)} recipient(s)"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


CHANNELS = {"slack": send_slack, "discord": send_discord, "email": send_email}


def notify(payload: dict, channels: list[str], *, report_url: str = "",
           **kwargs) -> dict[str, tuple[bool, str]]:
    """Send the summary to each named channel.

    Returns {channel: (ok, message)}. Never raises: a scan must not be lost to
    a webhook outage.
    """
    summary = summarise(payload, report_url=report_url)
    results: dict[str, tuple[bool, str]] = {}
    for name in channels:
        key = name.lower().strip()
        fn = CHANNELS.get(key)
        if fn is None:
            results[key] = (False, f"unknown channel {name!r}; "
                                   f"known: {', '.join(sorted(CHANNELS))}")
            continue
        try:
            results[key] = fn(summary, **kwargs) if key != "email" else fn(summary)
        except Exception as exc:                     # belt and braces
            results[key] = (False, f"{type(exc).__name__}: {exc}")
    return results


def configured_channels() -> list[str]:
    """Channels with credentials present in the environment."""
    out = []
    if os.environ.get("DELULUSCAN_SLACK_WEBHOOK"):
        out.append("slack")
    if os.environ.get("DELULUSCAN_DISCORD_WEBHOOK"):
        out.append("discord")
    if os.environ.get("DELULUSCAN_SMTP_HOST") and os.environ.get("DELULUSCAN_SMTP_TO"):
        out.append("email")
    return out
