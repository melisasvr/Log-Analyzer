"""
alerting.py — Email & Slack Alerting for Log Analyzer
Sends notifications when critical/high threats are detected.

Setup:
    Email → set SMTP credentials in environment variables (see below)
    Slack → paste your Slack Incoming Webhook URL

Environment variables for email:
    LOGSCAN_SMTP_HOST     SMTP server host     (default: smtp.gmail.com)
    LOGSCAN_SMTP_PORT     SMTP port            (default: 587)
    LOGSCAN_SMTP_USER     Your email address
    LOGSCAN_SMTP_PASS     Your app password (Gmail: create at myaccount.google.com/apppasswords)
    LOGSCAN_FROM_EMAIL    Sender address       (defaults to SMTP user)

Quick start (Gmail example):
    export LOGSCAN_SMTP_USER="you@gmail.com"
    export LOGSCAN_SMTP_PASS="your-app-password"
    python cli.py --file access.log --alert-email admin@yourcompany.com

Slack quick start:
    1. Go to https://api.slack.com/apps → Create App → Incoming Webhooks
    2. Enable Incoming Webhooks → Add to Workspace → Copy webhook URL
    python cli.py --file access.log --alert-slack https://hooks.slack.com/services/T.../B.../...
"""

import os
import json
import smtplib
import urllib.request
import urllib.error
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# SEVERITY ORDER
# ─────────────────────────────────────────────────────────────────────────────
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

SEV_EMOJI = {
    "CRITICAL": "🚨",
    "HIGH":     "🔴",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
}

SEV_COLOR = {
    "CRITICAL": "#FF2D55",
    "HIGH":     "#FF6B35",
    "MEDIUM":   "#FFC13D",
    "LOW":      "#4ADE80",
}


# ─────────────────────────────────────────────────────────────────────────────
# ALERT FORMATTER
# ─────────────────────────────────────────────────────────────────────────────
class AlertFormatter:
    """Builds alert messages for both email and Slack."""

    @staticmethod
    def build_subject(result: dict) -> str:
        counts = result["alert_counts"]
        c = counts.get("CRITICAL", 0)
        h = counts.get("HIGH", 0)
        source = os.path.basename(result["source"])

        if c > 0:
            return f"🚨 [CRITICAL] LogScan: {c} critical threat(s) in {source}"
        elif h > 0:
            return f"🔴 [HIGH] LogScan: {h} high threat(s) in {source}"
        else:
            return f"⚠️ LogScan: Threats detected in {source}"

    @staticmethod
    def build_html_email(result: dict, filtered_alerts: list) -> str:
        """Builds a styled HTML email body."""
        counts = result["alert_counts"]
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        source = result["source"]

        # Summary pills
        pills_html = ""
        for sev in SEVERITY_ORDER:
            c = counts.get(sev, 0)
            if c:
                color = SEV_COLOR[sev]
                pills_html += f"""
                <span style="background:{color};color:#fff;padding:4px 12px;
                             border-radius:12px;font-size:13px;font-weight:bold;
                             margin-right:6px">{SEV_EMOJI[sev]} {sev}: {c}</span>"""

        # Alert rows
        alert_rows = ""
        for a in filtered_alerts[:20]:  # Cap at 20 in email
            color = SEV_COLOR.get(a.severity, "#888")
            evidence_html = ""
            if a.evidence:
                ev_items = "".join(
                    f"<li style='color:#888;font-size:12px;font-family:monospace'>"
                    f"{str(e)[:120]}</li>"
                    for e in a.evidence[:3]
                )
                evidence_html = f"<ul style='margin:6px 0 0 0;padding-left:20px'>{ev_items}</ul>"

            ts_str = a.timestamp.strftime("%H:%M:%S") if a.timestamp else "N/A"
            alert_rows += f"""
            <tr>
              <td style="padding:12px 16px;border-bottom:1px solid #1e2d42;vertical-align:top">
                <span style="background:{color};color:#fff;padding:2px 8px;
                             border-radius:4px;font-size:11px;font-weight:bold">
                  {a.severity}
                </span>
              </td>
              <td style="padding:12px 16px;border-bottom:1px solid #1e2d42;vertical-align:top">
                <span style="color:#00d4ff;font-size:11px;letter-spacing:1px">
                  {a.category.replace("_", " ")}
                </span><br>
                <span style="color:#c8d8e8;font-size:13px">{a.description}</span>
                {evidence_html}
              </td>
              <td style="padding:12px 16px;border-bottom:1px solid #1e2d42;
                         color:#4a6278;font-size:12px;white-space:nowrap;vertical-align:top">
                {a.ip or "N/A"}<br>{ts_str}
              </td>
            </tr>"""

        more_note = ""
        if len(filtered_alerts) > 20:
            more_note = f"<p style='color:#4a6278;font-size:12px;text-align:center'>... and {len(filtered_alerts)-20} more alerts</p>"

        return f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#090d13;font-family:'Segoe UI',Arial,sans-serif">
  <div style="max-width:680px;margin:0 auto;padding:32px 16px">

    <!-- Header -->
    <div style="background:linear-gradient(135deg,#0f1520,#162030);
                border:1px solid #1e2d42;border-radius:12px;
                padding:28px 32px;margin-bottom:20px;
                border-top:3px solid #00d4ff">
      <h1 style="color:#fff;font-size:22px;margin:0 0 6px 0">
        🔍 LogScan Alert Report
      </h1>
      <p style="color:#4a6278;font-size:13px;margin:0">
        {ts} &nbsp;·&nbsp; Source: <code style="color:#00d4ff">{source}</code>
      </p>
    </div>

    <!-- Stats -->
    <div style="background:#0f1520;border:1px solid #1e2d42;border-radius:12px;
                padding:20px 32px;margin-bottom:20px">
      <p style="color:#4a6278;font-size:11px;letter-spacing:2px;
                text-transform:uppercase;margin:0 0 12px 0">SUMMARY</p>
      <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px">
        {pills_html}
      </div>
      <table style="color:#c8d8e8;font-size:13px;border-collapse:collapse;width:100%">
        <tr>
          <td style="padding:4px 16px 4px 0;color:#4a6278">Total Lines</td>
          <td style="font-weight:bold">{result['total_lines']}</td>
          <td style="padding:4px 16px;color:#4a6278">Unique IPs</td>
          <td style="font-weight:bold">{result['unique_ips']}</td>
        </tr>
        <tr>
          <td style="padding:4px 16px 4px 0;color:#4a6278">Parsed Entries</td>
          <td style="font-weight:bold">{result['parsed_entries']}</td>
          <td style="padding:4px 16px;color:#4a6278">Total Alerts</td>
          <td style="font-weight:bold">{len(filtered_alerts)}</td>
        </tr>
      </table>
    </div>

    <!-- Alerts table -->
    <div style="background:#0f1520;border:1px solid #1e2d42;border-radius:12px;
                overflow:hidden;margin-bottom:20px">
      <div style="padding:16px 24px;border-bottom:1px solid #1e2d42">
        <p style="color:#4a6278;font-size:11px;letter-spacing:2px;
                  text-transform:uppercase;margin:0">ALERTS</p>
      </div>
      <table style="width:100%;border-collapse:collapse">
        <thead>
          <tr style="background:#162030">
            <th style="padding:10px 16px;color:#4a6278;font-size:11px;
                       text-align:left;font-weight:normal;white-space:nowrap">SEV</th>
            <th style="padding:10px 16px;color:#4a6278;font-size:11px;
                       text-align:left;font-weight:normal">DETAIL</th>
            <th style="padding:10px 16px;color:#4a6278;font-size:11px;
                       text-align:left;font-weight:normal;white-space:nowrap">IP / TIME</th>
          </tr>
        </thead>
        <tbody>{alert_rows}</tbody>
      </table>
      {more_note}
    </div>

    <!-- Footer -->
    <p style="color:#4a6278;font-size:11px;text-align:center;margin:0">
      Generated by LogScan &nbsp;·&nbsp; Automated threat detection
    </p>
  </div>
</body>
</html>"""

    @staticmethod
    def build_plain_email(result: dict, filtered_alerts: list) -> str:
        """Fallback plain text email."""
        lines = [
            "═" * 60,
            "  LOGSCAN ALERT REPORT",
            "═" * 60,
            f"  Source    : {result['source']}",
            f"  Time      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"  Lines     : {result['total_lines']}",
            f"  Unique IPs: {result['unique_ips']}",
            "",
            "  Alert Summary:",
        ]
        for sev in SEVERITY_ORDER:
            c = result["alert_counts"].get(sev, 0)
            if c:
                lines.append(f"    {SEV_EMOJI[sev]} {sev}: {c}")
        lines += ["", "─" * 60, "  ALERTS", "─" * 60]
        for a in filtered_alerts[:20]:
            ts = a.timestamp.strftime("%Y-%m-%d %H:%M:%S") if a.timestamp else "N/A"
            lines.append(f"\n  [{a.severity}] {a.category}")
            lines.append(f"  {a.description}")
            lines.append(f"  IP: {a.ip or 'N/A'} | {ts}")
            for ev in a.evidence[:2]:
                lines.append(f"    → {str(ev)[:100]}")
        lines.append("\n" + "═" * 60)
        return "\n".join(lines)

    @staticmethod
    def build_slack_payload(result: dict, filtered_alerts: list) -> dict:
        """Builds a rich Slack Block Kit message."""
        counts = result["alert_counts"]
        source = result["source"]
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Header text
        c = counts.get("CRITICAL", 0)
        h = counts.get("HIGH", 0)
        if c > 0:
            header = f"🚨 *Critical threats detected in `{source}`*"
        elif h > 0:
            header = f"🔴 *High severity threats in `{source}`*"
        else:
            header = f"⚠️ *Threats detected in `{source}`*"

        # Summary line
        summary_parts = []
        for sev in SEVERITY_ORDER:
            c_val = counts.get(sev, 0)
            if c_val:
                summary_parts.append(f"{SEV_EMOJI[sev]} *{sev}:* {c_val}")
        summary_line = "  ".join(summary_parts)

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "🔍 LogScan Alert Report", "emoji": True}
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": header}
            },
            {
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"🕐 {ts}  ·  📄 {source}"}]
            },
            {"type": "divider"},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Total Lines:*\n{result['total_lines']}"},
                    {"type": "mrkdwn", "text": f"*Unique IPs:*\n{result['unique_ips']}"},
                    {"type": "mrkdwn", "text": f"*Parsed:*\n{result['parsed_entries']}"},
                    {"type": "mrkdwn", "text": f"*Total Alerts:*\n{len(filtered_alerts)}"},
                ]
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Severity Breakdown:*\n{summary_line}"}
            },
            {"type": "divider"},
        ]

        # Add top alerts (max 10 for Slack)
        for a in filtered_alerts[:10]:
            ts_str = a.timestamp.strftime("%H:%M:%S") if a.timestamp else "N/A"
            ev_text = ""
            if a.evidence:
                ev_lines = "\n".join(f"> _{str(e)[:100]}_" for e in a.evidence[:2])
                ev_text = f"\n{ev_lines}"

            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"{SEV_EMOJI[a.severity]} *[{a.severity}]* `{a.category}`\n"
                        f"{a.description}\n"
                        f"_IP: {a.ip or 'N/A'}  ·  {ts_str}_{ev_text}"
                    )
                }
            })

        if len(filtered_alerts) > 10:
            blocks.append({
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": f"_... and {len(filtered_alerts) - 10} more alerts not shown_"
                }]
            })

        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": "_Sent by LogScan · Automated threat detection_"}]
        })

        return {"blocks": blocks}


# ─────────────────────────────────────────────────────────────────────────────
# EMAIL SENDER
# ─────────────────────────────────────────────────────────────────────────────
class EmailSender:
    """Sends alert emails via SMTP (supports Gmail, Outlook, custom SMTP)."""

    def __init__(self):
        self.host = os.environ.get("LOGSCAN_SMTP_HOST", "smtp.gmail.com")
        self.port = int(os.environ.get("LOGSCAN_SMTP_PORT", "587"))
        self.user = os.environ.get("LOGSCAN_SMTP_USER", "")
        self.password = os.environ.get("LOGSCAN_SMTP_PASS", "")
        self.from_addr = os.environ.get("LOGSCAN_FROM_EMAIL", self.user)

    def is_configured(self) -> bool:
        return bool(self.user and self.password)

    def send(self, to_addr: str, subject: str, html_body: str, plain_body: str) -> bool:
        """
        Send email alert. Returns True on success.
        Uses STARTTLS (port 587) for secure transmission.
        """
        if not self.is_configured():
            print("  ⚠️  Email not configured. Set LOGSCAN_SMTP_USER and LOGSCAN_SMTP_PASS env vars.")
            print("     Gmail: create an App Password at myaccount.google.com/apppasswords")
            return False

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = self.from_addr
            msg["To"] = to_addr
            msg["X-Mailer"] = "LogScan/1.0"

            # Attach both plain and HTML parts (email clients prefer HTML)
            msg.attach(MIMEText(plain_body, "plain"))
            msg.attach(MIMEText(html_body, "html"))

            with smtplib.SMTP(self.host, self.port) as server:
                server.ehlo()
                server.starttls()
                server.login(self.user, self.password)
                server.sendmail(self.from_addr, to_addr, msg.as_string())

            print(f"  ✅ Alert email sent to {to_addr}")
            return True

        except smtplib.SMTPAuthenticationError:
            print("  ❌ SMTP authentication failed. Check your credentials.")
            print("     Gmail users: use an App Password, not your regular password.")
            return False
        except smtplib.SMTPException as e:
            print(f"  ❌ SMTP error: {e}")
            return False
        except Exception as e:
            print(f"  ❌ Email send failed: {e}")
            return False


# ─────────────────────────────────────────────────────────────────────────────
# SLACK SENDER
# ─────────────────────────────────────────────────────────────────────────────
class SlackSender:
    """Sends alert messages to Slack via Incoming Webhooks."""

    TIMEOUT = 10  # seconds

    def send(self, webhook_url: str, payload: dict) -> bool:
        """
        POST a Block Kit message to the Slack webhook URL.
        Returns True on success.
        """
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                webhook_url,
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "LogScan/1.0",
                },
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=self.TIMEOUT) as resp:
                response_text = resp.read().decode()
                if response_text == "ok":
                    print("  ✅ Slack alert sent successfully")
                    return True
                else:
                    print(f"  ⚠️  Slack responded with: {response_text}")
                    return False

        except urllib.error.HTTPError as e:
            body = e.read().decode()
            print(f"  ❌ Slack HTTP error {e.code}: {body}")
            if "invalid_payload" in body:
                print("     Tip: Check your webhook URL and payload format")
            elif "no_service" in body:
                print("     Tip: The webhook URL may have been revoked — regenerate it in Slack")
            return False
        except urllib.error.URLError as e:
            print(f"  ❌ Slack connection failed: {e.reason}")
            print("     Tip: Check your internet connection and webhook URL")
            return False
        except Exception as e:
            print(f"  ❌ Slack send failed: {e}")
            return False


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ALERTER CLASS
# ─────────────────────────────────────────────────────────────────────────────
class Alerter:
    """
    Unified alerting class. Plug into LogAnalyzer workflow.

    Usage:
        alerter = Alerter(
            email_to="admin@example.com",
            slack_webhook="https://hooks.slack.com/services/...",
            min_severity="HIGH",
        )
        alerter.send(result)
    """

    def __init__(
        self,
        email_to: Optional[str] = None,
        slack_webhook: Optional[str] = None,
        min_severity: str = "HIGH",
    ):
        self.email_to = email_to
        self.slack_webhook = slack_webhook
        self.min_severity = min_severity
        self.formatter = AlertFormatter()
        self.email_sender = EmailSender()
        self.slack_sender = SlackSender()

    def _filter_alerts(self, result: dict) -> list:
        """Return only alerts at or above the minimum severity threshold."""
        threshold_idx = SEVERITY_ORDER.index(self.min_severity)
        return [
            a for a in result["alerts"]
            if SEVERITY_ORDER.index(a.severity) <= threshold_idx
        ]

    def should_send(self, result: dict) -> bool:
        """Return True if any alerts meet the minimum severity."""
        return len(self._filter_alerts(result)) > 0

    def send(self, result: dict) -> dict:
        """
        Send all configured alerts. Returns a dict with send results.

        Args:
            result: The analysis result dict from LogAnalyzer._run_analysis()

        Returns:
            {"email": True/False/None, "slack": True/False/None}
        """
        outcomes = {"email": None, "slack": None}

        filtered = self._filter_alerts(result)
        if not filtered:
            print(f"  ℹ️  No alerts at or above {self.min_severity} — skipping notifications")
            return outcomes

        subject = self.formatter.build_subject(result)
        print(f"\n  📣 Sending alerts: {len(filtered)} alert(s) at {self.min_severity}+")

        # Email
        if self.email_to:
            html = self.formatter.build_html_email(result, filtered)
            plain = self.formatter.build_plain_email(result, filtered)
            outcomes["email"] = self.email_sender.send(
                to_addr=self.email_to,
                subject=subject,
                html_body=html,
                plain_body=plain,
            )

        # Slack
        if self.slack_webhook:
            payload = self.formatter.build_slack_payload(result, filtered)
            outcomes["slack"] = self.slack_sender.send(self.slack_webhook, payload)

        return outcomes


# ─────────────────────────────────────────────────────────────────────────────
# STANDALONE TEST
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Test alerting module standalone")
    parser.add_argument("--email", metavar="ADDRESS", help="Send test email to this address")
    parser.add_argument("--slack", metavar="WEBHOOK", help="Send test Slack message to this webhook")
    parser.add_argument(
        "--preview",
        choices=["html", "plain", "slack"],
        help="Print message preview to stdout without sending"
    )
    args = parser.parse_args()

    # Fake result for testing
    from datetime import datetime
    from dataclasses import dataclass, field
    from typing import Optional

    @dataclass
    class FakeAlert:
        severity: str
        category: str
        description: str
        ip: Optional[str] = None
        timestamp: Optional[datetime] = None
        evidence: list = field(default_factory=list)

    fake_result = {
        "source": "/var/log/nginx/access.log",
        "total_lines": 15420,
        "parsed_entries": 15380,
        "unique_ips": 87,
        "top_ips": [("203.0.113.77", 420), ("192.168.1.50", 310)],
        "status_distribution": {200: 12000, 401: 250, 404: 800, 500: 370},
        "alert_counts": {"CRITICAL": 2, "HIGH": 3, "MEDIUM": 1, "LOW": 2},
        "alerts": [
            FakeAlert("CRITICAL", "BRUTE_FORCE",
                      "18 failed login attempts from 192.168.1.50",
                      ip="192.168.1.50",
                      timestamp=datetime(2026, 2, 17, 10, 1, 15),
                      evidence=["POST /login HTTP/1.1 401", "POST /login HTTP/1.1 401"]),
            FakeAlert("CRITICAL", "PATH_TRAVERSAL",
                      "Directory traversal attempt: /../../etc/passwd",
                      ip="198.51.100.1",
                      timestamp=datetime(2026, 2, 17, 10, 3, 0),
                      evidence=["GET /../../etc/passwd HTTP/1.1 400"]),
            FakeAlert("HIGH", "SENSITIVE_PATH_SCAN",
                      "203.0.113.77 accessed 5 sensitive paths",
                      ip="203.0.113.77",
                      evidence=["/admin", "/.env", "/wp-admin"]),
            FakeAlert("HIGH", "SQL_INJECTION",
                      "10.0.0.9 made 2 SQL injection attempt(s)",
                      ip="10.0.0.9",
                      evidence=["Pattern: ' OR '1'='1"]),
            FakeAlert("MEDIUM", "SUSPICIOUS_USER_AGENT",
                      "203.0.113.77 used suspicious agent: sqlmap/1.6",
                      ip="203.0.113.77"),
        ],
    }

    formatter = AlertFormatter()

    if args.preview == "html":
        filtered = fake_result["alerts"]
        print(formatter.build_html_email(fake_result, filtered))
    elif args.preview == "plain":
        filtered = fake_result["alerts"]
        print(formatter.build_plain_email(fake_result, filtered))
    elif args.preview == "slack":
        filtered = fake_result["alerts"]
        payload = formatter.build_slack_payload(fake_result, filtered)
        print(json.dumps(payload, indent=2))
    elif args.email or args.slack:
        alerter = Alerter(
            email_to=args.email,
            slack_webhook=args.slack,
            min_severity="LOW",
        )
        outcomes = alerter.send(fake_result)
        print(f"\n  Results: {outcomes}")
    else:
        parser.print_help()
        print("\n  Quick test — printing plain text preview:\n")
        filtered = fake_result["alerts"]
        print(formatter.build_plain_email(fake_result, filtered))