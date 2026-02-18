"""
cli.py — Command Line Interface for Log Analyzer
Provides proper argparse flags with help text, validation, and rich output.

Usage examples:
    python cli.py --file access.log
    python cli.py --file access.log --format json --output report.json
    python cli.py --file access.log --threshold 20 --severity CRITICAL HIGH
    python cli.py --file access.log --advanced --geo
    python cli.py --file access.log --alert-email you@example.com
    python cli.py --file access.log --alert-slack https://hooks.slack.com/...
    python cli.py --demo
"""

import argparse
import sys
import os
import json
import csv
import io
from datetime import datetime
from collections import Counter


# ─────────────────────────────────────────────────────────────────────────────
# ANSI colors for terminal output
# ─────────────────────────────────────────────────────────────────────────────
class Color:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    ORANGE  = "\033[38;5;208m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    GRAY    = "\033[90m"
    WHITE   = "\033[97m"

    @staticmethod
    def sev(severity: str) -> str:
        return {
            "CRITICAL": Color.RED,
            "HIGH":     Color.ORANGE,
            "MEDIUM":   Color.YELLOW,
            "LOW":      Color.GREEN,
        }.get(severity, Color.RESET)

    @staticmethod
    def strip(text: str) -> str:
        """Remove all ANSI codes (for file output)."""
        import re
        return re.sub(r'\033\[[0-9;]*m', '', text)


def supports_color() -> bool:
    """Check if the terminal supports ANSI colors."""
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


# ─────────────────────────────────────────────────────────────────────────────
# ARGUMENT PARSER
# ─────────────────────────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logscan",
        description=(
            "╔══════════════════════════════════════════╗\n"
            "║   LogScan — Suspicious Log Analyzer      ║\n"
            "║   Detects attacks, anomalies & threats   ║\n"
            "╚══════════════════════════════════════════╝"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python cli.py --demo
  python cli.py --file /var/log/nginx/access.log
  python cli.py --file access.log --format json --output report.json
  python cli.py --file access.log --severity CRITICAL HIGH --format table
  python cli.py --file access.log --threshold 20 --advanced --geo
  python cli.py --file access.log --alert-email admin@example.com
  python cli.py --file access.log --alert-slack https://hooks.slack.com/T.../...
  python cli.py --file access.log --top-ips 20 --min-requests 5
        """
    )

    # ── Input ──────────────────────────────────────────────────────────────
    input_group = parser.add_argument_group("input")
    input_group.add_argument(
        "--file", "-f",
        metavar="PATH",
        help="Path to the log file to analyze (Apache, Nginx, SSH, or generic)"
    )
    input_group.add_argument(
        "--demo",
        action="store_true",
        help="Run with built-in synthetic demo logs (no file needed)"
    )
    input_group.add_argument(
        "--stdin",
        action="store_true",
        help="Read log lines from stdin (pipe mode)"
    )

    # ── Detection settings ─────────────────────────────────────────────────
    detect_group = parser.add_argument_group("detection")
    detect_group.add_argument(
        "--threshold", "-t",
        type=int,
        default=15,
        metavar="N",
        help="Failed login count to trigger brute-force alert (default: 15)"
    )
    detect_group.add_argument(
        "--window",
        type=int,
        default=60,
        metavar="SECONDS",
        help="Time window in seconds for rapid brute-force detection (default: 60)"
    )
    detect_group.add_argument(
        "--rate",
        type=int,
        default=100,
        metavar="RPM",
        help="Requests per minute to flag as high-volume anomaly (default: 100)"
    )
    detect_group.add_argument(
        "--repeat",
        type=int,
        default=20,
        metavar="N",
        help="Same-path hit count to flag as repeated access (default: 20)"
    )
    detect_group.add_argument(
        "--advanced", "-a",
        action="store_true",
        help="Enable advanced detectors: SQL injection, XSS, bot detection"
    )
    detect_group.add_argument(
        "--geo",
        action="store_true",
        help="Enable GeoIP lookups (requires internet, uses ip-api.com free tier)"
    )

    # ── Filtering ──────────────────────────────────────────────────────────
    filter_group = parser.add_argument_group("filtering")
    filter_group.add_argument(
        "--severity", "-s",
        nargs="+",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        metavar="LEVEL",
        help="Only show alerts at these severity levels (e.g. --severity CRITICAL HIGH)"
    )
    filter_group.add_argument(
        "--category", "-c",
        nargs="+",
        metavar="CAT",
        help="Only show alerts matching these categories (e.g. --category BRUTE_FORCE SQL_INJECTION)"
    )
    filter_group.add_argument(
        "--ip",
        metavar="ADDRESS",
        help="Filter results to a specific IP address"
    )
    filter_group.add_argument(
        "--min-requests",
        type=int,
        default=1,
        metavar="N",
        help="Only include IPs with at least N requests in the report (default: 1)"
    )

    # ── Output ─────────────────────────────────────────────────────────────
    output_group = parser.add_argument_group("output")
    output_group.add_argument(
        "--format",
        choices=["terminal", "json", "csv", "table", "summary"],
        default="terminal",
        help="Output format: terminal (default), json, csv, table, summary"
    )
    output_group.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Save output to this file (default: print to stdout)"
    )
    output_group.add_argument(
        "--top-ips",
        type=int,
        default=10,
        metavar="N",
        help="Number of top IPs to show in the report (default: 10)"
    )
    output_group.add_argument(
        "--no-evidence",
        action="store_true",
        help="Hide raw log evidence lines in output"
    )
    output_group.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color output"
    )
    output_group.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress banner and summary, only print alerts"
    )

    # ── Alerting ───────────────────────────────────────────────────────────
    alert_group = parser.add_argument_group("alerting")
    alert_group.add_argument(
        "--alert-email",
        metavar="ADDRESS",
        help="Send alert email to this address when CRITICAL/HIGH threats found"
    )
    alert_group.add_argument(
        "--alert-slack",
        metavar="WEBHOOK_URL",
        help="Send Slack notification to this webhook URL"
    )
    alert_group.add_argument(
        "--alert-min-severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default="HIGH",
        help="Minimum severity level that triggers alerting (default: HIGH)"
    )

    return parser


# ─────────────────────────────────────────────────────────────────────────────
# FORMATTERS
# ─────────────────────────────────────────────────────────────────────────────
def format_terminal(result: dict, args: argparse.Namespace, use_color: bool) -> str:
    """Rich terminal output with colors and sections."""
    C = Color if use_color else type("NoColor", (), {k: "" for k in vars(Color) if not k.startswith("_")})()
    lines = []

    if not args.quiet:
        lines += [
            f"\n{C.CYAN}{'═' * 65}{C.RESET}",
            f"  {C.BOLD}{C.WHITE}🔍 LOGSCAN — THREAT ANALYSIS REPORT{C.RESET}",
            f"{C.CYAN}{'═' * 65}{C.RESET}",
            f"  {C.GRAY}Source      :{C.RESET} {result['source']}",
            f"  {C.GRAY}Analyzed at :{C.RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"  {C.GRAY}Total Lines :{C.RESET} {result['total_lines']}",
            f"  {C.GRAY}Parsed      :{C.RESET} {result['parsed_entries']}",
            f"  {C.GRAY}Unique IPs  :{C.RESET} {result['unique_ips']}",
            "",
        ]

        counts = result["alert_counts"]
        sev_icons = {"CRITICAL": "🚨", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}
        lines.append(f"  {C.BOLD}Alert Summary:{C.RESET}")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            c = counts.get(sev, 0)
            col = Color.sev(sev) if use_color else ""
            reset = C.RESET if use_color else ""
            bar = "█" * min(c, 30)
            lines.append(f"    {sev_icons[sev]} {col}{sev:<10}{reset} {c:>3}  {C.GRAY}{bar}{C.RESET}")

        lines += ["", f"  {C.BOLD}Top Source IPs:{C.RESET}"]
        for ip, cnt in result["top_ips"][:args.top_ips]:
            flag = "⚠️ " if cnt >= args.threshold else "   "
            lines.append(f"    {flag}{C.CYAN}{ip:<20}{C.RESET} {cnt} requests")

    # Alerts
    alerts = result["alerts"]
    if args.severity:
        alerts = [a for a in alerts if a.severity in args.severity]
    if args.category:
        cats_upper = [c.upper() for c in args.category]
        alerts = [a for a in alerts if a.category in cats_upper]
    if args.ip:
        alerts = [a for a in alerts if a.ip == args.ip]

    if not args.quiet:
        lines += ["", f"{C.CYAN}{'─' * 65}{C.RESET}", f"  {C.BOLD}ALERTS ({len(alerts)} shown){C.RESET}", f"{C.CYAN}{'─' * 65}{C.RESET}"]

    if not alerts:
        lines.append(f"\n  {C.GREEN}✓ No alerts match the current filters.{C.RESET}")
    else:
        for alert in alerts:
            col = Color.sev(alert.severity) if use_color else ""
            reset = C.RESET if use_color else ""
            ts = alert.timestamp.strftime("%Y-%m-%d %H:%M:%S") if alert.timestamp else "N/A"
            lines += [
                "",
                f"  {col}[{alert.severity}]{reset} {C.BOLD}{alert.category}{C.RESET}",
                f"  {C.WHITE}{alert.description}{C.RESET}",
                f"  {C.GRAY}IP: {alert.ip or 'N/A'}  |  Time: {ts}{C.RESET}",
            ]
            if not args.no_evidence and alert.evidence:
                lines.append(f"  {C.GRAY}Evidence:{C.RESET}")
                for ev in alert.evidence[:3]:
                    lines.append(f"    {C.GRAY}→ {str(ev)[:110]}{C.RESET}")

    if not args.quiet:
        lines.append(f"\n{C.CYAN}{'═' * 65}{C.RESET}\n")

    return "\n".join(lines)


def format_table(result: dict, args: argparse.Namespace) -> str:
    """Fixed-width table format."""
    alerts = result["alerts"]
    if args.severity:
        alerts = [a for a in alerts if a.severity in args.severity]

    lines = []
    header = f"{'SEVERITY':<10} {'CATEGORY':<25} {'IP':<18} {'DESCRIPTION'}"
    lines.append(header)
    lines.append("─" * 90)

    for a in alerts:
        desc = a.description[:45] + "..." if len(a.description) > 45 else a.description
        lines.append(f"{a.severity:<10} {a.category:<25} {(a.ip or 'N/A'):<18} {desc}")

    lines.append("─" * 90)
    lines.append(f"Total: {len(alerts)} alert(s)")
    return "\n".join(lines)


def format_summary(result: dict) -> str:
    """One-line summary suitable for logging or monitoring systems."""
    counts = result["alert_counts"]
    parts = [
        f"source={result['source']}",
        f"lines={result['total_lines']}",
        f"ips={result['unique_ips']}",
        f"critical={counts.get('CRITICAL', 0)}",
        f"high={counts.get('HIGH', 0)}",
        f"medium={counts.get('MEDIUM', 0)}",
        f"low={counts.get('LOW', 0)}",
        f"total_alerts={len(result['alerts'])}",
        f"analyzed_at={datetime.now().isoformat()}",
    ]
    return " ".join(parts)


def format_csv(result: dict, args: argparse.Namespace) -> str:
    """CSV format for spreadsheet import."""
    alerts = result["alerts"]
    if args.severity:
        alerts = [a for a in alerts if a.severity in args.severity]

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["severity", "category", "ip", "description", "timestamp", "evidence"])
    for a in alerts:
        writer.writerow([
            a.severity,
            a.category,
            a.ip or "",
            a.description,
            a.timestamp.isoformat() if a.timestamp else "",
            " | ".join(str(e) for e in a.evidence[:3])
        ])
    return output.getvalue()


def format_json(result: dict, args: argparse.Namespace) -> str:
    """JSON format for API / pipeline consumption."""
    alerts = result["alerts"]
    if args.severity:
        alerts = [a for a in alerts if a.severity in args.severity]

    data = {
        "meta": {
            "source": result["source"],
            "analyzed_at": datetime.now().isoformat(),
            "total_lines": result["total_lines"],
            "parsed_entries": result["parsed_entries"],
            "unique_ips": result["unique_ips"],
        },
        "summary": result["alert_counts"],
        "top_ips": result["top_ips"],
        "status_distribution": result["status_distribution"],
        "alerts": [
            {
                "severity": a.severity,
                "category": a.category,
                "ip": a.ip,
                "description": a.description,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                "evidence": a.evidence,
            }
            for a in alerts
        ],
    }
    return json.dumps(data, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = build_parser()
    args = parser.parse_args()

    # Validate input
    if not args.demo and not args.file and not args.stdin:
        parser.print_help()
        print("\n❌  Error: provide --file, --demo, or --stdin")
        sys.exit(1)

    if args.file and not os.path.exists(args.file):
        print(f"❌  Error: file not found: {args.file}")
        sys.exit(1)

    # Import analyzer
    try:
        from log_analyzer import LogAnalyzer, Config
    except ImportError:
        print("❌  Error: log_analyzer.py not found. Make sure it's in the same directory.")
        sys.exit(1)

    # Apply CLI thresholds to config
    Config.FAILED_LOGIN_THRESHOLD = args.threshold
    Config.BRUTE_FORCE_WINDOW_SEC = args.window
    Config.RAPID_REQUEST_THRESHOLD = args.rate
    Config.REPEATED_PATTERN_THRESHOLD = args.repeat

    # Build analyzer
    analyzer = LogAnalyzer()

    # Attach advanced detectors if requested
    if args.advanced or args.geo:
        try:
            from detectors import get_all_advanced_detectors
            analyzer.detectors += get_all_advanced_detectors(enable_geo=args.geo)
            if not args.quiet:
                print(f"  ✅ Advanced detectors loaded{' + GeoIP' if args.geo else ''}")
        except ImportError:
            print("  ⚠️  detectors.py not found — running with base detectors only")

    # Attach alerting if requested
    alerter = None
    if args.alert_email or args.alert_slack:
        try:
            from alerting import Alerter
            alerter = Alerter(
                email_to=args.alert_email,
                slack_webhook=args.alert_slack,
                min_severity=args.alert_min_severity,
            )
        except ImportError:
            print("  ⚠️  alerting.py not found — alerting disabled")

    # Run analysis
    if args.demo:
        result = analyzer.analyze_text(DEMO_LOGS)
    elif args.stdin:
        text = sys.stdin.read()
        result = analyzer.analyze_text(text)
    else:
        result = analyzer.analyze_file(args.file)

    # Apply IP filter to stats if set
    if args.ip:
        result["alerts"] = [a for a in result["alerts"] if a.ip == args.ip]

    # Apply min-requests filter to top IPs
    result["top_ips"] = [(ip, cnt) for ip, cnt in result["top_ips"] if cnt >= args.min_requests]

    # Format output
    use_color = not args.no_color and supports_color() and args.format == "terminal"
    fmt = args.format

    if fmt == "terminal":
        output = format_terminal(result, args, use_color)
    elif fmt == "json":
        output = format_json(result, args)
    elif fmt == "csv":
        output = format_csv(result, args)
    elif fmt == "table":
        output = format_table(result, args)
    elif fmt == "summary":
        output = format_summary(result)
    else:
        output = format_terminal(result, args, use_color)

    # Write output
    if args.output:
        clean = Color.strip(output) if use_color else output
        with open(args.output, "w") as f:
            f.write(clean)
        print(f"  ✅ Report saved to: {args.output}")
    else:
        print(output)

    # Send alerts if configured
    if alerter:
        alerter.send(result)

    # Exit with non-zero code if critical alerts found
    counts = result["alert_counts"]
    if counts.get("CRITICAL", 0) > 0:
        sys.exit(2)
    elif counts.get("HIGH", 0) > 0:
        sys.exit(1)
    else:
        sys.exit(0)


# ─────────────────────────────────────────────────────────────────────────────
# DEMO LOGS
# ─────────────────────────────────────────────────────────────────────────────
DEMO_LOGS = """
192.168.1.50 - - [17/Feb/2026:10:01:01 +0000] "POST /login HTTP/1.1" 401 512 "-" "Mozilla/5.0"
192.168.1.50 - - [17/Feb/2026:10:01:02 +0000] "POST /login HTTP/1.1" 401 512 "-" "Mozilla/5.0"
192.168.1.50 - - [17/Feb/2026:10:01:03 +0000] "POST /login HTTP/1.1" 401 512 "-" "Mozilla/5.0"
192.168.1.50 - - [17/Feb/2026:10:01:04 +0000] "POST /login HTTP/1.1" 401 512 "-" "Mozilla/5.0"
192.168.1.50 - - [17/Feb/2026:10:01:05 +0000] "POST /login HTTP/1.1" 401 512 "-" "Mozilla/5.0"
192.168.1.50 - - [17/Feb/2026:10:01:06 +0000] "POST /login HTTP/1.1" 401 512 "-" "Mozilla/5.0"
192.168.1.50 - - [17/Feb/2026:10:01:07 +0000] "POST /login HTTP/1.1" 401 512 "-" "Mozilla/5.0"
192.168.1.50 - - [17/Feb/2026:10:01:08 +0000] "POST /login HTTP/1.1" 401 512 "-" "Mozilla/5.0"
192.168.1.50 - - [17/Feb/2026:10:01:09 +0000] "POST /login HTTP/1.1" 401 512 "-" "Mozilla/5.0"
192.168.1.50 - - [17/Feb/2026:10:01:10 +0000] "POST /login HTTP/1.1" 401 512 "-" "Mozilla/5.0"
192.168.1.50 - - [17/Feb/2026:10:01:11 +0000] "POST /login HTTP/1.1" 401 512 "-" "Mozilla/5.0"
192.168.1.50 - - [17/Feb/2026:10:01:12 +0000] "POST /login HTTP/1.1" 401 512 "-" "Mozilla/5.0"
192.168.1.50 - - [17/Feb/2026:10:01:13 +0000] "POST /login HTTP/1.1" 401 512 "-" "Mozilla/5.0"
192.168.1.50 - - [17/Feb/2026:10:01:14 +0000] "POST /login HTTP/1.1" 401 512 "-" "Mozilla/5.0"
192.168.1.50 - - [17/Feb/2026:10:01:15 +0000] "POST /login HTTP/1.1" 401 512 "-" "Mozilla/5.0"
203.0.113.77 - - [17/Feb/2026:10:02:00 +0000] "GET /admin HTTP/1.1" 403 256 "-" "sqlmap/1.6"
203.0.113.77 - - [17/Feb/2026:10:02:01 +0000] "GET /.env HTTP/1.1" 404 128 "-" "sqlmap/1.6"
203.0.113.77 - - [17/Feb/2026:10:02:02 +0000] "GET /wp-admin HTTP/1.1" 404 128 "-" "sqlmap/1.6"
203.0.113.77 - - [17/Feb/2026:10:02:03 +0000] "GET /phpmyadmin HTTP/1.1" 404 128 "-" "sqlmap/1.6"
203.0.113.77 - - [17/Feb/2026:10:02:04 +0000] "GET /.git/config HTTP/1.1" 200 1024 "-" "sqlmap/1.6"
198.51.100.1 - - [17/Feb/2026:10:03:00 +0000] "GET /../../etc/passwd HTTP/1.1" 400 256 "-" "curl/7.68"
10.0.0.9 - alice [17/Feb/2026:10:05:00 +0000] "GET /search?q=1'+OR+'1'='1 HTTP/1.1" 200 4096 "-" "Mozilla/5.0"
10.0.0.9 - alice [17/Feb/2026:10:05:01 +0000] "GET /user?id=1 UNION SELECT username,password FROM users HTTP/1.1" 500 512 "-" "Mozilla/5.0"
10.0.0.8 - - [17/Feb/2026:10:06:00 +0000] "GET /comment?text=<script>alert(1)</script> HTTP/1.1" 200 1024 "-" "Mozilla/5.0"
"""


if __name__ == "__main__":
    main()