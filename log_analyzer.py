"""
Log Analyzer - Detect suspicious behavior in log files
Detects: Failed login attempts, IP anomalies, Repeated access patterns
"""

import re
import json
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from typing import Optional
import ipaddress


# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────
class Config:
    FAILED_LOGIN_THRESHOLD = 15       # alerts after N failed logins
    BRUTE_FORCE_WINDOW_SEC = 60       # time window for brute-force detection
    RAPID_REQUEST_THRESHOLD = 100     # requests/minute that triggers alert
    REPEATED_PATTERN_THRESHOLD = 20   # same endpoint hits to flag
    PRIVATE_IP_RANGES = [
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"
    ]


# ─────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────
@dataclass
class LogEntry:
    raw: str
    timestamp: Optional[datetime] = None
    ip: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    status_code: Optional[int] = None
    user_agent: Optional[str] = None
    username: Optional[str] = None
    event_type: Optional[str] = None   # "auth", "access", "error"
    line_number: int = 0


@dataclass
class Alert:
    severity: str          # CRITICAL, HIGH, MEDIUM, LOW
    category: str          # BRUTE_FORCE, IP_ANOMALY, REPEATED_ACCESS, etc.
    description: str
    ip: Optional[str] = None
    timestamp: Optional[datetime] = None
    evidence: list = field(default_factory=list)

    def __str__(self):
        ts = self.timestamp.strftime("%Y-%m-%d %H:%M:%S") if self.timestamp else "N/A"
        return f"[{self.severity}] {self.category} | {self.description} | IP: {self.ip} | {ts}"


# ─────────────────────────────────────────────
# Log Parsers
# ─────────────────────────────────────────────
class LogParser:
    """Parses multiple common log formats."""

    # Apache/Nginx Combined Log Format
    APACHE_RE = re.compile(
        r'(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
        r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d{3})\s+\S+'
        r'(?:\s+"[^"]*"\s+"(?P<ua>[^"]*)")?'
    )

    # SSH/Auth log format
    SSH_RE = re.compile(
        r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+\S+\s+'
        r'(?:sshd|auth)\[\d+\]:\s+(?P<msg>.+)'
    )
    SSH_FAILED_RE = re.compile(r'Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+)')
    SSH_SUCCESS_RE = re.compile(r'Accepted (?:password|publickey) for (\S+) from (\S+)')

    # Generic timestamp + IP
    GENERIC_RE = re.compile(
        r'(?P<time>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})'
        r'.*?(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
    )

    @classmethod
    def parse_line(cls, line: str, line_number: int = 0) -> LogEntry:
        entry = LogEntry(raw=line.strip(), line_number=line_number)

        # Try Apache/Nginx
        m = cls.APACHE_RE.match(line)
        if m:
            entry.ip = m.group("ip")
            entry.method = m.group("method")
            entry.path = m.group("path")
            entry.status_code = int(m.group("status"))
            entry.user_agent = m.group("ua")
            entry.username = m.group("user") if m.group("user") != "-" else None
            entry.event_type = "access"
            try:
                entry.timestamp = datetime.strptime(m.group("time"), "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
            except ValueError:
                pass
            return entry

        # Try SSH
        m = cls.SSH_RE.match(line)
        if m:
            entry.event_type = "auth"
            msg = m.group("msg")
            year = datetime.now().year
            try:
                ts_str = f"{m.group('month')} {m.group('day')} {year} {m.group('time')}"
                entry.timestamp = datetime.strptime(ts_str, "%b %d %Y %H:%M:%S")
            except ValueError:
                pass

            fail = cls.SSH_FAILED_RE.search(msg)
            if fail:
                entry.username = fail.group(1)
                entry.ip = fail.group(2)
                entry.status_code = 401
                return entry

            success = cls.SSH_SUCCESS_RE.search(msg)
            if success:
                entry.username = success.group(1)
                entry.ip = success.group(2)
                entry.status_code = 200
                return entry

        # Generic fallback
        m = cls.GENERIC_RE.search(line)
        if m:
            entry.ip = m.group("ip")
            entry.event_type = "generic"
            try:
                entry.timestamp = datetime.fromisoformat(m.group("time"))
            except ValueError:
                pass

        return entry


# ─────────────────────────────────────────────
# Detection Engines
# ─────────────────────────────────────────────
class FailedLoginDetector:
    """Detects brute-force and credential stuffing attacks."""

    def analyze(self, entries: list[LogEntry]) -> list[Alert]:
        alerts = []
        ip_failures: dict[str, list[LogEntry]] = defaultdict(list)
        user_failures: dict[str, list[LogEntry]] = defaultdict(list)

        for e in entries:
            if e.status_code in (401, 403) or (e.event_type == "auth" and e.ip):
                if e.ip:
                    ip_failures[e.ip].append(e)
                if e.username:
                    user_failures[e.username].append(e)

        # Per-IP brute force
        for ip, events in ip_failures.items():
            if len(events) >= Config.FAILED_LOGIN_THRESHOLD:
                alerts.append(Alert(
                    severity="CRITICAL" if len(events) >= 30 else "HIGH",
                    category="BRUTE_FORCE",
                    description=f"{len(events)} failed login attempts from {ip}",
                    ip=ip,
                    timestamp=events[-1].timestamp,
                    evidence=[e.raw[:120] for e in events[:5]]
                ))

        # Credential stuffing: many users targeted from one IP
        ip_user_combos: dict[str, set] = defaultdict(set)
        for e in entries:
            if e.status_code in (401, 403) and e.ip and e.username:
                ip_user_combos[e.ip].add(e.username)

        for ip, users in ip_user_combos.items():
            if len(users) >= 5:
                alerts.append(Alert(
                    severity="CRITICAL",
                    category="CREDENTIAL_STUFFING",
                    description=f"IP {ip} tried {len(users)} different usernames",
                    ip=ip,
                    evidence=list(users)[:10]
                ))

        # Rapid failures: N failures in short window
        for ip, events in ip_failures.items():
            sorted_events = sorted([e for e in events if e.timestamp], key=lambda x: x.timestamp)
            for i in range(len(sorted_events)):
                window = [e for e in sorted_events[i:]
                          if (e.timestamp - sorted_events[i].timestamp).total_seconds()
                          <= Config.BRUTE_FORCE_WINDOW_SEC]
                if len(window) >= Config.FAILED_LOGIN_THRESHOLD:
                    alerts.append(Alert(
                        severity="HIGH",
                        category="RAPID_BRUTE_FORCE",
                        description=f"{len(window)} failures from {ip} within {Config.BRUTE_FORCE_WINDOW_SEC}s",
                        ip=ip,
                        timestamp=window[0].timestamp,
                        evidence=[e.raw[:100] for e in window[:3]]
                    ))
                    break  # one alert per IP

        return alerts


class IPAnomalyDetector:
    """Detects suspicious IP behavior."""

    def analyze(self, entries: list[LogEntry]) -> list[Alert]:
        alerts = []
        ip_requests: dict[str, list[LogEntry]] = defaultdict(list)

        for e in entries:
            if e.ip:
                ip_requests[e.ip].append(e)

        for ip, events in ip_requests.items():
            # High request volume
            if len(events) >= Config.RAPID_REQUEST_THRESHOLD:
                sorted_events = sorted([e for e in events if e.timestamp], key=lambda x: x.timestamp)
                if sorted_events:
                    window_size = (sorted_events[-1].timestamp - sorted_events[0].timestamp).total_seconds()
                    rate = len(events) / max(window_size / 60, 1)
                    if rate >= Config.RAPID_REQUEST_THRESHOLD:
                        alerts.append(Alert(
                            severity="HIGH",
                            category="IP_ANOMALY",
                            description=f"{ip} sent {len(events)} requests ({rate:.0f}/min) — possible scanner/DoS",
                            ip=ip,
                            timestamp=sorted_events[-1].timestamp
                        ))

            # Suspicious user agents
            agents = [e.user_agent for e in events if e.user_agent]
            suspicious_ua_keywords = ["sqlmap", "nikto", "nmap", "masscan", "zgrab",
                                       "python-requests", "curl", "wget", "scrapy", "go-http"]
            for ua in agents:
                for kw in suspicious_ua_keywords:
                    if kw.lower() in ua.lower():
                        alerts.append(Alert(
                            severity="MEDIUM",
                            category="SUSPICIOUS_USER_AGENT",
                            description=f"{ip} used suspicious agent: {ua[:80]}",
                            ip=ip,
                            evidence=[ua]
                        ))
                        break

            # IPs hitting many 4xx/5xx errors
            error_count = sum(1 for e in events if e.status_code and e.status_code >= 400)
            if error_count >= 30:
                alerts.append(Alert(
                    severity="MEDIUM",
                    category="IP_ANOMALY",
                    description=f"{ip} triggered {error_count} error responses — possible scanning",
                    ip=ip
                ))

        return alerts


class RepeatedAccessDetector:
    """Detects repeated access patterns — path scanning, enumeration."""

    SENSITIVE_PATHS = [
        r'/admin', r'/\.env', r'/wp-admin', r'/phpmyadmin', r'/config',
        r'/backup', r'\.git', r'/etc/passwd', r'/proc/', r'\.sql$',
        r'/api/v\d+/users', r'/login', r'/register', r'\.php$'
    ]
    SENSITIVE_RE = [re.compile(p, re.IGNORECASE) for p in SENSITIVE_PATHS]

    def analyze(self, entries: list[LogEntry]) -> list[Alert]:
        alerts = []
        path_counter: Counter = Counter()
        ip_path_map: dict[str, Counter] = defaultdict(Counter)
        sensitive_hits: dict[str, list] = defaultdict(list)

        for e in entries:
            if e.path:
                path_counter[e.path] += 1
                if e.ip:
                    ip_path_map[e.ip][e.path] += 1

            # Sensitive path access
            if e.path and e.ip:
                for pattern in self.SENSITIVE_RE:
                    if pattern.search(e.path):
                        sensitive_hits[e.ip].append(e)
                        break

        # Heavily repeated paths
        for path, count in path_counter.most_common(20):
            if count >= Config.REPEATED_PATTERN_THRESHOLD:
                alerts.append(Alert(
                    severity="LOW",
                    category="REPEATED_ACCESS",
                    description=f"Path '{path}' accessed {count} times",
                    evidence=[path]
                ))

        # Directory traversal attempts
        traversal_re = re.compile(r'\.\.[/\\]|%2e%2e|%252e')
        for e in entries:
            if e.path and traversal_re.search(e.path):
                alerts.append(Alert(
                    severity="CRITICAL",
                    category="PATH_TRAVERSAL",
                    description=f"Traversal attempt: {e.path[:100]}",
                    ip=e.ip,
                    timestamp=e.timestamp,
                    evidence=[e.raw[:120]]
                ))

        # IPs hitting many sensitive paths
        for ip, hits in sensitive_hits.items():
            unique_paths = set(e.path for e in hits)
            if len(unique_paths) >= 5:
                alerts.append(Alert(
                    severity="HIGH",
                    category="SENSITIVE_PATH_SCAN",
                    description=f"{ip} accessed {len(unique_paths)} sensitive paths",
                    ip=ip,
                    evidence=list(unique_paths)[:8]
                ))

        # IP scanning many unique paths (enumeration)
        for ip, paths in ip_path_map.items():
            unique = len(paths)
            if unique >= 50:
                alerts.append(Alert(
                    severity="MEDIUM",
                    category="PATH_ENUMERATION",
                    description=f"{ip} scanned {unique} unique paths — possible enumeration",
                    ip=ip
                ))

        return alerts


# ─────────────────────────────────────────────
# Main Analyzer
# ─────────────────────────────────────────────
class LogAnalyzer:
    def __init__(self):
        self.parser = LogParser()
        self.detectors = [
            FailedLoginDetector(),
            IPAnomalyDetector(),
            RepeatedAccessDetector(),
        ]

    def analyze_file(self, filepath: str) -> dict:
        entries = []
        with open(filepath, "r", errors="replace") as f:
            for i, line in enumerate(f, 1):
                if line.strip():
                    entries.append(self.parser.parse_line(line, line_number=i))
        return self._run_analysis(entries, source=filepath)

    def analyze_text(self, text: str) -> dict:
        entries = []
        for i, line in enumerate(text.strip().splitlines(), 1):
            if line.strip():
                entries.append(self.parser.parse_line(line, line_number=i))
        return self._run_analysis(entries, source="<inline>")

    def _run_analysis(self, entries: list[LogEntry], source: str) -> dict:
        all_alerts: list[Alert] = []
        for detector in self.detectors:
            all_alerts.extend(detector.analyze(entries))

        # Deduplicate by (category, ip)
        seen = set()
        unique_alerts = []
        for a in all_alerts:
            key = (a.category, a.ip, a.description[:50])
            if key not in seen:
                seen.add(key)
                unique_alerts.append(a)

        unique_alerts.sort(key=lambda a: ["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(a.severity))

        # Stats
        ip_counts = Counter(e.ip for e in entries if e.ip)
        status_counts = Counter(e.status_code for e in entries if e.status_code)
        severity_counts = Counter(a.severity for a in unique_alerts)

        return {
            "source": source,
            "total_lines": len(entries),
            "parsed_entries": sum(1 for e in entries if e.ip or e.timestamp),
            "unique_ips": len(ip_counts),
            "top_ips": ip_counts.most_common(10),
            "status_distribution": dict(status_counts),
            "alerts": unique_alerts,
            "alert_counts": dict(severity_counts),
            "entries": entries,
        }

    def print_report(self, result: dict):
        print("\n" + "═" * 65)
        print("  🔍 LOG ANALYZER REPORT")
        print("═" * 65)
        print(f"  Source       : {result['source']}")
        print(f"  Total Lines  : {result['total_lines']}")
        print(f"  Parsed       : {result['parsed_entries']}")
        print(f"  Unique IPs   : {result['unique_ips']}")

        counts = result["alert_counts"]
        print(f"\n  Alerts Found :")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            c = counts.get(sev, 0)
            icon = {"CRITICAL": "🚨", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}[sev]
            if c:
                print(f"    {icon} {sev}: {c}")

        print("\n  Top Source IPs:")
        for ip, cnt in result["top_ips"][:5]:
            print(f"    {ip:<20} {cnt} requests")

        print("\n" + "─" * 65)
        print("  ALERTS")
        print("─" * 65)
        for alert in result["alerts"]:
            print(f"\n  {alert}")
            if alert.evidence:
                for ev in alert.evidence[:2]:
                    print(f"    → {str(ev)[:100]}")

        print("\n" + "═" * 65)

    def export_json(self, result: dict, output_path: str):
        """Export results as JSON (serializable)."""
        serializable = {
            "source": result["source"],
            "total_lines": result["total_lines"],
            "parsed_entries": result["parsed_entries"],
            "unique_ips": result["unique_ips"],
            "top_ips": result["top_ips"],
            "status_distribution": result["status_distribution"],
            "alert_counts": result["alert_counts"],
            "alerts": [
                {
                    "severity": a.severity,
                    "category": a.category,
                    "description": a.description,
                    "ip": a.ip,
                    "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                    "evidence": a.evidence,
                }
                for a in result["alerts"]
            ],
        }
        with open(output_path, "w") as f:
            json.dump(serializable, f, indent=2)
        print(f"\n  ✅ JSON report saved to: {output_path}")


# ─────────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    analyzer = LogAnalyzer()

    if len(sys.argv) > 1:
        filepath = sys.argv[1]
        print(f"Analyzing: {filepath}")
        result = analyzer.analyze_file(filepath)
    else:
        # Built-in demo with synthetic logs
        print("No file provided — running demo with synthetic log data...\n")
        demo_logs = """
192.168.1.50 - - [17/Feb/2026:10:01:01 +0000] "POST /login HTTP/1.1" 401 512 "-" "Mozilla/5.0"
192.168.1.50 - - [17/Feb/2026:10:01:02 +0000] "POST /login HTTP/1.1" 401 512 "-" "Mozilla/5.0"
192.168.1.50 - - [17/Feb/2026:10:01:03 +0000] "POST /login HTTP/1.1" 401 512 "-" "Mozilla/5.0"
192.168.1.50 - - [17/Feb/2026:10:01:04 +0000] "POST /login HTTP/1.1" 401 512 "-" "Mozilla/5.0"
192.168.1.50 - - [17/Feb/2026:10:01:05 +0000] "POST /login HTTP/1.1" 401 512 "-" "Mozilla/5.0"
192.168.1.50 - - [17/Feb/2026:10:01:06 +0000] "POST /login HTTP/1.1" 401 512 "-" "Mozilla/5.0"
203.0.113.77 - - [17/Feb/2026:10:02:00 +0000] "GET /admin HTTP/1.1" 403 256 "-" "sqlmap/1.6"
203.0.113.77 - - [17/Feb/2026:10:02:01 +0000] "GET /.env HTTP/1.1" 404 128 "-" "sqlmap/1.6"
203.0.113.77 - - [17/Feb/2026:10:02:02 +0000] "GET /wp-admin HTTP/1.1" 404 128 "-" "sqlmap/1.6"
203.0.113.77 - - [17/Feb/2026:10:02:03 +0000] "GET /phpmyadmin HTTP/1.1" 404 128 "-" "sqlmap/1.6"
203.0.113.77 - - [17/Feb/2026:10:02:04 +0000] "GET /.git/config HTTP/1.1" 200 1024 "-" "sqlmap/1.6"
203.0.113.77 - - [17/Feb/2026:10:02:05 +0000] "GET /backup.sql HTTP/1.1" 200 1024 "-" "sqlmap/1.6"
198.51.100.1 - - [17/Feb/2026:10:03:00 +0000] "GET /../../etc/passwd HTTP/1.1" 400 256 "-" "curl/7.68"
10.0.0.5 - alice [17/Feb/2026:10:05:00 +0000] "GET /dashboard HTTP/1.1" 200 4096 "-" "Mozilla/5.0"
10.0.0.5 - alice [17/Feb/2026:10:05:30 +0000] "GET /api/users HTTP/1.1" 200 2048 "-" "Mozilla/5.0"
"""
        result = analyzer.analyze_text(demo_logs)

    analyzer.print_report(result)

    if len(sys.argv) > 2:
        analyzer.export_json(result, sys.argv[2])