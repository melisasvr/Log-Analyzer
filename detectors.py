"""
detectors.py — Advanced Threat Detectors
Includes: SQL Injection, XSS, Bot Detection, Geolocation Anomaly
Plug these into LogAnalyzer by adding them to the detectors list.
"""

import re
import json
import urllib.request
import urllib.error
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime, timedelta


# ─────────────────────────────────────────────────────────────────────────────
# Shared imports from main module
# Import Alert and LogEntry from log_analyzer when using together
# ─────────────────────────────────────────────────────────────────────────────
try:
    from log_analyzer import Alert, LogEntry, Config
except ImportError:
    # Standalone fallback definitions so this file can be read independently
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
        event_type: Optional[str] = None
        line_number: int = 0

    @dataclass
    class Alert:
        severity: str
        category: str
        description: str
        ip: Optional[str] = None
        timestamp: Optional[datetime] = None
        evidence: list = field(default_factory=list)

        def __str__(self):
            ts = self.timestamp.strftime("%Y-%m-%d %H:%M:%S") if self.timestamp else "N/A"
            return f"[{self.severity}] {self.category} | {self.description} | IP: {self.ip} | {ts}"

    class Config:
        FAILED_LOGIN_THRESHOLD = 15
        BRUTE_FORCE_WINDOW_SEC = 60
        RAPID_REQUEST_THRESHOLD = 100
        REPEATED_PATTERN_THRESHOLD = 20


# ─────────────────────────────────────────────────────────────────────────────
# 1. SQL INJECTION DETECTOR
# ─────────────────────────────────────────────────────────────────────────────
class SQLInjectionDetector:
    """
    Detects SQL injection attempts in URL paths and query strings.
    Covers classic payloads, blind injection, time-based attacks,
    UNION-based, error-based, and boolean-based patterns.
    """

    # Classic SQL keywords used in injection
    SQL_KEYWORDS = re.compile(
        r"(\b(select|insert|update|delete|drop|truncate|alter|create|exec|execute|"
        r"union|having|group\s+by|order\s+by|where|from|into|values|set)\b)",
        re.IGNORECASE
    )

    # Common injection syntax patterns
    SQL_SYNTAX = re.compile(
        r"('|\"|`)(.*?)(\bor\b|\band\b)(.*?)('|\"|`|--|\#)"  # ' OR '1'='1
        r"|--\s*$"                                             # trailing comment
        r"|\bor\b\s+\d+=\d+"                                  # OR 1=1
        r"|\bselect\b.+\bfrom\b"                              # SELECT ... FROM
        r"|\bunion\b.+\bselect\b"                             # UNION SELECT
        r"|\bwaitfor\s+delay\b"                               # MSSQL time-based
        r"|\bsleep\s*\(\s*\d+\s*\)"                          # MySQL SLEEP()
        r"|\bbenchmark\s*\("                                  # MySQL BENCHMARK()
        r"|\bload_file\s*\("                                  # MySQL file read
        r"|\binto\s+(outfile|dumpfile)\b"                     # MySQL file write
        r"|\bconvert\s*\(.+using\b"                          # charset injection
        r"|\bcast\s*\(.+as\s+(char|varchar|int)\b"           # CAST injection
        r"|0x[0-9a-fA-F]{4,}",                               # hex encoding
        re.IGNORECASE
    )

    # URL-encoded variants
    SQL_ENCODED = re.compile(
        r"%27|%22|%3b|%2d%2d|%23"   # ' " ; -- #
        r"|%20(or|and|union|select)%20"
        r"|\+or\+|\+and\+|\+union\+|\+select\+",
        re.IGNORECASE
    )

    # Error messages that indicate a successful injection probe
    SQL_ERROR_SIGNATURES = re.compile(
        r"(sql syntax|mysql_fetch|ORA-\d{5}|pg_query|sqlite_|"
        r"microsoft ole db|odbc sql server|syntax error.*sql|"
        r"unclosed quotation mark|quoted string not properly terminated)",
        re.IGNORECASE
    )

    def analyze(self, entries: list) -> list:
        alerts = []
        ip_sqli_hits: dict = defaultdict(list)

        for e in entries:
            targets = []
            if e.path:
                targets.append(e.path)
            if e.raw:
                targets.append(e.raw)

            detected = False
            matched_pattern = ""

            for target in targets:
                if self.SQL_SYNTAX.search(target):
                    detected = True
                    matched_pattern = self.SQL_SYNTAX.search(target).group()[:80]
                    break
                if self.SQL_ENCODED.search(target):
                    detected = True
                    matched_pattern = self.SQL_ENCODED.search(target).group()[:80]
                    break
                # Keyword density check: 3+ SQL keywords in a single request = suspicious
                kw_matches = self.SQL_KEYWORDS.findall(target)
                if len(kw_matches) >= 3:
                    detected = True
                    matched_pattern = f"{len(kw_matches)} SQL keywords in request"
                    break

            if detected and e.ip:
                ip_sqli_hits[e.ip].append((e, matched_pattern))

        for ip, hits in ip_sqli_hits.items():
            count = len(hits)
            severity = "CRITICAL" if count >= 5 else "HIGH"
            first_entry, pattern = hits[0]
            alerts.append(Alert(
                severity=severity,
                category="SQL_INJECTION",
                description=f"{ip} made {count} SQL injection attempt(s)",
                ip=ip,
                timestamp=first_entry.timestamp,
                evidence=[f"Pattern: {pattern}"] + [h[0].raw[:120] for h in hits[:3]]
            ))

        return alerts


# ─────────────────────────────────────────────────────────────────────────────
# 2. XSS DETECTOR
# ─────────────────────────────────────────────────────────────────────────────
class XSSDetector:
    """
    Detects Cross-Site Scripting (XSS) attempts.
    Covers reflected XSS, stored XSS probes, DOM-based patterns,
    event handler injection, and encoding evasion techniques.
    """

    # Script tag variants
    SCRIPT_TAG = re.compile(
        r"<\s*script[^>]*>|<\s*/\s*script\s*>"
        r"|<\s*script[^>]*/\s*>",
        re.IGNORECASE
    )

    # Event handler injection
    EVENT_HANDLERS = re.compile(
        r"\bon(load|error|click|mouseover|mouseout|focus|blur|change|submit|"
        r"keyup|keydown|keypress|input|paste|drag|drop|scroll|resize|"
        r"contextmenu|dblclick|touchstart|touchend)\s*=",
        re.IGNORECASE
    )

    # JavaScript protocol and dangerous URIs
    JS_PROTOCOL = re.compile(
        r"javascript\s*:"
        r"|vbscript\s*:"
        r"|data\s*:\s*text/html"
        r"|data\s*:\s*application/x-javascript",
        re.IGNORECASE
    )

    # Common XSS payloads
    XSS_PAYLOADS = re.compile(
        r"<\s*img[^>]+src\s*=[^>]*(onerror|onload)"   # <img src=x onerror=...>
        r"|<\s*svg[^>]*(onload|onerror)"               # <svg onload=...>
        r"|<\s*iframe[^>]*(src|srcdoc)"               # <iframe src=...>
        r"|<\s*body[^>]*(onload|onerror)"             # <body onload=...>
        r"|alert\s*\([^)]*\)"                          # alert()
        r"|confirm\s*\([^)]*\)"                        # confirm()
        r"|prompt\s*\([^)]*\)"                         # prompt()
        r"|document\.(cookie|location|write)"          # DOM access
        r"|window\.(location|open|eval)"               # window manipulation
        r"|eval\s*\("                                  # eval()
        r"|String\.fromCharCode\s*\(",                 # char encoding
        re.IGNORECASE
    )

    # URL-encoded XSS
    XSS_ENCODED = re.compile(
        r"%3c\s*script|%3cscript"      # <script
        r"|%3c\s*img|%3cimg"           # <img
        r"|%3c\s*svg|%3csvg"           # <svg
        r"|%22.*%3e|%27.*%3e"          # "...> or '...>
        r"|&#x?[0-9a-f]+;.*script",   # HTML entity encoding
        re.IGNORECASE
    )

    def analyze(self, entries: list) -> list:
        alerts = []
        ip_xss_hits: dict = defaultdict(list)

        for e in entries:
            targets = []
            if e.path:
                targets.append(e.path)
            if e.raw:
                targets.append(e.raw)

            detected = False
            payload_type = ""

            for target in targets:
                if self.SCRIPT_TAG.search(target):
                    detected = True
                    payload_type = "Script tag injection"
                    break
                if self.EVENT_HANDLERS.search(target):
                    detected = True
                    m = self.EVENT_HANDLERS.search(target)
                    payload_type = f"Event handler: {m.group()[:40]}"
                    break
                if self.JS_PROTOCOL.search(target):
                    detected = True
                    payload_type = "JavaScript protocol URI"
                    break
                if self.XSS_PAYLOADS.search(target):
                    detected = True
                    m = self.XSS_PAYLOADS.search(target)
                    payload_type = f"XSS payload: {m.group()[:50]}"
                    break
                if self.XSS_ENCODED.search(target):
                    detected = True
                    payload_type = "URL-encoded XSS attempt"
                    break

            if detected and e.ip:
                ip_xss_hits[e.ip].append((e, payload_type))

        for ip, hits in ip_xss_hits.items():
            count = len(hits)
            severity = "CRITICAL" if count >= 3 else "HIGH"
            first_entry, ptype = hits[0]
            alerts.append(Alert(
                severity=severity,
                category="XSS_ATTEMPT",
                description=f"{ip} made {count} XSS attempt(s) — {ptype}",
                ip=ip,
                timestamp=first_entry.timestamp,
                evidence=[h[0].raw[:120] for h in hits[:4]]
            ))

        return alerts


# ─────────────────────────────────────────────────────────────────────────────
# 3. BOT DETECTOR
# ─────────────────────────────────────────────────────────────────────────────
class BotDetector:
    """
    Detects automated bot traffic through multiple signals:
    - Known malicious bot user agents
    - Headless browser signatures
    - Scraper and crawler patterns
    - Request timing regularity (inhuman precision)
    - Missing or spoofed browser headers
    - Honeypot path access
    """

    # Known malicious/unwanted bots
    MALICIOUS_BOTS = re.compile(
        r"(sqlmap|nikto|nmap|masscan|zgrab|zmap|shodan|censys|"
        r"dirbuster|gobuster|wfuzz|ffuf|nuclei|burpsuite|"
        r"havij|acunetix|nessus|openvas|w3af|skipfish|"
        r"scrapy|phantomjs|selenium|puppeteer|playwright|"
        r"python-requests|go-http-client|java/\d|"
        r"libwww-perl|lwp-trivial|curl(?!/\d)|wget(?!/\d)|"
        r"httpie|insomnia|postman(?!/\d)|rest-client|"
        r"discord|slack|telegrambot|whatsapp|"
        r"semrush|ahrefs|mj12bot|dotbot|petalbot|"
        r"yandexbot|baiduspider|sogou|360spider)",
        re.IGNORECASE
    )

    # Headless browser signatures
    HEADLESS_SIGNATURES = re.compile(
        r"(headlesschrome|headless|phantomjs|"
        r"selenium/\d|webdriver|chromedriver|geckodriver|"
        r"htmlunit|cefsharp|electron/\d)",
        re.IGNORECASE
    )

    # Completely missing user agent
    MISSING_UA = ""

    # Honeypot paths — legitimate users should never access these
    HONEYPOT_PATHS = [
        "/honeypot", "/.hidden", "/trap", "/decoy",
        "/robots-test", "/fake-admin", "/__trap__",
        "/do-not-visit", "/secret-admin-panel",
    ]

    # Paths that bots commonly probe
    BOT_PROBE_PATHS = re.compile(
        r"(/robots\.txt|/sitemap\.xml|/sitemap_index\.xml|"
        r"/wp-login\.php|/xmlrpc\.php|/wp-cron\.php|"
        r"/feed/?$|/rss/?$|/atom/?$|"
        r"/.well-known/|/favicon\.ico)",
        re.IGNORECASE
    )

    def analyze(self, entries: list) -> list:
        alerts = []
        ip_bot_signals: dict = defaultdict(lambda: {
            "malicious_ua": [],
            "headless": [],
            "no_ua": 0,
            "honeypot": [],
            "probe_paths": [],
            "regular_timing": False,
        })

        for e in entries:
            if not e.ip:
                continue

            signals = ip_bot_signals[e.ip]
            ua = e.user_agent or ""

            # Malicious UA
            if self.MALICIOUS_BOTS.search(ua):
                signals["malicious_ua"].append(e)

            # Headless browser
            if self.HEADLESS_SIGNATURES.search(ua):
                signals["headless"].append(e)

            # Missing user agent
            if not ua.strip():
                signals["no_ua"] += 1

            # Honeypot access
            if e.path and any(e.path.lower().startswith(h) for h in self.HONEYPOT_PATHS):
                signals["honeypot"].append(e)

            # Bot probe paths
            if e.path and self.BOT_PROBE_PATHS.search(e.path):
                signals["probe_paths"].append(e)

        # Analyze timing regularity (requests at suspiciously even intervals)
        ip_timestamps: dict = defaultdict(list)
        for e in entries:
            if e.ip and e.timestamp:
                ip_timestamps[e.ip].append(e.timestamp)

        for ip, timestamps in ip_timestamps.items():
            if len(timestamps) >= 10:
                sorted_ts = sorted(timestamps)
                intervals = [
                    (sorted_ts[i+1] - sorted_ts[i]).total_seconds()
                    for i in range(len(sorted_ts)-1)
                ]
                if intervals:
                    avg = sum(intervals) / len(intervals)
                    variance = sum((x - avg)**2 for x in intervals) / len(intervals)
                    # Very low variance = suspiciously regular = likely bot
                    if avg > 0 and variance < 0.5 and len(intervals) >= 10:
                        ip_bot_signals[ip]["regular_timing"] = True

        # Generate alerts
        for ip, signals in ip_bot_signals.items():
            bot_evidence = []
            severity = "LOW"
            categories = []

            if signals["malicious_ua"]:
                ua = signals["malicious_ua"][0].user_agent or ""
                m = self.MALICIOUS_BOTS.search(ua)
                tool = m.group() if m else ua[:40]
                bot_evidence.append(f"Known malicious tool: {tool}")
                severity = "HIGH"
                categories.append("MALICIOUS_TOOL")

            if signals["headless"]:
                ua = signals["headless"][0].user_agent or ""
                bot_evidence.append(f"Headless browser detected: {ua[:60]}")
                severity = "HIGH"
                categories.append("HEADLESS_BROWSER")

            if signals["honeypot"]:
                paths = [e.path for e in signals["honeypot"]]
                bot_evidence.append(f"Accessed honeypot paths: {paths[:3]}")
                severity = "CRITICAL"
                categories.append("HONEYPOT_TRIGGERED")

            if signals["no_ua"] >= 10:
                bot_evidence.append(f"{signals['no_ua']} requests with no User-Agent")
                categories.append("MISSING_UA")

            if signals["regular_timing"]:
                bot_evidence.append("Suspiciously regular request intervals (bot rhythm)")
                categories.append("REGULAR_TIMING")

            if signals["probe_paths"] and len(signals["probe_paths"]) >= 3:
                unique_probes = list(set(e.path for e in signals["probe_paths"]))
                bot_evidence.append(f"Probed {len(unique_probes)} bot-typical paths")
                categories.append("BOT_PROBING")

            if bot_evidence:
                category_str = "+".join(categories) if categories else "BOT_DETECTED"
                alerts.append(Alert(
                    severity=severity,
                    category=category_str,
                    description=f"Bot activity from {ip} — {len(bot_evidence)} signal(s)",
                    ip=ip,
                    evidence=bot_evidence
                ))

        return alerts


# ─────────────────────────────────────────────────────────────────────────────
# 4. GEOLOCATION ANOMALY DETECTOR
# ─────────────────────────────────────────────────────────────────────────────
class GeoLocationDetector:
    """
    Enriches alerts with country/city data using the free ip-api.com service.
    Flags traffic from high-risk countries, Tor exit nodes,
    and detects impossible travel (same user, two countries in short time).

    NOTE: ip-api.com allows 45 requests/minute on the free tier.
    For high-volume analysis, results are cached to avoid hitting the limit.
    Set ENABLED = False to skip geo lookups entirely.
    """

    ENABLED = True   # Set False to skip all geo lookups
    API_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,proxy,hosting"
    TIMEOUT = 3      # seconds per request
    CACHE_FILE = ".geo_cache.json"

    # Countries commonly associated with high attack volumes
    # Adjust this list based on your own threat model
    HIGH_RISK_COUNTRIES = {
        "CN", "RU", "KP", "IR", "NG", "BR", "UA", "RO", "IN", "VN"
    }

    def __init__(self):
        self._cache: dict = self._load_cache()

    def _load_cache(self) -> dict:
        try:
            with open(self.CACHE_FILE, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _save_cache(self):
        try:
            with open(self.CACHE_FILE, "w") as f:
                json.dump(self._cache, f, indent=2)
        except IOError:
            pass

    def _is_private_ip(self, ip: str) -> bool:
        """Skip geo lookups for private/reserved IP ranges."""
        private_prefixes = ("10.", "192.168.", "172.16.", "172.17.", "172.18.",
                            "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                            "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                            "172.29.", "172.30.", "172.31.", "127.", "::1", "0.")
        return ip.startswith(private_prefixes)

    def lookup(self, ip: str) -> Optional[dict]:
        """Look up geo data for an IP, using cache when available."""
        if not self.ENABLED:
            return None
        if self._is_private_ip(ip):
            return None
        if ip in self._cache:
            return self._cache[ip]

        try:
            url = self.API_URL.format(ip=ip)
            req = urllib.request.Request(url, headers={"User-Agent": "LogAnalyzer/1.0"})
            with urllib.request.urlopen(req, timeout=self.TIMEOUT) as resp:
                data = json.loads(resp.read().decode())
                if data.get("status") == "success":
                    result = {
                        "country": data.get("country", "Unknown"),
                        "country_code": data.get("countryCode", "??"),
                        "city": data.get("city", "Unknown"),
                        "isp": data.get("isp", "Unknown"),
                        "is_proxy": data.get("proxy", False),
                        "is_hosting": data.get("hosting", False),
                    }
                    self._cache[ip] = result
                    self._save_cache()
                    return result
        except (urllib.error.URLError, urllib.error.HTTPError, Exception):
            pass
        return None

    def analyze(self, entries: list) -> list:
        if not self.ENABLED:
            return []

        alerts = []
        unique_ips = list(set(e.ip for e in entries if e.ip))

        # Collect geo data for all unique IPs
        geo_map: dict = {}
        for ip in unique_ips[:50]:  # Limit to 50 IPs to respect rate limit
            geo = self.lookup(ip)
            if geo:
                geo_map[ip] = geo

        # Flag high-risk country IPs
        for ip, geo in geo_map.items():
            code = geo.get("country_code", "??")
            country = geo.get("country", "Unknown")
            city = geo.get("city", "Unknown")
            isp = geo.get("isp", "")

            if code in self.HIGH_RISK_COUNTRIES:
                alerts.append(Alert(
                    severity="MEDIUM",
                    category="GEO_HIGH_RISK",
                    description=f"{ip} originates from high-risk country: {country} ({code}), {city}",
                    ip=ip,
                    evidence=[f"ISP: {isp}", f"Country: {country} ({code})", f"City: {city}"]
                ))

            # Flag proxy/VPN/hosting IPs
            if geo.get("is_proxy"):
                alerts.append(Alert(
                    severity="MEDIUM",
                    category="GEO_PROXY_VPN",
                    description=f"{ip} is a known proxy/VPN node ({country})",
                    ip=ip,
                    evidence=[f"ISP: {isp}", f"Proxy: True"]
                ))

            if geo.get("is_hosting"):
                alerts.append(Alert(
                    severity="LOW",
                    category="GEO_DATACENTER",
                    description=f"{ip} is a datacenter/hosting IP ({isp})",
                    ip=ip,
                    evidence=[f"ISP: {isp}", f"Hosting: True"]
                ))

        # Impossible travel detection:
        # Same username seen from two different countries within a short time
        user_geo_timeline: dict = defaultdict(list)
        for e in entries:
            if e.username and e.ip and e.timestamp and e.ip in geo_map:
                user_geo_timeline[e.username].append({
                    "ip": e.ip,
                    "timestamp": e.timestamp,
                    "country": geo_map[e.ip].get("country", "?"),
                    "code": geo_map[e.ip].get("country_code", "??"),
                })

        for username, timeline in user_geo_timeline.items():
            sorted_events = sorted(timeline, key=lambda x: x["timestamp"])
            for i in range(len(sorted_events) - 1):
                a = sorted_events[i]
                b = sorted_events[i + 1]
                if a["code"] != b["code"]:
                    delta = (b["timestamp"] - a["timestamp"]).total_seconds() / 3600
                    if delta < 2:  # Different country within 2 hours = impossible
                        alerts.append(Alert(
                            severity="CRITICAL",
                            category="GEO_IMPOSSIBLE_TRAVEL",
                            description=(
                                f"Impossible travel for '{username}': "
                                f"{a['country']} → {b['country']} in {delta:.1f}h"
                            ),
                            ip=b["ip"],
                            evidence=[
                                f"First seen: {a['country']} from {a['ip']} at {a['timestamp']}",
                                f"Then seen: {b['country']} from {b['ip']} at {b['timestamp']}",
                                f"Time delta: {delta:.1f} hours"
                            ]
                        ))

        return alerts


# ─────────────────────────────────────────────────────────────────────────────
# INTEGRATION HELPER
# ─────────────────────────────────────────────────────────────────────────────
def get_all_advanced_detectors(enable_geo: bool = False) -> list:
    """
    Returns all advanced detector instances ready to plug into LogAnalyzer.

    Usage:
        from detectors import get_all_advanced_detectors
        from log_analyzer import LogAnalyzer

        analyzer = LogAnalyzer()
        analyzer.detectors += get_all_advanced_detectors(enable_geo=True)
        result = analyzer.analyze_file("access.log")

    Args:
        enable_geo: Set True to enable GeoIP lookups (requires internet access).
                    Uses ip-api.com free tier (45 req/min limit).
    """
    geo = GeoLocationDetector()
    geo.ENABLED = enable_geo

    return [
        SQLInjectionDetector(),
        XSSDetector(),
        BotDetector(),
        geo,
    ]


# ─────────────────────────────────────────────────────────────────────────────
# STANDALONE DEMO
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n🧪 Running advanced detector demo...\n")

    sample_logs = [
        # SQL injection attempts
        LogEntry(raw="GET /search?q=1'+OR+'1'='1 HTTP/1.1", ip="10.0.0.1",
                 path="/search?q=1'+OR+'1'='1", status_code=200,
                 timestamp=datetime(2026, 2, 17, 10, 0, 1)),
        LogEntry(raw="GET /user?id=1 UNION SELECT username,password FROM users HTTP/1.1",
                 ip="10.0.0.1", path="/user?id=1 UNION SELECT username,password FROM users",
                 status_code=500, timestamp=datetime(2026, 2, 17, 10, 0, 2)),
        LogEntry(raw="GET /item?id=1; DROP TABLE users-- HTTP/1.1", ip="10.0.0.1",
                 path="/item?id=1; DROP TABLE users--", status_code=400,
                 timestamp=datetime(2026, 2, 17, 10, 0, 3)),

        # XSS attempts
        LogEntry(raw='GET /comment?text=<script>alert(1)</script> HTTP/1.1', ip="10.0.0.2",
                 path='/comment?text=<script>alert(1)</script>', status_code=200,
                 timestamp=datetime(2026, 2, 17, 10, 1, 0)),
        LogEntry(raw='GET /profile?name=<img src=x onerror=alert(document.cookie)> HTTP/1.1',
                 ip="10.0.0.2",
                 path='/profile?name=<img src=x onerror=alert(document.cookie)>',
                 status_code=200, timestamp=datetime(2026, 2, 17, 10, 1, 1)),

        # Bot activity
        LogEntry(raw='GET /admin HTTP/1.1', ip="10.0.0.3",
                 path="/admin", status_code=403,
                 user_agent="sqlmap/1.6#stable (https://sqlmap.org)",
                 timestamp=datetime(2026, 2, 17, 10, 2, 0)),
        LogEntry(raw='GET /robots.txt HTTP/1.1', ip="10.0.0.4",
                 path="/robots.txt", status_code=200,
                 user_agent="Mozilla/5.0 (compatible; Googlebot/2.1)",
                 timestamp=datetime(2026, 2, 17, 10, 3, 0)),
        LogEntry(raw='GET /.env HTTP/1.1', ip="10.0.0.3",
                 path="/.env", status_code=404,
                 user_agent="sqlmap/1.6#stable",
                 timestamp=datetime(2026, 2, 17, 10, 2, 1)),
    ]

    detectors = [SQLInjectionDetector(), XSSDetector(), BotDetector()]
    all_alerts = []
    for detector in detectors:
        all_alerts.extend(detector.analyze(sample_logs))

    # Deduplicate
    seen = set()
    unique = []
    for a in all_alerts:
        key = (a.category, a.ip)
        if key not in seen:
            seen.add(key)
            unique.append(a)

    print(f"  Found {len(unique)} alert(s):\n")
    for alert in unique:
        print(f"  {alert}")
        for ev in alert.evidence[:2]:
            print(f"    → {ev}")
    print()