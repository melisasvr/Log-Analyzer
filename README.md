# 🔍 Log Analyzer
- A Python tool that parses server log files and detects suspicious behavior, including brute-force attacks, SQL injection, XSS attempts, bot activity, IP anomalies, and repeated access patterns. Comes with a CLI, email/Slack alerting, and an interactive browser dashboard.

---

## 📁 Project Files

| File | Lines | Description |
|------|-------|-------------|
| `log_analyzer.py` | 502 | Core engine — parser, detectors, reporter |
| `detectors.py` | 699 | Advanced detectors — SQL injection, XSS, bots, GeoIP |
| `cli.py` | 540 | Full CLI with argparse flags and multiple output formats |
| `alerting.py` | 605 | Email (HTML + plain) and Slack alerting |
| `log_analyzer_dashboard.html` | 979 | Interactive browser dashboard |

**Total: 3,325 lines**

---

## 🚀 Getting Started

No external dependencies required. Uses only the Python standard library.

**Place all files in the same folder:**
```
Log Analyzer/
├── log_analyzer.py
├── detectors.py
├── cli.py
├── alerting.py
├── log_analyzer_dashboard.html
└── access.log        ← your log file goes here
```

**Run the demo instantly (no log file needed):**
```bash
python cli.py --demo
```

**Analyze your log file:**
```bash
python cli.py --file access.log
```

**Analyze with advanced detectors (SQL injection, XSS, bots):**
```bash
python cli.py --file access.log --advanced
```

---

## 🖥️ Dashboard

Open `log_analyzer_dashboard.html` in any browser. Paste log lines and click **Analyze**, or hit **Demo** to load sample attack logs instantly. Supports filtering by severity, clickable alert cards with evidence, and live IP stats in the sidebar.

---

## 🛡️ What It Detects

### Core Detectors (`log_analyzer.py`)

| Detection | Severity | Trigger |
|-----------|----------|---------|
| Brute Force | HIGH / CRITICAL | 15+ failed logins from one IP |
| Rapid Brute Force | HIGH | 15+ failures within a 60-second window |
| Credential Stuffing | CRITICAL | One IP targeting 5+ different usernames |
| Path Traversal | CRITICAL | `../`, `%2e%2e`, or encoded variants in URL |
| Sensitive Path Scan | HIGH | Accessing `.env`, `/admin`, `.git`, `backup.sql`, etc. |
| Suspicious User Agent | MEDIUM | Tools like `sqlmap`, `nikto`, `nmap`, `curl`, `scrapy` |
| High Request Volume | HIGH | 100+ requests/minute from a single IP |
| Repeated Access | LOW | Same endpoint hit 20+ times |
| Path Enumeration | MEDIUM | Single IP probing 50+ unique paths |
| Error Spike | MEDIUM | 30+ error responses (4xx/5xx) from one IP |

### Advanced Detectors (`detectors.py`) — enable with `--advanced`

| Detection | Severity | What It Catches |
|-----------|----------|-----------------|
| SQL Injection | HIGH / CRITICAL | `UNION SELECT`, `OR 1=1`, `SLEEP()`, hex encoding, encoded variants |
| XSS Attempt | HIGH / CRITICAL | `<script>`, event handlers, `javascript:`, `alert()`, DOM access |
| Bot Detection | MEDIUM / HIGH / CRITICAL | Known tools, headless browsers, honeypot access, regular timing patterns |
| GeoIP Anomaly | MEDIUM | High-risk countries, proxy/VPN nodes, datacenter IPs |
| Impossible Travel | CRITICAL | Same user seen from two countries within 2 hours |

---

## ⌨️ CLI Reference (`cli.py`)

```bash
python cli.py [OPTIONS]
```

### Input
| Flag | Description |
|------|-------------|
| `--file PATH` | Log file to analyze |
| `--demo` | Run with built-in synthetic attack logs |
| `--stdin` | Read from stdin (pipe mode) |

### Detection
| Flag | Default | Description |
|------|---------|-------------|
| `--threshold N` | 15 | Failed logins before brute-force alert |
| `--window SECONDS` | 60 | Time window for rapid brute-force |
| `--rate RPM` | 100 | Requests/min to flag as anomaly |
| `--repeat N` | 20 | Same-path hits to flag |
| `--advanced` | off | Enable SQL injection, XSS, bot detectors |
| `--geo` | off | Enable GeoIP lookups (requires internet) |

### Filtering
| Flag | Description |
|------|-------------|
| `--severity LEVEL` | Only show CRITICAL, HIGH, MEDIUM, or LOW alerts |
| `--category CAT` | Filter by category (e.g. `BRUTE_FORCE SQL_INJECTION`) |
| `--ip ADDRESS` | Filter results to a specific IP |
| `--min-requests N` | Only show IPs with N+ requests |

### Output
| Flag | Description |
|------|-------------|
| `--format` | `terminal` (default), `json`, `csv`, `table`, `summary` |
| `--output FILE` | Save report to file |
| `--top-ips N` | Number of top IPs to show (default: 10) |
| `--no-evidence` | Hide raw log evidence lines |
| `--no-color` | Disable ANSI colors |
| `--quiet` | Only print alerts, no banner |

### Alerting
| Flag | Description |
|------|-------------|
| `--alert-email ADDRESS` | Send HTML email when threats found |
| `--alert-slack WEBHOOK` | Send Slack message to webhook URL |
| `--alert-min-severity` | Minimum severity to trigger alerts (default: HIGH) |

### Examples
```bash
# Demo mode
python cli.py --demo

# Analyze file with all detectors
python cli.py --file access.log --advanced --geo

# Only critical alerts, save as JSON
python cli.py --file access.log --severity CRITICAL --format json --output report.json

# Table format, filter by IP
python cli.py --file access.log --format table --ip 203.0.113.77

# One-line summary (good for monitoring scripts)
python cli.py --file access.log --format summary

# Pipe mode
cat access.log | python cli.py --stdin --advanced

# Send Slack alert
python cli.py --file access.log --alert-slack https://hooks.slack.com/services/...

# Send email alert
python cli.py --file access.log --alert-email admin@yourcompany.com
```

---

## 📣 Alerting Setup (`alerting.py`)

### Preview alerts without sending
```bash
python alerting.py --preview plain    # Plain text email preview
python alerting.py --preview html     # HTML email preview
python alerting.py --preview slack    # Slack Block Kit JSON preview
```

### Slack Setup
1. Go to [api.slack.com/apps](https://api.slack.com/apps) → Create App
2. Enable **Incoming Webhooks** → Add to Workspace
3. Copy the webhook URL and pass it via `--alert-slack`

### Email Setup (Gmail)
1. Go to [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
2. Generate an App Password for "Mail."
3. Set environment variables:

**Windows:**
```bash
set LOGSCAN_SMTP_USER=you@gmail.com
set LOGSCAN_SMTP_PASS=your-app-password
```

**Mac / Linux:**
```bash
export LOGSCAN_SMTP_USER="you@gmail.com"
export LOGSCAN_SMTP_PASS="your-app-password"
```

Then run:
```bash
python cli.py --file access.log --alert-email admin@yourcompany.com
```

### Environment Variables
| Variable | Default | Description |
|----------|---------|-------------|
| `LOGSCAN_SMTP_HOST` | `smtp.gmail.com` | SMTP server |
| `LOGSCAN_SMTP_PORT` | `587` | SMTP port (STARTTLS) |
| `LOGSCAN_SMTP_USER` | — | Your email address |
| `LOGSCAN_SMTP_PASS` | — | App password |
| `LOGSCAN_FROM_EMAIL` | SMTP user | Sender address |

---

## ⚙️ Configuration
- Thresholds are in the `Config` class in `log_analyzer.py`. You can also override them via CLI flags.

```python
class Config:
    FAILED_LOGIN_THRESHOLD = 15       # Failed logins before alert triggers
    BRUTE_FORCE_WINDOW_SEC = 60       # Rapid brute-force time window (seconds)
    RAPID_REQUEST_THRESHOLD = 100     # Requests/min to flag as anomaly
    REPEATED_PATTERN_THRESHOLD = 20   # Same endpoint hits to flag
```

**Brute force severity escalation:**
- 15–29 failures → `HIGH`
- 30+ failures → `CRITICAL`

---

## 📋 Supported Log Formats

| Format | Example |
|--------|---------|
| Apache / Nginx combined | `192.168.1.1 - - [17/Feb/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1024` |
| SSH / Auth logs | `Feb 17 10:00:00 server sshd[1234]: Failed password for root from 1.2.3.4` |
| Generic (IP + timestamp) | Any log line containing an IPv4 address and ISO timestamp |

---

## 📤 Output Formats

### Terminal (default)
```
═════════════════════════════════════════════════════════════════
  🔍 LOGSCAN — THREAT ANALYSIS REPORT
═════════════════════════════════════════════════════════════════
  Source      : access.log
  Analyzed at : 2026-02-18 12:35:47
  Total Lines : 24
  Unique IPs  : 5

  Alert Summary:
    🚨 CRITICAL     1  █
    🔴 HIGH         3  ███
    🟡 MEDIUM       2  ██

  [CRITICAL] PATH_TRAVERSAL
  Traversal attempt: /../../etc/passwd
  IP: 198.51.100.1  |  Time: 2026-02-17 10:03:00
    → 198.51.100.1 - - "GET /../../etc/passwd HTTP/1.1" 400
```

### JSON
```bash
python cli.py --file access.log --format json --output report.json
```
```json
{
  "meta": { "source": "access.log", "total_lines": 24, "unique_ips": 5 },
  "summary": { "CRITICAL": 1, "HIGH": 3, "MEDIUM": 2 },
  "alerts": [
    {
      "severity": "CRITICAL",
      "category": "PATH_TRAVERSAL",
      "ip": "198.51.100.1",
      "description": "Traversal attempt: /../../etc/passwd",
      "evidence": ["GET /../../etc/passwd HTTP/1.1 400"]
    }
  ]
}
```

### Table
```bash
python cli.py --file access.log --format table
```
```
SEVERITY   CATEGORY           IP                 DESCRIPTION
──────────────────────────────────────────────────────────────────────────
CRITICAL   PATH_TRAVERSAL     198.51.100.1       Traversal attempt: /../../etc/passwd
HIGH       BRUTE_FORCE        192.168.1.50       15 failed login attempts from 192.168.1.50
```

### Summary (one line — good for monitoring)
```bash
python cli.py --file access.log --format summary
```
```
source=access.log lines=24 ips=5 critical=1 high=3 medium=2 low=0 total_alerts=6
```

---

## 🏗️ Architecture

```
Log Analyzer/
├── log_analyzer.py
│   ├── LogParser                — Parses Apache, SSH, and generic formats
│   ├── FailedLoginDetector      — Brute force & credential stuffing
│   ├── IPAnomalyDetector        — Volume, user agent, error spike
│   └── RepeatedAccessDetector   — Path scanning, traversal, enumeration
│
├── detectors.py
│   ├── SQLInjectionDetector     — SQL syntax, keywords, encoding evasion
│   ├── XSSDetector              — Script tags, event handlers, JS protocol
│   ├── BotDetector              — Known tools, headless browsers, timing analysis
│   └── GeoLocationDetector      — Country risk, proxy/VPN, impossible travel
│
├── cli.py                       — argparse CLI, formatters, output routing
├── alerting.py                  — Email (HTML/plain) + Slack Block Kit
└── log_analyzer_dashboard.html  — Browser-based interactive UI
```

Each detector is independent and returns a list of `Alert` objects. Add new detectors by creating a class with an `analyze(entries)` method and registering it in `LogAnalyzer.__init__`.

---

## 🔮 Possible Future Improvements

- Real-time log tailing (streaming mode)
- SQLite storage for historical trending and comparison
- Machine learning anomaly detection based on baseline behavior
- Custom rule engine via YAML/JSON config file
- Windows Event Log support
- Docker container for easy deployment

---

## 📄 License
- This project is licensed under the **MIT License**.

```
MIT License

Copyright (c) 2026 Space Weather Forecasting Project

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including, without limitation, the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 🤝 Contributing
- Contributions welcome! 
