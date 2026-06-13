<p align="center">
  <img src="assets/logo_dark.jpg" alt="PhishLens Logo" width="420"/>
</p>

<h1 align="center">PhishLens</h1>
<p align="center">
  <strong>Advanced Phishing Email Analyzer</strong><br>
Free, local phishing email analyzer — parses .eml/.msg, extracts IOCs, checks SPF/DKIM/DMARC, scores risk 0–100, and optionally enriches with VirusTotal, AbuseIPDB, URLScan, WHOIS, and Claude AI threat intelligence. No cloud. Your emails stay on your machine.Free, local phishing email analyzer — parses .eml/.msg, extracts IOCs, checks SPF/DKIM/DMARC, scores risk 0–100, and optionally enriches with VirusTotal, AbuseIPDB, URLScan, WHOIS, and Claude AI threat intelligence. No cloud. Your emails stay on your machine.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-2.0.0-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/python-3.8+-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square"/>
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/cost-free-brightgreen?style=flat-square"/>
</p>

---

## What is PhishLens?

PhishLens is a **free, local, installable** phishing email analysis tool. It parses `.eml` and `.msg` files, extracts IOCs, checks authentication headers, scores risk, and optionally enriches findings with live OSINT and AI-powered threat intelligence — all without sending your emails to any external service unless you explicitly enable it.

No subscription. No cloud. Your emails stay on your machine.

---

## Quick Start

```bash
# Clone or extract
git clone https://github.com/boltx/phishlens

# Install dependencies
pip install -r requirements.txt

# Launch
python run.py
```

Browser opens automatically at **http://127.0.0.1:7331**

---

## Features

### Core Analysis — Free, No API Keys Required
| Feature | Description |
|---------|-------------|
| Email Parsing | Full `.eml` and `.msg` (Outlook) support — MIME, multipart, base64 |
| Header Analysis | From, To, Reply-To, X-Originating-IP, X-Mailer, Message-ID |
| Auth Checks | SPF / DKIM / DMARC parsed from `Authentication-Results` |
| IOC Extraction | URLs, IPs, domains, email addresses |
| URL Analysis | IP-based URLs, shorteners, lookalike domains, suspicious TLDs |
| Attachment Analysis | Dangerous extension detection, SHA256 + MD5 hashing |
| Spoofing Detection | Display name spoofing, Reply-To mismatch |
| Received Chain | Full hop-by-hop trace |
| Keyword Detection | 40+ phishing keyword patterns |
| Risk Scoring | 0–100 weighted score with full factor breakdown |
| Bulk Analysis | Up to 50 files at once, parallel processing |
| History | SQLite persistence — search, filter, sort, export |
| Export | JSON, TXT (single) — CSV + JSON (bulk) |

### OSINT Integrations — Optional, Your Own API Keys
| Service | What It Does | Free Tier |
|---------|-------------|-----------|
| VirusTotal | URL, IP, domain, file hash reputation | 4 req/min |
| AbuseIPDB | IP abuse score, country, ISP, TOR node detection | 1000 checks/day |
| URLScan.io | Full URL scan with screenshot | Free tier available |
| WHOIS | Registrar, creation date, age, newly-registered flag | Free (no key needed) |
| DNS | A, MX, TXT, NS records + SPF/DMARC record lookup | Free (no key needed) |

### AI Analysis — Optional, Your Own API Key
- **Claude AI** — full threat intelligence report:
  - Attack type classification (credential phishing, BEC, malware delivery, etc.)
  - MITRE ATT&CK TTP mapping with technique IDs
  - Infrastructure analysis
  - Social engineering tactic breakdown
  - Recommended SOC actions
  - Threat hunting queries for SIEM

> AI analysis uses the Anthropic API — approximately $0.01 per email at Claude Sonnet rates.

---

## API Keys

All integrations are **100% optional**. The tool works fully without any API keys.

To add keys: run the tool → go to **SETTINGS** tab → enter keys → click **SAVE**.

Keys are stored locally in `phishlens_config.json` (never committed — listed in `.gitignore`).

| Service | Get Your Key |
|---------|-------------|
| VirusTotal | https://virustotal.com/gui/my-apikey |
| AbuseIPDB | https://abuseipdb.com/account/api |
| URLScan.io | https://urlscan.io/user/profile |
| Anthropic (Claude AI) | https://console.anthropic.com/settings/keys |

---

## Run Options

```bash
python run.py                      # Default — port 7331, opens browser
python run.py --port 8080          # Custom port
python run.py --no-browser         # Don't auto-open browser
python run.py --host 0.0.0.0       # Expose on LAN
python run.py --reload             # Dev mode — auto-reload on code change
python run.py --data-dir ~/data    # Custom directory for DB and config
```

---

## Project Structure

```
PhishLens/
├── run.py                     ← Cross-platform launcher (auto-installs deps)
├── requirements.txt           ← Python dependencies
├── .gitignore                 ← Excludes config, DB, venv, build artifacts
├── CHANGELOG.md               ← Version history
│
├── backend/
│   ├── main.py                ← FastAPI server — all API routes
│   ├── parser.py              ← Email parsing engine (.eml + .msg)
│   ├── osint.py               ← Async OSINT orchestrator
│   ├── ai_analysis.py         ← Claude AI threat intelligence engine
│   └── config.py              ← Config manager (PHISHLENS_DATA_DIR aware)
│
├── frontend/
│   └── index.html             ← Single-file SPA — 5 pages
│
├── samples/
│   ├── sample_phishing.eml    ← Test phishing email (score: 100)
│   └── sample_clean.eml       ← Test clean email (score: 0)
│
├── assets/
│   ├── logo.png               ← Logo (light background)
│   └── logo_dark.jpg          ← Logo (dark background)
│
└── packaging/
    ├── build_deb.sh           ← Build .deb installer (Ubuntu/Debian/Kali)
    ├── build_appimage.sh      ← Build portable AppImage (any Linux x86_64)
    ├── make_icon.py           ← Generate app icon from SVG
    └── deb/                   ← Debian package structure
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/analyze` | Upload single `.eml` or `.msg` |
| `POST` | `/api/analyze/raw` | Submit raw email text (paste mode) |
| `POST` | `/api/analyze/full` | Parse + OSINT + AI in one request |
| `POST` | `/api/analyze/bulk` | Upload up to 50 files at once |
| `POST` | `/api/osint/{id}` | Run OSINT on an existing analysis |
| `POST` | `/api/ai/{id}` | Run AI analysis on an existing analysis |
| `GET` | `/api/history` | List all past analyses |
| `GET` | `/api/history/{id}` | Get full result for one analysis |
| `DELETE` | `/api/history/{id}` | Delete one analysis |
| `DELETE` | `/api/history` | Clear all history |
| `GET` | `/api/stats` | Dashboard statistics |
| `GET` | `/api/config` | Read current settings (keys masked) |
| `POST` | `/api/config` | Save settings |
| `GET` | `/health` | Backend health check + service status |

---

## Linux Installation

### .deb Package — Ubuntu / Debian / Kali
```bash
bash packaging/build_deb.sh
sudo dpkg -i dist/phishlens_2.0.0_amd64.deb
phishlens
```

### AppImage — Any Linux x86_64 (no install needed)
```bash
bash packaging/build_appimage.sh
chmod +x dist/PhishLens-2.0.0-x86_64.AppImage
./dist/PhishLens-2.0.0-x86_64.AppImage
```

### Uninstall
```bash
sudo dpkg -r phishlens
```

---

## Requirements

- Python 3.8 or higher
- pip (dependencies install automatically on first run)

---

## Testing with Sample Files

Two sample emails are included in the `samples/` directory:

```bash
# Open the tool and drop these files to verify everything works
samples/sample_phishing.eml   → Expected: PHISHING, Score ~100
samples/sample_clean.eml      → Expected: LIKELY CLEAN, Score ~0
```

---

## License

MIT License — free to use, modify, and distribute.

---

<p align="center">
  <img src="assets/logo.png" alt="PhishLens" width="300"/>
  <br>
  <strong>Built by Boltx</strong>
</p>
