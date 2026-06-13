# Changelog — PhishLens

All notable changes listed here.

---

## [2.0.0] — 2026-06-11

### Added
- Full Python FastAPI backend — no more browser-only limitations
- `.eml` and `.msg` (Outlook) file parsing
- SPF / DKIM / DMARC extraction from `Authentication-Results` headers
- IOC extraction — URLs, IPs, domains, email addresses
- URL risk analysis — shorteners, IP-based URLs, lookalike domains, suspicious TLDs
- Attachment analysis — dangerous extension detection, SHA256/MD5 hashing
- Display name spoofing + Reply-To mismatch detection
- Received chain hop analysis
- 40+ phishing keyword patterns
- Risk scoring engine — 0–100 weighted score with factor breakdown
- **OSINT layer** — VirusTotal, AbuseIPDB, URLScan.io, WHOIS, DNS (all optional via config)
- **AI analysis** — Claude-powered threat intelligence report with MITRE ATT&CK mapping
- **Bulk analysis** — up to 50 .eml/.msg files at once, parallel processing
- History persistence — SQLite database, survives restarts
- History search, filter by verdict, filter by score, sortable columns
- Dashboard stats page
- Settings page — API keys configurable from UI, saved to `phishlens_config.json`
- Export — JSON, TXT (single), CSV + JSON (bulk)
- Linux packaging — `.deb` installer + AppImage build scripts
- Cross-platform launcher — Windows / Linux / macOS via `python run.py`
- Auto-opens browser on launch
- Auto-installs dependencies on first run

### Architecture
- `backend/parser.py` — email parsing + risk engine
- `backend/osint.py` — async OSINT orchestrator
- `backend/ai_analysis.py` — Claude AI integration
- `backend/config.py` — config manager (`PHISHLENS_DATA_DIR` aware)
- `backend/main.py` — FastAPI server with all routes
- `frontend/index.html` — 5-page SPA (Analyze, Bulk, History, Stats, Settings)
- `run.py` — cross-platform launcher with auto-dep-install

---

## [1.0.0] — 2026-05-01

### Initial Release
- Single-file HTML tool (client-side only)
- Basic header parsing in browser
- Manual IOC extraction
- Static risk scoring
