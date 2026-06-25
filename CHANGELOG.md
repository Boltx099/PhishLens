# Changelog — PhishLens

All notable changes listed here.

---

## [2.1.0] — 2026-06-21

### Detection Engine (parser.py)
- **Brand impersonation engine** — 25 known brands (PayPal, Google, Microsoft, Apple, Amazon, Netflix, Facebook, banks, couriers, etc.); detects display name claiming brand but sending from unrelated domain
- **Lookalike / homograph domain detection** — regex patterns for char-substitution attacks (`paypa1`, `g00gle`, `arnazon`, `micros0ft`, `app1e`, `paypal-secure.*`, `secure-paypal.*` etc.)
- **IDN / Punycode detection** — flags `xn--` domains used in homograph attacks
- **Weighted keyword categories** — replaced flat keyword list with 6 scored categories (credential harvest, account threat, urgency, financial scam, prize scam, credential request); global 35pt cap prevents over-flagging
- **Auth scoring rebalanced** — `fail` vs `none` treated differently; SPF softfail/fail = 15/25pts, `none` = 8pts; all three pass = −10 bonus
- **Suspicious sender TLD** — flags `.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.xyz`, `.top`, `.click`, `.work`, `.online` etc. in From domain
- **Free email provider for brand sender** — detects "PayPal Security" sending from gmail.com
- **HTML-only body detection** — phishing emails often omit plain text part
- **Missing Message-ID flag** — phishing tools often skip this required header
- **URL analysis expanded** — 17 shortener patterns, 12 high-abuse TLDs, brand-as-subdomain detection, HTTP on credential pages

### Security Hardening (main.py, config.py, osint.py)
- Local API token — every `/api/*` request authenticated; auto-injected into served HTML
- CORS restricted to `127.0.0.1`/`localhost` only (was `allow_origins=["*"]`)
- TLS verification re-enabled on all OSINT calls (was `ssl=False`)
- All email-derived data HTML-escaped in frontend before `innerHTML` injection
- Default model updated: `claude-sonnet-4-6`

### UI Improvements (frontend/index.html)
- Score bar color: red ≥70, amber ≥40, green <40 (was always blue)
- Full scan button promoted to primary; Parse only demoted to secondary
- Step-by-step loading progress: Parsing → OSINT → AI → Done
- Idle state hints: drop anywhere, paste headers, bulk 50 files
- Stats page: mini progress bars, detection rate %, empty state message
- Settings save: button turns green ✓ + health re-check after save
- Bulk results: click row to open full report in Analyze tab
- Global drag-and-drop on any tab
- Version badge auto-updates from `/health` endpoint

### Repo hygiene
- Added `.gitignore` (excludes `phishlens.db`, `phishlens_config.json`, `.phishlens_token`, `__pycache__/`, `dist/`, `*.deb`, `*.AppImage`)
- `DEPLOY.md` + `Procfile` for Railway/Render demo deployment
- README: slide screenshots, detection coverage table, updated feature list

 — 2026-06-11

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
