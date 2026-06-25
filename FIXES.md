# PhishLens — security/bug fixes applied

## 1. Stored XSS (frontend/index.html)
Every place that injected email-derived data (subject, from, reply-to, raw
headers, relay chain, IOC list, OSINT results, AI output, history table)
into `innerHTML` now goes through a new `escapeHtml()` helper first. Since
PhishLens analyzes attacker-controlled email content by design, an
unescaped subject/header was a guaranteed stored-XSS vector against the
analyst viewing the report.

## 2. TLS verification disabled (backend/osint.py)
`aiohttp.TCPConnector(ssl=False, ...)` disabled certificate validation for
every outbound OSINT call (VirusTotal, AbuseIPDB, URLScan) — these calls
send your API keys in headers. Removed `ssl=False`; verification is back
to default (on).

## 3. Double AI API call (backend/main.py, `/api/analyze/full`)
Previously called Claude once without OSINT context, then called it AGAIN
if OSINT had any hits — silently 2x'ing Anthropic spend on most real
phishing emails. Now: OSINT runs first, then exactly one AI call with full
context.

## 4. No authentication on the API (backend/main.py, backend/config.py)
- `CORSMiddleware` was `allow_origins=["*"]`, meaning ANY website open in
  the same browser could `fetch()` PhishLens's API and read your analysis
  history / config. Restricted to `127.0.0.1`/`localhost` via
  `allow_origin_regex`.
- Added a local API token (`config.get_or_create_token()`), stored in
  `.phishlens_token` in the data dir (0600 perms), required via
  `X-API-Key` on every `/api/*` request. The token is auto-injected into
  the served `index.html` as a `<meta>` tag, so the bundled UI keeps
  working with zero setup. Printed to console on startup for curl/Postman.
  This also closes the LAN-exposure gap when running `--host 0.0.0.0`.

## 5. Outdated default model (backend/config.py)
`ai_model` default was `claude-sonnet-4-20250514`. Updated to
`claude-sonnet-4-6`.

## 6. Unbounded bulk upload size (backend/main.py, `/api/analyze/bulk`)
Per-file cap existed (25MB) but no aggregate cap — 50 files could mean
1.25GB in one request. Added a 150MB combined cap.

## 7. Secrets/build artifacts were actually committed
`phishlens.db`, `dist/*.deb`, and `backend/__pycache__/` were present in
the repo despite the README claiming `.gitignore` excludes them — there
was no `.gitignore` in the repo at all. Added one (excludes db, config,
token, `__pycache__`, `dist/`, `*.deb`/`*.AppImage`, venvs).

**Since these were already committed, `.gitignore` alone won't remove them
from git history. Run this once in your actual repo:**

```bash
git rm --cached phishlens.db dist/phishlens_2.0.0_amd64.deb
git rm -r --cached backend/__pycache__
git add .gitignore
git commit -m "Remove committed DB/build artifacts, add .gitignore"
```

(If `phishlens.db` ever held real analysis data — i.e. real victims'
parsed emails — you also want it scrubbed from git history with
`git filter-repo` or BFG, not just removed from HEAD, since old commits
still contain it on GitHub.)

## Not changed (flag for you to decide)
- Bulk endpoint still processes sequentially in batches of 5 — fine for
  now, just noting it if you want more throughput later.
- No rate limiting on `/api/analyze*` — low priority for a local
  single-user tool, but worth adding if you ever expose this beyond
  localhost.
