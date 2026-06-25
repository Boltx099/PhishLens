# Deploy PhishLens for a demo — Railway (fastest)

Tested locally with the exact start command Railway will run — works.
~5 minutes, no code changes needed beyond what's already in this zip.

## Railway (recommended)

1. Push this folder to a GitHub repo (or your existing PhishLens repo —
   just make sure `Procfile`, `.gitignore`, and the patched `backend/` +
   `frontend/` from this zip are in it).
2. https://railway.app → New Project → Deploy from GitHub repo → pick it.
3. Railway auto-detects `requirements.txt` (Nixpacks) + `Procfile`. No
   config needed. It assigns `$PORT` automatically.
4. Settings → Generate Domain → you get a `*.up.railway.app` URL. Done.
5. Open it, go to Settings tab in the UI, paste your API keys
   (VirusTotal/AbuseIPDB/URLScan/Anthropic) — same as running locally,
   they're saved server-side in the container.

## Render (backup, if Railway free tier is exhausted)

1. https://render.com → New → Web Service → connect repo.
2. Build command: `pip install -r requirements.txt`
3. Start command: `cd backend && uvicorn main:app --host 0.0.0.0 --port $PORT --log-level warning`
4. Instance type: Free is fine for a demo (cold-starts after idle — first
   request after inactivity takes ~30-50s to wake up, keep that in mind
   mid-demo).

## What to know before the demo

- **Data is ephemeral.** SQLite (`phishlens.db`) and API keys
  (`phishlens_config.json`) live on the container's local disk. A
  redeploy or restart wipes them — fine for a live demo, don't rely on
  history surviving a restart.
- **API keys**: enter them once after first deploy via Settings tab in
  the browser, exactly like local use. Nothing extra needed in Railway/
  Render's env var UI unless you want to skip the manual step (optional,
  not wired up yet — say the word if you want env-var fallback added).
- **Local API token** (`.phishlens_token`) is per-deployment, generated
  on container start, auto-injected into the page. If you open the
  deployed URL in a different browser/incognito it still works — token
  comes from the page itself, not from your machine.
- This is still SQLite + local file config under the hood — fine for a
  demo / single presenter. Not meant for multiple concurrent real users
  hitting it (that's a bigger lift: Postgres + proper secrets — say if
  you actually need that later).
