"""
PhishLens v2.0 — FastAPI Backend Server
Phase 2: OSINT + AI Analysis
"""

import os
import json
import sqlite3
import asyncio
import re
from pathlib import Path
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, File, UploadFile, HTTPException, Request, Body
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from parser import parse_email
from osint import run_osint
from ai_analysis import run_ai_analysis
from config import load_config, save_config, configured_services, get_or_create_token

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).parent.parent
FRONTEND   = BASE_DIR / "frontend"
_data_dir  = Path(os.environ.get("PHISHLENS_DATA_DIR", BASE_DIR))
DB_PATH    = _data_dir / "phishlens.db"
API_TOKEN  = get_or_create_token()

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(title="PhishLens API", version="2.0.0")
# Only same-origin (localhost/127.0.0.1, any port) may use CORS — was allow_origins=["*"],
# which let ANY website open in the user's browser read PhishLens API responses.
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^https?://(127\.0\.0\.1|localhost)(:\d+)?$",
    allow_methods=["*"], allow_headers=["*"],
)

@app.middleware("http")
async def require_api_token(request: Request, call_next):
    """
    Every /api/* call must carry X-API-Key matching the local token.
    Without this, any page open in the same browser (or anyone on the
    LAN if --host 0.0.0.0 is used) could call the API directly — CORS
    headers don't protect non-browser or same-origin-spoofed requests.
    The frontend gets the token injected into the page it's served from.
    """
    if request.url.path.startswith("/api/"):
        if request.headers.get("x-api-key") != API_TOKEN:
            return JSONResponse({"detail": "Missing or invalid X-API-Key"}, status_code=401)
    return await call_next(request)

# ── DB ────────────────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            filename      TEXT,
            subject       TEXT,
            sender        TEXT,
            date_analyzed TEXT,
            risk_score    INTEGER,
            verdict       TEXT,
            ioc_count     INTEGER,
            has_osint     INTEGER DEFAULT 0,
            has_ai        INTEGER DEFAULT 0,
            result_json   TEXT
        )""")
    conn.commit()
    conn.close()

def _save(filename, result):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    iocs = result.get("iocs", {})
    ioc_n = sum(len(iocs.get(k, [])) for k in ["urls","ips","domains","emails"])
    c.execute("""INSERT INTO analyses
        (filename,subject,sender,date_analyzed,risk_score,verdict,ioc_count,has_osint,has_ai,result_json)
        VALUES (?,?,?,?,?,?,?,?,?,?)""", (
        filename,
        result.get("headers",{}).get("subject",""),
        result.get("headers",{}).get("from",""),
        datetime.now().isoformat(),
        result.get("risk",{}).get("score",0),
        result.get("risk",{}).get("verdict",""),
        ioc_n,
        1 if result.get("osint") else 0,
        1 if result.get("ai_analysis",{}).get("status") == "ok" else 0,
        json.dumps(result)
    ))
    conn.commit()
    last = c.lastrowid
    conn.close()
    return last

def _update(analysis_id, result):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""UPDATE analyses SET
        has_osint=?, has_ai=?, result_json=? WHERE id=?""", (
        1 if result.get("osint") else 0,
        1 if result.get("ai_analysis",{}).get("status") == "ok" else 0,
        json.dumps(result), analysis_id
    ))
    conn.commit()
    conn.close()

def _history(limit=50):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("""SELECT id,filename,subject,sender,date_analyzed,
                        risk_score,verdict,ioc_count,has_osint,has_ai
                 FROM analyses ORDER BY id DESC LIMIT ?""", (limit,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def _get(aid):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM analyses WHERE id=?", (aid,))
    row = c.fetchone()
    conn.close()
    if row:
        r = dict(row); r["result_json"] = json.loads(r["result_json"]); return r
    return None

def _delete(aid):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM analyses WHERE id=?", (aid,))
    conn.commit()
    d = conn.total_changes; conn.close(); return d > 0

# ── Startup ───────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    init_db()
    print(f"[+] Local API token: {API_TOKEN}")
    print(f"    (auto-injected into the web UI; needed for curl/Postman/etc.)")

# ── UI ────────────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def ui():
    f = FRONTEND / "index.html"
    if not f.exists():
        return HTMLResponse("Frontend missing", 404)
    html = f.read_text("utf-8")
    # Inject local API token so the frontend (served from this same origin)
    # can authenticate its own fetch() calls. Never sent anywhere else.
    token_tag = f'<meta name="phishlens-token" content="{API_TOKEN}">'
    if "<head>" in html:
        html = html.replace("<head>", f"<head>\n  {token_tag}", 1)
    else:
        html = token_tag + html
    return HTMLResponse(html)

@app.get("/health")
async def health():
    return {"status": "ok", "version": "2.0.0", "services": configured_services()}

# ── Core Analysis ─────────────────────────────────────────────────────────────
async def _parse_and_save(raw: bytes, filename: str) -> dict:
    result = parse_email(raw, filename)
    aid = _save(filename, result)
    result["analysis_id"] = aid
    result["filename"] = filename
    return result

@app.post("/api/analyze")
async def analyze_file(file: UploadFile = File(...)):
    ext = Path(file.filename or "x").suffix.lower()
    if ext not in [".eml", ".txt", ".msg", ""]:
        raise HTTPException(400, f"Unsupported type: {ext}")
    raw = await file.read()
    if len(raw) > 25 * 1024 * 1024:
        raise HTTPException(400, "File too large (max 25MB)")
    try:
        return JSONResponse(await _parse_and_save(raw, file.filename or "upload.eml"))
    except Exception as e:
        raise HTTPException(500, f"Parse error: {e}")

@app.post("/api/analyze/raw")
async def analyze_raw(request: Request):
    body = await request.body()
    if not body: raise HTTPException(400, "Empty body")
    try:
        return JSONResponse(await _parse_and_save(body, "pasted_email.eml"))
    except Exception as e:
        raise HTTPException(500, f"Parse error: {e}")

# ── OSINT ─────────────────────────────────────────────────────────────────────
@app.post("/api/osint/{analysis_id}")
async def run_osint_for(analysis_id: int):
    """Run OSINT enrichment on an existing analysis."""
    record = _get(analysis_id)
    if not record: raise HTTPException(404, "Analysis not found")
    result = record["result_json"]
    try:
        osint_data = await run_osint(result)
        result["osint"] = osint_data
        _update(analysis_id, result)
        return JSONResponse({"status": "ok", "osint": osint_data, "analysis_id": analysis_id})
    except Exception as e:
        raise HTTPException(500, f"OSINT error: {e}")

@app.post("/api/analyze/full")
async def analyze_full(file: UploadFile = File(...)):
    """Parse + OSINT + AI in one shot."""
    ext = Path(file.filename or "x").suffix.lower()
    if ext not in [".eml", ".txt", ".msg", ""]:
        raise HTTPException(400, f"Unsupported type: {ext}")
    raw = await file.read()
    if len(raw) > 25 * 1024 * 1024:
        raise HTTPException(400, "File too large")
    try:
        result = parse_email(raw)
        cfg = load_config()
        # OSINT first, then ONE AI call with full context.
        # (Previously: AI ran once without OSINT, then ran AGAIN if OSINT had
        # hits — silently doubling Anthropic API cost on most real phishing
        # emails, contradicting the "~$0.01/email" estimate in the README.)
        osint_data = await run_osint(result)
        result["osint"] = osint_data
        ai_data = await run_ai_analysis(result, osint_data)
        result["ai_analysis"] = ai_data
        aid = _save(file.filename or "upload.eml", result)
        result["analysis_id"] = aid
        result["filename"] = file.filename
        return JSONResponse(result)
    except Exception as e:
        raise HTTPException(500, f"Analysis error: {e}")

# ── Bulk Analysis ────────────────────────────────────────────────────────────
@app.post("/api/analyze/bulk")
async def analyze_bulk(files: list[UploadFile] = File(...)):
    """
    Analyze multiple .eml files at once.
    Returns per-file results + aggregate summary.
    """
    if not files:
        raise HTTPException(400, "No files provided")
    if len(files) > 50:
        raise HTTPException(400, "Max 50 files per bulk request")

    results = []
    errors  = []
    total_bytes = [0]  # mutable cell so _process can update aggregate total
    MAX_TOTAL = 150 * 1024 * 1024  # 150MB combined cap (50 files * 25MB each was unbounded)

    # Process concurrently in batches of 5
    async def _process(f: UploadFile) -> dict:
        try:
            ext = (f.filename or "").rsplit(".", 1)[-1].lower()
            if ext not in ("eml", "txt", "msg", ""):
                return {"filename": f.filename, "status": "error",
                        "error": f"Unsupported type .{ext}"}
            raw = await f.read()
            if len(raw) > 25 * 1024 * 1024:
                return {"filename": f.filename, "status": "error",
                        "error": "File too large (>25MB)"}
            total_bytes[0] += len(raw)
            if total_bytes[0] > MAX_TOTAL:
                return {"filename": f.filename, "status": "error",
                        "error": "Bulk request exceeds 150MB combined limit"}
            result = parse_email(raw, f.filename or "upload.eml")
            aid = _save(f.filename or "upload.eml", result)
            return {
                "filename":    f.filename,
                "status":      "ok",
                "analysis_id": aid,
                "subject":     result.get("headers", {}).get("subject", ""),
                "sender":      result.get("headers", {}).get("from", ""),
                "risk_score":  result.get("risk", {}).get("score", 0),
                "verdict":     result.get("risk", {}).get("verdict", ""),
                "verdict_color": result.get("risk", {}).get("verdict_color", ""),
                "ioc_count":   sum(len(v) for v in result.get("iocs", {}).values()),
                "attachment_count": len(result.get("attachments", [])),
                "url_count":   len(result.get("url_analysis", [])),
                "spf":         result.get("auth", {}).get("spf", "none"),
                "dkim":        result.get("auth", {}).get("dkim", "none"),
                "dmarc":       result.get("auth", {}).get("dmarc", "none"),
                "spoofed":     result.get("spoof_check", {}).get("spoofed", False),
                "risk_factors": [f["label"] for f in result.get("risk", {}).get("factors", [])],
            }
        except Exception as e:
            return {"filename": getattr(f, "filename", "?"), "status": "error", "error": str(e)}

    BATCH = 5
    for i in range(0, len(files), BATCH):
        batch = files[i:i + BATCH]
        batch_results = await asyncio.gather(*[_process(f) for f in batch])
        for r in batch_results:
            if r.get("status") == "error":
                errors.append(r)
            else:
                results.append(r)

    # Aggregate summary
    scores      = [r["risk_score"] for r in results]
    verdicts    = [r["verdict"]    for r in results]
    total       = len(results)
    phishing    = sum(1 for v in verdicts if "PHISHING" in v)
    suspicious  = sum(1 for v in verdicts if v == "SUSPICIOUS")
    clean       = total - phishing - suspicious
    avg_score   = round(sum(scores) / total, 1) if total else 0
    highest     = max(results, key=lambda x: x["risk_score"]) if results else None

    return JSONResponse({
        "status":  "ok",
        "total":   len(files),
        "success": total,
        "errors":  len(errors),
        "results": results,
        "error_details": errors,
        "summary": {
            "total":        total,
            "phishing":     phishing,
            "suspicious":   suspicious,
            "clean":        clean,
            "avg_score":    avg_score,
            "highest_risk": highest,
            "total_iocs":   sum(r.get("ioc_count", 0) for r in results),
        }
    })

# ── AI ────────────────────────────────────────────────────────────────────────
@app.post("/api/ai/{analysis_id}")
async def run_ai_for(analysis_id: int):
    """Run AI analysis on an existing parsed result."""
    record = _get(analysis_id)
    if not record: raise HTTPException(404, "Analysis not found")
    result = record["result_json"]
    try:
        osint = result.get("osint")
        ai_data = await run_ai_analysis(result, osint)
        result["ai_analysis"] = ai_data
        _update(analysis_id, result)
        return JSONResponse({"status": "ok", "ai_analysis": ai_data, "analysis_id": analysis_id})
    except Exception as e:
        raise HTTPException(500, f"AI analysis error: {e}")

# ── History ───────────────────────────────────────────────────────────────────
@app.get("/api/history")
async def history(limit: int = 50):
    return {"analyses": _history(limit)}

@app.get("/api/history/{aid}")
async def history_get(aid: int):
    r = _get(aid)
    if not r: raise HTTPException(404, "Not found")
    return r

@app.delete("/api/history/{aid}")
async def history_del(aid: int):
    if _delete(aid): return {"deleted": True}
    raise HTTPException(404, "Not found")

@app.delete("/api/history")
async def history_clear():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM analyses")
    conn.commit()
    n = conn.total_changes; conn.close()
    return {"deleted": n}

# ── Stats ─────────────────────────────────────────────────────────────────────
@app.get("/api/stats")
async def stats():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM analyses"); total = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM analyses WHERE verdict LIKE '%PHISHING%'"); phish = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM analyses WHERE verdict='SUSPICIOUS'"); susp = c.fetchone()[0]
    c.execute("SELECT AVG(risk_score) FROM analyses"); avg = c.fetchone()[0] or 0
    c.execute("SELECT SUM(ioc_count) FROM analyses"); iocs = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM analyses WHERE has_osint=1"); osint_n = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM analyses WHERE has_ai=1"); ai_n = c.fetchone()[0]
    conn.close()
    return {"total_analyzed": total, "phishing_detected": phish, "suspicious": susp,
            "clean": total - phish - susp, "avg_risk_score": round(avg, 1),
            "total_iocs": iocs, "osint_enriched": osint_n, "ai_analyzed": ai_n}

# ── Config / Settings ─────────────────────────────────────────────────────────
@app.get("/api/config")
async def get_config():
    cfg = load_config()
    # Mask key values — only return if set or not
    masked = {}
    for k, v in cfg.items():
        if "api_key" in k:
            masked[k] = "••••••••" if v else ""
        else:
            masked[k] = v
    masked["configured"] = configured_services()
    return masked

@app.post("/api/config")
async def set_config(body: dict = Body(...)):
    cfg = load_config()
    # Only update keys that were actually sent
    for k, v in body.items():
        if k in cfg:
            # Don't overwrite with masked value
            if "api_key" in k and v == "••••••••":
                continue
            cfg[k] = v
    if save_config(cfg):
        return {"status": "ok", "configured": configured_services()}
    raise HTTPException(500, "Failed to save config")

