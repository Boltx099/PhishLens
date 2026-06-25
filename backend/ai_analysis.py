"""
PhishLens v2 — AI Analysis Engine
Claude-powered deep analysis of phishing emails.
Skips gracefully if API key not configured.
"""

import json
import asyncio
from typing import Optional

try:
    import aiohttp
    AIOHTTP_OK = True
except ImportError:
    AIOHTTP_OK = False

from config import load_config

SYSTEM_PROMPT = """You are an expert SOC analyst and phishing email investigator with 10+ years of experience. 
You analyze parsed email data and OSINT results to provide structured threat intelligence reports.

Your analysis must be precise, technical, and actionable. You think like a threat hunter — 
looking for TTPs, infrastructure patterns, and attack objectives.

Always respond in valid JSON only. No markdown, no preamble, no explanation outside the JSON."""

ANALYSIS_PROMPT = """Analyze this phishing email investigation data and produce a structured threat intelligence report.

EMAIL ANALYSIS DATA:
{data}

Respond with this exact JSON structure:
{{
  "threat_summary": "2-3 sentence executive summary of the threat",
  "attack_type": "one of: credential_phishing | malware_delivery | business_email_compromise | spear_phishing | smishing | whaling | invoice_fraud | tech_support_scam | unknown",
  "confidence": "high | medium | low",
  "targeted": true or false,
  "target_brand": "impersonated brand name or null",
  "attack_objective": "what the attacker is trying to achieve",
  "ttps": [
    {{"technique": "MITRE ATT&CK technique name", "id": "T1xxx", "detail": "how it applies here"}}
  ],
  "infrastructure_analysis": "analysis of sender infrastructure, domains, IPs",
  "social_engineering": "analysis of psychological manipulation tactics used",
  "ioc_assessment": "assessment of extracted IOCs and their significance",
  "risk_verdict": "PHISHING | LIKELY_PHISHING | SUSPICIOUS | LIKELY_CLEAN | CLEAN",
  "risk_justification": "why this verdict was reached",
  "recommended_actions": [
    "actionable recommendation 1",
    "actionable recommendation 2",
    "actionable recommendation 3"
  ],
  "hunting_queries": [
    "SIEM/log query suggestion to hunt for similar threats"
  ]
}}"""


def _build_context(analysis: dict, osint: Optional[dict] = None) -> str:
    """Build condensed analysis context for AI prompt."""
    h = analysis.get("headers", {})
    auth = analysis.get("auth", {})
    risk = analysis.get("risk", {})
    iocs = analysis.get("iocs", {})
    spoof = analysis.get("spoof_check", {})
    keywords = analysis.get("phish_keywords", [])
    attachments = analysis.get("attachments", [])
    url_analysis = analysis.get("url_analysis", [])

    ctx = {
        "headers": {
            "from": h.get("from", ""),
            "reply_to": h.get("reply_to", ""),
            "subject": h.get("subject", ""),
            "date": h.get("date", ""),
            "x_mailer": h.get("x_mailer", ""),
            "x_originating_ip": h.get("x_originating_ip", ""),
        },
        "authentication": {
            "spf": auth.get("spf", "none"),
            "dkim": auth.get("dkim", "none"),
            "dmarc": auth.get("dmarc", "none"),
        },
        "risk": {
            "score": risk.get("score", 0),
            "verdict": risk.get("verdict", ""),
            "factors": [f.get("label", "") for f in risk.get("factors", [])],
        },
        "spoofing": {
            "detected": spoof.get("spoofed", False),
            "issues": [i.get("detail", "") for i in spoof.get("issues", [])],
        },
        "iocs": {
            "urls": iocs.get("urls", [])[:10],
            "ips": iocs.get("ips", [])[:10],
            "domains": iocs.get("domains", [])[:10],
            "emails": iocs.get("emails", [])[:5],
        },
        "url_flags": [
            {"url": u.get("url", "")[:80], "flags": u.get("flags", []), "risk": u.get("risk_level", "")}
            for u in url_analysis[:8]
        ],
        "attachments": [
            {"filename": a.get("filename", ""), "extension": a.get("extension", ""), "risk": a.get("risk", "")}
            for a in attachments
        ],
        "phishing_keywords": keywords[:15],
        "received_hops": len(analysis.get("received_chain", [])),
    }

    if osint:
        summary = osint.get("summary", {})
        ctx["osint_summary"] = {
            "malicious_urls": summary.get("malicious_urls", 0),
            "malicious_ips": summary.get("malicious_ips", 0),
            "malicious_domains": summary.get("malicious_domains", 0),
            "malicious_hashes": summary.get("malicious_hashes", 0),
            "total_checked": summary.get("total_checked", 0),
        }
        # Add VT verdicts for URLs
        vt_hits = []
        for u in osint.get("urls", []):
            vt = u.get("vt", {})
            if vt.get("status") == "ok":
                vt_hits.append({
                    "url": u.get("url", "")[:60],
                    "malicious_engines": vt.get("malicious", 0),
                    "detection_rate": vt.get("detection_rate", 0),
                })
        if vt_hits:
            ctx["virustotal_url_results"] = vt_hits

        # AbuseIPDB scores
        abuse_hits = []
        for ip_data in osint.get("ips", []):
            ab = ip_data.get("abuseipdb", {})
            if ab.get("status") == "ok":
                abuse_hits.append({
                    "ip": ip_data.get("ip", ""),
                    "abuse_score": ab.get("abuse_score", 0),
                    "country": ab.get("country", ""),
                    "isp": ab.get("isp", ""),
                })
        if abuse_hits:
            ctx["abuseipdb_results"] = abuse_hits

    return json.dumps(ctx, indent=2)


async def run_ai_analysis(analysis: dict, osint: Optional[dict] = None) -> dict:
    """Run Claude AI analysis on parsed email + OSINT data."""

    cfg = load_config()
    api_key = cfg.get("anthropic_api_key", "")
    model = cfg.get("ai_model", "claude-sonnet-4-20250514")

    if not api_key:
        return {
            "status": "not_configured",
            "message": "Anthropic API key not set. Add it in Settings to enable AI analysis."
        }

    if not AIOHTTP_OK:
        return {"status": "error", "message": "aiohttp not installed"}

    context = _build_context(analysis, osint)
    prompt = ANALYSIS_PROMPT.format(data=context)

    try:
        async with aiohttp.ClientSession() as session:
            payload = {
                "model": model,
                "max_tokens": 2000,
                "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": prompt}]
            }
            headers = {
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json"
            }
            async with session.post(
                "https://api.anthropic.com/v1/messages",
                json=payload,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as r:
                if r.status == 401:
                    return {"status": "error", "message": "Invalid Anthropic API key"}
                if r.status == 429:
                    return {"status": "error", "message": "Rate limit exceeded"}
                if r.status != 200:
                    return {"status": "error", "message": f"API error: {r.status}"}

                data = await r.json()
                raw = data.get("content", [{}])[0].get("text", "")

                # Strip any accidental markdown fences
                clean = raw.strip()
                if clean.startswith("```"):
                    clean = clean.split("```")[1]
                    if clean.startswith("json"):
                        clean = clean[4:]
                clean = clean.strip().rstrip("```").strip()

                parsed = json.loads(clean)
                parsed["status"] = "ok"
                parsed["model"] = model
                return parsed

    except json.JSONDecodeError as e:
        return {"status": "error", "message": f"AI response parse error: {e}", "raw": raw[:500]}
    except asyncio.TimeoutError:
        return {"status": "error", "message": "AI analysis timed out (30s)"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
