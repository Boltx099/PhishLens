"""
PhishLens v2 — OSINT Engine
Async integrations: VirusTotal, AbuseIPDB, WHOIS/DNS, URLScan.io
All calls gracefully skip if API key not configured.
"""

import asyncio
import json
import re
import socket
import hashlib
from typing import Optional
from datetime import datetime

try:
    import aiohttp
    AIOHTTP_OK = True
except ImportError:
    AIOHTTP_OK = False

try:
    import dns.resolver
    import dns.exception
    DNS_OK = True
except ImportError:
    DNS_OK = False

try:
    import whois as python_whois
    WHOIS_OK = True
except ImportError:
    WHOIS_OK = False

from config import load_config

# ── Helpers ───────────────────────────────────────────────────────────────────

def _cfg():
    return load_config()

def _not_configured(service: str) -> dict:
    return {"status": "not_configured", "service": service,
            "message": f"{service} API key not set. Add it in Settings."}

def _error(service: str, msg: str) -> dict:
    return {"status": "error", "service": service, "message": str(msg)}

def _ok(service: str, data: dict) -> dict:
    return {"status": "ok", "service": service, **data}


# ── VirusTotal ────────────────────────────────────────────────────────────────

async def vt_lookup_url(url: str, session: "aiohttp.ClientSession", key: str) -> dict:
    """Submit URL to VirusTotal and get analysis."""
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
        headers = {"x-apikey": key}

        async with session.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers, timeout=aiohttp.ClientTimeout(total=10)
        ) as r:
            if r.status == 404:
                # Not cached — submit for analysis
                async with session.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers=headers,
                    data={"url": url},
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as pr:
                    if pr.status == 200:
                        return _ok("virustotal", {
                            "url": url, "submitted": True,
                            "message": "URL submitted for analysis (not yet cached)"
                        })
                    return _error("virustotal", f"Submit failed: {pr.status}")

            if r.status != 200:
                return _error("virustotal", f"HTTP {r.status}")

            data = await r.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            mal = stats.get("malicious", 0)
            sus = stats.get("suspicious", 0)
            total = sum(stats.values()) or 1

            return _ok("virustotal", {
                "url": url,
                "malicious": mal,
                "suspicious": sus,
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total_engines": total,
                "detection_rate": round((mal + sus) / total * 100, 1),
                "verdict": "malicious" if mal >= 3 else "suspicious" if (mal > 0 or sus >= 3) else "clean",
                "last_analysis_date": data.get("data", {}).get("attributes", {}).get("last_analysis_date", "")
            })
    except asyncio.TimeoutError:
        return _error("virustotal", "Timeout")
    except Exception as e:
        return _error("virustotal", str(e))


async def vt_lookup_ip(ip: str, session: "aiohttp.ClientSession", key: str) -> dict:
    """VirusTotal IP reputation."""
    try:
        headers = {"x-apikey": key}
        async with session.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers=headers, timeout=aiohttp.ClientTimeout(total=10)
        ) as r:
            if r.status != 200:
                return _error("virustotal", f"HTTP {r.status}")
            data = await r.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            mal = stats.get("malicious", 0)
            sus = stats.get("suspicious", 0)
            total = sum(stats.values()) or 1

            return _ok("virustotal", {
                "ip": ip,
                "malicious": mal,
                "suspicious": sus,
                "total_engines": total,
                "detection_rate": round((mal + sus) / total * 100, 1),
                "verdict": "malicious" if mal >= 3 else "suspicious" if (mal > 0 or sus >= 2) else "clean",
                "country": attrs.get("country", ""),
                "asn": attrs.get("asn", ""),
                "as_owner": attrs.get("as_owner", ""),
                "reputation": attrs.get("reputation", 0),
            })
    except asyncio.TimeoutError:
        return _error("virustotal", "Timeout")
    except Exception as e:
        return _error("virustotal", str(e))


async def vt_lookup_domain(domain: str, session: "aiohttp.ClientSession", key: str) -> dict:
    """VirusTotal domain reputation."""
    try:
        headers = {"x-apikey": key}
        async with session.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers=headers, timeout=aiohttp.ClientTimeout(total=10)
        ) as r:
            if r.status != 200:
                return _error("virustotal", f"HTTP {r.status}")
            data = await r.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            mal = stats.get("malicious", 0)
            sus = stats.get("suspicious", 0)
            total = sum(stats.values()) or 1

            return _ok("virustotal", {
                "domain": domain,
                "malicious": mal,
                "suspicious": sus,
                "total_engines": total,
                "detection_rate": round((mal + sus) / total * 100, 1),
                "verdict": "malicious" if mal >= 3 else "suspicious" if (mal > 0 or sus >= 2) else "clean",
                "reputation": attrs.get("reputation", 0),
                "creation_date": attrs.get("creation_date", ""),
                "registrar": attrs.get("registrar", ""),
                "categories": attrs.get("categories", {}),
            })
    except asyncio.TimeoutError:
        return _error("virustotal", "Timeout")
    except Exception as e:
        return _error("virustotal", str(e))


async def vt_lookup_hash(file_hash: str, session: "aiohttp.ClientSession", key: str) -> dict:
    """VirusTotal file hash lookup."""
    try:
        headers = {"x-apikey": key}
        async with session.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers=headers, timeout=aiohttp.ClientTimeout(total=10)
        ) as r:
            if r.status == 404:
                return _ok("virustotal", {"hash": file_hash, "verdict": "unknown",
                                           "message": "Hash not found in VT database"})
            if r.status != 200:
                return _error("virustotal", f"HTTP {r.status}")
            data = await r.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            mal = stats.get("malicious", 0)
            total = sum(stats.values()) or 1

            return _ok("virustotal", {
                "hash": file_hash,
                "malicious": mal,
                "total_engines": total,
                "detection_rate": round(mal / total * 100, 1),
                "verdict": "malicious" if mal >= 3 else "suspicious" if mal > 0 else "clean",
                "name": attrs.get("meaningful_name", ""),
                "type": attrs.get("type_description", ""),
                "size": attrs.get("size", 0),
            })
    except Exception as e:
        return _error("virustotal", str(e))


# ── AbuseIPDB ─────────────────────────────────────────────────────────────────

async def abuseipdb_lookup(ip: str, session: "aiohttp.ClientSession", key: str) -> dict:
    """AbuseIPDB IP reputation check."""
    try:
        headers = {"Key": key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}
        async with session.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers, params=params,
            timeout=aiohttp.ClientTimeout(total=10)
        ) as r:
            if r.status != 200:
                return _error("abuseipdb", f"HTTP {r.status}")
            data = (await r.json()).get("data", {})

            score = data.get("abuseConfidenceScore", 0)
            return _ok("abuseipdb", {
                "ip": ip,
                "abuse_score": score,
                "verdict": "malicious" if score >= 80 else "suspicious" if score >= 25 else "clean",
                "total_reports": data.get("totalReports", 0),
                "num_distinct_users": data.get("numDistinctUsers", 0),
                "country": data.get("countryCode", ""),
                "isp": data.get("isp", ""),
                "domain": data.get("domain", ""),
                "is_tor": data.get("isTor", False),
                "is_public": data.get("isPublic", True),
                "last_reported": data.get("lastReportedAt", ""),
                "usage_type": data.get("usageType", ""),
            })
    except asyncio.TimeoutError:
        return _error("abuseipdb", "Timeout")
    except Exception as e:
        return _error("abuseipdb", str(e))


# ── DNS / WHOIS ───────────────────────────────────────────────────────────────

async def dns_lookup(domain: str) -> dict:
    """DNS A/MX/TXT records for a domain."""
    try:
        loop = asyncio.get_event_loop()
        results = {}

        def _do_dns():
            out = {}
            if not DNS_OK:
                return out
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5

            for rtype in ["A", "MX", "TXT", "NS"]:
                try:
                    answers = resolver.resolve(domain, rtype)
                    if rtype == "A":
                        out["A"] = [str(r) for r in answers]
                    elif rtype == "MX":
                        out["MX"] = [f"{r.preference} {r.exchange}" for r in answers]
                    elif rtype == "TXT":
                        out["TXT"] = [b''.join(r.strings).decode('utf-8', errors='replace') for r in answers]
                    elif rtype == "NS":
                        out["NS"] = [str(r) for r in answers]
                except Exception:
                    pass

            # SPF record from TXT
            spf = [t for t in out.get("TXT", []) if t.startswith("v=spf")]
            out["spf_record"] = spf[0] if spf else None

            # DMARC
            try:
                dmarc_answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
                out["dmarc_record"] = b''.join(dmarc_answers[0].strings).decode('utf-8', errors='replace')
            except Exception:
                out["dmarc_record"] = None

            return out

        results = await loop.run_in_executor(None, _do_dns)
        return _ok("dns", {"domain": domain, "records": results})

    except Exception as e:
        return _error("dns", str(e))


async def whois_lookup(domain: str) -> dict:
    """WHOIS lookup for domain registration info."""
    try:
        if not WHOIS_OK:
            return _error("whois", "python-whois not installed")

        loop = asyncio.get_event_loop()

        def _do_whois():
            w = python_whois.whois(domain)
            creation = w.creation_date
            expiry = w.expiration_date
            updated = w.updated_date

            def _dt(d):
                if isinstance(d, list): d = d[0]
                if isinstance(d, datetime): return d.isoformat()
                return str(d) if d else None

            age_days = None
            if creation:
                cd = creation[0] if isinstance(creation, list) else creation
                if isinstance(cd, datetime):
                    age_days = (datetime.now() - cd).days

            return {
                "domain": domain,
                "registrar": w.registrar,
                "creation_date": _dt(creation),
                "expiry_date": _dt(expiry),
                "updated_date": _dt(updated),
                "name_servers": w.name_servers if isinstance(w.name_servers, list) else ([w.name_servers] if w.name_servers else []),
                "registrant_country": w.country,
                "age_days": age_days,
                "recently_registered": age_days is not None and age_days < 30,
            }

        data = await loop.run_in_executor(None, _do_whois)
        return _ok("whois", data)

    except Exception as e:
        return _error("whois", str(e))


# ── URLScan.io ────────────────────────────────────────────────────────────────

async def urlscan_submit(url: str, session: "aiohttp.ClientSession", key: str) -> dict:
    """Submit URL to URLScan.io and get scan UUID."""
    try:
        headers = {"API-Key": key, "Content-Type": "application/json"}
        payload = {"url": url, "visibility": "private"}
        async with session.post(
            "https://urlscan.io/api/v1/scan/",
            headers=headers,
            json=payload,
            timeout=aiohttp.ClientTimeout(total=15)
        ) as r:
            if r.status == 200:
                data = await r.json()
                return _ok("urlscan", {
                    "url": url,
                    "uuid": data.get("uuid", ""),
                    "result_url": data.get("result", ""),
                    "api_url": data.get("api", ""),
                    "submitted": True,
                    "message": "Scan submitted. Results available in ~30 seconds."
                })
            elif r.status == 429:
                return _error("urlscan", "Rate limit exceeded")
            else:
                return _error("urlscan", f"HTTP {r.status}")
    except asyncio.TimeoutError:
        return _error("urlscan", "Timeout")
    except Exception as e:
        return _error("urlscan", str(e))


async def urlscan_get_result(uuid: str, session: "aiohttp.ClientSession") -> dict:
    """Fetch URLScan result by UUID."""
    try:
        async with session.get(
            f"https://urlscan.io/api/v1/result/{uuid}/",
            timeout=aiohttp.ClientTimeout(total=10)
        ) as r:
            if r.status == 404:
                return _error("urlscan", "Scan not ready yet")
            if r.status != 200:
                return _error("urlscan", f"HTTP {r.status}")
            data = await r.json()
            page = data.get("page", {})
            verdicts = data.get("verdicts", {}).get("overall", {})

            return _ok("urlscan", {
                "uuid": uuid,
                "url": page.get("url", ""),
                "domain": page.get("domain", ""),
                "ip": page.get("ip", ""),
                "country": page.get("country", ""),
                "server": page.get("server", ""),
                "malicious": verdicts.get("malicious", False),
                "score": verdicts.get("score", 0),
                "categories": verdicts.get("categories", []),
                "brands": verdicts.get("brands", []),
                "screenshot": data.get("task", {}).get("screenshotURL", ""),
                "result_url": f"https://urlscan.io/result/{uuid}/",
            })
    except Exception as e:
        return _error("urlscan", str(e))


# ── Main OSINT Orchestrator ───────────────────────────────────────────────────

async def run_osint(analysis_result: dict) -> dict:
    """
    Run all configured OSINT checks on an analysis result.
    Returns enriched OSINT data per IOC.
    """
    cfg = load_config()
    vt_key = cfg.get("virustotal_api_key", "")
    abuse_key = cfg.get("abuseipdb_api_key", "")
    urlscan_key = cfg.get("urlscan_api_key", "")
    timeout = cfg.get("osint_timeout", 10)
    max_urls = cfg.get("max_urls_to_scan", 5)
    max_ips = cfg.get("max_ips_to_scan", 5)

    iocs = analysis_result.get("iocs", {})
    urls = (iocs.get("urls", []))[:max_urls]
    ips = (iocs.get("ips", []))[:max_ips]
    domains = list(set(iocs.get("domains", [])))[:5]
    attachments = analysis_result.get("attachments", [])

    osint = {
        "services": {
            "virustotal": bool(vt_key),
            "abuseipdb": bool(abuse_key),
            "urlscan": bool(urlscan_key),
            "dns": True,
            "whois": WHOIS_OK,
        },
        "urls": [],
        "ips": [],
        "domains": [],
        "attachments": [],
        "summary": {
            "malicious_urls": 0,
            "malicious_ips": 0,
            "malicious_domains": 0,
            "malicious_hashes": 0,
            "total_checked": 0,
        }
    }

    if not AIOHTTP_OK:
        osint["error"] = "aiohttp not installed"
        return osint

    connector = aiohttp.TCPConnector(ssl=False, limit=10)
    async with aiohttp.ClientSession(connector=connector) as session:

        # ── URLs ──────────────────────────────────────────────────────────────
        url_tasks = []
        for url in urls:
            tasks = {}
            if vt_key:
                tasks["vt"] = vt_lookup_url(url, session, vt_key)
            if urlscan_key:
                tasks["urlscan"] = urlscan_submit(url, session, urlscan_key)
            url_tasks.append((url, tasks))

        for url, tasks in url_tasks:
            results = {"url": url}
            if tasks:
                resolved = await asyncio.gather(*tasks.values(), return_exceptions=True)
                for key, val in zip(tasks.keys(), resolved):
                    results[key] = val if not isinstance(val, Exception) else _error(key, str(val))
            else:
                results["note"] = "No OSINT keys configured"

            # VT verdict summary
            vt = results.get("vt", {})
            if vt.get("status") == "ok":
                if vt.get("verdict") == "malicious":
                    osint["summary"]["malicious_urls"] += 1
                    results["verdict"] = "malicious"
                elif vt.get("verdict") == "suspicious":
                    results["verdict"] = "suspicious"
                else:
                    results["verdict"] = "clean"

            osint["urls"].append(results)

        # ── IPs ───────────────────────────────────────────────────────────────
        ip_tasks = []
        for ip in ips:
            tasks = {}
            if vt_key:
                tasks["vt"] = vt_lookup_ip(ip, session, vt_key)
            if abuse_key:
                tasks["abuseipdb"] = abuseipdb_lookup(ip, session, abuse_key)
            ip_tasks.append((ip, tasks))

        for ip, tasks in ip_tasks:
            results = {"ip": ip}
            if tasks:
                resolved = await asyncio.gather(*tasks.values(), return_exceptions=True)
                for key, val in zip(tasks.keys(), resolved):
                    results[key] = val if not isinstance(val, Exception) else _error(key, str(val))
            else:
                results["note"] = "No OSINT keys configured"

            # Verdict
            vt = results.get("vt", {})
            ab = results.get("abuseipdb", {})
            if vt.get("verdict") == "malicious" or (ab.get("status") == "ok" and ab.get("abuse_score", 0) >= 80):
                osint["summary"]["malicious_ips"] += 1
                results["verdict"] = "malicious"
            elif vt.get("verdict") == "suspicious" or (ab.get("status") == "ok" and ab.get("abuse_score", 0) >= 25):
                results["verdict"] = "suspicious"
            else:
                results["verdict"] = "unknown"

            osint["ips"].append(results)

        # ── Domains ───────────────────────────────────────────────────────────
        domain_tasks = []
        for domain in domains:
            tasks = {
                "dns": dns_lookup(domain),
                "whois": whois_lookup(domain),
            }
            if vt_key:
                tasks["vt"] = vt_lookup_domain(domain, session, vt_key)
            domain_tasks.append((domain, tasks))

        for domain, tasks in domain_tasks:
            results = {"domain": domain}
            resolved = await asyncio.gather(*tasks.values(), return_exceptions=True)
            for key, val in zip(tasks.keys(), resolved):
                results[key] = val if not isinstance(val, Exception) else _error(key, str(val))

            # Whois freshness flag
            whois_data = results.get("whois", {})
            if whois_data.get("status") == "ok" and whois_data.get("recently_registered"):
                results["recently_registered"] = True

            vt = results.get("vt", {})
            if vt.get("verdict") == "malicious":
                osint["summary"]["malicious_domains"] += 1
                results["verdict"] = "malicious"
            elif vt.get("verdict") == "suspicious":
                results["verdict"] = "suspicious"
            else:
                results["verdict"] = "unknown"

            osint["domains"].append(results)

        # ── Attachment hashes ─────────────────────────────────────────────────
        if vt_key:
            hash_tasks = []
            for att in attachments:
                sha256 = att.get("sha256", "")
                if sha256 and len(sha256) == 64:
                    hash_tasks.append((att.get("filename", ""), sha256,
                                       vt_lookup_hash(sha256, session, vt_key)))

            for filename, sha256, task in hash_tasks:
                result = await task
                entry = {"filename": filename, "sha256": sha256, "vt": result}
                if result.get("verdict") == "malicious":
                    osint["summary"]["malicious_hashes"] += 1
                    entry["verdict"] = "malicious"
                osint["attachments"].append(entry)

    osint["summary"]["total_checked"] = (
        len(osint["urls"]) + len(osint["ips"]) +
        len(osint["domains"]) + len(osint["attachments"])
    )

    return osint
