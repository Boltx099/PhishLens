"""
PhishLens v2 — Config Manager
API keys stored in phishlens_config.json (project root)
"""

import json
import os
import secrets
from pathlib import Path

_base = Path(os.environ.get("PHISHLENS_DATA_DIR", Path(__file__).parent.parent))
CONFIG_PATH = _base / "phishlens_config.json"
TOKEN_PATH  = _base / ".phishlens_token"

DEFAULTS = {
    "virustotal_api_key": "",
    "abuseipdb_api_key": "",
    "urlscan_api_key": "",
    "anthropic_api_key": "",
    "osint_timeout": 10,
    "max_urls_to_scan": 5,
    "max_ips_to_scan": 5,
    "ai_analysis_enabled": True,
    "ai_model": "claude-sonnet-4-6",
}


def load_config() -> dict:
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r") as f:
                data = json.load(f)
            # Merge with defaults so new keys always exist
            merged = {**DEFAULTS, **data}
            return merged
        except Exception:
            pass
    return dict(DEFAULTS)


def save_config(data: dict) -> bool:
    try:
        # Only save known keys for safety
        safe = {k: data.get(k, DEFAULTS[k]) for k in DEFAULTS}
        with open(CONFIG_PATH, "w") as f:
            json.dump(safe, f, indent=2)
        return True
    except Exception:
        return False


def get_key(name: str) -> str:
    return load_config().get(name, "")


def is_configured(name: str) -> bool:
    return bool(get_key(name))


def configured_services() -> dict:
    cfg = load_config()
    return {
        "virustotal": bool(cfg.get("virustotal_api_key")),
        "abuseipdb":  bool(cfg.get("abuseipdb_api_key")),
        "urlscan":    bool(cfg.get("urlscan_api_key")),
        "anthropic":  bool(cfg.get("anthropic_api_key")),
    }


def get_or_create_token() -> str:
    """
    Local API token — required on every /api/* request.
    Prevents any other page open in the user's browser (or another
    machine on the LAN if --host 0.0.0.0 is used) from silently
    calling PhishLens's API, since CORS alone does not stop that.
    """
    if TOKEN_PATH.exists():
        try:
            tok = TOKEN_PATH.read_text().strip()
            if tok:
                return tok
        except Exception:
            pass
    tok = secrets.token_hex(24)
    try:
        TOKEN_PATH.write_text(tok)
        try:
            os.chmod(TOKEN_PATH, 0o600)
        except Exception:
            pass
    except Exception:
        pass
    return tok
