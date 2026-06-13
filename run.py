#!/usr/bin/env python3
"""
PhishLens v2.0 - Launcher
Cross-platform: Windows / Linux / macOS

Usage:
    python run.py
    python run.py --port 8080
    python run.py --no-browser
"""

import sys
import os
import argparse
import subprocess
import webbrowser
import threading
import time
from pathlib import Path

# ─── Check Python version ─────────────────────────────────────────────────────
if sys.version_info < (3, 8):
    print("[!] PhishLens requires Python 3.8+")
    print(f"    Current version: {sys.version}")
    sys.exit(1)

# ─── Banner ───────────────────────────────────────────────────────────────────

BANNER = r"""
    ____  __    _      __    __                    
   / __ \/ /_  (_)____/ /_  / /   ___  ____  _____
  / /_/ / __ \/ / ___/ __ \/ /   / _ \/ __ \/ ___/
 / ____/ / / / (__  ) / / / /___/  __/ / / (__  ) 
/_/   /_/ /_/_/____/_/ /_/_____/\___/_/ /_/____/  
                                                    
  Advanced Phishing Email Analyzer  v2.0
  ──────────────────────────────────────────────────
"""

# ─── Dependency Check ─────────────────────────────────────────────────────────

# (import_name, pip_package_name)
REQUIRED = [
    ('fastapi',           'fastapi>=0.110.0'),
    ('uvicorn',           'uvicorn[standard]>=0.29.0'),
    ('multipart',         'python-multipart>=0.0.9'),
    ('dns',               'dnspython>=2.6.0'),
    ('mailparser',        'mail-parser>=3.15.0'),
    ('extract_msg',       'extract-msg>=0.48.0'),
    ('whois',             'python-whois>=0.9.0'),
    ('aiohttp',           'aiohttp>=3.9.0'),
    ('requests',          'requests>=2.31.0'),
]

def check_deps():
    missing = []
    for import_name, pip_name in REQUIRED:
        try:
            __import__(import_name)
        except ImportError:
            missing.append(pip_name)
    return missing

def install_deps(packages):
    print("[*] Installing missing dependencies...")
    cmd = [sys.executable, '-m', 'pip', 'install'] + packages + ['--quiet']
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print("[!] Dependency install failed. Run manually:")
        print(f"    pip install {' '.join(packages)}")
        sys.exit(1)
    print("[+] Dependencies installed.")

# ─── Browser opener ───────────────────────────────────────────────────────────

def open_browser(port: int, delay: float = 1.5):
    def _open():
        time.sleep(delay)
        url = f"http://127.0.0.1:{port}"
        print(f"[*] Opening browser: {url}")
        webbrowser.open(url)
    t = threading.Thread(target=_open, daemon=True)
    t.start()

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='PhishLens v2.0 - Advanced Phishing Email Analyzer'
    )
    parser.add_argument('--port', type=int, default=7331, help='Port to run on (default: 7331)')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind to (default: 127.0.0.1)')
    parser.add_argument('--no-browser', action='store_true', help='Do not auto-open browser')
    parser.add_argument('--reload', action='store_true', help='Enable auto-reload (dev mode)')
    parser.add_argument('--data-dir', default=None, help='Directory for DB and config (default: project root)')
    args = parser.parse_args()

    print(BANNER)

    # Check deps
    missing = check_deps()
    if missing:
        install_deps(missing)

    # ── Resolve paths ──────────────────────────────────────────────────────────
    project_root = Path(__file__).parent.resolve()
    backend_dir  = project_root / 'backend'

    # Add backend/ to sys.path so uvicorn can import main, parser, osint, etc.
    if str(backend_dir) not in sys.path:
        sys.path.insert(0, str(backend_dir))

    # Stay at project root — do NOT chdir into backend/
    os.chdir(project_root)

    # ── Data dir (DB + config) ─────────────────────────────────────────────────
    if args.data_dir:
        data_dir = Path(args.data_dir).resolve()
    else:
        data_dir = project_root
    os.environ['PHISHLENS_DATA_DIR'] = str(data_dir)

    db_path = data_dir / 'phishlens.db'
    print(f"[+] Starting PhishLens on http://{args.host}:{args.port}")
    print(f"[+] Database: {db_path}")
    print(f"[+] Press Ctrl+C to stop\n")

    if not args.no_browser:
        open_browser(args.port)

    try:
        import uvicorn
        uvicorn.run(
            "main:app",
            host=args.host,
            port=args.port,
            reload=args.reload,
            reload_dirs=[str(backend_dir)] if args.reload else None,
            log_level="warning"
        )
    except KeyboardInterrupt:
        print("\n[+] PhishLens stopped.")
    except Exception as e:
        print(f"[!] Server error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
