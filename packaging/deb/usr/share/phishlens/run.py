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

REQUIRED = ['fastapi', 'uvicorn', 'python_multipart', 'dnspython']

def check_deps():
    missing = []
    for pkg in REQUIRED:
        try:
            __import__(pkg.replace('-', '_').split('[')[0])
        except ImportError:
            missing.append(pkg)
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

    # Change to backend dir
    backend_dir = Path(__file__).parent / 'backend'
    os.chdir(backend_dir)

    # Set data dir env var so backend knows where to store DB/config
    if args.data_dir:
        os.environ['PHISHLENS_DATA_DIR'] = str(Path(args.data_dir).resolve())

    print(f"[+] Starting PhishLens on http://{args.host}:{args.port}")
    print(f"[+] Database: {Path(__file__).parent / 'phishlens.db'}")
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
            log_level="warning"
        )
    except KeyboardInterrupt:
        print("\n[+] PhishLens stopped.")
    except Exception as e:
        print(f"[!] Server error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
