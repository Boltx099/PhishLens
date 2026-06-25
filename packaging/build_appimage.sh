#!/bin/bash
# PhishLens AppImage Builder
# Produces a single portable .AppImage that runs on any Linux x86_64
# Requirements: python3, pip, wget (appimagetool auto-downloaded)
set -e

VERSION="2.0.0"
DIST_DIR="$(pwd)/dist"
BUILD_DIR="$(pwd)/build_appimage"
APPDIR="$BUILD_DIR/PhishLens.AppDir"

echo "[*] Building PhishLens AppImage v${VERSION}"

# ── Install PyInstaller ────────────────────────────────────────────────────────
echo "[*] Installing PyInstaller..."
pip install pyinstaller --quiet

# ── Install app dependencies ──────────────────────────────────────────────────
echo "[*] Installing dependencies..."
pip install -r requirements.txt --quiet

# ── PyInstaller spec ──────────────────────────────────────────────────────────
echo "[*] Running PyInstaller..."

# Create a temporary entry point that bundles everything
cat > /tmp/phishlens_entry.py << 'PYEOF'
import sys, os
from pathlib import Path

# When bundled by PyInstaller, _MEIPASS is set
if getattr(sys, 'frozen', False):
    base = Path(sys._MEIPASS)
    os.chdir(base / 'backend')
    sys.path.insert(0, str(base / 'backend'))

import run
run.main()
PYEOF

pyinstaller \
    --onedir \
    --name "PhishLens" \
    --add-data "backend:backend" \
    --add-data "frontend:frontend" \
    --hidden-import "uvicorn.logging" \
    --hidden-import "uvicorn.loops" \
    --hidden-import "uvicorn.loops.auto" \
    --hidden-import "uvicorn.protocols" \
    --hidden-import "uvicorn.protocols.http" \
    --hidden-import "uvicorn.protocols.http.auto" \
    --hidden-import "uvicorn.protocols.websockets" \
    --hidden-import "uvicorn.protocols.websockets.auto" \
    --hidden-import "uvicorn.lifespan" \
    --hidden-import "uvicorn.lifespan.on" \
    --hidden-import "email.mime.text" \
    --hidden-import "email.mime.multipart" \
    --hidden-import "dns.resolver" \
    --hidden-import "aiohttp" \
    --hidden-import "fastapi" \
    --hidden-import "multipart" \
    --distpath "$BUILD_DIR/pyinstaller_dist" \
    --workpath "$BUILD_DIR/pyinstaller_work" \
    --specpath "$BUILD_DIR" \
    --noconfirm \
    /tmp/phishlens_entry.py

# ── Build AppDir structure ────────────────────────────────────────────────────
echo "[*] Building AppDir..."
mkdir -p "$APPDIR/usr/bin"
mkdir -p "$APPDIR/usr/share/applications"
mkdir -p "$APPDIR/usr/share/icons/hicolor/256x256/apps"

# Copy PyInstaller output
cp -r "$BUILD_DIR/pyinstaller_dist/PhishLens/"* "$APPDIR/usr/bin/"

# AppRun entrypoint
cat > "$APPDIR/AppRun" << 'APPEOF'
#!/bin/bash
SELF_DIR="$(dirname "$(readlink -f "$0")")"
DATA_DIR="$HOME/.local/share/phishlens"
mkdir -p "$DATA_DIR"
export PHISHLENS_DATA_DIR="$DATA_DIR"
exec "$SELF_DIR/usr/bin/PhishLens" "$@"
APPEOF
chmod +x "$APPDIR/AppRun"

# Desktop file
cat > "$APPDIR/phishlens.desktop" << 'DEOF'
[Desktop Entry]
Type=Application
Name=PhishLens
Exec=PhishLens
Icon=phishlens
Categories=Network;Security;
Comment=Advanced Phishing Email Analyzer
DEOF
cp "$APPDIR/phishlens.desktop" "$APPDIR/usr/share/applications/"

# Placeholder icon (replace with real PNG for production)
# appimagetool requires at least a placeholder
touch "$APPDIR/phishlens.png"
touch "$APPDIR/usr/share/icons/hicolor/256x256/apps/phishlens.png"

# ── Download appimagetool if needed ──────────────────────────────────────────
APPIMAGETOOL="$BUILD_DIR/appimagetool-x86_64.AppImage"
if [ ! -f "$APPIMAGETOOL" ]; then
    echo "[*] Downloading appimagetool..."
    wget -q "https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage" \
        -O "$APPIMAGETOOL"
    chmod +x "$APPIMAGETOOL"
fi

# ── Build AppImage ────────────────────────────────────────────────────────────
mkdir -p "$DIST_DIR"
echo "[*] Packaging AppImage..."
ARCH=x86_64 "$APPIMAGETOOL" "$APPDIR" "$DIST_DIR/PhishLens-${VERSION}-x86_64.AppImage" 2>&1

echo ""
echo "[+] Done: dist/PhishLens-${VERSION}-x86_64.AppImage"
echo ""
echo "Run with:"
echo "  chmod +x dist/PhishLens-${VERSION}-x86_64.AppImage"
echo "  ./dist/PhishLens-${VERSION}-x86_64.AppImage"
