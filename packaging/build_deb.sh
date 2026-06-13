#!/bin/bash
# PhishLens .deb Builder
# Run from project root: bash packaging/build_deb.sh
set -e

VERSION="2.0.0"
PKG_NAME="phishlens_${VERSION}_amd64"
BUILD_DIR="$(pwd)/packaging/deb"
DIST_DIR="$(pwd)/dist"
INSTALL_DIR="$BUILD_DIR/usr/share/phishlens"

echo "[*] Building PhishLens .deb package v${VERSION}"

# ── Clean old build ────────────────────────────────────────────────────────────
rm -rf "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/backend"
mkdir -p "$INSTALL_DIR/frontend"

# ── Copy app files ─────────────────────────────────────────────────────────────
echo "[*] Copying application files..."
cp run.py            "$INSTALL_DIR/"
cp requirements.txt  "$INSTALL_DIR/"
cp backend/main.py   "$INSTALL_DIR/backend/"
cp backend/parser.py "$INSTALL_DIR/backend/"
cp backend/osint.py  "$INSTALL_DIR/backend/"
cp backend/ai_analysis.py "$INSTALL_DIR/backend/"
cp backend/config.py "$INSTALL_DIR/backend/"
cp frontend/index.html "$INSTALL_DIR/frontend/"

# ── Set permissions ────────────────────────────────────────────────────────────
chmod 755 "$BUILD_DIR/DEBIAN/postinst"
chmod 755 "$BUILD_DIR/DEBIAN/prerm"
chmod 755 "$BUILD_DIR/usr/bin/phishlens"

# ── Calculate installed size ───────────────────────────────────────────────────
SIZE=$(du -sk "$BUILD_DIR" | awk '{print $1}')
# Update control file with size
sed -i "/^Installed-Size:/d" "$BUILD_DIR/DEBIAN/control"
echo "Installed-Size: $SIZE" >> "$BUILD_DIR/DEBIAN/control"

# ── Build .deb ────────────────────────────────────────────────────────────────
mkdir -p "$DIST_DIR"
dpkg-deb --build "$BUILD_DIR" "$DIST_DIR/${PKG_NAME}.deb"

echo ""
echo "[+] Done: dist/${PKG_NAME}.deb"
echo ""
echo "Install with:"
echo "  sudo dpkg -i dist/${PKG_NAME}.deb"
echo ""
echo "Uninstall with:"
echo "  sudo dpkg -r phishlens"
