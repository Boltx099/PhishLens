#!/bin/bash
# PhishLens Arch Linux (.pkg.tar.zst) Builder
# Run from project root: bash packaging/build_pkg.sh
#
# Requires: base-devel (makepkg), python3
# Output:   dist/phishlens-2.0.0-1-any.pkg.tar.zst
set -e

VERSION="2.0.0"
PKGREL="1"
PKG_NAME="phishlens-${VERSION}-${PKGREL}-any.pkg.tar.zst"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ARCH_DIR="$SCRIPT_DIR/arch"
BUILD_DIR="$PROJECT_ROOT/build_arch"
DIST_DIR="$PROJECT_ROOT/dist"
TARBALL_NAME="phishlens-${VERSION}.tar.gz"

echo "[*] Building PhishLens Arch package v${VERSION}-${PKGREL}"

# ── Sanity checks ──────────────────────────────────────────────────────────────
if ! command -v makepkg &>/dev/null; then
    echo "[!] makepkg not found. Install base-devel:"
    echo "    sudo pacman -S base-devel"
    exit 1
fi

if ! command -v python3 &>/dev/null; then
    echo "[!] python3 not found. Install with:"
    echo "    sudo pacman -S python"
    exit 1
fi

# ── Clean old build ────────────────────────────────────────────────────────────
echo "[*] Cleaning old build artifacts..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
mkdir -p "$DIST_DIR"

# ── Create source tarball ──────────────────────────────────────────────────────
echo "[*] Creating source tarball..."
STAGING="$BUILD_DIR/phishlens-${VERSION}"
mkdir -p "$STAGING/backend"
mkdir -p "$STAGING/frontend"
mkdir -p "$STAGING/assets"

cp "$PROJECT_ROOT/run.py"           "$STAGING/"
cp "$PROJECT_ROOT/requirements.txt" "$STAGING/"

cp "$PROJECT_ROOT/backend/main.py"        "$STAGING/backend/"
cp "$PROJECT_ROOT/backend/parser.py"      "$STAGING/backend/"
cp "$PROJECT_ROOT/backend/osint.py"       "$STAGING/backend/"
cp "$PROJECT_ROOT/backend/ai_analysis.py" "$STAGING/backend/"
cp "$PROJECT_ROOT/backend/config.py"      "$STAGING/backend/"

cp "$PROJECT_ROOT/frontend/index.html" "$STAGING/frontend/"

[ -f "$PROJECT_ROOT/assets/logo.png" ]      && cp "$PROJECT_ROOT/assets/logo.png"      "$STAGING/assets/"
[ -f "$PROJECT_ROOT/assets/logo_dark.jpg" ] && cp "$PROJECT_ROOT/assets/logo_dark.jpg" "$STAGING/assets/"

# Pack as tarball into the arch build dir
tar -czf "$BUILD_DIR/$TARBALL_NAME" -C "$BUILD_DIR" "phishlens-${VERSION}"
echo "[*] Tarball: $TARBALL_NAME"

# ── Copy packaging files ───────────────────────────────────────────────────────
echo "[*] Copying PKGBUILD and install script..."
cp "$ARCH_DIR/PKGBUILD"           "$BUILD_DIR/"
cp "$ARCH_DIR/phishlens.install"  "$BUILD_DIR/"

# ── Compute sha256 and patch PKGBUILD ─────────────────────────────────────────
echo "[*] Computing sha256sum..."
SHA256=$(sha256sum "$BUILD_DIR/$TARBALL_NAME" | awk '{print $1}')
sed -i "s/sha256sums=('SKIP')/sha256sums=('${SHA256}')/" "$BUILD_DIR/PKGBUILD"
echo "[*] sha256: $SHA256"

# ── Build with makepkg ────────────────────────────────────────────────────────
echo "[*] Running makepkg..."
cd "$BUILD_DIR"
makepkg --noconfirm --noprogressbar -f 2>&1

# ── Move output to dist/ ───────────────────────────────────────────────────────
BUILT_PKG=$(ls "$BUILD_DIR"/*.pkg.tar.zst 2>/dev/null | head -1)
if [ -z "$BUILT_PKG" ]; then
    echo "[!] makepkg did not produce a package. Check output above."
    exit 1
fi

mv "$BUILT_PKG" "$DIST_DIR/$PKG_NAME"

echo ""
echo "[+] Done: dist/$PKG_NAME"
echo ""
echo "Install with:"
echo "  sudo pacman -U dist/$PKG_NAME"
echo ""
echo "Uninstall with:"
echo "  sudo pacman -R phishlens"
echo ""
