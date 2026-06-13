#!/usr/bin/env python3
"""
PhishLens Icon Generator
Generates a simple SVG + PNG icon for use in .deb and AppImage packaging.
Run: python packaging/make_icon.py
"""

import os
from pathlib import Path

ICON_DIR = Path(__file__).parent / "icons"
ICON_DIR.mkdir(exist_ok=True)

SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256">
  <!-- Background -->
  <rect width="256" height="256" rx="32" fill="#0f1218"/>
  <!-- Outer shield -->
  <path d="M128 24 L208 60 L208 128 C208 176 168 212 128 228 C88 212 48 176 48 128 L48 60 Z"
        fill="none" stroke="#2196f3" stroke-width="6" stroke-linejoin="round"/>
  <!-- Inner shield -->
  <path d="M128 52 L188 80 L188 128 C188 162 162 188 128 204 C94 188 68 162 68 128 L68 80 Z"
        fill="#0a0c10" stroke="#1565c0" stroke-width="3" stroke-linejoin="round"/>
  <!-- Magnifier circle -->
  <circle cx="118" cy="122" r="36" fill="none" stroke="#2196f3" stroke-width="6"/>
  <!-- Magnifier handle -->
  <line x1="144" y1="148" x2="170" y2="175"
        stroke="#2196f3" stroke-width="8" stroke-linecap="round"/>
  <!-- Phishing hook inside magnifier -->
  <path d="M106 110 C106 102 130 102 130 110 C130 120 118 122 118 132"
        fill="none" stroke="#00bcd4" stroke-width="4" stroke-linecap="round"/>
  <circle cx="118" cy="137" r="3" fill="#00bcd4"/>
</svg>"""

# Write SVG
svg_path = ICON_DIR / "phishlens.svg"
svg_path.write_text(SVG)
print(f"[+] SVG: {svg_path}")

# Try to generate PNG via cairosvg or inkscape or rsvg-convert
png_path = ICON_DIR / "phishlens.png"

def try_cairosvg():
    import cairosvg
    cairosvg.svg2png(url=str(svg_path), write_to=str(png_path), output_width=256, output_height=256)
    return True

def try_inkscape():
    ret = os.system(f'inkscape --export-type=png --export-filename="{png_path}" --export-width=256 "{svg_path}" 2>/dev/null')
    return ret == 0 and png_path.exists()

def try_rsvg():
    ret = os.system(f'rsvg-convert -w 256 -h 256 "{svg_path}" -o "{png_path}" 2>/dev/null')
    return ret == 0 and png_path.exists()

def try_imagemagick():
    ret = os.system(f'convert -background none -size 256x256 "{svg_path}" "{png_path}" 2>/dev/null')
    return ret == 0 and png_path.exists()

converters = [
    ("cairosvg",    try_cairosvg),
    ("inkscape",    try_inkscape),
    ("rsvg-convert",try_rsvg),
    ("imagemagick", try_imagemagick),
]

for name, fn in converters:
    try:
        if fn():
            print(f"[+] PNG: {png_path} (via {name})")
            break
    except Exception:
        continue
else:
    print("[!] PNG conversion skipped — install cairosvg, inkscape, rsvg-convert, or imagemagick")
    print(f"    SVG is at: {svg_path}")
    print("    Copy it manually to:")
    print("    packaging/deb/usr/share/icons/hicolor/256x256/apps/phishlens.png")

# Copy to deb icon dir if PNG was generated
if png_path.exists():
    import shutil
    deb_icon = Path(__file__).parent / "deb/usr/share/icons/hicolor/256x256/apps/phishlens.png"
    deb_icon.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(png_path, deb_icon)
    print(f"[+] Copied to deb: {deb_icon}")
