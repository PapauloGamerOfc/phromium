#!/usr/bin/env python3
"""Generate Phromium's original P icon assets; requires Pillow >= 10.

The logo is repo-native geometry, not a modified upstream trademark. Internal
resource filenames stay unchanged so existing GRIT and installer references work.
Run from any working directory. macOS uses app.icns, not upstream Assets.car.
"""

from pathlib import Path
from PIL import Image, ImageDraw, ImageOps

ROOT = Path(__file__).resolve().parents[1]
THEME = ROOT / "chrome/app/theme"
BG = "#563ac7"
INK = "#ffffff"
ACCENT = "#39d6c5"
SVG = '''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256">
  <circle cx="128" cy="128" r="120" fill="#563ac7"/>
  <path fill="#fff" fill-rule="evenodd" d="M78 58h65a53 53 0 0 1 0 106h-31v38H78V58zm34 32v42h31a21 21 0 0 0 0-42h-31z"/>
  <circle cx="191" cy="191" r="19" fill="#39d6c5"/>
</svg>
'''


def logo(size, mono=False):
    scale = 4
    image = Image.new("RGBA", (256 * scale, 256 * scale))
    draw = ImageDraw.Draw(image)
    def box(points):
        return tuple(round(value * scale) for value in points)
    draw.ellipse(box((8, 8, 248, 248)), fill=BG)
    draw.rectangle(box((78, 58, 112, 202)), fill=INK)
    draw.rectangle(box((100, 58, 143, 164)), fill=INK)
    draw.ellipse(box((90, 58, 196, 164)), fill=INK)
    draw.rectangle(box((112, 90, 143, 132)), fill=BG)
    draw.ellipse(box((122, 90, 164, 132)), fill=BG)
    draw.ellipse(box((172, 172, 210, 210)), fill=ACCENT)
    if mono:
        alpha = image.getchannel("A")
        image = ImageOps.grayscale(image).convert("RGBA")
        image.putalpha(alpha)
    return image.resize((size, size), Image.Resampling.LANCZOS)


def main():
    paths = [THEME / "chromium", THEME / "default_100_percent/chromium",
             THEME / "default_200_percent/chromium"]
    count = 0
    for folder in paths:
        for path in folder.rglob("*.png"):
            if "chromeos" in path.parts:
                continue
            if not (path.name.startswith("product_logo")
                    or path.name.startswith("appicon_")
                    or "tiles" in path.parts):
                continue
            with Image.open(path) as old:
                width, height = old.size
            asset = logo(min(width, height), "mono" in path.name)
            if width != height:
                canvas = Image.new("RGBA", (width, height))
                canvas.alpha_composite(asset, (0, (height - asset.height) // 2))
                asset = canvas
            asset.save(path, optimize=True)
            count += 1
    for filename in ["chromium.ico", "app_list.ico"]:
        logo(256).save(THEME / "chromium/win" / filename,
                       sizes=[(n, n) for n in (16, 24, 32, 48, 64, 128, 256)])
        count += 1
    logo(1024).save(THEME / "chromium/mac/app.icns")
    count += 1
    for filename in ["product_logo.svg", "product_logo_animation.svg"]:
        (THEME / "chromium" / filename).write_text(SVG, encoding="utf-8", newline="\n")
        count += 1
    print(f"Generated {count} Phromium icon assets")


if __name__ == "__main__":
    main()
