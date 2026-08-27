"""
NetCheck app icon generator (design asset).

Draws the NetCheck icon and emits a multi-resolution Windows .ico plus a PNG
preview. Pure-Pillow (no SVG/cairo dependency) so Dev can regenerate the icon
in the build pipeline with only `pip install pillow`.

Concept: a rounded-square badge in the app's brand blue (#2f6fed), white radar
/ signal arcs (the "network" read), and a healthy-green check disc (#1a9d55,
the app's "good" status token) meaning "checked / OK". Colors are taken
directly from netcheck_gui.py STATUS_COLORS + QSS tokens so the icon matches
the running UI in both light and dark taskbars.

Usage:
    python assets/generate_icon.py
Outputs (next to this script):
    icon.ico          multi-res: 16/24/32/48/64/128/256
    icon_preview.png  256px preview for review
"""
from __future__ import annotations

import os
from PIL import Image, ImageDraw

# --- Brand tokens (mirrored from netcheck_gui.py) ---------------------------
BRAND_BLUE = (47, 111, 237)      # #2f6fed  primary
BRAND_BLUE_DK = (40, 95, 208)    # #285fd0  gradient bottom
GOOD_GREEN = (26, 157, 85)       # #1a9d55  status "good"
WHITE = (255, 255, 255)

SS = 8            # supersample factor for anti-aliasing
BASE = 256        # logical canvas size
SIZES = [16, 24, 32, 48, 64, 128, 256]

HERE = os.path.dirname(os.path.abspath(__file__))


def _rounded_mask(size: int, radius: int) -> Image.Image:
    m = Image.new("L", (size, size), 0)
    d = ImageDraw.Draw(m)
    d.rounded_rectangle([0, 0, size - 1, size - 1], radius=radius, fill=255)
    return m


def _vertical_gradient(size: int, top: tuple, bottom: tuple) -> Image.Image:
    grad = Image.new("RGB", (1, size))
    for y in range(size):
        t = y / max(1, size - 1)
        grad.putpixel((0, y), tuple(round(top[i] + (bottom[i] - top[i]) * t) for i in range(3)))
    return grad.resize((size, size))


def render(px: int) -> Image.Image:
    """Render the icon at `px` logical pixels (supersampled internally)."""
    S = px * SS
    canvas = Image.new("RGBA", (S, S), (0, 0, 0, 0))

    # Rounded badge with vertical brand gradient.
    radius = round(S * 0.22)
    badge = _vertical_gradient(S, BRAND_BLUE, BRAND_BLUE_DK).convert("RGBA")
    badge.putalpha(_rounded_mask(S, radius))
    canvas.alpha_composite(badge)

    d = ImageDraw.Draw(canvas)

    # Signal origin near lower-left; radar arcs sweeping up-right.
    ox, oy = round(S * 0.30), round(S * 0.72)
    dot_r = round(S * 0.045)
    d.ellipse([ox - dot_r, oy - dot_r, ox + dot_r, oy + dot_r], fill=WHITE)

    stroke = round(S * 0.055)
    for i, r in enumerate((0.20, 0.34, 0.48)):
        rr = round(S * r)
        # Arc from ~ -80deg to +10deg gives an up-and-right signal fan.
        d.arc([ox - rr, oy - rr, ox + rr, oy + rr], start=-82, end=8, fill=WHITE, width=stroke)

    # Green "check" disc, top-right, meaning checked/healthy.
    cd_r = round(S * 0.19)
    cx, cy = round(S * 0.70), round(S * 0.32)
    # subtle white ring so the disc reads on the blue in either taskbar theme
    ring = round(S * 0.028)
    d.ellipse([cx - cd_r - ring, cy - cd_r - ring, cx + cd_r + ring, cy + cd_r + ring], fill=WHITE)
    d.ellipse([cx - cd_r, cy - cd_r, cx + cd_r, cy + cd_r], fill=GOOD_GREEN)

    # Checkmark inside the disc.
    cw = round(S * 0.04)
    p1 = (cx - cd_r * 0.45, cy + cd_r * 0.02)
    p2 = (cx - cd_r * 0.08, cy + cd_r * 0.40)
    p3 = (cx + cd_r * 0.50, cy - cd_r * 0.38)
    d.line([p1, p2, p3], fill=WHITE, width=cw, joint="curve")

    return canvas.resize((px, px), Image.LANCZOS)


def main() -> None:
    imgs = {s: render(s) for s in SIZES}
    ico_path = os.path.join(HERE, "icon.ico")
    # Pillow writes all provided sizes into one .ico when given the largest + sizes list.
    imgs[256].save(ico_path, format="ICO", sizes=[(s, s) for s in SIZES])
    imgs[256].save(os.path.join(HERE, "icon_preview.png"), format="PNG")
    print("wrote", ico_path, "sizes", SIZES)
    print("wrote", os.path.join(HERE, "icon_preview.png"))


if __name__ == "__main__":
    main()
