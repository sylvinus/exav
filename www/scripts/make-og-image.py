#!/usr/bin/env python3
"""Draws www/public/og.png, the picture that link previews show for exav.org.

    python3 -I www/scripts/make-og-image.py

The picture is 1200 x 630 pixels: the site's mark (the teal shield with the
2x2 "exav" monogram of src/assets/logo.svg, drawn again here), the name and the
tagline, on the site's dark background. Everything is drawn from nothing by
this script, with Pillow; no photograph, logo or other asset is read.

Licence: the picture and this script are dedicated to the public domain under
CC0-1.0 (https://creativecommons.org/publicdomain/zero/1.0/). The text is set
in DejaVu Sans, a free font (Bitstream Vera licence with public domain
additions) whose licence lets its rendered text be used freely.

The output does not depend on the date or the machine beyond Pillow's
rasteriser, so running the script again on the same version gives the same
file.
"""
import os
import sys

from PIL import Image, ImageDraw, ImageFont
from PIL.PngImagePlugin import PngInfo

WIDTH, HEIGHT = 1200, 630
SCALE = 3  # drawn this many times larger, then reduced, for smooth edges

BACKGROUND = (0x17, 0x18, 0x1C)  # Starlight's dark --sl-color-black
TEAL = (0x0F, 0x9E, 0x8E)  # --sl-color-accent in src/styles/custom.css
WHITE = (0xFF, 0xFF, 0xFF)
TEXT = (0xED, 0xEE, 0xF3)  # --sl-color-white
MUTED = (0xC1, 0xC3, 0xC8)  # --sl-color-gray-2

NAME = "exav"
TAGLINE = ["Memory-safe tools", "for untrusted files."]
ADDRESS = "exav.org"

FONT_DIRS = ["/usr/share/fonts/truetype/dejavu", "/usr/share/fonts/dejavu", "/usr/share/fonts/TTF"]


def font(name, size):
    for directory in FONT_DIRS:
        path = os.path.join(directory, name)
        if os.path.exists(path):
            return ImageFont.truetype(path, size)
    sys.exit(f"{name} not found in {', '.join(FONT_DIRS)}: install DejaVu Sans (fonts-dejavu-core)")


def cubic(p0, p1, p2, p3, steps=24):
    """Points of a cubic Bezier curve, the start left out."""
    out = []
    for i in range(1, steps + 1):
        t = i / steps
        u = 1 - t
        out.append(
            (
                u**3 * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t**3 * p3[0],
                u**3 * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t**3 * p3[1],
            )
        )
    return out


def shield():
    """The shield of logo.svg, in its 32 x 32 units:
    M16 3.4 26 6.6v12.1c0 4.9-4.1 8.1-10 10-5.9-1.9-10-5.1-10-10V6.6Z"""
    points = [(16, 3.4), (26, 6.6), (26, 18.7)]
    points += cubic((26, 18.7), (26, 23.6), (21.9, 26.8), (16, 28.7))
    points += cubic((16, 28.7), (10.1, 26.8), (6, 23.6), (6, 18.7))
    points += [(6, 6.6)]
    return points


def draw_mark(draw, left, top, size):
    """The mark with its top left corner at (left, top), `size` pixels wide."""
    k = size / 32

    def at(x, y):
        return (left + x * k, top + y * k)

    draw.rounded_rectangle([left, top, left + size, top + size], radius=8 * k, fill=TEAL)
    draw.polygon([at(x, y) for x, y in shield()], fill=WHITE)
    letters = font("DejaVuSans-Bold.ttf", round(10 * k))
    for letter, x, y in (("e", 12.6, 15.3), ("x", 19.4, 15.3), ("a", 12.6, 22.9), ("v", 19.4, 22.9)):
        draw.text(at(x, y), letter, font=letters, fill=TEAL, anchor="ms")


def main():
    image = Image.new("RGB", (WIDTH * SCALE, HEIGHT * SCALE), BACKGROUND)
    draw = ImageDraw.Draw(image)

    mark = 330
    draw_mark(draw, 120 * SCALE, (HEIGHT - mark) // 2 * SCALE, mark * SCALE)

    left = 520 * SCALE
    draw.text((left, 292 * SCALE), NAME, font=font("DejaVuSans-Bold.ttf", 170 * SCALE), fill=TEXT, anchor="ls")
    tagline = font("DejaVuSans.ttf", 46 * SCALE)
    for i, line in enumerate(TAGLINE):
        draw.text((left, (362 + i * 62) * SCALE), line, font=tagline, fill=MUTED, anchor="ls")
    draw.text((left, 520 * SCALE), ADDRESS, font=font("DejaVuSansMono-Bold.ttf", 34 * SCALE), fill=TEAL, anchor="ls")

    image = image.resize((WIDTH, HEIGHT), Image.LANCZOS)

    info = PngInfo()
    info.add_text("Title", "exav: Memory-safe tools for untrusted files.")
    info.add_text("Copyright", "CC0-1.0: https://creativecommons.org/publicdomain/zero/1.0/")
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "public", "og.png")
    image.save(out, optimize=True, pnginfo=info)
    print(f"wrote {os.path.normpath(out)}")


if __name__ == "__main__":
    main()
