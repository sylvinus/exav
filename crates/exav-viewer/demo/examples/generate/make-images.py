#!/usr/bin/env python3
"""Writes the demo's raster image examples into ../files/images/.

    python3 -I make-images.py [OUT_DIR]

Output: CC0-1.0, a public domain dedication by the exav project. Every
picture is drawn here from scratch with numpy and Pillow (text in Pillow's
bundled Aileron font, CC0): no outside image is used.

Needs: Python 3, Pillow 10 or later (with libtiff, WebP and OpenJPEG),
numpy; the programs opj_compress (libopenjp2-tools), jbig2 (jbig2enc),
cjxl (libjxl-tools) and tiffcp (libtiff-tools) for the JPEG 2000, JBIG2,
JPEG XL and fax files. Without a program, the files it makes are skipped.

The encoders for QOI, farbfeld, Radiance HDR, DDS (BC1 and BC3), BMP with
RLE8 and the legacy ICO are written here, so that no encoder under another
licence is involved.
"""
import io
import math
import os
import shutil
import struct
import subprocess
import sys
import tempfile

import numpy as np
from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(HERE, "..", "files", "images")
WORK = tempfile.mkdtemp()
os.makedirs(OUT, exist_ok=True)


def font(size):
    return ImageFont.load_default(size)


def out(name):
    return os.path.join(OUT, name)


def tool(name):
    return shutil.which(name) is not None


# ---------------------------------------------------------------- the picture


def ridge(w, seed, base, amp):
    """A mountain line: heights in 0..1 from the top, one per column."""
    rng = np.random.default_rng(seed)
    x = np.linspace(0, 1, w)
    y = np.zeros(w)
    for k in range(1, 9):
        y += (amp / k**1.15) * np.sin(2 * math.pi * (k * 0.9 + rng.random()) * x + rng.random() * 6.28)
    return base + y


def scene(w=512, h=384):
    """A dusk landscape: sky, stars, sun, three ridges, a lake, pines, a caption.
    Returns the 8-bit RGB image and the sun's glow (0..1 per pixel)."""
    yy = np.linspace(0, 1, h)[:, None] * np.ones((1, w))
    xx = np.linspace(0, 1, w)[None, :] * np.ones((h, 1))
    horizon = 0.62
    t = np.clip(yy / horizon, 0, 1)
    top, mid, low = np.array([24, 30, 92.0]), np.array([196, 84, 110.0]), np.array([255, 190, 110.0])
    sky = np.where((t < 0.6)[..., None], top + (mid - top) * (t / 0.6)[..., None], mid + (low - mid) * ((t - 0.6) / 0.4)[..., None])
    sx, sy, sr = 0.68, 0.5, 0.045
    d = np.hypot((xx - sx) * w / h, yy - sy)
    glow = np.clip(1 - d / 0.35, 0, 1) ** 2
    sky += glow[..., None] * np.array([120, 70, 20.0])
    sky = np.where((d < sr)[..., None], np.array([255, 250, 225.0]), sky)
    rng = np.random.default_rng(3)
    for _ in range(90):
        px, py = rng.integers(0, w), rng.integers(0, int(h * 0.3))
        sky[py, px] = np.minimum(255, sky[py, px] + rng.integers(90, 200))
    img = sky.copy()
    haze = np.array([230, 150, 130.0])
    for i, (base, amp, col) in enumerate([(0.50, 0.05, (120, 80, 120)), (0.56, 0.05, (80, 55, 95)), (0.61, 0.035, (40, 32, 70))]):
        line = ridge(w, 10 + i, base, amp)
        mask = yy > line[None, :]
        shade = np.array(col, float) * (0.9 - 0.15 * i) + haze * (0.3 - 0.1 * i)
        img = np.where(mask[..., None] & (yy <= 0.7)[..., None], shade, img)
    # The lake: the sky and ridges mirrored about the horizon, with ripples.
    lake_top = int(h * 0.66)
    for row in range(lake_top, h):
        k = row - lake_top
        src = max(0, lake_top - 1 - int(k * 0.9))
        shift = int(3 * math.sin(k * 0.8))
        line = np.roll(img[src], shift, axis=0)
        img[row] = line * 0.7 + np.array([10, 30, 60.0]) * 0.3
    img = np.clip(img, 0, 255).astype(np.uint8)
    im = Image.fromarray(img, "RGB")
    dr = ImageDraw.Draw(im)
    for cx, base_y, size in [(0.1, 0.75, 70), (0.18, 0.72, 50), (0.3, 0.74, 90), (0.9, 0.73, 80), (0.8, 0.71, 55)]:
        bx, by = int(cx * w), int(base_y * h)
        for tier in range(5):
            half = int(size * (0.18 + 0.1 * (4 - tier) * 0.8))
            top_y = by - size + tier * int(size * 0.18)
            dr.polygon([(bx, top_y), (bx - half, top_y + int(size * 0.3)), (bx + half, top_y + int(size * 0.3))], fill=(14, 22, 36))
        dr.rectangle((bx - 3, by - 6, bx + 3, by + 8), fill=(10, 14, 22))
    dr.text((16, h - 34), "exav example picture", font=font(20), fill=(250, 235, 210))
    return im, glow


def bounce_frames(n=24, w=192, h=144):
    frames = []
    for i in range(n):
        im = Image.new("RGB", (w, h))
        px = np.zeros((h, w, 3), np.uint8)
        gy = np.linspace(0, 1, h)[:, None]
        # Every pixel changes a little in every frame (the tint below), so
        # that encoders keep full frames: cjxl reads no cropped ones.
        pulse = 14 * math.sin(2 * math.pi * i / n)
        px[..., 0] = 20 + 40 * gy
        px[..., 1] = 40 + 60 * gy
        px[..., 2] = 90 + 120 * gy
        im = Image.fromarray(px, "RGB")
        d = ImageDraw.Draw(im)
        d.rectangle((0, h - 24, w, h), fill=(46, 120, 66))
        phase = i / n
        x = 20 + phase * (w - 40)
        y = h - 24 - 14 - abs(math.sin(math.pi * phase * 2)) * 80
        rx, ry = 14 * (1 + (0.3 if y > h - 42 else 0)), 14 * (1 - (0.3 if y > h - 42 else 0))
        d.ellipse((x - 12, h - 26, x + 12, h - 20), fill=(30, 80, 45))
        d.ellipse((x - rx, y - ry, x + rx, y + ry), fill=(240, 200, 40), outline=(160, 110, 10))
        d.text((6, 6), f"{i + 1}/{n}", font=font(14), fill=(255, 255, 255))
        tint = np.array(im).astype(int)
        tint[..., 0] += int(pulse)
        tint[..., 2] -= int(pulse)
        frames.append(Image.fromarray(np.clip(tint, 0, 255).astype(np.uint8), "RGB"))
    return frames


def png_path(im, name):
    p = os.path.join(WORK, name)
    im.save(p)
    return p


# --------------------------------------------------------------- fax page


def fax_page(w=1728, h=2200, number=1):
    """A fax cover sheet and a letter, black on white, at fax size."""
    im = Image.new("L", (w, h), 255)
    d = ImageDraw.Draw(im)
    d.rectangle((60, 60, w - 60, 200), outline=0, width=6)
    d.text((100, 85), "FACSIMILE TRANSMISSION", font=font(72), fill=0)
    rows = [("To:", "Records office, harbour authority"), ("From:", "exav example generator"),
            ("Date:", "1 January 2000 (a fixed date)"), ("Pages:", "3 including this one"), ("Re:", "Mooring register, east quay")]
    y = 260
    for k, v in rows:
        d.text((100, y), k, font=font(44), fill=0)
        d.text((330, y), v, font=font(44), fill=0)
        d.line((330, y + 56, w - 100, y + 56), fill=0, width=2)
        y += 96
    d.line((60, y + 20, w - 60, y + 20), fill=0, width=8)
    body = [
        "Dear colleagues,", "",
        "The register of moorings on the east quay is attached. Each berth has a",
        "number, a length in metres and the name of the vessel that holds it. Please",
        "check the entries against your own list and send back a corrected copy",
        "before the end of the month.", "",
        "Berths 1 to 12 are for visiting boats and are not let by the season.",
        "Berths 13 to 40 are let by the season; the fee is the same for every length.", "",
        "This page and the next are sent in the fine mode (204 by 196 dots to the",
        "inch). If anything is unreadable, ask for the page to be sent again.", "",
        "With thanks,",
    ]
    y += 70
    for line in body:
        d.text((100, y), line, font=font(40), fill=0)
        y += 62
    # A table of berths.
    y += 40
    rows = 5
    cols = [100, 330, 700, 1100, w - 100]
    for r in range(rows + 1):
        top = y + r * 70
        d.line((cols[0], top, cols[-1], top), fill=0, width=3 if r else 6)
        if r < rows:
            vals = ["Berth", "Length (m)", "Vessel", "Let by"] if r == 0 else [str(12 + number * r), f"{6 + (r * 7 + number) % 9}.{(r * 3) % 10}", ["Aurora", "Brise", "Calypso", "Dorade", "Etoile", "Fauvette", "Goeland"][(r + number) % 7], ["season", "week", "year"][r % 3]]
            for c, v in enumerate(vals):
                d.text((cols[c] + 12, top + 10), v, font=font(40), fill=0)
    for c in cols:
        d.line((c, y, c, y + rows * 70), fill=0, width=3)
    # A signature scribble, a stamp, and the page number.
    base = y + rows * 70
    pts = [(120 + i * 6, base + 110 + int(40 * math.sin(i * 0.5) * math.cos(i * 0.13))) for i in range(70)]
    d.line(pts, fill=0, width=5)
    d.ellipse((1150, base + 40, 1450, base + 240), outline=0, width=8)
    d.text((1190, base + 115), "RECEIVED", font=font(36), fill=0)
    d.text((100, h - 100), f"Page {number} of 3", font=font(40), fill=0)
    return im


# ------------------------------------------------------------------ encoders


def qoi_encode(arr):
    """QOI (qoiformat.org/qoi-specification.pdf) from an HxWx3 or HxWx4 uint8 array."""
    h, w, ch = arr.shape
    out_ = bytearray(b"qoif" + struct.pack(">IIBB", w, h, ch, 0))
    index = [(0, 0, 0, 0)] * 64
    prev = (0, 0, 0, 255)
    run = 0
    flat = arr.reshape(-1, ch)
    for i, px in enumerate(flat):
        px = (int(px[0]), int(px[1]), int(px[2]), int(px[3]) if ch == 4 else 255)
        if px == prev:
            run += 1
            if run == 62 or i == len(flat) - 1:
                out_.append(0xC0 | (run - 1))
                run = 0
            continue
        if run:
            out_.append(0xC0 | (run - 1))
            run = 0
        h_ = (px[0] * 3 + px[1] * 5 + px[2] * 7 + px[3] * 11) % 64
        if index[h_] == px:
            out_.append(h_)
        else:
            index[h_] = px
            if px[3] == prev[3]:
                dr, dg, db = (px[0] - prev[0] + 256) % 256, (px[1] - prev[1] + 256) % 256, (px[2] - prev[2] + 256) % 256
                sr, sg, sb = dr - 256 if dr > 127 else dr, dg - 256 if dg > 127 else dg, db - 256 if db > 127 else db
                if -2 <= sr <= 1 and -2 <= sg <= 1 and -2 <= sb <= 1:
                    out_.append(0x40 | (sr + 2) << 4 | (sg + 2) << 2 | (sb + 2))
                else:
                    drg, dbg = sr - sg, sb - sg
                    if -32 <= sg <= 31 and -8 <= drg <= 7 and -8 <= dbg <= 7:
                        out_.append(0x80 | (sg + 32))
                        out_.append((drg + 8) << 4 | (dbg + 8))
                    else:
                        out_ += bytes([0xFE, px[0], px[1], px[2]])
            else:
                out_ += bytes([0xFF, px[0], px[1], px[2], px[3]])
        prev = px
    out_ += b"\x00\x00\x00\x00\x00\x00\x00\x01"
    return bytes(out_)


def farbfeld(rgba8):
    h, w, _ = rgba8.shape
    wide = rgba8.astype(np.uint16) * 257
    return b"farbfeld" + struct.pack(">II", w, h) + wide.astype(">u2").tobytes()


def rgbe(linear):
    """Radiance RGBE bytes from an HxWx3 float array."""
    m = linear.max(axis=2)
    mant, ex = np.frexp(m)
    scale = np.where(m > 1e-32, mant * 256.0 / np.maximum(m, 1e-32), 0)
    px = np.zeros(linear.shape[:2] + (4,), np.uint8)
    px[..., :3] = np.clip(linear * scale[..., None], 0, 255).astype(np.uint8)
    px[..., 3] = np.where(m > 1e-32, ex + 128, 0).astype(np.uint8)
    return px


def hdr_file(px, rle):
    h, w, _ = px.shape
    data = bytearray(b"#?RADIANCE\n# written by exav's make-images.py\nFORMAT=32-bit_rle_rgbe\nEXPOSURE=1.0\n\n")
    data += f"-Y {h} +X {w}\n".encode()
    for row in px:
        if not rle:
            data += row.tobytes()
            continue
        data += bytes([2, 2, w >> 8, w & 255])
        for c in range(4):
            ch = row[:, c].tolist()
            i = 0
            while i < w:
                j = i
                while j < w and ch[j] == ch[i] and j - i < 127:
                    j += 1
                if j - i >= 4:
                    data += bytes([128 + j - i, ch[i]])
                    i = j
                else:
                    k = i
                    while k < w and k - i < 128 and not (k + 3 < w and ch[k] == ch[k + 1] == ch[k + 2] == ch[k + 3]):
                        k += 1
                    k = max(k, i + 1)
                    data += bytes([k - i]) + bytes(ch[i:k])
                    i = k
    return bytes(data)


def bc_blocks(arr, fmt):
    """Greatly simplified BC1 / BC3 encoder: endpoints are the block's
    darkest and brightest colours; indices are the nearest of four."""
    h, w, _ = arr.shape
    out_ = bytearray()

    def to565(c):
        return ((int(c[0]) >> 3) << 11) | ((int(c[1]) >> 2) << 5) | (int(c[2]) >> 3)

    def from565(v):
        return np.array([((v >> 11) & 31) * 255 // 31, ((v >> 5) & 63) * 255 // 63, (v & 31) * 255 // 31], float)

    for by in range(0, h, 4):
        for bx in range(0, w, 4):
            blk = arr[by:by + 4, bx:bx + 4].reshape(-1, arr.shape[2])
            rgb = blk[:, :3].astype(float)
            lum = rgb @ np.array([0.3, 0.59, 0.11])
            c0, c1 = rgb[lum.argmax()], rgb[lum.argmin()]
            e0, e1 = to565(c0), to565(c1)
            if e0 < e1:
                e0, e1 = e1, e0
            if fmt == "bc3":
                a = blk[:, 3].astype(int)
                a0, a1 = int(a.max()), int(a.min())
                if a0 == a1:
                    a_idx = [0] * 16
                else:
                    pal = [a0, a1] + [((6 - i) * a0 + i * a1) // 7 for i in range(1, 7)]
                    a_idx = [int(np.argmin([abs(v - p) for p in pal])) for v in a]
                bits = 0
                for i, v in enumerate(a_idx):
                    bits |= v << (3 * i)
                out_ += bytes([a0, a1]) + bits.to_bytes(6, "little")
            if e0 == e1:
                idx = [0] * 16
            else:
                p0, p1 = from565(e0), from565(e1)
                pal = [p0, p1, (2 * p0 + p1) / 3, (p0 + 2 * p1) / 3]
                idx = [int(np.argmin([np.sum((px - p) ** 2) for p in pal])) for px in rgb]
            bits = 0
            for i, v in enumerate(idx):
                bits |= v << (2 * i)
            out_ += struct.pack("<HHI", e0, e1, bits)
    return bytes(out_)


def dds_file(im, fmt):
    """DDS with a full mip chain. fmt: 'bc1' (DXT1) or 'bc3' (DXT5)."""
    w, h = im.size
    levels = []
    cur = im
    while True:
        levels.append(cur)
        if cur.size[0] <= 4 and cur.size[1] <= 4:
            break
        cur = cur.resize((max(4, cur.size[0] // 2), max(4, cur.size[1] // 2)), Image.LANCZOS)
    flags = 0x1 | 0x2 | 0x4 | 0x1000 | 0x20000 | 0x80000
    pf = struct.pack("<II4sIIIII", 32, 0x4, b"DXT1" if fmt == "bc1" else b"DXT5", 0, 0, 0, 0, 0)
    pitch = max(1, w // 4) * (8 if fmt == "bc1" else 16)
    head = b"DDS " + struct.pack("<7I", 124, flags, h, w, pitch, 0, len(levels)) + b"\0" * 44 + pf + struct.pack("<5I", 0x1000 | 0x400000 | 0x8, 0, 0, 0, 0)
    body = b"".join(bc_blocks(np.array(lv.convert("RGBA")), fmt) for lv in levels)
    return head + body


def bmp_rle8(im):
    """An 8-bit BMP with RLE8 compression (a palette picture)."""
    p = im.convert("P", palette=Image.ADAPTIVE, colors=64)
    w, h = p.size
    pal = p.getpalette()[: 64 * 3]
    rows = []
    px = np.array(p)
    for y in range(h - 1, -1, -1):
        row = px[y].tolist()
        enc = bytearray()
        i = 0
        while i < w:
            j = i
            while j < w and row[j] == row[i] and j - i < 255:
                j += 1
            n = j - i
            if n >= 2:
                enc += bytes([n, row[i]])
                i = j
            else:
                k = i + 1
                while k < w and k - i < 255 and (k + 1 >= w or row[k] != row[k + 1]):
                    k += 1
                n = k - i
                if n >= 3:
                    enc += bytes([0, n]) + bytes(row[i:k]) + (b"\0" if n % 2 else b"")
                else:
                    for v in row[i:k]:
                        enc += bytes([1, v])
                i = k
        enc += b"\x00\x00"
        rows.append(bytes(enc))
    data = b"".join(rows)[:-2] + b"\x00\x01"
    palette = b"".join(bytes([pal[i * 3 + 2], pal[i * 3 + 1], pal[i * 3], 0]) for i in range(64))
    off = 14 + 40 + len(palette)
    info = struct.pack("<IiiHHIIiiII", 40, w, h, 1, 8, 1, len(data), 2835, 2835, 64, 64)
    return b"BM" + struct.pack("<IHHI", off + len(data), 0, 0, off) + info + palette + data


def ico_legacy(src):
    """An ICO of BMP-coded images (16 and 32 pixels at 32 bits, 48 at 8 bits) with
    AND masks, and a 64-pixel one coded as PNG."""
    entries = []
    for size, bits in [(16, 32), (32, 32), (48, 8)]:
        im = src.resize((size, size), Image.LANCZOS).convert("RGBA")
        a = np.array(im)
        mask_rows = bytearray()
        row_bytes = ((size + 31) // 32) * 4
        for y in range(size - 1, -1, -1):
            bits_row = bytearray(row_bytes)
            for x in range(size):
                if a[y, x, 3] < 128:
                    bits_row[x // 8] |= 0x80 >> (x % 8)
            mask_rows += bits_row
        if bits == 32:
            pix = a[::-1][..., [2, 1, 0, 3]].tobytes()
            pal = b""
        else:
            p = im.convert("RGB").convert("P", palette=Image.ADAPTIVE, colors=256)
            pp = p.getpalette()[:768]
            pal = b"".join(bytes([pp[i * 3 + 2], pp[i * 3 + 1], pp[i * 3], 0]) for i in range(256))
            pix = b"".join(bytes(np.array(p)[y].tolist()) for y in range(size - 1, -1, -1))
        head = struct.pack("<IiiHHIIiiII", 40, size, size * 2, 1, bits, 0, len(pix) + len(mask_rows), 0, 0, 256 if bits == 8 else 0, 0)
        entries.append((size, bits, head + pal + pix + bytes(mask_rows)))
    buf = io.BytesIO()
    src.resize((64, 64), Image.LANCZOS).convert("RGBA").save(buf, "PNG")
    entries.append((64, 32, buf.getvalue()))
    out_ = struct.pack("<HHH", 0, 1, len(entries))
    off = 6 + 16 * len(entries)
    for size, bits, data in entries:
        out_ += struct.pack("<BBBBHHII", size, size, 0, 0, 1, bits, len(data), off)
        off += len(data)
    return out_ + b"".join(e[2] for e in entries)


def run(*cmd, **kw):
    subprocess.run(cmd, check=True, capture_output=True, **kw)


# ---------------------------------------------------------------------- main

img, glow = scene()
big, _ = scene(1024, 768)
exif_ifd = Image.Exif()
exif_ifd[0x010E] = "A dusk landscape drawn by exav's make-images.py"
exif_ifd[0x8298] = "CC0-1.0, exav project"
exif_ifd[0x0131] = "exav make-images.py"

# PNG
img.save(out("scene.png"), optimize=True)
rgba = img.convert("RGBA")
a = np.array(rgba)
yy, xx = np.mgrid[0 : a.shape[0], 0 : a.shape[1]]
a[..., 3] = np.clip(255 - np.hypot(xx - 256, yy - 192) * 1.15, 0, 255).astype(np.uint8)
Image.fromarray(a, "RGBA").save(out("scene-alpha.png"), optimize=True)
img.convert("P", palette=Image.ADAPTIVE, colors=32).save(out("scene-indexed.png"), optimize=True)
grey16 = (np.linspace(0, 65535, 256)[None, :] * np.ones((192, 1)) * (0.6 + 0.4 * np.sin(np.linspace(0, 12, 192))[:, None])).clip(0, 65535).astype(np.uint16)
Image.fromarray(grey16, "I;16").save(out("gradient-grey16.png"))
frames = bounce_frames()
frames[0].save(out("bounce.png"), save_all=True, append_images=frames[1:], duration=60, loop=0, optimize=False)

# JPEG
img.save(out("scene.jpg"), quality=88, subsampling=2, exif=exif_ifd.tobytes())
img.save(out("scene-progressive.jpg"), quality=85, progressive=True, optimize=True)
rot = img.transpose(Image.ROTATE_270)
e6 = Image.Exif()
e6[0x0112] = 6
e6[0x010E] = "Stored rotated, EXIF orientation 6: shown upright"
rot.save(out("scene-orientation6.jpg"), quality=85, exif=e6.tobytes())
img.convert("L").save(out("scene-grey.jpg"), quality=85)
img.convert("CMYK").save(out("scene-cmyk.jpg"), quality=85)

# GIF
frames[0].save(out("bounce.gif"), save_all=True, append_images=frames[1:], duration=60, loop=0, optimize=False)
img.convert("P", palette=Image.ADAPTIVE, colors=256, dither=Image.FLOYDSTEINBERG).save(out("scene.gif"), optimize=True)

# WebP
img.save(out("scene.webp"), quality=80, method=6)
rgba.save(out("scene-lossless.webp"), lossless=True, method=6)
Image.fromarray(a, "RGBA").save(out("scene-alpha.webp"), quality=85, method=6)
frames[0].save(out("bounce.webp"), save_all=True, append_images=frames[1:], duration=60, loop=0, quality=75, method=4)

# TIFF
dpi = (300, 300)
img.save(out("scene-lzw.tif"), compression="tiff_lzw", dpi=dpi)
img.save(out("scene-jpeg.tif"), compression="jpeg", quality=88, dpi=dpi)
img.resize((256, 192), Image.LANCZOS).convert("CMYK").save(out("scene-cmyk-packbits.tif"), compression="packbits", dpi=dpi)
# PackBits does not shrink a picture of smooth colours: the CMYK one is kept small.
Image.open(out("scene-cmyk-packbits.tif")).resize((128, 96), Image.LANCZOS).save(out("scene-cmyk-packbits.tif"), compression="packbits", dpi=dpi)
Image.fromarray(grey16, "I;16").save(out("gradient-grey16.tif"), compression="tiff_adobe_deflate")
pages = [img, img.resize((256, 192), Image.LANCZOS), img.resize((128, 96), Image.LANCZOS).convert("L")]
pages[0].save(out("scene-pages.tif"), save_all=True, append_images=pages[1:], compression="tiff_adobe_deflate", dpi=dpi)

# BMP
half = img.resize((160, 120), Image.LANCZOS)
half.save(out("scene-24.bmp"))
half.convert("P", palette=Image.ADAPTIVE, colors=256).save(out("scene-8.bmp"))
half.convert("RGBA").save(out("scene-32.bmp"))
img.convert("1").save(out("scene-1bit.bmp"))
with open(out("scene-rle8.bmp"), "wb") as f:
    f.write(bmp_rle8(img))

# ICO
icon = Image.new("RGBA", (256, 256), (0, 0, 0, 0))
d = ImageDraw.Draw(icon)
d.rounded_rectangle((12, 12, 244, 244), radius=48, fill=(32, 64, 128, 255))
d.ellipse((60, 60, 196, 196), fill=(250, 200, 50, 255))
d.polygon([(128, 20), (150, 100), (236, 128), (150, 156), (128, 236), (106, 156), (20, 128), (106, 100)], outline=(255, 255, 255, 255), width=8)
icon.save(out("icon.ico"), sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
with open(out("icon-legacy.ico"), "wb") as f:
    f.write(ico_legacy(icon))

# PNM
small = img.resize((256, 192), Image.LANCZOS)
sa = np.array(img.resize((128, 96), Image.LANCZOS))
with open(out("scene.ppm"), "wb") as f:
    f.write(b"P6\n# exav example\n128 96\n255\n" + sa.tobytes())
tiny = np.array(img.resize((48, 36), Image.LANCZOS))
with open(out("scene-ascii.ppm"), "w") as f:
    f.write("P3\n# an ASCII pixmap\n48 36\n255\n" + "\n".join(" ".join(str(int(v)) for v in row.reshape(-1)) for row in tiny) + "\n")
g = np.array(small.convert("L").resize((128, 96)))
g16 = (g.astype(np.uint16) * 257).astype(">u2")
with open(out("scene-grey16.pgm"), "wb") as f:
    f.write(b"P5\n128 96\n65535\n" + g16.tobytes())
bw = np.array(small.convert("1")) > 0
rows = []
for row in bw:
    rows.append(np.packbits(~row).tobytes())
with open(out("scene.pbm"), "wb") as f:
    f.write(b"P4\n256 192\n" + b"".join(rows))
al = np.array(img.resize((128, 96), Image.LANCZOS).convert("RGBA"))
al[..., 3] = np.clip(255 - np.hypot(np.arange(128)[None, :] - 64, np.arange(96)[:, None] - 48) * 3.6, 0, 255)
with open(out("scene-alpha.pam"), "wb") as f:
    f.write(b"P7\nWIDTH 128\nHEIGHT 96\nDEPTH 4\nMAXVAL 255\nTUPLTYPE RGB_ALPHA\nENDHDR\n" + al.tobytes())

# QOI, farbfeld, HDR, DDS
with open(out("scene.qoi"), "wb") as f:
    f.write(qoi_encode(np.array(img)))
with open(out("scene-alpha.qoi"), "wb") as f:
    f.write(qoi_encode(np.array(Image.fromarray(a, "RGBA").resize((192, 144), Image.LANCZOS))))
with open(out("scene.ff"), "wb") as f:
    f.write(farbfeld(np.array(Image.fromarray(a, "RGBA").resize((96, 72), Image.LANCZOS))))
srgb = np.array(img, float) / 255
lin = np.where(srgb <= 0.04045, srgb / 12.92, ((srgb + 0.055) / 1.055) ** 2.4)
lin = lin * (1 + 60 * glow[..., None] ** 2)
with open(out("sunset.hdr"), "wb") as f:
    f.write(hdr_file(rgbe(lin[::2, ::2]), True))
with open(out("sunset-flat.hdr"), "wb") as f:
    f.write(hdr_file(rgbe(lin[::4, ::4]), False))
with open(out("scene-bc1.dds"), "wb") as f:
    f.write(dds_file(img.resize((256, 192), Image.LANCZOS), "bc1"))
with open(out("scene-bc3.dds"), "wb") as f:
    f.write(dds_file(Image.fromarray(a, "RGBA").resize((256, 192), Image.LANCZOS), "bc3"))

# JPEG 2000
if tool("opj_compress"):
    src = png_path(img, "scene.png")
    srca = png_path(Image.fromarray(a, "RGBA"), "scene-alpha.png")
    srcg = png_path(img.convert("L"), "scene-grey.png")
    run("opj_compress", "-i", src, "-o", out("scene.jp2"), "-r", "16,8,4", "-n", "5", "-p", "RPCL", "-t", "256,256", "-SOP", "-EPH")
    run("opj_compress", "-i", src, "-o", out("scene.j2k"), "-r", "12", "-n", "4")
    run("opj_compress", "-i", srcg, "-o", out("scene-grey.jp2"), "-r", "10")
    run("opj_compress", "-i", srca, "-o", out("scene-alpha.jp2"), "-r", "10")

# JBIG2
page = fax_page(1728, 2200, 1).resize((1240, 1579), Image.LANCZOS).point(lambda v: 255 if v > 140 else 0).convert("1")
if tool("jbig2"):
    pb = os.path.join(WORK, "page.png")
    page.save(pb)
    for name, args in [("page-generic.jb2", []), ("page-symbol.jb2", ["-s"])]:
        with open(out(name), "wb") as f:
            subprocess.run(["jbig2", *args, pb], stdout=f, check=True, stderr=subprocess.DEVNULL)

# Fax TIFF (CCITT): Pillow writes the uncompressed bilevel page, tiffcp codes it.
if tool("tiffcp"):
    pages = []
    for n in (1, 2, 3):
        p = os.path.join(WORK, f"fax{n}.tif")
        fax_page(1728, 2200, n).convert("1").save(p, dpi=(204, 196))
        pages.append(p)
    # Group 3 is written to show what the viewer says about it: its TIFF decoder reads Group 4 only.
    for name, mode in [("fax-g4.tif", "g4"), ("fax-g3-1d.tif", "g3:1d")]:
        run("tiffcp", "-c", mode, "-r", "2200", pages[0], out(name))
    run("tiffcp", "-c", "g4", "-r", "2200", *pages, out("fax-g4-3pages.tif"))

# JPEG XL
if tool("cjxl"):
    src = png_path(img, "jxl-scene.png")
    srca = png_path(Image.fromarray(a, "RGBA"), "jxl-scene-alpha.png")
    gif = os.path.join(WORK, "bounce.gif")
    frames[0].save(gif, save_all=True, append_images=frames[1:], duration=60, loop=0)
    run("cjxl", src, out("scene-lossy.jxl"), "-d", "1.0", "-e", "7")
    run("cjxl", src, out("scene-lossless.jxl"), "-d", "0", "-e", "7")
    run("cjxl", srca, out("scene-alpha.jxl"), "-d", "0", "-e", "7")
    run("cjxl", gif, out("bounce.jxl"), "-d", "1.0", "-e", "6")

shutil.rmtree(WORK)
