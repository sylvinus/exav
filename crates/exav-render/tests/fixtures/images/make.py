#!/usr/bin/env python3
"""Writes the JPEG 2000, JBIG2 and CCITT fixtures of tests/jpeg2000_jbig2.rs.

Each source picture is drawn here with Pillow and saved as PNG; the encoders
are independent of the decoders under test and run as black boxes:
opj_compress (OpenJPEG, Debian's libopenjp2-tools) in its default lossless
mode (and its opj_decompress for one decode at half the size), jbig2 (jbig2enc, Debian's jbig2), and libtiff's tiffcp and Pillow for
the CCITT strips (bilevel.<mode>, the strip of a one-strip TIFF). The
random-access JBIG2 file is the sequential one with its segment headers
moved before their data (T.88 Annex D.2), done below.

    python3 crates/exav-render/tests/fixtures/images/make.py
"""
import os
import shutil
import struct
import subprocess
import tempfile

from PIL import Image, ImageDraw, ImageOps

HERE = os.path.dirname(os.path.abspath(__file__))
# Written on local disk, then copied here: a tool reading a file just written
# to a shared folder may see it incomplete.
WORK = tempfile.mkdtemp()


def out(name):
    return os.path.join(WORK, name)


def pattern(mode, w, h):
    n = len(Image.new(mode, (1, 1)).getbands())
    im = Image.new(mode, (w, h))
    px = []
    for y in range(h):
        for x in range(w):
            v = [(x * 13 + y * 7 + c * 50 + (x * y) % 11) % 256 for c in range(n)]
            px.append(tuple(v) if n > 1 else v[0])
    im.putdata(px)
    return im


def opj(src, dst, *options):
    # Small pictures take fewer than the default six resolutions.
    subprocess.run(["opj_compress", "-n", "3", *options, "-i", out(src), "-o", out(dst)], check=True, capture_output=True)


pattern("RGB", 37, 23).save(out("rgb.png"))
opj("rgb.png", "rgb.jp2")
opj("rgb.png", "rgb.j2k")
# An image area offset on the reference grid; and a subsampled component in
# several tiles.
opj("rgb.png", "rgb-offset.j2k", "-d", "40,30")
pattern("L", 29, 17).save(out("grey.png"))
opj("grey.png", "grey.j2k")
opj("grey.png", "grey-subsampled-tiles.j2k", "-s", "2,2", "-t", "16,16")
# Tiles: a last column one sample wide, empty at half the size; and tiles
# of 16, with OpenJPEG's decode at half the size.
pattern("RGB", 38, 23).save(out("rgb38.png"))
opj("rgb38.png", "rgb38-narrow-tile.j2k", "-t", "37,23")
opj("rgb38.png", "rgb38-tiles.j2k", "-t", "16,16")
subprocess.run(["opj_decompress", "-r", "1", "-i", out("rgb38-tiles.j2k"), "-o", out("rgb38-tiles-r1.png")], check=True, capture_output=True)
pattern("RGBA", 21, 13).save(out("rgba.png"))
opj("rgba.png", "rgba.jp2")

bilevel = Image.new("1", (83, 37), 1)
d = ImageDraw.Draw(bilevel)
d.text((2, 1), "exav JBIG2", fill=0)
d.text((2, 13), "abc abc abc", fill=0)
d.rectangle((70, 2, 80, 30), fill=0)
d.line((0, 36, 82, 25), fill=0)
bilevel.save(out("bilevel.png"))
with open(out("generic.jb2"), "wb") as f:
    subprocess.run(["jbig2", out("bilevel.png")], stdout=f, check=True)
with open(out("symbol.jb2"), "wb") as f:
    subprocess.run(["jbig2", "-s", out("bilevel.png")], stdout=f, check=True)


def random_access(sequential):
    """The same segments, every header first, then every data part."""
    assert sequential[8] & 1, "a sequential file"
    at = 13 if not sequential[8] & 2 else 9
    headers, datas = [], []
    while at < len(sequential):
        start = at
        number = struct.unpack(">I", sequential[at:at + 4])[0]
        flags = sequential[at + 4]
        at += 5
        count = sequential[at] >> 5
        if count == 7:
            count = struct.unpack(">I", sequential[at:at + 4])[0] & 0x1FFFFFFF
            at += 4 + (count + 8) // 8
        else:
            at += 1
        at += count * (1 if number <= 256 else 2 if number <= 65536 else 4)
        at += 4 if flags & 0x40 else 1
        length = struct.unpack(">I", sequential[at:at + 4])[0]
        at += 4
        headers.append(sequential[start:at])
        datas.append(sequential[at:at + length])
        at += length
    return sequential[:8] + bytes([sequential[8] & ~1]) + sequential[9:13] + b"".join(headers) + b"".join(datas)


with open(out("generic.jb2"), "rb") as f:
    seq = f.read()
with open(out("generic-random.jb2"), "wb") as f:
    f.write(random_access(seq))


def strip(tif):
    """The one strip of a TIFF."""
    with open(tif, "rb") as f:
        b = f.read()
    e = "<" if b[:2] == b"II" else ">"
    ifd = struct.unpack(e + "I", b[4:8])[0]
    tags = {}
    for i in range(struct.unpack(e + "H", b[ifd:ifd + 2])[0]):
        tag, kind, count, value = struct.unpack(e + "HHII", b[ifd + 2 + 12 * i:ifd + 14 + 12 * i])
        if kind == 3 and count == 1:
            value = value & 0xFFFF if e == "<" else value >> 16
        tags[tag] = value
    return b[tags[273]:tags[273] + tags[279]]


# Fax codes call 0 white; Pillow writes a bilevel TIFF with 0 black. The
# picture is inverted first, so that the codes' white is the picture's.
tmp = out("tmp.tif")
inverted = ImageOps.invert(bilevel.convert("L")).convert("1")
inverted.save(tmp)
for mode, compression in [("g4", "g4"), ("g3-1d", "g3:1d"), ("g3-2d", "g3:2d"), ("g3-fill", "g3:1d:fill")]:
    coded = out("tmp-coded.tif")
    subprocess.run(["tiffcp", "-c", compression, "-r", "100000", tmp, coded], check=True)
    with open(out(f"bilevel.{mode}"), "wb") as f:
        f.write(strip(coded))
    os.remove(coded)
# Modified Huffman with each row byte-aligned and no EOL (TIFF compression 2).
inverted.save(tmp, compression="tiff_ccitt", tiffinfo={278: bilevel.height})
with open(out("bilevel.rle"), "wb") as f:
    f.write(strip(tmp))
os.remove(tmp)

for name in os.listdir(WORK):
    shutil.copy(out(name), os.path.join(HERE, name))
shutil.rmtree(WORK)
