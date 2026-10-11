#!/usr/bin/env python3
"""Writes the PDFs (and their image streams) on which this package's
JPXDecode, JBIG2Decode and CCITTFaxDecode decoders are compared with pdf.js's
own (e2e/pdf-decoders.spec.ts, ts/pdf/decoders.test.ts).

The pictures are drawn here with Pillow; the encoders run as black boxes:
opj_compress (OpenJPEG's, Debian's libopenjp2-tools), jbig2 (jbig2enc,
Debian's jbig2), libtiff's tiffcp and Pillow for the CCITT strips. JP2 files
that need boxes opj_compress does not write (a palette, CMYK, sYCC) are its
codestreams in boxes written below. Each PDF is one page showing one image
across it, written below too.

    python3 crates/exav-viewer/e2e/fixtures/pdf-images/make.py
"""
import json
import math
import os
import struct
import shutil
import subprocess
import tempfile
import zlib

from PIL import Image, ImageCms, ImageDraw, ImageOps

HERE = os.path.dirname(os.path.abspath(__file__))
# Intermediate files on local disk: a tool reading a file just written to a
# shared folder may see it incomplete.
TMP = tempfile.mkdtemp()


def tmp(name):
    return os.path.join(TMP, name)


def run(*args, **kw):
    r = subprocess.run(args, **kw)
    if r.returncode:
        raise SystemExit(f"{' '.join(args)} failed: {r.stdout!r} {r.stderr!r}")


# Pictures --------------------------------------------------------------------

W, H = 48, 32


def photo(mode):
    """Smooth gradients and an edge, per channel."""
    bands = len(Image.new(mode, (1, 1)).getbands())
    im = Image.new(mode, (W, H))
    px = []
    for y in range(H):
        for x in range(W):
            v = [
                int(127 + 120 * math.sin(x / (5.0 + c) + y / 7.0 + c)) if (x + c * 5) % 23 < 19 else 30 * c
                for c in range(bands)
            ]
            px.append(tuple(v) if bands > 1 else v[0])
    im.putdata(px)
    return im


def text(w, h):
    im = Image.new("1", (w, h), 1)
    d = ImageDraw.Draw(im)
    for i, row in enumerate(range(1, h - 10, 12)):
        d.text((2 + i * 3, row), "exav decodes %d" % (i * 7), fill=0)
    d.rectangle((w - 14, 3, w - 4, h // 2), fill=0)
    d.line((0, h - 1, w - 1, h // 2), fill=0)
    return im


def opj(png, out, *extra):
    run("opj_compress", "-n", "3", "-i", png, "-o", out, *extra, capture_output=True)
    with open(out, "rb") as f:
        return f.read()


def jp2_boxes(codestream, n, colr=None, extra=b""):
    """A JP2 file around a codestream, with a colour specification and other
    header boxes."""

    def box(kind, body):
        return struct.pack(">I4s", 8 + len(body), kind) + body

    siz = codestream.index(b"\xff\x51")
    xs, ys = struct.unpack(">II", codestream[siz + 6:siz + 14])
    ihdr = box(b"ihdr", struct.pack(">IIHBBBB", ys, xs, n, 7, 7, 0, 0))
    c = box(b"colr", struct.pack(">BBBI", 1, 0, 0, colr)) if colr is not None else b""
    return (box(b"jP  ", b"\r\n\x87\n") + box(b"ftyp", b"jp2 \0\0\0\0jp2 ") +
            box(b"jp2h", ihdr + c + extra) + box(b"jp2c", codestream))


streams = {}


def stream(name, data):
    streams[name] = data
    with open(os.path.join(HERE, name), "wb") as f:
        f.write(data)
    return name


for mode in ["RGB", "L", "RGBA", "LA"]:
    photo(mode).save(tmp(f"{mode}.png"))
stream("rgb.jp2", opj(tmp("RGB.png"), tmp("rgb.jp2")))
stream("grey.j2k", opj(tmp("L.png"), tmp("grey.j2k")))
stream("grey.jp2", opj(tmp("L.png"), tmp("grey.jp2")))
stream("rgba.jp2", opj(tmp("RGBA.png"), tmp("rgba.jp2")))
stream("greya.jp2", opj(tmp("LA.png"), tmp("greya.jp2")))
# Lossy, with the irreversible wavelet.
stream("lossy.jp2", opj(tmp("RGB.png"), tmp("lossy.jp2"), "-I", "-r", "5"))
# Four components, no component transform: CMYK. A PAM (opj_compress's raw
# input fails one run in a few).
planes = [list(photo("L").point(lambda p, c=c: (p * (c + 1) * 37) % 256).getdata()) for c in range(4)]
with open(tmp("cmyk.pam"), "wb") as f:
    f.write(f"P7\nWIDTH {W}\nHEIGHT {H}\nDEPTH 4\nMAXVAL 255\nTUPLTYPE RGB_ALPHA\nENDHDR\n".encode())
    f.write(bytes(planes[c][i] for i in range(W * H) for c in range(4)))
cmyk_cs = opj(tmp("cmyk.pam"), tmp("cmyk.j2k"), "-mct", "0")
stream("cmyk.jp2", jp2_boxes(cmyk_cs, 4, colr=12))
# Three components declared sYCC, converted to RGB for display.
rgb_cs = opj(tmp("RGB.png"), tmp("rgb.j2k"), "-mct", "0")
stream("sycc.jp2", jp2_boxes(rgb_cs, 3, colr=18))
# 4-bit grey: a PGM whose largest value is 15.
with open(tmp("g4.pgm"), "wb") as f:
    f.write(f"P5\n{W} {H}\n15\n".encode() + bytes(p >> 4 for p in photo("L").getdata()))
stream("grey4.j2k", opj(tmp("g4.pgm"), tmp("grey4.j2k")))
# Palette indices, and the palette as a pclr box mapping them to RGB.
palette = [((i * 37) % 256, (i * 91) % 256, (255 - i) % 256) for i in range(256)]
indices_cs = opj(tmp("L.png"), tmp("indices.j2k"))
pclr = struct.pack(">HB", 256, 3) + bytes([7, 7, 7]) + bytes(v for e in palette for v in e)
cmap = b"".join(struct.pack(">HBB", 0, 1, c) for c in range(3))
stream("palette.jp2", jp2_boxes(indices_cs, 1, colr=16,
                                extra=struct.pack(">I4s", 8 + len(pclr), b"pclr") + pclr +
                                struct.pack(">I4s", 8 + len(cmap), b"cmap") + cmap))

page = text(120, 64)
page.save(tmp("text.png"))
with open(tmp("generic.jbig2"), "wb") as f:
    run("jbig2", "-p", tmp("text.png"), stdout=f)
with open(tmp("tpgd.jbig2"), "wb") as f:
    run("jbig2", "-p", "-d", tmp("text.png"), stdout=f)
run("jbig2", "-s", "-p", "-b", tmp("symbol"), tmp("text.png"))
for name, src in [("generic.jbig2", tmp("generic.jbig2")), ("tpgd.jbig2", tmp("tpgd.jbig2")),
                  ("symbol.jbig2", tmp("symbol.0000")), ("symbol-globals.jbig2", tmp("symbol.sym"))]:
    with open(src, "rb") as f:
        stream(name, f.read())


def strip(tif):
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


# Fax codes call 0 white, Pillow's bilevel TIFF 0 black: inverted first.
ImageOps.invert(page.convert("L")).convert("1").save(tmp("fax.tif"))
for mode, compression in [("g4", "g4"), ("g3-1d", "g3:1d"), ("g3-2d", "g3:2d"), ("g3-fill", "g3:1d:fill")]:
    run("tiffcp", "-c", compression, "-r", "100000", tmp("fax.tif"), tmp(f"{mode}.tif"))
    stream(f"{mode}.ccitt", strip(tmp(f"{mode}.tif")))
ImageOps.invert(page.convert("L")).convert("1").save(tmp("rle.tif"), compression="tiff_ccitt", tiffinfo={278: page.height})
stream("rle.ccitt", strip(tmp("rle.tif")))

# An sRGB ICC profile, for an ICCBased image: pdf.js converts it with qcms.
icc = ImageCms.ImageCmsProfile(ImageCms.createProfile("sRGB")).tobytes()
# Without its creation time and profile ID (zero: not computed), so that
# every run writes the same file.
icc = icc[:24] + bytes(12) + icc[36:84] + bytes(16) + icc[100:]

# PDFs ------------------------------------------------------------------------


def pdf(name, image_dict, data, extra_objects=()):
    """One page, 4 points a pixel, showing the image. `image_dict` may refer
    to objects 6 and up, given in `extra_objects` (dictionary, data)."""
    w, h = image_dict["Width"], image_dict["Height"]
    objects = []

    def obj(body):
        objects.append(body)

    def stream_obj(d, data):
        return f"<< {d} /Length {len(data)} >>\nstream\n".encode() + data + b"\nendstream"

    content = f"q {w * 4} 0 0 {h * 4} 0 0 cm /Im0 Do Q".encode()
    entries = " ".join(f"/{k} {v}" for k, v in image_dict.items())
    obj(b"<< /Type /Catalog /Pages 2 0 R >>")
    obj(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    obj(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {w * 4} {h * 4}] /Resources << /XObject << /Im0 5 0 R >> >> /Contents 4 0 R >>".encode())
    obj(stream_obj("", content))
    obj(stream_obj(f"/Type /XObject /Subtype /Image {entries}", data))
    for d, data in extra_objects:
        obj(stream_obj(d, data))
    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, body in enumerate(objects, 1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    for o in offsets:
        out += f"{o:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    with open(os.path.join(HERE, name), "wb") as f:
        f.write(out)


cases = []


def case(name, stream_name, d, decode, extra_objects=()):
    """A PDF, and how pdf.js asks for its image (`decode`)."""
    pdf(f"{name}.pdf", d, streams[stream_name], extra_objects)
    cases.append({"pdf": f"{name}.pdf", "stream": stream_name, **decode})


def jpx(name, stream_name, cs=None, smask=False, nc=0, indexed=False):
    d = {"Width": W, "Height": H, "BitsPerComponent": 8, "Filter": "/JPXDecode"}
    if cs:
        d["ColorSpace"] = cs
    if smask:
        d["SMaskInData"] = 1
    case(name, stream_name, d, {"filter": "jpx", "numComponents": nc, "isIndexedColormap": indexed, "smaskInData": smask})


jpx("jpx-rgb", "rgb.jp2")
jpx("jpx-rgb-devicergb", "rgb.jp2", "/DeviceRGB", nc=3)
jpx("jpx-grey-devicegray", "grey.j2k", "/DeviceGray", nc=1)
jpx("jpx-grey", "grey.jp2")
jpx("jpx-grey4", "grey4.j2k", "/DeviceGray", nc=1)
jpx("jpx-cmyk-devicecmyk", "cmyk.jp2", "/DeviceCMYK", nc=4)
jpx("jpx-cmyk", "cmyk.jp2")
jpx("jpx-sycc", "sycc.jp2")
jpx("jpx-rgba-smaskindata", "rgba.jp2", smask=True)
jpx("jpx-greya-smaskindata", "greya.jp2", smask=True)
lookup = "".join(f"{r:02x}{g:02x}{b:02x}" for r, g, b in palette)
jpx("jpx-indexed", "palette.jp2", f"[/Indexed /DeviceRGB 255 <{lookup}>]", nc=1, indexed=True)
jpx("jpx-palette", "palette.jp2")
jpx("jpx-lossy", "lossy.jp2")

TW, TH = page.size


def bilevel(name, stream_name, d, decode, extra_objects=()):
    full = {"Width": TW, "Height": TH, "BitsPerComponent": 1, "ColorSpace": "/DeviceGray", **d}
    case(name, stream_name, full, {"width": TW, "height": TH, **decode}, extra_objects)


bilevel("jbig2-generic", "generic.jbig2", {"Filter": "/JBIG2Decode"}, {"filter": "jbig2"})
bilevel("jbig2-tpgd", "tpgd.jbig2", {"Filter": "/JBIG2Decode"}, {"filter": "jbig2"})
bilevel("jbig2-symbol", "symbol.jbig2", {"Filter": "/JBIG2Decode", "DecodeParms": "<< /JBIG2Globals 6 0 R >>"},
        {"filter": "jbig2", "globals": "symbol-globals.jbig2"}, [("", streams["symbol-globals.jbig2"])])


def ccitt(name, stream_name, k, eol=False, align=False, black_is_1=False):
    parms = f"<< /K {k} /Columns {TW} /Rows {TH} /EndOfLine {'true' if eol else 'false'} /EncodedByteAlign {'true' if align else 'false'} /BlackIs1 {'true' if black_is_1 else 'false'} >>"
    bilevel(name, stream_name, {"Filter": "/CCITTFaxDecode", "DecodeParms": parms},
            {"filter": "ccitt", "K": k, "EndOfLine": eol, "EncodedByteAlign": align, "BlackIs1": black_is_1, "Columns": TW, "Rows": TH})


ccitt("ccitt-g4", "g4.ccitt", -1)
ccitt("ccitt-g4-blackis1", "g4.ccitt", -1, black_is_1=True)
ccitt("ccitt-g3-1d", "g3-1d.ccitt", 0, eol=True)
ccitt("ccitt-g3-2d", "g3-2d.ccitt", 1, eol=True)
ccitt("ccitt-g3-fill", "g3-fill.ccitt", 0, eol=True, align=True)
ccitt("ccitt-rle", "rle.ccitt", 0, align=True)

# Not decoded by either decoder under test: an ICCBased image, to see pdf.js
# load its ICC engine from the same directory.
rgb = photo("RGB").tobytes()
pdf("icc.pdf", {"Width": W, "Height": H, "BitsPerComponent": 8, "ColorSpace": "[/ICCBased 6 0 R]", "Filter": "/FlateDecode"},
    zlib.compress(rgb), [("/N 3", icc)])

with open(os.path.join(HERE, "cases.json"), "w") as f:
    json.dump(cases, f, indent=1)
    f.write("\n")
shutil.rmtree(TMP)
