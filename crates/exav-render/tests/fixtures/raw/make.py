#!/usr/bin/env python3
"""Writes the synthetic camera RAW files of tests/raw.rs.

No camera file is involved: each is a container of one family laid out as
that family's files are (TIFF 6.0 directories for DNG, CR2, NEF, ARW, PEF and
the other TIFF/EP files, an ISO base media file for CR3, a header and a JPEG
for RAF, and so on), holding small JPEG previews that Pillow encodes, a block
of bytes standing for the sensor data, and sometimes a lossless JPEG stream
(what real sensor data is compressed with). Every preview is four colour
quadrants, so that the tests can tell how a decoder turned it.

    python3 crates/exav-render/tests/fixtures/raw/make.py
"""
import io
import os
import struct

from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))

RED, GREEN, BLUE, YELLOW = (255, 0, 0), (0, 255, 0), (0, 0, 255), (255, 255, 0)

# TIFF field types.
BYTE, ASCII, SHORT, LONG, UNDEFINED, IFD = 1, 2, 3, 4, 7, 13


def quadrants(w, h):
    """Top left red, top right green, bottom left blue, bottom right yellow."""
    im = Image.new("RGB", (w, h))
    for y in range(h):
        for x in range(w):
            im.putpixel((x, y), [[RED, GREEN], [BLUE, YELLOW]][y * 2 // h][x * 2 // w])
    return im


def jpeg(w, h, orientation=None, grey=False):
    """A baseline JPEG of the four quadrants (4:4:4), with its own Exif
    orientation when one is given."""
    im = quadrants(w, h)
    if grey:
        im = im.convert("L")
    kw = {"quality": 95, "subsampling": 0} if not grey else {"quality": 95}
    if orientation:
        exif = Image.Exif()
        exif[0x112] = orientation
        kw["exif"] = exif.tobytes()
    out = io.BytesIO()
    im.save(out, "JPEG", **kw)
    return out.getvalue()


def progressive_jpeg(w, h):
    out = io.BytesIO()
    quadrants(w, h).save(out, "JPEG", quality=95, subsampling=0, progressive=True)
    return out.getvalue()


def rgb_samples(w, h, wide=None):
    """The quadrants as interleaved 8-bit RGB, or 16-bit (`wide` is the byte
    order) with the sample in the high byte."""
    im = quadrants(w, h)
    raw = im.tobytes()
    if wide is None:
        return raw
    out = bytearray()
    for v in raw:
        out += struct.pack(wide + "H", v << 8 | 0x33)
    return bytes(out)


def lossless_jpeg(w, h):
    """A lossless JPEG stream (SOF3), as the sensor data of a DNG or a CR2
    is: well formed up to its scan, which no decoder of previews reads."""
    return (
        b"\xff\xd8\xff\xc3\x00\x0b\x08" + struct.pack(">HH", h, w) + b"\x01\x01\x11\x00"
        + b"\xff\xc4\x00\x15\x00" + bytes([0, 1] + [0] * 14) + b"\x00\x01"
        + b"\xff\xda\x00\x08\x01\x01\x00\x01\x00\x00"
        + bytes((i * 37) % 251 for i in range(300)).replace(b"\xff", b"\xfe")
        + b"\xff\xd9"
    )


class Buf:
    """A TIFF being laid out: the header, then whatever is allocated."""

    def __init__(self, le, magic=42, header=b""):
        self.e = "<" if le else ">"
        self.data = bytearray(b"II" if le else b"MM")
        self.data += struct.pack(self.e + "H", magic) + b"\0\0\0\0" + header

    def alloc(self, payload, align=2):
        while len(self.data) % align:
            self.data.append(0)
        at = len(self.data)
        self.data += payload
        return at

    def entry(self, tag, typ, values):
        e = self.e
        if typ in (ASCII, UNDEFINED, BYTE):
            payload = bytes(values) if not isinstance(values, str) else values.encode() + b"\0"
            count = len(payload)
        else:
            fmt = {SHORT: "H", LONG: "L", IFD: "L"}[typ]
            values = values if isinstance(values, (list, tuple)) else [values]
            payload = b"".join(struct.pack(e + fmt, v) for v in values)
            count = len(values)
        return (tag, typ, count, payload)

    def ifd(self, entries, next_ifd=0):
        e = self.e
        entries = sorted(entries, key=lambda t: t[0])
        out = struct.pack(e + "H", len(entries))
        for tag, typ, count, payload in entries:
            if len(payload) <= 4:
                field = payload.ljust(4, b"\0")
            else:
                field = struct.pack(e + "L", self.alloc(payload))
            out += struct.pack(e + "HHL", tag, typ, count) + field
        out += struct.pack(e + "L", next_ifd)
        return self.alloc(out)

    def finish(self, first_ifd):
        self.data[4:8] = struct.pack(self.e + "L", first_ifd)
        return bytes(self.data)


def picture(b, w, h, strips=None, samples=None, bits=8, orientation=None, subfile=None, compression=1, extra=()):
    """The entries of a directory that holds a picture: JPEG (`strips` is the
    JPEG bytes, one strip, compression 7) or `samples` (uncompressed unless
    `compression` says another, which makes them bytes no reader here
    understands)."""
    t = b.entry
    es = [t(0x100, LONG, w), t(0x101, LONG, h)]
    if orientation is not None:
        es.append(t(0x112, SHORT, orientation))
    if subfile is not None:
        es.append(t(0xFE, LONG, subfile))
    if strips is not None:
        at = b.alloc(strips)
        es += [t(0x103, SHORT, 7), t(0x106, SHORT, 6), t(0x111, LONG, at), t(0x117, LONG, len(strips)),
               t(0x115, SHORT, 3), t(0x116, LONG, h)]
    else:
        at = b.alloc(samples)
        es += [t(0x103, SHORT, compression), t(0x106, SHORT, 2), t(0x111, LONG, at),
               t(0x117, LONG, len(samples)), t(0x115, SHORT, 3), t(0x102, SHORT, [bits] * 3),
               t(0x116, LONG, h), t(0x11C, SHORT, 1)]
    return es + list(extra)


def sensor(b, w, h, compression=1, photometric=32803, data=None, cfa=True, extra=()):
    """The entries of a directory of sensor data: a colour filter array
    (photometric 32803 and the CFA tags) or, without `cfa`, only what the
    other arguments say."""
    t = b.entry
    data = data if data is not None else bytes((i * 7) % 253 for i in range(2000))
    at = b.alloc(data)
    es = [t(0xFE, LONG, 0), t(0x100, LONG, w), t(0x101, LONG, h), t(0x102, SHORT, 16),
          t(0x103, SHORT, compression), t(0x111, LONG, at), t(0x117, LONG, len(data)), t(0x115, SHORT, 1)]
    if photometric is not None:
        es.append(t(0x106, SHORT, photometric))
    if cfa:
        es += [t(0x828D, SHORT, [2, 2]), t(0x828E, BYTE, [0, 1, 1, 2])]
    return es + list(extra)


def write(name, data):
    with open(os.path.join(HERE, name), "wb") as f:
        f.write(data)


# Adobe DNG: the first directory a small uncompressed preview, a SubIFD of
# sensor data (lossless JPEG) and a SubIFD of a JPEG preview.
b = Buf(True)
t = b.entry
raw = sensor(b, 64, 48, compression=7, data=lossless_jpeg(64, 48))
sub_raw = b.ifd(raw)
sub_jpeg = b.ifd(picture(b, 64, 48, strips=jpeg(64, 48), subfile=1))
ifd0 = b.ifd(picture(b, 16, 12, samples=rgb_samples(16, 12), subfile=1, extra=[
    t(0xC612, BYTE, [1, 4, 0, 0]), t(0x14A, IFD, [sub_raw, sub_jpeg]), t(0x10F, ASCII, "Exav")]))
write("preview-jpeg.dng", b.finish(ifd0))

# A DNG whose only previews are uncompressed RGB (the first directory's, 16
# by 12, and a SubIFD's, 32 by 24), turned by orientation 6.
b = Buf(False)
t = b.entry
sub_raw = b.ifd(sensor(b, 64, 48))
sub_rgb = b.ifd(picture(b, 32, 24, samples=rgb_samples(32, 24), subfile=1, orientation=6))
ifd0 = b.ifd(picture(b, 16, 12, samples=rgb_samples(16, 12), subfile=1, orientation=6, extra=[
    t(0xC612, BYTE, [1, 4, 0, 0]), t(0x14A, IFD, [sub_raw, sub_rgb])]))
write("preview-rgb.dng", b.finish(ifd0))

# A DNG (grey preview, 8-bit): the picture of a monochrome camera.
b = Buf(True)
t = b.entry
grey = quadrants(16, 12).convert("L").tobytes()
es = [t(0x100, LONG, 16), t(0x101, LONG, 12), t(0xFE, LONG, 1), t(0x103, SHORT, 1), t(0x106, SHORT, 1),
      t(0x102, SHORT, 8), t(0x115, SHORT, 1), t(0x111, LONG, b.alloc(grey)), t(0x117, LONG, len(grey)),
      t(0xC612, BYTE, [1, 4, 0, 0])]
write("preview-grey.dng", b.finish(b.ifd(es)))

# A DNG with no preview: the first directory is the sensor data.
b = Buf(True)
t = b.entry
write("no-preview.dng", b.finish(b.ifd(sensor(b, 64, 48, extra=[t(0xC612, BYTE, [1, 4, 0, 0])]))))

# A lossy DNG: its sensor data is a baseline JPEG, larger than the preview,
# in a directory of linear raw (photometric 34892).
b = Buf(True)
t = b.entry
lossy = b.ifd(sensor(b, 128, 96, compression=34892, photometric=34892, data=jpeg(128, 96)))
ifd0 = b.ifd(picture(b, 48, 32, strips=jpeg(48, 32), subfile=1, extra=[
    t(0xC612, BYTE, [1, 4, 0, 0]), t(0x14A, IFD, [lossy])]))
write("lossy-linear.dng", b.finish(ifd0))

# A DNG whose preview is progressive.
b = Buf(True)
t = b.entry
ifd0 = b.ifd(picture(b, 48, 32, strips=progressive_jpeg(48, 32), subfile=1, extra=[
    t(0xC612, BYTE, [1, 4, 0, 0]), t(0x14A, IFD, [b.ifd(sensor(b, 64, 48))])]))
write("progressive.dng", b.finish(ifd0))

# A DNG with an orientation on its first directory and another on its JPEG.
b = Buf(True)
t = b.entry
ifd0 = b.ifd(picture(b, 48, 32, strips=jpeg(48, 32, orientation=6), subfile=1, orientation=3, extra=[
    t(0xC612, BYTE, [1, 4, 0, 0]), t(0x14A, IFD, [b.ifd(sensor(b, 64, 48))])]))
write("orientation-own.dng", b.finish(ifd0))

# Canon CR2: "CR" and the version after the header, IFD0 the full-size JPEG
# in a strip, IFD1 the thumbnail (JPEGInterchangeFormat), IFD2 uncompressed
# RGB, IFD3 the sensor data as a lossless JPEG.
b = Buf(True, header=b"CR\x02\x00" + b"\0\0\0\0")
t = b.entry
raw = lossless_jpeg(64, 48)
ifd3 = b.ifd([t(0x103, SHORT, 6), t(0x111, LONG, b.alloc(raw)), t(0x117, LONG, len(raw))])
rgb = rgb_samples(32, 24)
ifd2 = b.ifd(picture(b, 32, 24, samples=rgb), next_ifd=ifd3)
thumb = jpeg(16, 12)
at = b.alloc(thumb)
ifd1 = b.ifd([t(0x103, SHORT, 6), t(0x201, LONG, at), t(0x202, LONG, len(thumb))], next_ifd=ifd2)
big = jpeg(96, 64)
at = b.alloc(big)
ifd0 = b.ifd([t(0x100, LONG, 96), t(0x101, LONG, 64), t(0x103, SHORT, 6), t(0x111, LONG, at),
              t(0x117, LONG, len(big)), t(0x112, SHORT, 1), t(0x10F, ASCII, "Canon")], next_ifd=ifd1)
write("canon.cr2", b.finish(ifd0))

# Nikon NEF (big-endian): IFD0 a small RGB preview, a SubIFD of JPEG
# (JPEGInterchangeFormat), a SubIFD of sensor data in Nikon's compression.
b = Buf(False)
t = b.entry
nef_raw = b.ifd(sensor(b, 64, 48, compression=34713))
jp = jpeg(80, 48)
at = b.alloc(jp)
nef_jpeg = b.ifd([t(0xFE, LONG, 1), t(0x103, SHORT, 6), t(0x201, LONG, at), t(0x202, LONG, len(jp)),
                  t(0x100, LONG, 80), t(0x101, LONG, 48)])
ifd0 = b.ifd(picture(b, 16, 12, samples=rgb_samples(16, 12), subfile=1, extra=[
    t(0x14A, IFD, [nef_jpeg, nef_raw]), t(0x10F, ASCII, "NIKON CORPORATION")]))
write("nikon.nef", b.finish(ifd0))

# Sony ARW: IFD0 holds its JPEG as JPEGInterchangeFormat (the preview), the
# DNGPrivateData tag Sony writes, and a SubIFD of sensor data (compression
# 32767), laid out little-endian.
b = Buf(True)
t = b.entry
sub = b.ifd(sensor(b, 64, 48, compression=32767))
jp = jpeg(72, 48)
at = b.alloc(jp)
ifd0 = b.ifd([t(0x103, SHORT, 6), t(0x201, LONG, at), t(0x202, LONG, len(jp)), t(0x14A, IFD, [sub]),
              t(0xC634, BYTE, [1, 2, 3, 4]), t(0x10F, ASCII, "SONY")])
write("sony.arw", b.finish(ifd0))

# Pentax PEF (big-endian): sensor data in Pentax's compression, and the
# preview only where the maker keeps it, in the Exif directory's maker note,
# which no tag of a TIFF points at.
b = Buf(False)
t = b.entry
note = b"PENTAX \0MM" + b"\0" * 20 + jpeg(88, 56) + b"\0" * 8
exif = b.ifd([t(0x927C, UNDEFINED, note)])
sub = b.ifd(sensor(b, 64, 48, compression=65535))
ifd0 = b.ifd([t(0x14A, IFD, [sub]), t(0x8769, LONG, exif), t(0x10F, ASCII, "PENTAX Corporation")])
write("pentax.pef", b.finish(ifd0))

# Samsung SRW: a JPEG as a strip of a SubIFD, a SubIFD of sensor data (Samsung's
# compression, 32772).
b = Buf(True)
t = b.entry
sub_raw = b.ifd(sensor(b, 64, 48, compression=32772))
sub_jpeg = b.ifd(picture(b, 56, 40, strips=jpeg(56, 40), subfile=1))
ifd0 = b.ifd([t(0x14A, IFD, [sub_jpeg, sub_raw]), t(0x10F, ASCII, "SAMSUNG")])
write("samsung.srw", b.finish(ifd0))

# A TIFF/EP file that only a camera maker's name and its structure show (no
# colour filter array: a Hasselblad 3FR): a SubIFD of uncompressed RGB.
b = Buf(True)
t = b.entry
sub = b.ifd(picture(b, 32, 24, samples=rgb_samples(32, 24), subfile=0))
ifd0 = b.ifd(picture(b, 16, 12, samples=rgb_samples(16, 12), subfile=1, extra=[
    t(0x14A, IFD, [sub]), t(0x10F, ASCII, "Hasselblad")]))
write("hasselblad.3fr", b.finish(ifd0))

# A Sony file of the old kind: a maker's name, and a JPEG thumbnail in the
# directory that follows the first (no SubIFD, no sensor data in the TIFF).
b = Buf(True)
t = b.entry
thumb = jpeg(24, 16)
at = b.alloc(thumb)
ifd1 = b.ifd([t(0x103, SHORT, 6), t(0x201, LONG, at), t(0x202, LONG, len(thumb))])
ifd0 = b.ifd([t(0x10F, ASCII, "SONY"), t(0x110, ASCII, "DSC-F828")], next_ifd=ifd1)
write("sony-thumbnail.srf", b.finish(ifd0))

# A DNG whose JPEG preview comes after 600 start markers that lead nowhere:
# only the directory finds it.
b = Buf(True)
t = b.entry
b.alloc(b"\xff\xd8\xff\xfe\x00\x02" * 600)
ifd0 = b.ifd(picture(b, 64, 48, strips=jpeg(64, 48), subfile=1, extra=[t(0xC612, BYTE, [1, 4, 0, 0])]))
write("many-markers.dng", b.finish(ifd0))

# Kodak DCR with 16-bit RGB previews, in either byte order.
for name, le in (("kodak16-be.dcr", False), ("kodak16-le.dcr", True)):
    b = Buf(le)
    t = b.entry
    sub = b.ifd(sensor(b, 64, 48, compression=65000))
    write(name, b.finish(b.ifd(picture(b, 16, 12, samples=rgb_samples(16, 12, wide=b.e), bits=16, subfile=1, extra=[
        t(0x14A, IFD, [sub]), t(0x10F, ASCII, "EASTMAN KODAK COMPANY")]))))

# TIFF-structured files with no maker's name, that only their sensor data shows
# to be RAW: each compression the makers number (Leaf, Sony, Epson, Samsung,
# Nikon, Kodak, Pentax), photometric 32803 alone, the CFA tags alone, and the
# DNGPrivateData tag alone. The first directory is a 16 by 12 RGB preview.
def generic(name, le, sensor_args=None, ifd0_extra=()):
    b = Buf(le)
    t = b.entry
    extra = list(ifd0_extra)
    if sensor_args is not None:
        extra.append(t(0x14A, IFD, [b.ifd(sensor(b, 64, 48, **sensor_args))]))
    write(name, b.finish(b.ifd(picture(b, 16, 12, samples=rgb_samples(16, 12), subfile=1, extra=extra))))


for c in (99, 32767, 32769, 32772, 34713, 65000, 65535):
    generic(f"compression-{c}.tif", c % 2 == 0, dict(compression=c, photometric=None, cfa=False))
generic("photometric-cfa-only.tif", True, dict(cfa=False))
generic("cfa-tags-only.tif", False, dict(photometric=None))
generic("private-data-only.tif", True, None, [t for t in [Buf(True).entry(0xC634, BYTE, [1, 2, 3, 4])]])

# A plain TIFF: uncompressed RGB, no maker.
b = Buf(True)
write("plain.tif", b.finish(b.ifd(picture(b, 16, 12, samples=rgb_samples(16, 12), subfile=0))))

# What a program saves a camera photo as: the maker's name in a plain TIFF.
b = Buf(True)
t = b.entry
write("plain-with-make.tif", b.finish(b.ifd(picture(b, 16, 12, samples=rgb_samples(16, 12), subfile=0, extra=[
    t(0x10F, ASCII, "NIKON CORPORATION")]))))

# The same with a camera's structure (a SubIFD) but no preview a reader
# takes (LZW strips): it is still a TIFF.
b = Buf(True)
t = b.entry
sub = b.ifd(picture(b, 8, 8, samples=bytes(100), subfile=0, compression=5))
big = picture(b, 16, 12, samples=bytes(200), subfile=0, compression=5, extra=[
    t(0x10F, ASCII, "NIKON CORPORATION"), t(0x14A, IFD, [sub])])
write("camera-structure-no-preview.tif", b.finish(b.ifd(big)))

# Olympus ORF: "IIRO", a first directory with a JPEG thumbnail, and the
# larger JPEG in the maker note.
for name, le, magic in (("olympus.orf", True, 0x4F52), ("olympus-rs.orf", True, 0x5352), ("olympus-be.orf", False, 0x4F52)):
    b = Buf(le, magic=magic)
    t = b.entry
    note = b"OLYMPUS\0II\x03\0" + b"\0" * 16 + jpeg(104, 72) + b"\0" * 4
    exif = b.ifd([t(0x927C, UNDEFINED, note)])
    thumb = jpeg(16, 12)
    at = b.alloc(thumb)
    ifd1 = b.ifd([t(0x103, SHORT, 6), t(0x201, LONG, at), t(0x202, LONG, len(thumb))])
    ifd0 = b.ifd([t(0x8769, LONG, exif), t(0x112, SHORT, 1)], next_ifd=ifd1)
    write(name, b.finish(ifd0))

# Panasonic RW2: "IIU\0", sensor data, and the JPEG in a tag of the first
# directory that no TIFF reader knows.
b = Buf(True, magic=0x55)
t = b.entry
ifd0 = b.ifd([t(0x2E, UNDEFINED, jpeg(112, 64)), t(0x112, SHORT, 1), t(0x10F, ASCII, "Panasonic")])
write("panasonic.rw2", b.finish(ifd0))

# A Panasonic file with no preview at all.
b = Buf(True, magic=0x55)
write("panasonic-no-preview.rw2", b.finish(b.ifd([b.entry(0x112, SHORT, 1)])))

# Phase One IIQ: a TIFF header, "IIII" after it, and the first directory
# after the sensor data.
b = Buf(True, header=b"IIII")
t = b.entry
b.alloc(bytes((i * 11) % 251 for i in range(500)))
write("phaseone.iiq", b.finish(b.ifd(picture(b, 24, 16, samples=rgb_samples(24, 16), subfile=0))))

# Fujifilm RAF: the header, the offset and length of the JPEG at 84, the JPEG.
for o in range(1, 9):
    jp = jpeg(64, 48, orientation=o)
    head = b"FUJIFILMCCD-RAW " + b"0201" + b"FF129504" + b"X-TEST".ljust(32, b"\0") + b"0100" + b"\0" * 20
    head += struct.pack(">LLLLLL", 160, len(jp), 160 + len(jp), 64, 160 + len(jp) + 64, 2000)
    head = head.ljust(160, b"\0")
    write(f"fujifilm-o{o}.raf", head + jp + b"\0" * 64 + bytes((i * 3) % 250 for i in range(2000)))

# Canon CR3: an ISO base media file (ISO/IEC 14496-12) laid out as the CC0
# samples of raw.pixls.us are. `ftyp` has the major brand `crx `. `moov`
# starts with a `uuid` box whose content is boxes: CMT1 (the Exif TIFF
# structure of the first directory, with the orientation) and THMB (a 16-byte
# header, then a JPEG). Another `uuid` box holds XMP, a third a PRVW box (a
# 16-byte header, then a JPEG). `mdat`, with a 64-bit size, begins with the
# full-size JPEG. None of the JPEGs has Exif of its own. In the "heif" file
# bytes that are not a JPEG stand where the JPEGs are (HEVC, in the samples
# of the newest cameras).
def box(kind, body, wide=False):
    if wide:
        return struct.pack(">I", 1) + kind + struct.pack(">Q", 16 + len(body)) + body
    return struct.pack(">I", 8 + len(body)) + kind + body


def cmt1(o):
    b = Buf(True)
    return b.finish(
        b.ifd([b.entry(0x10F, ASCII, "Canon"), b.entry(0x110, ASCII, "Canon EOS Test"), b.entry(0x112, SHORT, o)])
    )


def cr3(o, heif=False):
    def thumb(w, h, j):
        return struct.pack(">IHHIHH", 0, w, h, len(j), 1, 0) + j

    def preview(w, h, j):
        return struct.pack(">IHHHHI", 0, 1, w, h, 1, len(j)) + j

    opaque = bytes((i * 5) % 249 for i in range(1500))
    small, mid, full = (jpeg(16, 12), jpeg(96, 64), jpeg(128, 96)) if not heif else (opaque[:300],) * 3
    meta = box(b"CNCV", b"CanonCR3_001") + box(b"CMT1", cmt1(o)) + box(b"THMB", thumb(16, 12, small))
    uuid_meta = box(b"uuid", bytes.fromhex("85c0b687820f11e08111f4ce462b6a48") + meta)
    moov = box(b"moov", uuid_meta + box(b"mvhd", b"\0" * 100))
    xmp = box(b"uuid", bytes.fromhex("be7acfcb97a942e89c71999491e3afac") + b'<?xpacket begin="" id="test"?>')
    prvw = box(b"PRVW", preview(96, 64, mid))
    uuid_prvw = box(b"uuid", bytes.fromhex("eaf42b5e1c984b88b9fbb7dc406e4d16") + struct.pack(">II", 0, 1) + prvw)
    mdat = box(b"mdat", full + opaque, wide=True)
    ftyp = box(b"ftyp", b"crx \0\0\0\1crx isom")
    return ftyp + moov + xmp + uuid_prvw + box(b"free", b"\0" * 16) + mdat


for o in (1, 8):
    write(f"canon-o{o}.cr3", cr3(o))
write("canon-heif.cr3", cr3(6, heif=True))

# Sigma X3F: "FOVb", then sections; the JPEGs are in the image sections.
body = b"FOVb\x02\x00\x02\x00" + b"\0" * 48 + b"SECi" + b"\0" * 12 + jpeg(32, 24) + b"SECi" + b"\0" * 12 + jpeg(80, 56)
write("sigma.x3f", body + bytes((i * 9) % 247 for i in range(1000)))

# Canon CRW (CIFF): "II", the heap offset (26), "HEAPCCDR", and the JPEG in
# the heap.
body = b"II" + struct.pack("<L", 26) + b"HEAPCCDR" + b"\x00\x01\x00\x00\x00" + b"\0" * 30
write("canon.crw", body + jpeg(72, 48) + b"\0" * 12 + bytes((i * 13) % 241 for i in range(600)))

# Minolta MRW: its blocks, with no JPEG.
prd = b"\0PRD" + struct.pack(">L", 24) + b"21810002" + b"\0" * 16
ttw = b"\0TTW" + struct.pack(">L", 8) + b"MM\0*\0\0\0\x08"
mrw_data = prd + ttw
write("minolta.mrw", b"\0MRM" + struct.pack(">L", len(mrw_data)) + mrw_data + bytes(500))
