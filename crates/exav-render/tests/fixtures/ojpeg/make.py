#!/usr/bin/env python3
"""Old-style JPEG TIFFs (compression 6): python3 make.py (needs Pillow).

The picture is 16 by 16: red on the left half, blue on the right. Three files,
each a way old-style JPEG is laid out, as libtiff reads them:

whole.tif       the strip is a whole JPEG file (Kofax's); JPEGInterchangeFormat
                names it
tables.tif      the strip holds the scan alone; the tables are elsewhere in the
                file and the tags JPEGQTables, JPEGDCTables and JPEGACTables
                say where; the frame comes from the image's own tags
interchange.tif a JPEG stream the file points to holds the headers and the
                scan; the strip is named from three bytes before the end of its
                scan header, and its byte count stops short of the stream's end
scanheader.tif the stream the file points to stops before the scan header, which
                starts the strip
"""
import io
import struct

from PIL import Image

im = Image.new("RGB", (16, 16))
for y in range(16):
    for x in range(16):
        im.putpixel((x, y), (200, 30, 30) if x < 8 else (30, 30, 200))
buf = io.BytesIO()
im.save(buf, "JPEG", quality=90, subsampling=2)
jpeg = buf.getvalue()


def segments(data):
    """(marker, offset, length) of each segment up to the scan header, and where the scan data start."""
    p, out = 2, []
    while True:
        marker = data[p + 1]
        n = struct.unpack(">H", data[p + 2 : p + 4])[0]
        out.append((marker, p, n + 2))
        p += 2 + n
        if marker == 0xDA:
            return out, p


segs, scan_at = segments(jpeg)
scan = jpeg[scan_at:-2]


class File:
    """A little-endian TIFF: data after the 8-byte header, then the directory."""

    def __init__(self):
        self.data = b""
        self.entries = []

    def put(self, blob):
        at = 8 + len(self.data)
        self.data += blob
        return at

    def tag(self, tag, kind, count, value):
        self.entries.append((tag, kind, count, value))

    def array(self, tag, kind, values):
        fmt = "<H" if kind == 3 else "<I"
        blob = b"".join(struct.pack(fmt, v) for v in values)
        # Four bytes or fewer sit in the entry itself.
        self.tag(tag, kind, len(values), blob.ljust(4, b"\0") if len(blob) <= 4 else self.put(blob))

    def finish(self, strip_at, strip_len):
        for tag, kind, value in (
            (256, 3, 16),
            (257, 3, 16),
            (259, 3, 6),
            (262, 3, 6),
            (273, 4, strip_at),
            (277, 3, 3),
            (278, 3, 16),
            (279, 4, strip_len),
        ):
            self.tag(tag, kind, 1, value)
        self.array(258, 3, [8, 8, 8])
        out = b"II*\0" + struct.pack("<I", 8 + len(self.data)) + self.data
        out += struct.pack("<H", len(self.entries))
        for tag, kind, count, value in sorted(self.entries):
            if isinstance(value, bytes):
                v = value
            elif kind == 3 and count == 1:
                v = struct.pack("<H", value) + b"\0\0"
            else:
                v = struct.pack("<I", value)
            out += struct.pack("<HHI", tag, kind, count) + v
        return out + struct.pack("<I", 0)


# whole: the JPEG is the strip.
f = File()
at = f.put(jpeg)
f.tag(513, 4, 1, at)
open("whole.tif", "wb").write(f.finish(at, len(jpeg)))

# tables: the scan, then the tables, which the tags point to. Pillow's file has
# two of each: component 0 uses the first, the others the second.
f = File()
at = f.put(scan)
q = [f.put(jpeg[o + 5 : o + n]) for m, o, n in segs if m == 0xDB]
dht = [(jpeg[o + 4], jpeg[o + 5 : o + n]) for m, o, n in segs if m == 0xC4]
dc = [f.put(t) for tc, t in dht if tc >> 4 == 0]
ac = [f.put(t) for tc, t in dht if tc >> 4 == 1]
f.tag(512, 3, 1, 1)
f.array(519, 4, [q[0], q[1], q[1]])
f.array(520, 4, [dc[0], dc[1], dc[1]])
f.array(521, 4, [ac[0], ac[1], ac[1]])
f.array(530, 3, [2, 2])
open("tables.tif", "wb").write(f.finish(at, len(scan)))

# interchange: the strip starts 3 bytes before the end of the scan header and
# is 5 bytes short of the stream's end.
f = File()
at = f.put(jpeg)
f.tag(512, 3, 1, 1)
f.tag(513, 4, 1, at)
f.tag(514, 4, 1, len(jpeg))
open("interchange.tif", "wb").write(f.finish(at + scan_at - 3, len(jpeg) - scan_at + 3 - 5))

# scanheader: the stream the file points to stops before the scan header, which
# starts the strip (a file with several strips has it in the first).
sos_at = [o for m, o, n in segs if m == 0xDA][0]
f = File()
at = f.put(jpeg[:sos_at])
f.tag(512, 3, 1, 1)
f.tag(513, 4, 1, at)
f.tag(514, 4, 1, sos_at)
strip_at = f.put(jpeg[sos_at:-2])
open("scanheader.tif", "wb").write(f.finish(strip_at, len(jpeg) - 2 - sos_at))
