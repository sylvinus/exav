#!/usr/bin/env python3
"""Write the proxy graphics fixture: custom entities whose graphics streams
(ODA spec 29) this script builds chunk by chunk.

    python3 make.py                                  # src/proxy.dxf.gz
    ODAFC=/path/to/odafc.sh python3 make.py --convert

`src/proxy.dxf` (2000, from ezdxf) holds one ACAD_PROXY_ENTITY per case of
CASES, on a class EXAV_SHAPE this script declares, at its own place along X,
and one EXAV_SHAPE record of the class's own type with its graphics in
AcDbEntity. With --convert, the ODA File Converter (a black box, run through
the wrapper `$ODAFC IN OUT VERSION FORMAT`) writes it as DWG of every version
the reader reads (dwg/<VERSION>/proxy.dwg), as R13 DXF (r13/proxy.dxf, whose
proxies are AcDbZombieEntity), and as R12 DXF (r12/proxy.dxf): R12 has no
proxies, so the converter writes what each draws as plain entities, an
INSERT of the handle of the proxy (or the one entity it drew).
tests/cad_proxy.rs draws them all and compares them per handle. Files are
stored gzipped (mtime 0).

Needs ezdxf (tested with 1.4.1).
"""

import gzip
import io
import math
import os
import struct
import subprocess
import sys
import tempfile

import ezdxf

ezdxf.options.write_fixed_meta_data_for_testing = True

HERE = os.path.dirname(os.path.abspath(__file__))
DWG_VERSIONS = [
    "ACAD13", "ACAD14", "ACAD2000", "ACAD2004", "ACAD2007", "ACAD2010", "ACAD2013", "ACAD2018",
]


# Stream: RL size, RL chunk count, chunks of RL size, RL type, data padded to 4.
def pad4(b):
    return b + b"\0" * (-len(b) % 4)


def chunk(kind, data=b""):
    data = pad4(data)
    return struct.pack("<II", 8 + len(data), kind) + data


def stream(chunks):
    body = b"".join(chunks)
    return struct.pack("<II", 8 + len(body), len(chunks)) + body


def rl(*v):
    return struct.pack("<%dI" % len(v), *[x & 0xFFFFFFFF for x in v])


def rd(*v):
    return struct.pack("<%dd" % len(v), *v)


def pts(p):
    return rl(len(p)) + b"".join(rd(*q) for q in p)


def polyline(p):
    return chunk(6, pts(p))


def seg(x, y):
    return polyline([(x, y, 0), (x + 4, y, 0)])


def polygon(p):
    return chunk(7, pts(p))


def circle(c, r, n=(0, 0, 1)):
    return chunk(2, rd(*c, r, *n))


def circle3(a, b, c):
    return chunk(3, rd(*a, *b, *c))


def arc(c, r, start, sweep, kind=0, n=(0, 0, 1)):
    return chunk(4, rd(*c, r, *n, *start, sweep) + rl(kind))


def arc3(a, b, c, kind=0):
    return chunk(5, rd(*a, *b, *c) + rl(kind))


def color(i):
    return chunk(14, rl(i))


def layer(i):
    return chunk(16, rl(i))


def linetype(i):
    return chunk(18, rl(i))


def marker(i):
    return chunk(19, rl(i))


def fill(i):
    return chunk(20, rl(i))


def truecolor(r, g, b):
    # An AcCmColor: method 0xC2 (RGB), red, green, blue from the high byte
    # down. The spec's three RC bytes (red first) the converter ignores.
    return chunk(22, rl(0xC2000000 | r << 16 | g << 8 | b))


def lineweight(i):
    return chunk(23, rl(i))


def ltscale(s):
    return chunk(24, rd(s))


def push(m):
    return chunk(29, rd(*m))


def pop():
    return chunk(31)


def polyline_n(p, n):
    return chunk(32, pts(p) + rd(*n))


def text(pos, s, h, w=1.0, obl=0.0, d=(1, 0, 0)):
    return chunk(10, rd(*pos, 0, 0, 1, *d, h, w, obl) + pad4(s.encode("cp1252") + b"\0"))


def text_u(pos, s, h, d=(1, 0, 0)):
    return chunk(36, rd(*pos, 0, 0, 1, *d, h, 1.0, 0.0) + pad4(s.encode("utf-16le") + b"\0\0"))


def text2(pos, s, h, raw, w=1.0, obl=0.0):
    return chunk(
        11,
        rd(*pos, 0, 0, 1, 1, 0, 0)
        + pad4(s.encode("cp1252") + b"\0")
        + rl(0xFFFFFFFF, raw)
        + rd(h, w, obl, 0)
        + rl(0, 0, 0, 0, 0)
        + pad4(b"txt\0")
        + pad4(b"\0"),
    )


def utext2(pos, s, h):
    u = lambda x: pad4(x.encode("utf-16le") + b"\0\0")
    return chunk(
        38,
        rd(*pos, 0, 0, 1, 1, 0, 0)
        + u(s)
        + rl(0xFFFFFFFF, 0)
        + rd(h, 1.0, 0.0, 0.0)
        + rl(0, 0, 0, 0, 0, 0, 0, 0, 0)
        + u("")
        + u("txt")
        + u(""),
    )


def shell(verts, entries, visible=None):
    # Edge data: only visibilities (0x40) when given.
    edges = rl(0x40, *visible) if visible else rl(0)
    return chunk(9, pts(verts) + rl(len(entries), *entries) + edges + rl(0, 0))


def mesh(rows, cols, verts):
    return chunk(8, rl(rows, cols) + b"".join(rd(*v) for v in verts) + rl(0, 0, 0))


def xline(a, b, ray=False):
    return chunk(13 if ray else 12, rd(*a, *b))


# DWG bit codes (spec 2), for LWPOLYLINE data (spec 20.4.85, R2000 layout).
class Bits:
    def __init__(self):
        self.bits = []

    def raw(self, v, n):
        self.bits += [(v >> i) & 1 for i in range(n - 1, -1, -1)]

    def bytes_(self, b):
        for x in b:
            self.raw(x, 8)

    def bs(self, v):
        if v == 0:
            self.raw(2, 2)
        elif 0 < v < 256:
            self.raw(1, 2)
            self.raw(v, 8)
        else:
            self.raw(0, 2)
            self.bytes_(struct.pack("<h", v))

    def bl(self, v):
        if v == 0:
            self.raw(2, 2)
        elif 0 < v < 256:
            self.raw(1, 2)
            self.raw(v, 8)
        else:
            self.raw(0, 2)
            self.bytes_(struct.pack("<i", v))

    def bd(self, v):
        if v == 1.0:
            self.raw(1, 2)
        elif v == 0.0:
            self.raw(2, 2)
        else:
            self.raw(0, 2)
            self.bytes_(struct.pack("<d", v))

    def dd(self, v, default):
        if v == default:
            self.raw(0, 2)
        else:
            self.raw(3, 2)
            self.bytes_(struct.pack("<d", v))

    def data(self):
        b = self.bits + [0] * (-len(self.bits) % 8)
        return bytes(int("".join(map(str, b[i:i + 8])), 2) for i in range(0, len(b), 8))


def lwpolyline(points, bulges=None, widths=None, closed=False):
    w = Bits()
    w.bs((512 if closed else 0) | (16 if bulges else 0) | (32 if widths else 0))
    w.bl(len(points))
    if bulges:
        w.bl(len(bulges))
    if widths:
        w.bl(len(widths))
    prev = None
    for k, (x, y) in enumerate(points):
        if k == 0:
            w.bytes_(struct.pack("<dd", x, y))
        else:
            w.dd(x, prev[0])
            w.dd(y, prev[1])
        prev = (x, y)
    for b in bulges or []:
        w.bd(b)
    for s, e in widths or []:
        w.bd(s)
        w.bd(e)
    d = w.data()
    # The spec's three unknown bytes after the data: without them the
    # converter loses the chunk after this one when it writes a DWG.
    return chunk(33, rl(len(d)) + d + b"\0\0\0")


def move(dx, dy, s=1.0, rot=0.0):
    c, n = math.cos(rot) * s, math.sin(rot) * s
    return [c, -n, 0, dx, n, c, 0, dy, 0, 0, s, 0, 0, 0, 0, 1]


# Layers: 0, Defpoints, L1, L2 (indices 0 to 3). Linetypes but ByBlock and
# ByLayer: Continuous, CENTER, CENTERX2, ... (ezdxf's setup).
# (name, layer, extra AcDbEntity groups, stream or None)
CASES = [
    # Traits: initial (the entity's), layer 0, ByBlock and ByLayer colour,
    # linetype indices and sentinels, lineweight, linetype scale.
    ("traits", "L2", [(62, 3), (6, "DASHED")], stream([
        seg(0, 0), layer(0), seg(0, 1), color(0), seg(0, 2), color(256), seg(0, 3),
        linetype(0), seg(0, 4), linetype(1), seg(0, 5), linetype(0xFFFFFFFF), seg(0, 6),
        linetype(0xFFFFFFFE), seg(0, 7), linetype(32767), seg(0, 8), linetype(32766), seg(0, 9),
        layer(2), color(1), seg(0, 10), lineweight(50), ltscale(2.0), seg(0, 11),
    ])),
    # Transforms: nested, popped, rotated and scaled.
    ("transforms", "0", [], stream([
        push(move(100, 0)), seg(0, 0), push(move(0, 10)), seg(0, 0), pop(), seg(0, 2), pop(),
        seg(100, 4), push(move(130, 0, 2.0, math.pi / 2)), seg(0, 0), pop(),
        # Turned, then moved within the turn: (160, 10) to (160, 14).
        push(move(160, 0)), push(move(0, 0, 1.0, math.pi / 2)), push(move(10, 0)), seg(0, 0),
        pop(), pop(), pop(),
    ])),
    # Curves: circle, circle through 3 points, arcs from a start vector,
    # about -Z, through 3 points (clockwise), a tilted circle.
    ("curves", "0", [], stream([
        circle((200, 0, 0), 5), circle3((220, 0, 0), (230, 0, 0), (225, 5, 0)),
        arc((240, 0, 0), 5, (0, 1, 0), math.pi), arc((260, 0, 0), 5, (1, 0, 0), math.pi / 2, n=(0, 0, -1)),
        arc3((270, 0, 0), (275, 5, 0), (280, 0, 0)), circle((290, 0, 0), 5, (1, 0, 0)),
    ])),
    # Fill: on after 1 and after 0, off after 2, polygon off by default.
    ("fill", "0", [], stream([
        polygon([(300, 0, 0), (310, 0, 0), (310, 10, 0)]), fill(0), polygon([(320, 0, 0), (330, 0, 0), (330, 10, 0)]),
        fill(2), polygon([(340, 0, 0), (350, 0, 0), (350, 10, 0)]), fill(1),
        polygon([(360, 0, 0), (370, 0, 0), (370, 10, 0)]),
    ])),
    # Filled closed curves and closed arcs (the converter fills sectors and
    # chords whatever the fill, and draws circles as outlines).
    ("filled curves", "0", [], stream([
        fill(1), circle((400, 0, 0), 5), arc((420, 0, 0), 5, (1, 0, 0), math.pi / 2, 1),
        fill(2), arc((440, 0, 0), 5, (1, 0, 0), math.pi / 2, 2),
    ])),
    # Texts: plain, Unicode, TEXT2 interpreted and raw, Unicode TEXT2.
    ("texts", "0", [], stream([
        text((500, 0, 0), "Hello", 2.5), text_u((500, 10, 0), "Wörld", 3.0, d=(0, 1, 0)),
        text2((520, 0, 0), "%%c50", 2.0, 0, 0.75, 0.2), text2((520, 10, 0), "%%c50", 2.0, 1),
        utext2((540, 0, 0), "Café", 2.0),
    ])),
    # Shells: two faces; one with a hidden edge; filled.
    ("shells", "0", [], stream([
        shell([(600, 0, 0), (610, 0, 0), (610, 10, 0), (620, 0, 0)], [3, 0, 1, 2, 3, 1, 3, 2]),
        shell([(630, 0, 0), (640, 0, 0), (640, 10, 0)], [3, 0, 1, 2], [1, 0, 1]),
        fill(1), shell([(650, 0, 0), (660, 0, 0), (660, 10, 0), (650, 10, 0)], [4, 0, 1, 2, 3]),
    ])),
    ("mesh", "0", [], stream([
        mesh(2, 3, [(700, 0, 0), (705, 0, 0), (710, 0, 0), (700, 5, 0), (705, 5, 0), (710, 5, 0)]),
    ])),
    # True colour, xline and ray (R12 has none of them).
    ("r12 lacks", "0", [], stream([
        truecolor(255, 0, 0), seg(800, 0), xline((800, 10, 0), (801, 11, 0)),
        xline((800, 20, 0), (801, 20, 0), ray=True),
    ])),
    ("polylines", "0", [], stream([
        polyline_n([(900, 0, 0), (904, 0, 0), (904, 4, 0)], (0, 0, 1)),
        polygon([(910, 0, 0), (914, 0, 0), (914, 4, 0)]),
    ])),
    ("no graphics", "0", [], None),
    ("empty graphics", "0", [], stream([])),
    # Chunks drawing nothing (extents, a marker, a type of no spec) before
    # a segment.
    ("skipped", "0", [], stream([
        chunk(1, rd(0, 0, 0, 1, 1, 0)), marker(3), chunk(99, rl(1, 2)), seg(1000, 0),
    ])),
    ("lwpolyline", "0", [], stream([
        lwpolyline([(1100, 0), (1110, 0), (1110, 10), (1100, 10)], bulges=[0, 0.5, 0, 0], closed=True),
        lwpolyline([(1120, 0), (1130, 0), (1130, 5)], widths=[(0, 0), (1, 2), (0, 0)]),
    ])),
    # Past the tables: the layer stays, the colour stays, the linetype is
    # ByLayer.
    ("out of range", "L2", [(62, 3), (6, "DASHED")], stream([
        layer(99), seg(1200, 0), color(300), seg(1200, 1), linetype(500), seg(1200, 2),
    ])),
    # Type 44, which the spec does not list: elliptical arcs, the second
    # tilted and its major axis turned.
    ("elliptical arcs", "0", [], stream([
        chunk(44, rd(1400, 0, 0, 0, 0, 1, 10, 5, 0, math.pi, 0) + rl(0)),
        chunk(44, rd(1430, 0, 0, 0.6, 0, 0.8, 10, 4, -1, 2, math.pi / 3) + rl(0)),
    ])),
    # A filled circle seen edge on has no area: its outline.
    ("edge on", "0", [], stream([fill(1), circle((1500, 0, 0), 5, (1, 0, 0))])),
]


def proxy_records(class_id, handle, owner, case):
    name, lay, extra, g = case
    out = [(0, "ACAD_PROXY_ENTITY"), (5, handle), (330, owner), (100, "AcDbEntity"), (8, lay)]
    out += extra
    out += [(100, "AcDbProxyEntity"), (90, 498), (91, class_id)]
    if g is not None:
        out.append((92, len(g)))
        hx = g.hex().upper()
        out += [(310, hx[k:k + 254]) for k in range(0, len(hx), 254)]
    out += [(93, 0), (94, 0), (95, 0x0011000F), (70, 0)]
    return out


def custom_record(handle, owner, g):
    """A record of the class's own type, graphics in AcDbEntity."""
    out = [(0, "EXAV_SHAPE"), (5, handle), (330, owner), (100, "AcDbEntity"), (8, "0"), (92, len(g))]
    hx = g.hex().upper()
    out += [(310, hx[k:k + 254]) for k in range(0, len(hx), 254)]
    return out + [(100, "ExavShape"), (90, 7)]


def source():
    doc = ezdxf.new("R2000", setup=True)
    doc.header["$PROXYGRAPHICS"] = 1
    doc.layers.add("L1", color=3)
    doc.layers.add("L2", color=5)
    msp = doc.modelspace()
    marks = [msp.add_line((k, -50), (k, -51)).dxf.handle for k in range(len(CASES) + 1)]
    s = io.StringIO()
    doc.write(s)
    lines = s.getvalue().splitlines()
    pairs = [(lines[i].strip(), lines[i + 1]) for i in range(0, len(lines) - 1, 2)]
    sec = next(i for i, (c, v) in enumerate(pairs) if c == "2" and v.strip() == "CLASSES")
    end = next(i for i in range(sec, len(pairs)) if pairs[i][1].strip() == "ENDSEC")
    pairs[end:end] = [("0", "CLASS"), ("1", "EXAV_SHAPE"), ("2", "ExavShape"),
                      ("3", "exav test fixture"), ("90", "1"), ("91", str(len(marks))),
                      ("280", "1"), ("281", "1")]
    names = [pairs[i + 1][1].strip() for i, (c, v) in enumerate(pairs) if c == "0" and v.strip() == "CLASS"]
    class_id = 500 + names.index("EXAV_SHAPE")
    out = []
    i = 0
    while i < len(pairs):
        c, v = pairs[i]
        if c == "0" and v.strip() == "LINE":
            j = i + 1
            while pairs[j][0] != "0":
                j += 1
            rec = dict((a, b.strip()) for a, b in pairs[i + 1:j])
            if rec.get("5") in marks:
                k = marks.index(rec["5"])
                if k < len(CASES):
                    recs = proxy_records(class_id, rec["5"], rec["330"], CASES[k])
                else:
                    recs = custom_record(rec["5"], rec["330"], stream([seg(1300, 0)]))
                out += [(str(a), str(b)) for a, b in recs]
                i = j
                continue
        out.append((c, v))
        i += 1
    return "".join(f"{c}\r\n{v}\r\n" for c, v in out).encode("cp1252")


def write_gz(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as f:
            f.write(data)


def convert():
    odafc = os.environ.get("ODAFC")
    if not odafc:
        sys.exit("set ODAFC to the ODA File Converter wrapper")
    with tempfile.TemporaryDirectory() as plain:
        with gzip.open(os.path.join(HERE, "src", "proxy.dxf.gz")) as f, open(
            os.path.join(plain, "proxy.dxf"), "wb"
        ) as out:
            out.write(f.read())
        runs = [("ACAD12", "DXF", "r12", ".dxf"), ("ACAD13", "DXF", "r13", ".dxf")] + [
            (v, "DWG", os.path.join("dwg", v.replace("ACAD", "R")), ".dwg") for v in DWG_VERSIONS
        ]
        for version, fmt, folder, ext in runs:
            with tempfile.TemporaryDirectory() as tmp:
                subprocess.run([odafc, plain, tmp, version, fmt, "proxy.dxf"], check=True)
                made = os.path.join(tmp, "proxy" + ext)
                if not os.path.exists(made) or os.path.getsize(made) == 0:
                    sys.exit(f"the converter wrote no {version} {fmt}")
                with open(made, "rb") as f:
                    write_gz(os.path.join(HERE, folder, "proxy" + ext + ".gz"), f.read())


if __name__ == "__main__":
    if "--convert" in sys.argv:
        convert()
    else:
        write_gz(os.path.join(HERE, "src", "proxy.dxf.gz"), source())
