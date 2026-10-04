#!/usr/bin/env python3
"""Writes the STL fixtures of tests/stl.rs (struct-packed by hand, no STL
library) and expected.json: triangles, extents, volume and colours.

    python3 make.py
"""
import json
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
EXPECTED = {}

# A 2 x 3 x 4 box from (1, 1, 1), outward, as 12 facets.
LO, HI = (1.0, 1.0, 1.0), (3.0, 4.0, 5.0)


def corner(i):
    return tuple(HI[k] if i >> k & 1 else LO[k] for k in range(3))


QUADS = [(0, 2, 3, 1), (4, 5, 7, 6), (0, 1, 5, 4), (2, 6, 7, 3), (0, 4, 6, 2), (1, 3, 7, 5)]
BOX = [t for q in QUADS for t in ((q[0], q[1], q[2]), (q[0], q[2], q[3]))]
FACETS = [tuple(corner(i) for i in t) for t in BOX]
VOLUME = 2 * 3 * 4


def binary(name, facets, header=b"exav fixture", attrs=None, declared=None):
    out = bytearray(header.ljust(80, b" ")[:80])
    out += struct.pack("<I", len(facets) if declared is None else declared)
    for i, f in enumerate(facets):
        # Normals left zero: readers must not depend on them.
        out += struct.pack("<3f", 0, 0, 0)
        for v in f:
            out += struct.pack("<3f", *v)
        out += struct.pack("<H", attrs[i] if attrs else 0)
    with open(os.path.join(HERE, name), "wb") as fh:
        fh.write(out)


def ascii_stl(name, facets):
    lines = ["solid fixture"]
    for f in facets:
        lines += ["  facet normal 0 0 0", "    outer loop"]
        lines += [f"      vertex {v[0]:e} {v[1]:e} {v[2]:e}" for v in f]
        lines += ["    endloop", "  endfacet"]
    lines.append("endsolid fixture")
    with open(os.path.join(HERE, name), "w") as fh:
        fh.write("\n".join(lines) + "\n")


def box_expect(**extra):
    return dict(triangles=12, min=list(LO), max=list(HI), volume=VOLUME, **extra)


binary("box.stl", FACETS)
EXPECTED["box.stl"] = box_expect()
ascii_stl("box_ascii.stl", FACETS)
EXPECTED["box_ascii.stl"] = box_expect()
# Binary, its header starting with "solid" as many exporters write it.
binary("solid_header.stl", FACETS, header=b"solid exported by a CAD program")
EXPECTED["solid_header.stl"] = box_expect()
# VisCAM/SolidView: bit 15 set, red in bits 10..14; the second facet uncoloured.
red = 0x8000 | (31 << 10)
binary("viscam.stl", FACETS, attrs=[red if i % 2 == 0 else 0 for i in range(12)])
EXPECTED["viscam.stl"] = box_expect(colors={"0": [255, 0, 0], "1": [255, 255, 255]})
# Magics: a default colour in the header (blue); bit 15 clear: the facet's
# own, red in bits 0..4.
binary("magics.stl", FACETS, header=b"COLOR=\x00\x00\xff\xff MATERIAL=", attrs=[31 if i % 2 == 0 else 0x8000 for i in range(12)])
EXPECTED["magics.stl"] = box_expect(colors={"0": [255, 0, 0], "1": [0, 0, 255]})
# Damaged: 12 declared, 5 present.
binary("truncated.stl", FACETS[:5], declared=12)
EXPECTED["truncated.stl"] = dict(triangles=5, damaged=True)
# A count of four billion for one facet: no allocation for the count.
binary("huge_count.stl", FACETS[:1], declared=0xFFFFFFF0)
EXPECTED["huge_count.stl"] = dict(triangles=1, damaged=True)

with open(os.path.join(HERE, "expected.json"), "w") as f:
    json.dump(EXPECTED, f, indent=1, sort_keys=True)
    f.write("\n")
print("wrote", ", ".join(sorted(EXPECTED)))
