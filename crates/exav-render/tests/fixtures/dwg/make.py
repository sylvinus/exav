#!/usr/bin/env python3
"""Write the drawings tests/dwg.rs tessellates, as DXF and as DWG.

    python3 make.py                                # *.dxf.gz (ezdxf)
    ODAFC=/path/to/odafc.sh python3 make.py --convert   # and *.dwg.gz

Each drawing is written by ezdxf (tested with 1.4.1) as a 2018 DXF. With
--convert, the ODA File Converter (a black box, run through the wrapper
`$ODAFC IN OUT VERSION FORMAT`) writes the ones in DWG_VERSIONS as DWG of
those versions, `<name>.dwg.gz` for 2018 and `<name>-<version>.dwg.gz` for
the others. Every file is stored gzipped (mtime 0: the same input gives the
same bytes).

- plan: a wall line and a column on WALLS (red), a label on NOTES (blue),
  and a paper-space layout "Sheet A".
- hostile: plan with a layer whose name holds a quote, a backslash, a tab
  and a control character (patched into the file: ezdxf refuses the name).
- lines200: 200 lines, y = 0 to 199, in that order.
- hatch7: a line and a one-family pattern hatch, each on a colour-7 layer.
- attribs: an insert of DOOR_TAG with visible attributes D-104 and "Tür 25°"
  and an invisible one SECRET, in a TrueType style.
- leader: a LEADER with an arrowhead and no text, dimension style ARROWS
  with DIMASZ 2.5 and DIMSCALE 2.
- layouts: a line in model space and two layouts "A" and "B", each with one
  viewport onto it.
"""

import gzip
import io
import os
import subprocess
import sys
import tempfile

import ezdxf

HERE = os.path.dirname(os.path.abspath(__file__))
# Fixed dates and GUIDs: the same script writes the same files.
ezdxf.options.write_fixed_meta_data_for_testing = True
DWG_VERSIONS = {
    "plan": ["ACAD2018", "ACAD2000"],
    "hatch7": ["ACAD2018"],
    "attribs": ["ACAD2018", "ACAD2000"],
    "layouts": ["ACAD2018"],
}


def new():
    doc = ezdxf.new("R2018", units=0)
    doc.layers.remove("Defpoints")
    return doc


def plan():
    doc = new()
    doc.layers.add("WALLS", color=1)
    doc.layers.add("NOTES", color=5)
    msp = doc.modelspace()
    msp.add_line((0, 0), (100, 0), dxfattribs={"layer": "WALLS"})
    msp.add_circle((50, 50), 25, dxfattribs={"layer": "WALLS"})
    msp.add_text("HELLO", height=2.5, dxfattribs={"layer": "NOTES", "insert": (10, 10)})
    doc.layouts.new("Sheet A")
    return doc


def hostile():
    doc = plan()
    doc.layers.add("HOSTILENAME", color=3)
    doc.modelspace().add_line((0, 0), (1, 1), dxfattribs={"layer": "HOSTILENAME"})
    return doc


def lines200():
    doc = new()
    msp = doc.modelspace()
    for y in range(200):
        msp.add_line((0, y), (10, y))
    return doc


def hatch7():
    doc = new()
    for name in ("LINES", "HATCHES"):
        doc.layers.add(name, color=7)
    msp = doc.modelspace()
    msp.add_line((0, -10), (100, -10), dxfattribs={"layer": "LINES"})
    hatch = msp.add_hatch(dxfattribs={"layer": "HATCHES"})
    hatch.set_pattern_fill("ANSI31", definition=[[45.0, (0, 0), (-2.245, 2.245), []]])
    hatch.paths.add_polyline_path([(0, 0), (100, 0), (100, 100), (0, 100)], is_closed=True)
    return doc


def attribs():
    doc = new()
    doc.styles.add("LABELS", font="arial.ttf")
    tag = doc.blocks.new("DOOR_TAG")
    tag.add_circle((0, 0), 5)
    msp = doc.modelspace()
    insert = msp.add_blockref("DOOR_TAG", (40, 30))
    for name, value, flags in (("NUMBER", "D-104", 0), ("COST", "SECRET", 1), ("ROOM", "Tür 25°", 0)):
        insert.add_attrib(name, value, (42, 28), dxfattribs={"style": "LABELS", "flags": flags})
    return doc


def leader():
    doc = new()
    style = doc.dimstyles.new("ARROWS")
    style.dxf.dimasz = 2.5
    style.dxf.dimscale = 2.0
    msp = doc.modelspace()
    msp.add_leader([(0, 0), (20, 0), (30, 10)], dimstyle="ARROWS")
    return doc


def layouts():
    doc = new()
    doc.modelspace().add_line((0, 0), (100, 0))
    for name in ("A", "B"):
        layout = doc.layouts.new(name)
        # The sheet's own viewport first, as AutoCAD writes it.
        layout.page_setup(size=(297, 210), margins=(0, 0, 0, 0), units="mm")
        layout.add_viewport(center=(50, 50), size=(80, 40), view_center_point=(50, 0), view_height=40)
    return doc


DRAWINGS = {
    "plan": plan,
    "hostile": hostile,
    "lines200": lines200,
    "hatch7": hatch7,
    "attribs": attribs,
    "leader": leader,
    "layouts": layouts,
}


def write_gz(path, data):
    with open(path, "wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as f:
            f.write(data)


def dxf_bytes(doc):
    out = io.StringIO()
    doc.write(out)
    return out.getvalue().encode("utf-8")


def convert(sources):
    odafc = os.environ.get("ODAFC")
    if not odafc:
        sys.exit("set ODAFC to the ODA File Converter wrapper")
    with tempfile.TemporaryDirectory() as plain:
        for name, versions in DWG_VERSIONS.items():
            with open(os.path.join(plain, name + ".dxf"), "wb") as f:
                f.write(sources[name])
        for name, versions in DWG_VERSIONS.items():
            for version in versions:
                with tempfile.TemporaryDirectory() as tmp:
                    subprocess.run([odafc, plain, tmp, version, "DWG", name + ".dxf"], check=True)
                    made = os.path.join(tmp, name + ".dwg")
                    if not os.path.exists(made) or os.path.getsize(made) == 0:
                        sys.exit(f"the converter wrote no {version} DWG of {name}")
                    suffix = "" if version == "ACAD2018" else "-" + version.replace("ACAD", "R")
                    with open(made, "rb") as f:
                        write_gz(os.path.join(HERE, f"{name}{suffix}.dwg.gz"), f.read())


if __name__ == "__main__":
    sources = {}
    for name, make in DRAWINGS.items():
        data = dxf_bytes(make())
        if name == "hostile":
            data = data.replace(b"HOSTILENAME", b'Q"\\\t\x01')
        sources[name] = data
        write_gz(os.path.join(HERE, name + ".dxf.gz"), data)
    if "--convert" in sys.argv:
        convert(sources)
