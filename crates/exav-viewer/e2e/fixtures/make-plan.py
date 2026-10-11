#!/usr/bin/env python3
"""Write the browser tests' drawing, a small floor plan, as plan.dxf and
plan.dwg beside this script, where they are kept: make-samples.mjs copies
them with the other samples. Being generated, they carry nobody's work.

    python3 e2e/fixtures/make-plan.py
    ODAFC=/path/to/odafc.sh python3 e2e/fixtures/make-plan.py   # and plan.dwg

ezdxf (tested with 1.4.1) writes the 2018 DXF; with ODAFC set, the ODA File
Converter (run through the wrapper `$ODAFC IN OUT VERSION FORMAT`) converts
it to a 2018 DWG.
"""

import os
import shutil
import subprocess
import sys
import tempfile

import ezdxf

OUT = os.path.dirname(os.path.abspath(__file__))
# Fixed dates and GUIDs: the same script writes the same DXF.
ezdxf.options.write_fixed_meta_data_for_testing = True


def plan():
    doc = ezdxf.new("R2018", units=0)
    doc.header["$MEASUREMENT"] = 0
    doc.layers.remove("Defpoints")
    for name, color in (("WALLS", 7), ("DOORS", 2), ("FURNITURE", 4), ("TEXT", 3), ("COLUMNS", 8)):
        doc.layers.add(name, color=color)
    msp = doc.modelspace()

    def rect(layer, x, y, w, h):
        msp.add_lwpolyline(
            [(x, y), (x + w, y), (x + w, y + h), (x, y + h)], close=True, dxfattribs={"layer": layer}
        )

    def label(x, y, height, value):
        msp.add_text(value, height=height, dxfattribs={"layer": "TEXT", "insert": (x, y)})

    # Outer walls, 12 by 8 metres, in millimetres, and the partitions.
    rect("WALLS", 0, 0, 12000, 8000)
    rect("WALLS", 200, 200, 11600, 7600)
    for a, b in (((5000, 200), (5000, 3800)), ((5000, 4800), (5000, 7800)), ((5000, 5200), (11800, 5200))):
        msp.add_line(a, b, dxfattribs={"layer": "WALLS"})

    # Doors: a leaf and its swing.
    msp.add_line((5000, 3800), (5900, 3800), dxfattribs={"layer": "DOORS"})
    msp.add_arc((5000, 3800), 900, 0, 90, dxfattribs={"layer": "DOORS"})
    msp.add_line((8000, 5200), (8000, 6100), dxfattribs={"layer": "DOORS"})
    msp.add_arc((8000, 5200), 900, 90, 180, dxfattribs={"layer": "DOORS"})

    # Furniture: a round table and its chairs, a desk, a bed.
    msp.add_circle((2500, 4000), 700, dxfattribs={"layer": "FURNITURE"})
    for dx, dy in ((0, 1000), (0, -1000), (1000, 0), (-1000, 0)):
        msp.add_circle((2500 + dx, 4000 + dy), 250, dxfattribs={"layer": "FURNITURE"})
    rect("FURNITURE", 6000, 600, 1800, 800)
    rect("FURNITURE", 9000, 5500, 2000, 1400)

    # A concrete column, filled.
    rect("COLUMNS", 5900, 4400, 400, 400)
    column = msp.add_hatch(dxfattribs={"layer": "COLUMNS"})
    column.set_solid_fill(color=256)
    column.paths.add_polyline_path(
        [(5900, 4400), (6300, 4400), (6300, 4800), (5900, 4800)], is_closed=True
    )

    label(1200, 6800, 350, "LIVING ROOM")
    label(6200, 2600, 350, "STUDY")
    label(8600, 7300, 350, "BEDROOM")
    label(200, -900, 250, "exav demo plan, 1:100")

    doc.layouts.new("A3 sheet")
    return doc


def main():
    os.makedirs(OUT, exist_ok=True)
    dxf = os.path.join(OUT, "plan.dxf")
    plan().saveas(dxf)
    print(f"wrote {dxf}")
    odafc = os.environ.get("ODAFC")
    if not odafc:
        print("ODAFC not set: plan.dwg left as it is")
        return
    with tempfile.TemporaryDirectory() as src, tempfile.TemporaryDirectory() as dst:
        shutil.copy(dxf, src)
        subprocess.run([odafc, src, dst, "ACAD2018", "DWG", "plan.dxf"], check=True)
        made = os.path.join(dst, "plan.dwg")
        if not os.path.exists(made) or os.path.getsize(made) == 0:
            sys.exit("the converter wrote no plan.dwg")
        shutil.copy(made, os.path.join(OUT, "plan.dwg"))
    print(f"wrote {os.path.join(OUT, 'plan.dwg')}")


if __name__ == "__main__":
    main()
