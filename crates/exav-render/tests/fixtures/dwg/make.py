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
- wide: LWPOLYLINEs with width: a 10 by 2 band, a donut and a taper.
- sheets: layouts "Metric" (millimetres) and "Imperial" (inches), each with a
  square an inch across and a line 2.11 mm wide.
- viewport_text: a layout "Sheet" whose viewport (40 by 20 at 100,100)
  shows model x -10 to 30 of a text running from 0 to about 60, and not a
  second text at x 200.
- xclip: a block TILE (base 5,5: a diagonal line, an xline, a text)
  inserted at 2x and 90 degrees at x 100, 300 and 500, clipped to world
  80..100 by 0..20, to a triangle (280,0) (300,0) (300,20), and with
  clipping off.
- transparency: at half opacity, a red hatch over a green line (x 40..60),
  a blue V (150..250), a cyan hatch over magenta text (290..410), and a
  line on layer GREY in its layer's colour (y -40); lineweights shown.
- not_drawn: a line, two inserts of the xref WALLS (walls.dwg) at (10,10)
  and (50,10), an image of photo.png, two 3DSOLIDs and a REGION.
- image_crops: a 100 by 200 image at the origin cropped to the pixels
  (10,20) (60,70), and one at x 200 cropped to a triangle.
- xref_title, xref_part: the files xref_sheet's reference TITLE names
  (title.dwg), and the one it refers to in turn (part.dwg, a line on layer
  PARTLINE). title.dwg is a 100 by 50 frame on layer FRAME, a block MARK
  (a circle of radius 2) at (50,25), a text in style LABELS and PART at
  (20,20).
- wipeout_triangle: a WIPEOUT over the triangle (100,200) (140,200) (100,210).
- solid_only: one 3DSOLID, and an 8 by 8 red thumbnail.
- text_frames: a block LABEL (an Arial "LABEL" and a stroke "STROKE" 5
  below) inserted mirrored at x 100 and stretched twice in x at (100,20);
  TEXT backward and upside down, 2.5 high, at (150,0) and (150,10), a
  backward stroke "BACK" at (150,20); Bottom Left at (200,0) in Arial and
  (200,10) in the stroke font, MIDDLE at (200,20), 3 high; "WIDE", 1 high,
  width factor 2, Aligned from (250,0) to (270,0).
- text_symbols: TEXT 2.5 high at x 0: Chinese in txt.shx with a bigfont (y
  0), "abg" in greeks.shx (10) and in symbol.ttf (20), "n0.05" in gdt.shx
  (30), "%%065%%066" (40); a block TAG at (0,60) with a constant ATTDEF
  "CONSTANT" and a constant invisible one "SECRET" 5 below.
- text_mtext: MTEXT 2.5 high in Arial at x 0: in a style of width factor 2
  (y 0), one slanted 30 degrees (10), tracked, half-width and slanted runs
  (20), masked in yellow at scale 1.5 (30; framed, in the drawing's
  background, at x 50), a centred paragraph in a box 50 wide (50), "1" and a
  stacked 1/2 (60); a multiline ATTRIB "MULTI" / "LINE ATTR" at (100,55); a
  MULTILEADER whose text has a red "red".
- text_many: every Latin, Greek and Cyrillic character in each of the
  twelve bundled faces, centred at y +-1000 and beyond, and "HE" 10 high
  centred on the origin.
- dense_hatch: ANSI31 at scale 0.001 over a red square 1000 across, and at
  0.01 over a blue square 1 across at x 2000.
- gaps: a 3DFACE 10 square with its first and third edges hidden (x 0); a
  POINT in $PDMODE 35 (a cross in a circle), $PDSIZE 2 (100); a unit cube as
  a polyface mesh (200); a 3 by 3 polygon mesh (300); a unit cube MESH (400);
  a TOLERANCE in a style 2 high with a gap of 0.5, "position | 0.05 | A"
  (500); a LEADER whose style's leader arrow is _DOT, size 2, tip (600,0);
  a MULTILEADER with an arrow of 3, tip (700,0).
- halo: a red line 2.11 mm wide from (0,50) to (100,50), then a thin dark
  grey (ACI 250) line across it from (50,-100) to (50,60); lineweights
  shown.
- stray: a 100 by 100 grid of lines from (38985257, 5800000), a circle of
  radius 0.5 at its (50.25, 50.25), and a line from (0,0) to (1,1).
- circle: a circle of radius 100 about the origin.
- complex_linetypes: lines from x 0 to 2.9 at y 0, 10... 50 in acad.lin's
  FENCELINE2, FENCELINE1, TRACKS, ZIGZAG, BATTING (ltypeshp.shx shapes) and
  GAS_LINE (its text in Arial).
- dimensions: dimensions saved without their block or text position, their
  text in Arial, in a style ISO (text above, 2 places, trailing zeros off,
  comma) unless said:
  linear (0,0)-(100,0) on y 20; aligned (200,0)-(230,40) 10 off; radius 30
  about (400,0) at 45 degrees; diameter 50 about (500,0); 90 degrees about
  (600,0) by three points; 45 degrees between two lines from (700,0); an X
  ordinate of (800,10) out to y 40; in a style TICKS (ticks, text on the
  line, no places) (0,-50)-(100.5,-50) on y -30; "<> mm" for
  (900,0)-(1012.25,0).
- plinegen: an LWPOLYLINE from (0,0) to (10.75,0) to (10.75,10) in a
  linetype of dashes and gaps of 0.5, with PLINEGEN; the same at y 20
  without it.
- colours: a yellow line (y 0) and a red one (y 20), 2.11 mm wide, and a
  cyan fill from y 40 to 60; lineweights shown.
- xref_sheet: $TEXTSIZE 40 and an xref TITLE (title.dwg) in model space at
  (10,10) and, at scale 10 at (1,1), on a 297 by 210 layout "Sheet".

ezdxf orders some objects by Python's string hashes: a run without
PYTHONHASHSEED set rewrites the other files with their objects shuffled, the
drawings the same.
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
    "xclip": ["ACAD2018", "ACAD2000"],
    "transparency": ["ACAD2018"],
    "not_drawn": ["ACAD2018"],
    "gaps": ["ACAD2018"],
    "plinegen": ["ACAD2018"],
    "complex_linetypes": ["ACAD2018"],
}
# Not converted: dimensions, which the converter gives blocks.


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


def wide():
    doc = new()
    msp = doc.modelspace()
    # A 10 by 2 band, a DONUT (inside 6, outside 10, at 50,0) and an arrow
    # tapering from 4 to 0 over 10.
    msp.add_lwpolyline([(0, 0), (10, 0)], dxfattribs={"const_width": 2})
    msp.add_lwpolyline([(46, 0, 2, 2, 1), (54, 0, 2, 2, 1)], format="xyseb", close=True)
    msp.add_lwpolyline([(0, 20, 4, 0), (10, 20, 0, 0)], format="xyse")
    return doc


def sheets():
    doc = new()
    doc.header["$LWDISPLAY"] = 1
    doc.modelspace().add_line((0, 0), (1, 1))
    # A square of one inch, on a sheet in millimetres and on one in inches,
    # beside a line 2.11 mm wide.
    for name, units, side in (("Metric", "mm", 25.4), ("Imperial", "inch", 1.0)):
        layout = doc.layouts.new(name)
        size = (297, 210) if units == "mm" else (11, 8.5)
        layout.page_setup(size=size, margins=(0, 0, 0, 0), units=units)
        layout.add_lwpolyline([(0, 0), (side, 0), (side, side), (0, side)], close=True)
        layout.add_line((0, -side), (side, -side), dxfattribs={"lineweight": 211})
    return doc


def viewport_text():
    doc = new()
    doc.styles.add("LABELS", font="arial.ttf")
    msp = doc.modelspace()
    # Text from x 0 to about 60, a viewport onto x -10 to 30 of it, and a
    # second text wholly outside the window.
    msp.add_text("CLIPPED TEXT RUNS ON", height=5, dxfattribs={"insert": (0, 0), "style": "LABELS"})
    msp.add_text("OUTSIDE", height=5, dxfattribs={"insert": (200, 0), "style": "LABELS"})
    layout = doc.layouts.new("Sheet")
    layout.page_setup(size=(297, 210), margins=(0, 0, 0, 0), units="mm")
    layout.add_viewport(center=(100, 100), size=(40, 20), view_center_point=(10, 2), view_height=20)
    return doc


def xclip():
    from ezdxf.xclip import XClip

    doc = new()
    doc.styles.add("LABELS", font="arial.ttf")
    tile = doc.blocks.new("TILE", base_point=(5, 5))
    tile.add_line((0, 0), (20, 20))
    tile.add_xline((10, 10), (1, 0))
    tile.add_text("TILE TEXT RUNS ACROSS", height=2, dxfattribs={"insert": (6, 9), "style": "LABELS"})
    msp = doc.modelspace()
    attribs = {"xscale": 2, "yscale": 2, "rotation": 90}
    a, b, c = (msp.add_blockref("TILE", (x, 0), dxfattribs=attribs) for x in (100, 300, 500))
    # A: a rectangle in block coordinates, as ezdxf writes it.
    XClip(a).set_block_clipping_path([(5, 5), (15, 15)])
    # B: a triangle in world coordinates with the inverse insert matrix, as
    # AutoCAD writes it.
    XClip(b).set_block_clipping_path([(5, 5), (15, 15)])
    f = XClip(b).get_spatial_filter()
    f.set_boundary_vertices([(280, 0), (300, 0), (300, 20)])
    m = b.matrix44()
    m.inverse()
    f.set_inverse_insert_matrix(m)
    # C: clipping turned off.
    XClip(c).set_block_clipping_path([(5, 5), (15, 15)])
    XClip(c).disable_clipping()
    return doc


def transparency():
    doc = new()
    doc.header["$LWDISPLAY"] = 1
    doc.styles.add("LABELS", font="arial.ttf")
    doc.layers.add("GREY", color=8)
    msp = doc.modelspace()
    wide = {"lineweight": 211}
    # A green line under a red hatch at half opacity, drawn after it.
    msp.add_line((0, 0), (100, 0), dxfattribs={"color": 3, **wide})
    red = msp.add_hatch(color=1)
    red.paths.add_polyline_path([(40, -20), (60, -20), (60, 20), (40, 20)])
    red.transparency = 0.5
    # A blue V at half opacity, whose segments meet at (200,-20).
    v = msp.add_lwpolyline([(150, 20), (200, -20), (250, 20)], dxfattribs={"color": 5, **wide})
    v.transparency = 0.5
    # Magenta text under a cyan hatch at half opacity.
    msp.add_text("MMMM", height=20, dxfattribs={"insert": (300, -10), "style": "LABELS", "color": 6})
    cyan = msp.add_hatch(color=4)
    cyan.paths.add_polyline_path([(290, -20), (410, -20), (410, 20), (290, 20)])
    cyan.transparency = 0.5
    # A ByLayer colour at half opacity.
    grey = msp.add_line((0, -40), (100, -40), dxfattribs={"layer": "GREY"})
    grey.transparency = 0.5
    return doc


def not_drawn():
    doc = new()
    msp = doc.modelspace()
    msp.add_line((0, 0), (100, 0))
    doc.add_xref_def("walls.dwg", "WALLS")
    msp.add_blockref("WALLS", (10, 10))
    msp.add_blockref("WALLS", (50, 10))
    photo = doc.add_image_def(filename="photo.png", size_in_pixel=(640, 360))
    msp.add_image(photo, insert=(0, 20), size_in_units=(64, 36))
    for body in (msp.add_3dsolid(), msp.add_3dsolid(), msp.add_region()):
        acis(body)
    return doc


def xref_sheet():
    doc = new()
    doc.header["$TEXTSIZE"] = 40
    doc.add_xref_def("title.dwg", "TITLE")
    doc.modelspace().add_blockref("TITLE", (10, 10))
    layout = doc.layouts.new("Sheet")
    layout.page_setup(size=(297, 210), margins=(0, 0, 0, 0), units="mm")
    layout.add_blockref("TITLE", (1, 1), dxfattribs={"xscale": 10, "yscale": 10, "zscale": 10})
    return doc


def image_crops():
    doc = new()
    msp = doc.modelspace()
    photo = doc.add_image_def(filename="photo.png", size_in_pixel=(100, 200))
    rect = msp.add_image(photo, insert=(0, 0), size_in_units=(100, 200))
    rect.set_boundary_path([(10, 20), (60, 70)])
    tri = msp.add_image(photo, insert=(200, 0), size_in_units=(100, 200))
    tri.set_boundary_path([(10, 20), (60, 20), (60, 70)])
    return doc


def xref_title():
    doc = new()
    doc.layers.add("FRAME", color=1)
    doc.styles.add("LABELS", font="arial.ttf")
    mark = doc.blocks.new("MARK")
    mark.add_circle((0, 0), 2)
    msp = doc.modelspace()
    msp.add_lwpolyline([(0, 0), (100, 0), (100, 50), (0, 50)], close=True, dxfattribs={"layer": "FRAME"})
    msp.add_blockref("MARK", (50, 25))
    msp.add_text("TITLE", height=5, dxfattribs={"style": "LABELS", "insert": (5, 5)})
    doc.add_xref_def("part.dwg", "PART")
    msp.add_blockref("PART", (20, 20))
    return doc


def xref_part():
    doc = new()
    doc.layers.add("PARTLINE", color=3)
    doc.modelspace().add_line((0, 0), (7, 7), dxfattribs={"layer": "PARTLINE"})
    return doc


def wipeout_triangle():
    doc = new()
    msp = doc.modelspace()
    msp.add_wipeout([(100, 200), (140, 200), (100, 210)])
    return doc


def acis(body):
    # A unit cube: ezdxf leaves out a body without ACIS data, and the ODA
    # converter refuses one that is not a real body.
    from ezdxf.acis import api
    from ezdxf.render import forms

    api.export_dxf(body, [api.body_from_mesh(forms.cube())])


def solid_only():
    doc = new()
    acis(doc.modelspace().add_3dsolid())
    return doc


def text_frames():
    from ezdxf.enums import TextEntityAlignment

    doc = new()
    doc.styles.add("LABELS", font="arial.ttf")
    doc.styles.add("WIDE", font="arial.ttf").dxf.width = 2.0
    msp = doc.modelspace()
    label = doc.blocks.new("LABEL")
    label.add_text("LABEL", height=2.5, dxfattribs={"style": "LABELS", "insert": (0, 0)})
    label.add_text("STROKE", height=2.5, dxfattribs={"insert": (0, -5)})
    msp.add_blockref("LABEL", (100, 0), dxfattribs={"xscale": -1})
    msp.add_blockref("LABEL", (100, 20), dxfattribs={"xscale": 2})
    msp.add_text("BACKWARD", height=2.5, dxfattribs={"style": "LABELS", "insert": (150, 0), "text_generation_flag": 2})
    msp.add_text("UPSIDE", height=2.5, dxfattribs={"style": "LABELS", "insert": (150, 10), "text_generation_flag": 4})
    msp.add_text("BACK", height=3, dxfattribs={"insert": (150, 20), "text_generation_flag": 2})
    msp.add_text("BOTTOM", height=3, dxfattribs={"style": "LABELS"}).set_placement(
        (200, 0), align=TextEntityAlignment.BOTTOM_LEFT
    )
    msp.add_text("LOW", height=3).set_placement((200, 10), align=TextEntityAlignment.BOTTOM_LEFT)
    msp.add_text("MIDDLE", height=3).set_placement((200, 20), align=TextEntityAlignment.MIDDLE)
    msp.add_text("WIDE", height=1, dxfattribs={"style": "WIDE", "width": 2.0}).set_placement(
        (250, 0), (270, 0), align=TextEntityAlignment.ALIGNED
    )
    return doc


def text_symbols():
    doc = new()
    doc.styles.add("CN", font="txt.shx").dxf.bigfont = "gbcbig.shx"
    doc.styles.add("GREEK", font="greeks.shx")
    doc.styles.add("SYMB", font="symbol.ttf")
    doc.styles.add("GDT", font="gdt.shx")
    msp = doc.modelspace()
    msp.add_text("中文标注", height=2.5, dxfattribs={"style": "CN", "insert": (0, 0)})
    msp.add_text("abg", height=2.5, dxfattribs={"style": "GREEK", "insert": (0, 10)})
    msp.add_text("abg", height=2.5, dxfattribs={"style": "SYMB", "insert": (0, 20)})
    msp.add_text("n0.05", height=2.5, dxfattribs={"style": "GDT", "insert": (0, 30)})
    msp.add_text("%%065%%066", height=2.5, dxfattribs={"insert": (0, 40)})
    tag = doc.blocks.new("TAG")
    tag.add_attdef("SHOWN", (0, 0), "CONSTANT", dxfattribs={"height": 2.5, "flags": 2})
    tag.add_attdef("HIDDEN", (0, -5), "SECRET", dxfattribs={"height": 2.5, "flags": 3})
    msp.add_blockref("TAG", (0, 60))
    return doc


def text_mtext():
    from ezdxf.math import Vec2
    from ezdxf.render import mleader

    doc = new()
    doc.styles.add("LABELS", font="arial.ttf")
    doc.styles.add("WIDE", font="arial.ttf").dxf.width = 2.0
    doc.styles.add("OBL", font="arial.ttf").dxf.oblique = 30
    msp = doc.modelspace()

    def mtext(s, at, **attribs):
        return msp.add_mtext(s, dxfattribs={"insert": at, "char_height": 2.5, "style": "LABELS", **attribs})

    mtext("WIDE MTEXT", (0, 0), style="WIDE")
    mtext("OBL MTEXT", (0, 10), style="OBL")
    mtext(r"{\T2;tracked} {\W0.5;half} {\Q20;slant}", (0, 20))
    mtext("MASKED", (0, 30)).set_bg_color(2, scale=1.5)
    mtext("FRAMED", (50, 30)).set_bg_color("canvas", scale=1.5, text_frame=True)
    mtext(r"\pxqc;centred\Pa longer second line", (0, 50), width=50)
    mtext(r"1\S1/2;", (0, 60))
    label = doc.blocks.new("LBL")
    label.add_attdef("TAG", (0, 0), dxfattribs={"height": 2.5, "style": "LABELS"})
    insert = msp.add_blockref("LBL", (100, 60))
    attrib = insert.add_attrib("TAG", "x", insert=(100, 55), dxfattribs={"height": 2.5, "style": "LABELS"})
    embedded = ezdxf.entities.MText.new(dxfattribs={"insert": (100, 55), "char_height": 2.5, "style": "LABELS"})
    embedded.text = r"MULTI\PLINE ATTR"
    attrib.embed_mtext(embedded)
    leader = msp.add_multileader_mtext("Standard")
    leader.set_content(r"ML {\C1;red} text", char_height=2.5, style="LABELS")
    leader.add_leader_line(mleader.ConnectionSide.left, [Vec2(200, 10), Vec2(195, 5)])
    leader.build(insert=Vec2(205, 15))
    return doc


def text_many():
    doc = new()
    msp = doc.modelspace()
    # Every Latin, Greek and Cyrillic character in each of the twelve
    # bundled faces, far above and below: more cells than the atlas budget
    # affords at a large em.
    chars = "".join(chr(c) for c in [*range(0x21, 0x250), *range(0x391, 0x3CA), *range(0x410, 0x450)])
    fonts = [
        "arial.ttf", "arialbd.ttf", "ariali.ttf", "arialbi.ttf",
        "times.ttf", "timesbd.ttf", "timesi.ttf", "timesbi.ttf",
        "cour.ttf", "courbd.ttf", "couri.ttf", "courbi.ttf",
    ]
    for i, font in enumerate(fonts):
        doc.styles.add(f"F{i}", font=font)
        for y in (1000 + i * 10, -1000 - i * 10):
            msp.add_text(chars, height=1, dxfattribs={"style": f"F{i}"}).set_placement(
                (0, y), align=ezdxf.enums.TextEntityAlignment.CENTER
            )
    msp.add_text("HE", height=10, dxfattribs={"style": "F0"}).set_placement(
        (0, 0), align=ezdxf.enums.TextEntityAlignment.MIDDLE_CENTER
    )
    return doc


def dense_hatch():
    doc = new()
    msp = doc.modelspace()
    # ANSI31 at a thousandth over 1000 units: millions of lines.
    dense = msp.add_hatch()
    dense.set_pattern_fill("ANSI31", color=1, scale=0.001)
    dense.paths.add_polyline_path([(0, 0), (1000, 0), (1000, 1000), (0, 1000)])
    # At a hundredth over one unit: lines 0.03 apart, some forty of them.
    fine = msp.add_hatch()
    fine.set_pattern_fill("ANSI31", color=5, scale=0.01)
    fine.paths.add_polyline_path([(2000, 0), (2001, 0), (2001, 1), (2000, 1)])
    return doc


def gaps():
    from ezdxf.math import Vec2
    from ezdxf.render import forms, mleader

    doc = new()
    doc.header["$PDMODE"] = 35
    doc.header["$PDSIZE"] = 2
    msp = doc.modelspace()
    # A square face with its first and third edges hidden.
    msp.add_3dface([(0, 0), (10, 0), (10, 10), (0, 10)], dxfattribs={"invisible_edges": 5})
    # A point as a cross in a circle, 2 across.
    msp.add_point((100, 0))
    # A unit cube as a polyface mesh, a 3 by 3 polygon mesh and a MESH.
    cube = forms.cube().translate(200, 0, 0)
    face = msp.add_polyface()
    face.append_faces([[cube.vertices[i] for i in f] for f in cube.faces])
    grid = msp.add_polymesh((3, 3))
    for i in range(3):
        for j in range(3):
            grid.set_mesh_vertex((i, j), (300 + j, i, 0))
    mesh = msp.add_mesh()
    with mesh.edit_data() as data:
        data.vertices = [(x + 400, y, z) for x, y, z in forms.cube().vertices]
        data.faces = list(forms.cube().faces)
    # A feature control frame: position, 0.05, datum A.
    doc.dimstyles.new("TOL", dxfattribs={"dimtxt": 2, "dimgap": 0.5, "dimscale": 1})
    msp.new_entity("TOLERANCE", {"insert": (500, 0), "dimstyle": "TOL", "content": r"{\Fgdt;j}%%v0.05%%vA"})
    # A leader whose style draws a dot.
    doc.dimstyles.new("DOTS", dxfattribs={"dimasz": 2})
    doc.dimstyles.get("DOTS").set_arrows(ldrblk="DOT")
    msp.add_leader([(600, 0), (610, 10), (620, 10)], dimstyle="DOTS")
    leader = msp.add_multileader_mtext("Standard")
    leader.set_content("NOTE", char_height=2.5)
    leader.set_arrow_properties(size=3)
    leader.add_leader_line(mleader.ConnectionSide.left, [Vec2(700, 0)])
    leader.build(insert=Vec2(710, 10))
    return doc


def halo():
    doc = new()
    doc.header["$LWDISPLAY"] = 1
    msp = doc.modelspace()
    # A wide red line, then a thin black one across it whose middle, lower
    # down, puts it in an earlier spatial bucket: drawn first, behind.
    msp.add_line((0, 50), (100, 50), dxfattribs={"color": 1, "lineweight": 211})
    msp.add_line((50, -100), (50, 60), dxfattribs={"color": 250})
    return doc


def stray():
    doc = new()
    msp = doc.modelspace()
    # A plan in national grid coordinates, a circle 0.5 across in it, and
    # one line forgotten at the origin.
    x0, y0 = 38_985_257.0, 5_800_000.0
    for i in range(100):
        msp.add_line((x0 + i, y0), (x0 + i, y0 + 99))
        msp.add_line((x0, y0 + i), (x0 + 99, y0 + i))
    msp.add_circle((x0 + 50.25, y0 + 50.25), 0.5)
    msp.add_line((0, 0), (1, 1))
    return doc


def plinegen():
    doc = new()
    doc.linetypes.add("HALF", pattern=[1.0, 0.5, -0.5])
    msp = doc.modelspace()
    # The pattern reaches the corner in a gap: carried on (PLINEGEN, at
    # y 0), the second segment starts with it; started afresh (y 20), with a
    # dash.
    for y, flags in ((0, 128), (20, 0)):
        lw = msp.add_lwpolyline([(0, y), (10.75, y), (10.75, y + 10)], dxfattribs={"linetype": "HALF"})
        lw.dxf.flags = flags
    return doc


def colours():
    doc = new()
    doc.header["$LWDISPLAY"] = 1
    msp = doc.modelspace()
    # A yellow line and a red one, wide enough to measure, and a cyan fill.
    msp.add_line((0, 0), (100, 0), dxfattribs={"color": 2, "lineweight": 211})
    msp.add_line((0, 20), (100, 20), dxfattribs={"color": 1, "lineweight": 211})
    fill = msp.add_hatch(color=4)
    fill.paths.add_polyline_path([(0, 40), (100, 40), (100, 60), (0, 60)])
    return doc


def circle():
    doc = new()
    doc.modelspace().add_circle((0, 0), 100)
    return doc


def dimensions():
    doc = new()
    doc.styles.add("DIMS", font="arial.ttf")
    common = {"dimasz": 2.5, "dimtxt": 2.5, "dimexo": 0.625, "dimexe": 1.25, "dimgap": 0.625, "dimtxsty": "DIMS"}
    doc.dimstyles.new("ISO", dxfattribs={**common, "dimtad": 1, "dimdec": 2, "dimzin": 8, "dimdsep": 44})
    doc.dimstyles.new("TICKS", dxfattribs={**common, "dimtad": 0, "dimdec": 0, "dimtsz": 1.5, "dimdle": 1.25})
    msp = doc.modelspace()
    # Not rendered: no block, no text position, as some generators write them.
    iso = {"dimstyle": "ISO"}
    msp.add_linear_dim(base=(50, 20), p1=(0, 0), p2=(100, 0), **iso)
    msp.add_aligned_dim(p1=(200, 0), p2=(230, 40), distance=10, **iso)
    msp.add_radius_dim(center=(400, 0), radius=30, angle=45, **iso)
    msp.add_diameter_dim(center=(500, 0), radius=25, angle=0, **iso)
    msp.add_angular_dim_3p(base=(620, 20), center=(600, 0), p1=(650, 0), p2=(600, 50), **iso)
    msp.add_angular_dim_2l(base=(725, 10), line1=((700, 0), (760, 0)), line2=((700, 0), (742.4264, 42.4264)), **iso)
    msp.add_ordinate_x_dim(feature_location=(800, 10), offset=(0, 30), **iso)
    msp.add_linear_dim(base=(50, -30), p1=(0, -50), p2=(100.5, -50), dimstyle="TICKS")
    mm = msp.add_linear_dim(base=(950, 20), p1=(900, 0), p2=(1012.25, 0), **iso).dimension
    mm.dxf.text = "<> mm"
    return doc


def complex_linetypes():
    doc = new()
    doc.styles.add("LABELS", font="arial.ttf")
    msp = doc.modelspace()
    # acad.lin's definitions, with ltypeshp.shx's shape numbers for names.
    types = [
        ("FENCELINE2", "A,.25,-.1,[132,ltypeshp.shx,x=-.1,s=.1],-.1,1", 1.45),
        ("FENCELINE1", "A,.25,-.1,[133,ltypeshp.shx,x=-.1,s=.1],-.1,1", 1.45),
        ("TRACKS", "A,.15,[130,ltypeshp.shx,s=.25],.15", 0.3),
        ("ZIGZAG", "A,.0001,-.2,[131,ltypeshp.shx,x=-.2,s=.2],-.4,[131,ltypeshp.shx,r=180,x=.2,s=.2],-.2", 0.8001),
        ("BATTING", "A,.0001,-.1,[134,ltypeshp.shx,x=-.1,s=.1],-.2,[134,ltypeshp.shx,r=180,x=.1,s=.1],-.1", 0.4001),
        ("GAS_LINE", 'A,.5,-.2,["GAS",LABELS,S=.1,R=0.0,X=-0.1,Y=-.05],-.25', 0.95),
    ]
    for i, (name, pattern, length) in enumerate(types):
        doc.linetypes.add(name, pattern=pattern, length=length, description=name)
        msp.add_line((0, 10 * i), (2.9, 10 * i), dxfattribs={"linetype": name})
    return doc


def thumbnail(data):
    """A THUMBNAILIMAGE section before EOF: an 8 by 8 red bitmap."""
    w = h = 8
    header = (40).to_bytes(4, "little") + w.to_bytes(4, "little") + h.to_bytes(4, "little")
    header += (1).to_bytes(2, "little") + (24).to_bytes(2, "little") + bytes(24)
    dib = header + bytes([0, 0, 255]) * (w * h)
    section = f"  0\nSECTION\n  2\nTHUMBNAILIMAGE\n 90\n{len(dib)}\n310\n{dib.hex().upper()}\n  0\nENDSEC\n"
    at = data.rindex(b"  0\nEOF")
    return data[:at] + section.encode() + data[at:]


DRAWINGS = {
    "plan": plan,
    "hostile": hostile,
    "lines200": lines200,
    "hatch7": hatch7,
    "attribs": attribs,
    "leader": leader,
    "layouts": layouts,
    "wide": wide,
    "sheets": sheets,
    "viewport_text": viewport_text,
    "xclip": xclip,
    "transparency": transparency,
    "not_drawn": not_drawn,
    "xref_sheet": xref_sheet,
    "image_crops": image_crops,
    "xref_title": xref_title,
    "xref_part": xref_part,
    "wipeout_triangle": wipeout_triangle,
    "solid_only": solid_only,
    "text_frames": text_frames,
    "text_symbols": text_symbols,
    "text_mtext": text_mtext,
    "text_many": text_many,
    "dense_hatch": dense_hatch,
    "gaps": gaps,
    "halo": halo,
    "stray": stray,
    "circle": circle,
    "complex_linetypes": complex_linetypes,
    "dimensions": dimensions,
    "plinegen": plinegen,
    "colours": colours,
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
        if name == "solid_only":
            data = thumbnail(data)
        sources[name] = data
        write_gz(os.path.join(HERE, name + ".dxf.gz"), data)
    if "--convert" in sys.argv:
        convert(sources)
