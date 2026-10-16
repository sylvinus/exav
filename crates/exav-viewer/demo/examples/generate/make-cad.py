#!/usr/bin/env python3
"""Writes the demo's DXF drawing examples into ../files/cad/.

    python3 -I make-cad.py [OUT_DIR]

Output: CC0-1.0, a public domain dedication by the exav project. Every
drawing is made here from scratch with ezdxf (MIT licence; tested with
1.4.1), with no outside drawing or block library. Two runs draw the same
drawing; the bytes differ in the order of a few table objects (ezdxf's
dictionaries follow the hash seed). The dates and GUIDs are fixed.

Needs: Python 3 and ezdxf 1.4.

- house-plan.dxf (2018), house-plan-r2000.dxf: a two-room-wide house plan,
  walls with openings, door and window blocks with attributes, furniture
  blocks, axes with bubbles, room labels, linear, aligned, radius and angular
  dimensions, hatches, a paper-space sheet with a title block and a viewport.
- house-elevations.dxf: four elevations and a section in 2D, with ground
  hatching, roof, windows, levels and height dimensions.
- hatch-gallery.dxf: the predefined patterns, gradients, solid fills, islands
  and boundaries made of arcs, ellipses and splines.
- dimensions.dxf: every dimension type, in two dimension styles.
- linetypes.dxf: the standard and custom linetypes (text and shapes inside),
  line weights, line type scales, wide and generated polylines.
- text-styles.dxf: fonts, width and oblique factors, mirrored and rotated
  text, MTEXT formatting, columns, background, special characters.
- blocks.dxf: nested blocks, attributes, arrays, mirrored and scaled inserts.
- bracket.dxf: a mechanical part with centre and hidden lines, a section,
  dimensions with tolerances and a title block.
- site-plan.dxf: contour lines (splines and polylines), parcels, points with
  heights, a legend and a north arrow.
- legacy-r12.dxf: a drawing in the R12 format.
"""
import math
import os
import sys

import ezdxf
from ezdxf import colors, zoom
from ezdxf.enums import TextEntityAlignment
from ezdxf.math import Vec2
from ezdxf.render.mleader import ConnectionSide
from ezdxf.tools import pattern

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(HERE, "..", "files", "cad")
os.makedirs(OUT, exist_ok=True)

# Fixed dates, GUIDs and creator line in the files, so that two runs give the same bytes.
ezdxf.options.write_fixed_meta_data_for_testing = True


def new(version="R2018", units=4):
    doc = ezdxf.new(version, setup=["linetypes"])
    doc.units = units
    return doc


def save(doc, name, extents=True):
    if extents:
        zoom.extents(doc.modelspace(), factor=1.05)
    doc.saveas(os.path.join(OUT, name))


def layer(doc, name, color=7, linetype="Continuous", weight=25, **kw):
    return doc.layers.add(name, color=color, linetype=linetype, lineweight=weight, **kw)


def text_style(doc, name, font, **kw):
    style = doc.styles.add(name, font=font)
    for key, value in kw.items():
        setattr(style.dxf, key, value)
    return style


def dimstyle(doc, name, scale_text=125, **over):
    ds = doc.dimstyles.new(name)
    ds.dxf.dimtxt = scale_text
    ds.dxf.dimasz = scale_text * 0.8
    ds.dxf.dimexe = scale_text * 0.6
    ds.dxf.dimexo = scale_text * 0.8
    ds.dxf.dimgap = scale_text * 0.3
    ds.dxf.dimdec = 0
    ds.dxf.dimtad = 1
    ds.dxf.dimclrd = 3
    ds.dxf.dimclre = 3
    ds.dxf.dimclrt = 2
    for k, v in over.items():
        setattr(ds.dxf, k, v)
    return ds


def rect(msp, x0, y0, x1, y1, **attr):
    return msp.add_lwpolyline([(x0, y0), (x1, y0), (x1, y1), (x0, y1)], close=True, dxfattribs=attr)


# ----------------------------------------------------------------- blocks


def make_blocks(doc):
    door = doc.blocks.new("DOOR")
    # A leaf 900 wide, open to 90 degrees, with its swing.
    door.add_line((0, 0), (0, 900), dxfattribs={"layer": "A-DOOR"})
    door.add_arc((0, 0), 900, 0, 90, dxfattribs={"layer": "A-DOOR", "linetype": "DASHED"})
    door.add_lwpolyline([(0, 0), (900, 0), (900, 40), (0, 40)], close=True, dxfattribs={"layer": "A-DOOR"})
    door.add_attdef("TAG", (350, -330), text="D-000", height=110, dxfattribs={"layer": "A-ANNO"})
    win = doc.blocks.new("WINDOW")
    # Unit width; the frame is scaled in x to the opening and in y to the wall.
    for y in (0.0, 0.35, 0.65, 1.0):
        win.add_line((0, y), (1, y), dxfattribs={"layer": "A-WIND"})
    win.add_line((0, 0), (0, 1), dxfattribs={"layer": "A-WIND"})
    win.add_line((1, 0), (1, 1), dxfattribs={"layer": "A-WIND"})
    bed = doc.blocks.new("BED")
    rect(bed, 0, 0, 1600, 2000, layer="A-FURN")
    rect(bed, 80, 1300, 760, 1920, layer="A-FURN")
    rect(bed, 840, 1300, 1520, 1920, layer="A-FURN")
    bed.add_line((0, 1200), (1600, 1200), dxfattribs={"layer": "A-FURN"})
    table = doc.blocks.new("TABLE")
    rect(table, 0, 0, 1800, 900, layer="A-FURN")
    for i in range(4):
        x = 150 + i * 450
        rect(table, x, -450, x + 400, -50, layer="A-FURN")
        rect(table, x, 950, x + 400, 1350, layer="A-FURN")
    sofa = doc.blocks.new("SOFA")
    rect(sofa, 0, 0, 2200, 950, layer="A-FURN")
    rect(sofa, 0, 0, 2200, 250, layer="A-FURN")
    for i in range(3):
        rect(sofa, 120 + i * 650, 300, 120 + i * 650 + 600, 900, layer="A-FURN")
    wc = doc.blocks.new("WC")
    rect(wc, 0, 0, 400, 200, layer="A-FIXT")
    wc.add_ellipse((200, -250), major_axis=(0, 230), ratio=0.8, dxfattribs={"layer": "A-FIXT"})
    sink = doc.blocks.new("SINK")
    rect(sink, 0, 0, 600, 450, layer="A-FIXT")
    sink.add_circle((300, 225), 160, dxfattribs={"layer": "A-FIXT"})
    sink.add_circle((300, 225), 25, dxfattribs={"layer": "A-FIXT"})
    bath = doc.blocks.new("BATH")
    rect(bath, 0, 0, 1700, 750, layer="A-FIXT")
    bath.add_lwpolyline([(100, 100), (1500, 100), (1600, 375), (1500, 650), (100, 650)], close=True, dxfattribs={"layer": "A-FIXT"})
    bubble = doc.blocks.new("AXIS")
    bubble.add_circle((0, 0), 300, dxfattribs={"layer": "A-GRID"})
    bubble.add_attdef("ID", (0, 0), text="A", height=300, dxfattribs={"layer": "A-GRID", "halign": 4, "valign": 0, "align_point": (0, 0)})
    north = doc.blocks.new("NORTH")
    north.add_circle((0, 0), 500, dxfattribs={"layer": "A-ANNO"})
    north.add_solid([(0, 650), (-170, -400), (0, -200), (170, -400)], dxfattribs={"layer": "A-ANNO", "color": 7})
    north.add_text("N", height=300, dxfattribs={"layer": "A-ANNO"}).set_placement((0, 800), align=TextEntityAlignment.BOTTOM_CENTER)
    level = doc.blocks.new("LEVEL")
    level.add_lwpolyline([(-250, 250), (0, 0), (250, 250)], close=True, dxfattribs={"layer": "A-ANNO"})
    level.add_line((-250, 250), (900, 250), dxfattribs={"layer": "A-ANNO"})
    level.add_attdef("H", (320, 290), text="+0.00", height=120, dxfattribs={"layer": "A-ANNO"})


def wall(msp, p1, p2, t, openings=(), layer="A-WALL", hatch=True):
    """A wall along p1 to p2 of thickness t (centre line), cut at the openings
    [(offset, width)]. Each piece is a closed polyline with its hatch."""
    v = Vec2(p2) - Vec2(p1)
    length = v.magnitude
    d = v.normalize()
    n = Vec2(-d.y, d.x) * (t / 2)
    cuts = sorted(openings)
    pos = 0.0
    pieces = []
    for off, width in cuts:
        pieces.append((pos, off))
        pos = off + width
    pieces.append((pos, length))
    for a, b in pieces:
        if b - a < 1:
            continue
        pts = [Vec2(p1) + d * a + n, Vec2(p1) + d * b + n, Vec2(p1) + d * b - n, Vec2(p1) + d * a - n]
        msp.add_lwpolyline(pts, close=True, dxfattribs={"layer": layer})
        if hatch:
            h = msp.add_hatch(color=8, dxfattribs={"layer": "A-WALL-PAT"})
            h.set_pattern_fill("ANSI31", color=8, scale=40)
            h.paths.add_polyline_path([(p.x, p.y) for p in pts], is_closed=True)
    # Door and window jambs.
    for off, width in cuts:
        for o in (off, off + width):
            msp.add_line(Vec2(p1) + d * o + n, Vec2(p1) + d * o - n, dxfattribs={"layer": layer})


# ------------------------------------------------------------- the house


W, D = 10000, 8000  # outer size (centre lines of the outer walls)
EXT, INT = 300, 150


def house_layers(doc):
    layer(doc, "A-WALL", 7, weight=50)
    layer(doc, "A-WALL-PAT", 8, weight=9)
    layer(doc, "A-DOOR", 3, weight=25)
    layer(doc, "A-WIND", 5, weight=25)
    layer(doc, "A-FURN", 9, weight=13)
    layer(doc, "A-FIXT", 4, weight=18)
    layer(doc, "A-GRID", 1, linetype="CENTER", weight=9)
    layer(doc, "A-ANNO", 2, weight=18)
    layer(doc, "A-DIMS", 3, weight=13)
    layer(doc, "A-AREA", 6, weight=9)
    layer(doc, "A-FLOR", 252, weight=9)
    layer(doc, "A-SLAB", 254, weight=9)
    layer(doc, "A-STAIR", 30, weight=18)
    layer(doc, "A-SHEET", 7, weight=35)
    layer(doc, "A-VPORT", 7, weight=9, plot=False)


def house_plan(version, name):
    doc = new(version)
    house_layers(doc)
    doc.ltscale = 50
    text_style(doc, "ARCH-TEXT", "arial.ttf")
    text_style(doc, "ARCH-TITLE", "times.ttf", width=1.0)
    text_style(doc, "ARCH-NOTE", "arial.ttf", oblique=15, width=0.9)
    dimstyle(doc, "PLAN50", 220, dimtxsty="ARCH-TEXT")
    make_blocks(doc)
    msp = doc.modelspace()

    ow, od = W, D
    # Floor slab, under the walls.
    h = msp.add_hatch(color=254, dxfattribs={"layer": "A-SLAB"})
    h.set_solid_fill(color=254)
    h.paths.add_polyline_path([(0, 0), (ow, 0), (ow, od), (0, od)], is_closed=True)

    # Outer walls with the front door and windows.
    wall(msp, (0, 0), (ow, 0), EXT, [(1400, 1500), (3600, 900), (6200, 900), (8200, 1200)])
    wall(msp, (ow, 0), (ow, od), EXT, [(1500, 1300), (4800, 1300)])
    wall(msp, (ow, od), (0, od), EXT, [(1200, 1400), (3600, 1600), (6600, 1200)])
    wall(msp, (0, od), (0, 0), EXT, [(1600, 1400), (5000, 1400)])
    # Inner walls: a hall in the middle, a bathroom and two bedrooms.
    wall(msp, (0, 4200), (6200, 4200), INT, [(600, 900), (2700, 900), (4800, 900)])
    wall(msp, (6200, 0), (6200, 4200), INT, [(1700, 900)])
    wall(msp, (6200, 4200), (6200, od), INT, [(6000 - 4200 + 300, 900)])
    wall(msp, (3500, 0), (3500, 4200), INT, [(2400, 900)])
    wall(msp, (6200, 4200), (ow, 4200), INT, [])
    wall(msp, (8200, 4200), (8200, od), INT, [(1600, 900)])

    # Doors: block, rotated and mirrored to swing the right way.
    msp.add_blockref("DOOR", (1700, 150), dxfattribs={"layer": "A-DOOR", "rotation": 0}).add_auto_attribs({"TAG": "D-101"})
    msp.add_blockref("DOOR", (6275, 1700), dxfattribs={"layer": "A-DOOR", "rotation": 90}).add_auto_attribs({"TAG": "D-102"})
    msp.add_blockref("DOOR", (3575, 2400), dxfattribs={"layer": "A-DOOR", "rotation": 90}).add_auto_attribs({"TAG": "D-103"})
    msp.add_blockref("DOOR", (700, 4275), dxfattribs={"layer": "A-DOOR", "rotation": 0, "yscale": -1.0}).add_auto_attribs({"TAG": "D-104"})
    msp.add_blockref("DOOR", (2800, 4275), dxfattribs={"layer": "A-DOOR", "rotation": 0}).add_auto_attribs({"TAG": "D-105"})
    msp.add_blockref("DOOR", (4900, 4275), dxfattribs={"layer": "A-DOOR", "rotation": 0, "yscale": -1.0}).add_auto_attribs({"TAG": "D-106"})
    msp.add_blockref("DOOR", (8275, 5800), dxfattribs={"layer": "A-DOOR", "rotation": 90}).add_auto_attribs({"TAG": "D-107"})

    # Windows: the unit block stretched over each opening and the wall's thickness.
    def window(p, width, vertical, thick=EXT):
        x, y = p
        if vertical:
            msp.add_blockref("WINDOW", (x + thick / 2, y), dxfattribs={"layer": "A-WIND", "xscale": width, "yscale": thick, "rotation": 90})
        else:
            msp.add_blockref("WINDOW", (x, y - thick / 2), dxfattribs={"layer": "A-WIND", "xscale": width, "yscale": thick})

    for x, w in [(3600, 900), (6200, 900), (8200, 1200)]:
        window((x, 0), w, False)
    for y, w in [(4800, 1300)]:
        window((ow, y), w, True)
    for x, w in [(1200, 1400), (3600, 1600), (6600, 1200)]:
        window((x, od), w, False)
    for y, w in [(5000, 1400)]:
        window((0, y), w, True)

    # Furniture and fixtures.
    msp.add_blockref("SOFA", (1200, 6900), dxfattribs={"layer": "A-FURN"})
    msp.add_blockref("TABLE", (3900, 5300), dxfattribs={"layer": "A-FURN", "rotation": 0})
    msp.add_blockref("BED", (4300, 400), dxfattribs={"layer": "A-FURN", "xscale": 1.0})
    msp.add_blockref("BED", (500, 600), dxfattribs={"layer": "A-FURN", "rotation": 0, "xscale": 0.8, "yscale": 0.9})
    msp.add_blockref("BATH", (7000 - 200, 300), dxfattribs={"layer": "A-FIXT"})
    msp.add_blockref("WC", (8300, 3200), dxfattribs={"layer": "A-FIXT", "rotation": 90})
    msp.add_blockref("SINK", (6500, 3350), dxfattribs={"layer": "A-FIXT"})

    # A straight stair in the hall: treads, a walking line and the cut line.
    sx, sy = 6400, 4400
    for i in range(12):
        msp.add_line((sx, sy + i * 280), (sx + 1000, sy + i * 280), dxfattribs={"layer": "A-STAIR"})
    msp.add_lwpolyline([(sx, sy), (sx + 1000, sy), (sx + 1000, sy + 12 * 280), (sx, sy + 12 * 280)], close=True, dxfattribs={"layer": "A-STAIR"})
    msp.add_lwpolyline([(sx + 500, sy + 100), (sx + 500, sy + 3300)], dxfattribs={"layer": "A-STAIR"})
    msp.add_leader([(sx + 500, sy + 3300), (sx + 420, sy + 3000), (sx + 580, sy + 3000)], dxfattribs={"layer": "A-STAIR"})
    msp.add_text("UP", height=150, dxfattribs={"layer": "A-STAIR", "style": "ARCH-TEXT"}).set_placement((sx + 550, sy + 200))

    # Axes and bubbles.
    for i, x in enumerate((0, 3500, 6200, ow)):
        msp.add_line((x, -1700), (x, od + 1200), dxfattribs={"layer": "A-GRID"})
        msp.add_blockref("AXIS", (x, -2000), dxfattribs={"layer": "A-GRID"}).add_auto_attribs({"ID": str(i + 1)})
    for i, y in enumerate((0, 4200, od)):
        msp.add_line((-1700, y), (ow + 1200, y), dxfattribs={"layer": "A-GRID"})
        msp.add_blockref("AXIS", (-2000, y), dxfattribs={"layer": "A-GRID"}).add_auto_attribs({"ID": "ABC"[i]})

    # Room names and areas.
    rooms = [("Bedroom 1", (1750, 2100), 3.5 * 4.2), ("Bedroom 2", (4850, 2100), 2.7 * 4.2), ("Bath", (7500, 2100), 3.8 * 4.2),
             ("Living room", (3100, 6100), 6.2 * 3.8), ("Kitchen", (7150, 6100), 3.8 * 3.8), ("Hall", (1500, 4650), 0.0)]
    for label, (x, y), area in rooms:
        t = r"\fArial|b1;" + label.upper() + (r"\P\fArial|b0;" + f"{area:.1f} m²" if area else "")
        m = msp.add_mtext(t, dxfattribs={"layer": "A-AREA", "style": "ARCH-TEXT", "char_height": 260, "attachment_point": 5})
        m.set_location((x, y))
        m.dxf.width = 2600

    # Dimensions.
    msp.add_linear_dim(base=(0, -3100), p1=(0, 0), p2=(ow, 0), dimstyle="PLAN50", dxfattribs={"layer": "A-DIMS"}).render()
    msp.add_linear_dim(base=(0, -2600), p1=(0, 0), p2=(3500, 0), dimstyle="PLAN50", dxfattribs={"layer": "A-DIMS"}).render()
    msp.add_linear_dim(base=(0, -2600), p1=(3500, 0), p2=(6200, 0), dimstyle="PLAN50", dxfattribs={"layer": "A-DIMS"}).render()
    msp.add_linear_dim(base=(0, -2600), p1=(6200, 0), p2=(ow, 0), dimstyle="PLAN50", dxfattribs={"layer": "A-DIMS"}).render()
    msp.add_linear_dim(base=(-3100, 0), p1=(0, 0), p2=(0, od), angle=90, dimstyle="PLAN50", dxfattribs={"layer": "A-DIMS"}).render()
    msp.add_linear_dim(base=(-2600, 0), p1=(0, 0), p2=(0, 4200), angle=90, dimstyle="PLAN50", dxfattribs={"layer": "A-DIMS"}).render()
    msp.add_linear_dim(base=(-2600, 0), p1=(0, 4200), p2=(0, od), angle=90, dimstyle="PLAN50", dxfattribs={"layer": "A-DIMS"}).render()
    # A boundary fence beside the house: an aligned dimension and an angle against the house's wall.
    msp.add_lwpolyline([(ow + 1500, 500), (ow + 4500, 3500)], dxfattribs={"layer": "A-WALL", "linetype": "DASHED"})
    msp.add_aligned_dim(p1=(ow + 1500, 500), p2=(ow + 4500, 3500), distance=-700, dimstyle="PLAN50", dxfattribs={"layer": "A-DIMS"}).render()
    msp.add_line((ow + 1500, 500), (ow + 4500, 500), dxfattribs={"layer": "A-GRID"})
    msp.add_angular_dim_2l(base=(ow + 2300, 700), line1=((ow + 1500, 500), (ow + 4500, 3500)), line2=((ow + 1500, 500), (ow + 4500, 500)), dimstyle="PLAN50", dxfattribs={"layer": "A-DIMS"}).render()
    msp.add_radius_dim(center=(6275, 1700), radius=900, angle=45, dimstyle="PLAN50", dxfattribs={"layer": "A-DIMS"}).render()

    # North arrow, level marks, title text.
    msp.add_blockref("NORTH", (ow + 2200, od + 700), dxfattribs={"layer": "A-ANNO", "xscale": 1.0})
    msp.add_blockref("LEVEL", (5000, 3400), dxfattribs={"layer": "A-ANNO"}).add_auto_attribs({"H": "±0.00"})
    t = msp.add_text("GROUND FLOOR PLAN  1:50", height=330, dxfattribs={"layer": "A-ANNO", "style": "ARCH-TITLE"})
    t.set_placement((0, -4700))
    msp.add_line((0, -4900), (4500, -4900), dxfattribs={"layer": "A-ANNO", "lineweight": 70})
    msp.add_text("Drawn for the exav demo. Dimensions in millimetres.", height=130, dxfattribs={"layer": "A-ANNO", "style": "ARCH-NOTE"}).set_placement((0, -5200))

    # A sheet in paper space: title block, a viewport on the plan.
    lay = doc.layouts.new("A3 Plan")
    lay.page_setup(size=(420, 297), margins=(10, 10, 10, 10), units="mm")
    rect(lay, 10, 10, 410, 287, layer="A-SHEET")
    rect(lay, 5, 5, 415, 292, layer="A-SHEET")
    rect(lay, 260, 10, 410, 60, layer="A-SHEET")
    lay.add_line((260, 35), (410, 35), dxfattribs={"layer": "A-SHEET"})
    lay.add_line((335, 10), (335, 35), dxfattribs={"layer": "A-SHEET"})
    lay.add_text("HOUSE, GROUND FLOOR", height=7, dxfattribs={"layer": "A-SHEET", "style": "ARCH-TITLE"}).set_placement((265, 45))
    lay.add_text("Scale 1:50", height=4, dxfattribs={"layer": "A-SHEET", "style": "ARCH-TEXT"}).set_placement((265, 18))
    lay.add_text("Sheet A-101", height=4, dxfattribs={"layer": "A-SHEET", "style": "ARCH-TEXT"}).set_placement((340, 18))
    vp = lay.add_viewport(center=(135, 160), size=(250, 200), view_center_point=(ow / 2, od / 2 - 600), view_height=200 * 50, status=1)
    vp.dxf.layer = "A-VPORT"
    vp.dxf.flags |= 0
    save(doc, name)


# ------------------------------------------------------------ elevations


def window_elev(msp, x, y, w, h, layer="A-WIND"):
    rect(msp, x, y, x + w, y + h, layer=layer)
    rect(msp, x + 60, y + 60, x + w - 60, y + h - 60, layer=layer)
    msp.add_line((x + w / 2, y + 60), (x + w / 2, y + h - 60), dxfattribs={"layer": layer})
    hh = msp.add_hatch(color=5, dxfattribs={"layer": layer, "transparency": colors.float2transparency(0.6)})
    hh.set_solid_fill(color=5)
    hh.paths.add_polyline_path([(x + 60, y + 60), (x + w - 60, y + 60), (x + w - 60, y + h - 60), (x + 60, y + h - 60)], is_closed=True)
    rect(msp, x - 80, y - 90, x + w + 80, y, layer=layer)


def elevation(msp, ox, oy, name, width, windows, door, label):
    """A gabled house front: ground, walls, roof, windows, door, levels."""
    wall_h, ridge = 5400, 8300
    layer_ = "E-WALL"
    # Ground and its hatch.
    msp.add_lwpolyline([(ox - 1500, oy), (ox + width + 1500, oy)], dxfattribs={"layer": "E-GROUND", "lineweight": 70})
    hh = msp.add_hatch(color=3, dxfattribs={"layer": "E-GROUND"})
    hh.set_pattern_fill("EARTH", color=3, scale=60)
    hh.paths.add_polyline_path([(ox - 1500, oy - 600), (ox + width + 1500, oy - 600), (ox + width + 1500, oy), (ox - 1500, oy)], is_closed=True)
    # Walls with a render hatch, plinth, roof.
    rect(msp, ox, oy, ox + width, oy + wall_h, layer=layer_)
    hw = msp.add_hatch(color=252, dxfattribs={"layer": "E-RENDER"})
    hw.set_pattern_fill("AR-SAND", color=8, scale=15)
    hw.paths.add_polyline_path([(ox, oy), (ox + width, oy), (ox + width, oy + wall_h), (ox, oy + wall_h)], is_closed=True)
    rect(msp, ox, oy, ox + width, oy + 450, layer="E-PLINTH")
    roof = [(ox - 450, oy + wall_h), (ox + width / 2, oy + ridge), (ox + width + 450, oy + wall_h)]
    msp.add_lwpolyline(roof, close=True, dxfattribs={"layer": "E-ROOF", "lineweight": 50})
    hr = msp.add_hatch(color=1, dxfattribs={"layer": "E-ROOF"})
    hr.set_pattern_fill("AR-RROOF", color=1, scale=60)
    hr.paths.add_polyline_path(roof, is_closed=True)
    # A floor line at 2700.
    msp.add_line((ox, oy + 2700), (ox + width, oy + 2700), dxfattribs={"layer": "E-FLOOR", "linetype": "DASHDOT"})
    for wx, wy, w, h in windows:
        window_elev(msp, ox + wx, oy + wy, w, h)
    if door:
        dx, dw, dh = door
        rect(msp, ox + dx, oy, ox + dx + dw, oy + dh, layer="E-DOOR")
        rect(msp, ox + dx + 100, oy + 100, ox + dx + dw - 100, oy + dh - 100, layer="E-DOOR")
        msp.add_circle((ox + dx + dw - 200, oy + 1000), 40, dxfattribs={"layer": "E-DOOR"})
        for i in range(3):
            rect(msp, ox + dx - 150 - i * 120, oy + 450 - 150 * i - 150, ox + dx + dw + 150 + i * 120, oy + 450 - 150 * i, layer="E-STEP")
    # Levels and heights.
    for lv, txt in [(0, "+0.00"), (2700, "+2.70"), (wall_h, "+5.40"), (ridge, "+8.30")]:
        b = msp.add_blockref("LEVEL", (ox + width + 1900, oy + lv), dxfattribs={"layer": "A-ANNO"})
        b.add_auto_attribs({"H": txt})
        msp.add_line((ox + width, oy + lv), (ox + width + 1900, oy + lv), dxfattribs={"layer": "A-ANNO", "linetype": "DASHED"})
    msp.add_linear_dim(base=(ox - 1900, oy), p1=(ox, oy), p2=(ox, oy + wall_h), angle=90, dimstyle="ELEV50", dxfattribs={"layer": "A-DIMS"}).render()
    msp.add_linear_dim(base=(ox - 1900, oy), p1=(ox, oy + wall_h), p2=(ox, oy + ridge), angle=90, dimstyle="ELEV50", dxfattribs={"layer": "A-DIMS"}).render()
    msp.add_linear_dim(base=(ox, oy - 1100), p1=(ox, oy), p2=(ox + width, oy), dimstyle="ELEV50", dxfattribs={"layer": "A-DIMS"}).render()
    t = msp.add_text(label, height=300, dxfattribs={"layer": "A-ANNO", "style": "ARCH-TITLE"})
    t.set_placement((ox, oy - 2100))
    msp.add_line((ox, oy - 2250), (ox + 3600, oy - 2250), dxfattribs={"layer": "A-ANNO", "lineweight": 70})


def house_elevations():
    doc = new("R2018")
    for n, c, lt, w in [("E-GROUND", 3, "Continuous", 50), ("E-WALL", 7, "Continuous", 35), ("E-RENDER", 8, "Continuous", 9),
                        ("E-PLINTH", 8, "Continuous", 25), ("E-ROOF", 1, "Continuous", 35), ("E-FLOOR", 9, "DASHDOT", 9),
                        ("E-DOOR", 30, "Continuous", 25), ("E-STEP", 8, "Continuous", 18), ("A-WIND", 5, "Continuous", 25),
                        ("A-ANNO", 2, "Continuous", 18), ("A-DIMS", 3, "Continuous", 13), ("A-FIXT", 4, "Continuous", 18)]:
        layer(doc, n, c, lt, w)
    doc.ltscale = 80
    text_style(doc, "ARCH-TEXT", "arial.ttf")
    text_style(doc, "ARCH-TITLE", "times.ttf")
    dimstyle(doc, "ELEV50", 160, dimtxsty="ARCH-TEXT")
    make_blocks(doc)
    msp = doc.modelspace()
    # South (the front, with the door), east, north, west; widths 10000, 8000, 10000, 8000.
    south = ([(3600, 1100, 900, 1300), (6200, 1100, 900, 1300), (8200, 1100, 1200, 1300), (800, 3400, 1000, 1400), (3600, 3400, 900, 1400), (6200, 3400, 900, 1400)], (1400, 1500, 2300))
    east = ([(1500, 1100, 1300, 1300), (4800, 1100, 1300, 1300), (1500, 3400, 1300, 1400), (4800, 3400, 1300, 1400)], None)
    north = ([(1200, 1100, 1400, 1300), (3600, 1100, 1600, 1300), (6600, 1100, 1200, 1300), (3600, 3400, 1600, 1400)], None)
    west = ([(1600, 1100, 1400, 1300), (5000, 1100, 1400, 1300), (3000, 3400, 1200, 1400)], None)
    elevation(msp, 0, 0, "south", 10000, *south, "SOUTH ELEVATION  1:50")
    elevation(msp, 16000, 0, "east", 8000, *east, "EAST ELEVATION  1:50")
    elevation(msp, 0, -17000, "north", 10000, *north, "NORTH ELEVATION  1:50")
    elevation(msp, 16000, -17000, "west", 8000, *west, "WEST ELEVATION  1:50")
    # A section: floors, walls, roof, stair opening, hatched cuts.
    ox, oy = 32000, 0
    for (x0, x1) in [(ox, ox + 300), (ox + 9700, ox + 10000)]:
        rect(msp, x0, oy, x1, oy + 5400, layer="E-WALL")
        hh = msp.add_hatch(color=8, dxfattribs={"layer": "E-WALL"})
        hh.set_pattern_fill("ANSI31", color=8, scale=60)
        hh.paths.add_polyline_path([(x0, oy), (x1, oy), (x1, oy + 5400), (x0, oy + 5400)], is_closed=True)
    for y in (0, 2700, 5100):
        rect(msp, ox, oy + y - 100 if y else oy - 300, ox + 10000, oy + y + (200 if y else 0), layer="E-WALL")
    sec = [(ox - 450, oy + 5400), (ox + 5000, oy + 8300), (ox + 10450, oy + 5400), (ox + 10450, oy + 5250), (ox + 5000, oy + 8150), (ox - 450, oy + 5250)]
    msp.add_lwpolyline(sec, close=True, dxfattribs={"layer": "E-ROOF", "lineweight": 50})
    hr = msp.add_hatch(color=1, dxfattribs={"layer": "E-ROOF"})
    hr.set_solid_fill(color=1)
    hr.paths.add_polyline_path(sec, is_closed=True)
    msp.add_lwpolyline([(ox - 1500, oy - 300), (ox + 11500, oy - 300)], dxfattribs={"layer": "E-GROUND", "lineweight": 70})
    for i in range(10):
        msp.add_line((ox + 6300 + i * 300, oy + i * 270), (ox + 6600 + i * 300, oy + i * 270), dxfattribs={"layer": "E-STEP"})
        msp.add_line((ox + 6600 + i * 300, oy + i * 270), (ox + 6600 + i * 300, oy + (i + 1) * 270), dxfattribs={"layer": "E-STEP"})
    t = msp.add_text("SECTION A-A  1:50", height=300, dxfattribs={"layer": "A-ANNO", "style": "ARCH-TITLE"})
    t.set_placement((ox, oy - 2100))
    save(doc, "house-elevations.dxf")


# ---------------------------------------------------------- hatch gallery


def hatch_gallery():
    doc = new("R2018")
    layer(doc, "PATTERNS", 7)
    layer(doc, "GRADIENTS", 5)
    layer(doc, "ISLANDS", 1)
    layer(doc, "EDGES", 3)
    layer(doc, "LABELS", 2)
    text_style(doc, "LABEL", "arial.ttf")
    msp = doc.modelspace()
    names = [n for n in pattern.load() if n.startswith(("ANSI", "AR-", "BRICK", "CLAY", "CORK", "CROSS", "DOTS", "EARTH", "GRASS", "GRAVEL", "HEX", "HONEY", "LINE", "NET", "SQUARE", "STEEL", "STARS", "TRIANG", "ZIGZAG", "ESCHER", "DOLMIT", "SWAMP", "INSUL", "MUDST", "PLAST", "BOX", "BRASS", "CONCRETE"))]
    cols = 8
    size, gap = 100, 40
    for i, name in enumerate(names):
        cx, cy = (i % cols) * (size + gap), -(i // cols) * (size + gap + 25)
        h = msp.add_hatch(color=7, dxfattribs={"layer": "PATTERNS"})
        h.set_pattern_fill(name, color=7, scale=1.0)
        h.paths.add_polyline_path([(cx, cy), (cx + size, cy), (cx + size, cy + size), (cx, cy + size)], is_closed=True)
        rect(msp, cx, cy, cx + size, cy + size, layer="PATTERNS", color=8)
        msp.add_text(name, height=9, dxfattribs={"layer": "LABELS", "style": "LABEL"}).set_placement((cx, cy - 14))
    y0 = -(len(names) // cols + 1) * (size + gap + 25) - 100
    # Gradients.
    kinds = ["LINEAR", "CYLINDER", "INVCYLINDER", "SPHERICAL", "INVSPHERICAL", "HEMISPHERICAL", "INVHEMISPHERICAL", "CURVED", "INVCURVED"]
    for i, k in enumerate(kinds):
        cx = (i % cols) * (size + gap)
        cy = y0 - (i // cols) * (size + gap + 25)
        h = msp.add_hatch(dxfattribs={"layer": "GRADIENTS"})
        h.set_gradient((255, 220, 80), (20, 60, 140), rotation=30 if i % 2 else 0, name=k)
        h.paths.add_polyline_path([(cx, cy), (cx + size, cy), (cx + size, cy + size), (cx, cy + size)], is_closed=True)
        msp.add_text(k.lower(), height=9, dxfattribs={"layer": "LABELS", "style": "LABEL"}).set_placement((cx, cy - 14))
    y1 = y0 - 2 * (size + gap + 25) - 100
    # Islands: an outer square with a circle and a triangle inside, the three hatch styles.
    for i, (style, label) in enumerate([(0, "normal: nested islands"), (1, "outer only"), (2, "ignore: all filled")]):
        cx, cy = i * (size * 2 + gap), y1
        h = msp.add_hatch(color=1, dxfattribs={"layer": "ISLANDS", "hatch_style": style})
        h.set_pattern_fill("ANSI31", color=1, scale=1.4)
        h.paths.add_polyline_path([(cx, cy), (cx + 2 * size, cy), (cx + 2 * size, cy + 2 * size), (cx, cy + 2 * size)], is_closed=True, flags=1 | 16)
        ep = h.paths.add_edge_path(flags=16)
        ep.add_arc((cx + size, cy + size), 70, 0, 360, ccw=True)
        h.paths.add_polyline_path([(cx + size - 25, cy + size - 20), (cx + size + 25, cy + size - 20), (cx + size, cy + size + 28)], is_closed=True, flags=16)
        msp.add_text(label, height=9, dxfattribs={"layer": "LABELS", "style": "LABEL"}).set_placement((cx, cy - 14))
    # A boundary of line, arc, ellipse and spline edges.
    cx, cy = 3 * (size * 2 + gap), y1
    h = msp.add_hatch(color=3, dxfattribs={"layer": "EDGES"})
    h.set_pattern_fill("HONEY", color=3, scale=1.0)
    ep = h.paths.add_edge_path(flags=1)
    ep.add_line((cx, cy), (cx + 160, cy))
    ep.add_arc((cx + 160, cy + 40), 40, 270, 90, ccw=True)
    ep.add_line((cx + 160, cy + 80), (cx + 120, cy + 80))
    ep.add_spline([(cx + 120, cy + 80), (cx + 100, cy + 140), (cx + 60, cy + 40), (cx + 40, cy + 120), (cx, cy + 100)], degree=3)
    ep.add_line((cx, cy + 100), (cx, cy))
    msp.add_text("edges: line, arc, spline", height=9, dxfattribs={"layer": "LABELS", "style": "LABEL"}).set_placement((cx, cy - 14))
    cx = 3 * (size * 2 + gap) + 220
    h = msp.add_hatch(color=6, dxfattribs={"layer": "EDGES"})
    h.set_solid_fill(color=6)
    ep = h.paths.add_edge_path(flags=1)
    ep.add_ellipse((cx + 70, cy + 70), major_axis=(70, 0), ratio=0.55, start_angle=0, end_angle=360, ccw=True)
    msp.add_text("ellipse, solid", height=9, dxfattribs={"layer": "LABELS", "style": "LABEL"}).set_placement((cx, cy - 14))
    # A pattern with its own angle and scale, and one with a seed point and a user-defined pattern.
    cx = 3 * (size * 2 + gap) + 400
    h = msp.add_hatch(color=2, dxfattribs={"layer": "EDGES"})
    h.set_pattern_fill("ANSI37", color=2, angle=15, scale=2.5)
    h.paths.add_polyline_path([(cx, cy), (cx + 140, cy), (cx + 140, cy + 140), (cx, cy + 140)], is_closed=True)
    msp.add_text("angle 15, scale 2.5", height=9, dxfattribs={"layer": "LABELS", "style": "LABEL"}).set_placement((cx, cy - 14))
    save(doc, "hatch-gallery.dxf")


# -------------------------------------------------------------- dimensions


def dimensions():
    doc = new("R2018")
    layer(doc, "OBJECT", 7, weight=35)
    layer(doc, "DIMS", 3, weight=13)
    layer(doc, "NOTE", 2, weight=13)
    text_style(doc, "DIM-TEXT", "arial.ttf")
    dimstyle(doc, "METRIC", 3.5, dimtxsty="DIM-TEXT", dimdec=1)
    dimstyle(doc, "TOL", 3.5, dimtxsty="DIM-TEXT", dimdec=2, dimtol=1, dimtp=0.05, dimtm=0.02, dimtfac=0.7, dimtolj=1)
    dimstyle(doc, "ARCH", 3.5, dimtxsty="DIM-TEXT", dimdec=0, dimtad=0, dimtih=1, dimtix=0, dimscale=1.0)
    msp = doc.modelspace()
    A = {"layer": "DIMS"}
    rect(msp, 0, 0, 80, 50, layer="OBJECT")
    msp.add_linear_dim(base=(0, -12), p1=(0, 0), p2=(80, 0), dimstyle="METRIC", dxfattribs=A).render()
    msp.add_linear_dim(base=(-14, 0), p1=(0, 0), p2=(0, 50), angle=90, dimstyle="METRIC", dxfattribs=A).render()
    msp.add_linear_dim(base=(0, 62), p1=(0, 50), p2=(80, 50), dimstyle="TOL", dxfattribs=A, text="<>").render()
    msp.add_linear_dim(base=(0, 70), p1=(0, 50), p2=(80, 50), dimstyle="METRIC", dxfattribs=A, text="80 overall (text override)").render()
    msp.add_aligned_dim(p1=(80, 0), p2=(110, 50), distance=12, dimstyle="METRIC", dxfattribs=A).render()
    # Circles and arcs.
    msp.add_circle((150, 25), 25, dxfattribs={"layer": "OBJECT"})
    msp.add_diameter_dim(center=(150, 25), radius=25, angle=40, dimstyle="METRIC", dxfattribs=A).render()
    msp.add_circle((220, 25), 18, dxfattribs={"layer": "OBJECT"})
    msp.add_radius_dim(center=(220, 25), radius=18, angle=-60, dimstyle="METRIC", dxfattribs=A).render()
    msp.add_arc((290, 0), 40, 20, 140, dxfattribs={"layer": "OBJECT"})
    msp.add_arc_dim_3p(base=(290 + 48 * math.cos(math.radians(80)), 48 * math.sin(math.radians(80))), center=(290, 0), p1=(290 + 40 * math.cos(math.radians(20)), 40 * math.sin(math.radians(20))), p2=(290 + 40 * math.cos(math.radians(140)), 40 * math.sin(math.radians(140))), dimstyle="METRIC", dxfattribs=A).render()
    # Angles.
    msp.add_line((0, -60), (60, -60), dxfattribs={"layer": "OBJECT"})
    msp.add_line((0, -60), (45, -20), dxfattribs={"layer": "OBJECT"})
    msp.add_angular_dim_2l(base=(30, -56), line1=((0, -60), (60, -60)), line2=((0, -60), (45, -20)), dimstyle="METRIC", dxfattribs=A).render()
    msp.add_angular_dim_3p(base=(140, -60), center=(130, -80), p1=(150, -45), p2=(170, -80), dimstyle="METRIC", dxfattribs=A).render()
    msp.add_line((130, -80), (170, -80), dxfattribs={"layer": "OBJECT"})
    msp.add_line((130, -80), (150, -45), dxfattribs={"layer": "OBJECT"})
    # Ordinate dimensions from an origin.
    msp.add_lwpolyline([(220, -90), (320, -90), (320, -40), (260, -40), (260, -60), (220, -60)], close=True, dxfattribs={"layer": "OBJECT"})
    for x in (220, 260, 320):
        msp.add_ordinate_x_dim(feature_location=(x, -90), offset=(0, -12), origin=(220, -90), dimstyle="METRIC", dxfattribs=A).render()
    for y in (-90, -60, -40):
        msp.add_ordinate_y_dim(feature_location=(320, y), offset=(14, 0), origin=(220, -90), dimstyle="METRIC", dxfattribs=A).render()
    # Leaders and multileaders.
    ml = msp.add_multileader_mtext("Standard")
    ml.set_content("Chamfer 2 x 45°", char_height=3.5)
    ml.add_leader_line(ConnectionSide.left, [Vec2(75, 45)])
    ml.build(insert=Vec2(100, 85))
    msp.add_leader([(15, 15), (30, 30), (40, 30)], dimstyle="METRIC", dxfattribs={"layer": "NOTE"})
    msp.add_text("hole 5", height=3.5, dxfattribs={"layer": "NOTE", "style": "DIM-TEXT"}).set_placement((41, 29))
    # Styles shown side by side.
    msp.add_text("METRIC style (left), TOL style with tolerances, ARCH (text horizontal)", height=4, dxfattribs={"layer": "NOTE", "style": "DIM-TEXT"}).set_placement((0, 110))
    rect(msp, 0, -160, 60, -130, layer="OBJECT")
    msp.add_linear_dim(base=(0, -168), p1=(0, -160), p2=(60, -160), dimstyle="ARCH", dxfattribs=A).render()
    msp.add_linear_dim(base=(0, -178), p1=(0, -160), p2=(60, -160), dimstyle="TOL", dxfattribs=A).render()
    save(doc, "dimensions.dxf")


# --------------------------------------------------------------- linetypes


def linetypes():
    doc = new("R2018")
    doc.ltscale = 1.0
    text_style(doc, "LT-TEXT", "arial.ttf")
    # Custom linetypes: simple, with text and with a shape-like arrow.
    doc.linetypes.add("EXAV_DASH3", pattern=[10.0, 6.0, -3.0, 0.0, -3.0, 0.0, -3.0], description="Dash and three dots")
    doc.linetypes.add("GAS_LINE", pattern='A,5,-2,["GAS",LT-TEXT,S=1.5,U=0.0,X=-1.0,Y=-0.75],-4', description="Gas line ---- GAS ----")
    doc.linetypes.add("HOT_WATER", pattern='A,6,-1.5,["HW",LT-TEXT,S=1.5,R=0.0,X=-1.0,Y=-0.75],-3', description="Hot water ---- HW ----")
    doc.linetypes.add("FENCE", pattern='A,4,-2,["x",LT-TEXT,S=1.4,U=0.0,X=-0.5,Y=-0.7],-2', description="Fence ---- x ----")
    msp = doc.modelspace()
    names = ["Continuous", "DASHED", "DASHED2", "DASHEDX2", "HIDDEN" if "HIDDEN" in doc.linetypes else "DASHED", "CENTER", "CENTER2", "CENTERX2", "PHANTOM", "PHANTOM2", "DASHDOT", "DASHDOT2", "DOT", "DOT2", "DIVIDE", "DIVIDE2", "EXAV_DASH3", "GAS_LINE", "HOT_WATER", "FENCE"]
    y = 0
    for i, n in enumerate(names):
        layer(doc, f"LT-{i:02d}", (i % 7) + 1, linetype=n, weight=25)
        msp.add_line((0, y), (220, y), dxfattribs={"layer": f"LT-{i:02d}", "linetype": "BYLAYER"})
        msp.add_text(n, height=3, dxfattribs={"style": "LT-TEXT", "color": 7}).set_placement((230, y - 1))
        y -= 8
    y -= 6
    # Line weights.
    msp.add_text("Line weights (mm)", height=4, dxfattribs={"style": "LT-TEXT", "color": 7}).set_placement((0, y + 6))
    for i, w in enumerate([0, 5, 9, 13, 18, 25, 35, 50, 70, 100, 140, 200]):
        msp.add_line((0, y), (220, y), dxfattribs={"lineweight": w, "color": 7})
        msp.add_text(f"{w / 100:.2f}", height=3, dxfattribs={"style": "LT-TEXT", "color": 7}).set_placement((230, y - 1))
        y -= 5
    y -= 10
    # Per-entity linetype scale and BYBLOCK.
    for i, s in enumerate([0.25, 0.5, 1, 2, 4]):
        msp.add_line((0, y), (220, y), dxfattribs={"linetype": "DASHED", "ltscale": s, "color": 4})
        msp.add_text(f"DASHED, ltscale {s}", height=3, dxfattribs={"style": "LT-TEXT", "color": 7}).set_placement((230, y - 1))
        y -= 6
    y -= 8
    # Polylines: linetype generation on and off, wide segments.
    pts = [(0, y), (40, y - 12), (80, y), (120, y - 12), (160, y), (200, y - 12)]
    for gen in (True, False):
        p = msp.add_lwpolyline(pts, dxfattribs={"linetype": "PHANTOM", "color": 1 if gen else 3})
        p.dxf.flags = 128 if gen else 0
        msp.add_text(f"lwpolyline, linetype generation {'on' if gen else 'off'}", height=3, dxfattribs={"style": "LT-TEXT", "color": 7}).set_placement((230, y - 1))
        pts = [(a, b - 25) for a, b in pts]
        y -= 25
    y -= 6
    msp.add_lwpolyline([(0, y, 0, 6, 0), (50, y, 6, 1, 0), (100, y - 15, 1, 6, 0), (150, y, 6, 6, 0), (200, y - 8, 0, 0, 0)], format="xyseb", dxfattribs={"color": 6})
    msp.add_text("lwpolyline with start and end widths per segment", height=3, dxfattribs={"style": "LT-TEXT", "color": 7}).set_placement((230, y - 1))
    y -= 30
    msp.add_circle((30, y), 15, dxfattribs={"linetype": "CENTER", "color": 1, "lineweight": 35})
    msp.add_arc((90, y), 15, 30, 300, dxfattribs={"linetype": "HIDDEN" if "HIDDEN" in doc.linetypes else "DASHED", "color": 3})
    msp.add_ellipse((150, y), major_axis=(25, 0), ratio=0.5, dxfattribs={"linetype": "PHANTOM", "color": 5})
    msp.add_spline([(190, y - 10), (200, y + 12), (215, y - 14), (225, y + 10)], dxfattribs={"linetype": "DASHDOT", "color": 6})
    save(doc, "linetypes.dxf")


# ------------------------------------------------------------- text styles


def text_styles():
    doc = new("R2018")
    layer(doc, "TEXT", 7)
    layer(doc, "NOTE", 8)
    fonts = [("S-ARIAL", "arial.ttf", {}), ("S-TIMES", "times.ttf", {}), ("S-COURIER", "cour.ttf", {}), ("S-NARROW", "arial.ttf", {"width": 0.6}),
             ("S-WIDE", "arial.ttf", {"width": 1.6}), ("S-SLANT", "times.ttf", {"oblique": 20}), ("S-ROMANS", "romans.shx", {}), ("S-SIMPLEX", "simplex.shx", {}),
             ("S-BACKWARDS", "arial.ttf", {}), ("S-UPSIDE", "arial.ttf", {})]
    for n, f, kw in fonts:
        st = text_style(doc, n, f, **kw)
    doc.styles.get("S-BACKWARDS").dxf.flags |= 2
    doc.styles.get("S-UPSIDE").dxf.flags |= 4
    msp = doc.modelspace()
    y = 0
    sample = "Sphinx of black quartz, judge my vow 0123456789"
    for n, f, kw in fonts:
        msp.add_text(f"{n} ({f}): {sample}", height=6, dxfattribs={"style": n, "layer": "TEXT"}).set_placement((0, y))
        y -= 12
    y -= 6
    for i, (halign, name) in enumerate([(TextEntityAlignment.TOP_LEFT, "TOP_LEFT"), (TextEntityAlignment.MIDDLE_CENTER, "MIDDLE_CENTER"), (TextEntityAlignment.BOTTOM_RIGHT, "BOTTOM_RIGHT"), (TextEntityAlignment.ALIGNED, "ALIGNED"), (TextEntityAlignment.FIT, "FIT")]):
        x = 20 + i * 130
        msp.add_line((x - 5, y), (x + 5, y), dxfattribs={"color": 1})
        msp.add_line((x, y - 5), (x, y + 5), dxfattribs={"color": 1})
        t = msp.add_text(name, height=6, dxfattribs={"style": "S-ARIAL", "layer": "TEXT"})
        if halign in (TextEntityAlignment.ALIGNED, TextEntityAlignment.FIT):
            t.set_placement((x, y), (x + 70, y), align=halign)
        else:
            t.set_placement((x, y), align=halign)
    y -= 24
    for angle in (0, 30, 60, 90):
        msp.add_text(f"rotated {angle} degrees", height=6, rotation=angle, dxfattribs={"style": "S-TIMES", "layer": "TEXT"}).set_placement((20 + angle * 1.5, y))
    y -= 70
    msp.add_text("Special: %%d degree 45%%d, %%p plus/minus 0.5, %%c diameter 25, %%%% percent, %%u under%%u, %%o over%%o", height=5, dxfattribs={"style": "S-ARIAL", "layer": "TEXT"}).set_placement((0, y))
    y -= 10
    msp.add_text("Unicode: éèê üöä ß ñ ΔΩπ Жя € ½ ²³", height=5, dxfattribs={"style": "S-ARIAL", "layer": "TEXT"}).set_placement((0, y))
    y -= 20
    # MTEXT formatting.
    def mt(text, x, yy, w=110, h=4, **kw):
        m = msp.add_mtext(text, dxfattribs={"style": "S-ARIAL", "char_height": h, "layer": "TEXT", **kw})
        m.set_location((x, yy))
        m.dxf.width = w
        return m
    mt(r"{\C1;Red}, {\C3;green}, {\C5;blue} and {\c16744192;orange by RGB}.\P"
       r"{\fTimes New Roman|b1;Bold serif}, {\fArial|i1;italic sans}, {\fCourier New|b1|i1;bold italic mono}.\P"
       r"Underline \Lis on\l, overline \Ois on\o, \Kstrike-through\k.\P"
       r"Height \H2x;doubles\H1x; and returns; width \W2;wide\W1; and back; slant \Q20;oblique\Q0;.\P"
       r"Stacked: \S1/2; \S1#2; \S1^2; \S\U+00B1 0.1^ -0.1; and x\S2^;, H\S2^ ;.\P"
       r"Tab\Pstops: A\tB\tC", 0, y, 120)
    mt(r"{\L\C2;Paragraph 1}\PA justified-looking paragraph with a long text that wraps inside the box of the entity, "
       r"set at width 90, to see how line breaks are made by the viewer.", 130, y, 90, 4.2)
    m = mt("Background box, with a border in the text colour: the viewer fills the box behind the text.", 230, y, 70, 4.2)
    m.set_bg_color((255, 235, 140), scale=1.5)
    y -= 70
    cols = msp.add_mtext_static_columns(["Column one text, a short paragraph that sits at the left.", "Column two: more text, in the middle.", "Column three at the right."], width=40, gutter_width=6, height=40, dxfattribs={"style": "S-ARIAL", "char_height": 3.5, "layer": "TEXT"})
    cols.set_location((0, y))
    msp.add_text("MTEXT in three static columns", height=3, dxfattribs={"layer": "NOTE", "style": "S-ARIAL"}).set_placement((0, y - 44))
    for i, ap in enumerate(range(1, 10)):
        m = msp.add_mtext(f"AP {ap}", dxfattribs={"style": "S-ARIAL", "char_height": 4, "layer": "TEXT", "attachment_point": ap})
        m.set_location((150 + (i % 3) * 40, y - (i // 3) * 14))
        m.dxf.width = 30
        msp.add_circle((150 + (i % 3) * 40, y - (i // 3) * 14), 0.8, dxfattribs={"color": 1})
    save(doc, "text-styles.dxf")


# ------------------------------------------------------------------ blocks


def blocks():
    doc = new("R2018")
    layer(doc, "PARTS", 7)
    layer(doc, "NOTE", 8)
    layer(doc, "RED", 1)
    text_style(doc, "BL-TEXT", "arial.ttf")
    msp = doc.modelspace()
    # A bolt: cap, shank and a thread hatch.
    bolt = doc.blocks.new("BOLT")
    bolt.add_lwpolyline([(-6, 0), (6, 0), (6, 4), (-6, 4)], close=True)
    bolt.add_lwpolyline([(-3, 0), (3, 0), (3, -22), (-3, -22)], close=True)
    for i in range(7):
        bolt.add_line((-3, -4 - i * 2.5), (3, -6.5 - i * 2.5))
    bolt.add_attdef("SIZE", (8, 1), text="M6", height=2.5)
    # A plate with four BOLT inserts in a nested block.
    plate = doc.blocks.new("PLATE")
    plate.add_lwpolyline([(0, 0), (100, 0), (100, 60), (0, 60)], close=True)
    for x, y in [(15, 15), (85, 15), (15, 45), (85, 45)]:
        plate.add_circle((x, y), 4)
        plate.add_blockref("BOLT", (x, y), dxfattribs={"layer": "RED"}).add_auto_attribs({"SIZE": "M6"})
    plate.add_attdef("MARK", (50, 30), text="P-1", height=6, dxfattribs={"halign": 4, "valign": 0, "align_point": (50, 30)})
    # A frame that nests the plate twice at different scales.
    frame = doc.blocks.new("FRAME")
    frame.add_lwpolyline([(-10, -10), (330, -10), (330, 90), (-10, 90)], close=True)
    frame.add_blockref("PLATE", (0, 0)).add_auto_attribs({"MARK": "A"})
    frame.add_blockref("PLATE", (120, 0), dxfattribs={"xscale": 0.7, "yscale": 0.7, "rotation": 0}).add_auto_attribs({"MARK": "B"})
    frame.add_blockref("PLATE", (230, 70), dxfattribs={"rotation": -90, "xscale": 0.6, "yscale": 0.6}).add_auto_attribs({"MARK": "C"})
    msp.add_blockref("FRAME", (0, 0), dxfattribs={"layer": "PARTS"})
    msp.add_text("FRAME: nested PLATE, BOLT blocks, attributes", height=4, dxfattribs={"layer": "NOTE", "style": "BL-TEXT"}).set_placement((0, -20))
    # Inserts: rotated, scaled, mirrored in x and y.
    y = -80
    for i, (sx, sy, rot, label) in enumerate([(1, 1, 0, "scale 1"), (-1, 1, 0, "xscale -1"), (1, -1, 0, "yscale -1"), (1.5, 0.6, 0, "1.5 by 0.6"), (1, 1, 30, "rotated 30")]):
        x = i * 130
        msp.add_blockref("PLATE", (x + (100 if sx < 0 else 0), y + (60 if sy < 0 else 0)), dxfattribs={"xscale": sx, "yscale": sy, "rotation": rot}).add_auto_attribs({"MARK": label})
        msp.add_text(label, height=4, dxfattribs={"layer": "NOTE", "style": "BL-TEXT"}).set_placement((x, y - 20))
    # Arrays: a MINSERT of bolts (rows and columns), spaced.
    y -= 120
    arr = msp.add_blockref("BOLT", (0, y), dxfattribs={"layer": "PARTS"})
    arr.dxf.row_count = 3
    arr.dxf.column_count = 8
    arr.dxf.row_spacing = 35
    arr.dxf.column_spacing = 20
    arr.add_auto_attribs({"SIZE": "M6"})
    msp.add_text("MINSERT: 3 rows by 8 columns of BOLT", height=4, dxfattribs={"layer": "NOTE", "style": "BL-TEXT"}).set_placement((0, y - 110))
    # A block on a layer that is on, BYBLOCK colours.
    sym = doc.blocks.new("SYMBOL")
    sym.add_circle((0, 0), 10, dxfattribs={"color": 0})
    sym.add_line((-10, 0), (10, 0), dxfattribs={"color": 0})
    sym.add_line((0, -10), (0, 10), dxfattribs={"color": 256})
    for i, c in enumerate([1, 3, 5, 6]):
        msp.add_blockref("SYMBOL", (200 + i * 30, y - 20), dxfattribs={"color": c})
    msp.add_text("BYBLOCK circle and cross, BYLAYER vertical line: insert colour 1, 3, 5, 6", height=3, dxfattribs={"layer": "NOTE", "style": "BL-TEXT"}).set_placement((200, y - 40))
    save(doc, "blocks.dxf")


# ----------------------------------------------------------------- bracket


def bracket():
    doc = new("R2018")
    layer(doc, "OUTLINE", 7, weight=50)
    layer(doc, "HIDDEN", 4, linetype="DASHED", weight=25)
    layer(doc, "CENTER", 1, linetype="CENTER", weight=18)
    layer(doc, "SECTION", 8, weight=9)
    layer(doc, "DIMS", 3, weight=18)
    layer(doc, "SHEET", 7, weight=35)
    layer(doc, "TEXT", 2, weight=18)
    doc.ltscale = 1.0
    text_style(doc, "MECH", "arial.ttf")
    dimstyle(doc, "MECH", 3.5, dimtxsty="MECH", dimdec=1)
    dimstyle(doc, "MECHTOL", 3.5, dimtxsty="MECH", dimdec=2, dimtol=1, dimtp=0.1, dimtm=0.0, dimtfac=0.7, dimtolj=1)
    msp = doc.modelspace()
    O, Hd, C = {"layer": "OUTLINE"}, {"layer": "HIDDEN"}, {"layer": "CENTER"}
    # Front view: an L bracket with two holes in the base and a slot in the upright.
    # Base 100 x 60, thickness 12; upright 60 high; fillet radius 8.
    pts = [(0, 0), (100, 0), (100, 12), (20, 12), (12, 12), (12, 72), (0, 72)]
    msp.add_lwpolyline(pts, close=True, dxfattribs=O)
    msp.add_arc((20, 20), 8, 180, 270, dxfattribs=O)
    msp.add_line((12, 12), (12, 20), dxfattribs={"layer": "OUTLINE", "color": 8})
    msp.add_line((0, 0), (100, 0), dxfattribs=O)
    # The holes seen from the front: hidden.
    for x in (35, 80):
        msp.add_line((x - 4, 0), (x - 4, 12), dxfattribs=Hd)
        msp.add_line((x + 4, 0), (x + 4, 12), dxfattribs=Hd)
        msp.add_line((x, -6), (x, 18), dxfattribs=C)
    msp.add_line((-6, 52), (18, 52), dxfattribs=C)
    # The upright's slot, hidden.
    msp.add_line((0, 45), (12, 45), dxfattribs=Hd)
    msp.add_line((0, 59), (12, 59), dxfattribs=Hd)
    # Top view: below the front view.
    oy = -90
    msp.add_lwpolyline([(0, oy), (100, oy), (100, oy - 60), (0, oy - 60)], close=True, dxfattribs=O)
    msp.add_line((12, oy), (12, oy - 60), dxfattribs=O)
    for x in (35, 80):
        msp.add_circle((x, oy - 30), 4, dxfattribs=O)
        msp.add_line((x - 8, oy - 30), (x + 8, oy - 30), dxfattribs=C)
        msp.add_line((x, oy - 22), (x, oy - 38), dxfattribs=C)
    msp.add_lwpolyline([(0, oy - 20), (12, oy - 20)], dxfattribs=Hd)
    msp.add_lwpolyline([(0, oy - 40), (12, oy - 40)], dxfattribs=Hd)
    msp.add_lwpolyline([(0, oy - 20, 0, 0, 0), (0, oy - 40, 0, 0, 0)], format="xyseb", dxfattribs={"layer": "OUTLINE", "color": 8})
    # Section A-A through a hole, to the right: hatched cut.
    sx = 150
    cut = [(sx, 0), (sx + 60, 0), (sx + 60, 12), (sx + 42, 12), (sx + 42, 0 + 12), (sx + 38, 12), (sx + 12, 12), (sx + 12, 72), (sx, 72)]
    sec = [(sx, 0), (sx + 31, 0), (sx + 31, 12), (sx + 39, 12), (sx + 39, 0), (sx + 60, 0), (sx + 60, 12), (sx + 12, 12), (sx + 12, 72), (sx, 72)]
    msp.add_lwpolyline([(sx, 0), (sx + 31, 0), (sx + 31, 12), (sx + 12, 12), (sx + 12, 72), (sx, 72)], close=True, dxfattribs=O)
    msp.add_lwpolyline([(sx + 39, 0), (sx + 60, 0), (sx + 60, 12), (sx + 39, 12)], close=True, dxfattribs=O)
    h = msp.add_hatch(color=8, dxfattribs={"layer": "SECTION"})
    h.set_pattern_fill("ANSI31", color=8, scale=2.0)
    h.paths.add_polyline_path([(sx, 0), (sx + 31, 0), (sx + 31, 12), (sx + 12, 12), (sx + 12, 72), (sx, 72)], is_closed=True)
    h2 = msp.add_hatch(color=8, dxfattribs={"layer": "SECTION"})
    h2.set_pattern_fill("ANSI31", color=8, scale=2.0)
    h2.paths.add_polyline_path([(sx + 39, 0), (sx + 60, 0), (sx + 60, 12), (sx + 39, 12)], is_closed=True)
    msp.add_line((sx + 35, -6), (sx + 35, 18), dxfattribs=C)
    msp.add_text("SECTION A-A", height=5, dxfattribs={"layer": "TEXT", "style": "MECH"}).set_placement((sx, -14))
    # Cutting plane line in the top view.
    msp.add_lwpolyline([(-8, oy - 30), (108, oy - 30)], dxfattribs={"layer": "CENTER", "lineweight": 50})
    msp.add_text("A", height=6, dxfattribs={"layer": "TEXT", "style": "MECH"}).set_placement((-14, oy - 33))
    msp.add_text("A", height=6, dxfattribs={"layer": "TEXT", "style": "MECH"}).set_placement((112, oy - 33))
    # Dimensions, two with tolerances.
    D = {"layer": "DIMS"}
    msp.add_linear_dim(base=(0, -12), p1=(0, 0), p2=(100, 0), dimstyle="MECH", dxfattribs=D).render()
    msp.add_linear_dim(base=(-12, 0), p1=(0, 0), p2=(0, 72), angle=90, dimstyle="MECHTOL", dxfattribs=D).render()
    msp.add_linear_dim(base=(0, -24), p1=(35, 0), p2=(80, 0), dimstyle="MECHTOL", dxfattribs=D).render()
    msp.add_radius_dim(center=(20, 20), radius=8, angle=225, dimstyle="MECH", dxfattribs=D).render()
    msp.add_linear_dim(base=(0, oy + 12), p1=(0, oy), p2=(100, oy), dimstyle="MECH", dxfattribs=D).render()
    msp.add_diameter_dim(center=(80, oy - 30), radius=4, angle=35, dimstyle="MECH", dxfattribs=D, text="2x ⌀<>").render()
    msp.add_linear_dim(base=(sx + 70, 0), p1=(sx + 60, 0), p2=(sx + 60, 12), angle=90, dimstyle="MECH", dxfattribs=D).render()
    msp.add_leader([(sx + 5, 60), (sx - 12, 80), (sx - 40, 80)], dxfattribs={"layer": "DIMS"})
    msp.add_text("slot 14 x 12", height=3.5, dxfattribs={"layer": "TEXT", "style": "MECH"}).set_placement((sx - 40, 82))
    # A sheet: layout with a viewport and a title block.
    lay = doc.layouts.new("A4 Sheet")
    lay.page_setup(size=(297, 210), margins=(5, 5, 5, 5), units="mm")
    rect(lay, 5, 5, 292, 205, layer="SHEET")
    rect(lay, 137, 5, 292, 45, layer="SHEET")
    lay.add_line((137, 25), (292, 25), dxfattribs={"layer": "SHEET"})
    lay.add_line((200, 5), (200, 25), dxfattribs={"layer": "SHEET"})
    lay.add_line((250, 5), (250, 25), dxfattribs={"layer": "SHEET"})
    for txt, x, y, hgt in [("L-BRACKET 100 x 72 x 60", 142, 33, 6), ("Material: steel S235", 142, 15, 3.5), ("Scale 1:1", 205, 15, 3.5), ("Sheet 1/1", 255, 15, 3.5), ("Drawn: exav demo", 142, 8, 3)]:
        lay.add_text(txt, height=hgt, dxfattribs={"layer": "SHEET", "style": "MECH"}).set_placement((x, y))
    vp = lay.add_viewport(center=(130, 120), size=(250, 140), view_center_point=(90, -30), view_height=140, status=1)
    save(doc, "bracket.dxf")


# --------------------------------------------------------------- site plan


def site_plan():
    doc = new("R2018", units=6)
    layer(doc, "CONTOUR-MINOR", 8, weight=9)
    layer(doc, "CONTOUR-MAJOR", 30, weight=25)
    layer(doc, "PARCEL", 1, linetype="DASHDOT", weight=35)
    layer(doc, "BUILDING", 7, weight=50)
    layer(doc, "ROAD", 9, weight=18)
    layer(doc, "WATER", 5, weight=18)
    layer(doc, "TREES", 3, weight=9)
    layer(doc, "SPOT", 2, weight=9)
    layer(doc, "TEXT", 2, weight=13)
    layer(doc, "LEGEND", 7, weight=13)
    text_style(doc, "SITE", "arial.ttf")
    doc.ltscale = 6
    make_blocks(doc)
    msp = doc.modelspace()

    def height(x, y):
        return 100 + 18 * math.sin(x / 38) * math.cos(y / 47) + 8 * math.sin((x + y) / 21) + (x - 160) * 0.05

    # Contours: marching squares would be long; use closed hill rings as splines at several heights.
    for k, hgt in enumerate(range(94, 134, 2)):
        r = 12 + k * 7
        cx, cy = 150 + 3 * k, 110 - 2 * k
        pts = []
        for i in range(24):
            a = i * 2 * math.pi / 24
            rr = r * (1 + 0.12 * math.sin(3 * a + k * 0.3) + 0.06 * math.cos(5 * a))
            pts.append((cx + rr * math.cos(a), cy + rr * 0.75 * math.sin(a)))
        major = hgt % 10 == 0
        lyr = "CONTOUR-MAJOR" if major else "CONTOUR-MINOR"
        msp.add_spline(pts + pts[:1], degree=3, dxfattribs={"layer": lyr})
        if major:
            msp.add_text(f"{hgt}", height=3, dxfattribs={"layer": "TEXT", "style": "SITE"}).set_placement((pts[0][0] + 1, pts[0][1]), align=TextEntityAlignment.MIDDLE_LEFT)
    # Roads: two polylines with a width, a roundabout.
    msp.add_lwpolyline([(-40, 40), (60, 50), (140, 20), (260, 30), (360, 70)], dxfattribs={"layer": "ROAD", "const_width": 9})
    msp.add_lwpolyline([(140, 20), (150, -40), (130, -90)], dxfattribs={"layer": "ROAD", "const_width": 6})
    msp.add_circle((140, 20), 12, dxfattribs={"layer": "ROAD"})
    # Parcels with their numbers and areas.
    parcels = [[(20, 60), (120, 66), (116, 150), (14, 140)], [(120, 66), (230, 62), (240, 160), (116, 150)], [(230, 62), (330, 80), (320, 170), (240, 160)]]
    for i, p in enumerate(parcels):
        msp.add_lwpolyline(p, close=True, dxfattribs={"layer": "PARCEL"})
        cx = sum(a for a, _ in p) / 4
        cy = sum(b for _, b in p) / 4
        area = 0.5 * abs(sum(p[j][0] * p[(j + 1) % 4][1] - p[(j + 1) % 4][0] * p[j][1] for j in range(4)))
        m = msp.add_mtext(rf"Parcel {101 + i}\P{area:.0f} m²", dxfattribs={"layer": "TEXT", "style": "SITE", "char_height": 5, "attachment_point": 5})
        m.set_location((cx, cy - 40))
    # Buildings with a hatch.
    for x, y, w, d in [(40, 90, 40, 26), (150, 95, 34, 30), (262, 110, 44, 28)]:
        msp.add_lwpolyline([(x, y), (x + w, y), (x + w, y + d), (x, y + d)], close=True, dxfattribs={"layer": "BUILDING"})
        h = msp.add_hatch(color=252, dxfattribs={"layer": "BUILDING"})
        h.set_pattern_fill("ANSI31", color=8, scale=3)
        h.paths.add_polyline_path([(x, y), (x + w, y), (x + w, y + d), (x, y + d)], is_closed=True)
    # A pond (hatched gradient), trees as circles and points with heights.
    pond = [(280, -10), (310, -25), (340, -5), (325, 20), (295, 18)]
    msp.add_lwpolyline(pond, close=True, dxfattribs={"layer": "WATER"})
    h = msp.add_hatch(dxfattribs={"layer": "WATER"})
    h.set_gradient((140, 200, 255), (30, 90, 170), rotation=90, name="LINEAR")
    h.paths.add_polyline_path(pond, is_closed=True)
    import random
    rnd = random.Random(5)
    for _ in range(60):
        x, y = rnd.uniform(-20, 340), rnd.uniform(-110, 40)
        if 270 < x < 350 and -30 < y < 25:
            continue
        msp.add_circle((x, y), rnd.uniform(1.5, 3.2), dxfattribs={"layer": "TREES"})
    for i in range(30):
        x, y = rnd.uniform(0, 330), rnd.uniform(-90, 170)
        msp.add_point((x, y), dxfattribs={"layer": "SPOT", "color": 2})
        msp.add_text(f"{height(x, y):.2f}", height=1.8, dxfattribs={"layer": "SPOT", "style": "SITE"}).set_placement((x + 1.5, y + 0.5))
    # North arrow, scale bar, legend.
    msp.add_blockref("NORTH", (370, 180), dxfattribs={"layer": "LEGEND", "xscale": 0.02, "yscale": 0.02, "zscale": 0.02})
    for i in range(5):
        msp.add_lwpolyline([(0 + i * 20, -130), (20 + i * 20, -130), (20 + i * 20, -125), (0 + i * 20, -125)], close=True, dxfattribs={"layer": "LEGEND", "color": 7 if i % 2 else 8})
        h = msp.add_hatch(color=7 if i % 2 else 252, dxfattribs={"layer": "LEGEND"})
        h.set_solid_fill(color=7 if i % 2 else 252)
        h.paths.add_polyline_path([(0 + i * 20, -130), (20 + i * 20, -130), (20 + i * 20, -125), (0 + i * 20, -125)], is_closed=True)
    for i, v in enumerate((0, 20, 40, 60, 80, 100)):
        msp.add_text(f"{v}", height=3, dxfattribs={"layer": "LEGEND", "style": "SITE"}).set_placement((v, -138), align=TextEntityAlignment.TOP_CENTER)
    msp.add_text("m", height=3, dxfattribs={"layer": "LEGEND", "style": "SITE"}).set_placement((108, -138))
    ly = 170
    for lyr, label in [("CONTOUR-MINOR", "Contour, 2 m"), ("CONTOUR-MAJOR", "Contour, 10 m"), ("PARCEL", "Parcel boundary"), ("BUILDING", "Building"), ("ROAD", "Road"), ("WATER", "Water"), ("TREES", "Tree")]:
        msp.add_line((300 + 70, ly), (320 + 70, ly), dxfattribs={"layer": lyr})
        msp.add_text(label, height=3, dxfattribs={"layer": "LEGEND", "style": "SITE"}).set_placement((324 + 70, ly - 1))
        ly -= 8
    msp.add_text("SITE PLAN  1:1000", height=8, dxfattribs={"layer": "TEXT", "style": "SITE"}).set_placement((0, -160))
    save(doc, "site-plan.dxf")


# --------------------------------------------------------------- R12 drawing


def legacy_r12():
    doc = ezdxf.new("R12")
    doc.layers.add("GEAR", color=7)
    doc.layers.add("AXES", color=1, linetype="CENTER") if "CENTER" in doc.linetypes else doc.layers.add("AXES", color=1)
    doc.layers.add("TEXT", color=2)
    doc.layers.add("DIMS", color=3)
    msp = doc.modelspace()
    teeth, r_out, r_in = 20, 40.0, 33.0
    pts = []
    for i in range(teeth):
        a0 = i * 2 * math.pi / teeth
        step = 2 * math.pi / teeth
        for da, r in [(0.0, r_in), (step * 0.2, r_out), (step * 0.55, r_out), (step * 0.75, r_in)]:
            pts.append((r * math.cos(a0 + da), r * math.sin(a0 + da)))
    msp.add_polyline2d(pts, close=True, dxfattribs={"layer": "GEAR"})
    msp.add_circle((0, 0), 10, dxfattribs={"layer": "GEAR"})
    msp.add_circle((0, 0), 4, dxfattribs={"layer": "GEAR"})
    for i in range(6):
        a = i * math.pi / 3
        msp.add_circle((20 * math.cos(a), 20 * math.sin(a)), 4, dxfattribs={"layer": "GEAR"})
    msp.add_line((-50, 0), (50, 0), dxfattribs={"layer": "AXES"})
    msp.add_line((0, -50), (0, 50), dxfattribs={"layer": "AXES"})
    msp.add_arc((0, 0), r_in - 3, 30, 150, dxfattribs={"layer": "GEAR", "color": 4})
    msp.add_text("GEAR, 20 TEETH (R12 FILE)", height=4, dxfattribs={"layer": "TEXT"}).set_placement((-45, -58))
    msp.add_text("module 4, pitch diameter 80", height=3, dxfattribs={"layer": "TEXT"}).set_placement((-45, -64))
    msp.add_point((0, 0), dxfattribs={"layer": "AXES"})
    msp.add_solid([(55, 40), (65, 40), (55, 46), (65, 46)], dxfattribs={"layer": "DIMS"})
    msp.add_3dface([(55, -10, 0), (70, -10, 0), (70, 5, 0), (55, 5, 0)], dxfattribs={"layer": "DIMS", "color": 5})
    blk = doc.blocks.new("TAG")
    blk.add_circle((0, 0), 5)
    blk.add_text("1", dxfattribs={"height": 5}).set_placement((-1.5, -2))
    for i in range(3):
        msp.add_blockref("TAG", (60, 20 - i * 15), dxfattribs={"layer": "DIMS", "xscale": 1 + i * 0.3, "yscale": 1 + i * 0.3})
    save(doc, "legacy-r12.dxf")


if __name__ == "__main__":
    house_plan("R2018", "house-plan.dxf")
    house_plan("R2000", "house-plan-r2000.dxf")
    house_elevations()
    hatch_gallery()
    dimensions()
    linetypes()
    text_styles()
    blocks()
    bracket()
    site_plan()
    legacy_r12()
