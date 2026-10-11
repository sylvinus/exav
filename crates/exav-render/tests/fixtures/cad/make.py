#!/usr/bin/env python3
"""Write the DXF fixtures of exav-render's drawing model and what each was given.

    python3 make.py            # src/*.dxf.gz (ezdxf) and expected.json
    ODAFC=/path/to/odafc.sh python3 make.py --convert

`src/all.dxf` (2018) has every entity type the model holds and the cases
around them, also as ezdxf's binary DXF (`all-binary.dxf`);
`src/gradient.dxf` a gradient fill (not converted); `src/cp1251.dxf` (2000, code page
ANSI_1251) text outside ASCII; `src/dwgcases.dxf`, `src/entities.dxf`,
`src/objects.dxf` and `src/c7.dxf` cases of the DWG layout (converted to DWG only). Every file is stored gzipped, as the
converter's 2000-and-later output is mostly the same boilerplate.
`expected.json` records the values this script put in, in the
model's terms (angles in radians), for tests/cad_fixtures.rs to check every
conversion against: per entity handle, or per table entry name, a field
path into the `exav_render::cad::to_json` dump (`a.0.b`; `a#` is a list's length,
`a.*.b` collects over a list) and its value.

With --convert, the ODA File Converter (a black box, run through the wrapper
`$ODAFC IN OUT VERSION FORMAT`) writes each source as ASCII DXF and as
binary DXF (its "DXB" format) of R12, 2000, 2004, 2007, 2010, 2013 and 2018
into ascii/<VERSION>/ and binary/<VERSION>/. With --convert-dwg, it writes each
source as DWG of the versions the DWG reader reads into dwg/<VERSION>/;
--only=ACAD2004,ACAD2010 limits either to those versions, and
--source=entities,dwgcases writes and converts those sources only (ezdxf's
files are not byte-reproducible: their creation dates and GUIDs change).
--keep-src converts the committed src/ as it is, writing neither it nor
expected.json.

Needs ezdxf (tested with 1.4.1).
"""

import gzip
import json
import math
import os
import struct
import subprocess
import sys
import tempfile

import ezdxf
from ezdxf import colors
from ezdxf.lldxf.tags import Tags
from ezdxf.lldxf.types import DXFBinaryTag, DXFTag, DXFVertex
from ezdxf.math import Vec2, Vec3
from ezdxf.render import mleader

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "src")
VERSIONS = ["ACAD12", "ACAD2000", "ACAD2004", "ACAD2007", "ACAD2010", "ACAD2013", "ACAD2018"]
# The DWG versions the DWG reader reads (tests/cad_dwg.rs).
DWG_VERSIONS = [
    "ACAD13", "ACAD14", "ACAD2000", "ACAD2004", "ACAD2007", "ACAD2010", "ACAD2013", "ACAD2018",
]

expected = []
CURRENT = ""


def expect(e, fields=None, **named):
    """An entity's expected values: keyword arguments for plain fields, a
    dict for paths that are not identifiers."""
    expected.append(
        {
            "source": CURRENT,
            "handle": e.dxf.handle,
            "type": e.dxftype(),
            "fields": {**(fields or {}), **named},
        }
    )
    return e


def expect_entry(table, entry_name, key=None, **fields):
    """A table entry's or object's expected values, found by its name, or
    by the value of field `key` (`file_name`, `handle`...)."""
    entry = {"source": CURRENT, "table": table, "name": entry_name, "fields": fields}
    if key:
        entry["key"] = key
    expected.append(entry)


def alpha(transparency):
    return colors.float2transparency(transparency) & 0xFF


def r(deg):
    return math.radians(deg)


def p3(*v):
    return [float(x) for x in (list(v) + [0.0, 0.0, 0.0])[:3]]


def tables(doc):
    doc.layers.add("WALLS", color=1, linetype="DASHED", lineweight=50)
    expect_entry("layers", "WALLS", color=1, linetype="DASHED", lineweight=50)
    doc.layers.add("GLASS", true_color=colors.rgb2int((10, 200, 250)), transparency=0.5)
    expect_entry("layers", "GLASS", color="#0ac8fa", alpha=alpha(0.5))
    off = doc.layers.add("HIDDEN_OFF", color=3)
    off.off()
    expect_entry("layers", "HIDDEN_OFF", color=3, off=True)
    frozen = doc.layers.add("FROZEN", color=4)
    frozen.freeze()
    expect_entry("layers", "FROZEN", flags=1)
    doc.linetypes.add("DOTTED_X", [0.6, 0.5, -0.1], description="dots . . .")
    expect_entry(
        "linetypes", "DOTTED_X", description="dots . . .", **{"elements.*.length": [0.5, -0.1]}
    )
    doc.linetypes.add(
        "GAS_LINE",
        'A,.5,-.2,["GAS",STANDARD,S=.1,U=0.0,X=-0.1,Y=-.05],-.25',
        description="Gas line ---- GAS ----",
        length=0.95,
    )
    expect_entry(
        "linetypes",
        "GAS_LINE",
        **{
            "elements.*.length": [0.5, -0.2, -0.25],
            "elements.1.text": "GAS",
            "elements.1.scale": 0.1,
            "elements.1.offset": [-0.1, -0.05],
        },
    )
    doc.styles.add("LABELS", font="arial.ttf")
    expect_entry("text_styles", "LABELS", font_file="arial.ttf")
    doc.styles.add("NOTES", font="romans.shx").dxf.width = 0.8
    expect_entry("text_styles", "NOTES", font_file="romans.shx", width_factor=0.8)


def blocks(doc):
    ring = doc.blocks.new("RING", base_point=(1, 1))
    ring.add_circle((1, 1), radius=1)
    ring.add_attdef("ROOM", insert=(0, -1), dxfattribs={"height": 0.25})
    ring.add_attdef(
        "FIXED", insert=(0, -2), text="constant", dxfattribs={"height": 0.25, "flags": 2}
    )
    outer = doc.blocks.new("NESTED")
    outer.add_blockref("RING", (5, 0), dxfattribs={"xscale": 2, "yscale": 2})
    outer.add_line((0, 0), (5, 0))


def model(doc):
    msp = doc.modelspace()
    expect(
        msp.add_line((1, 2, 0), (3, 4, 0), dxfattribs={"layer": "WALLS", "color": 3}),
        start=p3(1, 2),
        end=p3(3, 4),
        layer="WALLS",
        color=3,
    )
    expect(
        msp.add_line(
            (0, 0), (10, 0), dxfattribs={"true_color": colors.rgb2int((255, 128, 0))}
        ),
        color="#ff8000",
    )
    t = msp.add_line((0, 1), (10, 1), dxfattribs={"linetype": "DOTTED_X", "ltscale": 2.0})
    t.transparency = 0.25
    expect(t, linetype="DOTTED_X", linetype_scale=2.0, transparency=alpha(0.25))
    expect(
        msp.add_line((0, 2), (10, 2), dxfattribs={"lineweight": 35, "color": 0}),
        lineweight=35,
        color="byblock",
    )
    expect(msp.add_point((5, 5, 1)), location=p3(5, 5, 1))
    expect(msp.add_circle((10, 10), 3), center=p3(10, 10), radius=3.0)
    expect(
        msp.add_arc((20, 10), 2, 30, 120),
        center=p3(20, 10),
        radius=2.0,
        start_angle=r(30),
        end_angle=r(120),
    )
    expect(
        msp.add_circle((30, 10), 1, dxfattribs={"extrusion": (0, 0, -1)}),
        extrusion=p3(0, 0, -1),
    )
    expect(
        msp.add_ellipse((40, 10), major_axis=(4, 0), ratio=0.5, start_param=0, end_param=math.pi),
        center=p3(40, 10),
        major_axis=p3(4, 0),
        ratio=0.5,
        start_param=0.0,
        end_param=math.pi,
    )
    fit = [(0, 20), (2, 23), (4, 20), (6, 23)]
    expect(msp.add_spline(fit), fit_points=[p3(*p) for p in fit])
    ctrl = [(10, 20), (12, 24), (14, 20), (16, 24)]
    expect(msp.add_open_spline(ctrl, degree=3), degree=3, control_points=[p3(*p) for p in ctrl])
    expect(
        msp.add_rational_spline(ctrl, [1, 2, 2, 1], degree=3),
        weights=[1.0, 2.0, 2.0, 1.0],
    )
    lw = [(0, 30, 0, 0, 0.5), (5, 30, 0.2, 0.4, 0), (5, 35, 0, 0, -1), (0, 35, 0, 0, 0)]
    expect(
        msp.add_lwpolyline(lw, format="xyseb", close=True),
        flags=1,
        vertices=[[float(x) for x in v] for v in lw],
    )
    p2d = msp.add_polyline2d([(10, 30), (15, 30), (15, 35)], close=True)
    expect(p2d, {"vertices.*.location": [p3(10, 30), p3(15, 30), p3(15, 35)]}, flags=1)
    p2d = msp.add_polyline2d([(20, 30), (25, 30)])
    p2d.vertices[0].dxf.bulge = 1.0
    expect(p2d, {"vertices.0.bulge": 1.0, "vertices#": 2})
    p3d = msp.add_polyline3d([(30, 30, 0), (35, 30, 5), (35, 35, 10)])
    expect(p3d, {"vertices.2.location": p3(35, 35, 10)}, flags=8)
    mesh = msp.add_polymesh((3, 3))
    for m_ in range(3):
        for n in range(3):
            mesh.set_mesh_vertex((m_, n), (40 + m_, 30 + n, m_ * n))
    expect(mesh, {"vertices#": 9}, flags=16, m_count=3, n_count=3)
    pf = msp.add_polyface()
    pf.append_face([(50, 30), (52, 30), (52, 32), (50, 32)])
    expect(pf, {"vertices#": 5, "vertices.4.indices": [1, 2, 3, 4]}, flags=64)
    expect(
        msp.add_solid([(0, 40), (2, 40), (0, 42), (2, 42)]),
        corners=[p3(0, 40), p3(2, 40), p3(0, 42), p3(2, 42)],
    )
    expect(
        msp.add_solid([(5, 40), (7, 40), (5, 42)]),
        corners=[p3(5, 40), p3(7, 40), p3(5, 42), p3(5, 42)],
    )
    expect(
        msp.add_trace([(10, 40), (12, 40), (10, 42), (12, 42)]),
        corners=[p3(10, 40), p3(12, 40), p3(10, 42), p3(12, 42)],
    )
    expect(
        msp.add_3dface([(20, 40, 0), (22, 40, 1), (22, 42, 2), (20, 42, 3)]),
        corners=[p3(20, 40, 0), p3(22, 40, 1), p3(22, 42, 2), p3(20, 42, 3)],
    )
    expect(
        msp.add_text(
            "Left text", height=2.5, rotation=15, dxfattribs={"insert": (0, 50), "style": "LABELS"}
        ),
        value="Left text",
        height=2.5,
        rotation=r(15),
        style="LABELS",
        insertion=p3(0, 50),
    )
    t = msp.add_text("Centred %%c50 %%d", height=1.0, dxfattribs={"style": "NOTES"})
    t.set_placement((20, 50), align=ezdxf.enums.TextEntityAlignment.MIDDLE_CENTER)
    expect(t, value="Centred %%c50 %%d", h_align="center", v_align="middle", alignment_point=p3(20, 50))
    t = msp.add_text("Fitted", height=1.0)
    t.set_placement((30, 50), (40, 50), align=ezdxf.enums.TextEntityAlignment.FIT)
    expect(t, h_align="fit", insertion=p3(30, 50), alignment_point=p3(40, 50))
    expect(
        msp.add_text("Unicode Ä ж 中", height=1.0, dxfattribs={"insert": (50, 50)}),
        value="Unicode Ä ж 中",
    )
    mt = msp.add_mtext(
        "First line\\PSecond {\\C1;red} line", dxfattribs={"char_height": 1.5, "width": 20}
    )
    mt.dxf.insert = (0, 60)
    mt.dxf.rotation = 30
    expect(
        mt,
        text="First line\\PSecond {\\C1;red} line",
        height=1.5,
        reference_width=20.0,
        insertion=p3(0, 60),
    )
    long = "x" * 600 + " end"
    expect(msp.add_mtext(long, dxfattribs={"insert": (30, 60)}), text=long)
    ins = msp.add_blockref("RING", (0, 70), dxfattribs={"rotation": 45, "xscale": 2, "yscale": 3})
    ins.add_auto_attribs({"ROOM": "Kitchen"})
    expect(
        ins,
        {"attributes.0.tag": "ROOM", "attributes.0.text.value": "Kitchen"},
        block_name="RING",
        rotation=r(45),
        scale=[2.0, 3.0, 1.0],
    )
    minsert = msp.add_blockref("RING", (10, 70))
    minsert.grid(size=(2, 3), spacing=(4, 5))
    expect(minsert, rows=2, columns=3, row_spacing=4.0, column_spacing=5.0)
    expect(msp.add_blockref("NESTED", (30, 70)), block_name="NESTED")

    for dim in (
        msp.add_linear_dim(base=(0, 85), p1=(0, 80), p2=(10, 80)),
        msp.add_aligned_dim(p1=(20, 80), p2=(30, 85), distance=2),
        msp.add_angular_dim_2l(
            base=(45, 85), line1=((40, 80), (50, 80)), line2=((40, 80), (48, 86))
        ),
        msp.add_diameter_dim(center=(60, 82), radius=3, angle=45),
        msp.add_radius_dim(center=(70, 82), radius=3, angle=45),
        msp.add_angular_dim_3p(base=(85, 85), center=(80, 80), p1=(85, 80), p2=(80, 85)),
        msp.add_ordinate_x_dim(feature_location=(90, 80), offset=(2, 5)),
    ):
        dim.render()
        kind = [
            "linear",
            "aligned",
            "angular",
            "diameter",
            "radius",
            "angular_3_point",
            "ordinate",
        ][dim.dimension.dxf.dimtype & 7]
        # The converter renumbers the anonymous blocks: the test checks the
        # named block exists instead of its name.
        expect(dim.dimension, kind=kind)

    expect(
        msp.add_leader([(0, 90), (5, 95), (10, 95)]),
        vertices=[p3(0, 90), p3(5, 95), p3(10, 95)],
    )
    ml = msp.add_multileader_mtext("Standard")
    ml.set_content("Leader text", char_height=1.0)
    ml.add_leader_line(mleader.ConnectionSide.left, [Vec2(20, 90), Vec2(23, 93)])
    ml.build(insert=Vec2(28, 95))
    expect(
        ml.multileader,
        {
            "context.text": "Leader text",
            "context.has_text": True,
            "context.leaders.0.lines.0.vertices.0": p3(20, 90),
        },
    )
    mline = msp.add_mline([(40, 90), (50, 90), (50, 95)])
    expect(mline, {"vertices.*.position": [p3(40, 90), p3(50, 90), p3(50, 95)]})

    hatch_cases(msp)

    helix = msp.add_helix(radius=2, pitch=1, turns=3)
    expect(helix, {"spline.control_points#": len(helix.control_points)}, radius=2.0, turns=3.0)
    expect(msp.add_ray((0, 100), (1, 1)), base=p3(0, 100))
    expect(msp.add_xline((5, 100), (0, 1)), base=p3(5, 100), direction=p3(0, 1))
    expect(
        msp.add_wipeout([(10, 100), (14, 100), (14, 103), (10, 103)]),
        insertion=p3(10, 100),
    )
    image_def = doc.add_image_def("photo.png", size_in_pixel=(640, 480))
    expect(
        msp.add_image(image_def, insert=(20, 100), size_in_units=(6.4, 4.8)),
        insertion=p3(20, 100),
        size=[640.0, 480.0],
    )
    pdf = doc.add_underlay_def("plan.pdf", fmt="pdf", name="1")
    expect(
        msp.add_underlay(pdf, insert=(30, 100), scale=(2, 2, 1), rotation=10),
        insertion=p3(30, 100),
        rotation=r(10),
    )
    doc.styles.add_shx("ltypeshp.shx")
    expect(msp.add_shape("TRACK1", (40, 100), size=2), name="TRACK1", size=2.0)


def hatch_cases(msp):
    # Solid, polyline loop with a bulge and an island.
    h = msp.add_hatch(color=2)
    h.paths.add_polyline_path([(0, 110, 0), (10, 110, 0.5), (10, 120, 0), (0, 120, 0)], is_closed=True)
    h.paths.add_polyline_path([(3, 113), (6, 113), (6, 116)], is_closed=True)
    expect(h, {"paths#": 2, "paths.0.vertices.1": [10.0, 110.0, 0.5]}, solid=True)
    # Pattern, every edge type.
    h = msp.add_hatch()
    h.set_pattern_fill("ANSI31", scale=0.5, angle=15)
    path = h.paths.add_edge_path()
    path.add_line((20, 110), (30, 110))
    path.add_arc((30, 115), radius=5, start_angle=-90, end_angle=90, ccw=True)
    path.add_line((30, 120), (25, 120))
    path.add_ellipse((22.5, 120), major_axis=(2.5, 0), ratio=0.5, start_angle=0, end_angle=180, ccw=True)
    path.add_spline(
        fit_points=[(20, 120), (19, 116), (20, 110)],
        control_points=[(20, 120), (18, 117), (18, 113), (20, 110)],
        knot_values=[0, 0, 0, 0, 1, 1, 1, 1],
        degree=3,
    )
    expect(
        h,
        {
            "paths.0.edges.*.type": ["line", "arc", "line", "ellipse", "spline"],
            "paths.0.edges.4.control_points#": 4,
            "paths.0.edges.4.knots": [0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 1.0, 1.0],
        },
        pattern_name="ANSI31",
        pattern_scale=0.5,
        pattern_angle=r(15),
    )
    # A clockwise arc edge.
    h = msp.add_hatch(color=5)
    path = h.paths.add_edge_path()
    path.add_line((40, 110), (50, 110))
    path.add_arc((45, 110), radius=5, start_angle=0, end_angle=180, ccw=False)
    expect(h, {"paths.0.edges.1.counter_clockwise": False, "paths.0.edges.1.radius": 5.0})


def gradient_dxf():
    """A gradient fill, in a file of its own: the converter fails to write
    a drawing holding one as 2000 or R12, which have no gradients."""
    global CURRENT
    CURRENT = "gradient"
    doc = ezdxf.new("R2018")
    h = doc.modelspace().add_hatch()
    h.set_gradient((255, 0, 0), (0, 0, 255), rotation=30, name="CYLINDER")
    h.paths.add_polyline_path([(60, 110), (70, 110), (70, 120), (60, 120)], is_closed=True)
    expect(
        h,
        {
            "gradient.name": "CYLINDER",
            "gradient.angle": r(30),
            "gradient.colors.*.1": ["#ff0000", "#0000ff"],
        },
    )
    save(doc, "gradient.dxf")


def layouts(doc):
    sheet = doc.layouts.new("Sheet A")
    sheet.page_setup(size=(420, 297), margins=(10, 10, 10, 10), units="mm")
    vp = sheet.add_viewport(center=(200, 150), size=(300, 200), view_center_point=(30, 60), view_height=150)
    vp.frozen_layers = ["WALLS"]
    expect(
        vp,
        {"frozen_layers#": 1},
        center=p3(200, 150),
        width=300.0,
        height=200.0,
        view_height=150.0,
        view_center=[30.0, 60.0],
    )
    expect(sheet.add_text("Title", height=5, dxfattribs={"insert": (20, 20)}), paper_space=True)
    expect_entry("layouts", "Sheet A", **{"plot.paper_width": 420.0, "plot.paper_height": 297.0})


def all_dxf():
    global CURRENT
    CURRENT = "all"
    doc = ezdxf.new("R2018", setup=True)
    doc.header["$INSUNITS"] = 4
    doc.header["$LTSCALE"] = 2.5
    doc.header["$MEASUREMENT"] = 1
    expected.append(
        {"source": CURRENT, "header": True, "fields": {"insunits": 4, "ltscale": 2.5, "measurement": 1}}
    )
    tables(doc)
    blocks(doc)
    model(doc)
    layouts(doc)
    save(doc, "all.dxf")
    if not selected("all-binary.dxf") or "--keep-src" in sys.argv:
        return
    # The same drawing as ezdxf writes binary DXF.
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "all.dxf")
        doc.saveas(path, fmt="bin")
        with open(path, "rb") as f:
            write_gz(os.path.join(SRC, "all-binary.dxf.gz"), f.read())


def cp1251_dxf():
    global CURRENT
    CURRENT = "cp1251"
    doc = ezdxf.new("R2000")
    # Sets $DWGCODEPAGE to ANSI_1251, and the file's encoding.
    doc.encoding = "cp1251"
    doc.layers.add("Стены", color=1)
    expect_entry("layers", "Стены", color=1)
    msp = doc.modelspace()
    expect(
        msp.add_text("Привет", height=1.0, dxfattribs={"layer": "Стены"}),
        value="Привет",
        layer="Стены",
    )
    # Outside the code page: ezdxf writes \U+XXXX escapes.
    expect(msp.add_text("中文 ✓", height=1.0, dxfattribs={"insert": (0, 5)}), value="中文 ✓")
    expect(msp.add_mtext("Строка\\Pвторая", dxfattribs={"insert": (0, 10)}), text="Строка\\Pвторая")
    save(doc, "cp1251.dxf")


def dwg_cases_dxf():
    """Cases of the DWG layout the other sources do not have, converted to
    DWG only: an xref block (whose record has no owned entity list), and a
    linetype with two texts (the second at an offset into the text area)."""
    global CURRENT
    CURRENT = "dwgcases"
    doc = ezdxf.new("R2018")
    doc.add_xref_def("other.dwg", "XREF_A")
    doc.blocks.get("XREF_A").block.dxf.base_point = (2, 3, 0)
    expect_entry("blocks", "XREF_A", flags=4, xref_path="other.dwg", base_point=[2.0, 3.0, 0.0])
    doc.linetypes.add(
        "SPR_LINE",
        'A,.5,-.2,["SPR",STANDARD,S=.1,U=0.0,X=-0.1,Y=-.05],-.25,.5,-.2,["SPR",STANDARD,S=.1,U=0.0,X=-0.1,Y=-.05],-.25',
        description="two texts",
        length=1.9,
    )
    expect_entry("linetypes", "SPR_LINE", **{"elements.1.text": "SPR", "elements.4.text": "SPR"})
    doc.modelspace().add_line((0, 0), (10, 0), dxfattribs={"linetype": "SPR_LINE"})
    save(doc, "dwgcases.dxf")


def entities_dxf():
    """Entity cases the corpus and `all` lack, converted to DWG only:
    MTEXT columns and background, a multiline attribute, DWF and DGN
    underlays, an OLE2FRAME, an arc dimension, viewports off and clipped,
    polylines with widths, splines closed and through fit points."""
    global CURRENT
    CURRENT = "entities"
    doc = ezdxf.new("R2018", setup=True)
    msp = doc.modelspace()
    m = msp.add_mtext_static_columns(
        ["First column", "Second column"], width=8, gutter_width=1, height=20,
        dxfattribs={"insert": (0, 0), "char_height": 1},
    )
    expect(
        m,
        {"columns.kind": 1, "columns.count": 2, "columns.width": 8.0, "columns.gutter": 1.0},
    )
    m = msp.add_mtext_dynamic_manual_height_columns(
        "Flowing text " * 20, width=6, gutter_width=0.5, heights=[4, 5, 6],
        dxfattribs={"insert": (20, 0), "char_height": 0.5},
    )
    expect(m, {"columns.kind": 2, "columns.count": 3, "columns.heights": [4.0, 5.0, 6.0]})
    m = msp.add_mtext("Masked", dxfattribs={"insert": (40, 0), "char_height": 1})
    m.set_bg_color((200, 10, 30), scale=1.25)
    expect(m, background_fill=1, background_color="#c80a1e", background_scale=1.25)
    m = msp.add_mtext("Rotated", dxfattribs={"insert": (50, 0), "char_height": 1})
    m.dxf.text_direction = (0, 1, 0)
    expect(m, x_direction=p3(0, 1, 0))

    block = doc.blocks.new("TAGGED")
    block.add_circle((0, 0), 1)
    attdef = block.add_attdef("NOTE", (0, -2), dxfattribs={"height": 0.5})
    ins = msp.add_blockref("TAGGED", (0, 30))
    a = ins.add_attrib("NOTE", "line one", (0, 28), dxfattribs={"height": 0.5})
    note = msp.add_mtext("line one\\Pline two", dxfattribs={"insert": (0, 28), "char_height": 0.5})
    a.embed_mtext(note)
    expect(
        ins,
        {"attributes.0.tag": "NOTE", "attributes.0.mtext.text": "line one\\Pline two"},
    )
    expect(attdef, tag="NOTE")

    for fmt, name, where in (("dwf", "1", (60, 0)), ("dgn", "default", (70, 0))):
        d = doc.add_underlay_def(f"plan.{fmt}", fmt=fmt, name=name)
        u = msp.add_underlay(d, insert=where, scale=(2, 3, 1), rotation=20)
        u.dxf.contrast = 70
        u.dxf.fade = 10
        expect(
            u,
            kind=fmt,
            insertion=p3(*where),
            scale=[2.0, 3.0, 1.0],
            rotation=r(20),
            contrast=70,
            fade=10,
        )

    payload = compound_file("CONTENTS", b"an embedded object")
    expect(
        ole2frame(msp, (80, 10), (90, 0), payload),
        upper_left=p3(80, 10),
        lower_right=p3(90, 0),
        version=2,
    )

    arc = msp.add_arc_dim_3p(base=(5, 45), center=(0, 40), p1=(4, 40), p2=(0, 44))
    arc.render()
    expect(arc.dimension, kind="angular_3_point", point15=p3(0, 40))

    pl = msp.add_polyline2d(
        [(0, 50), (5, 50), (5, 55)], dxfattribs={"default_start_width": 0.4, "default_end_width": 0.2}
    )
    pl.vertices[1].dxf.start_width = 1.0
    pl.vertices[1].dxf.end_width = 0.6
    expect(
        pl,
        {"vertices.1.start_width": 1.0, "vertices.1.end_width": 0.6},
        default_start_width=0.4,
        default_end_width=0.2,
    )
    # Closed and periodic (a closed flag on clamped knots the converter
    # drops).
    closed = msp.add_spline()
    closed.apply_construction_tool(
        ezdxf.math.closed_uniform_bspline([(10, 50), (14, 52), (12, 56), (8, 54)], order=4)
    )
    closed.closed = True
    expect(closed, flags=3)
    fit = msp.add_spline([(20, 50), (22, 53), (25, 51)])
    fit.dxf.start_tangent = (1, 1, 0)
    fit.dxf.end_tangent = (1, -1, 0)
    expect(fit, fit_points=[p3(20, 50), p3(22, 53), p3(25, 51)])
    t = msp.add_text("Right", height=1.0)
    t.set_placement((35, 50, 2.5), align=ezdxf.enums.TextEntityAlignment.BOTTOM_RIGHT)
    expect(t, h_align="right", v_align="bottom", alignment_point=p3(35, 50, 2.5))
    expect(
        msp.add_3dface([(40, 50), (42, 50), (42, 52), (40, 52)], dxfattribs={"invisible_edges": 5}),
        invisible_edges=5,
    )
    expect(
        msp.add_blockref("TAGGED", (50, 50), dxfattribs={"xscale": 2, "yscale": 3, "zscale": 4}),
        scale=[2.0, 3.0, 4.0],
    )

    sheet = doc.layouts.new("Sheet B")
    on = sheet.add_viewport(center=(100, 100), size=(80, 60), view_center_point=(0, 0), view_height=50)
    expect(on, status=1, id=1)
    off = sheet.add_viewport(center=(200, 100), size=(80, 60), view_center_point=(0, 0), view_height=50)
    off.dxf.flags = off.dxf.flags | 0x20000
    # The converter's DXF numbers an off viewport -1 (experiments/stacking).
    expect(off, status=0, id=-1)
    frame = sheet.add_lwpolyline([(150, 150), (190, 150), (170, 190)], close=True)
    clipped = sheet.add_viewport(center=(170, 165), size=(40, 40), view_center_point=(0, 0), view_height=50)
    clipped.dxf.clipping_boundary_handle = frame.dxf.handle
    clipped.dxf.flags = clipped.dxf.flags | 0x10000
    expect(clipped, clip_boundary=frame.dxf.handle, id=3)
    save(doc, "entities.dxf")


def objects_dxf():
    """Objects the drawing depends on, converted to DWG only: a layout with
    its page setup, its insertion base and UCS origin apart, and four
    viewports whose last active one is not the first; a multiline style
    with elements on a linetype, ByBlock and ByLayer; a multileader style;
    an image and a PDF underlay definition; a draw order table; a
    dictionary of our own."""
    global CURRENT
    CURRENT = "objects"
    doc = ezdxf.new("R2018", setup=True)
    msp = doc.modelspace()

    sheet = doc.layouts.new("Plot A")
    sheet.page_setup(size=(297, 210), units="mm")
    lay = sheet.dxf_layout
    values = {
        "left_margin": 5.0, "bottom_margin": 6.0, "right_margin": 7.0, "top_margin": 8.0,
        "plot_origin_x_offset": 1.25, "plot_origin_y_offset": 2.25,
        "plot_window_x1": -3.0, "plot_window_y1": -4.0, "plot_window_x2": 30.0, "plot_window_y2": 40.0,
        "scale_numerator": 1.0, "scale_denominator": 50.0, "plot_rotation": 1, "plot_type": 4,
        "paper_image_origin_x": 0.5, "paper_image_origin_y": 0.75,
        "insert_base": (1.5, 2.5, 3.5), "ucs_origin": (7.25, 8.25, 9.25),
        "limmin": (-1, -2), "limmax": (297, 210), "extmin": (4, 5, 6), "extmax": (40, 50, 60),
        "elevation": 0.75,
    }
    for k, v in values.items():
        lay.dxf.set(k, v)
    main = sheet.main_viewport()
    vps = [
        sheet.add_viewport(center=(60 + 70 * i, 100), size=(60, 40), view_center_point=(i, i), view_height=10 + i)
        for i in range(3)
    ]
    # The converter takes the last active viewport from status 1 (68): the
    # third here; its DXF of the DWG stacks it first, the rest in order
    # (experiments/stacking).
    main.dxf.status = 2
    vps[0].dxf.status = 3
    vps[1].dxf.status = 4
    vps[2].dxf.status = 1
    lay.dxf.viewport_handle = vps[2].dxf.handle
    expect(main, status=2, id=1)
    expect(vps[0], status=3, id=2)
    expect(vps[1], status=4, id=3)
    expect(vps[2], status=1, id=4)
    expect_entry(
        "layouts",
        "Plot A",
        **{
            "insertion_base": [1.5, 2.5, 3.5],
            "ucs_origin": [7.25, 8.25, 9.25],
            "limits_min": [-1.0, -2.0],
            "limits_max": [297.0, 210.0],
            "extents_min": [4.0, 5.0, 6.0],
            "extents_max": [40.0, 50.0, 60.0],
            "elevation": 0.75,
            "last_viewport": vps[2].dxf.handle,
            "plot.margins": [5.0, 6.0, 7.0, 8.0],
            "plot.paper_width": 297.0,
            "plot.paper_height": 210.0,
            "plot.origin": [1.25, 2.25],
            "plot.window_min": [-3.0, -4.0],
            "plot.window_max": [30.0, 40.0],
            "plot.scale_denominator": 50.0,
            "plot.rotation": 1,
            "plot.plot_type": 4,
            "plot.image_origin": [0.5, 0.75],
        },
    )

    style = doc.mline_styles.new("TRIPLE")
    style.dxf.flags = 1 | 2 | 16 | 512
    style.dxf.fill_color = 3
    style.dxf.start_angle = 80
    style.dxf.end_angle = 100
    style.elements.append(0.5, 1, "DASHED")
    style.elements.append(0.0, 0, "BYBLOCK")
    style.elements.append(-0.5, 5, "BYLAYER")
    msp.add_mline([(0, 0), (10, 0), (10, 10)], dxfattribs={"style_name": "TRIPLE"})
    expect_entry(
        "mline_styles",
        "TRIPLE",
        flags=1 | 2 | 16 | 512,
        fill_color=3,
        start_angle=r(80),
        end_angle=r(100),
        **{
            "elements.*.offset": [0.5, 0.0, -0.5],
            "elements.*.color": [1, "byblock", 5],
            "elements.*.linetype": ["DASHED", "BYBLOCK", "BYLAYER"],
        },
    )

    ml = doc.mleader_styles.new("Callout")
    for k, v in {
        "content_type": 2, "leader_type": 2, "leader_line_color": colors.encode_raw_color(4),
        "leader_lineweight": 35, "has_landing": 1, "landing_gap_size": 0.3, "has_dogleg": 1,
        "dogleg_length": 1.5, "arrow_head_size": 0.6, "text_left_attachment_type": 3,
        "text_right_attachment_type": 4, "text_angle_type": 2, "text_alignment_type": 1,
        "text_color": colors.encode_raw_color(6), "char_height": 0.4, "has_text_frame": 1,
        "block_scale_x": 2.0, "block_scale_y": 3.0, "block_scale_z": 1.0, "block_rotation": 0.5,
        "block_connection_type": 1, "scale": 2.5,
    }.items():
        ml.dxf.set(k, v)
    expect_entry(
        "mleader_styles",
        "Callout",
        content_type=2,
        leader_line_type=2,
        leader_line_color=4,
        leader_lineweight=35,
        landing=True,
        landing_gap=0.3,
        dogleg=True,
        dogleg_length=1.5,
        arrowhead_size=0.6,
        text_left_attachment=3,
        text_right_attachment=4,
        text_angle_type=2,
        text_alignment_type=1,
        text_color=6,
        text_height=0.4,
        text_frame=True,
        block_scale=[2.0, 3.0, 1.0],
        block_rotation=0.5,
        block_connection=1,
        scale=2.5,
    )

    image_def = doc.add_image_def("photo.png", size_in_pixel=(640, 480))
    image_def.dxf.resolution_units = 2
    msp.add_image(image_def, insert=(20, 0), size_in_units=(6.4, 4.8))
    expect_entry(
        "image_defs", "photo.png", key="file_name", size=[640.0, 480.0], resolution_units=2, loaded=True
    )
    pdf = doc.add_underlay_def("plan.pdf", fmt="pdf", name="3")
    msp.add_underlay(pdf, insert=(30, 0))
    expect_entry("underlay_defs", "plan.pdf", key="file_name", kind="pdf", name="3")

    first = msp.add_line((0, 20), (5, 20))
    second = msp.add_line((0, 21), (5, 21))
    msp.set_redraw_order([(first.dxf.handle, "FFF0"), (second.dxf.handle, "FFE0")])
    expect_entry(
        "sort_tables",
        msp.block_record_handle,
        key="block_record",
        entries=[[first.dxf.handle, "FFF0"], [second.dxf.handle, "FFE0"]],
    )

    own = doc.rootdict.add_new_dict("EXAV_OBJECTS")
    own.dxf.cloning = 2
    own.add_xrecord("NOTE")
    expect_entry("dictionaries", own.dxf.handle, key="handle", cloning=2, **{"entries.*.0": ["NOTE"]})
    save(doc, "objects.dxf")


def c7_dxf():
    """Cases the real-world corpus showed, converted to DWG only: TEXT and
    MTEXT whose value has a \\U+ escape (the converter keeps it as written
    in 2007 and later DWG, decodes it before), OLE2FRAMEs in model space,
    paper space and a block (the converter's DXF tile mode, 72, is 0 in
    model space only), a HATCH edge on an ellipse, and a layout whose
    overall viewport is off."""
    global CURRENT
    CURRENT = "c7"
    doc = ezdxf.new("R2018")
    msp = doc.modelspace()
    m = msp.add_mtext("73\\U+00B0 MTEXT", dxfattribs={"insert": (0, 0), "char_height": 1})
    expect(m, text="73° MTEXT")
    t = msp.add_text("TEXT 45\\U+00B0", dxfattribs={"insert": (0, 5), "height": 1})
    expect(t, value="TEXT 45°")
    payload = compound_file("Contents", b"c7")
    expect(ole2frame(msp, (10, 10), (15, 5), payload), tile_mode=0)
    expect(ole2frame(doc.layout("Layout1"), (10, 10), (15, 5), payload), tile_mode=1)
    block = doc.blocks.new("OLE_IN_BLOCK")
    expect(ole2frame(block, (10, 10), (15, 5), payload), tile_mode=1)
    msp.add_blockref("OLE_IN_BLOCK", (30, 0))
    # A HATCH edge on an ellipse: DXF's 50 and 51 are angles, a DWG keeps
    # the ellipse's parameters at them (0.857 for 30 degrees at ratio 0.5).
    h = msp.add_hatch(color=1)
    path = h.paths.add_edge_path()
    path.add_ellipse((0, 0), (10, 0), ratio=0.5, start_angle=30, end_angle=120)
    path.add_line((-2.773500981126146, 4.803844614152614), (6.546536707079771, 3.7796447300922722))
    expect(h, {"paths.0.edges.0.start_angle": r(30), "paths.0.edges.0.end_angle": r(120)})
    # A layout whose overall viewport is off: it keeps number 1, another
    # off viewport is -1 (the converter's DXF of its DWG).
    sheet = doc.layouts.new("Off sheet")
    sheet.page_setup(size=(297, 210), units="mm")
    main = sheet.main_viewport()
    main.dxf.flags = main.dxf.flags | 0x20000
    on = sheet.add_viewport(center=(100, 100), size=(50, 50), view_center_point=(0, 0), view_height=10)
    off = sheet.add_viewport(center=(200, 100), size=(50, 50), view_center_point=(0, 0), view_height=10)
    off.dxf.flags = off.dxf.flags | 0x20000
    expect(main, id=1, status=0)
    expect(on, id=2, status=1)
    expect(off, id=-1, status=0)
    save(doc, "c7.dxf")


def compound_file(stream, data):
    """A compound file (MS-CFB, version 3) holding one stream of fewer than
    4096 bytes: header, FAT, directory, mini FAT, mini stream."""
    end, free, fat_sect = 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD
    minis = max(1, (len(data) + 63) // 64)
    mini_stream = data.ljust(minis * 64, b"\0")
    sectors = (len(mini_stream) + 511) // 512
    header = bytearray(512)
    header[0:8] = bytes.fromhex("D0CF11E0A1B11AE1")
    struct.pack_into("<HHHHH", header, 24, 0x3E, 3, 0xFFFE, 9, 6)
    # FAT sectors, first directory sector, mini stream cutoff, first mini
    # FAT sector and count, no DIFAT sectors.
    struct.pack_into("<IIIIIIII", header, 44, 1, 1, 0, 4096, 2, 1, end, 0)
    struct.pack_into("<I", header, 76, 0)
    for i in range(1, 109):
        struct.pack_into("<I", header, 76 + 4 * i, free)
    fat = [fat_sect, end, end] + [3 + i + 1 for i in range(sectors - 1)] + [end]
    fat += [free] * (128 - len(fat))
    minifat = [i + 1 for i in range(minis - 1)] + [end]
    minifat += [free] * (128 - len(minifat))

    def entry(name, kind, child, start, size):
        e = bytearray(128)
        n = (name + "\0").encode("utf-16-le")
        e[0 : len(n)] = n
        struct.pack_into("<HBB", e, 64, len(n), kind, 1)
        struct.pack_into("<III", e, 68, free, free, child)
        struct.pack_into("<IQ", e, 116, start, size)
        return bytes(e)

    empty = bytearray(128)
    struct.pack_into("<III", empty, 68, free, free, free)
    directory = (
        entry("Root Entry", 5, 1, 3, len(mini_stream))
        + entry(stream, 2, free, 0, len(data))
        + bytes(empty) * 2
    )
    return (
        bytes(header)
        + struct.pack("<128I", *fat)
        + directory
        + struct.pack("<128I", *minifat)
        + mini_stream.ljust(sectors * 512, b"\0")
    )


def ole2frame(msp, upper_left, lower_right, payload):
    """An OLE2FRAME embedding `payload` (a compound file), its data laid out
    as AutoCAD's: two bytes, the four corners from the upper left
    clockwise, 26 bytes, the compound file's length, the compound file."""
    (x0, y0), (x1, y1) = upper_left, lower_right
    corners = [(x0, y0, 0.0), (x1, y0, 0.0), (x1, y1, 0.0), (x0, y1, 0.0)]
    data = b"\x80\x55" + b"".join(struct.pack("<3d", *c) for c in corners)
    data += bytes(26) + struct.pack("<I", len(payload)) + payload
    e = msp.new_entity("OLE2FRAME", {})
    tags = [DXFTag(100, "AcDbOle2Frame"), DXFTag(70, 2), DXFTag(3, "Package")]
    tags += [DXFVertex(10, (x0, y0, 0.0)), DXFVertex(11, (x1, y1, 0.0))]
    tags += [DXFTag(71, 2), DXFTag(72, 0), DXFTag(90, len(data))]
    tags += [DXFBinaryTag(310, data[i : i + 127]) for i in range(0, len(data), 127)]
    tags += [DXFTag(1, "OLE")]
    e.acdb_ole2frame = Tags(tags)
    return e


def write_gz(path, data):
    # mtime 0 and no file name: the same input gives the same bytes.
    with open(path, "wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as f:
            f.write(data)


def selected(name):
    """Whether --source names this source (or there is no --source)."""
    only = [a[len("--source="):].split(",") for a in sys.argv if a.startswith("--source=")]
    return not only or name.split(".")[0].split("-")[0] in only[0]


def save(doc, name):
    if not selected(name) or "--keep-src" in sys.argv:
        return
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, name)
        doc.saveas(path)
        with open(path, "rb") as f:
            write_gz(os.path.join(SRC, name + ".gz"), f.read())


# Sources not converted in some versions: the converter fails to write a
# gradient fill as 2000 or R12, and writes ezdxf's as a plain solid fill in
# the others, so the gradient is checked in ezdxf's own file only.
SKIP = {"gradient.dxf": VERSIONS + DWG_VERSIONS}
# Sources converted to DWG only.
DWG_ONLY = {"dwgcases.dxf", "entities.dxf", "objects.dxf", "c7.dxf"}


def convert(dwg):
    """The sources as DXF (ascii/, binary/), or with `dwg` as DWG (dwg/)."""
    odafc = os.environ.get("ODAFC")
    if not odafc:
        sys.exit("set ODAFC to the ODA File Converter wrapper")
    with tempfile.TemporaryDirectory() as plain:
        for name in os.listdir(SRC):
            if name.endswith(".dxf.gz") and "binary" not in name:
                with gzip.open(os.path.join(SRC, name)) as f, open(
                    os.path.join(plain, name[:-3]), "wb"
                ) as out:
                    out.write(f.read())
        if dwg:
            runs = [("DWG", "dwg", DWG_VERSIONS)]
        else:
            runs = [("DXF", "ascii", VERSIONS), ("DXB", "binary", VERSIONS)]
        only = [a[len("--only="):].split(",") for a in sys.argv if a.startswith("--only=")]
        for fmt, folder, versions in runs:
            for version in versions:
                if only and version not in only[0]:
                    continue
                out = os.path.join(HERE, folder, version.replace("ACAD", "R"))
                os.makedirs(out, exist_ok=True)
                for name in sorted(os.listdir(plain)):
                    if version in SKIP.get(name, ()) or (not dwg and name in DWG_ONLY):
                        continue
                    if not selected(name):
                        continue
                    with tempfile.TemporaryDirectory() as tmp:
                        subprocess.run([odafc, plain, tmp, version, fmt, name], check=True)
                        made = os.path.join(tmp, name)
                        if dwg:
                            made = made[: -len(".dxf")] + ".dwg"
                        if not os.path.exists(made) or os.path.getsize(made) == 0:
                            sys.exit(f"the converter wrote no {version} {fmt} of {name}")
                        with open(made, "rb") as f:
                            write_gz(os.path.join(out, os.path.basename(made) + ".gz"), f.read())


if __name__ == "__main__":
    os.makedirs(SRC, exist_ok=True)
    all_dxf()
    gradient_dxf()
    cp1251_dxf()
    dwg_cases_dxf()
    entities_dxf()
    objects_dxf()
    c7_dxf()
    if "--keep-src" not in sys.argv:
        with open(os.path.join(HERE, "expected.json"), "w", encoding="utf-8") as f:
            json.dump(expected, f, ensure_ascii=False, indent=1)
    if "--convert" in sys.argv:
        convert(dwg=False)
    if "--convert-dwg" in sys.argv:
        convert(dwg=True)
