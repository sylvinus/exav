#!/usr/bin/env python3
"""Writes the IFC fixtures of tests/ifc.rs and their expected values.

Each fixture is STEP text written here directly (no IFC library), one
element per representation case, with dimensions chosen so that the volume
and the extents have a closed form computed below, independently of the
reader under test. `expected.json` maps file -> element name -> {volume,
min, max, tol} (metres; `tol` relative, for curves sampled as chords) and
the file-level checks.

    python3 make.py   (writes *.ifc and expected.json beside this script)
"""
import json
import math
import os

HERE = os.path.dirname(os.path.abspath(__file__))
EXPECTED = {}


class Step:
    def __init__(self, schema="IFC4"):
        self.schema = schema
        self.lines = []
        self.n = 0
        self.guids = 0

    def e(self, text):
        self.n += 1
        self.lines.append(f"#{self.n}={text};")
        return f"#{self.n}"

    def guid(self):
        self.guids += 1
        # 22 characters of the IFC base64 alphabet.
        return "'" + ("0" * 22 + str(self.guids))[-22:] + "'"

    def text(self):
        return (
            "ISO-10303-21;\nHEADER;\nFILE_DESCRIPTION(('ViewDefinition [ReferenceView]'),'2;1');\n"
            "FILE_NAME('fixture','2026-01-01T00:00:00',(''),(''),'make.py','exav','');\n"
            f"FILE_SCHEMA(('{self.schema}'));\nENDSEC;\nDATA;\n" + "\n".join(self.lines) + "\nENDSEC;\nEND-ISO-10303-21;\n"
        )


def fnum(v):
    s = repr(float(v))
    return s.upper() if "e" in s else s


def pt(s, *c):
    return s.e("IFCCARTESIANPOINT((" + ",".join(fnum(v) for v in c) + "))")


def dr(s, *c):
    return s.e("IFCDIRECTION((" + ",".join(fnum(v) for v in c) + "))")


class Model:
    """A project, site, building and storey, and helpers for elements."""

    def __init__(self, schema="IFC4", units=None, site_at=(0, 0, 0)):
        """`units(step)` makes and returns the length and angle units (None
        for metres and radians)."""
        length = angle = None
        s = self.s = Step(schema)
        self.elements = []
        # Optional in IFC4; IFC2X3 requires one, which no reader here needs.
        self.owner = "$"
        if units:
            length, angle = units(s)
        self.origin = pt(s, 0.0, 0.0, 0.0)
        self.z = dr(s, 0.0, 0.0, 1.0)
        self.x = dr(s, 1.0, 0.0, 0.0)
        self.world = s.e(f"IFCAXIS2PLACEMENT3D({self.origin},{self.z},{self.x})")
        self.ctx = s.e(f"IFCGEOMETRICREPRESENTATIONCONTEXT($,'Model',3,1.E-05,{self.world},$)")
        units = [length or s.e("IFCSIUNIT(*,.LENGTHUNIT.,$,.METRE.)"), angle or s.e("IFCSIUNIT(*,.PLANEANGLEUNIT.,$,.RADIAN.)")]
        ua = s.e(f"IFCUNITASSIGNMENT(({','.join(units)}))")
        self.project = s.e(f"IFCPROJECT({s.guid()},{self.owner},'Fixtures',$,$,$,$,({self.ctx}),{ua})")
        site_pl = self.place(None, *site_at)
        self.site = s.e(f"IFCSITE({s.guid()},{self.owner},'Site',$,$,{site_pl},$,$,.ELEMENT.,$,$,$,$,$)")
        b_pl = self.place(site_pl, 0, 0, 0)
        self.building = s.e(f"IFCBUILDING({s.guid()},{self.owner},'Building',$,$,{b_pl},$,$,.ELEMENT.,$,$,$)")
        self.storey_pl = self.place(b_pl, 0, 0, 0)
        self.storey = s.e(f"IFCBUILDINGSTOREY({s.guid()},{self.owner},'Level 0',$,$,{self.storey_pl},$,$,.ELEMENT.,0.)")
        s.e(f"IFCRELAGGREGATES({s.guid()},{self.owner},$,$,{self.project},({self.site}))")
        s.e(f"IFCRELAGGREGATES({s.guid()},{self.owner},$,$,{self.site},({self.building}))")
        s.e(f"IFCRELAGGREGATES({s.guid()},{self.owner},$,$,{self.building},({self.storey}))")

    def axis(self, x=0.0, y=0.0, z=0.0, zdir=None, xdir=None):
        s = self.s
        a = dr(s, *zdir) if zdir else "$"
        r = dr(s, *xdir) if xdir else "$"
        return s.e(f"IFCAXIS2PLACEMENT3D({pt(s, x, y, z)},{a},{r})")

    def place(self, rel, x=0.0, y=0.0, z=0.0, zdir=None, xdir=None):
        return self.s.e(f"IFCLOCALPLACEMENT({rel or '$'},{self.axis(x, y, z, zdir, xdir)})")

    def shape(self, items, kind="SweptSolid", ident="Body"):
        s = self.s
        rep = s.e(f"IFCSHAPEREPRESENTATION({self.ctx},'{ident}','{kind}',({','.join(items)}))")
        return s.e(f"IFCPRODUCTDEFINITIONSHAPE($,$,({rep}))")

    def element(self, cls, name, items, at=(0, 0, 0), kind="SweptSolid", rel=None, extra=None, contained=True, placement=None, **pl):
        s = self.s
        place = placement or self.place(rel or self.storey_pl, *at, **pl)
        shape = self.shape(items, kind)
        # Tag, and in IFC4 PredefinedType.
        tail = extra if extra is not None else (",$" if s.schema == "IFC2X3" else ",$,$")
        e = s.e(f"{cls}({s.guid()},{self.owner},'{name}',$,$,{place},{shape}{tail})")
        if contained:
            self.elements.append(e)
        return e, place

    def rect(self, x, y, cx=0.0, cy=0.0):
        s = self.s
        pos = s.e(f"IFCAXIS2PLACEMENT2D({pt(s, cx, cy)},$)")
        return s.e(f"IFCRECTANGLEPROFILEDEF(.AREA.,$,{pos},{fnum(x)},{fnum(y)})")

    def extrude(self, profile, depth, direction=(0.0, 0.0, 1.0), position="$"):
        return self.s.e(f"IFCEXTRUDEDAREASOLID({profile},{position},{dr(self.s, *direction)},{fnum(depth)})")

    def write(self, name, expect):
        s = self.s
        if self.elements:
            s.e(f"IFCRELCONTAINEDINSPATIALSTRUCTURE({s.guid()},{self.owner},$,$,({','.join(self.elements)}),{self.storey})")
        with open(os.path.join(HERE, name), "w") as f:
            f.write(s.text())
        EXPECTED[name] = expect


def box(x0, y0, z0, x1, y1, z1, tol=1e-6, **extra):
    return dict(volume=(x1 - x0) * (y1 - y0) * (z1 - z0), min=[x0, y0, z0], max=[x1, y1, z1], tol=tol, **extra)


# Discretisation: circles are 32 chords; the volume tolerance for curved
# sections allows for that (a 32-gon has 0.64% less area than its circle).
CURVED = 0.012


def profiles():
    m = Model()
    s = m.s
    exp = {}
    d = 2.0  # every profile extruded 2 m along z
    x = 0.0

    def add(name, profile, area, w, h, tol=1e-6):
        nonlocal x
        m.element("IFCMEMBER", name, [m.extrude(profile, d)], at=(x, 0, 0))
        exp[name] = dict(volume=area * d, min=[x - w / 2, -h / 2, 0], max=[x + w / 2, h / 2, d], tol=tol)
        x += 2.0

    def pos():
        return s.e(f"IFCAXIS2PLACEMENT2D({pt(s, 0.0, 0.0)},$)")

    add("rectangle", m.rect(0.4, 0.3), 0.12, 0.4, 0.3)
    add("circle", s.e(f"IFCCIRCLEPROFILEDEF(.AREA.,$,{pos()},0.25)"), math.pi * 0.0625, 0.5, 0.5, CURVED)
    add("circle hollow", s.e(f"IFCCIRCLEHOLLOWPROFILEDEF(.AREA.,$,{pos()},0.25,0.05)"), math.pi * (0.0625 - 0.04), 0.5, 0.5, CURVED)
    add("rectangle hollow", s.e(f"IFCRECTANGLEHOLLOWPROFILEDEF(.AREA.,$,{pos()},0.4,0.3,0.02,$,$)"), 0.12 - 0.36 * 0.26, 0.4, 0.3)
    add("ellipse", s.e(f"IFCELLIPSEPROFILEDEF(.AREA.,$,{pos()},0.3,0.2)"), math.pi * 0.06, 0.6, 0.4, CURVED)
    # I: 0.2 wide, 0.3 deep, web 0.01, flanges 0.02, no fillet.
    add("i shape", s.e(f"IFCISHAPEPROFILEDEF(.AREA.,$,{pos()},0.2,0.3,0.01,0.02,$,$,$)"), 2 * 0.2 * 0.02 + 0.26 * 0.01, 0.2, 0.3)
    # The same with a 0.015 root fillet: four times (1 - pi/4) r^2 more.
    add(
        "i shape filleted",
        s.e(f"IFCISHAPEPROFILEDEF(.AREA.,$,{pos()},0.2,0.3,0.01,0.02,0.015,$,$)"),
        2 * 0.2 * 0.02 + 0.26 * 0.01 + 4 * (1 - math.pi / 4) * 0.015**2,
        0.2,
        0.3,
        0.002,
    )
    add("l shape", s.e(f"IFCLSHAPEPROFILEDEF(.AREA.,$,{pos()},0.2,0.15,0.02,$,$,$)"), 0.2 * 0.02 + 0.13 * 0.02, 0.15, 0.2)
    add("t shape", s.e(f"IFCTSHAPEPROFILEDEF(.AREA.,$,{pos()},0.25,0.2,0.01,0.02,$,$,$,$,$)"), 0.2 * 0.02 + 0.23 * 0.01, 0.2, 0.25)
    add("u shape", s.e(f"IFCUSHAPEPROFILEDEF(.AREA.,$,{pos()},0.3,0.1,0.01,0.02,$,$,$)"), 2 * 0.1 * 0.02 + 0.26 * 0.01, 0.1, 0.3)
    add("c shape", s.e(f"IFCCSHAPEPROFILEDEF(.AREA.,$,{pos()},0.2,0.1,0.01,0.03,$)"), 0.2 * 0.01 + 2 * 0.09 * 0.01 + 2 * 0.02 * 0.01, 0.1, 0.2)
    add("z shape", s.e(f"IFCZSHAPEPROFILEDEF(.AREA.,$,{pos()},0.3,0.1,0.01,0.02,$,$)"), 2 * 0.1 * 0.02 + 0.26 * 0.01, 0.19, 0.3)
    add("trapezium", s.e(f"IFCTRAPEZIUMPROFILEDEF(.AREA.,$,{pos()},0.4,0.2,0.3,0.1)"), (0.4 + 0.2) / 2 * 0.3, 0.4, 0.3)
    add("rounded rectangle", s.e(f"IFCROUNDEDRECTANGLEPROFILEDEF(.AREA.,$,{pos()},0.4,0.3,0.05)"), 0.12 - (4 - math.pi) * 0.0025, 0.4, 0.3, 0.003)
    # Arbitrary: an L as a polyline, closed.
    poly = s.e("IFCPOLYLINE((" + ",".join(pt(s, *p) for p in [(-0.2, -0.2), (0.2, -0.2), (0.2, 0.0), (0.0, 0.0), (0.0, 0.2), (-0.2, 0.2), (-0.2, -0.2)]) + "))")
    add("arbitrary", s.e(f"IFCARBITRARYCLOSEDPROFILEDEF(.AREA.,$,{poly})"), 0.16 - 0.04, 0.4, 0.4)
    # With a void: a 0.4 square minus a 0.2 square.
    outer = s.e("IFCPOLYLINE((" + ",".join(pt(s, *p) for p in [(-0.2, -0.2), (0.2, -0.2), (0.2, 0.2), (-0.2, 0.2), (-0.2, -0.2)]) + "))")
    inner = s.e("IFCPOLYLINE((" + ",".join(pt(s, *p) for p in [(-0.1, -0.1), (0.1, -0.1), (0.1, 0.1), (-0.1, 0.1), (-0.1, -0.1)]) + "))")
    add("with voids", s.e(f"IFCARBITRARYPROFILEDEFWITHVOIDS(.AREA.,$,{outer},({inner}))"), 0.16 - 0.04, 0.4, 0.4)
    # A stadium: two lines and two half circles (trimmed by parameter in
    # one, by points in the other), as a composite curve.
    c1 = s.e(f"IFCCIRCLE({s.e(f'IFCAXIS2PLACEMENT2D({pt(s, 0.1, 0.0)},$)')},0.1)")
    c2 = s.e(f"IFCCIRCLE({s.e(f'IFCAXIS2PLACEMENT2D({pt(s, -0.1, 0.0)},$)')},0.1)")
    segs = [
        s.e(f"IFCCOMPOSITECURVESEGMENT(.CONTINUOUS.,.T.,{s.e('IFCPOLYLINE((' + pt(s, -0.1, -0.1) + ',' + pt(s, 0.1, -0.1) + '))')})"),
        s.e(f"IFCCOMPOSITECURVESEGMENT(.CONTINUOUS.,.T.,{s.e(f'IFCTRIMMEDCURVE({c1},(IFCPARAMETERVALUE({fnum(-math.pi / 2)})),(IFCPARAMETERVALUE({fnum(math.pi / 2)})),.T.,.PARAMETER.)')})"),
        s.e(f"IFCCOMPOSITECURVESEGMENT(.CONTINUOUS.,.T.,{s.e('IFCPOLYLINE((' + pt(s, 0.1, 0.1) + ',' + pt(s, -0.1, 0.1) + '))')})"),
        s.e(f"IFCCOMPOSITECURVESEGMENT(.CONTINUOUS.,.T.,{s.e(f'IFCTRIMMEDCURVE({c2},({pt(s, -0.1, 0.1)}),({pt(s, -0.1, -0.1)}),.T.,.CARTESIAN.)')})"),
    ]
    cc = s.e(f"IFCCOMPOSITECURVE(({','.join(segs)}),.F.)")
    add("composite", s.e(f"IFCARBITRARYCLOSEDPROFILEDEF(.AREA.,$,{cc})"), 0.04 + math.pi * 0.01, 0.4, 0.2, CURVED)
    # The same stadium as an indexed poly curve with arcs.
    pl = s.e("IFCCARTESIANPOINTLIST2D(((-0.1,-0.1),(0.1,-0.1),(0.2,0.0),(0.1,0.1),(-0.1,0.1),(-0.2,0.0)))")
    ipc = s.e(f"IFCINDEXEDPOLYCURVE({pl},(IFCLINEINDEX((1,2)),IFCARCINDEX((2,3,4)),IFCLINEINDEX((4,5)),IFCARCINDEX((5,6,1))),$)")
    add("indexed poly curve", s.e(f"IFCARBITRARYCLOSEDPROFILEDEF(.AREA.,$,{ipc})"), 0.04 + math.pi * 0.01, 0.4, 0.2, CURVED)
    # Derived: the rectangle scaled by 2 and moved by (0.1, 0).
    op = s.e(f"IFCCARTESIANTRANSFORMATIONOPERATOR2D($,$,{pt(s, 0.1, 0.0)},2.)")
    prof = m.rect(0.2, 0.1)
    m.element("IFCMEMBER", "derived", [m.extrude(s.e(f"IFCDERIVEDPROFILEDEF(.AREA.,$,{prof},{op},$)"), d)], at=(x, 0, 0))
    exp["derived"] = dict(volume=0.4 * 0.2 * d, min=[x - 0.1, -0.1, 0], max=[x + 0.3, 0.1, d], tol=1e-6)
    x += 2.0
    m.write("profiles.ifc", {"elements": exp})


def solids():
    m = Model()
    s = m.s
    exp = {}
    # Slanted extrusion: Cavalieri, same volume as straight.
    m.element("IFCCOLUMN", "slanted", [m.extrude(m.rect(1.0, 1.0, 0.5, 0.5), 2.0, direction=(0.6, 0.0, 0.8))])
    exp["slanted"] = dict(volume=1.0 * 1.6, min=[0, 0, 0], max=[1 + 1.2, 1, 1.6], tol=1e-6)
    # Positioned extrusion: the solid rotated so it extrudes along x.
    position = m.axis(10.0, 0.0, 0.0, zdir=(1.0, 0.0, 0.0), xdir=(0.0, 1.0, 0.0))
    m.element("IFCBEAM", "along x", [m.extrude(m.rect(0.2, 0.4), 3.0, position=position)])
    exp["along x"] = dict(volume=0.24, min=[10, -0.1, -0.2], max=[13, 0.1, 0.2], tol=1e-6)
    # Tapered: 1 x 1 to 0.5 x 0.5 over 2 (a frustum): h/3 (A1 + A2 + sqrt(A1 A2)).
    e = s.e(f"IFCEXTRUDEDAREASOLIDTAPERED({m.rect(1.0, 1.0)},$,{dr(s, 0., 0., 1.)},2.,{m.rect(0.5, 0.5)})")
    m.element("IFCCOLUMN", "tapered", [e], at=(20, 0, 0))
    exp["tapered"] = dict(volume=2 / 3 * (1 + 0.25 + 0.5), min=[19.5, -0.5, 0], max=[20.5, 0.5, 2], tol=1e-6)
    # Revolved: a 0.2 x 1 rectangle at 1..1.2 from the z axis, full turn:
    # a tube pi (R^2 - r^2) h.
    prof = m.rect(0.2, 1.0, 1.1, 0.5)
    ax = s.e(f"IFCAXIS1PLACEMENT({pt(s, 0.0, 0.0, 0.0)},{dr(s, 0., 1., 0.)})")
    # The profile in the solid's xy, revolved about its y axis; the solid
    # placed with that y along z.
    rpos = m.axis(0, 0, 0, zdir=(0.0, -1.0, 0.0), xdir=(1.0, 0.0, 0.0))
    m.element("IFCCOLUMN", "revolved", [s.e(f"IFCREVOLVEDAREASOLID({prof},{rpos},{ax},{fnum(2 * math.pi)})")], at=(30, 0, 0))
    exp["revolved"] = dict(volume=math.pi * (1.44 - 1.0) * 1.0, min=[28.8, -1.2, 0], max=[31.2, 1.2, 1], tol=CURVED)
    # A quarter of it: a quarter of the volume (Pappus).
    m.element("IFCCOLUMN", "revolved quarter", [s.e(f"IFCREVOLVEDAREASOLID({prof},{rpos},{ax},{fnum(math.pi / 2)})")], at=(40, 0, 0))
    exp["revolved quarter"] = dict(volume=math.pi * (1.44 - 1.0) / 4, tol=CURVED)
    # Swept disk along an L of 2 + 1, radius 0.05, inner 0.03: a mitred
    # tube's volume is its section times its centre line.
    path = s.e("IFCPOLYLINE((" + pt(s, 0., 0., 0.) + "," + pt(s, 2., 0., 0.) + "," + pt(s, 2., 1., 0.) + "))")
    m.element("IFCPIPESEGMENT", "swept disk", [s.e(f"IFCSWEPTDISKSOLID({path},0.05,0.03,$,$)")], at=(50, 0, 0))
    # The end caps are flat, square to the path; the mitre reaches out to
    # the corner's outside.
    exp["swept disk"] = dict(volume=math.pi * (0.0025 - 0.0009) * 3.0, min=[50, -0.05, -0.05], max=[52.05, 1, 0.05], tol=0.03)
    # A rectangle swept along a straight directrix on the xy plane: a box.
    line = s.e("IFCPOLYLINE((" + pt(s, 0., 0., 0.) + "," + pt(s, 0., 3., 0.) + "))")
    plane = s.e(f"IFCPLANE({m.axis()})")
    sw = s.e(f"IFCSURFACECURVESWEPTAREASOLID({m.rect(0.2, 0.4)},$,{line},$,$,{plane})")
    m.element("IFCBEAM", "surface curve swept", [sw], at=(60, 0, 0))
    # x of the profile along the plane normal (z), its y across: x in -0.2..0.2 is z.
    exp["surface curve swept"] = dict(volume=0.24, min=[59.8, 0, -0.1], max=[60.2, 3, 0.1], tol=1e-6)
    fr = s.e(f"IFCFIXEDREFERENCESWEPTAREASOLID({m.rect(0.2, 0.4)},$,{line},$,$,{dr(s, 1., 0., 0.)})")
    m.element("IFCBEAM", "fixed reference swept", [fr], at=(70, 0, 0))
    exp["fixed reference swept"] = dict(volume=0.24, min=[69.9, 0, -0.2], max=[70.1, 3, 0.2], tol=1e-6)
    # CSG primitives.
    for i, (cls, text, vol, tol) in enumerate(
        [
            ("block", f"IFCBLOCK({m.axis()},1.,2.,3.)", 6.0, 1e-6),
            ("cylinder", f"IFCRIGHTCIRCULARCYLINDER({m.axis()},2.,0.5)", math.pi * 0.25 * 2, CURVED),
            ("cone", f"IFCRIGHTCIRCULARCONE({m.axis()},3.,1.)", math.pi * 3 / 3, CURVED),
            ("sphere", f"IFCSPHERE({m.axis()},1.)", 4 / 3 * math.pi, 0.03),
            ("pyramid", f"IFCRECTANGULARPYRAMID({m.axis()},2.,3.,4.)", 8.0, 1e-6),
        ]
    ):
        m.element("IFCBUILDINGELEMENTPROXY", cls, [s.e(f"IFCCSGSOLID({s.e(text)})")], at=(80 + 5 * i, 0, 0), kind="CSG")
        exp[cls] = dict(volume=vol, tol=tol)
    exp["block"].update(min=[80, 0, 0], max=[81, 2, 3])
    # CSG boolean: union of two overlapping blocks (2 + 2 - 1 overlap).
    b1 = s.e(f"IFCBLOCK({m.axis()},2.,1.,1.)")
    b2 = s.e(f"IFCBLOCK({m.axis(1.0, 0.0, 0.0)},2.,1.,1.)")
    m.element("IFCBUILDINGELEMENTPROXY", "csg union", [s.e(f"IFCCSGSOLID({s.e(f'IFCBOOLEANRESULT(.UNION.,{b1},{b2})')})")], at=(110, 0, 0), kind="CSG")
    exp["csg union"] = box(110, 0, 0, 113, 1, 1)
    m.element("IFCBUILDINGELEMENTPROXY", "csg intersection", [s.e(f"IFCCSGSOLID({s.e(f'IFCBOOLEANRESULT(.INTERSECTION.,{b1},{b2})')})")], at=(120, 0, 0), kind="CSG")
    exp["csg intersection"] = box(121, 0, 0, 122, 1, 1)
    m.write("solids.ifc", {"elements": exp})


def tessellated():
    m = Model()
    s = m.s
    exp = {}
    cube = [(0, 0, 0), (1, 0, 0), (1, 1, 0), (0, 1, 0), (0, 0, 2), (1, 0, 2), (1, 1, 2), (0, 1, 2)]
    pts3 = "(" + ",".join("(" + ",".join(fnum(v) for v in p) + ")" for p in cube) + ")"
    # The face set of the specification's own example (Figure D).
    tris = "((1,6,5),(1,2,6),(6,2,7),(7,2,3),(7,8,6),(6,8,5),(5,8,1),(1,8,4),(4,2,1),(2,4,3),(4,8,7),(7,3,4))"
    tfs = s.e(f"IFCTRIANGULATEDFACESET({s.e(f'IFCCARTESIANPOINTLIST3D({pts3})')},$,.T.,{tris},$)")
    m.element("IFCSLAB", "triangulated", [tfs], kind="Tessellation")
    exp["triangulated"] = box(0, 0, 0, 1, 1, 2)
    # PnIndex: the same with the points listed in reverse, through an index.
    rev = "(" + ",".join("(" + ",".join(fnum(v) for v in p) + ")" for p in reversed(cube)) + ")"
    tfs2 = s.e(f"IFCTRIANGULATEDFACESET({s.e(f'IFCCARTESIANPOINTLIST3D({rev})')},$,.T.,{tris},(8,7,6,5,4,3,2,1))")
    m.element("IFCSLAB", "pn index", [tfs2], at=(5, 0, 0), kind="Tessellation")
    exp["pn index"] = box(5, 0, 0, 6, 1, 2)
    # Polygonal face set: the specification's box (Figure B).
    faces = [(1, 2, 6, 5), (6, 2, 3, 7), (7, 3, 4, 8), (8, 4, 1, 5), (1, 4, 3, 2), (6, 7, 8, 5)]
    fs = ",".join(s.e(f"IFCINDEXEDPOLYGONALFACE(({','.join(map(str, f))}))") for f in faces)
    pfs = s.e(f"IFCPOLYGONALFACESET({s.e(f'IFCCARTESIANPOINTLIST3D({pts3})')},.T.,({fs}),$)")
    m.element("IFCSLAB", "polygonal", [pfs], at=(10, 0, 0), kind="Tessellation")
    exp["polygonal"] = box(10, 0, 0, 11, 1, 2)
    # A 4 x 4 x 1 frame with a 2 x 2 hole through: faces with voids.
    o = [(0, 0, 0), (4, 0, 0), (4, 4, 0), (0, 4, 0)]
    i = [(1, 1, 0), (3, 1, 0), (3, 3, 0), (1, 3, 0)]
    allp = o + i + [(a, b, 1) for a, b, _ in o] + [(a, b, 1) for a, b, _ in i]
    plist = "(" + ",".join("(" + ",".join(fnum(v) for v in p) + ")" for p in allp) + ")"
    F = []
    F.append(s.e("IFCINDEXEDPOLYGONALFACEWITHVOIDS((1,4,3,2),((5,6,7,8)))"))  # bottom, down
    F.append(s.e("IFCINDEXEDPOLYGONALFACEWITHVOIDS((9,10,11,12),((13,16,15,14)))"))  # top, up
    for a, b in [(1, 2), (2, 3), (3, 4), (4, 1)]:
        F.append(s.e(f"IFCINDEXEDPOLYGONALFACE(({a},{b},{b + 8},{a + 8}))"))
    for a, b in [(5, 6), (6, 7), (7, 8), (8, 5)]:
        F.append(s.e(f"IFCINDEXEDPOLYGONALFACE(({b},{a},{a + 8},{b + 8}))"))
    frame = s.e(f"IFCPOLYGONALFACESET({s.e(f'IFCCARTESIANPOINTLIST3D({plist})')},.T.,({','.join(F)}),$)")
    m.element("IFCSLAB", "faces with voids", [frame], at=(20, 0, 0), kind="Tessellation")
    exp["faces with voids"] = dict(volume=16 - 4, min=[20, 0, 0], max=[24, 4, 1], tol=1e-6)

    # Faceted B-rep of a box, with a void of 1 x 1 x 1 inside a 3 x 3 x 3.
    def shell(lo, hi):
        c = [(lo[0] if k & 1 == 0 else hi[0], lo[1] if k & 2 == 0 else hi[1], lo[2] if k & 4 == 0 else hi[2]) for k in range(8)]
        ids = [pt(s, *p) for p in c]
        quads = [(0, 2, 3, 1), (4, 5, 7, 6), (0, 1, 5, 4), (2, 6, 7, 3), (0, 4, 6, 2), (1, 3, 7, 5)]
        faces = []
        for q in quads:
            loop = s.e("IFCPOLYLOOP((" + ",".join(ids[k] for k in q) + "))")
            faces.append(s.e(f"IFCFACE(({s.e(f'IFCFACEOUTERBOUND({loop},.T.)')}))"))
        return s.e(f"IFCCLOSEDSHELL(({','.join(faces)}))")

    m.element("IFCWALL", "brep", [s.e(f"IFCFACETEDBREP({shell((0, 0, 0), (2, 1, 3))})")], at=(30, 0, 0), kind="Brep")
    exp["brep"] = box(30, 0, 0, 32, 1, 3)
    m.element("IFCWALL", "brep with voids", [s.e(f"IFCFACETEDBREPWITHVOIDS({shell((0, 0, 0), (3, 3, 3))},({shell((1, 1, 1), (2, 2, 2))}))")], at=(40, 0, 0), kind="Brep")
    exp["brep with voids"] = dict(volume=27 - 1, min=[40, 0, 0], max=[43, 3, 3], tol=1e-6)
    # Surface models: an open box (five faces), area 1 + 4 * 2.
    c = [pt(s, *p) for p in cube]

    def face(*k):
        loop = s.e("IFCPOLYLOOP((" + ",".join(c[i] for i in k) + "))")
        return s.e(f"IFCFACE(({s.e(f'IFCFACEOUTERBOUND({loop},.T.)')}))")

    open_faces = [face(0, 3, 2, 1), face(0, 1, 5, 4), face(1, 2, 6, 5), face(2, 3, 7, 6), face(3, 0, 4, 7)]
    faces = ",".join(open_faces)
    sb = s.e(f"IFCSHELLBASEDSURFACEMODEL(({s.e(f'IFCOPENSHELL(({faces}))')}))")
    m.element("IFCCOVERING", "shell surface", [sb], at=(50, 0, 0), kind="SurfaceModel")
    exp["shell surface"] = dict(area=9.0, min=[50, 0, 0], max=[51, 1, 2], tol=1e-6)
    fb = s.e(f"IFCFACEBASEDSURFACEMODEL(({s.e(f'IFCCONNECTEDFACESET(({faces}))')}))")
    m.element("IFCCOVERING", "face surface", [fb], at=(60, 0, 0), kind="SurfaceModel")
    exp["face surface"] = dict(area=9.0, min=[60, 0, 0], max=[61, 1, 2], tol=1e-6)
    m.write("tessellated.ifc", {"elements": exp})


def booleans():
    m = Model()
    s = m.s
    exp = {}
    # A 4 x 0.2 x 3 wall cut by the plane z = 2.5 (normal up, material
    # above: AgreementFlag FALSE, the half-space the normal points into).
    wall = m.extrude(m.rect(4.0, 0.2, 2.0, 0.1), 3.0)
    hs = s.e(f"IFCHALFSPACESOLID({s.e(f'IFCPLANE({m.axis(0.0, 0.0, 2.5)})')},.F.)")
    m.element("IFCWALL", "clipped", [s.e(f"IFCBOOLEANCLIPPINGRESULT(.DIFFERENCE.,{wall},{hs})")], kind="Clipping")
    exp["clipped"] = box(0, 0, 0, 4, 0.2, 2.5)
    # TRUE: the material is below the plane, so the top 0.5 is what stays.
    wall2 = m.extrude(m.rect(4.0, 0.2, 2.0, 0.1), 3.0)
    hs2 = s.e(f"IFCHALFSPACESOLID({s.e(f'IFCPLANE({m.axis(0.0, 0.0, 2.5)})')},.T.)")
    m.element("IFCWALL", "clipped agreeing", [s.e(f"IFCBOOLEANCLIPPINGRESULT(.DIFFERENCE.,{wall2},{hs2})")], at=(10, 0, 0), kind="Clipping")
    exp["clipped agreeing"] = box(10, 0, 2.5, 14, 0.2, 3)
    # A sloped cut, the roof line from z = 3 at x = 0 to z = 2 at x = 4,
    # bounded to x in 0..2 by a polygonal boundary: only the first half
    # loses its wedge.
    wall3 = m.extrude(m.rect(4.0, 0.2, 2.0, 0.1), 3.0)
    n = (0.25, 0.0, 1.0)
    ln = math.hypot(*n)
    plane = s.e(f"IFCPLANE({m.axis(0.0, 0.0, 3.0, zdir=(n[0] / ln, 0.0, n[2] / ln), xdir=(n[2] / ln, 0.0, -n[0] / ln))})")
    bound = s.e("IFCPOLYLINE((" + ",".join(pt(s, *p) for p in [(0.0, -1.0), (2.0, -1.0), (2.0, 1.0), (0.0, 1.0), (0.0, -1.0)]) + "))")
    pbh = s.e(f"IFCPOLYGONALBOUNDEDHALFSPACE({plane},.F.,{m.axis(0.0, 0.0, -10.0)},{bound})")
    m.element("IFCWALL", "polygonal bounded", [s.e(f"IFCBOOLEANCLIPPINGRESULT(.DIFFERENCE.,{wall3},{pbh})")], at=(20, 0, 0), kind="Clipping")
    # Over x in 0..2 the top falls from 3 to 2.5: a wedge of 0.5 * 2 / 2 * 0.2.
    exp["polygonal bounded"] = dict(volume=4 * 0.2 * 3 - 0.5 * 2 / 2 * 0.2, min=[20, 0, 0], max=[24, 0.2, 3], tol=1e-6)
    # Openings: a 4 x 0.2 x 3 wall with a 1 x 1 window through (a 1 x 1 x 1
    # opening box placed relative to the wall) and a door half outside.
    w, wpl = m.element("IFCWALL", "wall with openings", [m.extrude(m.rect(4.0, 0.2, 2.0, 0.1), 3.0)], at=(30, 0, 0))
    o1, _ = m.element("IFCOPENINGELEMENT", "window opening", [m.extrude(m.rect(1.0, 1.0, 0.5, 0.0), 1.0)], at=(1.0, 0.1, 1.0), rel=wpl, contained=False)
    o2, _ = m.element("IFCOPENINGELEMENT", "door opening", [m.extrude(m.rect(1.0, 1.0, 0.5, 0.0), 3.0)], at=(3.5, 0.1, -1.0), rel=wpl, contained=False)
    s.e(f"IFCRELVOIDSELEMENT({s.guid()},$,$,$,{w},{o1})")
    s.e(f"IFCRELVOIDSELEMENT({s.guid()},$,$,$,{w},{o2})")
    # Window: 1 x 0.2 x 1; door: x 3.5..4 (in the wall), z 0..2.
    exp["wall with openings"] = dict(volume=4 * 0.2 * 3 - 0.2 - 0.5 * 0.2 * 2, min=[30, 0, 0], max=[34, 0.2, 3], tol=1e-6)
    m.write("booleans.ifc", {"elements": exp, "absent": ["window opening", "door opening"]})


def mapped_and_units():
    # Millimetres, angles in degrees, a mapped item with a scaled operator,
    # a placement chain with rotations, colours, and a site far away.
    def units(s):
        mm = s.e("IFCSIUNIT(*,.LENGTHUNIT.,.MILLI.,.METRE.)")
        rad = s.e("IFCSIUNIT(*,.PLANEANGLEUNIT.,$,.RADIAN.)")
        measure = s.e(f"IFCMEASUREWITHUNIT(IFCPLANEANGLEMEASURE(0.017453292519943295),{rad})")
        deg = s.e(f"IFCCONVERSIONBASEDUNIT({s.e('IFCDIMENSIONALEXPONENTS(0,0,0,0,0,0,0)')},.PLANEANGLEUNIT.,'DEGREE',{measure})")
        return mm, deg

    m = Model(units=units, site_at=(2500000000.0, 1200000000.0, 300000.0))
    s = m.s
    exp = {}
    big = (2_500_000, 1_200_000, 300)
    # A 1000 x 500 x 200 mm block as a representation map, placed twice:
    # once as is, once scaled by 2 and turned 90 degrees about z.
    block = m.extrude(m.rect(1000.0, 500.0, 500.0, 250.0), 200.0)
    rep = s.e(f"IFCSHAPEREPRESENTATION({m.ctx},'Body','SweptSolid',({block}))")
    rmap = s.e(f"IFCREPRESENTATIONMAP({m.axis()},{rep})")
    plain = s.e(f"IFCMAPPEDITEM({rmap},{s.e(f'IFCCARTESIANTRANSFORMATIONOPERATOR3D($,$,{pt(s, 0., 0., 0.)},$,$)')})")
    turned = s.e(
        f"IFCMAPPEDITEM({rmap},{s.e(f'IFCCARTESIANTRANSFORMATIONOPERATOR3D({dr(s, 0., 1., 0.)},{dr(s, -1., 0., 0.)},{pt(s, 0., 0., 0.)},2.,{dr(s, 0., 0., 1.)})')})"
    )
    m.element("IFCFURNISHINGELEMENT", "mapped", [plain], kind="MappedRepresentation")
    exp["mapped"] = box(big[0], big[1], big[2], big[0] + 1, big[1] + 0.5, big[2] + 0.2, tol=1e-6)
    m.element("IFCFURNISHINGELEMENT", "mapped scaled", [turned], at=(5000.0, 0.0, 0.0), kind="MappedRepresentation")
    exp["mapped scaled"] = box(big[0] + 5 - 1, big[1], big[2], big[0] + 5, big[1] + 2, big[2] + 0.4, tol=1e-6)
    # Nonuniform: x by 3, y by 1, z by 0.5.
    nonu = s.e(
        f"IFCMAPPEDITEM({rmap},{s.e(f'IFCCARTESIANTRANSFORMATIONOPERATOR3DNONUNIFORM($,$,{pt(s, 0., 0., 0.)},3.,$,1.,0.5)')})"
    )
    m.element("IFCFURNISHINGELEMENT", "mapped nonuniform", [nonu], at=(10000.0, 0.0, 0.0), kind="MappedRepresentation")
    exp["mapped nonuniform"] = box(big[0] + 10, big[1], big[2], big[0] + 13, big[1] + 0.5, big[2] + 0.1, tol=1e-6)
    # Revolved by 90 (degrees): a quarter tube. Profile 200 x 1000 at
    # 1000..1200 from the axis.
    prof = m.rect(200.0, 1000.0, 1100.0, 500.0)
    ax = s.e(f"IFCAXIS1PLACEMENT({pt(s, 0.0, 0.0, 0.0)},{dr(s, 0., 1., 0.)})")
    rpos = m.axis(0, 0, 0, zdir=(0.0, -1.0, 0.0), xdir=(1.0, 0.0, 0.0))
    m.element("IFCCOLUMN", "revolved degrees", [s.e(f"IFCREVOLVEDAREASOLID({prof},{rpos},{ax},90.)")], at=(20000.0, 0.0, 0.0))
    exp["revolved degrees"] = dict(volume=math.pi * (1.44 - 1.0) / 4, tol=CURVED)
    # Placement chain: a storey-relative placement turned 90 degrees about z
    # (local x along world y), then a child placement 1000 along local x.
    turned_pl = m.place(m.storey_pl, 30000.0, 0.0, 0.0, zdir=(0., 0., 1.), xdir=(0., 1., 0.))
    m.element("IFCCOLUMN", "chained", [m.extrude(m.rect(100.0, 100.0), 1000.0)], at=(1000.0, 0.0, 0.0), rel=turned_pl)
    exp["chained"] = box(big[0] + 30 - 0.05, big[1] + 1 - 0.05, big[2], big[0] + 30.05, big[1] + 1.05, big[2] + 1, tol=1e-6)
    # Colours: an item style (red, half transparent), and a material's.
    styled = m.extrude(m.rect(100.0, 100.0), 100.0)
    rgb = s.e("IFCCOLOURRGB($,1.,0.,0.)")
    sty = s.e(f"IFCSURFACESTYLE('red',.BOTH.,({s.e(f'IFCSURFACESTYLERENDERING({rgb},0.5,$,$,$,$,$,$,.NOTDEFINED.)')}))")
    s.e(f"IFCSTYLEDITEM({styled},({sty}),$)")
    m.element("IFCSLAB", "styled", [styled], at=(40000.0, 0.0, 0.0))
    exp["styled"] = dict(color=[1.0, 0.0, 0.0, 0.5])
    plain_e, _ = m.element("IFCSLAB", "material colour", [m.extrude(m.rect(100.0, 100.0), 100.0)], at=(41000.0, 0.0, 0.0))
    mat = s.e("IFCMATERIAL('green',$,$)")
    shading = s.e(f"IFCSURFACESTYLESHADING({s.e('IFCCOLOURRGB($,0.,1.,0.)')},0.)")
    green = s.e(f"IFCSURFACESTYLE('green',.BOTH.,({shading}))")
    srep = s.e(f"IFCSTYLEDREPRESENTATION({m.ctx},'Style','Material',({s.e(f'IFCSTYLEDITEM($,({green}),$)')}))")
    s.e(f"IFCMATERIALDEFINITIONREPRESENTATION($,$,({srep}),{mat})")
    s.e(f"IFCRELASSOCIATESMATERIAL({s.guid()},$,$,$,({plain_e}),{mat})")
    exp["material colour"] = dict(color=[0.0, 1.0, 0.0, 1.0])
    m.element("IFCSLAB", "no colour", [m.extrude(m.rect(100.0, 100.0), 100.0)], at=(42000.0, 0.0, 0.0))
    exp["no colour"] = dict(color=None)
    m.write("mapped_units.ifc", {"elements": exp, "origin_near": list(big)})


def ifc2x3_and_feet():
    # IFC2X3 with feet (a conversion-based unit) and IFC2X3 style assignment.
    def units(s):
        metre = s.e("IFCSIUNIT(*,.LENGTHUNIT.,$,.METRE.)")
        measure = s.e(f"IFCMEASUREWITHUNIT(IFCLENGTHMEASURE(0.3048),{metre})")
        ft = s.e(f"IFCCONVERSIONBASEDUNIT({s.e('IFCDIMENSIONALEXPONENTS(1,0,0,0,0,0,0)')},.LENGTHUNIT.,'FOOT',{measure})")
        return ft, None

    m = Model(schema="IFC2X3", units=units)
    s = m.s
    exp = {}
    item = m.extrude(m.rect(10.0, 1.0, 5.0, 0.5), 8.0, position=m.axis())
    rgb = s.e("IFCCOLOURRGB($,0.,0.,1.)")
    sty = s.e(f"IFCSURFACESTYLE('blue',.BOTH.,({s.e(f'IFCSURFACESTYLERENDERING({rgb},0.,$,$,$,$,$,$,.NOTDEFINED.)')}))")
    s.e(f"IFCSTYLEDITEM({item},({s.e(f'IFCPRESENTATIONSTYLEASSIGNMENT(({sty}))')}),$)")
    w, _ = m.element("IFCWALLSTANDARDCASE", "feet wall", [item])
    f = 0.3048
    exp["feet wall"] = dict(volume=80 * f**3, min=[0, 0, 0], max=[10 * f, f, 8 * f], tol=1e-6, color=[0.0, 0.0, 1.0, 1.0])
    m.write("ifc2x3_feet.ifc", {"elements": exp, "storey": {"feet wall": "Level 0"}})


def damaged():
    # Reference loops and broken records: the good element is still drawn.
    m = Model()
    s = m.s
    m.element("IFCWALL", "good", [m.extrude(m.rect(1.0, 1.0, 0.5, 0.5), 1.0)])
    # A placement relative to itself.
    axis = m.axis()
    n = s.n + 1
    s.lines.append(f"#{n}=IFCLOCALPLACEMENT(#{n},{axis});")
    s.n = n
    shape = m.shape([m.extrude(m.rect(1.0, 1.0), 1.0)])
    s.e(f"IFCWALL({s.guid()},$,'placement loop',$,$,#{n},{shape},$,$)")
    # A mapped item whose map contains it.
    axis = m.axis()
    k = s.n + 1
    s.lines.append(f"#{k}=IFCMAPPEDITEM(#{k + 1},#{k + 3});")
    s.lines.append(f"#{k + 1}=IFCREPRESENTATIONMAP({axis},#{k + 2});")
    s.lines.append(f"#{k + 2}=IFCSHAPEREPRESENTATION({m.ctx},'Body','MappedRepresentation',(#{k}));")
    s.lines.append(f"#{k + 3}=IFCCARTESIANTRANSFORMATIONOPERATOR3D($,$,{m.origin},$,$);")
    s.n = k + 3
    m.element("IFCWALL", "mapped loop", [f"#{k}"], kind="MappedRepresentation")
    # A boolean whose operand is itself.
    j = s.n + 1
    s.lines.append(f"#{j}=IFCBOOLEANRESULT(.DIFFERENCE.,#{j},#{j});")
    s.n = j
    m.element("IFCWALL", "boolean loop", [f"#{j}"], kind="CSG")
    # A missing reference, and a broken record.
    m.element("IFCWALL", "missing", ["#999999"])
    s.lines.append("#999998=IFCWALL('x',$,'broken',(,$;")
    m.write("damaged.ifc", {"elements": {"good": box(0, 0, 0, 1, 1, 1)}, "absent": ["placement loop", "mapped loop", "boolean loop", "missing", "broken"], "damaged": True})


def circle(m, cx, cy, cz, r, axis, ref):
    """An IfcCircle at (cx, cy, cz), its z axis `axis` and x axis `ref`."""
    return m.s.e(f"IFCCIRCLE({m.axis(cx, cy, cz, zdir=axis, xdir=ref)},{fnum(r)})")


def trimmed(s, curve, a, b):
    """An arc of `curve` from parameter a to b (radians)."""
    return s.e(f"IFCTRIMMEDCURVE({curve},(IFCPARAMETERVALUE({fnum(a)})),(IFCPARAMETERVALUE({fnum(b)})),.T.,.PARAMETER.)")


def vertex(s, p):
    return s.e(f"IFCVERTEXPOINT({pt(s, *p)})")


def edge(s, a, b, geometry):
    return s.e(f"IFCEDGECURVE({a},{b},{geometry},.T.)")


def oriented(s, e, forward=True):
    return s.e(f"IFCORIENTEDEDGE(*,*,{e},{'.T.' if forward else '.F.'})")


def loop(s, *edges):
    """An edge loop of (edge, forward) pairs."""
    return s.e("IFCEDGELOOP((" + ",".join(oriented(s, e, f) for e, f in edges) + "))")


def face(s, loops, surface, outer_bound=True):
    """An advanced face; `outer_bound` False writes every bound as a plain
    IfcFaceBound, as some writers do for a tube."""
    bounds = [s.e(f"IFCFACEOUTERBOUND({l},.T.)" if i == 0 and outer_bound else f"IFCFACEBOUND({l},.T.)") for i, l in enumerate(loops)]
    return s.e(f"IFCADVANCEDFACE(({','.join(bounds)}),{surface},.T.)")


def curved_faces():
    """Faces of B-reps on spheres, tori, cylinders and B-spline surfaces,
    each with a closed form for its volume or area. tests/ifc_geometry.rs
    also checks that every point lies on the surface."""
    m = Model()
    s = m.s
    exp = {}
    R = 2.0
    sphere = s.e(f"IFCSPHERICALSURFACE({m.axis()},{fnum(R)})")
    equator = circle(m, 0, 0, 0, R, (0, 0, 1), (1, 0, 0))
    v0 = vertex(s, (R, 0, 0))
    e_eq = edge(s, v0, v0, equator)
    floor = s.e(f"IFCPLANE({m.axis()})")
    # A hemisphere: its cap has the equator for its only edge, so the pole
    # is inside the face. The loop runs counter-clockwise seen from +z: the
    # face is the northern cap.
    cap = face(s, [loop(s, (e_eq, True))], sphere)
    disk = face(s, [loop(s, (e_eq, False))], floor)
    shell = s.e(f"IFCCLOSEDSHELL(({cap},{disk}))")
    m.element("IFCBUILDINGELEMENTPROXY", "hemisphere", [s.e(f"IFCADVANCEDBREP({shell})")], at=(0, 0, 0), kind="AdvancedBrep")
    exp["hemisphere"] = dict(volume=2 / 3 * math.pi * R**3, area=3 * math.pi * R**2, min=[-R, -R, 0], max=[R, R, R], tol=0.03)
    # The same turned over: the loop runs the other way, the face is the
    # southern cap.
    cap = face(s, [loop(s, (e_eq, False))], sphere)
    disk = face(s, [loop(s, (e_eq, True))], floor)
    shell = s.e(f"IFCCLOSEDSHELL(({cap},{disk}))")
    m.element("IFCBUILDINGELEMENTPROXY", "bowl", [s.e(f"IFCADVANCEDBREP({shell})")], at=(10, 0, 0), kind="AdvancedBrep")
    exp["bowl"] = dict(volume=2 / 3 * math.pi * R**3, area=3 * math.pi * R**2, min=[10 - R, -R, -R], max=[10 + R, R, 0], tol=0.03)

    # A patch of a sphere between two parallels and two meridians, an open
    # surface: lon 0..90 degrees, lat 0.3..0.9 radians.
    lat0, lat1, lon1 = 0.3, 0.9, math.pi / 2
    c = lambda lat, lon: (R * math.cos(lat) * math.cos(lon), R * math.cos(lat) * math.sin(lon), R * math.sin(lat))
    a, b, cc, d = (vertex(s, c(lat0, 0)), vertex(s, c(lat0, lon1)), vertex(s, c(lat1, lon1)), vertex(s, c(lat1, 0)))
    parallel = lambda lat: circle(m, 0, 0, R * math.sin(lat), R * math.cos(lat), (0, 0, 1), (1, 0, 0))
    e_ab = edge(s, a, b, trimmed(s, parallel(lat0), 0, lon1))
    e_dc = edge(s, d, cc, trimmed(s, parallel(lat1), 0, lon1))
    # Meridians: circles through the poles, parametrised by latitude.
    e_bc = edge(s, b, cc, trimmed(s, circle(m, 0, 0, 0, R, (1, 0, 0), (0, 1, 0)), lat0, lat1))
    e_ad = edge(s, a, d, trimmed(s, circle(m, 0, 0, 0, R, (0, -1, 0), (1, 0, 0)), lat0, lat1))
    patch = face(s, [loop(s, (e_ab, True), (e_bc, True), (e_dc, False), (e_ad, False))], sphere)
    model = s.e(f"IFCSHELLBASEDSURFACEMODEL(({s.e(f'IFCOPENSHELL(({patch}))')}))")
    m.element("IFCCOVERING", "sphere patch", [model], at=(20, 0, 0), kind="SurfaceModel")
    exp["sphere patch"] = dict(
        area=R * R * lon1 * (math.sin(lat1) - math.sin(lat0)),
        min=[20, 0, R * math.sin(lat0)],
        max=[20 + R * math.cos(lat0), R * math.cos(lat0), R * math.sin(lat1)],
        tol=0.02,
    )

    # A quarter of a torus (major radius 3, minor 1) turned about z from the
    # x axis to the y axis, a face with a seam, and two flat ends.
    big, small = 3.0, 1.0
    torus = s.e(f"IFCTOROIDALSURFACE({m.axis()},{fnum(big)},{fnum(small)})")
    va, vb = vertex(s, (big + small, 0, 0)), vertex(s, (0, big + small, 0))
    c1 = circle(m, big, 0, 0, small, (0, -1, 0), (1, 0, 0))
    c2 = circle(m, 0, big, 0, small, (1, 0, 0), (0, 1, 0))
    e1, e2 = edge(s, va, va, c1), edge(s, vb, vb, c2)
    seam = edge(s, va, vb, trimmed(s, circle(m, 0, 0, 0, big + small, (0, 0, 1), (1, 0, 0)), 0, math.pi / 2))
    lateral = face(s, [loop(s, (e1, True), (seam, True), (e2, False), (seam, False))], torus)
    # The ends face out of the solid: -y at the first, -x at the second; the
    # circles turn about -y and +x.
    end1 = face(s, [loop(s, (e1, True))], s.e(f"IFCPLANE({m.axis(0, 0, 0, zdir=(0, 1, 0), xdir=(1, 0, 0))})"))
    end2 = face(s, [loop(s, (e2, False))], s.e(f"IFCPLANE({m.axis(0, 0, 0, zdir=(1, 0, 0), xdir=(0, 1, 0))})"))
    shell = s.e(f"IFCCLOSEDSHELL(({lateral},{end1},{end2}))")
    m.element("IFCBUILDINGELEMENTPROXY", "torus elbow", [s.e(f"IFCADVANCEDBREP({shell})")], at=(30, 0, 0), kind="AdvancedBrep")
    exp["torus elbow"] = dict(
        volume=math.pi * small**2 * big * math.pi / 2,
        area=2 * math.pi * small * big * math.pi / 2 + 2 * math.pi * small**2,
        min=[30, 0, -small],
        max=[30 + big + small, big + small, small],
        tol=0.03,
    )

    # A cylinder whose side has two circles for bounds and no seam between
    # them (written as two plain face bounds), closed by two disks.
    r, h = 1.5, 4.0
    cyl = s.e(f"IFCCYLINDRICALSURFACE({m.axis()},{fnum(r)})")
    cb = circle(m, 0, 0, 0, r, (0, 0, 1), (1, 0, 0))
    ct = circle(m, 0, 0, h, r, (0, 0, 1), (1, 0, 0))
    vb0, vt0 = vertex(s, (r, 0, 0)), vertex(s, (r, 0, h))
    eb, et = edge(s, vb0, vb0, cb), edge(s, vt0, vt0, ct)
    side = face(s, [loop(s, (eb, True)), loop(s, (et, True))], cyl, outer_bound=False)
    bottom = face(s, [loop(s, (eb, False))], s.e(f"IFCPLANE({m.axis()})"))
    top = face(s, [loop(s, (et, True))], s.e(f"IFCPLANE({m.axis(0, 0, h)})"))
    shell = s.e(f"IFCCLOSEDSHELL(({side},{bottom},{top}))")
    m.element("IFCBUILDINGELEMENTPROXY", "tube without seam", [s.e(f"IFCADVANCEDBREP({shell})")], at=(40, 0, 0), kind="AdvancedBrep")
    exp["tube without seam"] = dict(
        volume=math.pi * r * r * h,
        area=2 * math.pi * r * h + 2 * math.pi * r * r,
        min=[40 - r, -r, 0],
        max=[40 + r, r, h],
        tol=0.02,
    )

    # A quarter of a cylinder as a rational B-spline surface (radius 2,
    # height 5), cut to 15..75 degrees and 1..4 high by four straight
    # edges: the face is the part of the surface inside them.
    r, h, w = 2.0, 5.0, math.sqrt(2) / 2
    p3 = lambda x, y, z: pt(s, x, y, z)
    rows = ",".join(f"({p3(x, y, 0)},{p3(x, y, h)})" for x, y in [(r, 0), (r, r), (0, r)])
    spline = s.e(f"IFCRATIONALBSPLINESURFACEWITHKNOTS(2,1,({rows}),.UNSPECIFIED.,.F.,.F.,.F.,(3,3),(2,2),(0.,1.),(0.,1.),.UNSPECIFIED.,((1.,1.),({fnum(w)},{fnum(w)}),(1.,1.)))")
    t0, t1, z0, z1 = math.radians(15), math.radians(75), 1.0, 4.0
    corner = lambda t, z: vertex(s, (r * math.cos(t), r * math.sin(t), z))
    k = [corner(t0, z0), corner(t1, z0), corner(t1, z1), corner(t0, z1)]
    straight = lambda i, j: edge(s, k[i], k[j], s.e("IFCPOLYLINE((" + ",".join(s.e(f"IFCCARTESIANPOINT(({','.join(fnum(v) for v in p)}))") for p in [pos[i], pos[j]]) + "))"))
    pos = [(r * math.cos(t0), r * math.sin(t0), z0), (r * math.cos(t1), r * math.sin(t1), z0), (r * math.cos(t1), r * math.sin(t1), z1), (r * math.cos(t0), r * math.sin(t0), z1)]
    patch = face(s, [loop(s, (straight(0, 1), True), (straight(1, 2), True), (straight(2, 3), True), (straight(3, 0), True))], spline)
    model = s.e(f"IFCSHELLBASEDSURFACEMODEL(({s.e(f'IFCOPENSHELL(({patch}))')}))")
    m.element("IFCCOVERING", "spline patch", [model], at=(50, 0, 0), kind="SurfaceModel")
    exp["spline patch"] = dict(
        area=r * (t1 - t0) * (z1 - z0),
        min=[50 + r * math.cos(t1), r * math.sin(t0), z0],
        max=[50 + r * math.cos(t0), r * math.sin(t1), z1],
        tol=0.02,
    )

    # A flat B-spline square (4 x 4, degree 2) cut to the square from 0.5 to
    # 3.5 with a round hole of radius 1 at its middle.
    rows = ",".join("(" + ",".join(p3(2.0 * i, 2.0 * j, 0) for j in range(3)) + ")" for i in range(3))
    plate = s.e(f"IFCBSPLINESURFACEWITHKNOTS(2,2,({rows}),.UNSPECIFIED.,.F.,.F.,.F.,(3,3),(3,3),(0.,1.),(0.,1.),.UNSPECIFIED.)")
    q = [(0.5, 0.5), (3.5, 0.5), (3.5, 3.5), (0.5, 3.5)]
    qv = [vertex(s, (x, y, 0)) for x, y in q]
    sides = []
    for i in range(4):
        x0, y0 = q[i]
        x1, y1 = q[(i + 1) % 4]
        line = s.e("IFCPOLYLINE((" + pt(s, x0, y0, 0) + "," + pt(s, x1, y1, 0) + "))")
        sides.append((edge(s, qv[i], qv[(i + 1) % 4], line), True))
    hole_c = circle(m, 2, 2, 0, 1.0, (0, 0, 1), (1, 0, 0))
    vh = vertex(s, (3, 2, 0))
    hole = edge(s, vh, vh, hole_c)
    cut = face(s, [loop(s, *sides), loop(s, (hole, False))], plate)
    model = s.e(f"IFCSHELLBASEDSURFACEMODEL(({s.e(f'IFCOPENSHELL(({cut}))')}))")
    m.element("IFCCOVERING", "plate with hole", [model], at=(60, 0, 0), kind="SurfaceModel")
    # The hole is the 32-gon the circle is sampled with.
    exp["plate with hole"] = dict(area=9.0 - 16 * math.sin(2 * math.pi / 32), min=[60.5, 0.5, 0], max=[63.5, 3.5, 0], tol=1e-4)
    # Caps cut by a circle in a tilted plane (axis 45 degrees up), so that
    # their parameters make no rectangle: one that stays clear of the pole
    # (angular radius 25.8 degrees), one that holds it (53.1 degrees). The
    # area of a cap is 2 pi R^2 (1 - cos of its angular radius).
    nx = nz = math.sqrt(0.5)
    for k, (name, h) in enumerate([("tilted cap", 1.8), ("tilted cap with the pole", 1.2)]):
        rho = math.sqrt(R * R - h * h)
        rim = circle(m, h * nx, 0, h * nz, rho, (nx, 0, nz), (0, 1, 0))
        vr = vertex(s, (h * nx, rho, h * nz))
        er = edge(s, vr, vr, rim)
        cap = face(s, [loop(s, (er, True))], sphere)
        model = s.e(f"IFCSHELLBASEDSURFACEMODEL(({s.e(f'IFCOPENSHELL(({cap}))')}))")
        m.element("IFCCOVERING", name, [model], at=(70 + 10 * k, 0, 0), kind="SurfaceModel")
        exp[name] = dict(area=2 * math.pi * R * R * (1 - h / R), tol=0.03)
    m.write("curved_faces.ifc", {"elements": exp})


def sweep_params():
    """Sweeps between a start and an end parameter, along each kind of
    directrix that publishes one. The angle unit is the degree."""

    def units(s):
        metre = s.e("IFCSIUNIT(*,.LENGTHUNIT.,$,.METRE.)")
        rad = s.e("IFCSIUNIT(*,.PLANEANGLEUNIT.,$,.RADIAN.)")
        measure = s.e(f"IFCMEASUREWITHUNIT(IFCPLANEANGLEMEASURE(0.017453292519943295),{rad})")
        deg = s.e(f"IFCCONVERSIONBASEDUNIT({s.e('IFCDIMENSIONALEXPONENTS(0,0,0,0,0,0,0)')},.PLANEANGLEUNIT.,'DEGREE',{measure})")
        return metre, deg

    m = Model(units=units)
    s = m.s
    exp = {}
    rad = 0.1
    tube = math.pi * rad * rad
    poly = lambda *ps: s.e("IFCPOLYLINE((" + ",".join(pt(s, *p) for p in ps) + "))")
    L = (0, 0, 0), (2, 0, 0), (2, 2, 0)
    # Index parameters of a polyline: 0.5 is half way along the first side,
    # 1.5 half way along the second: a path of 1 + 1.
    m.element("IFCPIPESEGMENT", "disk on polyline", [s.e(f"IFCSWEPTDISKSOLID({poly(*L)},{fnum(rad)},$,0.5,1.5)")], at=(0, 0, 0))
    exp["disk on polyline"] = dict(volume=tube * 2.0, min=[1, -rad, -rad], max=[2 + rad, 1, rad], tol=0.03)
    # The same path asked for from the far end: the same solid.
    m.element("IFCPIPESEGMENT", "disk on polyline reversed", [s.e(f"IFCSWEPTDISKSOLID({poly(*L)},{fnum(rad)},$,1.5,0.5)")], at=(10, 0, 0))
    exp["disk on polyline reversed"] = dict(volume=tube * 2.0, min=[11, -rad, -rad], max=[12 + rad, 1, rad], tol=0.03)
    # Parameters beyond the ends are the ends.
    m.element("IFCPIPESEGMENT", "disk past the ends", [s.e(f"IFCSWEPTDISKSOLID({poly(*L)},{fnum(rad)},$,-3.,9.)")], at=(15, 0, 0))
    exp["disk past the ends"] = dict(volume=tube * 4.0, tol=0.03)
    # A composite curve of two polylines is parametrised by the sum of its
    # segments' parametric lengths: 0..1 and 1..2.
    segs = [s.e(f"IFCCOMPOSITECURVESEGMENT(.CONTINUOUS.,.T.,{poly(L[0], L[1])})"), s.e(f"IFCCOMPOSITECURVESEGMENT(.CONTINUOUS.,.T.,{poly(L[1], L[2])})")]
    cc = s.e(f"IFCCOMPOSITECURVE(({','.join(segs)}),.F.)")
    m.element("IFCPIPESEGMENT", "disk on composite", [s.e(f"IFCSWEPTDISKSOLID({cc},{fnum(rad)},$,0.5,1.5)")], at=(20, 0, 0))
    exp["disk on composite"] = dict(volume=tube * 2.0, min=[21, -rad, -rad], max=[22 + rad, 1, rad], tol=0.03)
    # A circle of radius 2 swept from 0 to 90 degrees (the file's unit).
    circ = circle(m, 0, 0, 0, 2.0, (0, 0, 1), (1, 0, 0))
    m.element("IFCPIPESEGMENT", "disk on circle", [s.e(f"IFCSWEPTDISKSOLID({circ},{fnum(rad)},$,0.,90.)")], at=(30, 0, 0))
    # The end caps are square to the last chord of the arc, not to the arc:
    # the extents are those of the arc, a hundredth of a metre either way.
    exp["disk on circle"] = dict(volume=tube * math.pi, tol=0.03)
    # A trimmed circle: the parameters are those of the basis circle, so the
    # whole half circle from 90 to 270 degrees is swept from 135 to 225.
    half = s.e(f"IFCTRIMMEDCURVE({circ},(IFCPARAMETERVALUE(90.)),(IFCPARAMETERVALUE(270.)),.T.,.PARAMETER.)")
    m.element("IFCPIPESEGMENT", "disk on trimmed circle", [s.e(f"IFCSWEPTDISKSOLID({half},{fnum(rad)},$,135.,225.)")], at=(40, 0, 0))
    exp["disk on trimmed circle"] = dict(volume=tube * math.pi, tol=0.03)
    # Surface curve swept and fixed reference sweeps (the profile 0.2 x 0.4).
    plane = s.e(f"IFCPLANE({m.axis()})")
    line3 = poly((0, 0, 0), (0, 1, 0), (0, 3, 0))
    sw = s.e(f"IFCSURFACECURVESWEPTAREASOLID({m.rect(0.2, 0.4)},$,{line3},1.,2.,{plane})")
    m.element("IFCBEAM", "surface curve swept", [sw], at=(50, 0, 0))
    exp["surface curve swept"] = dict(volume=0.08 * 2.0, min=[49.8, 1, -0.1], max=[50.2, 3, 0.1], tol=1e-6)
    # An unbounded line is parametrised by multiples of its vector.
    unbounded = s.e(f"IFCLINE({pt(s, 0., 0., 0.)},{s.e(f'IFCVECTOR({dr(s, 0., 1., 0.)},2.)')})")
    fr = s.e(f"IFCFIXEDREFERENCESWEPTAREASOLID({m.rect(0.2, 0.4)},$,{unbounded},0.5,1.5,{dr(s, 1., 0., 0.)})")
    m.element("IFCBEAM", "fixed reference on a line", [fr], at=(60, 0, 0))
    exp["fixed reference on a line"] = dict(volume=0.08 * 2.0, min=[59.9, 1, -0.2], max=[60.1, 3, 0.2], tol=1e-6)
    # No parameters at all: the whole directrix, as before.
    m.element("IFCPIPESEGMENT", "disk whole", [s.e(f"IFCSWEPTDISKSOLID({poly(*L)},{fnum(rad)},$,$,$)")], at=(70, 0, 0))
    exp["disk whole"] = dict(volume=tube * 4.0, tol=0.03)
    m.write("sweep_params.ifc", {"elements": exp})


def alignment():
    """An IFC4X3 alignment: a plan of a line, a clothoid, a left arc, a
    right arc (a negative segment length) and a line, and a profile of two
    gradients, as `IfcCurveSegment`s of an `IfcGradientCurve`. Stations and
    heights below are integrated here, apart from the reader."""
    m = Model(schema="IFC4X3_ADD2")
    s = m.s
    exp = {}
    P = lambda x, y: pt(s, x, y)
    D = lambda x, y: dr(s, x, y)
    seg = lambda x, y, hx, hy, start, length, parent: s.e(
        f"IFCCURVESEGMENT(.CONTINUOUS.,{s.e(f'IFCAXIS2PLACEMENT2D({P(x, y)},{D(hx, hy)})')},IFCLENGTHMEASURE({fnum(start)}),IFCLENGTHMEASURE({fnum(length)}),{parent})"
    )
    line = s.e(f"IFCLINE({P(0., 0.)},{s.e(f'IFCVECTOR({D(1., 0.)},1.)')})")
    origin2 = s.e(f"IFCAXIS2PLACEMENT2D({P(0., 0.)},{D(1., 0.)})")
    R3, R4, L2, L3, L4 = 300.0, 200.0, 60.0, 120.0, 100.0
    A = math.sqrt(R3 * L2)
    clothoid = s.e(f"IFCCLOTHOID({origin2},{fnum(A)})")
    arc3 = s.e(f"IFCCIRCLE({origin2},{fnum(R3)})")
    arc4 = s.e(f"IFCCIRCLE({origin2},{fnum(R4)})")

    def fresnel(a, s_end, n=20000):
        """The integral of cos and sin of s^2 / (2 A^2) from 0 to s_end
        (Simpson)."""
        h = s_end / n
        cx = sy = 0.0
        for i in range(n + 1):
            wgt = 1 if i in (0, n) else (4 if i % 2 else 2)
            th = (i * h) ** 2 / (2 * a * a)
            cx += wgt * math.cos(th)
            sy += wgt * math.sin(th)
        return cx * h / 3, sy * h / 3

    p1 = (100.0, 0.0)
    fx, fy = fresnel(A, L2)
    p2 = (p1[0] + fx, p1[1] + fy)
    th2 = L2 * L2 / (2 * A * A)
    th3 = th2 + L3 / R3
    p3 = (p2[0] + R3 * (math.sin(th3) - math.sin(th2)), p2[1] + R3 * (math.cos(th2) - math.cos(th3)))
    th4 = th3 - L4 / R4
    p4 = (p3[0] + R4 * (math.sin(th3) - math.sin(th4)), p3[1] + R4 * (math.cos(th4) - math.cos(th3)))
    th_mid = th3 - 50.0 / R4
    p_mid = (p3[0] + R4 * (math.sin(th3) - math.sin(th_mid)), p3[1] + R4 * (math.cos(th_mid) - math.cos(th3)))
    p5 = (p4[0] + 50 * math.cos(th4), p4[1] + 50 * math.sin(th4))
    plan_segments = [
        seg(0, 0, 1, 0, 0, 100, line),
        seg(p1[0], p1[1], 1, 0, 0, L2, clothoid),
        seg(p2[0], p2[1], math.cos(th2), math.sin(th2), 0, L3, arc3),
        # Right turn: the circle's start, travelled the other way.
        seg(p3[0], p3[1], math.cos(th3), math.sin(th3), 0, -L4, arc4),
        seg(p4[0], p4[1], math.cos(th4), math.sin(th4), 0, 50, line),
    ]
    plan = s.e(f"IFCCOMPOSITECURVE(({','.join(plan_segments)}),.F.)")
    g1, g2 = 0.02, -0.01
    vseg = lambda x, z, grad, run, parent=line: seg(x, z, 1, grad, 0, run * math.sqrt(1 + grad * grad), parent)
    vertical = [vseg(0, 10, g1, 200), vseg(200, 10 + g1 * 200, g2, 230)]
    gradient = s.e(f"IFCGRADIENTCURVE(({','.join(vertical)}),.F.,{plan},$)")
    height = lambda x: 10 + g1 * x if x <= 200 else 10 + g1 * 200 + g2 * (x - 200)
    # The alignment itself: an axis curve, which is not drawn.
    axis_rep = s.e(f"IFCSHAPEREPRESENTATION({m.ctx},'Axis','Curve3D',({gradient}))")
    s.e(f"IFCALIGNMENT({s.guid()},$,'Alignment',$,$,{m.place(None)},{s.e(f'IFCPRODUCTDEFINITIONSHAPE($,$,({axis_rep}))')},$)")
    # Tubes along it, whole and between 100 and 280 (distances along).
    rad = 0.5
    slant = lambda a, b: sum(max(0.0, min(b, hi) - max(a, lo)) * math.sqrt(1 + g * g) for lo, hi, g in [(0, 200, g1), (200, 430, g2)])
    m.element("IFCPIPESEGMENT", "tube whole", [s.e(f"IFCSWEPTDISKSOLID({gradient},{fnum(rad)},$,$,$)")], at=(0, 0, 0))
    # The disk is a 16-gon: 2.5% less area than the circle.
    exp["tube whole"] = dict(volume=math.pi * rad * rad * slant(0, 430), tol=0.03)
    m.element("IFCPIPESEGMENT", "tube 100 to 280", [s.e(f"IFCSWEPTDISKSOLID({gradient},{fnum(rad)},$,100.,280.)")], at=(0, 0, 0))
    exp["tube 100 to 280"] = dict(volume=math.pi * rad * rad * slant(100, 280), tol=0.03)
    # A column 250 along it and 3 to the left. The linear placement has no
    # Cartesian equivalent: it is worked out along the curve.
    d, lateral = 250.0, 3.0
    th = th2 + (d - 160.0) / R3
    px = p2[0] + R3 * (math.sin(th) - math.sin(th2))
    py = p2[1] + R3 * (math.cos(th2) - math.cos(th))
    lx, ly = -math.sin(th), math.cos(th)
    at_point = (px + lateral * lx, py + lateral * ly, height(d))
    expr = s.e(f"IFCPOINTBYDISTANCEEXPRESSION(IFCLENGTHMEASURE({fnum(d)}),{fnum(lateral)},$,$,{gradient})")
    linear = s.e(f"IFCLINEARPLACEMENT($,{s.e(f'IFCAXIS2PLACEMENTLINEAR({expr},$,$)')},$)")
    m.element("IFCCOLUMN", "column on the alignment", [m.extrude(m.rect(2.0, 1.0), 4.0)], placement=linear)
    hx, hy = abs(math.cos(th)) + 0.5 * abs(math.sin(th)), abs(math.sin(th)) + 0.5 * abs(math.cos(th))
    # Its position is checked in tests/ifc_geometry.rs.
    exp["column on the alignment"] = dict(volume=8.0, tol=1e-6)
    stations_extra = dict(column_at=at_point, column_half=[hx, hy])
    # With the writer's Cartesian position too: that one is used.
    cart = m.axis(5.0, 5.0, 0.0)
    linear2 = s.e(f"IFCLINEARPLACEMENT($,{s.e(f'IFCAXIS2PLACEMENTLINEAR({expr},$,$)')},{cart})")
    m.element("IFCCOLUMN", "column with its Cartesian position", [m.extrude(m.rect(1.0, 1.0), 1.0)], placement=linear2)
    exp["column with its Cartesian position"] = box(4.5, 4.5, 0, 5.5, 5.5, 1)
    stations = dict(
        line_end=p1,
        clothoid_end=p2,
        left_arc_end=p3,
        right_arc_mid=p_mid,
        right_arc_end=p4,
        end=p5,
        heading=[0.0, th2, th3, th4, th4],
        heights=[height(0), height(100), height(200), height(430)],
        **stations_extra,
    )
    m.write("alignment.ifc", {"elements": exp, "stations": stations, "tube_radius": rad})


def grid():
    """Placements at the intersections of a grid's axes, IFC4 and IFC4X3."""
    m = Model()
    s = m.s
    exp = {}
    # The grid: placed at (100, 50), turned a quarter (its x along world y).
    gpl = m.place(m.storey_pl, 100.0, 50.0, 0.0, zdir=(0, 0, 1), xdir=(0, 1, 0))
    poly = lambda *ps: s.e("IFCPOLYLINE((" + ",".join(pt(s, *p) for p in ps) + "))")
    u1 = s.e(f"IFCGRIDAXIS('1',{poly((0.0, 0.0), (20.0, 0.0))},.T.)")
    u2 = s.e(f"IFCGRIDAXIS('2',{poly((0.0, 6.0), (20.0, 6.0))},.T.)")
    # Unbounded lines, one of them the other way round.
    vector = s.e(f"IFCVECTOR({dr(s, 0., 1.)},1.)")
    v1 = s.e(f"IFCGRIDAXIS('A',{s.e(f'IFCLINE({pt(s, 0., 0.)},{vector})')},.T.)")
    v2 = s.e(f"IFCGRIDAXIS('B',{s.e(f'IFCLINE({pt(s, 8., 0.)},{vector})')},.T.)")
    u2_back = s.e(f"IFCGRIDAXIS('2r',{poly((0.0, 6.0), (20.0, 6.0))},.F.)")
    s.e(f"IFCGRID({s.guid()},$,'Grid',$,$,{gpl},$,({u1},{u2},{u2_back}),({v1},{v2}),$,$)")
    cross = lambda a, b, off: s.e(f"IFCVIRTUALGRIDINTERSECTION(({a},{b}),({','.join(fnum(o) for o in off)}))")
    to_world = lambda x, y: (100.0 - y, 50.0 + x)

    def column(name, location, refdir, size, at_grid, z=0.0, dirw=None):
        e, _ = m.element("IFCCOLUMN", name, [m.extrude(m.rect(*size), 3.0)], placement=s.e(f"IFCGRIDPLACEMENT({location},{refdir})"))
        wx, wy = to_world(*at_grid)
        # The box, 3 high, with its x along `dirw` (default: grid x, which
        # is world y).
        dx, dy = dirw or (0.0, 1.0)
        hx = abs(dx) * size[0] / 2 + abs(dy) * size[1] / 2
        hy = abs(dy) * size[0] / 2 + abs(dx) * size[1] / 2
        exp[name] = dict(volume=size[0] * size[1] * 3.0, min=[wx - hx, wy - hy, z], max=[wx + hx, wy + hy, z + 3.0], tol=1e-6)

    # At the intersection of axes 1 and B: (8, 0) in the grid, its x along
    # the first axis, which is the grid's x.
    column("at an intersection", cross(u1, v2, (0.0, 0.0, 0.0)), "$", (2.0, 1.0), (8.0, 0.0))
    # With offsets: 0.5 to the left of axis 2 (which runs +x: y = 6.5), 1 to
    # the left of B (which runs +y: x = 7, so -1 is x = 9), and 2 up.
    column("with offsets", cross(u2, v2, (0.5, -1.0, 2.0)), "$", (2.0, 1.0), (9.0, 6.5), z=2.0)
    # The axis the other way: left of it is the other side.
    column("on a reversed axis", cross(u2_back, v2, (0.5, 0.0)), "$", (2.0, 1.0), (8.0, 5.5), dirw=(0.0, -1.0))
    # Its x along a given direction (the grid's y).
    column("along a direction", cross(u1, v1, (0.0, 0.0)), dr(s, 0.0, 1.0), (2.0, 1.0), (0.0, 0.0), dirw=(-1.0, 0.0))
    # Its x towards another intersection: (8, 6) from (0, 0), 10 long.
    column("towards an intersection", cross(u1, v1, (0.0, 0.0)), cross(u2, v2, (0.0, 0.0)), (2.0, 1.0), (0.0, 0.0), dirw=to_world_dir((8.0, 6.0)))
    m.write("grid.ifc", {"elements": exp})

    # IFC4X3: the placement names the grid's own placement first.
    m = Model(schema="IFC4X3_ADD2")
    s = m.s
    exp = {}
    gpl = m.place(m.storey_pl, 100.0, 50.0, 0.0, zdir=(0, 0, 1), xdir=(0, 1, 0))
    a = s.e(f"IFCGRIDAXIS('1',{s.e('IFCPOLYLINE((' + pt(s, 0., 0.) + ',' + pt(s, 20., 0.) + '))')},.T.)")
    b = s.e(f"IFCGRIDAXIS('A',{s.e('IFCPOLYLINE((' + pt(s, 8., -1.) + ',' + pt(s, 8., 9.) + '))')},.T.)")
    s.e(f"IFCGRID({s.guid()},$,'Grid',$,$,{gpl},$,({a}),({b}),$,$)")
    where = s.e(f"IFCVIRTUALGRIDINTERSECTION(({a},{b}),(0.,0.,0.))")
    m.element("IFCCOLUMN", "at an intersection", [m.extrude(m.rect(2.0, 1.0), 3.0)], placement=s.e(f"IFCGRIDPLACEMENT({gpl},{where},$)"))
    exp["at an intersection"] = dict(volume=6.0, min=[99.5, 57.0, 0], max=[100.5, 59.0, 3], tol=1e-6)
    m.write("grid_ifc4x3.ifc", {"elements": exp})


def to_world_dir(d):
    """The grid's direction `d` in the world, for the grid turned a quarter."""
    n = math.hypot(*d)
    return (-d[1] / n, d[0] / n)


def storeys():
    """Three storeys in millimetres with their elevations, an element in
    each, a room with a table in it, and an element in the building itself."""

    def units(s):
        return s.e("IFCSIUNIT(*,.LENGTHUNIT.,.MILLI.,.METRE.)"), None

    m = Model(units=units)
    s = m.s
    storeys = [("Level 0", 0.0, m.storey, m.storey_pl)]
    building_pl = m.place(None, 0, 0, 0)
    for k, (name, z) in enumerate([("Level 1", 3000.0), ("Level 2", 6000.0)]):
        pl = m.place(building_pl, 0, 0, z)
        st = s.e(f"IFCBUILDINGSTOREY({s.guid()},$,'{name}',$,$,{pl},$,$,.ELEMENT.,{fnum(z)})")
        s.e(f"IFCRELAGGREGATES({s.guid()},$,$,$,{m.building},({st}))")
        storeys.append((name, z, st, pl))
    per = {}
    for name, z, st, pl in storeys:
        e, _ = m.element("IFCWALL", f"wall {name}", [m.extrude(m.rect(1000.0, 100.0), 2500.0)], placement=pl, contained=False)
        per.setdefault(st, []).append(e)
    # A room on level 1 with a table in it.
    room = s.e(f"IFCSPACE({s.guid()},$,'Room',$,$,{storeys[1][3]},$,$,.ELEMENT.,.INTERNAL.,$)")
    s.e(f"IFCRELAGGREGATES({s.guid()},$,$,$,{storeys[1][2]},({room}))")
    table, _ = m.element("IFCFURNISHINGELEMENT", "table", [m.extrude(m.rect(800.0, 800.0), 700.0)], placement=storeys[1][3], contained=False)
    s.e(f"IFCRELCONTAINEDINSPATIALSTRUCTURE({s.guid()},$,$,$,({table}),{room})")
    # Not in a storey: in the building.
    shed, _ = m.element("IFCBUILDINGELEMENTPROXY", "shed", [m.extrude(m.rect(500.0, 500.0), 500.0)], at=(20000.0, 0, 0), contained=False)
    s.e(f"IFCRELCONTAINEDINSPATIALSTRUCTURE({s.guid()},$,$,$,({shed}),{m.building})")
    for st, es in per.items():
        s.e(f"IFCRELCONTAINEDINSPATIALSTRUCTURE({s.guid()},$,$,$,({','.join(es)}),{st})")
    m.write(
        "storeys.ifc",
        {
            "storeys": [["Level 0", 0.0], ["Level 1", 3.0], ["Level 2", 6.0]],
            "membership": {"wall Level 0": "Level 0", "wall Level 1": "Level 1", "wall Level 2": "Level 2", "table": "Level 1", "shed": None},
        },
    )


profiles()
solids()
tessellated()
booleans()
mapped_and_units()
ifc2x3_and_feet()
damaged()
curved_faces()
sweep_params()
alignment()
grid()
storeys()
with open(os.path.join(HERE, "expected.json"), "w") as f:
    json.dump(EXPECTED, f, indent=1, sort_keys=True)
    f.write("\n")
print("wrote", ", ".join(sorted(EXPECTED)))
