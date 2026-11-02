#!/usr/bin/env python3
"""Writes the demo's IFC example into ../files/ifc/.

    python3 -I make-ifc.py [OUT_DIR]

Output: CC0-1.0, a public domain dedication by the exav project. The model is
written here as STEP text, entity by entity, with no IFC library and no
outside model.

Needs: Python 3.

house.ifc (IFC4): a two-storey house, 10 by 8 metres. Per storey: outer and
inner walls (extruded rectangles), openings cut by IfcRelVoidsElement and
filled by windows and doors (IfcRelFillsElement) with separate frame and glass
colours, a floor slab; a gable roof (an extruded triangle), a porch with
columns, a straight stair (a step per solid), a table and four chairs that
share one mapped representation, spaces, a material and a property set, and
colours through IfcStyledItem.
"""
import hashlib
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(HERE, "..", "files", "ifc")
os.makedirs(OUT, exist_ok=True)

ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_$"


def guid(n):
    num = int.from_bytes(hashlib.md5(f"exav-house-{n}".encode()).digest(), "big")
    chars = [ALPHABET[num >> 126]]
    for i in range(21):
        chars.append(ALPHABET[(num >> (120 - 6 * i)) & 63])
    return "".join(chars)


def f(x):
    s = repr(float(x))
    return s if "e" in s or "." in s else s + "."


class Step:
    def __init__(self):
        self.lines = []
        self.n = 0
        self.g = 0

    def add(self, text):
        self.n += 1
        self.lines.append(f"#{self.n}={text};")
        return f"#{self.n}"

    def gid(self):
        self.g += 1
        return f"'{guid(self.g)}'"


S = Step()
pt_cache = {}


def point(x, y, z=None):
    key = (round(x, 6), round(y, 6), None if z is None else round(z, 6))
    if key not in pt_cache:
        pt_cache[key] = S.add(f"IFCCARTESIANPOINT(({f(x)},{f(y)}" + (f",{f(z)}))" if z is not None else "))"))
    return pt_cache[key]


def direction(x, y, z=None):
    return S.add(f"IFCDIRECTION(({f(x)},{f(y)}" + (f",{f(z)}))" if z is not None else "))"))


def axis3(origin=(0, 0, 0), z=None, x=None):
    return S.add(f"IFCAXIS2PLACEMENT3D({point(*origin)}," + (direction(*z) if z else "$") + "," + (direction(*x) if x else "$") + ")")


def axis2(origin=(0, 0), x=None):
    return S.add(f"IFCAXIS2PLACEMENT2D({point(*origin)}," + (direction(*x) if x else "$") + ")")


def placement(rel, origin=(0, 0, 0), z=None, x=None):
    return S.add(f"IFCLOCALPLACEMENT({rel if rel else '$'},{axis3(origin, z, x)})")


def rect_profile(w, d, centre=(0, 0)):
    return S.add(f"IFCRECTANGLEPROFILEDEF(.AREA.,$,{axis2(centre)},{f(w)},{f(d)})")


def circle_profile(r):
    return S.add(f"IFCCIRCLEPROFILEDEF(.AREA.,$,{axis2()},{f(r)})")


def poly_profile(points):
    pl = S.add("IFCPOLYLINE((" + ",".join(point(*p) for p in points + [points[0]]) + "))")
    return S.add(f"IFCARBITRARYCLOSEDPROFILEDEF(.AREA.,$,{pl})")


def extrude(profile, depth, origin=(0, 0, 0), z=None, x=None):
    return S.add(f"IFCEXTRUDEDAREASOLID({profile},{axis3(origin, z, x)},{direction(0, 0, 1)},{f(depth)})")


# ------------------------------------------------------------------ styles

style_cache = {}


def style(name, rgb, transparency=0.0):
    if name not in style_cache:
        col = S.add(f"IFCCOLOURRGB($,{f(rgb[0])},{f(rgb[1])},{f(rgb[2])})")
        rend = S.add(f"IFCSURFACESTYLERENDERING({col},{f(transparency)},$,$,$,$,$,$,.FLAT.)")
        style_cache[name] = S.add(f"IFCSURFACESTYLE('{name}',.BOTH.,({rend}))")
    return style_cache[name]


def styled(item, name, rgb, transparency=0.0):
    S.add(f"IFCSTYLEDITEM({item},({style(name, rgb, transparency)}),$)")
    return item


# --------------------------------------------------------------- the model

origin_axis = axis3()
ctx = S.add(f"IFCGEOMETRICREPRESENTATIONCONTEXT($,'Model',3,1.E-05,{origin_axis},$)")
body = S.add(f"IFCGEOMETRICREPRESENTATIONSUBCONTEXT('Body','Model',*,*,*,*,{ctx},$,.MODEL_VIEW.,$)")
length = S.add("IFCSIUNIT(*,.LENGTHUNIT.,$,.METRE.)")
area = S.add("IFCSIUNIT(*,.AREAUNIT.,$,.SQUARE_METRE.)")
volume = S.add("IFCSIUNIT(*,.VOLUMEUNIT.,$,.CUBIC_METRE.)")
angle = S.add("IFCSIUNIT(*,.PLANEANGLEUNIT.,$,.RADIAN.)")
units = S.add(f"IFCUNITASSIGNMENT(({length},{area},{volume},{angle}))")
project = S.add(f"IFCPROJECT({S.gid()},$,'Example house',$,$,$,$,({ctx}),{units})")

site_pl = placement(None)
site = S.add(f"IFCSITE({S.gid()},$,'Site',$,$,{site_pl},$,$,.ELEMENT.,$,$,$,$,$)")
bld_pl = placement(site_pl)
building = S.add(f"IFCBUILDING({S.gid()},$,'House',$,$,{bld_pl},$,$,.ELEMENT.,$,$,$)")
STOREY_H = 3.0
storeys = []
for i, name in enumerate(["Ground floor", "First floor"]):
    pl = placement(bld_pl, (0, 0, i * STOREY_H))
    storeys.append((S.add(f"IFCBUILDINGSTOREY({S.gid()},$,'{name}',$,$,{pl},$,$,.ELEMENT.,{f(i * STOREY_H)})"), pl))
S.add(f"IFCRELAGGREGATES({S.gid()},$,$,$,{project},({site}))")
S.add(f"IFCRELAGGREGATES({S.gid()},$,$,$,{site},({building}))")
S.add(f"IFCRELAGGREGATES({S.gid()},$,$,$,{building},({storeys[0][0]},{storeys[1][0]}))")

contained = {s[0]: [] for s in storeys}
walls_all = []
brick = S.add("IFCMATERIAL('Brick, rendered')")
WALL_RGB, FRAME_RGB, GLASS_RGB, DOOR_RGB = (0.93, 0.9, 0.82), (0.95, 0.95, 0.95), (0.55, 0.78, 0.92), (0.45, 0.28, 0.14)


def shape(items, kind="SweptSolid"):
    rep = S.add(f"IFCSHAPEREPRESENTATION({body},'Body','{kind}',({','.join(items)}))")
    return S.add(f"IFCPRODUCTDEFINITIONSHAPE($,$,({rep}))")


def add_wall(storey, p1, p2, t, h, openings, name):
    """openings: [(kind, offset along the wall, width, sill, height)]."""
    sidx = storey
    sto, sto_pl = storeys[sidx]
    dx, dy = p2[0] - p1[0], p2[1] - p1[1]
    L = math.hypot(dx, dy)
    ux, uy = dx / L, dy / L
    pl = placement(sto_pl, (p1[0], p1[1], 0), (0, 0, 1), (ux, uy, 0))
    solid = styled(extrude(rect_profile(L, t, (L / 2, 0)), h), "Render", WALL_RGB)
    wall = S.add(f"IFCWALL({S.gid()},$,'{name}',$,$,{pl},{shape([solid])},$,.STANDARD.)")
    contained[sto].append(wall)
    walls_all.append(wall)
    for k, (kind, off, w, sill, oh) in enumerate(openings):
        opl = placement(pl, (off + w / 2, 0, sill))
        hole = extrude(rect_profile(w, t + 0.2), oh)
        opening = S.add(f"IFCOPENINGELEMENT({S.gid()},$,'Opening {name} {k + 1}',$,$,{opl},{shape([hole])},$,.OPENING.)")
        S.add(f"IFCRELVOIDSELEMENT({S.gid()},$,$,$,{wall},{opening})")
        fpl = placement(pl, (off + w / 2, 0, sill))
        if kind == "window":
            frame = styled(extrude(rect_profile(w, 0.1), oh), "Frame", FRAME_RGB)
            glass = styled(extrude(rect_profile(w - 0.12, 0.04), oh - 0.12, (0, 0, 0.06)), "Glass", GLASS_RGB, 0.55)
            bar = styled(extrude(rect_profile(0.05, 0.12), oh), "Frame", FRAME_RGB)
            el = S.add(f"IFCWINDOW({S.gid()},$,'Window {name} {k + 1}',$,$,{fpl},{shape([frame, glass, bar])},$,{f(oh)},{f(w)},.WINDOW.,.NOTDEFINED.,$)")
        else:
            leaf = styled(extrude(rect_profile(w - 0.1, 0.06), oh - 0.05), "Door", DOOR_RGB)
            knob = styled(extrude(rect_profile(0.08, 0.14), 0.08, (w / 2 - 0.2, 0, 1.0)), "Frame", FRAME_RGB)
            el = S.add(f"IFCDOOR({S.gid()},$,'Door {name} {k + 1}',$,$,{fpl},{shape([leaf, knob])},$,{f(oh)},{f(w)},.DOOR.,.NOTDEFINED.,$)")
        S.add(f"IFCRELFILLSELEMENT({S.gid()},$,$,$,{opening},{el})")
        contained[sto].append(el)
    return wall


H = 2.8
for sidx in (0, 1):
    tag = "G" if sidx == 0 else "F"
    door_south = [("door", 6.7, 1.1, 0.0, 2.1)] if sidx == 0 else [("window", 6.9, 1.2, 0.9, 1.3)]
    add_wall(sidx, (0, 0), (10, 0), 0.3, H, [("window", 1.0, 1.2, 0.9, 1.3), ("window", 3.6, 1.2, 0.9, 1.3)] + door_south, f"{tag}-South")
    add_wall(sidx, (10, 0), (10, 8), 0.3, H, [("window", 1.4, 1.3, 0.9, 1.3), ("window", 5.0, 1.3, 0.9, 1.3)], f"{tag}-East")
    add_wall(sidx, (10, 8), (0, 8), 0.3, H, [("window", 1.2, 1.4, 0.9, 1.3), ("window", 4.1, 1.6, 0.9, 1.3), ("window", 7.2, 1.2, 0.9, 1.3)], f"{tag}-North")
    add_wall(sidx, (0, 8), (0, 0), 0.3, H, [("window", 1.6, 1.4, 0.9, 1.3), ("window", 5.0, 1.4, 0.9, 1.3)], f"{tag}-West")
    add_wall(sidx, (6, 0.15), (6, 7.85), 0.15, H, [("door", 1.5, 0.9, 0.0, 2.05), ("door", 5.0, 0.9, 0.0, 2.05)], f"{tag}-Partition A")
    add_wall(sidx, (0.15, 4), (6, 4), 0.15, H, [("door", 1.0, 0.9, 0.0, 2.05)], f"{tag}-Partition B")

# Slabs: ground slab under the house, a floor slab between the storeys, a porch slab.
ground, ground_pl = storeys[0]
first, first_pl = storeys[1]
slab1 = styled(extrude(rect_profile(10.3, 8.3, (5, 4)), 0.2, (0, 0, -0.2)), "Concrete", (0.62, 0.62, 0.6))
s1 = S.add(f"IFCSLAB({S.gid()},$,'Ground slab',$,$,{placement(ground_pl)},{shape([slab1])},$,.BASESLAB.)")
slab2 = styled(extrude(poly_profile([(-0.15, -0.15), (10.15, -0.15), (10.15, 8.15), (-0.15, 8.15)]), 0.2, (0, 0, H)), "Concrete", (0.7, 0.7, 0.68))
s2 = S.add(f"IFCSLAB({S.gid()},$,'Floor slab',$,$,{placement(ground_pl)},{shape([slab2])},$,.FLOOR.)")
porch = styled(extrude(rect_profile(4.0, 1.4, (8.2, -0.8)), 0.15, (0, 0, H)), "Concrete", (0.7, 0.7, 0.68))
s3 = S.add(f"IFCSLAB({S.gid()},$,'Porch roof',$,$,{placement(ground_pl)},{shape([porch])},$,.ROOF.)")
contained[ground] += [s1, s2, s3]
for k, (cx, cy) in enumerate([(6.4, -1.3), (10.0, -1.3)]):
    col = styled(extrude(circle_profile(0.15), H, (0, 0, 0)), "Column", (0.9, 0.9, 0.9))
    contained[ground].append(S.add(f"IFCCOLUMN({S.gid()},$,'Porch column {k + 1}',$,$,{placement(ground_pl, (cx, cy, 0))},{shape([col])},$,.COLUMN.)"))

# Roof: a triangle in the YZ plane, extruded along X.
tri = poly_profile([(-0.6, 0.0), (8.6, 0.0), (4.0, 2.7)])
roof_solid = styled(extrude(tri, 11.2, (0, 0, 0), (1, 0, 0), (0, 1, 0)), "Tiles", (0.7, 0.28, 0.2))
roof_pl = placement(first_pl, (-0.6, 0, 2.8 + 0.2))
roof = S.add(f"IFCROOF({S.gid()},$,'Gable roof',$,$,{roof_pl},{shape([roof_solid])},$,.GABLE_ROOF.)")
contained[first].append(roof)

# A straight stair in the hall: eleven steps, each a block up to its tread.
steps = []
for k in range(11):
    top = 0.25 * (k + 1)
    steps.append(styled(extrude(rect_profile(1.0, 0.28, (0.0, 0.14 + 0.28 * k)), top), "Wood", (0.6, 0.42, 0.25)))
stair = S.add(f"IFCSTAIR({S.gid()},$,'Stair',$,$,{placement(ground_pl, (6.9, 4.3, 0))},{shape(steps)},$,.STRAIGHT_RUN_STAIR.)")
contained[ground].append(stair)

# A table and four chairs sharing one mapped representation.
def furniture_map(parts, name):
    rep = S.add(f"IFCSHAPEREPRESENTATION({body},'Body','SweptSolid',({','.join(parts)}))")
    return S.add(f"IFCREPRESENTATIONMAP({axis3()},{rep})")


chair_parts = [styled(extrude(rect_profile(0.45, 0.45, (0, 0)), 0.05, (0, 0, 0.45)), "Chair", (0.75, 0.2, 0.2)),
               styled(extrude(rect_profile(0.45, 0.05, (0, -0.2)), 0.5, (0, 0, 0.5)), "Chair", (0.75, 0.2, 0.2))]
for dx in (-0.19, 0.19):
    for dy in (-0.19, 0.19):
        chair_parts.append(styled(extrude(rect_profile(0.05, 0.05, (dx, dy)), 0.45), "Chair legs", (0.3, 0.2, 0.15)))
chair_map = furniture_map(chair_parts, "Chair")
table_parts = [styled(extrude(rect_profile(1.6, 0.9, (0, 0)), 0.06, (0, 0, 0.72)), "Wood", (0.6, 0.42, 0.25))]
for dx in (-0.72, 0.72):
    for dy in (-0.36, 0.36):
        table_parts.append(styled(extrude(rect_profile(0.07, 0.07, (dx, dy)), 0.72), "Wood", (0.5, 0.35, 0.2)))
table_map = furniture_map(table_parts, "Table")


def mapped(rep_map, scale=1.0):
    op = S.add(f"IFCCARTESIANTRANSFORMATIONOPERATOR3D($,$,{point(0, 0, 0)},{f(scale)},$)")
    item = S.add(f"IFCMAPPEDITEM({rep_map},{op})")
    return shape([item], "MappedRepresentation")


contained[ground].append(S.add(f"IFCFURNISHINGELEMENT({S.gid()},$,'Table',$,$,{placement(ground_pl, (3.0, 6.0, 0))},{mapped(table_map)},$)"))
for k, (cx, cy, rot) in enumerate([(2.4, 6.0, 90), (3.6, 6.0, -90), (3.0, 5.2, 180), (3.0, 6.8, 0)]):
    a = math.radians(rot)
    contained[ground].append(S.add(f"IFCFURNISHINGELEMENT({S.gid()},$,'Chair {k + 1}',$,$,{placement(ground_pl, (cx, cy, 0), (0, 0, 1), (math.cos(a), math.sin(a), 0))},{mapped(chair_map)},$)"))

# Spaces (no geometry), a property set and the material on the walls.
spaces = []
for name, plc in [("Living room", ground_pl), ("Kitchen", ground_pl), ("Hall", ground_pl), ("Bedroom", first_pl), ("Bath", first_pl)]:
    spaces.append(S.add(f"IFCSPACE({S.gid()},$,'{name}',$,$,{placement(plc)},$,$,.ELEMENT.,.INTERNAL.,$)"))
S.add(f"IFCRELAGGREGATES({S.gid()},$,$,$,{ground},({spaces[0]},{spaces[1]},{spaces[2]}))")
S.add(f"IFCRELAGGREGATES({S.gid()},$,$,$,{first},({spaces[3]},{spaces[4]}))")
prop_ext = S.add("IFCPROPERTYSINGLEVALUE('IsExternal',$,IFCBOOLEAN(.T.),$)")
prop_fire = S.add("IFCPROPERTYSINGLEVALUE('FireRating',$,IFCLABEL('REI 60'),$)")
pset = S.add(f"IFCPROPERTYSET({S.gid()},$,'Pset_WallCommon',$,({prop_ext},{prop_fire}))")
S.add(f"IFCRELDEFINESBYPROPERTIES({S.gid()},$,$,$,({','.join(walls_all[:4])}),{pset})")
S.add(f"IFCRELASSOCIATESMATERIAL({S.gid()},$,$,$,({','.join(walls_all)}),{brick})")
for sto, items in contained.items():
    S.add(f"IFCRELCONTAINEDINSPATIALSTRUCTURE({S.gid()},$,$,$,({','.join(items)}),{sto})")

text = (
    "ISO-10303-21;\nHEADER;\n"
    "FILE_DESCRIPTION(('ViewDefinition [CoordinationView]'),'2;1');\n"
    "FILE_NAME('house.ifc','2000-01-01T00:00:00',('exav'),('exav'),'exav make-ifc.py','exav make-ifc.py','');\n"
    "FILE_SCHEMA(('IFC4'));\nENDSEC;\nDATA;\n" + "\n".join(S.lines) + "\nENDSEC;\nEND-ISO-10303-21;\n"
)
with open(os.path.join(OUT, "house.ifc"), "w", newline="\n") as fh:
    fh.write(text)
