#!/usr/bin/env python3
"""The exav-render drawing model's JSON dump of a DXF file, as ezdxf reads it.

    python3 ezdxf_dump.py drawing.dxf > ezdxf.json

The oracle for exav-render's DXF reader (tests/cad_oracle.rs): the same
schema as `exav_render::cad::to_json`, filled from ezdxf's own parse. Values come from ezdxf's
attributes and their defaults; the model's conventions are applied on top:
angles in radians, `\\U+XXXX` and `\\M+nXXXX` escapes decoded in every
string, handles as upper-case hexadecimal.

Needs ezdxf (tested with 1.4.1).
"""

import json
import math
import re
import sys

import ezdxf
from ezdxf.lldxf.const import DXFValueError

UNICODE = re.compile(r"\\[Uu]\+([0-9A-Fa-f]{4})")
MIF = re.compile(r"\\[Mm]\+([1235])([0-9A-Fa-f]{4})")
MIF_CODEC = {"1": "cp932", "2": "cp950", "3": "cp949", "5": "cp936"}


def unescape(s):
    if s is None:
        return ""
    s = str(s)

    def uni(m):
        v = int(m.group(1), 16)
        if 0xD800 <= v <= 0xDFFF:
            return m.group(0)
        return chr(v)

    def pair(m):
        hi, lo = int(m.group(1), 16), int(m.group(2), 16)
        return chr(0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00))

    s = re.sub(
        r"\\[Uu]\+(D[89ABab][0-9A-Fa-f]{2})\\[Uu]\+(D[C-Fc-f][0-9A-Fa-f]{2})", pair, s
    )
    s = UNICODE.sub(uni, s)

    def mif(m):
        raw = bytes.fromhex(m.group(2))
        if raw[0] == 0:
            raw = raw[1:]
        try:
            out = raw.decode(MIF_CODEC[m.group(1)])
        except (UnicodeDecodeError, LookupError):
            return m.group(0)
        return out if len(out) == 1 else m.group(0)

    return MIF.sub(mif, s)


def num(v):
    v = float(v)
    return v if math.isfinite(v) else None


def rad(deg):
    return num(math.radians(float(deg)))


def v3(p):
    if p is None:
        return None
    p = tuple(p)
    if len(p) == 2:
        p = (p[0], p[1], 0.0)
    return [num(p[0]), num(p[1]), num(p[2])]


def v2(p):
    if p is None:
        return None
    p = tuple(p)
    return [num(p[0]), num(p[1])]


def h(handle):
    if handle in (None, "", 0):
        return "0"
    try:
        return format(int(str(handle), 16), "X")
    except ValueError:
        return "0"


def get(e, name, fallback=None):
    """An attribute as ezdxf has it, its ezdxf default when unset, else
    `fallback`."""
    try:
        v = e.dxf.get(name)
    except (DXFValueError, AttributeError):
        v = None
    if v is None:
        try:
            v = e.dxf.get_default(name)
        except (DXFValueError, AttributeError):
            v = None
    return fallback if v is None else v


def aci_color(v):
    v = abs(int(v))
    if v == 0:
        return "byblock"
    if 1 <= v <= 255:
        return v
    return "bylayer"


def rgb(v):
    v = int(v)
    return "#%02x%02x%02x" % ((v >> 16) & 255, (v >> 8) & 255, v & 255)


def raw_color(v):
    v = int(v)
    kind = (v >> 24) & 0xFF
    if kind == 0xC1:
        return "byblock"
    if kind == 0xC2:
        return rgb(v & 0xFFFFFF)
    if kind == 0xC3:
        return aci_color(v & 0xFF)
    return "bylayer"


def lineweight(v):
    v = int(v)
    return {-1: "bylayer", -2: "byblock", -3: "default"}.get(
        v, v if 0 <= v <= 211 else "default"
    )


def transparency(e):
    if not e.dxf.hasattr("transparency"):
        return "bylayer"
    v = int(e.dxf.transparency)
    if v & 0x02000000:
        return v & 0xFF
    if v & 0x01000000:
        return "byblock"
    return "bylayer"


def entity_color(e):
    if e.dxf.hasattr("true_color"):
        return rgb(e.dxf.true_color)
    if e.dxf.hasattr("color"):
        return aci_color(e.dxf.color)
    return "bylayer"


VERSION = {
    "AC1009": "R12",
    "AC1012": "R13",
    "AC1014": "R14",
    "AC1015": "R2000",
    "AC1018": "R2004",
    "AC1021": "R2007",
    "AC1024": "R2010",
    "AC1027": "R2013",
    "AC1032": "R2018",
}


def header(doc):
    hd = doc.header

    def hv(name, default):
        try:
            v = hd.get(name, None)
        except Exception:
            v = None
        return default if v is None else v

    acadver = doc.loaded_dxfversion or ""
    return {
        "version": VERSION.get(acadver, "R2018" if acadver > "AC1032" else "R12"),
        "acadver": acadver,
        "code_page": str(hv("$DWGCODEPAGE", "")),
        "handle_seed": h(hv("$HANDSEED", "0")),
        "insbase": v3(hv("$INSBASE", (0, 0, 0))),
        "extmin": v3(hv("$EXTMIN", (0, 0, 0))),
        "extmax": v3(hv("$EXTMAX", (0, 0, 0))),
        "limmin": v2(hv("$LIMMIN", (0, 0))),
        "limmax": v2(hv("$LIMMAX", (12, 9))),
        "pinsbase": v3(hv("$PINSBASE", (0, 0, 0))),
        "pextmin": v3(hv("$PEXTMIN", (0, 0, 0))),
        "pextmax": v3(hv("$PEXTMAX", (0, 0, 0))),
        "plimmin": v2(hv("$PLIMMIN", (0, 0))),
        "plimmax": v2(hv("$PLIMMAX", (12, 9))),
        "ltscale": num(hv("$LTSCALE", 1.0)),
        "celtscale": num(hv("$CELTSCALE", 1.0)),
        "psltscale": bool(hv("$PSLTSCALE", 1)),
        "insunits": int(hv("$INSUNITS", 0)),
        "measurement": int(hv("$MEASUREMENT", 0)),
        "lunits": int(hv("$LUNITS", 2)),
        "luprec": int(hv("$LUPREC", 4)),
        "textsize": num(hv("$TEXTSIZE", 0.2)),
        "textstyle": unescape(hv("$TEXTSTYLE", "STANDARD")),
        "clayer": unescape(hv("$CLAYER", "0")),
        "dimstyle": unescape(hv("$DIMSTYLE", "STANDARD")),
        "dimscale": num(hv("$DIMSCALE", 1.0)),
        "dimasz": num(hv("$DIMASZ", 0.18)),
        "dimtxt": num(hv("$DIMTXT", 0.18)),
        "dimgap": num(hv("$DIMGAP", 0.09)),
        "pdmode": int(hv("$PDMODE", 0)),
        "pdsize": num(hv("$PDSIZE", 0.0)),
        "angbase": rad(hv("$ANGBASE", 0.0)),
        "angdir": int(hv("$ANGDIR", 0)),
        "tilemode": bool(hv("$TILEMODE", 1)),
        "lwdisplay": bool(hv("$LWDISPLAY", 0)),
        "fillmode": bool(hv("$FILLMODE", 1)),
        "mirrtext": bool(hv("$MIRRTEXT", 0)),
    }


def layer(l):
    color = int(get(l, "color", 7))
    alpha = 255
    try:
        for code, value in l.get_xdata("AcCmTransparency"):
            if code == 1071 and int(value) & 0x02000000:
                alpha = int(value) & 0xFF
    except DXFValueError:
        pass
    return {
        "handle": h(l.dxf.handle),
        "name": unescape(l.dxf.name),
        "flags": int(get(l, "flags", 0)),
        "color": rgb(l.dxf.true_color)
        if l.dxf.hasattr("true_color")
        else aci_color(color),
        "off": color < 0,
        "linetype": unescape(get(l, "linetype", "Continuous")),
        "plot": bool(get(l, "plot", 1)),
        "lineweight": lineweight(get(l, "lineweight", -3)),
        "plot_style": h(get(l, "plotstyle_handle", None)),
        "material": h(get(l, "material_handle", None)),
        "alpha": alpha,
    }


def linetype(lt):
    elements = []
    tags = lt.pattern_tags.tags if lt.pattern_tags else []
    for t in tags:
        code, value = t.code, t.value
        if code == 49:
            elements.append(
                {
                    "length": num(value),
                    "flags": 0,
                    "shape_number": 0,
                    "style": "0",
                    "scale": 1.0,
                    "rotation": 0.0,
                    "offset": [0.0, 0.0],
                    "text": "",
                }
            )
        elif elements:
            el = elements[-1]
            if code == 74:
                el["flags"] = int(value)
            elif code == 75:
                el["shape_number"] = int(value)
            elif code == 340:
                el["style"] = h(value)
            elif code == 46:
                el["scale"] = num(value)
            elif code == 50:
                el["rotation"] = rad(value)
            elif code == 44:
                el["offset"][0] = num(value)
            elif code == 45:
                el["offset"][1] = num(value)
            elif code == 9:
                el["text"] = unescape(value)
    total = 0.0
    for t in tags:
        if t.code == 40:
            total = float(t.value)
    return {
        "handle": h(lt.dxf.handle),
        "name": unescape(lt.dxf.name),
        "flags": int(get(lt, "flags", 0)),
        "description": unescape(get(lt, "description", "")),
        "pattern_length": num(total),
        "elements": elements,
    }


def text_style(s):
    family, flags = "", 0
    try:
        for code, value in s.get_xdata("ACAD"):
            if code == 1000 and not family:
                family = unescape(value)
            elif code == 1071:
                flags = int(value)
    except DXFValueError:
        pass
    return {
        "handle": h(s.dxf.handle),
        "name": unescape(s.dxf.name),
        "flags": int(get(s, "flags", 0)),
        "height": num(get(s, "height", 0.0)),
        "width_factor": num(get(s, "width", 1.0)),
        "oblique": rad(get(s, "oblique", 0.0)),
        "generation": int(get(s, "generation_flags", 0)),
        "last_height": num(get(s, "last_height", 0.0)),
        "font_file": unescape(get(s, "font", "")),
        "bigfont_file": unescape(get(s, "bigfont", "")),
        "font_family": family,
        "font_flags": flags,
    }


def dim_style(d, r13, doc):
    # ezdxf turns the handles into names on load and drops the handles.
    def hh(name):
        if not r13 or not d.dxf.hasattr(name):
            return "0"
        value = d.dxf.get(name)
        if not value:
            return "0"
        if name == "dimtxsty":
            return h(doc.styles.get(value).dxf.handle) if doc.styles.has_entry(value) else "0"
        block = doc.blocks.get(value)
        return h(block.block_record_handle) if block is not None else "0"

    return {
        "handle": h(d.dxf.handle),
        "name": unescape(d.dxf.name),
        "flags": int(get(d, "flags", 0)),
        "dimscale": num(get(d, "dimscale", 1.0)),
        "dimasz": num(get(d, "dimasz", 0.18)),
        "dimexo": num(get(d, "dimexo", 0.0625)),
        "dimexe": num(get(d, "dimexe", 0.18)),
        "dimdle": num(get(d, "dimdle", 0.0)),
        "dimtsz": num(get(d, "dimtsz", 0.0)),
        "dimtxt": num(get(d, "dimtxt", 0.18)),
        "dimgap": num(get(d, "dimgap", 0.09)),
        "dimclrd": aci_color(get(d, "dimclrd", 0)),
        "dimclre": aci_color(get(d, "dimclre", 0)),
        "dimclrt": aci_color(get(d, "dimclrt", 0)),
        "dimlwd": lineweight(get(d, "dimlwd", -2)),
        "dimlwe": lineweight(get(d, "dimlwe", -2)),
        "dimtxsty": hh("dimtxsty"),
        "dimldrblk": hh("dimldrblk"),
        "dimblk": hh("dimblk"),
        "dimblk1": hh("dimblk1"),
        "dimblk2": hh("dimblk2"),
    }


def vport(v):
    return {
        "handle": h(v.dxf.handle),
        "name": unescape(v.dxf.name),
        "flags": int(get(v, "flags", 0)),
        "lower_left": v2(get(v, "lower_left", (0, 0))),
        "upper_right": v2(get(v, "upper_right", (1, 1))),
        "center": v2(get(v, "center", (0, 0))),
        "view_direction": v3(get(v, "direction", (0, 0, 1))),
        "target": v3(get(v, "target", (0, 0, 0))),
        "height": num(get(v, "height", 1.0)),
        "aspect_ratio": num(get(v, "aspect_ratio", 1.0)),
        "twist": rad(get(v, "view_twist", 0.0)),
    }


def plane(e, out):
    out["thickness"] = num(get(e, "thickness", 0.0))
    out["extrusion"] = v3(get(e, "extrusion", (0, 0, 1)))


HALIGN = ["left", "center", "right", "aligned", "middle", "fit"]
VALIGN = ["baseline", "bottom", "middle", "top"]


def text_fields(e):
    out = {
        "insertion": v3(get(e, "insert", (0, 0, 0))),
        "alignment_point": v3(e.dxf.align_point)
        if e.dxf.hasattr("align_point")
        else None,
        "height": num(get(e, "height", 1.0)),
        "value": unescape(get(e, "text", "")),
        "rotation": rad(get(e, "rotation", 0.0)),
        "width_factor": num(get(e, "width", 1.0)),
        "oblique": rad(get(e, "oblique", 0.0)),
        "style": unescape(get(e, "style", "STANDARD")),
        "generation": int(get(e, "text_generation_flag", 0)),
    }
    ha, va = int(get(e, "halign", 0)), int(get(e, "valign", 0))
    out["h_align"] = HALIGN[ha] if 0 <= ha < 6 else "left"
    out["v_align"] = VALIGN[va] if 0 <= va < 4 else "baseline"
    plane(e, out)
    return out


def mtext_fields(m):
    if m.dxf.hasattr("bg_fill_true_color"):
        bg = rgb(m.dxf.bg_fill_true_color)
    elif m.dxf.hasattr("bg_fill_color"):
        bg = aci_color(m.dxf.bg_fill_color)
    else:
        bg = "bylayer"
    return {
        "insertion": v3(get(m, "insert", (0, 0, 0))),
        "height": num(get(m, "char_height", 1.0)),
        "reference_width": num(get(m, "width", 0.0)),
        "defined_height": num(get(m, "defined_height", 0.0)),
        "attachment": int(get(m, "attachment_point", 1)),
        "drawing_direction": int(get(m, "flow_direction", 1)),
        "style": unescape(get(m, "style", "STANDARD")),
        "extrusion": v3(get(m, "extrusion", (0, 0, 1))),
        "x_direction": v3(m.dxf.text_direction)
        if m.dxf.hasattr("text_direction")
        else None,
        "rotation": rad(get(m, "rotation", 0.0)),
        "line_spacing_style": int(get(m, "line_spacing_style", 1)),
        "line_spacing_factor": num(get(m, "line_spacing_factor", 1.0)),
        "text": unescape(m.text),
        "background_fill": int(get(m, "bg_fill", 0)),
        "background_color": bg,
        "background_scale": num(get(m, "box_fill_scale", 1.5)),
        "columns": columns(m),
    }


def columns(m):
    """ezdxf's reading of an MTEXT's columns (its extended data before 2018,
    the embedded object from 2018)."""
    c = getattr(m, "columns", None)
    if c is None or int(c.column_type) == 0:
        return None
    return {
        "kind": int(c.column_type),
        "count": int(c.count),
        "flow_reversed": bool(c.reversed_column_flow),
        "auto_height": bool(c.auto_height),
        "width": num(c.width),
        "gutter": num(c.gutter_width),
        "heights": [num(h) for h in c.heights],
    }


def attribute_fields(a, attdef):
    out = {
        "text": text_fields(a),
        "tag": unescape(get(a, "tag", "")),
        "prompt": unescape(get(a, "prompt", "")) if attdef else "",
        "flags": int(get(a, "flags", 0)),
        "field_length": int(get(a, "field_length", 0)),
        "lock_position": bool(get(a, "lock_position", 0)),
        "mtext": None,
    }
    if a.has_embedded_mtext_entity:
        out["mtext"] = mtext_fields(a.virtual_mtext_entity())
    return out


def spline_fields(s):
    weights = [num(w) for w in s.weights]
    st =s.dxf.start_tangent if s.dxf.hasattr("start_tangent") else None
    et = s.dxf.end_tangent if s.dxf.hasattr("end_tangent") else None
    return {
        "extrusion": v3(get(s, "extrusion", (0, 0, 1))),
        "flags": int(get(s, "flags", 0)),
        "degree": int(get(s, "degree", 3)),
        "knots": [num(k) for k in s.knots],
        "control_points": [v3(p) for p in s.control_points],
        "weights": weights,
        "fit_points": [v3(p) for p in s.fit_points],
        "start_tangent": v3(st),
        "end_tangent": v3(et),
        "knot_tolerance": num(get(s, "knot_tolerance", 1e-7)),
        "control_point_tolerance": num(get(s, "control_point_tolerance", 1e-7)),
        "fit_tolerance": num(get(s, "fit_tolerance", 1e-10)),
    }


DIMKIND = [
    "linear",
    "aligned",
    "angular",
    "diameter",
    "radius",
    "angular_3_point",
    "ordinate",
    "linear",
]


def edge_json(edge):
    t = edge.type.name.lower() if hasattr(edge.type, "name") else str(edge.type)
    if t == "line":
        return {"type": "line", "start": v2(edge.start), "end": v2(edge.end)}
    if t == "arc":
        return {
            "type": "arc",
            "center": v2(edge.center),
            "radius": num(edge.radius),
            "start_angle": rad(edge.start_angle),
            "end_angle": rad(edge.end_angle),
            "counter_clockwise": bool(edge.ccw),
        }
    if t == "ellipse":
        return {
            "type": "ellipse",
            "center": v2(edge.center),
            "major_axis": v2(edge.major_axis),
            "ratio": num(edge.ratio),
            "start_angle": rad(edge.start_angle),
            "end_angle": rad(edge.end_angle),
            "counter_clockwise": bool(edge.ccw),
        }
    weights = [num(w) for w in edge.weights]
    if not edge.rational and all(w == 1.0 for w in weights):
        weights = []
    return {
        "type": "spline",
        "degree": int(edge.degree),
        "rational": bool(edge.rational),
        "periodic": bool(edge.periodic),
        "knots": [num(k) for k in edge.knot_values],
        "control_points": [v2(p) for p in edge.control_points],
        "weights": weights,
        "fit_points": [v2(p) for p in edge.fit_points],
        "start_tangent": v2(edge.start_tangent) if edge.start_tangent is not None else None,
        "end_tangent": v2(edge.end_tangent) if edge.end_tangent is not None else None,
    }


def hatch_fields(e):
    paths = []
    for p in e.paths:
        kind = type(p).__name__
        item = {"flags": int(p.path_type_flags)}
        if kind == "PolylinePath":
            item["type"] = "polyline"
            item["closed"] = bool(p.is_closed)
            item["vertices"] = [[num(x), num(y), num(b)] for x, y, b in p.vertices]
        else:
            item["type"] = "edges"
            item["edges"] = [edge_json(edge) for edge in p.edges]
        item["sources"] = [h(s) for s in p.source_boundary_objects]
        paths.append(item)
    lines = []
    if e.pattern:
        for l in e.pattern.lines:
            lines.append(
                {
                    "angle": rad(l.angle),
                    "base": v2(l.base_point),
                    "offset": v2(l.offset),
                    "dashes": [num(d) for d in l.dash_length_items],
                }
            )
    gradient = None
    g = e.gradient
    if g is not None:
        colors = []
        for i in range(min(int(g.number_of_colors), 2)):
            c = g.color1 if i == 0 else g.color2
            colors.append([float(i), "#%02x%02x%02x" % tuple(c)])
        gradient = {
            "kind": int(g.kind),
            "name": unescape(g.name),
            "angle": rad(g.rotation),
            "shift": num(g.centered),
            "single_color": bool(g.one_color),
            "tint": num(g.tint),
            "colors": colors,
        }
    return {
        "elevation": num(get(e, "elevation", (0, 0, 0))[2]),
        "extrusion": v3(get(e, "extrusion", (0, 0, 1))),
        "pattern_name": unescape(get(e, "pattern_name", "")),
        "solid": bool(get(e, "solid_fill", 0)),
        "associative": bool(get(e, "associative", 0)),
        "paths": paths,
        "style": int(get(e, "hatch_style", 0)),
        "pattern_type": int(get(e, "pattern_type", 1)),
        "pattern_angle": rad(get(e, "pattern_angle", 0.0)),
        "pattern_scale": num(get(e, "pattern_scale", 1.0)),
        "pattern_double": bool(get(e, "pattern_double", 0)),
        "pattern_lines": lines,
        "pixel_size": num(get(e, "pixel_size", 0.0)),
        "seeds": [v2(s) for s in e.seeds],
        "gradient": gradient,
    }


def multileader_fields(e):
    c = e.context
    m = c.mtext
    b = c.block
    ctx = {
        "scale": num(c.scale),
        "content_base": v3(c.base_point),
        "text_height": num(c.char_height),
        "arrowhead_size": num(c.arrow_head_size),
        "landing_gap": num(c.landing_gap_size),
        "has_text": m is not None,
        "text": unescape(m.default_content) if m else "",
        "text_normal": v3(m.extrusion) if m else [0.0, 0.0, 1.0],
        "text_style": h(m.style_handle) if m else "0",
        "text_location": v3(m.insert) if m else [0.0, 0.0, 0.0],
        "text_direction": v3(m.text_direction) if m else [1.0, 0.0, 0.0],
        "text_rotation": num(m.rotation) if m else 0.0,
        "text_width": num(m.width) if m else 0.0,
        "text_boundary_height": num(m.defined_height) if m else 0.0,
        "line_spacing_factor": num(m.line_spacing_factor) if m else 1.0,
        "line_spacing_style": int(m.line_spacing_style) if m else 1,
        "text_color": raw_color(m.color) if m else "byblock",
        "text_attachment": int(m.alignment) if m else 1,
        "text_flow_direction": int(m.flow_direction) if m else 1,
        "has_block": b is not None,
        "block": h(b.block_record_handle) if b else "0",
        "block_normal": v3(b.extrusion) if b else [0.0, 0.0, 1.0],
        "block_position": v3(b.insert) if b else [0.0, 0.0, 0.0],
        "block_scale": v3(b.scale) if b else [1.0, 1.0, 1.0],
        "block_rotation": num(b.rotation) if b else 0.0,
        "block_color": raw_color(b.color) if b else "byblock",
        "block_transform": [num(x) for x in b._matrix] if b else [],
        "plane_origin": v3(c.plane_origin),
        "plane_x_axis": v3(c.plane_x_axis),
        "plane_y_axis": v3(c.plane_y_axis),
        "plane_normal_reversed": bool(c.plane_normal_reversed),
        "leaders": [],
    }
    for leader in c.leaders:
        ctx["leaders"].append(
            {
                "connection_point": v3(leader.last_leader_point),
                "direction": v3(leader.dogleg_vector),
                "has_connection_point": bool(leader.has_last_leader_line),
                "has_direction": bool(leader.has_dogleg_vector),
                "branch_index": int(leader.index),
                "dogleg_length": num(leader.dogleg_length),
                "lines": [
                    {"vertices": [v3(p) for p in line.vertices], "index": int(line.index)}
                    for line in leader.lines
                ],
                "attachment_direction": int(leader.attachment_direction),
            }
        )
    return {
        "style": h(get(e, "style_handle", None)),
        "property_overrides": int(get(e, "property_override_flags", 0)),
        "leader_line_type": int(get(e, "leader_type", 1)),
        "leader_line_color": raw_color(get(e, "leader_line_color", 0xC1000000)),
        "leader_linetype": h(get(e, "leader_linetype_handle", None)),
        "leader_lineweight": lineweight(get(e, "leader_lineweight", -2)),
        "landing": bool(get(e, "has_landing", 1)),
        "dogleg": bool(get(e, "has_dogleg", 1)),
        "dogleg_length": num(get(e, "dogleg_length", 0.0)),
        "arrowhead": h(get(e, "arrow_head_handle", None)),
        "arrowhead_size": num(get(e, "arrow_head_size", 0.0)),
        "content_type": int(get(e, "content_type", 2)),
        "text_style": h(get(e, "text_style_handle", None)),
        "text_left_attachment": int(get(e, "text_left_attachment_type", 1)),
        "text_right_attachment": int(get(e, "text_right_attachment_type", 1)),
        "text_angle_type": int(get(e, "text_angle_type", 1)),
        "text_alignment_type": int(get(e, "text_alignment_type", 0)),
        "text_color": raw_color(get(e, "text_color", 0xC1000000)),
        "text_frame": bool(get(e, "has_text_frame", 0)),
        "block": h(get(e, "block_record_handle", None)),
        "block_color": raw_color(get(e, "block_color", 0xC1000000)),
        "block_scale": v3(get(e, "block_scale_vector", (1, 1, 1))),
        "block_rotation": num(get(e, "block_rotation", 0.0)),
        "block_connection": int(get(e, "block_connection_type", 0)),
        "block_attributes": [
            {
                "definition": h(a.handle),
                "index": int(a.index),
                "width": num(a.width),
                "text": unescape(a.text),
            }
            for a in e.block_attribs
        ],
        "text_attachment_point": int(get(e, "text_attachment_point", 1)),
        "context": ctx,
    }


def raw_subclass(e, index):
    """Groups of an entity ezdxf keeps only as tags."""
    tags = getattr(e, "acdb_ole2frame", None)
    return list(tags) if tags else []


def image_fields(e):
    return {
        "class_version": int(get(e, "class_version", 0)),
        "insertion": v3(get(e, "insert", (0, 0, 0))),
        "u_vector": v3(get(e, "u_pixel", (1, 0, 0))),
        "v_vector": v3(get(e, "v_pixel", (0, 1, 0))),
        "size": v2(get(e, "image_size", (0, 0))),
        "image_def": h(get(e, "image_def_handle", None)),
        "display": int(get(e, "flags", 0)),
        "clipping": bool(get(e, "clipping", 0)),
        "brightness": int(get(e, "brightness", 50)),
        "contrast": int(get(e, "contrast", 50)),
        "fade": int(get(e, "fade", 0)),
        "reactor": h(get(e, "image_def_reactor_handle", None)),
        "clip_type": int(get(e, "clipping_boundary_type", 1)),
        "clip_vertices": [v2(p) for p in e.boundary_path],
        "clip_inside": bool(get(e, "clip_mode", 0)),
    }


def kind_fields(e, doc):
    t = TYPE_NAMES.get(e.dxftype(), e.dxftype())
    out = {}
    if t == "LINE":
        out = {"start": v3(get(e, "start")), "end": v3(get(e, "end"))}
        plane(e, out)
    elif t == "POINT":
        out = {"location": v3(get(e, "location")), "x_axis_angle": rad(get(e, "angle", 0.0))}
        plane(e, out)
    elif t == "CIRCLE":
        out = {"center": v3(get(e, "center")), "radius": num(get(e, "radius", 0.0))}
        plane(e, out)
    elif t == "ARC":
        out = {
            "center": v3(get(e, "center")),
            "radius": num(get(e, "radius", 0.0)),
            "start_angle": rad(get(e, "start_angle", 0.0)),
            "end_angle": rad(get(e, "end_angle", 0.0)),
        }
        plane(e, out)
    elif t == "ELLIPSE":
        out = {
            "center": v3(get(e, "center")),
            "major_axis": v3(get(e, "major_axis", (1, 0, 0))),
            "extrusion": v3(get(e, "extrusion", (0, 0, 1))),
            "ratio": num(get(e, "ratio", 1.0)),
            "start_param": num(get(e, "start_param", 0.0)),
            "end_param": num(get(e, "end_param", math.tau)),
        }
    elif t == "SPLINE":
        out = spline_fields(e)
    elif t == "LWPOLYLINE":
        out = {
            "flags": int(get(e, "flags", 0)),
            "constant_width": num(get(e, "const_width", 0.0)),
            "elevation": num(get(e, "elevation", 0.0)),
        }
        plane(e, out)
        out["vertices"] = [[num(x) for x in p] for p in e.get_points("xyseb")]
    elif t == "POLYLINE":
        out = {
            "flags": int(get(e, "flags", 0)),
            "elevation": num(get(e, "elevation", (0, 0, 0))[2]),
            "default_start_width": num(get(e, "default_start_width", 0.0)),
            "default_end_width": num(get(e, "default_end_width", 0.0)),
            "m_count": int(get(e, "m_count", 0)),
            "n_count": int(get(e, "n_count", 0)),
            "m_density": int(get(e, "m_smooth_density", 0)),
            "n_density": int(get(e, "n_smooth_density", 0)),
            "curve_type": int(get(e, "smooth_type", 0)),
        }
        plane(e, out)
        out["vertices"] = [
            {
                "handle": h(v.dxf.handle),
                "location": v3(get(v, "location")),
                "start_width": num(get(v, "start_width", 0.0)),
                "end_width": num(get(v, "end_width", 0.0)),
                "bulge": num(get(v, "bulge", 0.0)),
                "flags": int(get(v, "flags", 0)),
                "tangent": rad(get(v, "tangent", 0.0)),
                "indices": [int(get(v, n, 0)) for n in ("vtx0", "vtx1", "vtx2", "vtx3")],
            }
            for v in e.vertices
        ]
    elif t in ("SOLID", "TRACE", "3DFACE"):
        corners = [get(e, "vtx%d" % i, None) for i in range(4)]
        if not e.dxf.hasattr("vtx3"):
            corners[3] = corners[2]
        out = {"corners": [v3(c if c is not None else (0, 0, 0)) for c in corners]}
        if t == "3DFACE":
            out["invisible_edges"] = int(get(e, "invisible_edges", 0))
        else:
            plane(e, out)
    elif t == "TEXT":
        out = text_fields(e)
    elif t in ("ATTRIB", "ATTDEF"):
        out = attribute_fields(e, t == "ATTDEF")
    elif t == "INSERT":
        out = {
            "block_name": unescape(get(e, "name", "")),
            "insertion": v3(get(e, "insert", (0, 0, 0))),
            "scale": [
                num(get(e, "xscale", 1.0)),
                num(get(e, "yscale", 1.0)),
                num(get(e, "zscale", 1.0)),
            ],
            "rotation": rad(get(e, "rotation", 0.0)),
            "columns": max(0, min(65535, int(get(e, "column_count", 1)))),
            "rows": max(0, min(65535, int(get(e, "row_count", 1)))),
            "column_spacing": num(get(e, "column_spacing", 0.0)),
            "row_spacing": num(get(e, "row_spacing", 0.0)),
            "extrusion": v3(get(e, "extrusion", (0, 0, 1))),
            "attributes": [entity_json(a, doc) for a in e.attribs],
        }
    elif t == "MTEXT":
        out = mtext_fields(e)
    elif t == "DIMENSION":
        dimtype = int(get(e, "dimtype", 0))
        out = {
            "kind": DIMKIND[dimtype & 7],
            "flags": dimtype,
            "block_name": unescape(get(e, "geometry", "")),
            "style": unescape(get(e, "dimstyle", "STANDARD")),
            "definition_point": v3(get(e, "defpoint", (0, 0, 0))),
            "text_midpoint": v3(get(e, "text_midpoint", (0, 0, 0))),
            "insertion_point": v3(get(e, "insert", (0, 0, 0))),
            "point13": v3(get(e, "defpoint2", (0, 0, 0))),
            "point14": v3(get(e, "defpoint3", (0, 0, 0))),
            "point15": v3(get(e, "defpoint4", (0, 0, 0))),
            "point16": v3(get(e, "defpoint5", (0, 0, 0))),
            "attachment": int(get(e, "attachment_point", 5)),
            "line_spacing_style": int(get(e, "line_spacing_style", 1)),
            "line_spacing_factor": num(get(e, "line_spacing_factor", 1.0)),
            "measurement": num(get(e, "actual_measurement", 0.0)),
            "text": unescape(get(e, "text", "")),
            "text_rotation": rad(get(e, "text_rotation", 0.0)),
            "horizontal_direction": rad(get(e, "horizontal_direction", 0.0)),
            "angle": rad(get(e, "angle", 0.0)),
            "oblique": rad(get(e, "oblique_angle", 0.0)),
            "leader_length": num(get(e, "leader_length", 0.0)),
            "extrusion": v3(get(e, "extrusion", (0, 0, 1))),
            "insertion_scale": [1.0, 1.0, 1.0],
            "insertion_rotation": 0.0,
        }
    elif t == "LEADER":
        out = {
            "style": unescape(get(e, "dimstyle", "STANDARD")),
            "arrowhead": bool(get(e, "has_arrowhead", 1)),
            "path_type": int(get(e, "path_type", 0)),
            "creation": int(get(e, "annotation_type", 3)),
            "hookline_direction": int(get(e, "hookline_direction", 0)),
            "hookline": bool(get(e, "has_hookline", 0)),
            "text_height": num(get(e, "text_height", 0.0)),
            "text_width": num(get(e, "text_width", 0.0)),
            "vertices": [v3(p) for p in e.vertices],
            "leader_color": aci_color(e.dxf.block_color) if e.dxf.hasattr("block_color") else "bylayer",
            "annotation": h(get(e, "annotation_handle", None)),
            "extrusion": v3(get(e, "normal_vector", (0, 0, 1))),
            "horizontal_direction": v3(get(e, "horizontal_direction", (1, 0, 0))),
            "block_offset": v3(get(e, "leader_offset_block_ref", (0, 0, 0))),
            "annotation_offset": v3(get(e, "leader_offset_annotation_placement", (0, 0, 0))),
        }
    elif t == "MULTILEADER":
        out = multileader_fields(e)
    elif t == "MLINE":
        out = {
            "style_name": unescape(get(e, "style_name", "")),
            "style": h(get(e, "style_handle", None)),
            "scale": num(get(e, "scale_factor", 1.0)),
            "justification": int(get(e, "justification", 0)),
            "flags": int(get(e, "flags", 0)),
            "style_element_count": int(get(e, "style_element_count", 0)),
            "start": v3(get(e, "start_location", (0, 0, 0))),
            "extrusion": v3(get(e, "extrusion", (0, 0, 1))),
            "vertices": [
                {
                    "position": v3(v.location),
                    "direction": v3(v.line_direction),
                    "miter": v3(v.miter_direction),
                    "elements": [
                        {
                            "parameters": [num(x) for x in lp],
                            "fill_parameters": [num(x) for x in fp],
                        }
                        for lp, fp in zip(v.line_params, v.fill_params)
                    ],
                }
                for v in e.vertices
            ],
        }
    elif t == "HATCH":
        out = hatch_fields(e)
    elif t == "HELIX":
        out = {
            "spline": spline_fields(e),
            "axis_base": v3(get(e, "axis_base_point", (0, 0, 0))),
            "start_point": v3(get(e, "start_point", (1, 0, 0))),
            "axis_vector": v3(get(e, "axis_vector", (0, 0, 1))),
            "radius": num(get(e, "radius", 1.0)),
            "turns": num(get(e, "turns", 1.0)),
            "turn_height": num(get(e, "turn_height", 1.0)),
            "right_handed": bool(get(e, "handedness", 1)),
            "constraint": int(get(e, "constrain", 0)),
        }
    elif t in ("RAY", "XLINE"):
        out = {"base": v3(get(e, "start")), "direction": v3(get(e, "unit_vector"))}
    elif t == "VIEWPORT":
        frozen = []
        for name in e.frozen_layers:
            layer = doc.layers.get(name) if doc.layers.has_entry(name) else None
            if layer is not None:
                frozen.append(h(layer.dxf.handle))
        out = {
            "center": v3(get(e, "center", (0, 0, 0))),
            "width": num(get(e, "width", 1.0)),
            "height": num(get(e, "height", 1.0)),
            "status": int(get(e, "status", 0)),
            "id": int(get(e, "id", 0)),
            "view_center": v2(get(e, "view_center_point", (0, 0))),
            "snap_base": v2(get(e, "snap_base_point", (0, 0))),
            "snap_spacing": v2(get(e, "snap_spacing", (10, 10))),
            "grid_spacing": v2(get(e, "grid_spacing", (10, 10))),
            "view_direction": v3(get(e, "view_direction_vector", (0, 0, 1))),
            "view_target": v3(get(e, "view_target_point", (0, 0, 0))),
            "lens_length": num(get(e, "perspective_lens_length", 50.0)),
            "front_clip": num(get(e, "front_clip_plane_z_value", 0.0)),
            "back_clip": num(get(e, "back_clip_plane_z_value", 0.0)),
            "view_height": num(get(e, "view_height", 1.0)),
            "snap_angle": rad(get(e, "snap_angle", 0.0)),
            "twist": rad(get(e, "view_twist_angle", 0.0)),
            "circle_zoom": int(get(e, "circle_zoom", 100)),
            "frozen_layers": frozen,
            "flags": int(get(e, "flags", 0)),
            "clip_boundary": h(get(e, "clipping_boundary_handle", None)),
            "plot_style_sheet": unescape(get(e, "plot_style_name", "")),
            "render_mode": int(get(e, "render_mode", 0)),
            "elevation": num(get(e, "elevation", 0.0)),
            "shade_plot_mode": int(get(e, "shade_plot_mode", 0)),
        }
    elif t in ("IMAGE", "WIPEOUT"):
        out = image_fields(e)
    elif t in ("PDFUNDERLAY", "DWFUNDERLAY", "DGNUNDERLAY"):
        out = {
            "kind": t[:3].lower(),
            "definition": h(get(e, "underlay_def_handle", None)),
            "insertion": v3(get(e, "insert", (0, 0, 0))),
            "scale": [
                num(get(e, "scale_x", 1.0)),
                num(get(e, "scale_y", 1.0)),
                num(get(e, "scale_z", 1.0)),
            ],
            "rotation": rad(get(e, "rotation", 0.0)),
            "extrusion": v3(get(e, "extrusion", (0, 0, 1))),
            "flags": int(get(e, "flags", 2)),
            "contrast": int(get(e, "contrast", 100)),
            "fade": int(get(e, "fade", 0)),
            "clip_vertices": [v2(p) for p in e.boundary_path],
        }
    elif t == "OLE2FRAME":
        tags = raw_subclass(e, 2)
        first = {}
        for tag in tags:
            first.setdefault(tag.code, tag.value)
        out = {
            "version": int(first.get(70, 0)),
            "description": unescape(first.get(3, "")),
            "upper_left": v3(first.get(10, (0, 0, 0))),
            "lower_right": v3(first.get(11, (0, 0, 0))),
            "ole_type": int(first.get(71, 0)),
            "tile_mode": int(first.get(72, 0)),
            "data_length": int(first.get(90, 0)),
        }
    elif t == "ACAD_TABLE":
        out = {
            "block_name": unescape(get(e, "geometry", "")),
            "insertion": v3(get(e, "insert", (0, 0, 0))),
            "horizontal_direction": v3(get(e, "horizontal_direction", (1, 0, 0))),
            "style": h(get(e, "table_style_id", None)),
            "block_record": h(get(e, "block_record_handle", None)),
            "rows": int(get(e, "n_rows", 0)),
            "columns": int(get(e, "n_cols", 0)),
        }
    elif t == "SHAPE":
        out = {
            "insertion": v3(get(e, "insert", (0, 0, 0))),
            "size": num(get(e, "size", 1.0)),
            "name": unescape(get(e, "name", "")),
            "rotation": rad(get(e, "rotation", 0.0)),
            "width_factor": num(get(e, "xscale", 1.0)),
            "oblique": rad(get(e, "oblique", 0.0)),
        }
        plane(e, out)
    return out


# DXF type names the model reads under one name.
TYPE_NAMES = {
    "PDFREFERENCE": "PDFUNDERLAY",
    "DWFREFERENCE": "DWFUNDERLAY",
    "DGNREFERENCE": "DGNUNDERLAY",
    "MLEADER": "MULTILEADER",
    "ARC_DIMENSION": "DIMENSION",
    "LARGE_RADIAL_DIMENSION": "DIMENSION",
}


def entity_json(e, doc):
    t = e.dxftype()
    t = TYPE_NAMES.get(t, t)
    try:
        linetype = unescape(e.dxf.linetype) if e.dxf.hasattr("linetype") else "BYLAYER"
    except Exception:
        linetype = "BYLAYER"
    out = {
        "type": t,
        "handle": h(e.dxf.handle),
        "owner": h(e.dxf.owner),
        "layer": unescape(get(e, "layer", "0")),
        "linetype": linetype,
        "color": entity_color(e),
        "color_name": unescape(e.dxf.color_name) if e.dxf.hasattr("color_name") else "",
        "lineweight": lineweight(e.dxf.lineweight) if e.dxf.hasattr("lineweight") else "bylayer",
        "transparency": transparency(e),
        "linetype_scale": num(get(e, "ltscale", 1.0)),
        "invisible": bool(get(e, "invisible", 0)),
        "paper_space": bool(get(e, "paperspace", 0)),
    }
    try:
        out.update(kind_fields(e, doc))
    except Exception as exc:  # report, do not hide
        out["oracle_error"] = "%s: %s" % (type(exc).__name__, exc)
    return out


def block_json(b, doc):
    blk, rec = b.block, b.block_record
    name = b.name
    if name.upper() in ("$MODEL_SPACE", "*MODEL_SPACE"):
        name = "*Model_Space"
    elif name.upper() in ("$PAPER_SPACE", "*PAPER_SPACE"):
        name = "*Paper_Space"
    return {
        "name": unescape(name),
        "record": h(rec.dxf.handle),
        "handle": h(blk.dxf.handle),
        "end_handle": h(b.endblk.dxf.handle),
        "flags": int(get(blk, "flags", 0)),
        "base_point": v3(get(blk, "base_point", (0, 0, 0))),
        "xref_path": unescape(get(blk, "xref_path", "")),
        "description": unescape(get(blk, "description", "")),
        "layer": unescape(get(blk, "layer", "0")),
        "layout": h(get(rec, "layout", None)),
        "insert_units": int(get(rec, "units", 0)),
        "explodable": bool(get(rec, "explode", 1)),
        "scalable": bool(get(rec, "scale", 1)),
        "entities": [entity_json(e, doc) for e in b],
    }


def layout_json(l):
    d = l.dxf_layout
    return {
        "handle": h(d.dxf.handle),
        "name": unescape(d.dxf.name),
        "flags": int(get(d, "layout_flags", 0)),
        "tab_order": int(get(d, "taborder", 0)),
        "limits_min": v2(get(d, "limmin", (0, 0))),
        "limits_max": v2(get(d, "limmax", (12, 9))),
        "insertion_base": v3(get(d, "insert_base", (0, 0, 0))),
        "extents_min": v3(get(d, "extmin", (0, 0, 0))),
        "extents_max": v3(get(d, "extmax", (0, 0, 0))),
        "elevation": num(get(d, "elevation", 0.0)),
        "ucs_origin": v3(get(d, "ucs_origin", (0, 0, 0))),
        "ucs_x_axis": v3(get(d, "ucs_xaxis", (1, 0, 0))),
        "ucs_y_axis": v3(get(d, "ucs_yaxis", (0, 1, 0))),
        "block_record": h(get(d, "block_record_handle", None)),
        "last_viewport": h(get(d, "viewport_handle", None)),
        "plot": {
            "page_setup_name": unescape(get(d, "page_setup_name", "")),
            "plot_device": unescape(get(d, "plot_configuration_file", "")),
            "paper_size": unescape(get(d, "paper_size", "")),
            "plot_view": unescape(get(d, "plot_view_name", "")),
            "style_sheet": unescape(get(d, "current_style_sheet", "")),
            "margins": [
                num(get(d, "left_margin", 0.0)),
                num(get(d, "bottom_margin", 0.0)),
                num(get(d, "right_margin", 0.0)),
                num(get(d, "top_margin", 0.0)),
            ],
            "paper_width": num(get(d, "paper_width", 0.0)),
            "paper_height": num(get(d, "paper_height", 0.0)),
            "origin": [
                num(get(d, "plot_origin_x_offset", 0.0)),
                num(get(d, "plot_origin_y_offset", 0.0)),
            ],
            "window_min": [
                num(get(d, "plot_window_x1", 0.0)),
                num(get(d, "plot_window_y1", 0.0)),
            ],
            "window_max": [
                num(get(d, "plot_window_x2", 0.0)),
                num(get(d, "plot_window_y2", 0.0)),
            ],
            "scale_numerator": num(get(d, "scale_numerator", 1.0)),
            "scale_denominator": num(get(d, "scale_denominator", 1.0)),
            "flags": int(get(d, "plot_layout_flags", 0)),
            "paper_units": int(get(d, "plot_paper_units", 0)),
            "rotation": int(get(d, "plot_rotation", 0)),
            "plot_type": int(get(d, "plot_type", 0)),
            "standard_scale_type": int(get(d, "standard_scale_type", 0)),
            "standard_scale": num(get(d, "unit_factor", 1.0)),
            "image_origin": [
                num(get(d, "paper_image_origin_x", 0.0)),
                num(get(d, "paper_image_origin_y", 0.0)),
            ],
        },
    }


def objects_json(doc):
    out = {
        "dictionaries": [],
        "sort_tables": [],
        "image_defs": [],
        "underlay_defs": [],
        "mline_styles": [],
        "mleader_styles": [],
    }
    for o in doc.objects:
        t = o.dxftype()
        if t in ("DICTIONARY", "ACDBDICTIONARYWDFLT"):
            out["dictionaries"].append(
                {
                    "handle": h(o.dxf.handle),
                    "owner": h(o.dxf.owner),
                    "hard_owner": bool(get(o, "hard_owned", 0)),
                    "cloning": int(get(o, "cloning", 1)),
                    "entries": [
                        [unescape(k), h(v if isinstance(v, str) else v.dxf.handle)]
                        for k, v in o.items()
                    ],
                }
            )
        elif t == "SORTENTSTABLE":
            out["sort_tables"].append(
                {
                    "handle": h(o.dxf.handle),
                    "block_record": h(get(o, "block_record_handle", None)),
                    "entries": [[h(a), h(b)] for a, b in o.table.items()],
                }
            )
        elif t == "IMAGEDEF":
            out["image_defs"].append(
                {
                    "handle": h(o.dxf.handle),
                    "file_name": unescape(get(o, "filename", "")),
                    "size": v2(get(o, "image_size", (0, 0))),
                    "pixel_size": v2(get(o, "pixel_size", (0, 0))),
                    "loaded": bool(get(o, "loaded", 0)),
                    "resolution_units": int(get(o, "resolution_units", 0)),
                }
            )
        elif t in ("PDFDEFINITION", "DWFDEFINITION", "DGNDEFINITION"):
            out["underlay_defs"].append(
                {
                    "handle": h(o.dxf.handle),
                    "kind": t[:3].lower(),
                    "file_name": unescape(get(o, "filename", "")),
                    "name": unescape(get(o, "name", "")),
                }
            )
        elif t == "MLINESTYLE":
            fill = (
                rgb(o.dxf.fill_true_color)
                if o.dxf.hasattr("fill_true_color")
                else aci_color(get(o, "fill_color", 256))
            )
            out["mline_styles"].append(
                {
                    "handle": h(o.dxf.handle),
                    "name": unescape(get(o, "name", "")),
                    "flags": int(get(o, "flags", 0)),
                    "description": unescape(get(o, "description", "")),
                    "fill_color": fill,
                    "start_angle": rad(get(o, "start_angle", 90.0)),
                    "end_angle": rad(get(o, "end_angle", 90.0)),
                    "elements": [
                        {
                            "offset": num(el.offset),
                            "color": aci_color(el.color),
                            "linetype": unescape(el.linetype),
                        }
                        for el in o.elements
                    ],
                }
            )
        elif t == "MLEADERSTYLE":
            out["mleader_styles"].append(
                {
                    "handle": h(o.dxf.handle),
                    "name": "",
                    "content_type": int(get(o, "content_type", 2)),
                    "leader_line_type": int(get(o, "leader_type", 1)),
                    "leader_line_color": raw_color(get(o, "leader_line_color", 0xC1000000)),
                    "leader_linetype": h(get(o, "leader_linetype_handle", None)),
                    "leader_lineweight": lineweight(get(o, "leader_lineweight", -2)),
                    "landing": bool(get(o, "has_landing", 1)),
                    "landing_gap": num(get(o, "landing_gap_size", 0.09)),
                    "dogleg": bool(get(o, "has_dogleg", 1)),
                    "dogleg_length": num(get(o, "dogleg_length", 0.36)),
                    "arrowhead": h(get(o, "arrow_head_handle", None)),
                    "arrowhead_size": num(get(o, "arrow_head_size", 0.18)),
                    "text_style": h(get(o, "text_style_handle", None)),
                    "text_left_attachment": int(get(o, "text_left_attachment_type", 1)),
                    "text_right_attachment": int(get(o, "text_right_attachment_type", 1)),
                    "text_angle_type": int(get(o, "text_angle_type", 1)),
                    "text_alignment_type": int(get(o, "text_alignment_type", 0)),
                    "text_color": raw_color(get(o, "text_color", 0xC1000000)),
                    "text_height": num(get(o, "char_height", 0.18)),
                    "text_frame": bool(get(o, "has_frame_text", 0)),
                    "block": h(get(o, "block_record_handle", None)),
                    "block_color": raw_color(get(o, "block_color", 0xC1000000)),
                    "block_scale": [
                        num(get(o, "block_scale_x", 1.0)),
                        num(get(o, "block_scale_y", 1.0)),
                        num(get(o, "block_scale_z", 1.0)),
                    ],
                    "block_rotation": num(get(o, "block_rotation", 0.0)),
                    "block_connection": int(get(o, "block_connection_type", 0)),
                    "scale": num(get(o, "scale", 1.0)),
                }
            )
    # A multileader style's name is its dictionary entry's.
    names = {}
    for d in out["dictionaries"]:
        for n, hd in d["entries"]:
            names.setdefault(hd, n)
    for s in out["mleader_styles"]:
        s["name"] = names.get(s["handle"], "")
    return out


def dump(path):
    doc = ezdxf.readfile(path)
    r13 = (doc.loaded_dxfversion or "AC1009") > "AC1009"
    out = {"header": header(doc)}
    out["layers"] = [layer(l) for l in doc.layers]
    out["linetypes"] = [linetype(l) for l in doc.linetypes]
    out["text_styles"] = [text_style(s) for s in doc.styles]
    out["dim_styles"] = [dim_style(d, r13, doc) for d in doc.dimstyles]
    out["vports"] = [vport(v) for v in doc.viewports]
    out["blocks"] = [block_json(b, doc) for b in doc.blocks]
    out["layouts"] = [layout_json(l) for l in doc.layouts]
    out.update(objects_json(doc))
    out["warnings"] = []
    out["warnings_dropped"] = 0
    return out


if __name__ == "__main__":
    json.dump(dump(sys.argv[1]), sys.stdout, ensure_ascii=False)
