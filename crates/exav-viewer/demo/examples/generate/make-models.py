#!/usr/bin/env python3
"""Writes the demo's 3D model examples into ../files/models/.

    python3 -I make-models.py [OUT_DIR]

Output: CC0-1.0, a public domain dedication by the exav project. Every model
is computed here from scratch with numpy; no mesh library or outside model is
used.

Needs: Python 3 and numpy.

- gear.stl: a spur gear, binary STL with a colour per facet (VisCAM
  convention): orange teeth, blue hub, grey faces.
- bracket-ascii.stl: an L bracket as ASCII STL.
- knot.obj: a trefoil knot tube with a colour per vertex, and a base, as two
  OBJ objects.
- terrain.ply: a height field, binary little-endian PLY with vertex colours
  and normals.
- icosphere-ascii.ply: an icosphere as ASCII PLY with vertex colours.
- arm.glb: an articulated arm, a node tree with rotations and scales, five
  materials, vertex colours on one mesh, in a GLB.
- table.gltf: a table and a chair, a .gltf with its buffer as a data URI.
"""
import base64
import json
import math
import os
import struct
import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(HERE, "..", "files", "models")
os.makedirs(OUT, exist_ok=True)


def out(name):
    return os.path.join(OUT, name)


def normal(a, b, c):
    n = np.cross(b - a, c - a)
    length = np.linalg.norm(n)
    return n / length if length else n


# ---------------------------------------------------------------- the gear


def gear_facets(teeth=18, r_root=14.0, r_tip=17.0, r_bore=5.0, thick=8.0, hub_r=8.0):
    """Facets (a, b, c, colour) of a spur gear: z from 0 to thick."""
    outline = []
    step = 2 * math.pi / teeth
    for i in range(teeth):
        a0 = i * step
        for da, r in [(0.0, r_root), (0.18 * step, r_tip), (0.5 * step, r_tip), (0.68 * step, r_root)]:
            outline.append((a0 + da, r))
    n = len(outline)
    bore = [(outline[i][0], r_bore) for i in range(n)]
    hub = [(outline[i][0], hub_r) for i in range(n)]

    def p(ang_r, z):
        return np.array([ang_r[1] * math.cos(ang_r[0]), ang_r[1] * math.sin(ang_r[0]), z])

    ORANGE, BLUE, GREY = (255, 140, 30), (40, 100, 220), (170, 170, 175)
    facets = []

    def quad(a, b, c, d, colour):
        facets.append((a, b, c, colour))
        facets.append((a, c, d, colour))

    for i in range(n):
        j = (i + 1) % n
        # Top and bottom: the ring between the bore and the outline, the hub ring in blue.
        for z, flip in ((thick, False), (0.0, True)):
            ring = [(bore[i], bore[j], hub[j], hub[i], BLUE), (hub[i], hub[j], outline[j], outline[i], ORANGE if z else GREY)]
            for a, b, c, d, col in ring:
                pts = [p(a, z), p(b, z), p(c, z), p(d, z)]
                if flip:
                    pts = pts[::-1]
                quad(*pts, col)
        # The tooth walls and the bore wall.
        quad(p(outline[i], 0), p(outline[j], 0), p(outline[j], thick), p(outline[i], thick), ORANGE)
        quad(p(bore[j], 0), p(bore[i], 0), p(bore[i], thick), p(bore[j], thick), GREY)
    return facets


def stl_binary(path, facets, header):
    out_ = bytearray(header.ljust(80, b" ")[:80])
    out_ += struct.pack("<I", len(facets))
    for a, b, c, colour in facets:
        nrm = normal(a, b, c)
        attr = 0x8000 | ((colour[0] >> 3) << 10) | ((colour[1] >> 3) << 5) | (colour[2] >> 3) if colour else 0
        out_ += struct.pack("<12fH", *nrm, *a, *b, *c, attr)
    with open(path, "wb") as f:
        f.write(out_)


def box_facets(lo, hi):
    x0, y0, z0 = lo
    x1, y1, z1 = hi
    v = [np.array(c, float) for c in [(x0, y0, z0), (x1, y0, z0), (x1, y1, z0), (x0, y1, z0), (x0, y0, z1), (x1, y0, z1), (x1, y1, z1), (x0, y1, z1)]]
    quads = [(0, 3, 2, 1), (4, 5, 6, 7), (0, 1, 5, 4), (1, 2, 6, 5), (2, 3, 7, 6), (3, 0, 4, 7)]
    tris = []
    for a, b, c, d in quads:
        tris.append((v[a], v[b], v[c]))
        tris.append((v[a], v[c], v[d]))
    return tris


def stl_ascii(path, tris, name):
    lines = [f"solid {name}"]
    for a, b, c in tris:
        n = normal(a, b, c)
        lines.append(f"  facet normal {n[0]:.6e} {n[1]:.6e} {n[2]:.6e}")
        lines.append("    outer loop")
        for v in (a, b, c):
            lines.append(f"      vertex {v[0]:.6e} {v[1]:.6e} {v[2]:.6e}")
        lines.append("    endloop")
        lines.append("  endfacet")
    lines.append(f"endsolid {name}")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


stl_binary(out("gear.stl"), gear_facets(), b"exav example gear, colours as VisCAM attributes")
stl_ascii(out("bracket-ascii.stl"), box_facets((0, 0, 0), (40, 25, 4)) + box_facets((0, 0, 4), (4, 25, 30)) + box_facets((4, 0, 4), (6, 25, 12)), "bracket")

# ------------------------------------------------------------------- the knot


def hsv(h):
    h6 = (h % 1.0) * 6
    i = int(h6)
    f = h6 - i
    q, t = 1 - f, f
    r, g, b = [(1, t, 0), (q, 1, 0), (0, 1, t), (0, q, 1), (t, 0, 1), (1, 0, q)][i % 6]
    return int(r * 255), int(g * 255), int(b * 255)


def knot_obj(path, segs=90, ring=10):
    def centre(t):
        return np.array([(2 + math.cos(3 * t)) * math.cos(2 * t), (2 + math.cos(3 * t)) * math.sin(2 * t), math.sin(3 * t)])

    verts, colours, normals, faces = [], [], [], []
    for i in range(segs):
        t = 2 * math.pi * i / segs
        c = centre(t)
        tan = centre(t + 1e-3) - c
        tan /= np.linalg.norm(tan)
        up = np.array([0.0, 0.0, 1.0])
        nrm = np.cross(tan, up)
        nrm /= np.linalg.norm(nrm)
        bin_ = np.cross(tan, nrm)
        for k in range(ring):
            a = 2 * math.pi * k / ring
            d = math.cos(a) * nrm + math.sin(a) * bin_
            verts.append(c + 0.32 * d)
            normals.append(d)
            colours.append(hsv(i / segs))
    for i in range(segs):
        for k in range(ring):
            a = i * ring + k
            b = i * ring + (k + 1) % ring
            c = ((i + 1) % segs) * ring + (k + 1) % ring
            d = ((i + 1) % segs) * ring + k
            faces.append((a, b, c, d))
    lines = ["# A trefoil knot with a colour per vertex, and a base: two objects.", "o knot"]
    for v, col in zip(verts, colours):
        lines.append(f"v {v[0]:.4f} {v[1]:.4f} {v[2]:.4f} {col[0] / 255:.3f} {col[1] / 255:.3f} {col[2] / 255:.3f}")
    for n in normals:
        lines.append(f"vn {n[0]:.4f} {n[1]:.4f} {n[2]:.4f}")
    for f in faces:
        lines.append("f " + " ".join(f"{i + 1}//{i + 1}" for i in f))
    base = len(verts)
    lines.append("o base")
    ring_n = 48
    for k in range(ring_n):
        a = 2 * math.pi * k / ring_n
        lines.append(f"v {4.2 * math.cos(a):.4f} {4.2 * math.sin(a):.4f} -1.6 0.35 0.35 0.4")
        lines.append(f"v {4.2 * math.cos(a):.4f} {4.2 * math.sin(a):.4f} -1.2 0.6 0.6 0.65")
    lines.append(f"v 0 0 -1.2 0.6 0.6 0.65")
    centre_i = base + 2 * ring_n + 1
    for k in range(ring_n):
        j = (k + 1) % ring_n
        lo0, hi0, lo1, hi1 = base + 2 * k + 1, base + 2 * k + 2, base + 2 * j + 1, base + 2 * j + 2
        lines.append(f"f {lo0} {lo1} {hi1} {hi0}")
        lines.append(f"f {hi0} {hi1} {centre_i}")
    # Faces counted from the end, as OBJ allows: the base's bottom disc.
    for k in range(ring_n):
        j = (k + 1) % ring_n
        lines.append(f"f {base + 2 * j + 1} {base + 2 * k + 1} {base + 2 * ring_n + 1}")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


knot_obj(out("knot.obj"))

# -------------------------------------------------------------------- terrain


def terrain_ply(path, n=48):
    xs = np.linspace(-1, 1, n)
    X, Y = np.meshgrid(xs, xs)
    Z = 0.35 * np.exp(-((X - 0.3) ** 2 + (Y + 0.2) ** 2) * 6) + 0.25 * np.exp(-((X + 0.5) ** 2 + (Y - 0.4) ** 2) * 9) + 0.04 * np.sin(9 * X) * np.cos(7 * Y) - 0.1
    verts = np.stack([X * 50, Y * 50, Z * 50], axis=-1).reshape(-1, 3).astype("<f4")
    gx, gy = np.gradient(Z * 50, 100 / (n - 1))
    nrm = np.stack([-gx, -gy, np.ones_like(gx)], axis=-1)
    nrm /= np.linalg.norm(nrm, axis=-1, keepdims=True)
    nrm = nrm.reshape(-1, 3).astype("<f4")
    h = (Z.reshape(-1) - Z.min()) / (Z.max() - Z.min())
    stops = np.array([[30, 70, 160], [60, 150, 90], [190, 180, 90], [140, 100, 70], [250, 250, 250]], float)
    pos = h * (len(stops) - 1)
    lo = np.clip(pos.astype(int), 0, len(stops) - 2)
    frac = (pos - lo)[:, None]
    col = (stops[lo] * (1 - frac) + stops[lo + 1] * frac).astype(np.uint8)
    faces = []
    for j in range(n - 1):
        for i in range(n - 1):
            a = j * n + i
            faces.append((a, a + 1, a + n + 1))
            faces.append((a, a + n + 1, a + n))
    header = (
        "ply\nformat binary_little_endian 1.0\ncomment a height field with a colour per vertex\n"
        f"element vertex {len(verts)}\nproperty float x\nproperty float y\nproperty float z\n"
        "property float nx\nproperty float ny\nproperty float nz\nproperty uchar red\nproperty uchar green\nproperty uchar blue\n"
        f"element face {len(faces)}\nproperty list uchar int vertex_indices\nend_header\n"
    )
    body = bytearray()
    for v, nn, c in zip(verts, nrm, col):
        body += struct.pack("<6f3B", *v, *nn, *c)
    for f in faces:
        body += struct.pack("<B3i", 3, *f)
    with open(path, "wb") as fh:
        fh.write(header.encode() + bytes(body))


terrain_ply(out("terrain.ply"))


def icosphere(level=2):
    t = (1 + 5**0.5) / 2
    v = [(-1, t, 0), (1, t, 0), (-1, -t, 0), (1, -t, 0), (0, -1, t), (0, 1, t), (0, -1, -t), (0, 1, -t), (t, 0, -1), (t, 0, 1), (-t, 0, -1), (-t, 0, 1)]
    verts = [np.array(a, float) / np.linalg.norm(a) for a in v]
    faces = [(0, 11, 5), (0, 5, 1), (0, 1, 7), (0, 7, 10), (0, 10, 11), (1, 5, 9), (5, 11, 4), (11, 10, 2), (10, 7, 6), (7, 1, 8),
             (3, 9, 4), (3, 4, 2), (3, 2, 6), (3, 6, 8), (3, 8, 9), (4, 9, 5), (2, 4, 11), (6, 2, 10), (8, 6, 7), (9, 8, 1)]
    cache = {}

    def mid(a, b):
        key = (min(a, b), max(a, b))
        if key not in cache:
            m = verts[a] + verts[b]
            verts.append(m / np.linalg.norm(m))
            cache[key] = len(verts) - 1
        return cache[key]

    for _ in range(level):
        new = []
        for a, b, c in faces:
            ab, bc, ca = mid(a, b), mid(b, c), mid(c, a)
            new += [(a, ab, ca), (b, bc, ab), (c, ca, bc), (ab, bc, ca)]
        faces = new
    return verts, faces


def sphere_ply(path):
    verts, faces = icosphere(2)
    lines = ["ply", "format ascii 1.0", "comment an icosphere, colours from the position", f"element vertex {len(verts)}",
             "property float x", "property float y", "property float z", "property float nx", "property float ny", "property float nz",
             "property uchar red", "property uchar green", "property uchar blue", "property uchar alpha", f"element face {len(faces)}",
             "property list uchar uint vertex_indices", "end_header"]
    for v in verts:
        col = [int(127.5 + 127.5 * c) for c in v]
        lines.append(f"{v[0]:.5f} {v[1]:.5f} {v[2]:.5f} {v[0]:.5f} {v[1]:.5f} {v[2]:.5f} {col[0]} {col[1]} {col[2]} 255")
    for f in faces:
        lines.append(f"3 {f[0]} {f[1]} {f[2]}")
    with open(path, "w") as fh:
        fh.write("\n".join(lines) + "\n")


sphere_ply(out("icosphere-ascii.ply"))

# ----------------------------------------------------------------------- glTF


class Gltf:
    def __init__(self):
        self.buf = bytearray()
        self.views, self.accessors, self.meshes, self.nodes, self.materials = [], [], [], [], []

    def _view(self, data, target=None):
        while len(self.buf) % 4:
            self.buf.append(0)
        self.views.append({"buffer": 0, "byteOffset": len(self.buf), "byteLength": len(data), **({"target": target} if target else {})})
        self.buf += data
        return len(self.views) - 1

    def accessor(self, array, ctype, kind, target=None, minmax=False):
        a = np.ascontiguousarray(array)
        acc = {"bufferView": self._view(a.tobytes(), target), "componentType": ctype, "count": len(a), "type": kind}
        if minmax:
            acc["min"] = [float(x) for x in a.min(axis=0)]
            acc["max"] = [float(x) for x in a.max(axis=0)]
        self.accessors.append(acc)
        return len(self.accessors) - 1

    def material(self, rgba, metallic=0.0, rough=0.8, emissive=None, name=""):
        m = {"name": name, "pbrMetallicRoughness": {"baseColorFactor": list(rgba), "metallicFactor": metallic, "roughnessFactor": rough}}
        if emissive:
            m["emissiveFactor"] = list(emissive)
        if rgba[3] < 1:
            m["alphaMode"] = "BLEND"
        self.materials.append(m)
        return len(self.materials) - 1

    def mesh(self, pos, nrm, idx, material, colors=None, name=""):
        attrs = {"POSITION": self.accessor(pos.astype("<f4"), 5126, "VEC3", 34962, True), "NORMAL": self.accessor(nrm.astype("<f4"), 5126, "VEC3", 34962)}
        if colors is not None:
            attrs["COLOR_0"] = self.accessor(colors.astype("<f4"), 5126, "VEC3", 34962)
        prim = {"attributes": attrs, "indices": self.accessor(idx.astype("<u2" if idx.max() < 65535 else "<u4").reshape(-1), 5123 if idx.max() < 65535 else 5125, "SCALAR", 34963), "material": material, "mode": 4}
        self.meshes.append({"name": name, "primitives": [prim]})
        return len(self.meshes) - 1

    def node(self, **kw):
        self.nodes.append(kw)
        return len(self.nodes) - 1

    def document(self, roots, uri=None):
        doc = {"asset": {"version": "2.0", "generator": "exav make-models.py", "copyright": "CC0-1.0"}, "scene": 0, "scenes": [{"nodes": roots}],
               "nodes": self.nodes, "meshes": self.meshes, "materials": self.materials, "accessors": self.accessors, "bufferViews": self.views,
               "buffers": [{"byteLength": len(self.buf), **({"uri": uri} if uri else {})}]}
        return doc


def box_mesh(sx, sy, sz):
    pos, nrm, idx = [], [], []
    for axis in range(3):
        for sign in (-1, 1):
            n = np.zeros(3)
            n[axis] = sign
            u, v = np.zeros(3), np.zeros(3)
            u[(axis + 1) % 3] = 1
            v[(axis + 2) % 3] = 1
            base = len(pos)
            for du, dv in [(-1, -1), (1, -1), (1, 1), (-1, 1)]:
                pos.append((n + du * u + dv * v) * 0.5 * np.array([sx, sy, sz]))
                nrm.append(n)
            order = [0, 1, 2, 0, 2, 3] if sign * np.dot(np.cross(u, v), n) > 0 else [0, 2, 1, 0, 3, 2]
            idx += [base + o for o in order]
    return np.array(pos), np.array(nrm), np.array(idx)


def uv_sphere(r, rings=12, segs=20):
    pos, nrm, idx = [], [], []
    for i in range(rings + 1):
        phi = math.pi * i / rings
        for j in range(segs + 1):
            th = 2 * math.pi * j / segs
            n = np.array([math.sin(phi) * math.cos(th), math.cos(phi), math.sin(phi) * math.sin(th)])
            pos.append(n * r)
            nrm.append(n)
    for i in range(rings):
        for j in range(segs):
            a = i * (segs + 1) + j
            idx += [a, a + segs + 1, a + 1, a + 1, a + segs + 1, a + segs + 2]
    return np.array(pos), np.array(nrm), np.array(idx)


def cylinder(r, h, segs=20):
    pos, nrm, idx = [], [], []
    for j in range(segs + 1):
        th = 2 * math.pi * j / segs
        n = np.array([math.cos(th), 0, math.sin(th)])
        pos += [n * r + [0, 0, 0], n * r + [0, h, 0]]
        nrm += [n, n]
    for j in range(segs):
        a = 2 * j
        idx += [a, a + 2, a + 1, a + 1, a + 2, a + 3]
    c0 = len(pos)
    pos.append(np.array([0, h, 0.0]))
    nrm.append(np.array([0, 1.0, 0]))
    for j in range(segs + 1):
        th = 2 * math.pi * j / segs
        pos.append(np.array([math.cos(th) * r, h, math.sin(th) * r]))
        nrm.append(np.array([0, 1.0, 0]))
    for j in range(segs):
        idx += [c0, c0 + 2 + j, c0 + 1 + j]
    return np.array(pos), np.array(nrm), np.array(idx)


def quat(axis, deg):
    a = np.array(axis, float)
    a /= np.linalg.norm(a)
    s = math.sin(math.radians(deg) / 2)
    return [float(a[0] * s), float(a[1] * s), float(a[2] * s), math.cos(math.radians(deg) / 2)]


def arm_glb(path):
    g = Gltf()
    steel = g.material((0.7, 0.72, 0.78, 1), 0.9, 0.35, name="steel")
    orange = g.material((0.95, 0.45, 0.1, 1), 0.2, 0.5, name="paint")
    blue = g.material((0.1, 0.3, 0.8, 1), 0.1, 0.6, name="blue")
    glass = g.material((0.4, 0.8, 1.0, 0.45), 0.0, 0.1, name="glass")
    glow = g.material((0.1, 0.1, 0.1, 1), 0.0, 0.5, emissive=(1.0, 0.3, 0.1), name="lamp")
    base_m = g.mesh(*cylinder(0.6, 0.25), steel, name="base")
    link_m = g.mesh(*box_mesh(0.22, 1.0, 0.22), orange, name="link")
    joint_m = g.mesh(*uv_sphere(0.17), blue, name="joint")
    dome_m = g.mesh(*uv_sphere(0.9, 10, 16), glass, name="dome")
    lamp_m = g.mesh(*uv_sphere(0.1, 8, 12), glow, name="lamp")
    pos, nrm, idx = box_mesh(2.4, 0.05, 2.4)
    colors = np.array([[0.9, 0.9, 0.9] if (int(p[0] * 2.5 + 100) + int(p[2] * 2.5 + 100)) % 2 else [0.3, 0.3, 0.35] for p in pos])
    floor_m = g.mesh(pos, nrm, idx, g.material((1, 1, 1, 1), 0.0, 0.9, name="floor"), colors=colors, name="floor")
    # A tree: base > joint1 > link1 > joint2 > link2 > joint3 > link3 > lamp.
    lamp = g.node(mesh=lamp_m, translation=[0, 0.55, 0], name="lamp")
    link3 = g.node(mesh=link_m, scale=[0.7, 0.6, 0.7], translation=[0, 0.3, 0], name="link3", children=[lamp])
    joint3 = g.node(mesh=joint_m, translation=[0, 1.0, 0], rotation=quat([0, 0, 1], -50), name="joint3", children=[link3])
    link2 = g.node(mesh=link_m, translation=[0, 0.5, 0], name="link2", children=[joint3])
    joint2 = g.node(mesh=joint_m, translation=[0, 1.0, 0], rotation=quat([0, 0, 1], 65), name="joint2", children=[link2])
    link1 = g.node(mesh=link_m, translation=[0, 0.5, 0], name="link1", children=[joint2])
    joint1 = g.node(mesh=joint_m, translation=[0, 0.25, 0], rotation=quat([0, 1, 0], 40), name="joint1", children=[link1])
    base = g.node(mesh=base_m, name="base", children=[joint1])
    dome = g.node(mesh=dome_m, translation=[0, 0.0, 0], name="dome")
    floor = g.node(mesh=floor_m, translation=[0, -0.03, 0], name="floor")
    root = g.node(name="arm cell", children=[floor, base, dome], rotation=quat([0, 1, 0], -20))
    doc = g.document([root])
    js = json.dumps(doc, separators=(",", ":")).encode()
    js += b" " * (-len(js) % 4)
    binary = bytes(g.buf) + b"\0" * (-len(g.buf) % 4)
    blob = struct.pack("<4sII", b"glTF", 2, 12 + 8 + len(js) + 8 + len(binary)) + struct.pack("<I4s", len(js), b"JSON") + js + struct.pack("<I4s", len(binary), b"BIN\0") + binary
    with open(path, "wb") as f:
        f.write(blob)


arm_glb(out("arm.glb"))


def table_gltf(path):
    g = Gltf()
    wood = g.material((0.55, 0.35, 0.18, 1), 0.0, 0.7, name="wood")
    cloth = g.material((0.8, 0.15, 0.15, 1), 0.0, 0.9, name="cloth")
    top_m = g.mesh(*box_mesh(1.6, 0.08, 0.9), wood, name="top")
    leg_m = g.mesh(*box_mesh(0.08, 0.7, 0.08), wood, name="leg")
    seat_m = g.mesh(*box_mesh(0.45, 0.06, 0.45), cloth, name="seat")
    back_m = g.mesh(*box_mesh(0.45, 0.5, 0.05), cloth, name="back")
    legs = [g.node(mesh=leg_m, translation=[x, -0.39, z], name=f"leg {i}") for i, (x, z) in enumerate([(-0.74, -0.38), (0.74, -0.38), (-0.74, 0.38), (0.74, 0.38)])]
    table = g.node(mesh=top_m, translation=[0, 0.74, 0], name="table", children=legs)
    chair_legs = [g.node(mesh=leg_m, scale=[0.8, 0.6, 0.8], translation=[x, -0.2, z], name=f"chair leg {i}") for i, (x, z) in enumerate([(-0.19, -0.19), (0.19, -0.19), (-0.19, 0.19), (0.19, 0.19)])]
    back = g.node(mesh=back_m, translation=[0, 0.28, -0.2], name="back")
    seat = g.node(mesh=seat_m, translation=[0, 0.45, 0], name="seat", children=chair_legs + [back])
    chair_a = g.node(name="chair a", translation=[-0.4, 0, 0.85], children=[seat])
    chair_b = g.node(name="chair b", translation=[0.5, 0, -0.85], rotation=quat([0, 1, 0], 180), children=[g.node(mesh=seat_m, translation=[0, 0.45, 0], name="seat b", children=[g.node(mesh=back_m, translation=[0, 0.28, -0.2], name="back b")] + [g.node(mesh=leg_m, scale=[0.8, 0.6, 0.8], translation=[x, -0.2, z]) for x, z in [(-0.19, -0.19), (0.19, -0.19), (-0.19, 0.19), (0.19, 0.19)]])])
    doc = g.document([table, chair_a, chair_b], uri="data:application/octet-stream;base64," + base64.b64encode(bytes(g.buf)).decode())
    with open(path, "w") as f:
        json.dump(doc, f, separators=(",", ":"))


table_gltf(out("table.gltf"))
