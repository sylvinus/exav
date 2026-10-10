# The DWG and DXF engine

How exav renders AutoCAD drawings in a browser: a DWG (or DXF) read and
tessellated in Rust compiled to WebAssembly, drawn by a purpose-built WebGL2
renderer (`crates/exav-viewer/ts/cad/`). Pan, zoom, layers, layouts. No
editing. Section numbers are what the code cites.

## 1. Decisions

| Decision | Choice |
|---|---|
| Reader | exav's own drawing model (`crate::cad`, MIT) from DXF and DWG, in a worker |
| DWG support | Native, in the browser, no server, no GPL |
| Renderer | Purpose-built WebGL2, three shader programs |
| WebGPU | Not now: nothing to gain for 2D line soup |
| Canvas2D fallback | Not needed: WebGL2 coverage is effectively complete |
| Engine (three.js, PixiJS) | No, see 4.3 |

## 2. Why this shape

The constraint is no GPL and no server. The only mature open-source DWG
reader is LibreDWG, which is GPL-3.0, as is its wasm build: linking it into an
embeddable viewer would carry the GPL into every product embedding it, and
converting DWG to DXF on a server would mean uploading drawings, which is what
a browser-side viewer exists to avoid.

So the reader is exav's own, written from Autodesk's DXF reference and the
Open Design Specification: `crate::cad` reads a file into a drawing model
shaped for drawing it, and the tessellator draws from that model and nothing
else. It reads DXF, and (`cad::read_dwg`) R13 to 2018 DWG: the header,
tables, blocks with their entities, and
the objects (layouts, dictionaries, draw order, image and underlay
definitions, multiline and multileader styles). A DWG keeps a spline drawn
through fit points as those points only (no control points); the
tessellator draws it through them. DWG has no viewport number or status:
the reader gives them as DXF has them, from the layout's last active
viewport. An R13 or R14 drawing AutoCAD saved has no LAYOUT objects; its
paper space is offered as a `Layout1` tab when it holds something.

## 3. Architecture

```
┌ main thread ────────────────┐   ┌ worker ──────────────────┐
│ Renderer (WebGL2)           │   │ exav_viewer_dwg.wasm     │
│  camera, pan, zoom          │   │  DWG/DXF bytes → model   │
│  draws from GPU buffers     │   │ Tessellator              │
│ Layer state (visibility)    │   │  arcs, splines → strokes │
│                             │   │  hatches → triangles     │
│                             │   │  text → glyph records    │
│        ◄── transfer ────────┼───┤  blocks flattened        │
└─────────────────────────────┘   └──────────────────────────┘
```

Parsing and tessellation both run in the worker: the main thread never sees a
DWG entity, only finished vertex buffers, transferred once. After that pan
and zoom are GPU state changes, and a layer toggle is a uniform update.

### 3.1 Why tessellate in Rust, not JS

The tessellator needs the parsed document (block tables, linetypes, hatch
patterns, text styles) and produces flat arrays. Doing it beside the parser
avoids serialising the entity graph across the worker boundary, and never
builds a JS object per entity, which is what makes naive viewers choke at 50k
entities.

### 3.2 Scene representation

| Class | Source entities | GPU form |
|---|---|---|
| Strokes | Line, Arc, Circle, Ellipse, Polyline, LwPolyline, Spline, Ray, XLine, dimension and block contents, stroke-font text | instanced quads: colour, layer id, lineweight, flags |
| Fills | Hatch, Solid, Face3D, gradients | triangles: colour, layer id |
| Glyphs | Text, MText, Attribute in an outline face | instanced quads into a Canvas-built atlas |

Curves are flattened at a tolerance chosen from the drawing's extents. Both
the stroke and fill buffers are sorted into spatial buckets recording the true
box of their contents, so a view draws only the buckets it touches. Buckets
are built within the opaque and the translucent halves, which are two passes
(only the first writes depth).

### 3.3 Layer show and hide without re-uploading

Every stroke, triangle and glyph carries a layer id. Visibility lives in a
one-byte texture indexed by it, in rows of 256 so that all 65,536 ids fit
under any GPU's size limit, and the vertex shader collapses invisible
geometry to a degenerate position. A toggle costs
one uniform upload, whatever the drawing's size.

## 4. Rendering

### 4.1 Mobile

WebGL2 is available on iOS and iPadOS since 15, which makes it the baseline.
WebGPU (iOS 26) helps draw-call or compute-bound work; a 2D drawing is a
handful of instanced draws, bound by tessellation and fill rate. WebGL2 in a
worker (OffscreenCanvas) is skipped: only recent Safari has it, and mobile
Safari may drop large offscreen canvases under memory pressure. Rendering on
the main thread is fine once tessellation is off it.

### 4.2 Lineweight rules out GL lines

`gl.lineWidth()` is clamped to 1 px on Apple and ANGLE drivers. Every stroke
is an instanced quad whose width the vertex shader resolves from its
lineweight and the zoom.

### 4.3 Why not three.js or PixiJS

three.js is a 3D scene graph: an orthographic camera and three draw calls
would pay for a scene graph, a material system and a lighting model, and
still need custom shaders for lineweight, dashing and hatch patterns. PixiJS
is a sprite and display-object engine whose per-object model is wrong for
500k segments. The primitives needed are narrow (instanced quads, triangles,
glyph quads), and bundle size matters for an embeddable viewer.

### 4.4 Coordinate precision

Real drawings carry survey coordinates in the millions with millimetre
detail, and a `float32` vertex has about seven significant digits: visible
jitter exactly where it matters. So the worker subtracts a per-drawing origin
before writing vertices, keeps the origin in `float64`, and the renderer folds
it into the view matrix.

## 5. Fidelity

| Feature | State |
|---|---|
| Lines, arcs, circles, ellipses, polylines, splines | Drawn |
| Blocks and inserts, nested, scaled, rotated, MINSERT arrays | Drawn, with a cycle guard |
| Dimensions | Drawn from the anonymous block AutoCAD bakes |
| MLINE, HELIX | Drawn |
| Layers: colour, on/off, freeze, transparency | From the file |
| Lineweight | Instanced quads, zoom-aware |
| Solid and gradient hatch, islands | Even-odd, holes bridged into the outer ring |
| Pattern hatch | Line families clipped to the region, with dash phase |
| Linetypes | Dashed in drawing units, phase carried along a polyline; LTSCALE, per-entity and block scale |
| Extrusion (OCS) | Arbitrary Axis Algorithm, for the entity types stored in object coordinates |
| TrueType text | Bundled faces, glyph atlas |
| SHX text | Substituted, see 5.3 |
| MTEXT formatting | Colour, height, font, the three rules, indents and tabs kept; stacked fractions as `a/b` |
| Paper-space layouts and viewports | Drawn |
| External references, images, OLE | Frame only; counted in the warnings |
| Custom objects (proxy graphics) | Drawn from the graphics saved with them, see 5.4; those saved without are counted in the warnings |
| Plot styles (CTB/STB) | Not planned |

### 5.1 Hatch boundaries are not geometry

AutoCAD never strokes a hatch's boundary paths: they are bookkeeping, and the
visible edge belongs to entities drawn in their own right. Drawing them puts
lines on screen that are not in the drawing.

A boundary arc flagged clockwise stores its angles mirrored about the centre's
horizontal axis. Taken at face value it lands on the other side of its
centre, and a large-radius kerb arc becomes a fill over the whole sheet that
also inflates the extents. The angles of clockwise arcs are negated, which
makes the endpoints meet their neighbours; `curves.rs` has the regression
test.

### 5.2 Extrusion direction is not optional

An entity stored in OCS keeps its coordinates in a frame defined by its
extrusion vector, and an extrusion of (0, 0, -1) mirrors the X axis: a block
at x = 16613 drawn at x = -16613. The transform is the Arbitrary Axis
Algorithm, not a sign flip, and applies only to the entity types that are in
OCS: LINE, POINT, SPLINE, ELLIPSE, 3DFACE and MLINE carry an extrusion vector
but store world coordinates.

### 5.3 SHX

SHX fonts are proprietary Autodesk shape files and cannot be bundled.
Substituting a system font for one changes glyph shapes and string widths, so
text overruns its leaders and boxes, and differently on each machine: a
browser cannot even be asked whether it has a face (`document.fonts.check()`
reports whether a family name resolves, which it always does). So only faces
the viewer ships are used:

- A **stroke** style resolves to NewStroke (CC0, `stroke_font/`, compiled into
  the wasm) and is drawn as geometry, so that the drawing's lineweight decides
  its thickness, as AutoCAD draws SHX text. NewStroke descends from Hershey
  Simplex, the lineage of `romans` and `simplex`.
- A **TrueType** style resolves to Arimo, Tinos or Cousine (SIL OFL, the
  metric-compatible set for Arial, Times New Roman and Courier New) by generic
  family.

The bundled faces' advance widths are compiled in (`metrics.rs`, written by
`crates/exav-render/scripts/font-tables.py`), so MTEXT wraps at the same place
everywhere and nothing is measured by the host. Units are cap heights, since a
DWG text height is one.

Still to come: a host hook supplying a real `.shx`, which matters most for the
SHAPE entity and for linetypes that stamp a symbol along a line.

### 5.4 Proxy graphics

An application's own entities (TArch's walls, Civil 3D's alignments, Plant
3D's pipes) are saved with a stream of what they draw, so that a program
without the application shows them: ACAD_PROXY_ENTITY, or the entity of its
own class when `$PROXYGRAPHICS` was 1 (ODA specification chapter 29). The
model keeps the stream as primitives and the traits between them
(`cad::ProxyGraphics`, read in `cad/proxy.rs`); `proxy.rs` here makes
plain entities of it (lines, 3D polylines, texts, LWPOLYLINEs, fills) and the
tessellator draws them as it draws the entities beside the custom one: the
pieces start with its layer, colour, linetype and lineweight, ByBlock is the
block it is in, and the transforms pushed apply to the points before they
lose their Z.

What the specification leaves open was settled with the ODA File Converter:
it writes a custom entity of a release without proxies (R12) as plain
entities, and writes the stream again, through its own drawing code, when it
saves a DWG. Both are compared with this drawing, entity by entity
(`tests/cad_proxy.rs`, on the streams `tests/fixtures/cad/proxy/make.py`
writes, and real drawings outside the repository). Found so: the stream starts with its size and chunk
count; layer and linetype chunks index the tables (the linetypes without
ByLayer and ByBlock; 32767 and 32766 are ByLayer and ByBlock too, an index
past the end ByLayer); a true colour is an RL AcCmColor (`0xC2RRGGBB`), not
three bytes; fill is on but for 2, off until set; the raw flag of a text is
1 for literal `%%`; an LWPOLYLINE's data has the layout of the release that
wrote the stream, not always the file's; type 44, not in the specification,
is an elliptical arc. Where the R12 output does not follow the fill trait,
this drawing does: with fill on a circle, shell or closed arc is filled (the
R12 output draws circles and shells as outlines, and fills sectors and chords
whatever the fill), and seen edge on, a filled shape draws its outline.
Clipping (types 27 and 28) is not applied, and PUSH_MODELXFORM2 (30), whose
data the converter reads otherwise than the specification says and no
stream of the corpus has, pushes no change.

## 6. Prior art

| Project | Licence | Use |
|---|---|---|
| `mlightcad/cad-viewer` | MIT | Closest prior art; its DWG support is the optional GPL LibreDWG package |
| `vagran/dxf-viewer` | MPL-2.0 | three.js-based DXF rendering |
| `bjnortier/dxf` | MIT | DXF parser |
| LibreDWG | GPL-3.0 | Not read, not linked |

## 7. Testing

`crates/exav-render/tests/dwg.rs` reads drawings ezdxf wrote and the ODA
File Converter turned into DWG (`tests/fixtures/dwg/make.py`) and checks
what is drawn against what was put in: geometry, layers and their colours,
layouts and their viewports, text, and that a damaged file fails without
panicking. A corpus of real drawings goes through the same checks with
`EXAV_DEBUG_DWG_CORPUS=<dir>`. The `scene_stats` example prints a summary of
what each layout draws (counts, extents, layers, warnings, stroke length per
layer and colour, text, coarse occupancy grids), to compare two builds over
a corpus, and with `--entities` what each entity draws on its own.
