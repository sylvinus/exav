---
title: exav-render
description: Memory-safe decoders that turn a file into something to draw, raster images into pixels, DWG and DXF drawings and IFC and STL models into GPU-ready buffers, behind @exav/viewer and exav-imagehash.
---

**Memory-safe decoders that turn a file into something to draw.** The Rust
library under [@exav/viewer](/viewer/)'s WebAssembly
modules, and the decoding half of [exav-imagehash](/subprojects/exav-imagehash/),
which hashes the pixels it returns. The crate is `forbid(unsafe_code)`, and
so is the DWG reader it vendors.

```toml
[dependencies]
exav-render = "0.0.2"                                            # images
exav-render = { version = "0.0.2", features = ["dwg"] }           # and drawings
exav-render = { version = "0.0.2", features = ["ifc", "stl"] }    # and models
```

## Images

PNG, GIF, JPEG, TIFF, BMP, WebP, ICO, PNM, QOI, DDS, farbfeld, Radiance
HDR, JPEG 2000 and JBIG2 (feature `image`, default; each format after the
first five is a feature of its own, all on by default: `webp`, `ico`, `pnm`,
`qoi`, `dds`, `ff`, `hdr`, `jp2`, `jbig2`). OpenEXR is left out: its crate
brings `rayon-core` and `smallvec`.

```rust
use exav_render::image::decode_any;

let bytes = std::fs::read("scan.tiff")?;
let pixels = decode_any(&bytes, 64 << 20)?; // at most 64 MiB of pixels
let rgba = pixels.to_rgba8();
# Ok::<(), Box<dyn std::error::Error>>(())
```

`decode` takes the format, `decode_any` reads it off the bytes. Both refuse
an image whose pixels would exceed the limit before allocating them;
`DECODE_MAX` is 512 MiB. `Pixels` holds what the decoder produced, at its
bit depth, so a hash can be computed on exactly the samples a reference
implementation sees.

The decoders are the versions libclamav 1.5.4 links: that is what lets
exav-imagehash reproduce `sigtool --fuzzy-img` to the bit. JPEG and TIFF go
through `src/image_codecs/`, the `image` crate's own decoders over a
zune-jpeg built without its SIMD code, its only `unsafe`.

JPEG 2000 (feature `jp2`: JP2 and JPX files, and bare codestreams) and
JBIG2 (feature `jbig2`: single-page files, sequential or random-access),
both default, are decoded by
[hayro-jpeg2000](https://crates.io/crates/hayro-jpeg2000) and
[hayro-jbig2](https://crates.io/crates/hayro-jbig2) (MIT OR Apache-2.0),
which are `forbid(unsafe_code)` and are built without their `simd` feature
(fearless_simd, whose intrinsics are `unsafe`). libclamav decodes neither;
exav-imagehash hashes them like the other formats, so a `fuzzy_img#`
signature made from a PNG matches the same picture stored as JPEG 2000 or
JBIG2.

## PDF images

`pdf_image` decodes the JPXDecode, JBIG2Decode (with `/JBIG2Globals`) and
CCITTFaxDecode (feature `ccitt`, default, through
[hayro-ccitt](https://crates.io/crates/hayro-ccitt)) images of PDF streams
into the buffers pdf.js reads from its own decoders: the layout for each
`/ColorSpace` (`/Indexed` included) and `/SMaskInData`, the components and
colour conversions, the rows of bits, and the failures, as observed on
pdf.js's OpenJPEG and PDFium builds. @exav/viewer gives them to pdf.js in
their place. Lossless JPEG 2000, JBIG2 and fax images decode to the same
bytes as pdf.js's; lossy JPEG 2000 one level apart on a few samples, and
16-bit JPEG 2000 one level apart at most.

## DWG and DXF

Feature `dwg`. DXF, ASCII or binary, R12 to 2018, is read into the
drawing model below, and the tessellator draws from that model. DWG, from
R13 to the 2018 format, is read into the
same model.

```rust
use exav_render::dwg::Document;

let doc = Document::parse(&std::fs::read("plan.dwg")?)?;    // DWG or DXF, by its first bytes
for layout in doc.layouts() {
    let drawing = doc.tessellate(Some(&layout.name), Some([255, 255, 255]));
    println!("{}: {} strokes, {} texts", layout.name, drawing.stroke_count(), drawing.text_count());
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

`tessellate` turns one layout into a `Drawing`: interleaved stroke
instances with their lineweight, fill triangles, text records, the layer
table, and tiles for culling, in little-endian buffers a WebGL renderer
uploads as they are. A renderer never sees an entity. Indexed colours
resolve against the background given, as in AutoCAD, so white on a dark
model space is black on paper. Text is laid out here, with the NewStroke
stroke font (CC0) standing in for SHX fonts and the advance widths of the
outline faces the viewer bundles, so it measures the same everywhere.

What is drawn: lines, rays, polylines with their bulges (not their widths), multilines,
arcs, circles, ellipses, splines, helices, points, solids, traces and 3D faces,
solid, pattern and gradient hatches, wipeouts, text, multiline text and
tables, dimensions, leaders and multileaders, blocks with their attributes,
in their linetypes and lineweights, paper layouts through their
viewports, and custom objects (ACAD_PROXY_ENTITY, an application's own
entities such as TArch's walls or Civil 3D's alignments) from the proxy
graphics they were saved with. External references are counted in
`Drawing`'s warnings, not drawn, and so are custom objects saved without
graphics (`proxy_without_graphics`).

A damaged file is meant to be an error, not a panic, a hang or an
allocation of gigabytes: the readers' panics are caught where unwinding is
available, declared sizes and counts are held to what the file can hold, a
layout stops at a budget of eight million strokes and fill vertices
(`SCENE_BUDGET`, or another through `Document::tessellate_within`; what is
left out is counted in `Drawing`'s warnings), and the tests and the `drawing` fuzz
target feed it truncated, bit-flipped and fuzzed files. `@exav/viewer` still
runs it in a worker it stops after two minutes (`timeoutMs`). In a wasm
build with `panic = "abort"` a panic or a failed allocation traps the
instance, and the worker is replaced.

`src/formats/dwg/DESIGN.md` explains the buffers, the coordinate origin kept
in `f64` while vertices are `f32`, and the text layout.

### The DXF drawing model

Also behind `dwg`, `cad::read_dxf` reads a DXF file, ASCII or binary, R12 to
2018, into a `Drawing`: the header variables a renderer needs, the layer,
linetype, text style, dimension style and viewport tables, every block with
its entities (model and paper space included), the layouts with their page
setup, and the dictionaries, draw order tables, image and underlay
definitions and multiline and multileader styles. It is written from
Autodesk's DXF reference and reads the file's pairs and
records through [exav-unpack](/unpack/rust/)'s `dxf` module.
`dwg::Document::drawing` gives the model a parsed DWG or DXF was drawn
from.

```rust
let drawing = exav_render::cad::read_dxf(&std::fs::read("plan.dxf")?)?;
for block in &drawing.blocks {
    println!("{}: {} entities", block.name, block.entities.len());
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

Angles are in radians, text in UTF-8 (the drawing's code page before 2007,
`\U+` and `\M+` escapes decoded), and an R12 file gets the block records,
handles and layouts it does not have. Every count is bounded by what is left
of the file and by `cad::Limits`; a damaged file gives an error or a partial
drawing with warnings. `cad::to_json` prints the model, which the tests
compare with ezdxf's reading of the same files.

`cad::read_dwg` reads a DWG file, R13 to 2018, into the
same model (what the compressed sections of a 2004 to 2018 file may expand
to is bounded by `cad::Limits::max_decompressed_bytes`),
from the objects [exav-unpack](/unpack/rust/)'s `dwg` module
reads, following the Open Design Specification for .dwg files: the header
variables, the tables, every block with its entities, each type the model
holds read in full (a 2010 and later table's content aside: the table is
drawn from its block), and the objects (layouts, dictionaries, draw order,
image and underlay definitions, multiline and multileader styles, and the
context data of an annotative 2018 MTEXT's columns). The tests compare it,
by handle, with the model the DXF reader gives of the ODA File Converter's
DXF of the same file. `dwg::Document::parse_with` takes the same limits.

Both readers keep, for an entity of a type the model does not read, the
proxy graphics it was saved with (`Unknown::graphics`: the stream's
primitives and the traits between them, ODA specification chapter 29, and
an elliptical arc the specification does not list), and the thumbnail the
drawing was saved with (`Drawing::preview`, PNG or BMP).
`cad::preview` reads that thumbnail without reading the drawing: from where
a DWG's file header points, from the end of an ASCII DXF.

## IFC and STL models

Features `ifc` and `stl`. Both read into one output, `mesh::Scene`:
triangles grouped in batches by class and colour, each element's ranges in
them, positions in `f32` relative to an origin kept in `f64` (a
georeferenced model stays precise), Z up, and the creases and open borders
as outline segments.

```rust
use exav_render::ifc::{read, Limits};

let scene = read(&std::fs::read("house.ifc")?, &Limits::default())?;
for e in &scene.elements {
    println!("#{} {} {:?}", e.id, e.class, e.name);
}
```

`ifc::read` takes IFC2X3, IFC4 and IFC4X3 files (STEP physical files,
ISO 10303-21, indexed in one pass and parsed as the geometry asks), and
meshes each product's body in metres: placements and mapped items with
their transformation operators, extrusions (tapered too) of every profile
type, revolutions, swept disks, sweeps along a directrix, tessellated and
polygonal face sets, faceted B-reps with voids, advanced B-reps (planar,
cylindrical and B-spline faces), shell and face based surface models,
bounded planes, CSG primitives, booleans with half-spaces and polygonal
bounded ones, and the openings of `IfcRelVoidsElement` cut out of their
host. Colours come from styled items, else from the element's material or
its type's. Each element has its GlobalId, class, name and containing
spatial element; the spatial tree (project, site, building, storeys) is
`scene.nodes`. It is written from buildingSMART's schemas and
documentation; booleans are binary space partitioning trees of our own.
Every reference is followed to a fixed depth, every curve sampled with a
fixed number of points per turn, a boolean gives up past a fixed amount of
work, and all triangles come out of `Limits::max_triangles`; what is not
drawn is counted in `scene.warnings`. The tests check each kind of
geometry against closed-form volumes and extents, and compare elements
with web-ifc's meshes.

Not drawn faithfully yet:

- B-rep faces on conical, spherical and toroidal surfaces are drawn as flat
  polygons through their edges (counted in the warnings).
- B-spline faces are drawn whole: their trimming boundaries are ignored.
- IFC4X3 alignments and the geometry placed along them are not read.
- The start and end parameters of sweeps are ignored: the whole directrix
  is swept.
- Grid placements (`IfcGridPlacement`) sit at their parent's placement.
- The viewer lists storeys in the selection only: there is no storey
  filter.

`stl::read` takes binary and ASCII STL (a binary file whose header begins
with "solid" included), the VisCAM and Materialise facet colours, and
checks a binary file's declared count against its size.
