---
title: exav-render
description: Memory-safe decoders that turn a file into something to draw, raster images into pixels, DWG and DXF drawings and IFC, STL, OBJ, PLY and glTF models into GPU-ready buffers, and spreadsheets, presentations and text documents into XLSX, PPTX and DOCX, behind @exav/viewer and exav-imagehash.
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
exav-render = { version = "0.0.2", features = ["office"] }        # and office documents
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

JPEG XL (feature `jxl`, not a default: libclamav does not decode it and it is
the largest decoder here) is decoded by
[zenjxl-decoder](https://crates.io/crates/zenjxl-decoder) (BSD-3-Clause), a
fork of the libjxl team's jxl-rs that is `forbid(unsafe_code)` unless its
`allow-unsafe` feature is on, and is built without its SIMD. The first frame
comes back as 8-bit grey with alpha or RGBA, in sRGB, a codestream or a
container alike. The caller's budget is the decoder's: its pixel and memory
limits are set from it, so a file declaring more than the budget is refused
from its header. `@exav/viewer`'s image module has it.

## Camera RAW

Feature `raw`, a default. A RAW file holds the sensor data and, beside it,
JPEG previews of several sizes, sometimes an uncompressed RGB one. The reader
(`exav_render::image::raw`) finds them and `decode_any` shows the largest the
budget allows, as 8-bit pixels with the Exif orientation applied (the JPEG's
own, else the file's). The sensor data is never decoded: a file with no
preview, such as most phones' DNG, is `Error::NoPreview`, not a blank.

```rust
use exav_render::image::{decode_any, raw, DECODE_MAX};

let bytes = std::fs::read("IMG_0001.CR3")?;
assert_eq!(raw::detect(&bytes), Some(raw::Kind::Cr3));
let pixels = decode_any(&bytes, DECODE_MAX)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

| Family | Read as |
|---|---|
| DNG (and the Leica, Ricoh, Pentax, GoPro and phone files that are DNG), Canon CR2, Phase One IIQ | TIFF directories |
| Olympus ORF (`IIRO`, `IIRS`, `MMOR`), Panasonic RW2, RAW and Leica RWL (`IIU`) | TIFF directories with the makers' own magic numbers |
| Nikon NEF and NRW, Sony ARW, SR2 and SRF, Pentax PEF, Samsung SRW, Hasselblad 3FR, Kodak, Epson, Mamiya, Leaf | TIFF/EP directories: told from a plain TIFF by sensor data in the file (a colour filter array, a maker's compression, the DNG tags), or by a camera maker's name beside a SubIFD or a thumbnail |
| Canon CR3 | an ISO base media file (`ftyp` brand `crx `); the orientation is in its metadata boxes |
| Fujifilm RAF, Sigma X3F, Canon CRW | a signature, then a search for the JPEG streams |
| Minolta MRW | a signature; it holds no JPEG, so it is `NoPreview` |

Detection is by the first bytes and, for a TIFF-structured file, its
directories, never the name. A plain TIFF, even one that kept a camera's Make
tag, is not claimed: `Format::detect` and `decode` read every TIFF as TIFF
(which is what exav-imagehash must do), and only `decode_any` and
`raw::decode` try a RAW file first.

The previews of a TIFF-structured file are listed from the tags the
specifications give them: JPEGInterchangeFormat, and strips of JPEG or of
8 or 16-bit RGB or grey (taken by their high byte), in every directory the
chain, the SubIFDs and the Exif pointer reach. Every file is also searched for
JPEG streams, which is where the makers keep theirs (maker notes, boxes,
sections): a stream counts when its marker segments are well formed up to a
first scan, with a baseline, extended sequential or progressive frame of
8 bits. Lossless JPEG, which is what sensor data is compressed with, is not
read, and neither is the baseline JPEG of a lossy DNG's linear raw data, which
the directory that holds it tells apart. The reader takes the largest, tries
the next when one does not decode, and counts each as the RGBA the page holds
(four bytes a pixel, six when it must be turned) against the budget, so a
preview over it gives way to a smaller one.

Every offset and count in the file is checked against the data. A directory is
read once, at most 64 are read, nested at most 3 deep, with at most 1,024
entries and 65,536 strips each; at most 512 JPEG start markers are tried and
64 streams kept, each walked once. A file that panics a decoder is
`Undecodable`. The `raw_preview` fuzz target runs all of it.

## Markdown

Feature `markdown`, not a default. CommonMark with tables and strikethrough is
read by [pulldown-cmark](https://crates.io/crates/pulldown-cmark) (MIT), built
without its `html` and `simd` features so that no markup is made and the crate
is `forbid(unsafe_code)`, and folded into a tree of `Block`s and `Inline`s
with no step that recurses on the input.

```rust
use exav_render::markdown::{parse, Block};

let doc = parse("# Title\n\nSome *text* and [a link](https://example.com).");
assert!(matches!(doc.blocks[0], Block::Heading { level: 1, .. }));
let json = doc.to_json(); // the shape @exav/viewer's page reads
```

Raw HTML is text (a `<script>` is the characters `<script>`), and an image is
its alt text. A link is kept only for an absolute `http:`, `https:` or
`mailto:` address of at most 2048 bytes without a space, control, line or
paragraph separator or bidirectional control character and, for the web ones,
without credentials
(`https://bank.example@evil.example`); any other is its label alone. Quotes and
lists nest to 10 and what is deeper is kept as text, inlines to 32, a table
has at most 64 columns, and past 100,000 nodes the rest of the document is
left out and `Document::truncated` says so. It reads in linear time on every
hostile input tried (1 MB of unclosed brackets, emphasis runs, backticks,
nested quotes and lists, wide tables), and the `markdown` fuzz target checks
the bounds and the JSON.

## Office documents

Features `office-sheets`, `office-slides` and `office-docs`, or `office` for
the three; none is a default. The modules `exav_render::sheets`, `slides` and
`docs` turn a document that an Open XML renderer cannot read into the Open XML
package it can: a spreadsheet into XLSX, a presentation or a drawing into
PPTX, a text document into DOCX. This is how `@exav/viewer` opens them: the
three modules run in workers, one wasm module each. They are written from
published specifications and from what other converters do with sample files
(their output, never their code); the notices are in the crate's `NOTICE`.

```rust
use exav_render::sheets::{convert, Format, Limits};

let bytes = std::fs::read("budget.ods")?;
let xlsx = convert(&bytes, Format::Ods, &Limits::default())?.xlsx;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Nothing is recalculated and no macro runs: a formula keeps its text and its
cached result. A password-protected file is refused (`Error::Encrypted`),
except an XLS encrypted with Excel's default password, which opens.

| Module | To | Reads |
|---|---|---|
| `sheets` | XLSX | Excel 2.x to 2003 (BIFF2 to BIFF8, templates and workspaces; a lenient compound file reader), ODS, FODS and OTS, Apple Numbers (3 and later, '08 and '09), and the text formats Excel opens from a .xls name: XML Spreadsheet 2003, HTML tables and SYLK |
| `slides` | PPTX | PowerPoint 95 and 97 to 2003 (.ppt, .pps, .pot; 2 to 4 are recognised and reported as unsupported), ODP, FODP and OTP, Apple Keynote of every version; and drawings: ODG, OTG and FODG, and Visio 2013 and later (VSDX, VSDM, VSTX, VSTM) |
| `docs` | DOCX | Word 6 to 2003 (.doc, .dot), ODT, OTT and FODT, RTF, Word 2003 XML and Apple Pages (text, page size and margins) |

What each keeps:

- **Spreadsheets**: values, formulas as text with their cached results, styles
  and number formats, merges, conditional formats, validations, comments,
  links, pictures, shapes and charts.
- **Presentations**: masters, placeholders, styles, shapes with their
  geometry, text, pictures, tables and charts, every property resolved in the
  PPTX written. `convert_first` converts the first slides only, and
  `convert_first_from` reads a package part by part from any `Read + Seek`
  source, so that one that fetches byte ranges fetches only what the slides
  converted need.
- **Drawings**: a page becomes a slide, named as the page is, in the size of
  the largest page. An ODG, OTG or FODG drawing leaves out the layers that are
  not displayed. A Visio drawing is read through its masters and styles, the
  formulas where a master's depend on the instance, geometry rows and
  splines, text, pictures, layers, hyperlinks and the theme's colours. The
  Visio reader is written from Microsoft's published Visio file format
  reference and [MS-VSDX]. The binary `.vsd` and the Visio 2003 XML `.vdx`
  are not read: `@exav/viewer` sends them to an external converter.
- **Text documents**: styles stay styles; sections with their headers and
  footers, lists, tables, notes, comments, fields, pictures and OfficeArt
  shapes. Tracked changes in a DOC are drawn as strike-through and underline.

Every conversion is bounded by `Limits`, one per module, and fails with
`Error::TooLarge` rather than convert part of a document. The error's `kind()`
is `not-format`, `encrypted`, `unsupported`, `too-large` or `malformed`.

| Limit | `sheets` | `slides` | `docs` |
|---|---|---|---|
| Input | 256 MiB | 512 MiB | 512 MiB |
| Memory the model and the output may take | 1 GiB | 1 GiB | 1 GiB |
| One decompressed part | 256 MiB | 256 MiB | 256 MiB |
| Cells | 4,000,000 | | 2,000,000 |
| Sheets | 4,096 | | |
| Slides | | 10,000 | |
| Shapes | | 1,000,000 | |
| Paragraphs | | | 5,000,000 |

The `sheets_*`, `slides_*` and `docs_*` fuzz targets run the readers and the
writers (`docs/FUZZING.md`).

### How close the pages come

`@silurus/ooxml` draws the converted file, and the page is compared with the
same page of a reference rendering (a PDF of the original made by an office suite), by structural similarity
(SSIM). A page is **close** or **near** when its score is in the upper bands;
close is the stricter. These are results on the project's own collections of
public sample files, which are not part of the repository, and the figures
move with the drawing engine.

| Format | Files | Pages close | Pages near | Documents close | Median SSIM |
|---|---|---|---|---|---|
| ODG | 63, of which 61 convert (two are not drawings) | 43 of 73 (58.9%) | 51 of 73 (69.9%) | 36 of 60 | 0.981 |
| FODG | | 28 of 52 (53.8%) | | | 0.951 |
| VSDX | 48, all convert | 58 of 71 (81.7%) | 66 of 71 (93.0%) | 36 of 45 (80%) | 0.983 |
| DOC | | 32% of pages | | | |

The ODG and VSDX rows were measured with @silurus/ooxml 0.88.0; the ODG
results are the same with 0.89.1, which `@exav/viewer` uses now, and FODG
with 0.89.1 is 28 of 52 pages close (27 with 0.88.0). For comparison, a DOCX
file drawn natively comes out close on 50% of its pages: the `docs` converter
is a prototype.

### Speed

Release build, native. A drawing converts in a few milliseconds:
ODG in a median 1 ms (90th percentile 2.6 ms, slowest 19 ms), FODG in a median
1 ms (90th percentile 4.8 ms), VSDX in a median 3 ms (90th percentile 32 ms;
the slowest, a 13 MB file, 1.2 s). In wasm it is several times slower. Reading
only the text of a document is faster than converting it:

| Format | Text only | Converted |
|---|---|---|
| Spreadsheets (`sheets`) | 38 MB/s | 21.5 MB/s |
| Text documents (`docs`) | 37 MB/s | 16 MB/s |
| PPT | 113 MB/s | 67 MB/s |
| FODP | 33 MB/s | 22 MB/s |
| Keynote | 193 MB/s | 128 MB/s |

The median document of `docs` takes 0.36 ms to read and 0.52 ms to convert.

### In the viewer

The wasm modules are `exav_viewer_sheets` (1,081,680 bytes, 450,494 brotli),
`exav_viewer_slides` (1,015,358 bytes, 434,088 brotli; it was 891,741 bytes
before the Visio reader) and `exav_viewer_docs` (826,632 bytes, 359,102
brotli). Each is built with a 2 GiB memory cap and imports nothing but
wasm-bindgen's plumbing ([Security](/viewer/security/)).

## Text

Features `text`, `text-pdf` and `text-office`, for a scanner or a search: the
text a reader sees in a document, one entry for every kind that has some. It
is not used by `@exav/viewer`.

```rust
use exav_render::text::visible_text;

let limits = exav_unpack::Limits::default();
let v = visible_text("page.html", b"<p>Click <b>here</b></p>", 1 << 20, &limits).unwrap();
assert_eq!(v.text, "Click here\n");
```

Markdown is read as above. HTML goes through html5gum's tokenizer alone (no
tree), with a sink that keeps the words and drops comments, scripts, styles,
templates and iframes; an image is its `alt`. The XML parts of Word,
PowerPoint, Excel and OpenDocument files (known by their path in the package)
are read by quick-xml, without field codes and deleted text. DXF and DWG
drawings give their TEXT and MTEXT, attributes with their tags and prompts,
dimension overrides, multileaders' text, and block and layer names. PDF
(`text-pdf`) is read by [hayro](https://crates.io/crates/hayro-interpret): each
page is interpreted, its glyphs come with their Unicode, and they are put back
in lines and words from where they sit. In all of them a link is its label
followed by its target, `label (target)`, whatever the target is, and
`Visible::links` lists the pairs whose label is not the target, for a check of
what a link says against where it goes.

With `text-office` (not a default; it turns on `office`) the legacy and flat
office formats the XML parts do not reach are read too: DOC, XLS, PPT, RTF,
Word 2003 XML, SpreadsheetML 2003, SYLK, the flat OpenDocument files (FODT,
FODS, FODP, FODG), Numbers, Pages and Keynote. Their text comes from the
model the converters above read, without writing an Open XML package first,
and is cut into sections that say where a match is, in `Visible::sections`: a
sheet (`sheet "Budget"`), a slide (`slide 2`), a header or a note. A table row
is a line, its cells apart by tabs.

```rust
use exav_render::text::visible_text;

let limits = exav_unpack::Limits::default();
let v = visible_text("book.xls", &std::fs::read("book.xls")?, 1 << 20, &limits).unwrap();
for (label, range) in &v.sections {
    println!("{label}: {} bytes", range.len()); // sheet "Budget": 123 bytes
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

A compound file is read as an office document only by its extension (`.doc`,
`.dot`, `.xls`, `.xlt`, `.xlw`, `.ppt`, `.pps`, `.pot`), so as not to read an
installer or a message whole to find out. RTF, Word 2003 XML, SpreadsheetML,
flat OpenDocument files and SYLK are told by their first bytes, and the iWork
files by the name (`.key`, `.keynote`, `.numbers`, `.pages`). A document of
those kinds whose text could not be taken out (encrypted, past a limit,
damaged) is never an empty text: `Visible::unreadable` says why, and a scanner
marks the scan incomplete. Speaker notes and the text of animations are left
out, as the converters leave them out.

hayro puts no bound on what a PDF stream decompresses to (a 1 MB file took
2.1 GB), so a PDF is handed to it only after exav-unpack's reader has taken
every stream within `Limits`; one that goes past them is cut, not read. A
panic in hayro is contained. `hayro-interpret` turns on `hayro-syntax`'s
`unsafe` feature itself, which switches every `flate2` in the build to zlib-rs;
that is why `text-pdf` is not a default of the crates that use it.

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
cylindrical, spherical, toroidal and B-spline faces, each meshed in its
surface's parameters), shell and face based surface models,
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

Curved faces, sweeps, alignments, grids and storeys:

- **Faces on curved surfaces.** The boundary of a face on a sphere, a
  torus, a cylinder or a B-spline surface is unrolled into the surface's
  parameters, the polygon it bounds is meshed there (a regular grid when it
  is a rectangle, else its triangles are bisected until a side's midpoint is
  as near the surface as a 32-chord circle's), and the points are those of the
  surface. A sphere's cap (one loop round a pole) is read, so is a band
  between two loops with no seam (some writers leave a tube so); a B-spline
  face is cut by its bounds, their points projected on the surface, and
  holes are holes. A face whose bounds are not on its surface, or whose
  edges do not make a loop, is drawn whole (a B-spline) or flat through its
  edges, and counted in `warnings.unsupported` under its surface's class.
  Points added in the parameters between two samples of an edge are on the
  surface, not on the edge: up to a chord's sag off it, more near a pole.
  There is no cone: no IFC schema has a conical surface (a cone is an
  `IfcSurfaceOfRevolution`, still drawn flat, with the surfaces of linear
  extrusion).
- **Sweeps.** `StartParam` and `EndParam` of `IfcSweptDiskSolid` and the
  directrix-curve swept area solids are read by each curve's published
  parametrisation: the index of a polyline's points, the sum of the
  parametric lengths of a composite curve's segments, an angle in the file's
  unit on a circle, the multiple of the vector on a line, the knot values
  of a B-spline. Parameters beyond the curve are its ends; an end before
  the start sweeps the other way. A curve whose parameters are not published
  (an indexed poly curve with arcs) is swept whole, and counted.
- **Alignments (IFC4X3).** `IfcCompositeCurve` of `IfcCurveSegment`s
  (parents: `IfcLine`, `IfcCircle`, the clothoid and the second, third and
  seventh order polynomial spirals, `IfcPolynomialCurve`; a negative
  segment length runs against the parent's sense) and `IfcGradientCurve`
  (a plan curve and a profile in distance and height) are curves a sweep
  can follow, and `IfcLinearPlacement` without a Cartesian position is
  worked out along its curve (the writer's `CartesianPosition` is used when
  it has one). The alignment's own axis is a curve, which is not drawn.
- **Grid placements.** `IfcGridPlacement` sits at the intersection of its
  two axes (lines, polylines, trimmed curves), offset as
  `IfcVirtualGridIntersection` says, its x axis along the first axis, an
  explicit direction or towards a second intersection. The grid's own axes
  are curves, which are not drawn.
- **Storeys.** `Element::storey` is the building storey an element is in
  (its container's, or the nearest above it in the spatial tree),
  `Node::elevation` a storey's elevation in metres, and a `Batch` holds the
  elements of one storey only (`Batch::storey`), so that a viewer can hide a
  storey by batch. `@exav/viewer` has a `storeys` controller.

Not read yet: `IfcSegmentedReferenceCurve` (cant), offset curves, the sine
and cosine spirals, `IfcSectionedSolidHorizontal`, the design parameters of
`IfcAlignmentSegment`, the parameter curves (`IfcPcurve`) of surface curves.

The evaluation of surfaces and curves is counted as well as the triangles:
a file may cost about twenty million evaluations, past which a face is
drawn flat or left out and counted.

`stl::read` takes binary and ASCII STL (a binary file whose header begins
with "solid" included), the VisCAM and Materialise facet colours, and
checks a binary file's declared count against its size.

## OBJ, PLY and glTF meshes

Features `obj`, `ply` and `gltf`; `obj::read`, `ply::read` and `gltf::read`
take the bytes and a triangle budget (200,000 in the fuzz targets, 6 million
by default in the viewer) and give a `mesh::Scene` of one batch, with one
element per OBJ group or object, per glTF node that has a mesh, and one for a
PLY. Triangles are not welded; each has the file's normals where it gives
usable ones, else its own. No dependency: glTF's JSON is read by a small
reader of its own.

- **OBJ**: `v` (with `r g b`), `vn`, `f` in the `v`, `v/vt`, `v//vn` and
  `v/vt/vn` forms with negative indices, `g`, `o`, continued lines. Texture
  coordinates, materials (`usemtl`; an `.mtl` is never opened) and every other
  statement are ignored; lines, points and curves are counted in
  `warnings.unsupported`.
- **PLY**: ASCII and binary in either byte order; `x y z`, `nx ny nz`, byte,
  16-bit or float colours; face lists of any count and index type; other
  elements and properties are skipped by type. A file without faces is a
  point cloud: an error.
- **glTF**: `.gltf` with base64 `data:` buffers and `.glb`; node trees with
  `matrix` or TRS; triangle primitives with 8, 16 or 32-bit indices,
  `POSITION`, `NORMAL`, `COLOR_0`, strides and sparse accessors; the
  material's `baseColorFactor` (linear, converted to sRGB). Buffers in other
  files or at a URL are `Error::External`. Points, lines, strips, fans, Draco
  and meshopt primitives are counted as unsupported. Textures, animations,
  skins and morph targets are ignored.

Limits, for files that are hostile: polygons of up to 64 corners are
ear-clipped within 20 million steps in all, the rest are fanned (linear);
a polygon past the budget is cut at it. Coordinates that are not finite or
past 10^12 drop their triangles (`warnings.invalid`). At most 10,000 elements
(later triangles join the last). glTF: nodes nested at most 256 deep, a node
with two parents or a cycle is refused, at most 2 million JSON values and 64
levels of JSON, every accessor and sparse list checked against its view and
buffer in 64-bit arithmetic before anything is allocated, and the triangles
looked at, instances of a mesh included, limited to four times the budget (at
least a million). OBJ and PLY keep the file's axes; glTF is Y up.
