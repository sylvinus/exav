# exav-render

Memory-safe decoders that turn a file into something to draw. The library
behind [`@exav/viewer`](../exav-viewer) and the decoding half of
[`exav-imagehash`](../exav-imagehash).

- **Images** (`image`, default): PNG, GIF, JPEG, TIFF, BMP, WebP, ICO,
  PNM, QOI, DDS, farbfeld and Radiance HDR, into the samples the decoder
  produced (`Pixels`), or RGBA8 for display. The decoders are the versions
  libclamav 1.5.4 links, so exav-imagehash hashes exactly the pixels
  `sigtool --fuzzy-img` does. JPEG and TIFF go through `src/image_codecs/`,
  the `image` crate's own decoders over zune-jpeg built without its SIMD
  code (its only `unsafe`); see the README there. JPEG 2000 and JBIG2
  files too (`jp2`, `jbig2`, default), through hayro-jpeg2000 and
  hayro-jbig2 built without their SIMD code (libclamav decodes neither;
  exav-imagehash hashes them like the others). JPEG XL (`jxl`, not a
  default) goes through zenjxl-decoder, a fork of the libjxl team's jxl-rs
  that is `forbid(unsafe_code)`, built without its SIMD: the first frame, as
  8-bit grey or RGBA, within the caller's memory budget.
- **Camera RAW files** (`raw`, default): the largest JPEG or RGB preview a
  RAW file embeds, as 8-bit pixels with the Exif orientation applied
  (`image::raw`, and `decode_any`). DNG, Canon CR2, CR3 and CRW, Nikon NEF and
  NRW, Sony ARW, SR2 and SRF, Olympus ORF, Panasonic RW2, RAW and Leica RWL,
  Fujifilm RAF, Pentax PEF, Samsung SRW, Hasselblad 3FR, Phase One IIQ, Sigma
  X3F, Kodak, Epson, Mamiya and Leaf, told by their bytes, not their names: a
  plain TIFF is not one of them and the TIFF decoder reads it. The sensor
  data is not decoded, so a file that holds no preview (most phones' DNG) is
  `Error::NoPreview`. The previews come from the tags TIFF 6.0 and DNG
  define, and from a search of the file for the JPEG streams the makers keep
  elsewhere. Written from the public specifications, see `raw.rs`.
- **PDF images** (`jp2`, `jbig2`, `ccitt`): the JPXDecode, JBIG2Decode and
  CCITTFaxDecode images of PDF streams, into the buffers pdf.js reads from
  its own decoders (`src/formats/pdf_image/`), which @exav/viewer gives
  pdf.js in place of its OpenJPEG and PDFium builds.
- **Markdown** (`markdown`, not a default): CommonMark with tables and
  strikethrough, read by pulldown-cmark (without its `html` and `simd`
  features: `forbid(unsafe_code)`) into a tree of blocks and inlines, as
  data. Raw HTML is text, an image is its alt text, a link is kept only for
  an absolute http, https or mailto address; nesting, columns and nodes are
  bounded. `Document::to_json` is the shape @exav/viewer's page reads.
- **The text of a document** (`text`, `text-pdf`, `text-office`; not used by
  the viewer): `text::visible_text` gives the words a reader sees, for a
  scanner or a search: Markdown, HTML, the XML parts of Office and
  OpenDocument files, DWG and DXF, PDF (`text-pdf`, through hayro) and, with
  `text-office`, DOC, XLS, PPT, RTF, Word 2003 XML, SpreadsheetML 2003, SYLK,
  the flat OpenDocument files, Numbers, Pages and Keynote, taken from what
  the office converters read, in sections (a sheet, a slide). A link is its
  label then its target. A document of those kinds whose text could not be
  taken out says so in `Visible::unreadable`.
- **DWG and DXF** (`dwg`): read into the drawing model below and
  tessellated into GPU-ready buffers: strokes with their lineweight, fills,
  text runs, layers and layouts. See `src/formats/dwg/`.
- **DXF drawing model** (`dwg`): `cad::read_dxf` reads ASCII and binary DXF,
  R12 to 2018, into a model of the drawing (header, tables, blocks with
  their entities, layouts, the objects drawing depends on), from the pairs
  and records `exav_unpack::dxf` gives. Written from the DXF reference and
  checked against ezdxf. `cad::read_dwg` reads R13 to 2018 DWG into the
  same model, objects included, from `exav_unpack::dwg`, checked against the DXF reader's reading of the
  ODA File Converter's DXF of each file. Custom objects keep the proxy
  graphics they were saved with, which the tessellator draws, and the model
  carries the drawing's thumbnail (`cad::preview` reads it alone). See
  `src/formats/cad/`.

- **IFC and STL models** (`ifc`, `stl`): IFC2X3, IFC4 and IFC4X3 files,
  and binary or ASCII STL, into triangle meshes ready for a GPU
  (`mesh::Scene`): batches by class and colour, each element's ranges, its
  GlobalId, class, name and storey, the spatial tree. Written from
  buildingSMART's schemas and documentation, booleans and openings
  included. See `src/formats/ifc/`. Wavefront OBJ (`obj`), Stanford PLY
  (`ply`) and glTF 2.0 with GLB (`gltf`, with a JSON reader of its own and
  no dependency) read into the same meshes, never opening another file.
  B-rep faces on spheres, tori, cylinders and B-spline surfaces are meshed
  in their surface's parameters (B-spline faces cut by their bounds),
  sweeps honour their start and end parameters, IFC4X3 curve segments
  (lines, circles, clothoids and the other spirals, polynomials), gradient
  curves and linear placements along them are evaluated, grid placements
  sit at their grid intersections, and each element and batch has its
  building storey (`Element::storey`, `Batch::storey`, `Node::elevation`).
  What is not drawn yet is on exav.org's exav-render page.

- **Office documents** (`office-sheets`, `office-slides`, `office-docs`, or
  `office` for the three; not defaults): converted to the Open XML package an
  Open XML renderer draws, in the browser behind `@exav/viewer`. A
  conversion is bounded by `Limits` (input, cells, slides, paragraphs,
  memory, each decompressed part) and fails with `Error::TooLarge` rather
  than convert part of a document. Nothing is recalculated and no macro runs.
  - **Spreadsheets** (`sheets`, to XLSX): Excel 2.x to 2003 (BIFF2 to BIFF8,
    a lenient compound file reader, default-password encryption), ODS, FODS
    and OTS, Apple Numbers (Numbers 3 and later, and '08 and '09), and the
    text formats Excel opens from a .xls file: XML Spreadsheet 2003, HTML
    tables and SYLK. Values, formulas as text with their cached results,
    styles and number formats, merges, conditional formats, validations,
    comments, links, pictures, shapes and charts.
  - **Presentations** (`slides`, to PPTX): PowerPoint 95 and 97 to 2003
    (2 to 4 are recognised and reported as unsupported), ODP, FODP and OTP,
    and Apple Keynote in every version. Masters, placeholders, styles,
    shapes and their geometry, text, pictures, tables and charts, every
    property resolved in the PPTX written. `convert_first` converts the first
    slides only, `convert_first_from` reads a package part by part from any
    `Read + Seek` source. Drawings too, a page to a slide in the pages'
    largest size: ODG, OTG and FODG, and Visio 2013 and later (VSDX, VSDM,
    VSTX, VSTM: shapes through their masters and styles, formulas where a
    master's depend on the instance, geometry rows, splines, text, pictures,
    layers, hyperlinks, the theme's colours; the binary .vsd and the Visio
    2003 XML .vdx are not read).
  - **Text documents** (`docs`, to DOCX): Word 6 to 2003, ODT, OTT and FODT,
    RTF, Word 2003 XML and Apple Pages (text, page size and margins). Styles
    stay styles; sections with headers and footers, lists, tables, notes,
    comments, fields, pictures and OfficeArt shapes.
  - Encrypted files are refused. Fuzzed by the `sheets_*`, `slides_*` and
    `docs_*` targets (docs/FUZZING.md). See NOTICE for the specifications
    and data they are written from.

The crate is `forbid(unsafe_code)`.

```rust
use exav_render::image::{decode_any, DECODE_MAX};

let bytes = std::fs::read("scan.tiff")?;
let pixels = decode_any(&bytes, 64 << 20)?; // at most 64 MiB of pixels
let rgba = pixels.to_rgba8();
# Ok::<(), Box<dyn std::error::Error>>(())
```

```rust,ignore
// With the `office-sheets` feature.
use exav_render::sheets::{convert, Format, Limits};

let xlsx = convert(&bytes, Format::Ods, &Limits::default())?.xlsx;
```

MIT. The vendored decoders keep their licences (`src/image_codecs/`), and
the NewStroke stroke font its CC0-1.0 dedication (`fonts/`).
