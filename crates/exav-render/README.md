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
  exav-imagehash hashes them like the others).
- **PDF images** (`jp2`, `jbig2`, `ccitt`): the JPXDecode, JBIG2Decode and
  CCITTFaxDecode images of PDF streams, into the buffers pdf.js reads from
  its own decoders (`src/formats/pdf_image/`), which @exav/viewer gives
  pdf.js in place of its OpenJPEG and PDFium builds.
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
  included. See `src/formats/ifc/`. Not drawn faithfully yet: conical,
  spherical and toroidal B-rep faces (flat), B-spline face trimming, IFC4X3
  alignments, sweep start/end parameters, grid placements (listed on
  exav.org's exav-render page).

The crate is `forbid(unsafe_code)`.

```rust
use exav_render::image::{decode_any, DECODE_MAX};

let bytes = std::fs::read("scan.tiff")?;
let pixels = decode_any(&bytes, 64 << 20)?; // at most 64 MiB of pixels
let rgba = pixels.to_rgba8();
# Ok::<(), Box<dyn std::error::Error>>(())
```

MIT. The vendored decoders keep their licences (`src/image_codecs/`), and
the NewStroke stroke font its CC0-1.0 dedication (`fonts/`).
