//! Memory-safe decoders that turn a file into something to draw.
//!
//! - [`image`]: raster images into pixels, with the decoders ClamAV 1.5.4
//!   links, so that `exav-imagehash` hashes the pixels `sigtool --fuzzy-img`
//!   does. Feature `image` (default).
//!   JPEG 2000 and JBIG2 files too, with features `jp2` and `jbig2` (default),
//!   which libclamav does not decode.
//! - [`pdf_image`]: the JPXDecode, JBIG2Decode and CCITTFaxDecode images of
//!   PDF streams, into the buffers pdf.js reads. Features `jp2`, `jbig2`,
//!   `ccitt`.
//! - [`dwg`]: DWG and DXF drawings into GPU-ready buffers, from the drawing
//!   model. Feature `dwg`.
//! - [`cad`]: DXF drawings into a drawing model, read from the pairs
//!   `exav_unpack::dxf` gives, and DWG (R13 to 2018) from the
//!   objects `exav_unpack::dwg` reads. Feature `dwg`.
//! - [`ifc`], [`stl`], [`obj`], [`ply`] and [`gltf`]: IFC models (IFC2X3,
//!   IFC4, IFC4X3), STL, Wavefront OBJ, Stanford PLY and glTF 2.0 (GLB too)
//!   meshes into the triangle batches of a [`mesh::Scene`]. Features `ifc`,
//!   `stl`, `obj`, `ply`, `gltf`.
//! - [`markdown`]: Markdown into a tree of blocks and inlines, as data. Raw
//!   HTML is text, links are limited to http, https and mailto. Feature
//!   `markdown`.
//! - [`sheets`], [`slides`] and [`docs`]: spreadsheets (Excel 2 to 2003,
//!   ODS, FODS, Numbers, XML Spreadsheet 2003, HTML tables, SYLK) to XLSX,
//!   presentations (PowerPoint 95 to 2003, ODP, FODP, Keynote) to PPTX, and
//!   text documents (Word 6 to 2003, ODT, FODT, RTF, Word 2003 XML, Pages) to
//!   DOCX, for an Open XML renderer to draw. Features `office-sheets`,
//!   `office-slides`, `office-docs` (`office` for all three).
//! - [`text`]: the text a reader sees in a document, for a scanner or a
//!   search: Markdown, HTML, Office and OpenDocument XML parts, PDF, and
//!   AutoCAD drawings. Feature `text`.
//!
//! Every decoder is safe Rust: this crate is `forbid(unsafe_code)`, so are
//! exav-unpack's DXF and DWG readers and the hayro decoders, and
//! the dependencies that carry SIMD `unsafe` (zune-jpeg, hayro's
//! fearless_simd) are built without it.

#![forbid(unsafe_code)]

pub mod formats;

#[cfg(feature = "dwg")]
pub use formats::cad;
#[cfg(feature = "dwg")]
pub use formats::dwg;
#[cfg(feature = "gltf")]
pub use formats::gltf;
#[cfg(feature = "ifc")]
pub use formats::ifc;
#[cfg(feature = "image")]
pub use formats::image;
#[cfg(feature = "markdown")]
pub use formats::markdown;
#[cfg(any(
    feature = "ifc",
    feature = "stl",
    feature = "obj",
    feature = "ply",
    feature = "gltf"
))]
pub use formats::mesh;
#[cfg(feature = "obj")]
pub use formats::obj;
#[cfg(feature = "office-docs")]
pub use formats::office::docs;
#[cfg(feature = "office-sheets")]
pub use formats::office::sheets;
#[cfg(feature = "office-slides")]
pub use formats::office::slides;
#[cfg(any(feature = "jp2", feature = "jbig2", feature = "ccitt"))]
pub use formats::pdf_image;
#[cfg(feature = "ply")]
pub use formats::ply;
#[cfg(feature = "stl")]
pub use formats::stl;
#[cfg(feature = "text")]
pub use formats::text;

#[cfg(feature = "image")]
mod image_codecs;
