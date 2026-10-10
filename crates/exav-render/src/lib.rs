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
//! - [`ifc`] and [`stl`]: IFC models (IFC2X3, IFC4, IFC4X3) and STL meshes
//!   into the triangle batches of a [`mesh::Scene`]. Features `ifc`, `stl`.
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
#[cfg(feature = "ifc")]
pub use formats::ifc;
#[cfg(feature = "image")]
pub use formats::image;
#[cfg(any(feature = "ifc", feature = "stl"))]
pub use formats::mesh;
#[cfg(any(feature = "jp2", feature = "jbig2", feature = "ccitt"))]
pub use formats::pdf_image;
#[cfg(feature = "stl")]
pub use formats::stl;

#[cfg(feature = "image")]
mod image_codecs;
