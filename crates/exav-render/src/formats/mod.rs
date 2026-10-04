//! One module per family of formats.

#[cfg(feature = "dwg")]
pub mod cad;
#[cfg(feature = "dwg")]
pub mod dwg;
#[cfg(feature = "ifc")]
pub mod ifc;
#[cfg(feature = "image")]
pub mod image;
#[cfg(any(feature = "ifc", feature = "stl"))]
pub mod mesh;
#[cfg(any(feature = "jp2", feature = "jbig2", feature = "ccitt"))]
pub mod pdf_image;
#[cfg(feature = "stl")]
pub mod stl;
