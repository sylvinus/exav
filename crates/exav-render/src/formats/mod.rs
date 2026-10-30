//! One module per family of formats.

#[cfg(feature = "dwg")]
pub mod cad;
#[cfg(feature = "dwg")]
pub mod dwg;
#[cfg(feature = "gltf")]
pub mod gltf;
#[cfg(feature = "ifc")]
pub mod ifc;
#[cfg(feature = "image")]
pub mod image;
#[cfg(feature = "jp2")]
mod jp2_tiles;
#[cfg(feature = "markdown")]
pub mod markdown;
#[cfg(any(
    feature = "ifc",
    feature = "stl",
    feature = "obj",
    feature = "ply",
    feature = "gltf"
))]
pub mod mesh;
#[cfg(feature = "obj")]
pub mod obj;
#[cfg(feature = "_office")]
pub mod office;
#[cfg(any(feature = "jp2", feature = "jbig2", feature = "ccitt"))]
pub mod pdf_image;
#[cfg(feature = "ply")]
pub mod ply;
#[cfg(any(feature = "obj", feature = "ply", feature = "gltf"))]
mod soup;
#[cfg(feature = "stl")]
pub mod stl;
#[cfg(feature = "text")]
pub mod text;

/// Most bytes a decoded image may take: the `image` crate's default, which
/// ClamAV decodes with.
pub const DECODE_MAX: u64 = 512 * 1024 * 1024;
