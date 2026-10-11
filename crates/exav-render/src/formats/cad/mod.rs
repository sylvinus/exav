//! AutoCAD drawings read into a model shaped for drawing them.
//!
//! [`read_dxf`] reads an ASCII or binary DXF file, R12 to 2018, into a
//! [`Drawing`]: the header variables a renderer needs, the layer, linetype,
//! text style, dimension style and viewport tables, every block with its
//! entities (model and paper space included), the layouts, and the objects
//! drawing depends on (dictionaries, draw order, image and underlay
//! definitions, multiline and multileader styles). The file's pairs,
//! records and strings come from `exav_unpack::dxf`; this module says what
//! they mean.
//!
//! [`read_dwg`] reads a DWG file, R13 to R2018, into the same model from
//! `exav_unpack::dwg`'s objects: the header, the tables, the blocks with
//! their entities and the objects DXF's reader keeps.
//!
//! Both keep, for an entity of a type the model does not read, the proxy
//! graphics it was saved with ([`Unknown::graphics`]), and the drawing's
//! thumbnail ([`Drawing::preview`]), which [`preview`] reads without
//! reading the drawing.
//!
//! The model follows the DXF reference, not any reader's API. Angles are in
//! radians whatever unit the file stores them in; a handle is the number the
//! file writes in hexadecimal. Text is decoded to UTF-8, `\U+XXXX` and
//! `\M+nXXXX` escapes included; `%%` control codes and MTEXT formatting are
//! left in place for the renderer.
//!
//! Input is untrusted: every count and size is bounded by the input left and
//! by [`Limits`]. Nothing grows with the input faster than the input itself:
//! the reader does not recurse (block references are kept as names, not
//! expanded), and every count a file gives is capped by the groups left to
//! read. A damaged file gives an [`Error`], or a partial drawing whose
//! [`Drawing::warnings`] say what was dropped.

#![cfg_attr(
    not(test),
    deny(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic
    )
)]

mod dwg;
mod dxf;
mod json;
pub mod model;
mod preview;
mod proxy;

pub use exav_unpack::dwg::{looks_like_dwg, pre_r13_version};
pub use exav_unpack::dxf::{looks_like_dxf, Limits};
pub use json::to_json;
pub use model::*;
pub use preview::preview;

/// Why a file could not be read at all.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Neither the binary sentinel nor group-code/value pairs.
    NotDxf,
    /// No DWG file header.
    NotDwg,
    /// A DWG release the reader does not read, by its version ID: one
    /// before R13 (`AC1009` and older).
    Unsupported(String),
    /// The file ends, or stops making sense, before its first section (DXF),
    /// or the sections its header locates are not there (DWG).
    Damaged(String),
    /// The compressed sections of a DWG file expand past
    /// [`Limits::max_decompressed_bytes`].
    LimitExceeded(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NotDxf => f.write_str("not a DXF file"),
            Error::NotDwg => f.write_str("not a DWG file"),
            Error::Unsupported(v) => write!(
                f,
                "DWG version {v} is not supported: R13 (AC1012) to 2018 (AC1032) are"
            ),
            Error::Damaged(why) => write!(f, "damaged drawing: {why}"),
            Error::LimitExceeded(why) => write!(f, "drawing past the size limit: {why}"),
        }
    }
}

impl std::error::Error for Error {}

/// Read a DXF file, ASCII or binary, with the default [`Limits`].
pub fn read_dxf(bytes: &[u8]) -> Result<Drawing, Error> {
    read_dxf_with(bytes, &Limits::default())
}

/// Read a DXF file, ASCII or binary.
pub fn read_dxf_with(bytes: &[u8], limits: &Limits) -> Result<Drawing, Error> {
    dxf::read(bytes, limits)
}

/// Read a DWG file, R13 to R2018, with the default [`Limits`].
pub fn read_dwg(bytes: &[u8]) -> Result<Drawing, Error> {
    read_dwg_with(bytes, &Limits::default())
}

/// Read a DWG file, R13 to R2018: the header, the tables, the blocks with
/// their entities, and the objects (layouts, dictionaries, draw order, image
/// and underlay definitions, multiline and multileader styles).
pub fn read_dwg_with(bytes: &[u8], limits: &Limits) -> Result<Drawing, Error> {
    dwg::read(bytes, limits)
}
