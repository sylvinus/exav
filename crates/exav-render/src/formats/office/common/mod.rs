//! Readers shared by the office converters (`sheets`, `slides`, `docs`):
//! legacy code pages, OfficeArt records, ZIP packages, iWork archives
//! (Snappy, protocol buffers, the IWA object store), a bounded XML tree with
//! OpenDocument's prefixes, and a little-endian cursor that never panics.
//! Compound files are read by `exav_unpack::cfb`, which the scanner uses too.
//!
//! Each converter uses a subset: what a build leaves unused is not an error.

#![allow(dead_code)]

pub mod base64;
pub mod bytes;
pub use exav_unpack::charset as codepage;
pub mod css;
pub mod escher;
pub mod image;
pub mod iwa;
pub mod odf;
pub mod package;
pub mod xml;
pub mod xmlout;
