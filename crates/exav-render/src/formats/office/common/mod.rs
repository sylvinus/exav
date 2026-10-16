//! Readers shared by the office converters (`sheets`, `slides`, `docs`): a
//! lenient OLE2 compound file reader, legacy code pages, OfficeArt records,
//! ZIP packages, iWork archives (Snappy, protocol buffers, the IWA object
//! store), a bounded XML tree with OpenDocument's prefixes, and a
//! little-endian cursor that never panics.
//!
//! Each converter uses a subset: what a build leaves unused is not an error.

#![allow(dead_code)]

pub mod base64;
pub mod bytes;
pub mod cfb;
pub mod codepage;
mod codepage_tables;
pub mod escher;
pub mod image;
pub mod iwa;
pub mod odf;
pub mod package;
pub mod xml;
pub mod xmlout;
