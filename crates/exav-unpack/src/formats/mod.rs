//! Per-format container extractors (one module each).

mod gzip;
mod bzip2;
mod xz;
mod tar;
mod zip;
mod cab;
mod sevenz;
mod lha;
mod iso;
mod ole;
mod pdf;
mod email;
mod upx;

// Re-export the extractor entry points used by the dispatch in `lib.rs`.
pub(crate) use gzip::extract_gzip;
pub(crate) use bzip2::extract_bzip2;
pub(crate) use xz::extract_xz;
pub(crate) use tar::extract_tar;
pub(crate) use zip::extract_zip;
pub use zip::ZipMembers;
pub(crate) use cab::extract_cab;
pub(crate) use sevenz::extract_7z;
pub(crate) use lha::extract_lha;
pub(crate) use iso::extract_iso;
pub(crate) use ole::extract_ole;
pub(crate) use pdf::extract_pdf;
pub(crate) use email::extract_email;
pub(crate) use upx::{extract_upx, find_packheader};
