//! Per-format container extractors (one module each).

mod ar;
mod arj;
mod arj_parse;
mod bzip2;
mod cab;
mod cpio;
mod dmg;
mod email;
mod gzip;
mod iso;
mod lha;
mod lzip;
mod ole;
mod pdf;
mod pdf_parse;
mod ppmd7;
mod rar;
mod rar3_unpack;
mod rar5_unpack;
mod sevenz;
mod tar;
mod udif;
mod upx;
mod vba;
mod xar;
mod xz;
#[doc(hidden)]
pub mod zip;
mod zip_crypto;
mod zstd;

// Re-export the extractor entry points used by the dispatch in `lib.rs`.
pub(crate) use ar::extract_ar;
pub(crate) use arj::extract_arj;
pub(crate) use bzip2::extract_bzip2;
pub(crate) use cab::extract_cab;
pub(crate) use cpio::extract_cpio;
pub(crate) use dmg::{extract_dmg, is_dmg};
pub(crate) use email::extract_email;
pub(crate) use gzip::extract_gzip;
pub(crate) use iso::extract_iso;
pub(crate) use lha::extract_lha;
pub(crate) use lzip::extract_lzip;
pub(crate) use ole::extract_ole;
pub(crate) use pdf::extract_pdf;
pub(crate) use rar::extract_rar;
pub(crate) use sevenz::extract_sevenz;
pub(crate) use tar::extract_tar;
pub(crate) use upx::{extract_upx, find_packheader};
pub(crate) use xar::extract_xar;
pub(crate) use xz::extract_xz;
pub(crate) use zip::extract_zip;
pub use zip::ZipMembers;
pub(crate) use zstd::extract_zstd;
// Exposed for the rar5_check example / integration tests.
pub use rar5_unpack::{unpack50, window_size_from_comp_info};
// Exposed for the rar3_check example / integration tests.
pub use rar3_unpack::unpack29;
