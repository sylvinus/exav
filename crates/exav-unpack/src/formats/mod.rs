//! Per-format container extractors (one module each).

mod gzip;
mod bzip2;
mod xz;
mod tar;
mod zip;
mod zip_crypto;
mod cab;
mod sevenz;
mod lha;
mod arj;
mod iso;
mod ole;
mod vba;
mod pdf;
mod email;
mod upx;
mod ar;
mod cpio;
mod xar;
mod ppmd7;
mod rar;
mod rar3_unpack;
mod rar5_unpack;
mod dmg;
mod udif;

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
pub(crate) use arj::extract_arj;
pub(crate) use iso::extract_iso;
pub(crate) use ole::extract_ole;
pub(crate) use pdf::extract_pdf;
pub(crate) use email::extract_email;
pub(crate) use upx::{extract_upx, find_packheader};
pub(crate) use ar::extract_ar;
pub(crate) use cpio::extract_cpio;
pub(crate) use xar::extract_xar;
pub(crate) use rar::extract_rar;
pub(crate) use dmg::{extract_dmg, is_dmg};
// Exposed for the rar5_check example / integration tests.
pub use rar5_unpack::{unpack50, window_size_from_comp_info};
// Exposed for the rar3_check example / integration tests.
pub use rar3_unpack::unpack29;
