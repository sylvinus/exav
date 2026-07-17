//! Per-format container extractors (one module each). Each module and its
//! extractor entry point are gated behind the matching Cargo feature (see the
//! crate's `[features]`); a disabled format simply isn't compiled in.

#[cfg(feature = "ar")]
pub(crate) mod ar;
#[cfg(feature = "arj")]
mod arj;
#[cfg(feature = "arj")]
mod arj_parse;
#[cfg(feature = "bzip2")]
mod bzip2;
#[cfg(feature = "cab")]
mod cab;
#[cfg(feature = "cab")]
mod cab_parse;
#[cfg(feature = "chm")]
mod chm;
#[cfg(feature = "cpio")]
pub(crate) mod cpio;
#[cfg(feature = "dmg")]
mod dmg;
#[cfg(feature = "email")]
mod email;
#[cfg(feature = "gzip")]
mod gzip;
#[cfg(feature = "iso")]
pub(crate) mod iso;
#[cfg(feature = "lha")]
mod lha;
#[cfg(feature = "lzip")]
mod lzip;
#[cfg(feature = "ole")]
mod ole;
#[cfg(all(feature = "ole", feature = "decrypt"))]
mod ole_crypto;
#[cfg(feature = "pdf")]
mod pdf;
#[cfg(feature = "pdf")]
mod pdf_parse;
#[cfg(feature = "ole")]
mod xlm;
#[cfg(feature = "ole")]
mod xlm_functions;
// Shared PPMd7 model: used by both RAR (RAR3 PPMd blocks) and 7-Zip.
#[cfg(feature = "autoit")]
mod autoit;
#[cfg(feature = "binhex")]
mod binhex;
#[cfg(feature = "lnk")]
mod lnk;
#[cfg(feature = "machofat")]
pub(crate) mod machofat;
#[cfg(feature = "nsis")]
mod nsis;
#[cfg(feature = "onenote")]
pub(crate) mod onenote;
#[cfg(feature = "partition")]
pub(crate) mod partition;
#[cfg(any(feature = "rar", feature = "sevenz"))]
mod ppmd7;
#[cfg(feature = "rar")]
mod rar;
#[cfg(feature = "rar")]
mod rar3_unpack;
#[cfg(feature = "rar")]
mod rar5_unpack;
#[cfg(feature = "sevenz")]
pub(crate) mod sevenz;
#[cfg(feature = "tar")]
mod tar;
#[cfg(feature = "dmg")]
mod udif;
#[cfg(feature = "upx")]
mod upx;
#[cfg(feature = "ole")]
mod vba;
#[cfg(feature = "xar")]
mod xar;
#[cfg(feature = "xz")]
mod xz;
#[cfg(feature = "zip")]
#[doc(hidden)]
pub mod zip;
#[cfg(all(feature = "zip", feature = "decrypt"))]
mod zip_crypto;
#[cfg(feature = "zstd")]
mod zstd;
// aPLib codec: the compression used by the Petite/FSG2/NsPack PE packers.
#[cfg(feature = "aimodel")]
mod aimodel;
#[cfg(feature = "pepack")]
mod aplib;
#[cfg(feature = "javaclass")]
mod javaclass;
#[cfg(feature = "pepack")]
mod pepack;
#[cfg(feature = "pyc")]
pub(crate) mod pyc;
#[cfg(feature = "rtf")]
mod rtf;
#[cfg(feature = "screnc")]
mod screnc;
#[cfg(feature = "sfx")]
pub(crate) mod sfx;
#[cfg(feature = "swf")]
mod swf;
#[cfg(feature = "szdd")]
mod szdd;
#[cfg(feature = "tnef")]
pub(crate) mod tnef;
#[cfg(feature = "uuencode")]
mod uuencode;
#[cfg(feature = "xdp")]
mod xdp;

// Re-export the extractor entry points used by the dispatch in `lib.rs`.
#[cfg(feature = "aimodel")]
pub(crate) use aimodel::{extract_aimodel, is_aimodel};
#[cfg(feature = "ar")]
pub(crate) use ar::extract_ar;
#[cfg(feature = "arj")]
pub(crate) use arj::extract_arj;
#[cfg(feature = "autoit")]
pub(crate) use autoit::{extract_autoit, is_autoit};
#[cfg(feature = "binhex")]
pub(crate) use binhex::{extract_binhex, looks_like_binhex};
#[cfg(feature = "bzip2")]
pub(crate) use bzip2::extract_bzip2;
#[cfg(feature = "cab")]
pub(crate) use cab::{extract_cab, stream_cab};
#[cfg(feature = "chm")]
pub(crate) use chm::extract_chm;
#[cfg(feature = "cpio")]
pub(crate) use cpio::extract_cpio;
#[cfg(feature = "dmg")]
pub(crate) use dmg::{extract_dmg, is_dmg};
#[cfg(feature = "email")]
pub(crate) use email::extract_email;
#[cfg(feature = "gzip")]
pub(crate) use gzip::extract_gzip;
#[cfg(feature = "iso")]
pub(crate) use iso::extract_iso;
#[cfg(feature = "javaclass")]
pub(crate) use javaclass::extract_javaclass;
#[cfg(feature = "lha")]
pub(crate) use lha::extract_lha;
#[cfg(feature = "lnk")]
pub(crate) use lnk::extract_lnk;
#[cfg(feature = "lzip")]
pub(crate) use lzip::extract_lzip;
#[cfg(feature = "machofat")]
pub(crate) use machofat::{extract_machofat, looks_like_machofat};
#[cfg(feature = "nsis")]
pub(crate) use nsis::{extract_nsis, is_nsis};
#[cfg(feature = "ole")]
pub(crate) use ole::extract_ole;
#[cfg(feature = "onenote")]
pub(crate) use onenote::{extract_onenote, is_onenote};
#[cfg(feature = "partition")]
pub(crate) use partition::{extract_partition, is_partition};
#[cfg(feature = "pdf")]
pub(crate) use pdf::extract_pdf;
pub use pdf::has_obfuscated_name_object;
#[cfg(feature = "pepack")]
pub(crate) use pepack::{extract_pepack, is_pepack};
#[cfg(feature = "pyc")]
pub(crate) use pyc::extract_pyc;
#[cfg(feature = "rar")]
pub(crate) use rar::extract_rar;
#[cfg(feature = "rtf")]
pub(crate) use rtf::extract_rtf;
#[cfg(feature = "screnc")]
pub(crate) use screnc::{extract_screnc, looks_like_screnc};
#[cfg(feature = "sevenz")]
pub(crate) use sevenz::extract_sevenz;
#[cfg(feature = "sfx")]
pub(crate) use sfx::{extract_sfx, looks_like_sfx};
#[cfg(feature = "swf")]
pub(crate) use swf::extract_swf;
#[cfg(feature = "szdd")]
pub(crate) use szdd::{extract_szdd, is_szdd};
#[cfg(feature = "tar")]
pub(crate) use tar::extract_tar;
#[cfg(feature = "tnef")]
pub(crate) use tnef::extract_tnef;
#[cfg(feature = "upx")]
pub(crate) use upx::{extract_upx, find_packheader};
#[cfg(feature = "uuencode")]
pub(crate) use uuencode::{extract_uuencode, looks_like_uuencode};
#[cfg(feature = "xar")]
pub(crate) use xar::extract_xar;
#[cfg(feature = "xdp")]
pub(crate) use xdp::{extract_xdp, looks_like_xdp};
#[cfg(feature = "xz")]
pub(crate) use xz::extract_xz;
#[cfg(feature = "zip")]
pub(crate) use zip::extract_zip;
#[cfg(feature = "zip")]
pub use zip::ZipMembers;
#[cfg(feature = "zstd")]
pub(crate) use zstd::extract_zstd;
// Exposed for the rar5_check example / integration tests.
#[cfg(feature = "rar")]
pub use rar5_unpack::{unpack50, window_size_from_comp_info};
// Exposed for the rar3_check example / integration tests.
#[cfg(feature = "rar")]
pub use rar3_unpack::unpack29;
