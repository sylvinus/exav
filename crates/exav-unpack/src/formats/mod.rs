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
pub(crate) mod bzip2;
// Every feature that enables `bzip2-decoder`; the feature alone decodes nothing.
#[cfg(any(
    feature = "bzip2",
    feature = "sevenz",
    feature = "nsis",
    feature = "alz",
    feature = "egg",
    feature = "dmg"
))]
mod bzip2_rs;
#[cfg(feature = "cab")]
pub(crate) mod cab;
#[cfg(feature = "cab")]
mod cab_parse;
#[cfg(feature = "chm")]
mod chm;
#[cfg(feature = "cpio")]
pub(crate) mod cpio;
#[cfg(feature = "dmg")]
pub(crate) mod dmg;
#[cfg(feature = "egg")]
pub(crate) mod egg;
#[cfg(feature = "email")]
mod email;
#[cfg(feature = "gzip")]
pub(crate) mod gzip;
#[cfg(feature = "iso")]
pub(crate) mod iso;
#[cfg(feature = "lha")]
pub(crate) mod lha;
#[cfg(feature = "lzip")]
pub(crate) mod lzip;
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
#[cfg(feature = "zstd")]
pub(crate) mod zstd;
// Shared PPMd7 model: used by both RAR (RAR3 PPMd blocks) and 7-Zip.
#[cfg(feature = "ace")]
pub(crate) mod ace;
#[cfg(feature = "alz")]
pub(crate) mod alz;
#[cfg(feature = "arc")]
pub(crate) mod arc;
#[cfg(feature = "autoit")]
mod autoit;
#[cfg(feature = "autoit")]
mod autoit_data;
#[cfg(feature = "egg")]
pub(crate) mod azo;
#[cfg(feature = "egg")]
pub(crate) mod azo_tables;
#[cfg(feature = "binhex")]
mod binhex;
#[cfg(feature = "ext")]
pub(crate) mod ext;
#[cfg(feature = "fat")]
pub(crate) mod fat;
#[cfg(feature = "hwp3")]
pub(crate) mod hwp3;
#[cfg(feature = "inno")]
pub(crate) mod inno;
#[cfg(feature = "ishieldz")]
pub(crate) mod ishield_z;
#[cfg(feature = "lnk")]
mod lnk;
#[cfg(feature = "lz4")]
pub(crate) mod lz4;
#[cfg(feature = "lzw")]
pub(crate) mod lzw;
#[cfg(feature = "machofat")]
pub(crate) mod machofat;
#[doc(hidden)]
pub mod mediacheck;
#[cfg(feature = "nsis")]
mod nsis;
#[cfg(feature = "ntfs")]
pub(crate) mod ntfs;
#[cfg(feature = "onenote")]
pub(crate) mod onenote;
#[doc(hidden)]
pub mod partition;
#[cfg(any(feature = "rar", feature = "sevenz"))]
mod ppmd7;
#[cfg(feature = "diskimage")]
pub(crate) mod qcow2;
#[cfg(feature = "rar")]
mod rar;
#[cfg(feature = "rar")]
mod rar3_unpack;
#[cfg(feature = "rar")]
mod rar5_unpack;
// Every container exav recognises but does not open reports through here.
pub(crate) mod reported;
#[cfg(feature = "sevenz")]
pub(crate) mod sevenz;
pub(crate) mod sniff;
#[cfg(feature = "stuffit")]
pub(crate) mod stuffit;
#[cfg(feature = "tar")]
pub(crate) mod tar;
#[cfg(feature = "iso")]
pub(crate) mod udf;
#[cfg(feature = "dmg")]
mod udif;
#[cfg(feature = "upx")]
mod upx;
#[cfg(feature = "ole")]
mod vba;
#[cfg(feature = "vhd")]
pub(crate) mod vhd;
#[cfg(feature = "diskimage")]
pub(crate) mod vhdx;
#[cfg(feature = "diskimage")]
pub(crate) mod vmdk;
#[cfg(feature = "wim")]
pub(crate) mod wim;
#[cfg(feature = "xar")]
mod xar;
#[cfg(feature = "xz")]
#[doc(hidden)]
pub mod xz;
#[cfg(feature = "zip")]
#[doc(hidden)]
pub mod zip;
#[cfg(all(feature = "zip", feature = "decrypt"))]
mod zip_crypto;
#[cfg(feature = "zoo")]
pub(crate) mod zoo;
#[cfg(feature = "zoo")]
mod zoo_parse;
// aPLib codec: the compression used by the Petite/FSG2/NsPack PE packers.
#[cfg(feature = "aimodel")]
mod aimodel;
#[cfg(feature = "pepack")]
mod aplib;
#[cfg(feature = "javaclass")]
mod javaclass;
#[cfg(feature = "pepack")]
pub(crate) mod pepack;
#[cfg(feature = "pyc")]
pub(crate) mod pyc;
#[cfg(feature = "rtf")]
mod rtf;
#[cfg(feature = "screnc")]
mod screnc;
#[cfg(feature = "sfx")]
pub(crate) mod sfx;
#[cfg(feature = "swf")]
pub(crate) mod swf;
#[cfg(feature = "szdd")]
pub(crate) mod szdd;
#[cfg(feature = "tnef")]
pub(crate) mod tnef;
#[cfg(feature = "uuencode")]
mod uuencode;
#[cfg(feature = "xdp")]
mod xdp;

// Re-export the extractor entry points used by the dispatch in `lib.rs`.
#[cfg(feature = "aimodel")]
pub(crate) use aimodel::{extract_aimodel, is_aimodel};
#[cfg(feature = "arj")]
pub(crate) use arj::extract_arj;
#[cfg(feature = "autoit")]
pub(crate) use autoit::{extract_autoit, is_autoit, MARKER_EA05, MARKER_EA06};
#[cfg(feature = "binhex")]
pub(crate) use binhex::{extract_binhex, looks_like_binhex};
#[cfg(feature = "chm")]
pub(crate) use chm::extract_chm;
#[cfg(feature = "dmg")]
pub(crate) use dmg::is_dmg;
#[cfg(feature = "email")]
pub(crate) use email::extract_email;
#[cfg(feature = "javaclass")]
pub(crate) use javaclass::extract_javaclass;
#[cfg(feature = "lnk")]
pub(crate) use lnk::extract_lnk;
#[cfg(feature = "machofat")]
pub(crate) use machofat::looks_like_machofat;
#[cfg(feature = "nsis")]
pub(crate) use nsis::{extract_nsis, is_nsis, NSIS_SIG};
#[cfg(feature = "ole")]
pub(crate) use ole::extract_ole;
#[cfg(feature = "onenote")]
pub(crate) use onenote::is_onenote;
#[cfg(feature = "partition")]
pub(crate) use partition::is_partition;
#[cfg(feature = "pdf")]
pub(crate) use pdf::extract_pdf;
#[cfg(feature = "pdf")]
pub use pdf::has_obfuscated_name_object;
#[cfg(feature = "pe-emu")]
pub(crate) use pepack::emulate_pe;
#[cfg(feature = "pepack")]
pub(crate) use pepack::{extract_pepack, is_pepack};
#[cfg(feature = "rar")]
pub(crate) use rar::{extract_rar, join_volumes as join_rar_volumes};
#[cfg(feature = "rtf")]
pub(crate) use rtf::extract_rtf;
#[cfg(feature = "screnc")]
pub(crate) use screnc::{extract_screnc, looks_like_screnc, MARKER as SCRENC_MARKER};
#[cfg(feature = "sfx")]
pub(crate) use sfx::looks_like_sfx;
#[cfg(feature = "szdd")]
pub(crate) use szdd::{extract_szdd, is_szdd};
#[cfg(feature = "upx")]
pub(crate) use upx::{extract_upx, find_packheader, has_packheader_layout};
#[cfg(feature = "uuencode")]
pub(crate) use uuencode::{extract_uuencode, looks_like_uuencode};
#[cfg(feature = "xar")]
pub(crate) use xar::extract_xar;
#[cfg(feature = "xdp")]
pub(crate) use xdp::{extract_xdp, looks_like_xdp};
#[cfg(feature = "zip")]
pub(crate) use zip::extract_zip;
// Exposed for the rar5_check example / integration tests.
#[cfg(feature = "rar")]
pub use rar5_unpack::{unpack50, window_size_from_comp_info};
// Exposed for the rar3_check example / integration tests.
#[cfg(feature = "rar")]
pub use rar3_unpack::unpack29;
