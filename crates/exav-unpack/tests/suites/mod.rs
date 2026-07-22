//! Every integration suite, compiled into ONE test binary.
//!
//! Cargo builds each top-level `tests/*.rs` as its own crate, statically linked
//! against the whole dependency graph — here that was 38 binaries at ~170 MB
//! each, so a full run spent most of its time linking near-identical images.
//! Collapsing them into modules under `tests/suites/` keeps every test and every
//! name filter working (`cargo test --test suites alz::` still selects one
//! suite) while linking once.
//!
//! Helpers are per-suite and several go unused under a lean feature set, which
//! is expected rather than a smell.
#![allow(dead_code)]

mod allowed_formats;
#[cfg(feature = "alz")]
mod alz;
#[cfg(feature = "arc")]
mod arc;
#[cfg(feature = "arj")]
mod arj_never_silent;
mod broken_media;
#[cfg(feature = "cab")]
mod cab_quantum;
#[cfg(feature = "chm")]
mod chm;
#[cfg(feature = "cpio")]
mod cpio_never_silent;
#[cfg(all(not(feature = "decrypt"), feature = "zip"))]
mod decrypt_disabled;
mod disabled_formats;
#[cfg(feature = "diskimage")]
mod diskimage;
#[cfg(feature = "dmg")]
mod dmg;
mod egg;
#[cfg(feature = "decrypt")]
mod encrypted_zip;
#[cfg(feature = "tar")]
mod entry_accounting;
#[cfg(feature = "ext")]
mod ext;
#[cfg(feature = "fat")]
mod fat;
mod hwp3;
#[cfg(feature = "ishieldz")]
mod ishield_z;
#[cfg(feature = "iso")]
mod iso_joliet;
#[cfg(feature = "iso")]
mod iso_never_silent;
#[cfg(feature = "lha")]
mod lha_header_bounds;
#[cfg(feature = "lz4")]
mod lz4;
#[cfg(feature = "lzw")]
mod lzw;
#[cfg(feature = "nsis")]
mod nsis;
#[cfg(feature = "ntfs")]
mod ntfs;
#[cfg(feature = "ole")]
mod ole_lenient;
#[cfg(feature = "onenote")]
mod onenote;
#[cfg(feature = "all-formats")]
mod panic_containment;
mod partition_intersection;
#[cfg(feature = "partition")]
mod partition_never_silent;
#[cfg(feature = "decrypt")]
mod pdf_empty_password;
#[cfg(feature = "pdf")]
mod pdf_parse;
#[cfg(feature = "pepack")]
mod pe_emulation;
#[cfg(feature = "pepack")]
mod pe_emulation_corpus;
#[cfg(feature = "pepack")]
mod pe_emulation_techniques;
#[cfg(feature = "ole")]
mod ppt_embedded_storage;
mod protectors;
#[cfg(feature = "rar")]
mod rar3_ppmd;
#[cfg(feature = "rar")]
mod rar_solid;
#[cfg(feature = "sevenz")]
mod sevenz_bcj2;
mod silent_skips;
#[cfg(feature = "iso")]
mod udf;
#[cfg(feature = "upx")]
mod upx_rebuild;
#[cfg(feature = "ole")]
mod vba_module_source;
#[cfg(feature = "vhd")]
mod vhd;
#[cfg(feature = "wim")]
mod wim;
#[cfg(feature = "xz")]
mod xz_dict;
#[cfg(feature = "zip")]
mod zip_codecs;
#[cfg(feature = "zip")]
mod zip_deflate64;
#[cfg(feature = "zip")]
mod zip_disguised_members;
#[cfg(feature = "zip")]
mod zip_overlap;
#[cfg(feature = "zoo")]
mod zoo;
