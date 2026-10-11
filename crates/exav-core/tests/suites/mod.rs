//! Every integration suite, compiled into ONE test binary.
//!
//! Cargo builds each top-level `tests/*.rs` as its own crate, statically linked
//! against the whole dependency graph. Collapsing them into modules keeps every
//! test and every name filter working (`cargo test --test all tdb_attributes::`
//! still selects one suite) while linking once instead of once per file.
#![allow(dead_code)]

mod allmatch_parity;
mod authenticode;
#[cfg(feature = "base64scan")]
mod base64_scan;
mod broken_executable;
#[cfg(feature = "unstable-internals")]
mod bytecode_gating;
// NB: gate container suites on `all-formats`, never on exav-core's own per-format
// features (`zip`, `ole`, …). Those are NOT implied by `all-formats` — it
// forwards to `exav-unpack/all-formats` — so `#[cfg(feature = "zip")]` here is
// off in a default build and silently skips the suite.
#[cfg(feature = "all-formats")]
mod cdb_stream;
#[cfg(feature = "all-formats")]
mod checksum_mismatch;
#[cfg(feature = "all-formats")]
mod cut_short_members;
#[cfg(feature = "all-formats")]
mod embedded_carve;
#[cfg(feature = "all-formats")]
mod encrypted_archives;
#[cfg(feature = "image-hash")]
mod fuzzy_img_formats;
#[cfg(feature = "all-formats")]
mod heuristic_alerts;
#[cfg(feature = "all-formats")]
mod heuristic_names;
#[cfg(feature = "all-formats")]
mod limits_alerts;
#[cfg(feature = "all-formats")]
mod match_location;
#[cfg(feature = "all-formats")]
mod matryoshka;
#[cfg(feature = "all-formats")]
mod multi_volume;
#[cfg(feature = "all-formats")]
mod one_scan;
#[cfg(feature = "all-formats")]
mod ooxml_container;
#[cfg(feature = "all-formats")]
mod oversize_container;
mod salvage;
#[cfg(feature = "all-formats")]
mod sevenz_ppmd;
mod size_caps;
mod tar_size_terminator;
mod target_flash;
mod target_text;
#[cfg(feature = "all-formats")]
mod tdb_attributes;
mod untyped_container_dispatch;
#[cfg(feature = "yara")]
mod yara_dotnet;
#[cfg(feature = "all-formats")]
mod zip_dual_index;
#[cfg(feature = "all-formats")]
mod zip_ppmd;
