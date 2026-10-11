//! The scan options the broad targets run under, chosen by the input.
//!
//! Every check that a switch turns on is a code path the default options never
//! reach: the `alert_*` heuristics, the structured-data and phishing checks,
//! the Authenticode parser, the block-cache read of an object over
//! `deep_analysis_max`. The input selects them (its last two bytes for
//! `analyze`, the header for `full_pipeline`), so a seed that opens one
//! parser reaches it under each combination.
//!
//! Included with `#[path = "../options.rs"] mod options;`.
#![allow(dead_code)]

use exav_core::ScanOptions;

/// Tight bounds unless both of bits 12 and 13 are set, so that three
/// executions in four stay short and one in four runs under the limits a
/// production scan has.
pub fn scan_options(bits: u16) -> ScanOptions {
    let bit = |n: u32| bits & (1 << n) != 0;
    let mut o = ScanOptions::default();
    o.heuristics = bit(0);
    o.clamav_heuristics = !bit(1);
    o.alert_encrypted = bit(2);
    o.alert_macros = bit(3);
    o.alert_exceeds_max = bit(4);
    o.alert_partition_intersection = bit(5);
    o.alert_broken = bit(6);
    o.alert_broken_media = bit(7);
    o.alert_packed = bit(8);
    o.alert_phishing = bit(9);
    o.alert_broken_authenticode = bit(10);
    if bit(11) {
        o.structured_cc_count = Some(1);
        o.structured_ssn_count = Some(1);
    }
    if !(bit(12) && bit(13)) {
        let l = &mut o.limits;
        l.max_recursion = 8;
        l.max_members = 1_000;
        // Small enough that a scan of what a bomb expands to, which is what
        // the sanitizer's wall clock is spent on, is a few hundred ms.
        l.max_extracted_bytes = 2 << 20;
        l.max_compression_ratio = 200;
        l.max_buffer_bytes = 1 << 20;
        l.max_scanned_bytes = 4 << 20;
        l.max_pe_emulation_steps = 2_000_000;
        // PCRE over megabytes of text is the sanitizer's seconds, in all-match
        // mode, which runs every signature to the end.
        o.max_pcre_bytes = Some(1 << 16);
    }
    // An object over this is read through the block cache, which is another
    // way in than a buffer.
    if bit(13) {
        o.deep_analysis_max = 4096;
    }
    if bit(14) {
        o.max_scan_size = Some(8192);
    }
    if bit(15) {
        o.filename = Some("sample.js".to_string());
        o.decode_base64 = false;
    }
    o.verify_checksums = true;
    o.passwords = vec!["infected".to_string(), "hunter2".to_string()];
    o
}
