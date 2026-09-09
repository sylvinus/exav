#![no_main]
//! Archive extraction on hostile bytes, tried as EVERY supported format.
//! The fuzzer doesn't need to "luck into" valid headers — each input is
//! attempted as all formats, so even random bytes exercise every parser's
//! error paths. Tight budgets prevent DoS from decompression bombs.
//!
//! A short list of candidate passwords is supplied so the decryption paths
//! (ZipCrypto/WinZip-AES, 7z AES, PDF/DMG crypto) are reachable when the mutator
//! produces a plausible encrypted container.
//!
//! Seed corpus: `fuzz/corpus/unpack/` — real format headers (zip, rar, pdf,
//! ole2, 7z, cab, and the newer decoders) that let the mutator start inside each
//! parser instead of rediscovering magic bytes.
use libfuzzer_sys::fuzz_target;
use exav_unpack::{extract, Budget, Format, Limits};

const TIGHT_LIMITS: Limits = Limits {
    max_extracted_bytes: 256 * 1024,
    max_members: 5,
    max_compression_ratio: 50,
    max_buffer_bytes: 128 * 1024,
    max_scanned_bytes: 256 * 1024,
    max_recursion: 2,
    // Every format stays reachable. Narrowing the set here would take whole
    // parsers out of the fuzzer's reach, which is the opposite of what this
    // target is for.
    allowed_formats: None,
};

/// Every extractable format. Kept exhaustive on purpose: a new `Format` variant
/// should be added here so its parser's error paths are fuzzed directly, without
/// the mutator having to synthesise valid magic bytes.
const ALL_FORMATS: &[Format] = &[
    Format::Zip,
    Format::Gzip,
    Format::Tar,
    Format::Bzip2,
    Format::Xz,
    Format::Cab,
    Format::Chm,
    Format::Ole,
    Format::Pdf,
    Format::Email,
    Format::SevenZip,
    Format::Iso,
    Format::Lha,
    Format::Arj,
    Format::Rar,
    Format::Upx,
    Format::Ar,
    Format::Cpio,
    Format::Xar,
    Format::Dmg,
    Format::Zstd,
    Format::Lzip,
    Format::Uuencode,
    Format::Xdp,
    Format::Szdd,
    Format::Tnef,
    Format::Swf,
    Format::Binhex,
    Format::Lnk,
    Format::Partition,
    Format::Pyc,
    Format::Nsis,
    Format::Machofat,
    Format::Sfx,
    Format::Autoit,
    Format::OneNote,
    Format::Rtf,
    Format::PePacked,
    Format::JavaClass,
    Format::AiModel,
    Format::Screnc,
];

fuzz_target!(|data: &[u8]| {
    for &fmt in ALL_FORMATS {
        // Candidate passwords exercise the decryption paths (7z AES, ZipCrypto,
        // WinZip-AES, PDF/DMG); harmless for every other format.
        let mut budget = Budget::with_passwords(
            TIGHT_LIMITS,
            vec!["infected".to_string(), "hunter2".to_string()],
        );
        let _ = extract(fmt, data, &mut budget);
    }
});
