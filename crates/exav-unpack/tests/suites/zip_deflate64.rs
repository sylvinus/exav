//! ZIP compression method 9 — Deflate64 ("enhanced deflate").
//!
//! ClamAV decodes method 9, so under the drop-in-replacement rule exav must too:
//! before this, a Deflate64 member fell through `decode_zip_raw` and surfaced as
//! `UNSCANNABLE`, i.e. a payload behind it was never scanned. It is not an exotic
//! codec either — 7-Zip writes it with `-mm=Deflate64` and Windows' own
//! compressed-folder writer emits it, so a victim opens the archive normally
//! while a scanner that skips the codec sees nothing.
//!
//! Deflate64 differs from deflate in exactly three places, and a decoder that
//! gets any of them wrong emits *plausible bytes, not errors* — so the fixtures
//! are chosen to force each one:
//!
//! * **64 KiB window / distance codes 30 and 31** (14 extra bits, distances up to
//!   64 KiB) — `eicar_deflate64.zip`. Its source repeats an ~11 KB section only
//!   after >32 KiB of filler, so the encoder can only compress the repeat with a
//!   back-reference plain deflate cannot express: the stream uses distance codes
//!   30/31 43 times, at distances up to 60028. Confirmed out-of-band by feeding
//!   the raw member to zlib's *plain* inflate, which rejects it.
//! * **Length code 285 redefined** — 16 extra bits, lengths 3..65538, instead of
//!   deflate's fixed 258. `deflate64_len285.zip` covers this, and it had to be
//!   hand-built: 7-Zip's Deflate64 *encoder* never emits code 285, so no
//!   7z-produced archive exercises it. The stream carries a 65538-byte match (the
//!   maximum) plus a 40000-byte match at distance 50000.
//!
//! **The oracle is never exav itself.** Expected content is pinned by CRC-32
//! values computed by 7-Zip, an independent C++ implementation: `FD9E0382` is the
//! CRC 7-Zip stored for `payload.txt` when it created the archive, and `3EFA5A88`
//! is the CRC of the bytes `7z x` produced from the hand-built stream.
//!
//! **What this does NOT cover:** stored (BTYPE=0) blocks inside a Deflate64
//! member, dynamic-Huffman trees that assign codes 30/31 explicitly rather than
//! via the fixed table, and truncated/corrupt streams. Those were covered
//! out-of-band by round-tripping five files (69 B to 1 MB, text and binary,
//! repetitive and high-entropy) through `7z a -tzip -mm=Deflate64` and comparing
//! exav's output byte-for-byte against the originals.

use exav_unpack::{extract, Budget, Format, Limits};

const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR";

fn fixture(name: &str) -> Vec<u8> {
    let p = format!("{}/tests/fixtures/zip/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

/// CRC-32/IEEE, so the expected content can be pinned to a value produced by an
/// independent implementation without a dev-dependency.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & (0u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}

fn only_member(blob: &[u8]) -> exav_unpack::Entry {
    let mut budget = Budget::new(Limits::default());
    let mut entries = extract(Format::Zip, blob, &mut budget).expect("extract");
    assert_eq!(entries.len(), 1, "expected exactly one member");
    let e = entries.remove(0);
    assert!(
        e.unsupported.is_none(),
        "member {} reported unsupported ({:?}) — method 9 was not decoded",
        e.name,
        e.unsupported
    );
    e
}

/// A Deflate64 member using the 64 KiB window (distance codes 30/31) decodes
/// byte-exactly, and the EICAR string inside it is present to be matched.
#[test]
fn deflate64_extended_window_member_is_decoded() {
    let e = only_member(&fixture("eicar_deflate64.zip"));
    assert_eq!(e.name, "payload.txt");
    assert_eq!(e.data.len(), 180153, "decoded length differs");
    assert_eq!(
        crc32(&e.data),
        0xFD9E_0382,
        "decoded bytes differ from the 7-Zip oracle"
    );
    assert!(
        e.data.windows(EICAR.len()).any(|w| w == EICAR),
        "EICAR inside a Deflate64 member must be present for the scanner to match"
    );
}

/// Length code 285 with its 16 extra bits (a 65538-byte match) and a 50000-byte
/// distance decode byte-exactly. Reading 285 as deflate's fixed length 258 would
/// still produce output — just the wrong output — so this is checked against the
/// bytes 7-Zip's decoder produced from the same archive, not against exav.
#[test]
fn deflate64_long_length_code_285_is_decoded() {
    let e = only_member(&fixture("deflate64_len285.zip"));
    assert_eq!(e.name, "long_match.bin");
    assert_eq!(
        e.data.len(),
        106797,
        "length code 285 must mean 3 + 16 extra bits, not deflate's fixed 258"
    );
    assert_eq!(
        crc32(&e.data),
        0x3EFA_5A88,
        "decoded bytes differ from the 7-Zip oracle"
    );
}
