//! Microsoft Script Encoder (`#@~^`) decoder — VBScript.Encode / JScript.Encode.
//!
//! `screnc.exe` (and the `Scripting.Encoder` COM object) wraps a plaintext
//! script into an opaque blob so the payload is not visible at rest. The blob is
//!
//! ```text
//! #@~^<6-char length>==<encoded body><6-char checksum>==^#~@
//! ```
//!
//! Malware ships this form as `.vbe` / `.jse`, or embedded inside `.hta` / HTML
//! `<script language="VBScript.Encode">` blocks; the real payload
//! (`CreateObject("WScript.Shell")`, downloaded URLs, `eval`, …) only appears
//! once decoded. This handler finds every such blob, decodes it, and surfaces
//! the recovered plaintext as a `screnc-decoded` member so signatures match the
//! *decoded* script.
//!
//! # Algorithm
//!
//! The encoding is a fixed, published substitution (no key). Each decodable
//! byte maps to one of three possible plaintext bytes, chosen by a rotating
//! "pick" index that advances once per consumed byte and cycles through a fixed
//! 64-entry sequence. A handful of characters are escape-encoded (`@&`→LF,
//! `@#`→CR, `@*`→`>`, `@!`→`<`, `@$`→`@`), and `<`/`>`/`@` plus control bytes
//! pass through literally while still advancing the pick index.
//!
//! The decode/combination tables are the authentic published ones (Didier
//! Stevens' public-domain `decode-vbe.py`, equivalently the classic `scrdec`
//! algorithm). Every index is bounds-checked; truncated or hostile input yields
//! whatever decoded cleanly (or nothing) and never panics — the crate is
//! `#![forbid(unsafe_code)]`.

use crate::*;

/// Blob start marker.
const MARKER: &[u8] = b"#@~^";
/// Blob end marker.
const TERMINATOR: &[u8] = b"^#~@";
/// Bytes between the marker and the encoded body: `<6-char length>` + `==`.
const HEADER_EXTRA: usize = 6 + 2;
/// Trailing footer stripped from the body's tail: `<6-char checksum>` + `==`.
const FOOTER_LEN: usize = 6 + 2;

/// Rotating pick sequence: 64 entries, each selecting column 0/1/2 of `DECODE`.
const COMBINATION: [usize; 64] = [
    0, 1, 2, 0, 1, 2, 1, 2, 2, 1, 2, 1, 0, 2, 1, 2, 0, 2, 1, 2, 0, 0, 1, 2, 2, 1, 0, 2, 1, 2, 2, 1,
    0, 0, 2, 1, 2, 1, 2, 0, 2, 0, 0, 1, 2, 0, 2, 1, 0, 2, 1, 2, 0, 0, 1, 2, 2, 0, 0, 1, 2, 0, 2, 1,
];

/// Decode table: `DECODE[b]` holds the three candidate plaintext bytes for an
/// encoded byte `b` (0..128). Rows `0..9` are unused (never selected by the
/// decode predicate) and left zero. Authentic published values.
#[rustfmt::skip]
const DECODE: [[u8; 3]; 128] = [
    [0x00, 0x00, 0x00], // 0
    [0x00, 0x00, 0x00], // 1
    [0x00, 0x00, 0x00], // 2
    [0x00, 0x00, 0x00], // 3
    [0x00, 0x00, 0x00], // 4
    [0x00, 0x00, 0x00], // 5
    [0x00, 0x00, 0x00], // 6
    [0x00, 0x00, 0x00], // 7
    [0x00, 0x00, 0x00], // 8
    [0x57, 0x6e, 0x7b], // 9
    [0x4a, 0x4c, 0x41], // 10
    [0x0b, 0x0b, 0x0b], // 11
    [0x0c, 0x0c, 0x0c], // 12
    [0x4a, 0x4c, 0x41], // 13
    [0x0e, 0x0e, 0x0e], // 14
    [0x0f, 0x0f, 0x0f], // 15
    [0x10, 0x10, 0x10], // 16
    [0x11, 0x11, 0x11], // 17
    [0x12, 0x12, 0x12], // 18
    [0x13, 0x13, 0x13], // 19
    [0x14, 0x14, 0x14], // 20
    [0x15, 0x15, 0x15], // 21
    [0x16, 0x16, 0x16], // 22
    [0x17, 0x17, 0x17], // 23
    [0x18, 0x18, 0x18], // 24
    [0x19, 0x19, 0x19], // 25
    [0x1a, 0x1a, 0x1a], // 26
    [0x1b, 0x1b, 0x1b], // 27
    [0x1c, 0x1c, 0x1c], // 28
    [0x1d, 0x1d, 0x1d], // 29
    [0x1e, 0x1e, 0x1e], // 30
    [0x1f, 0x1f, 0x1f], // 31
    [0x2e, 0x2d, 0x32], // 32
    [0x47, 0x75, 0x30], // 33
    [0x7a, 0x52, 0x21], // 34
    [0x56, 0x60, 0x29], // 35
    [0x42, 0x71, 0x5b], // 36
    [0x6a, 0x5e, 0x38], // 37
    [0x2f, 0x49, 0x33], // 38
    [0x26, 0x5c, 0x3d], // 39
    [0x49, 0x62, 0x58], // 40
    [0x41, 0x7d, 0x3a], // 41
    [0x34, 0x29, 0x35], // 42
    [0x32, 0x36, 0x65], // 43
    [0x5b, 0x20, 0x39], // 44
    [0x76, 0x7c, 0x5c], // 45
    [0x72, 0x7a, 0x56], // 46
    [0x43, 0x7f, 0x73], // 47
    [0x38, 0x6b, 0x66], // 48
    [0x39, 0x63, 0x4e], // 49
    [0x70, 0x33, 0x45], // 50
    [0x45, 0x2b, 0x6b], // 51
    [0x68, 0x68, 0x62], // 52
    [0x71, 0x51, 0x59], // 53
    [0x4f, 0x66, 0x78], // 54
    [0x09, 0x76, 0x5e], // 55
    [0x62, 0x31, 0x7d], // 56
    [0x44, 0x64, 0x4a], // 57
    [0x23, 0x54, 0x6d], // 58
    [0x75, 0x43, 0x71], // 59
    [0x4a, 0x4c, 0x41], // 60
    [0x7e, 0x3a, 0x60], // 61
    [0x4a, 0x4c, 0x41], // 62
    [0x5e, 0x7e, 0x53], // 63
    [0x40, 0x4c, 0x40], // 64
    [0x77, 0x45, 0x42], // 65
    [0x4a, 0x2c, 0x27], // 66
    [0x61, 0x2a, 0x48], // 67
    [0x5d, 0x74, 0x72], // 68
    [0x22, 0x27, 0x75], // 69
    [0x4b, 0x37, 0x31], // 70
    [0x6f, 0x44, 0x37], // 71
    [0x4e, 0x79, 0x4d], // 72
    [0x3b, 0x59, 0x52], // 73
    [0x4c, 0x2f, 0x22], // 74
    [0x50, 0x6f, 0x54], // 75
    [0x67, 0x26, 0x6a], // 76
    [0x2a, 0x72, 0x47], // 77
    [0x7d, 0x6a, 0x64], // 78
    [0x74, 0x39, 0x2d], // 79
    [0x54, 0x7b, 0x20], // 80
    [0x2b, 0x3f, 0x7f], // 81
    [0x2d, 0x38, 0x2e], // 82
    [0x2c, 0x77, 0x4c], // 83
    [0x30, 0x67, 0x5d], // 84
    [0x6e, 0x53, 0x7e], // 85
    [0x6b, 0x47, 0x6c], // 86
    [0x66, 0x34, 0x6f], // 87
    [0x35, 0x78, 0x79], // 88
    [0x25, 0x5d, 0x74], // 89
    [0x21, 0x30, 0x43], // 90
    [0x64, 0x23, 0x26], // 91
    [0x4d, 0x5a, 0x76], // 92
    [0x52, 0x5b, 0x25], // 93
    [0x63, 0x6c, 0x24], // 94
    [0x3f, 0x48, 0x2b], // 95
    [0x7b, 0x55, 0x28], // 96
    [0x78, 0x70, 0x23], // 97
    [0x29, 0x69, 0x41], // 98
    [0x28, 0x2e, 0x34], // 99
    [0x73, 0x4c, 0x09], // 100
    [0x59, 0x21, 0x2a], // 101
    [0x33, 0x24, 0x44], // 102
    [0x7f, 0x4e, 0x3f], // 103
    [0x6d, 0x50, 0x77], // 104
    [0x55, 0x09, 0x3b], // 105
    [0x53, 0x56, 0x55], // 106
    [0x7c, 0x73, 0x69], // 107
    [0x3a, 0x35, 0x61], // 108
    [0x5f, 0x61, 0x63], // 109
    [0x65, 0x4b, 0x50], // 110
    [0x46, 0x58, 0x67], // 111
    [0x58, 0x3b, 0x51], // 112
    [0x31, 0x57, 0x49], // 113
    [0x69, 0x22, 0x4f], // 114
    [0x6c, 0x6d, 0x46], // 115
    [0x5a, 0x4d, 0x68], // 116
    [0x48, 0x25, 0x7c], // 117
    [0x27, 0x28, 0x36], // 118
    [0x5c, 0x46, 0x70], // 119
    [0x3d, 0x4a, 0x6e], // 120
    [0x24, 0x32, 0x7a], // 121
    [0x79, 0x41, 0x2f], // 122
    [0x37, 0x3d, 0x5f], // 123
    [0x60, 0x5f, 0x4b], // 124
    [0x51, 0x4f, 0x5a], // 125
    [0x20, 0x42, 0x2c], // 126
    [0x36, 0x65, 0x57], // 127
];

/// Decode one encoded body (the bytes between `#@~^...==` and the trailing
/// checksum footer). Fully bounds-checked; never panics on truncated input.
fn decode_body(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len());
    // Reference "pick" counter: advances once per byte < 128 (post-escape).
    let mut idx: usize = 0;
    let mut i = 0usize;
    while i < body.len() {
        let b = body[i];
        // Resolve escape sequences first; a lone `@` (or `@?` with an unknown
        // follower) is a literal `@`.
        let ch: u8 = if b == b'@' && i + 1 < body.len() {
            match body[i + 1] {
                b'&' => {
                    i += 2;
                    0x0A
                }
                b'#' => {
                    i += 2;
                    0x0D
                }
                b'*' => {
                    i += 2;
                    0x3E
                }
                b'!' => {
                    i += 2;
                    0x3C
                }
                b'$' => {
                    i += 2;
                    0x40
                }
                _ => {
                    i += 1;
                    b
                }
            }
        } else {
            i += 1;
            b
        };

        if (ch as usize) < 128 {
            let combo = COMBINATION[idx % 64];
            idx += 1;
            // Decodable range: TAB, or 0x20..0x7F excluding `<`, `>`, `@`.
            if (ch == 9 || (ch > 31)) && ch != 60 && ch != 62 && ch != 64 {
                out.push(DECODE[ch as usize][combo]);
            } else {
                out.push(ch);
            }
        } else {
            // Bytes >= 128 pass through and do not advance the pick counter.
            out.push(ch);
        }
    }
    out
}

/// True iff `data` contains the 4-byte `#@~^` Script Encoder marker.
pub(crate) fn looks_like_screnc(data: &[u8]) -> bool {
    memchr::memmem::find(data, MARKER).is_some()
}

/// Find every `#@~^ … ^#~@` blob, decode each, and emit the recovered plaintext
/// as a `screnc-decoded` member. Emits nothing if no blob decodes.
pub(crate) fn extract_screnc<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    let mut search_from = 0usize;
    while let Some(rel) = memchr::memmem::find(&data[search_from..], MARKER) {
        let marker_pos = search_from + rel;
        // Default: resume just past this marker so a malformed blob can't loop.
        search_from = marker_pos + MARKER.len();

        let body_start = marker_pos + MARKER.len() + HEADER_EXTRA;
        if body_start >= data.len() {
            continue;
        }
        // Locate the terminator; without one the blob is truncated — skip it.
        let term_rel = match memchr::memmem::find(&data[body_start..], TERMINATOR) {
            Some(t) => t,
            None => continue,
        };
        let term_pos = body_start + term_rel;
        // The 8 bytes before the terminator are the checksum footer.
        if term_pos < body_start + FOOTER_LEN {
            continue;
        }
        let body = &data[body_start..term_pos - FOOTER_LEN];
        if body.is_empty() {
            continue;
        }

        let decoded = decode_body(body);
        if decoded.is_empty() {
            continue;
        }

        budget.count_entry()?;
        let cap = budget.reserve()?;
        if decoded.len() as u64 > cap {
            return Err(LimitHit::new(
                "screnc decoded output exceeds budget".to_string(),
            ));
        }
        budget.commit(decoded.len() as u64);
        if let Some(r) = visit(Entry::new("screnc-decoded".into(), decoded), budget) {
            return Ok(Some(r));
        }

        // Continue past this blob to pick up any further concatenated blobs.
        search_from = term_pos + TERMINATOR.len();
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encoded blob produced by inverting the published table for the plaintext
    /// below, and confirmed to decode to that plaintext by the authentic
    /// public-domain reference decoder (Didier Stevens' `decode-vbe.py`). It
    /// exercises the substitution tables, the pick rotation, and the `@#`/`@&`
    /// (CR/LF) escapes.
    const REAL_VECTOR: &[u8] = b"\x23\x40\x7e\x5e\x41\x41\x41\x41\x41\x41\x3d\x3d\x6a\x7f\x59\x7e\x6b\x50\x7b\x50\x5a\x4d\x2b\x6d\x4f\x2b\x7d\x34\x25\x2b\x31\x59\x63\x45\x71\x3f\x6d\x4d\x72\x77\x44\x52\x3f\x34\x6e\x73\x56\x72\x23\x40\x23\x40\x26\x64\x52\x5d\x3b\x09\x50\x45\x6d\x6d\x73\x6d\x63\x2b\x61\x6e\x72\x40\x23\x40\x26\x6e\x2d\x6d\x56\x63\x4a\x38\x51\x38\x4a\x62\x40\x23\x40\x26\x42\x42\x42\x42\x42\x42\x3d\x3d\x5e\x23\x7e\x40";

    const EXPECTED_PLAINTEXT: &[u8] =
        b"Set s = CreateObject(\"WScript.Shell\")\r\ns.Run \"calc.exe\"\r\neval(\"1+1\")\r\n";

    #[test]
    fn decodes_real_published_vector() {
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Screnc, REAL_VECTOR, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "screnc-decoded");
        assert_eq!(
            entries[0].data,
            EXPECTED_PLAINTEXT,
            "decoded plaintext mismatch: {:?}",
            String::from_utf8_lossy(&entries[0].data)
        );
        // Spot-check the malware-relevant substrings survive intact.
        assert!(entries[0].data.windows(13).any(|w| w == b"CreateObject("));
    }

    #[test]
    fn looks_like_screnc_detects_marker() {
        assert!(looks_like_screnc(REAL_VECTOR));
        assert!(looks_like_screnc(b"junk#@~^stuff"));
        assert!(!looks_like_screnc(b"MsgBox \"hello, world\"\r\n"));
        assert!(!looks_like_screnc(b""));
    }

    #[test]
    fn truncated_blob_does_not_panic() {
        // Marker + partial header/body but no `^#~@` terminator.
        let blob = b"#@~^AAAAAA==\x6a\x7f\x59\x7e\x6b\x50";
        assert!(looks_like_screnc(blob));
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Screnc, blob, &mut budget).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn marker_only_does_not_panic() {
        let blob = b"#@~^";
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Screnc, blob, &mut budget).unwrap();
        assert!(entries.is_empty());
    }
}
