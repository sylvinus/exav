//! Unix `compress` (`.Z`) decoding, validated against the real thing.
//!
//! The fixtures under `tests/fixtures/lzw/` were produced by **ncompress 5.0**
//! (the maintained `compress(1)`), not by any code in this repository. That
//! matters: a round-trip against an encoder written alongside the decoder proves
//! only that the two agree with each other, and would pass happily if both
//! misread the format in the same way. Every `.Z` here came out of the reference
//! implementation, so a disagreement is exav's.
//!
//! Regenerate with:
//! ```sh
//! for f in short repetitive widths bigreset eicar; do
//!   compress -b16 -c "$f.txt" > "$f.b16.Z"
//!   compress -b12 -c "$f.txt" > "$f.b12.Z"
//! done
//! ```

use exav_unpack::{extract_each, Budget, Entry, Format, Limits};

fn fixture(name: &str) -> Vec<u8> {
    let p = format!("{}/tests/fixtures/lzw/{name}", env!("CARGO_MANIFEST_DIR"));
    exav_unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

fn emitted(blob: &[u8]) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut b = Budget::new(Limits {
        max_buffer_bytes: 8 * 1024 * 1024,
        max_extracted_bytes: 8 * 1024 * 1024,
        ..Limits::default()
    });
    let _ = extract_each(
        Format::Lzw,
        blob,
        &mut b,
        &mut |e: Entry, _: &mut Budget| {
            out.push(e);
            None::<()>
        },
    );
    out
}

/// Decode a reference `.Z` and require it to match the original byte for byte.
fn matches_reference(stem: &str, bits: &str) {
    let z = fixture(&format!("{stem}.{bits}.Z"));
    let want = fixture(&format!("{stem}.txt"));
    assert_eq!(
        exav_unpack::detect(&z),
        Some(Format::Lzw),
        "{stem}.{bits}.Z must be detected as .Z"
    );
    let e = emitted(&z);
    let got = e
        .iter()
        .find(|x| x.unsupported.is_none())
        .unwrap_or_else(|| panic!("{stem}.{bits}: no decoded member, got {e:?}"));
    assert_eq!(
        got.data.len(),
        want.len(),
        "{stem}.{bits}: decoded {} bytes, reference is {}",
        got.data.len(),
        want.len()
    );
    assert!(
        got.data == want,
        "{stem}.{bits}: decoded bytes differ from the reference"
    );
}

#[test]
fn short_text_matches_reference() {
    matches_reference("short", "b16");
    matches_reference("short", "b12");
}

#[test]
fn repetitive_text_matches_reference() {
    // Long prefix chains and the KwKwK case, where a code refers to the entry
    // being defined by that very code.
    matches_reference("repetitive", "b16");
    matches_reference("repetitive", "b12");
}

#[test]
fn many_distinct_strings_match_reference() {
    // Pushes the code width through 9, 10, 11, 12 bits. Each change pads the
    // code stream to a group boundary, measured from a base that moves to the
    // previous padding point — get that wrong and the first few hundred bytes
    // still decode correctly before it silently drifts.
    matches_reference("widths", "b16");
    matches_reference("widths", "b12");
}

#[test]
fn a_stream_with_table_resets_matches_reference() {
    // 300 KB of varied data fills the table and makes real `compress` emit CLEAR
    // codes in block mode — which also pads the code stream to a whole group of
    // eight codes at the current width. Getting that padding wrong misaligns
    // every code afterwards. This is precisely the case a decoder and its
    // hand-written twin encoder would agree on and both get wrong.
    matches_reference("bigreset", "b16");
    matches_reference("bigreset", "b12");
}

#[test]
fn a_payload_inside_a_real_z_is_reachable() {
    let eicar = exav_unpack::eicar();
    for bits in ["b16", "b12"] {
        let e = emitted(&fixture(&format!("eicar.{bits}.Z")));
        assert!(
            e.iter()
                .any(|x| x.data.windows(eicar.len()).any(|w| w == eicar)),
            "the payload inside a real .Z must be reachable ({bits})"
        );
    }
}

#[test]
fn a_truncated_stream_keeps_what_decoded() {
    // A sequential stream that runs out of input: everything decoded before the
    // cut is returned, and that is honest — the missing tail is absent, not
    // hidden (docs/QUIRKS.md).
    let mut z = fixture("widths.b16.Z");
    let want = fixture("widths.txt");
    z.truncate(z.len() / 2);
    let e = emitted(&z);
    let got = e.iter().find(|x| x.unsupported.is_none());
    assert!(
        got.is_some_and(|g| !g.data.is_empty() && want.starts_with(&g.data)),
        "a truncated .Z must yield a prefix of the reference output, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported, x.data.len()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn an_oversized_stream_is_reported_not_truncated_silently() {
    // Decoding past the per-member budget must surface rather than hand back a
    // silently shortened member.
    let z = fixture("bigreset.b16.Z");
    let mut b = Budget::new(Limits {
        max_buffer_bytes: 4096,
        ..Limits::default()
    });
    let mut out = Vec::new();
    let _ = extract_each(Format::Lzw, &z, &mut b, &mut |e: Entry, _: &mut Budget| {
        out.push(e);
        None::<()>
    });
    assert!(
        out.iter().any(|x| x.unsupported.is_some()),
        "an over-budget .Z must be reported, got {:?}",
        out.iter()
            .map(|x| (&x.name, x.unsupported, x.data.len()))
            .collect::<Vec<_>>()
    );
}
