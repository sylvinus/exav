//! EGG decoded against real archives, with the format's own CRC-32 as oracle.
//!
//! Every EGG block records a CRC-32 of its *decompressed* bytes, written by
//! ESTsoft's compressor. A decoder that produces plausible-but-wrong output —
//! the failure mode this project cares about, because it is silent — cannot
//! match it. So `Entry::new` here means "these bytes reproduce the checksum the
//! writer recorded", not "our decoder is happy with itself".
//!
//! Fixtures are from the MIT-licensed `EggDotNet` test corpus.

#![cfg(feature = "egg")]

use exav_unpack::{extract_each, Budget, Entry, Format, Limits};

fn members(blob: &[u8]) -> Vec<Entry> {
    let mut budget = Budget::new(Limits::default());
    let mut out = Vec::new();
    let _ = extract_each::<()>(
        Format::Egg,
        blob,
        &mut budget,
        &mut |e: Entry, _: &mut Budget| {
            out.push(e);
            None
        },
    );
    out
}

macro_rules! fixture {
    ($name:literal) => {
        include_bytes!(concat!("../fixtures/egg/", $name))
    };
}

/// Every fixture, so a regression in one cannot hide behind another.
fn corpus() -> Vec<(&'static str, &'static [u8])> {
    vec![
        ("posix_small", fixture!("posix_small.egg")),
        ("azoshort_txt", fixture!("azoshort_txt.egg")),
        ("directories", fixture!("directories.egg")),
        ("extattr", fixture!("extattr.egg")),
        ("globalcomment", fixture!("globalcomment.egg")),
        ("globalencrypt", fixture!("globalencrypt.egg")),
        ("lorem_long_aes128", fixture!("lorem_long_aes128.egg")),
        (
            "lorem_short_readonlyhidden",
            fixture!("lorem_short_readonlyhidden.egg"),
        ),
        ("lzma_simple", fixture!("lzma_simple.egg")),
        ("solid", fixture!("solid.egg")),
    ]
}

#[test]
fn every_fixture_is_recognised_as_egg() {
    for (name, blob) in corpus() {
        assert_eq!(
            exav_unpack::detect(blob),
            Some(Format::Egg),
            "{name} was not recognised"
        );
    }
}

#[test]
fn no_fixture_scans_clean() {
    // The invariant that matters most: whatever exav cannot decode, it says so.
    // An archive that yields nothing at all is indistinguishable from an empty
    // one, which is how a packed payload gets through.
    for (name, blob) in corpus() {
        let m = members(blob);
        assert!(!m.is_empty(), "{name}: produced no members at all");
        assert!(
            m.iter()
                .any(|e| !e.data.is_empty() || e.unsupported.is_some()),
            "{name}: every member was empty and unexplained: {:?}",
            m.iter().map(|e| &e.name).collect::<Vec<_>>()
        );
    }
}

#[test]
fn a_deflate_member_decodes_to_its_recorded_checksum() {
    // `Entry::new` is only produced on a CRC match, so reaching one at all is
    // the assertion — the decode agreed with ESTsoft's compressor.
    let m = members(fixture!("posix_small.egg"));
    let decoded: Vec<&Entry> = m.iter().filter(|e| e.unsupported.is_none()).collect();
    assert!(
        !decoded.is_empty(),
        "no member survived the CRC check: {:?}",
        m.iter()
            .map(|e| (&e.name, e.unsupported))
            .collect::<Vec<_>>()
    );
    assert!(
        decoded.iter().any(|e| e.name.contains("posix")),
        "expected the archive's named member: {:?}",
        decoded.iter().map(|e| &e.name).collect::<Vec<_>>()
    );
}

#[test]
fn lzma_members_decode_to_their_recorded_checksums() {
    // LZMA blocks open with a codec record the spec does not document, so this
    // is the case most likely to silently regress into "reported, not decoded".
    let m = members(fixture!("lzma_simple.egg"));
    let decoded: Vec<(&String, usize)> = m
        .iter()
        .filter(|e| e.unsupported.is_none())
        .map(|e| (&e.name, e.data.len()))
        .collect();
    assert_eq!(
        decoded.len(),
        2,
        "both LZMA members must survive the CRC check, got {:?}",
        m.iter()
            .map(|e| (&e.name, e.unsupported))
            .collect::<Vec<_>>()
    );
    assert!(
        decoded.iter().any(|(_, len)| *len > 30_000),
        "the large member must decompress in full, got {decoded:?}"
    );
}

#[test]
fn every_decoded_member_is_non_empty() {
    // A zero-length `Entry::new` would mean the CRC matched an empty decode —
    // which is how a decoder that quietly produces nothing still looks green.
    for (name, blob) in corpus() {
        for e in members(blob) {
            if e.unsupported.is_none() {
                assert!(
                    !e.data.is_empty(),
                    "{name}: '{}' decoded to nothing yet reported success",
                    e.name
                );
            }
        }
    }
}

#[test]
fn an_encrypted_archive_reports_rather_than_yielding_plaintext() {
    for name in ["globalencrypt.egg", "lorem_long_aes128.egg"] {
        let blob: &[u8] = match name {
            "globalencrypt.egg" => fixture!("globalencrypt.egg"),
            _ => fixture!("lorem_long_aes128.egg"),
        };
        let m = members(blob);
        assert!(
            m.iter().all(|e| e.data.is_empty()),
            "{name}: no plaintext may be produced for an encrypted archive: {:?}",
            m.iter()
                .map(|e| (&e.name, e.data.len()))
                .collect::<Vec<_>>()
        );
        assert!(
            m.iter().any(|e| e.unsupported.is_some()),
            "{name}: must be reported, not silently empty"
        );
    }
}

#[test]
fn an_azo_member_decodes_to_its_recorded_checksum() {
    // AZO is ESTsoft's own algorithm, absent from their published spec and
    // decodable only via a from-scratch port. The CRC-32 is what separates
    // "decoded" from "produced plausible bytes": this member is only ever
    // handed on as content because it reproduces the checksum ESTsoft's
    // compressor wrote.
    let m = members(fixture!("azoshort_txt.egg"));
    let decoded: Vec<&Entry> = m.iter().filter(|e| e.unsupported.is_none()).collect();
    assert_eq!(
        decoded.len(),
        1,
        "the AZO member must survive the CRC check: {:?}",
        m.iter()
            .map(|e| (&e.name, e.unsupported))
            .collect::<Vec<_>>()
    );
    let text = String::from_utf8_lossy(&decoded[0].data);
    assert!(
        text.contains("This is some text."),
        "AZO output is not the archived document: {text:?}"
    );
    assert_eq!(decoded[0].data.len(), 128);
}
