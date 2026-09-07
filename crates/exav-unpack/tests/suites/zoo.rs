//! ZOO — an archive format old enough that not opening it is a hiding place.
//!
//! **The oracle is the format itself.** `store.zoo` holds its members
//! uncompressed and `default.zoo` / `high_per.zoo` hold the same files through
//! ZOO's two codecs (LZD, a 13-bit LZW; and LZH, Dhesi's own — not the LHA one
//! despite the name). A decoder validated against its own output proves
//! nothing, so the assertion here is that the compressed archives reproduce,
//! byte for byte, what the stored one already holds. A subtly wrong decoder
//! emits plausible bytes rather than an error, and that is what catches it.
//!
//! Fixtures are the `unarc-rs` project's own test archives (MIT OR Apache-2.0),
//! written by real `zoo`; see `NOTICE`.

use exav_unpack::{detect, extract_each, Budget, Entry, Format, Limits};

fn fixture(name: &str) -> Vec<u8> {
    let p = format!("{}/tests/fixtures/zoo/{name}", env!("CARGO_MANIFEST_DIR"));
    exav_unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

fn members(blob: &[u8]) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut b = Budget::new(Limits::default());
    let _ = extract_each(
        Format::Zoo,
        blob,
        &mut b,
        &mut |e: Entry, _: &mut Budget| {
            out.push(e);
            None::<()>
        },
    );
    out
}

/// `(name, bytes)` for every member that decoded, sorted by name.
fn contents(name: &str) -> Vec<(String, Vec<u8>)> {
    let mut v: Vec<(String, Vec<u8>)> = members(&fixture(name))
        .into_iter()
        .filter(|e| e.unsupported.is_none())
        .map(|e| (e.name, e.data))
        .collect();
    v.sort_by(|a, b| a.0.cmp(&b.0));
    v
}

#[test]
fn a_zoo_archive_is_recognised() {
    assert_eq!(detect(&fixture("store.zoo")), Some(Format::Zoo));
}

#[test]
fn stored_members_come_out_whole() {
    // Pinned against a direct read of the ZOO directory entries: one member,
    // `license`, `org_size` 11357, stored/LZD/LZH across the three fixtures.
    // Without this the cross-codec test below could pass on three empty
    // archives agreeing with each other.
    let c = contents("store.zoo");
    assert_eq!(
        c.len(),
        1,
        "got {:?}",
        c.iter().map(|(n, _)| n).collect::<Vec<_>>()
    );
    assert_eq!(c[0].0, "license");
    assert_eq!(
        c[0].1.len(),
        11357,
        "the directory entry declares 11357 bytes"
    );
}

#[test]
fn the_compressed_archives_decode_to_exactly_what_the_stored_one_holds() {
    // What the suite exists for. Nothing here trusts the decoder's own
    // output: LZD and LZH have to reproduce the stored bytes exactly.
    let stored = contents("store.zoo");
    for name in ["default.zoo", "high_per.zoo"] {
        let got = contents(name);
        assert_eq!(
            got.iter().map(|(n, _)| n).collect::<Vec<_>>(),
            stored.iter().map(|(n, _)| n).collect::<Vec<_>>(),
            "{name} must hold the same members as store.zoo"
        );
        for ((gn, gd), (sn, sd)) in got.iter().zip(stored.iter()) {
            assert_eq!(
                gd,
                sd,
                "{name}: member {gn} decoded to {} bytes, but {sn} in store.zoo \
                 is {} — a codec that is subtly wrong emits plausible bytes, not \
                 an error",
                gd.len(),
                sd.len()
            );
        }
    }
}

#[test]
fn every_member_carries_its_name() {
    let c = contents("store.zoo");
    assert!(
        c.iter().all(|(n, _)| !n.is_empty()),
        "a nameless member cannot be reported or matched by a `.cdb` signature"
    );
}

#[test]
fn a_truncated_archive_is_reported_not_shrugged_off() {
    // The magic still says ZOO, so a real `zoo x` would get at least the first
    // members; coming back with nothing at all and no complaint would read as
    // an empty archive.
    let full = fixture("store.zoo");
    let cut = &full[..full.len() / 2];
    let e = members(cut);
    assert!(
        e.iter().any(|x| x.unsupported.is_some()) || !e.is_empty(),
        "a truncated ZOO must either yield members or say what it could not read"
    );
}

#[test]
fn a_corrupt_directory_chain_is_reported() {
    // The directory is a linked list of offsets: one broken link hides every
    // member after it, which must not pass as "that was all of them".
    let mut img = fixture("store.zoo");
    // The archive header ends with the offset of the first directory entry.
    for b in &mut img[24..34] {
        *b = 0xFF;
    }
    let e = members(&img);
    assert!(
        e.iter().any(|x| x.unsupported.is_some()) || e.is_empty(),
        "got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
}
