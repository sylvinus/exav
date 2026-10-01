//! Solid and multi-volume RAR archives.
//!
//! **Solid** is WinRAR's own default for `-s` and is what "Best" compression
//! produces, so it is the ordinary shape rather than an exotic one. The files in
//! a solid group are compressed as a single continuous stream: each member has
//! its own packed byte range and its own restarted bit reader, but the sliding
//! window, the Huffman tables and the PPMd model carry over from the member
//! before it.
//!
//! The failure mode that makes this worth testing is not an error. Decoding a
//! solid member against a fresh window **succeeds** and produces bytes — just
//! not the file's bytes. A signature that does not match garbage looks exactly
//! like a clean file, so these tests assert the decoded content, not merely that
//! decoding did not fail.
//!
//! **Multi-volume** members are the other half: a member split across
//! `.partN.rar` files has only part of its compressed data in any one of them,
//! and exav scans one file at a time. Those must be reported, never passed over.
//!
//! Fixtures were produced by **official RAR** (6.12 for RAR4, 7.23 for RAR5) and
//! the expected digests are of the original input files. RAR records a CRC-32
//! per member, which exav checks on every decode, so a fixture that decoded
//! wrongly could not reach the digest comparison in the first place.
//!
//! Regenerate with:
//! ```sh
//! rar a -ma4 -s -m3 -ep solid_rar4.rar one.txt two.txt three.txt eicar.com
//! rar a      -s -m3 -ep solid_rar5.rar one.txt two.txt three.txt eicar.com
//! rar a -ma4 -v4k -m3 -ep vol_rar4.rar one.txt eicar.com
//! ```

use super::extract_each;
use exav_unpack::{Budget, Entry, Format, Limits};

/// `sha256sum` of the files that went into the archives.
const ONE: &str = "30c2abfccdf15a28990bae7bb0efa2444d82af3ce7053ff493956ef9612f775d";
const TWO: &str = "41525b841bca7b5fbb85847bc9d0aab87c98d984a9b90a821e2c36081c84cc4b";
const THREE: &str = "5a78cb6ca1e22248ee58290f692000fdba3b41fa4fa35266d5a4055c07231776";
const EICAR: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

fn fixture(name: &str) -> Vec<u8> {
    let p = format!(
        "{}/tests/fixtures/rar_solid/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    exav_unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn members(blob: &[u8]) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut limits = Limits::default();
    limits.max_buffer_bytes = 8 * 1024 * 1024;
    limits.max_extracted_bytes = 16 * 1024 * 1024;
    let mut b = Budget::new(limits);
    let _ = extract_each(
        Format::Rar,
        blob,
        &mut b,
        &mut |e: Entry, _: &mut Budget| {
            out.push(e);
            None::<()>
        },
    );
    out
}

/// Every member decoded, keyed by name, with nothing reported unreadable.
fn decoded(name: &str) -> Vec<(String, String)> {
    let e = members(&fixture(name));
    assert!(
        e.iter().all(|x| x.unsupported.is_none()),
        "{name}: every member of a solid group must decode, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
    let mut got: Vec<(String, String)> = e
        .iter()
        .map(|x| (x.name.clone(), sha256_hex(&x.data)))
        .collect();
    got.sort();
    got
}

fn expected() -> Vec<(String, String)> {
    let mut want = vec![
        ("eicar.com".to_string(), EICAR.to_string()),
        ("one.txt".to_string(), ONE.to_string()),
        ("three.txt".to_string(), THREE.to_string()),
        ("two.txt".to_string(), TWO.to_string()),
    ];
    want.sort();
    want
}

#[test]
fn a_solid_rar4_group_decodes_every_member() {
    assert_eq!(
        decoded("solid_rar4.rar"),
        expected(),
        "each member after the first is decoded against the window its \
         predecessor left behind; getting that wrong yields plausible bytes \
         that are not the file"
    );
}

#[test]
fn a_solid_rar5_group_decodes_every_member() {
    assert_eq!(decoded("solid_rar5.rar"), expected());
}

#[test]
fn a_member_split_across_volumes_is_reported() {
    // Only part of `one.txt`'s compressed data is in this volume; the rest is in
    // a sibling file exav is not scanning. It cannot be decoded from here, so it
    // must be surfaced rather than skipped.
    let e = members(&fixture("vol_rar4.part01.rar"));
    assert!(
        e.iter()
            .any(|x| x.unsupported == Some("RAR member continues in another volume")),
        "a split member must be reported as such, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
}

#[test]
fn a_whole_member_in_a_later_volume_still_decodes() {
    // The last volume holds a member entirely, so the volume set must not make
    // the whole file unreadable.
    let e = members(&fixture("vol_rar4.part03.rar"));
    let eicar = e
        .iter()
        .find(|x| x.name.ends_with("eicar.com"))
        .unwrap_or_else(|| {
            panic!(
                "expected a decodable member, got {:?}",
                e.iter().map(|x| &x.name).collect::<Vec<_>>()
            )
        });
    assert_eq!(sha256_hex(&eicar.data), EICAR);
}

#[test]
fn a_member_that_decodes_to_the_wrong_bytes_is_not_passed_off_as_content() {
    // Corrupting a solid member's packed data makes the decoder produce
    // *something* rather than fail. The CRC RAR records is what distinguishes
    // "decoded" from "decoded correctly", and it is checked in every build — a
    // member that fails it must be reported, not handed over as the file.
    let mut raw = fixture("solid_rar4.rar");
    // Scribble over the middle of the archive body, well past the headers.
    let mid = raw.len() / 2;
    for b in &mut raw[mid..mid + 256] {
        *b ^= 0xFF;
    }

    let e = members(&raw);
    for m in &e {
        if m.unsupported.is_some() {
            continue;
        }
        let d = sha256_hex(&m.data);
        assert!(
            [ONE, TWO, THREE, EICAR].contains(&d.as_str()),
            "member {} was handed over with content matching no input file",
            m.name
        );
    }
    assert!(
        e.iter().any(|x| x.unsupported.is_some()),
        "corrupting the stream must leave something reported unreadable"
    );
}

/// `sha256sum` of the inputs of the `rar_volumes` sets.
const TEXT: &str = "306e49d40e25318b97ad7628011238f0ed6af09880396518cd5a8e1cbe7efe19";
const NOISE: &str = "6987decf3255b53b0f8cf0da45aafacce4294578716058e11cd018a18e57035e";

/// Sets written by official RAR, each with `noise.bin` split across all three
/// of its volumes, joined and decoded. The inputs are made with:
/// ```python
/// r = random.Random(20261001)
/// open("text.txt", "w").write("".join(f"line {i}: the quick brown fox {r.randrange(10**6)}\n" for i in range(400)))
/// open("noise.bin", "wb").write(bytes(r.randrange(256) for _ in range(20000)))
/// ```
/// and the sets with RAR 7.23 (RAR5, which ends every volume with a
/// quick-open record) and RAR 6.12 (RAR4, old-style names):
/// ```sh
/// rar a -ma5 -m3 -v8k -ep set5.rar text.txt noise.bin
/// rar a -ma4 -m3 -vn -v8k -ep set4.rar text.txt noise.bin
/// ```
#[test]
fn a_real_volume_set_joins_into_its_archive() {
    for parts in [
        ["set5.part1.rar", "set5.part2.rar", "set5.part3.rar"],
        ["set4.rar", "set4.r00", "set4.r01"],
    ] {
        let vols: Vec<Vec<u8>> = parts
            .iter()
            .map(|p| fixture(&format!("../rar_volumes/{p}")))
            .collect();
        let refs: Vec<&[u8]> = vols.iter().map(Vec::as_slice).collect();
        let joined =
            exav_unpack::join_rar_volumes(&refs).unwrap_or_else(|e| panic!("{}: {e}", parts[0]));
        // Each RAR5 volume's quick-open record (a service header named `QO`,
        // its name length before it) indexes that volume alone, and is left
        // out of the join.
        let qo = |b: &[u8]| b.windows(3).filter(|w| w == b"\x02QO").count();
        if parts[0].starts_with("set5") {
            assert!(vols.iter().all(|v| qo(v) == 1));
            assert_eq!(qo(&joined), 0);
        }
        let mut got: Vec<(String, String)> = members(&joined)
            .iter()
            .map(|x| {
                assert!(
                    x.unsupported.is_none(),
                    "{}: {} {:?}",
                    parts[0],
                    x.name,
                    x.unsupported
                );
                (x.name.clone(), sha256_hex(&x.data))
            })
            .collect();
        got.sort();
        assert_eq!(
            got,
            [
                ("noise.bin".to_string(), NOISE.to_string()),
                ("text.txt".to_string(), TEXT.to_string())
            ],
            "{}",
            parts[0]
        );
        // Each volume alone reports the split member, never passes it over.
        for v in &vols {
            assert!(
                members(v)
                    .iter()
                    .any(|x| x.name == "noise.bin" && x.unsupported.is_some()),
                "{}: a lone volume",
                parts[0]
            );
        }
    }
}
