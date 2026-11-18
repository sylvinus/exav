//! A RAR whose block header does not parse is reported damaged.
//!
//! Where the next block starts is not known past a header the reader cannot
//! parse, so the walk ends there. It used to end without a word, and a marker
//! followed by zeros scanned clean. An archive cut by its end is another
//! matter: what is missing is absent, not hidden, and a clean prefix is OK.
//!
//! The archives are laid out by hand (the stored members, and the end block
//! the walk stops at); the checksums are not read by the walk.

use exav_core::{ScanOptions, Scanner, Verdict, analyze};

const RAR4: &[u8] = b"Rar!\x1a\x07\x00";
const RAR5: &[u8] = b"Rar!\x1a\x07\x01\x00";

fn vint(mut x: u64) -> Vec<u8> {
    let mut o = Vec::new();
    loop {
        let b = (x & 0x7f) as u8;
        x >>= 7;
        if x == 0 {
            o.push(b);
            return o;
        }
        o.push(b | 0x80);
    }
}

/// A RAR4 archive of one stored file, without its end block.
fn rar4_open(name: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut v = RAR4.to_vec();
    // The archive header, then the file's: PACK_SIZE doubles as the block's
    // ADD_SIZE.
    v.extend_from_slice(&[0, 0, 0x73, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0]);
    let mut fields = Vec::new();
    fields.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    fields.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    fields.push(0); // host OS
    fields.extend_from_slice(&[0; 8]); // CRC, time
    fields.extend_from_slice(&[20, 0x30]); // version, stored
    fields.extend_from_slice(&(name.len() as u16).to_le_bytes());
    fields.extend_from_slice(&[0; 4]); // attributes
    fields.extend_from_slice(name);
    v.extend_from_slice(&[0, 0, 0x74, 0x00, 0x80]);
    v.extend_from_slice(&((7 + fields.len()) as u16).to_le_bytes());
    v.extend(fields);
    v.extend_from_slice(payload);
    v
}

const RAR4_END: &[u8] = &[0x3d, 0x7b, 0x7b, 0x00, 0x40, 0x07, 0x00];

/// A RAR5 block: its checksum, which the walk does not read, the size of its
/// header and the header.
fn block5(content: Vec<u8>) -> Vec<u8> {
    [vec![0; 4], vint(content.len() as u64), content].concat()
}

/// A RAR5 file header of one stored file, whose `fields` come after its sizes.
fn file5(name: &[u8], payload: &[u8], fields: Option<Vec<u8>>) -> Vec<u8> {
    let mut c = [2, 0x02, payload.len() as u64].map(vint).concat();
    c.extend(fields.unwrap_or_else(|| {
        // File flags, unpacked size, attributes, stored, host OS, name.
        let mut f = [0, payload.len() as u64, 0, 0, 0, name.len() as u64]
            .map(vint)
            .concat();
        f.extend_from_slice(name);
        f
    }));
    [block5(c), payload.to_vec()].concat()
}

/// A RAR5 archive of one stored file, without its end block.
fn rar5_open(name: &[u8], payload: &[u8]) -> Vec<u8> {
    let main = block5([1, 0, 0].map(vint).concat());
    [RAR5.to_vec(), main, file5(name, payload, None)].concat()
}

fn rar5_end() -> Vec<u8> {
    block5([5, 0, 0].map(vint).concat())
}

fn verdict(data: &[u8]) -> Verdict {
    analyze(&Scanner::builtin(), data, &ScanOptions::default()).verdict
}

/// The reason of an `Unscannable` verdict, naming the damage.
fn damage(data: &[u8]) -> Option<String> {
    match verdict(data) {
        Verdict::Unscannable { reason } => Some(reason),
        _ => None,
    }
}

const BODY: &[u8] = b"nothing to see here, a plain stored file";

/// The archives themselves are clean: what follows is damage, not the format.
#[test]
fn the_archives_built_here_are_clean() {
    for arc in [
        [rar4_open(b"a.txt", BODY), RAR4_END.to_vec()].concat(),
        // Without its end block, ended by the end of the archive.
        rar4_open(b"a.txt", BODY),
        [rar5_open(b"a.txt", BODY), rar5_end()].concat(),
        rar5_open(b"a.txt", BODY),
    ] {
        assert_eq!(verdict(&arc), Verdict::Clean);
    }
}

#[test]
fn a_marker_followed_by_zeros_is_not_ok() {
    for marker in [RAR4, RAR5] {
        let arc = [marker.to_vec(), vec![0; 64 << 10]].concat();
        let why = damage(&arc).unwrap_or_else(|| panic!("{:?}", verdict(&arc)));
        assert!(why.contains("does not parse"), "{why}");
    }
}

/// Members before the damage are read, and the bytes after it are not: the
/// report says so, and an end block before them ends the walk as it did.
#[test]
fn damage_after_a_member_is_not_ok_and_an_end_block_before_it_is() {
    for (open, end) in [
        (rar4_open(b"a.txt", BODY), RAR4_END.to_vec()),
        (rar5_open(b"a.txt", BODY), rar5_end()),
    ] {
        let after = [open.clone(), vec![0; 64]].concat();
        let why = damage(&after).unwrap_or_else(|| panic!("{:?}", verdict(&after)));
        assert!(why.contains("does not parse"), "{why}");
        let ended = [open, end, vec![0; 64]].concat();
        assert_eq!(verdict(&ended), Verdict::Clean);
    }
}

/// A RAR5 header over the largest the format has is no header, whatever the
/// archive's size.
#[test]
fn a_rar5_header_over_the_largest_is_not_ok() {
    let arc = [rar5_open(b"a.txt", BODY), [0; 4].to_vec(), vint(5 << 20)].concat();
    let why = damage(&arc).unwrap_or_else(|| panic!("{:?}", verdict(&arc)));
    assert!(why.contains("does not parse"), "{why}");
}

/// A file header whose fields are no integers: the walk can go on to the
/// next block, and says the member was not read.
#[test]
fn a_rar5_file_header_whose_fields_do_not_parse_is_not_ok() {
    let main = block5([1, 0, 0].map(vint).concat());
    let file = file5(b"a.txt", BODY, Some(vec![0x80; 12]));
    let arc = [RAR5.to_vec(), main, file, rar5_end()].concat();
    let why = damage(&arc).unwrap_or_else(|| panic!("{:?}", verdict(&arc)));
    assert!(why.contains("file header does not parse"), "{why}");
}

/// What the archive's end cuts is absent, not hidden: nothing is reported.
#[test]
fn an_archive_cut_by_its_end_is_still_ok() {
    for arc in [
        rar4_open(b"a.txt", BODY),
        [rar4_open(b"a.txt", BODY), RAR4_END[..3].to_vec()].concat(),
        rar5_open(b"a.txt", BODY),
        [rar5_open(b"a.txt", BODY), rar5_end()[..3].to_vec()].concat(),
        // A header that says it is longer than the archive.
        [
            rar5_open(b"a.txt", BODY),
            vec![0; 4],
            vint(1000),
            vec![2, 0],
        ]
        .concat(),
    ] {
        assert_eq!(verdict(&arc), Verdict::Clean, "{} bytes", arc.len());
    }
}

/// A stored member the archive ends inside is cut, not over a limit: the
/// bytes present are scanned, and the rest is absent.
#[test]
fn a_stored_member_cut_by_the_end_of_the_archive_is_scanned() {
    let eicar = exav_core::unpack::eicar();
    let payload = [BODY, eicar, BODY].concat();
    for (label, whole) in [
        ("rar4", rar4_open(b"a.txt", &payload)),
        ("rar5", rar5_open(b"a.txt", &payload)),
    ] {
        let data_at = whole.len() - payload.len();
        // Cut before, inside and after the EICAR string.
        for (kept, want_found) in [
            (BODY.len() / 2, false),
            (BODY.len() + eicar.len() / 2, false),
            (BODY.len() + eicar.len() + 5, true),
        ] {
            let v = verdict(&whole[..data_at + kept]);
            if want_found {
                assert!(
                    matches!(&v, Verdict::Infected { signature, .. }
                        if signature.to_ascii_uppercase().contains("EICAR")),
                    "{label}, {kept} kept: {v:?}"
                );
            } else {
                assert_eq!(v, Verdict::Clean, "{label}, {kept} kept");
            }
        }
    }
}

/// The archive's links are resolved by the reader that holds the archive
/// whole, which reports damage as the walk of a source does.
#[test]
fn damage_after_the_members_of_an_archive_with_a_link_is_not_ok() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../exav-unpack/tests/fixtures/rar5/hardlink.rar"
    );
    let arc = exav_core::unpack::read_fixture(path).unwrap();
    assert_eq!(verdict(&arc), Verdict::Clean);
    // The archive is a main header, two files (the second a link to the
    // first) and, at 166, an end block: its size, then its type.
    let end = 166;
    assert_eq!(arc[end + 4..end + 6], [3, 5]);
    let damaged = [arc[..end].to_vec(), vec![0; 64]].concat();
    let why = damage(&damaged).unwrap_or_else(|| panic!("{:?}", verdict(&damaged)));
    assert!(why.contains("does not parse"), "{why}");
}
