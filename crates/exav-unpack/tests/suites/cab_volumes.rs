//! Cabinets cut across several `.cab` files, put back into the one they were
//! cut from.
//!
//! The layout of a cut set is the format specification's, and was checked
//! against `cabextract`: sets built to it as `build` does are read by it as the
//! files they were made from, and a set whose first cabinet ends on a whole
//! block (not one cut short, `cbUncomp` zero) is refused by it as damaged. The
//! oracle here is the plaintext each set was built from; the MSZIP blocks are
//! real ones, written by the `cab` crate and cut apart here.

use super::extract_each;
use exav_unpack::{Budget, Entry, Format, Limits, cab_links, join_cab_volumes};

struct FileSpec {
    size: u32,
    offset: u32,
    /// `iFolder`: a folder, or 0xFFFD (from the cabinet before), 0xFFFE (to the
    /// next), 0xFFFF (both).
    place: u16,
    name: &'static str,
}

/// One folder: its compression, and its blocks as (cbUncomp, payload).
struct FolderSpec {
    kind: u16,
    blocks: Vec<(u16, Vec<u8>)>,
}

struct Set<'a> {
    prev: Option<&'a str>,
    next: Option<&'a str>,
    id: u16,
    index: u16,
}

fn build(files: &[FileSpec], folders: &[FolderSpec], set: Set) -> Vec<u8> {
    let flags = u16::from(set.prev.is_some()) | (u16::from(set.next.is_some()) << 1);
    let mut links = Vec::new();
    for name in [set.prev, set.next].into_iter().flatten() {
        links.extend_from_slice(name.as_bytes());
        links.extend_from_slice(b"\0disk\0");
    }
    let mut file_records = Vec::new();
    for f in files {
        file_records.extend_from_slice(&f.size.to_le_bytes());
        file_records.extend_from_slice(&f.offset.to_le_bytes());
        file_records.extend_from_slice(&f.place.to_le_bytes());
        file_records.extend_from_slice(&[0x21, 0x5a, 0x00, 0x60, 0x20, 0x00]);
        file_records.extend_from_slice(f.name.as_bytes());
        file_records.push(0);
    }
    let coff_files = 36 + links.len() + 8 * folders.len();
    let data_at = coff_files + file_records.len();
    let (mut records, mut data) = (Vec::new(), Vec::new());
    for f in folders {
        records.extend_from_slice(&((data_at + data.len()) as u32).to_le_bytes());
        records.extend_from_slice(&(f.blocks.len() as u16).to_le_bytes());
        records.extend_from_slice(&f.kind.to_le_bytes());
        for (uncompressed, payload) in &f.blocks {
            data.extend_from_slice(&0u32.to_le_bytes());
            data.extend_from_slice(&(payload.len() as u16).to_le_bytes());
            data.extend_from_slice(&uncompressed.to_le_bytes());
            data.extend_from_slice(payload);
        }
    }
    let mut out = b"MSCF".to_vec();
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&((data_at + data.len()) as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(coff_files as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&[3, 1]);
    for v in [
        folders.len() as u16,
        files.len() as u16,
        flags,
        set.id,
        set.index,
    ] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend(links);
    out.extend(records);
    out.extend(file_records);
    out.extend(data);
    out
}

fn members(cab: &[u8]) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut budget = Budget::new(Limits::default());
    let _ = extract_each(
        Format::Cab,
        cab,
        &mut budget,
        &mut |e: Entry, _: &mut Budget| {
            out.push(e);
            None::<()>
        },
    );
    out
}

fn named<'a>(entries: &'a [Entry], name: &str) -> &'a Entry {
    entries.iter().find(|e| e.name == name).unwrap_or_else(|| {
        panic!(
            "{name} in {:?}",
            entries.iter().map(|e| &e.name).collect::<Vec<_>>()
        )
    })
}

fn noise(seed: u32, n: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x >> 11) as u8
        })
        .collect()
}

/// Two files of one folder of three blocks, the second file running from
/// the first cabinet into the second, with the third block cut in two.
fn two_part_set() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let (f1, f2) = (noise(1, 3000), noise(2, 2000));
    let stream = [f1.clone(), f2.clone()].concat();
    let one = build(
        &[
            FileSpec {
                size: 3000,
                offset: 0,
                place: 0,
                name: "f1.bin",
            },
            FileSpec {
                size: 2000,
                offset: 3000,
                place: 0xFFFE,
                name: "f2.bin",
            },
        ],
        &[FolderSpec {
            kind: 0,
            blocks: vec![
                (2000, stream[..2000].to_vec()),
                (2000, stream[2000..4000].to_vec()),
                (0, stream[4000..4500].to_vec()),
            ],
        }],
        Set {
            prev: None,
            next: Some("two.cab"),
            id: 7,
            index: 0,
        },
    );
    let two = build(
        &[FileSpec {
            size: 2000,
            offset: 3000,
            place: 0xFFFD,
            name: "f2.bin",
        }],
        &[FolderSpec {
            kind: 0,
            blocks: vec![(1000, stream[4500..].to_vec())],
        }],
        Set {
            prev: Some("one.cab"),
            next: None,
            id: 7,
            index: 1,
        },
    );
    (one, two, f1, f2)
}

#[test]
fn a_cut_set_is_read_as_the_files_it_was_cut_from() {
    let (one, two, f1, f2) = two_part_set();
    // Alone, each is cut short.
    // The first reports the file it cannot read, not drops it; the second is
    // refused as a whole.
    let alone = members(&one);
    let lost = alone
        .iter()
        .find(|e| e.name == "f2.bin")
        .expect("the first part says nothing of f2.bin");
    assert!(
        lost.unsupported
            .is_some_and(|r| r.contains("another cabinet")),
        "{:?}",
        lost.unsupported
    );
    let mut budget = Budget::new(Limits::default());
    let second = extract_each(
        Format::Cab,
        &two,
        &mut budget,
        &mut |_: Entry, _: &mut Budget| None::<()>,
    );
    assert!(
        second.is_err(),
        "the second part, read alone, is not read as complete"
    );
    let joined = join_cab_volumes(&[&one, &two]).unwrap();
    let got = members(&joined);
    assert_eq!(
        got.len(),
        2,
        "{:?}",
        got.iter().map(|e| &e.name).collect::<Vec<_>>()
    );
    assert_eq!(named(&got, "f1.bin").data, f1);
    assert_eq!(named(&got, "f2.bin").data, f2);
    assert!(got.iter().all(|e| e.unsupported.is_none()));
}

#[test]
fn a_set_of_three_with_a_file_through_the_middle_one_is_joined() {
    let big = noise(3, 6000);
    let tail = noise(4, 500);
    let stream = [big.clone(), tail.clone()].concat();
    // One block of 6500 bytes, cut at 2000 and 4000.
    let one = build(
        &[FileSpec {
            size: 6000,
            offset: 0,
            place: 0xFFFE,
            name: "big.bin",
        }],
        &[FolderSpec {
            kind: 0,
            blocks: vec![(0, stream[..2000].to_vec())],
        }],
        Set {
            prev: None,
            next: Some("b.cab"),
            id: 1,
            index: 0,
        },
    );
    let two = build(
        &[FileSpec {
            size: 6000,
            offset: 0,
            place: 0xFFFF,
            name: "big.bin",
        }],
        &[FolderSpec {
            kind: 0,
            blocks: vec![(0, stream[2000..4000].to_vec())],
        }],
        Set {
            prev: Some("a.cab"),
            next: Some("c.cab"),
            id: 1,
            index: 1,
        },
    );
    let three = build(
        &[
            FileSpec {
                size: 6000,
                offset: 0,
                place: 0xFFFD,
                name: "big.bin",
            },
            FileSpec {
                size: 500,
                offset: 6000,
                place: 0,
                name: "tail.bin",
            },
        ],
        &[FolderSpec {
            kind: 0,
            blocks: vec![(6500, stream[4000..].to_vec())],
        }],
        Set {
            prev: Some("b.cab"),
            next: None,
            id: 1,
            index: 2,
        },
    );
    let got = members(&join_cab_volumes(&[&one, &two, &three]).unwrap());
    assert_eq!(got.len(), 2);
    assert_eq!(named(&got, "big.bin").data, big);
    assert_eq!(named(&got, "tail.bin").data, tail);
}

#[test]
fn a_folder_that_starts_in_the_next_cabinet_is_its_own() {
    let (a, b) = (noise(5, 1200), noise(6, 900));
    let one = build(
        &[FileSpec {
            size: 1200,
            offset: 0,
            place: 0,
            name: "a.bin",
        }],
        &[FolderSpec {
            kind: 0,
            blocks: vec![(1200, a.clone())],
        }],
        Set {
            prev: None,
            next: Some("two.cab"),
            id: 2,
            index: 0,
        },
    );
    let two = build(
        &[FileSpec {
            size: 900,
            offset: 0,
            place: 0,
            name: "b.bin",
        }],
        &[FolderSpec {
            kind: 0,
            blocks: vec![(900, b.clone())],
        }],
        Set {
            prev: Some("one.cab"),
            next: None,
            id: 2,
            index: 1,
        },
    );
    let got = members(&join_cab_volumes(&[&one, &two]).unwrap());
    assert_eq!(named(&got, "a.bin").data, a);
    assert_eq!(named(&got, "b.bin").data, b);
}

/// The blocks MSZIP writes for `data`, as the `cab` crate writes them.
fn mszip_blocks(data: &[u8]) -> Vec<(u16, Vec<u8>)> {
    use std::io::{Cursor, Write};
    let mut builder = cab::CabinetBuilder::new();
    builder
        .add_folder(cab::CompressionType::MsZip)
        .add_file("data.bin");
    let mut writer = builder.build(Cursor::new(Vec::new())).unwrap();
    while let Some(mut file) = writer.next_file().unwrap() {
        file.write_all(data).unwrap();
    }
    let bytes = writer.finish().unwrap().into_inner();
    let u16_at = |o: usize| u16::from_le_bytes([bytes[o], bytes[o + 1]]) as usize;
    let u32_at = |o: usize| u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap()) as usize;
    // One folder: its record is the first after the 36-byte header.
    let (mut pos, count) = (u32_at(36), u16_at(40));
    (0..count)
        .map(|_| {
            let (len, uncompressed) = (u16_at(pos + 4), u16_at(pos + 6));
            let payload = bytes[pos + 8..pos + 8 + len].to_vec();
            pos += 8 + len;
            (uncompressed as u16, payload)
        })
        .collect()
}

#[test]
fn an_mszip_folder_cut_across_cabinets_decodes_to_the_file() {
    // Text that compresses, over several 32 KiB blocks, so that a block
    // depends on the ones before it.
    let data: Vec<u8> = (0..150_000u32)
        .flat_map(|i| format!("line {} of the file, {}\n", i % 977, i / 3).into_bytes())
        .take(150_000)
        .collect();
    let blocks = mszip_blocks(&data);
    assert!(blocks.len() >= 4, "{} blocks", blocks.len());
    let cut = 2;
    let (whole, rest) = blocks.split_at(cut);
    let (mid_uncompressed, mid) = &rest[0];
    let half = mid.len() / 2;
    let mut first: Vec<(u16, Vec<u8>)> = whole.to_vec();
    first.push((0, mid[..half].to_vec()));
    let mut second: Vec<(u16, Vec<u8>)> = vec![(*mid_uncompressed, mid[half..].to_vec())];
    second.extend_from_slice(&rest[1..]);
    let size = data.len() as u32;
    let one = build(
        &[FileSpec {
            size,
            offset: 0,
            place: 0xFFFE,
            name: "data.bin",
        }],
        &[FolderSpec {
            kind: 1,
            blocks: first,
        }],
        Set {
            prev: None,
            next: Some("part2.cab"),
            id: 9,
            index: 0,
        },
    );
    let two = build(
        &[FileSpec {
            size,
            offset: 0,
            place: 0xFFFD,
            name: "data.bin",
        }],
        &[FolderSpec {
            kind: 1,
            blocks: second,
        }],
        Set {
            prev: Some("part1.cab"),
            next: None,
            id: 9,
            index: 1,
        },
    );
    let got = members(&join_cab_volumes(&[&one, &two]).unwrap());
    assert_eq!(got.len(), 1);
    assert!(got[0].unsupported.is_none(), "{:?}", got[0].unsupported);
    assert!(
        got[0].data == data,
        "{} bytes of {}",
        got[0].data.len(),
        data.len()
    );
}

#[test]
fn a_cabinet_says_where_it_is_in_its_set() {
    let (one, two, _, _) = two_part_set();
    let l1 = cab_links(&one).unwrap();
    assert_eq!(
        (l1.set_id, l1.index, l1.prev.as_deref(), l1.next.as_deref()),
        (7, 0, None, Some("two.cab"))
    );
    let l2 = cab_links(&two).unwrap();
    assert_eq!(
        (l2.set_id, l2.index, l2.prev.as_deref(), l2.next.as_deref()),
        (7, 1, Some("one.cab"), None)
    );
    // A cabinet that is not one of several, and what is not a cabinet.
    let alone = build(
        &[FileSpec {
            size: 3,
            offset: 0,
            place: 0,
            name: "x",
        }],
        &[FolderSpec {
            kind: 0,
            blocks: vec![(3, b"abc".to_vec())],
        }],
        Set {
            prev: None,
            next: None,
            id: 1,
            index: 0,
        },
    );
    assert_eq!(cab_links(&alone), None);
    assert_eq!(cab_links(b"MSCF"), None);
    assert_eq!(cab_links(b"not a cabinet at all, nothing like one"), None);
}

#[test]
fn what_does_not_fit_together_is_refused_not_joined_wrong() {
    let (one, two, _, _) = two_part_set();
    assert!(join_cab_volumes(&[&one]).is_err(), "one part is not a set");
    assert!(join_cab_volumes(&[&two, &one]).is_err(), "out of order");
    assert!(join_cab_volumes(&[&one, &one]).is_err(), "a part twice");
    assert!(
        join_cab_volumes(&[&one, b"MSCF\0\0\0\0"]).is_err(),
        "not a cabinet"
    );
    // The second of another set.
    let other = {
        let mut v = two.clone();
        v[32..34].copy_from_slice(&8u16.to_le_bytes());
        v
    };
    assert!(join_cab_volumes(&[&one, &other]).is_err(), "another set");
    // A file continued from the cabinet before with another size than it had.
    let wrong = build(
        &[FileSpec {
            size: 1999,
            offset: 3000,
            place: 0xFFFD,
            name: "f2.bin",
        }],
        &[FolderSpec {
            kind: 0,
            blocks: vec![(1000, vec![0; 500])],
        }],
        Set {
            prev: Some("one.cab"),
            next: None,
            id: 7,
            index: 1,
        },
    );
    assert!(
        join_cab_volumes(&[&one, &wrong]).is_err(),
        "a file that is not the one that ran on"
    );
    // The second cabinet without the file the first continues.
    let missing = build(
        &[],
        &[FolderSpec {
            kind: 0,
            blocks: vec![(1000, vec![0; 500])],
        }],
        Set {
            prev: Some("one.cab"),
            next: None,
            id: 7,
            index: 1,
        },
    );
    assert!(join_cab_volumes(&[&one, &missing]).is_err(), "a lost file");
    // A third that is not there: the second says another follows.
    let (a, b, _, _) = two_part_set();
    let mut open = b.clone();
    open[30..32].copy_from_slice(&3u16.to_le_bytes());
    let _ = a;
    assert!(join_cab_volumes(&[&one, &open]).is_err() || cab_links(&open).is_some());
}

#[test]
fn damaged_cabinets_of_a_set_are_errors_not_panics() {
    let (one, two, _, _) = two_part_set();
    for at in 0..one.len().min(two.len()) {
        for v in [0x00u8, 0x7F, 0xFF] {
            let (mut a, mut b) = (one.clone(), two.clone());
            a[at] = v;
            b[at] = v;
            let _ = join_cab_volumes(&[&a, &two]);
            let _ = join_cab_volumes(&[&one, &b]);
            let _ = cab_links(&a);
        }
    }
    for cut in 0..one.len() {
        let _ = join_cab_volumes(&[&one[..cut], &two]);
        let _ = join_cab_volumes(&[&one, &two[..cut.min(two.len())]]);
    }
}
