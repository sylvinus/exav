//! 7z archives with entries that have no stream (directories and empty
//! files) among more than eight in all, so that the bit vectors of the
//! header span two bytes. `many_entries.7z` was written by p7zip 16.02:
//! `7z a -mx=1 -mtc=off -mta=off many_entries.7z top`, from a tree of three
//! directories, two empty files and ten files of 54 bytes.

use exav_unpack::{Budget, Format, Limits, extract};

fn fixture() -> Vec<u8> {
    let p = format!(
        "{}/tests/fixtures/7z/many_entries.7z",
        env!("CARGO_MANIFEST_DIR")
    );
    exav_unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

#[test]
fn the_empty_entries_of_a_larger_archive_do_not_misplace_the_names_after_them() {
    let entries = extract(
        Format::SevenZip,
        &fixture(),
        &mut Budget::new(Limits::default()),
    )
    .unwrap();
    for i in 0..10 {
        let want = format!("content of file {i}\n").repeat(3);
        let name = format!("top/file{i}.txt");
        let e = entries.iter().find(|e| e.name == name).unwrap_or_else(|| {
            panic!(
                "{name} among {:?}",
                entries.iter().map(|e| &e.name).collect::<Vec<_>>()
            )
        });
        assert_eq!(e.data, want.as_bytes(), "{name}");
    }
    // A directory is not a file.
    for dir in ["top", "top/empty_dir", "top/sub"] {
        assert!(!entries.iter().any(|e| e.name == dir), "{dir}");
    }
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & (crc & 1).wrapping_neg());
        }
    }
    !crc
}

/// An archive of nothing but a header: `files` entries and `props` properties
/// of them that mean nothing.
fn header_only(files: u32, props: usize) -> Vec<u8> {
    let mut header = vec![0x01, 0x05];
    // A 7z number of three bytes.
    header.extend([0xC0 | (files >> 16) as u8, files as u8, (files >> 8) as u8]);
    for _ in 0..props {
        header.extend([0x30, 0x00]);
    }
    header.extend([0x00, 0x00]);
    let mut start = Vec::new();
    start.extend(0u64.to_le_bytes());
    start.extend((header.len() as u64).to_le_bytes());
    start.extend(crc32(&header).to_le_bytes());
    let mut out = b"7z\xBC\xAF\x27\x1C\x00\x04".to_vec();
    out.extend(crc32(&start).to_le_bytes());
    out.extend(start);
    out.extend(header);
    out
}

/// The entries without a stream are counted when the property that sets them
/// is read, not again for every property that follows.
#[test]
fn a_header_of_many_properties_over_many_files_is_read_in_linear_time() {
    let blob = header_only(100_000, 100_000);
    let start = std::time::Instant::now();
    let _ = extract(Format::SevenZip, &blob, &mut Budget::new(Limits::default()));
    assert!(start.elapsed().as_secs() < 3, "{:?}", start.elapsed());
}

/// A coder of a forged folder: method id, inputs, outputs.
struct Coder(&'static [u8], u8, u8);

const BCJ2: &[u8] = &[0x03, 0x03, 0x01, 0x1B];
const COPY: &[u8] = &[0x00];

/// An archive of one folder of `coders`, joined by `binds` (input, output),
/// with the inputs `packed` fed by empty packed streams, and one file in it.
fn forged_folder(coders: &[Coder], binds: &[(u8, u8)], packed: &[u8]) -> Vec<u8> {
    let outs: u8 = coders.iter().map(|c| c.2).sum();
    let ins: u8 = coders.iter().map(|c| c.1).sum();
    assert_eq!(binds.len(), usize::from(outs - 1).min(coders.len()));
    assert_eq!(packed.len(), usize::from(ins) - binds.len());
    let mut h = vec![0x01, 0x04, 0x06, 0x00, packed.len() as u8, 0x09];
    h.extend(vec![0u8; packed.len()]);
    h.extend([0x00, 0x07, 0x0B, 0x01, 0x00, coders.len() as u8]);
    for Coder(id, ins, outs) in coders {
        h.push(0x10 | id.len() as u8);
        h.extend(*id);
        h.extend([*ins, *outs]);
    }
    for &(i, o) in binds {
        h.extend([i, o]);
    }
    if packed.len() > 1 {
        h.extend(packed);
    }
    h.push(0x0C);
    h.extend(vec![16u8; usize::from(outs)]);
    // The end of the unpack info, the folder's one stream, the end of the
    // streams info; then one file, and the end of the header.
    h.extend([0x00, 0x08, 0x00, 0x00, 0x05, 0x01, 0x00, 0x00]);
    let mut start = Vec::new();
    start.extend(0u64.to_le_bytes());
    start.extend((h.len() as u64).to_le_bytes());
    start.extend(crc32(&h).to_le_bytes());
    let mut out = b"7z\xBC\xAF\x27\x1C\x00\x04".to_vec();
    out.extend(crc32(&start).to_le_bytes());
    out.extend(start);
    out.extend(h);
    out
}

/// Walked, the archive's end: the reason it stopped.
fn stop(blob: &[u8]) -> String {
    let mut budget = Budget::new(Limits::default());
    match exav_unpack::walk(
        Format::SevenZip,
        &blob,
        &mut budget,
        &mut |_, _, _| None::<()>,
    ) {
        Err(e) => e.to_string(),
        Ok(_) => String::new(),
    }
}

/// 7-Zip refuses a folder in which a coder feeds several inputs. Built once
/// for each, a coder under a few dozen bind pairs makes more readers than
/// memory holds, each BCJ2 one with buffers of its own.
#[test]
fn a_folder_that_binds_one_output_to_several_inputs_is_refused() {
    // Eight BCJ2 coders and a leaf: the four inputs of the first on the
    // output of the second, the four of the second on the third's.
    let mut coders: Vec<Coder> = (0..8).map(|_| Coder(BCJ2, 4, 1)).collect();
    coders.push(Coder(COPY, 1, 1));
    let binds: Vec<(u8, u8)> = (0..8).map(|i| (i, i / 4 + 1)).collect();
    let packed: Vec<u8> = (8..=32).collect();
    let why = stop(&forged_folder(&coders, &binds, &packed));
    assert!(why.contains("two inputs"), "{why}");

    // A coder of two outputs, each bound to an input of the one above it.
    let coders = [Coder(BCJ2, 4, 1), Coder(COPY, 1, 2)];
    let binds = [(0, 1), (1, 2)];
    let why = stop(&forged_folder(&coders, &binds, &[2, 3, 4]));
    assert!(why.contains("two inputs"), "{why}");

    // One input bound to two outputs.
    let coders = [Coder(BCJ2, 4, 1), Coder(COPY, 1, 1), Coder(COPY, 1, 1)];
    let binds = [(0, 1), (0, 2)];
    let why = stop(&forged_folder(&coders, &binds, &[1, 2, 3, 4]));
    assert!(why.contains("two outputs"), "{why}");
}
