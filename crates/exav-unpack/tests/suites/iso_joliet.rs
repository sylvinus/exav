//! Regression: an ISO-9660 image that lists its payload ONLY in the Joliet
//! supplementary tree (leaving the primary tree empty) — a common malware-ISO
//! evasion, e.g. an `Invoice.pdf.lnk` delivered inside an ISO — must still have
//! that file extracted and scanned. Walking only the primary volume descriptor's
//! directory tree would silently miss such files.

use exav_unpack::{extract, Budget, Format, Limits};

const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR";
const SECTOR: usize = 2048;

/// Build one ISO-9660 directory record.
fn dir_record(lba: u32, size: u32, is_dir: bool, name: &[u8]) -> Vec<u8> {
    let mut r = vec![0u8; 33 + name.len()];
    r[2..6].copy_from_slice(&lba.to_le_bytes());
    r[6..10].copy_from_slice(&lba.to_be_bytes());
    r[10..14].copy_from_slice(&size.to_le_bytes());
    r[14..18].copy_from_slice(&size.to_be_bytes());
    r[25] = if is_dir { 0x02 } else { 0x00 };
    r[32] = name.len() as u8;
    r[33..].copy_from_slice(name);
    if r.len() % 2 == 1 {
        r.push(0); // records are padded to even length
    }
    r[0] = r.len() as u8;
    r
}

/// A minimal ISO whose only file (`name`, holding `payload`) is listed solely in
/// the Joliet tree; the primary tree's root directory is empty.
///
/// Layout (one object per sector): 16=PVD, 17=Joliet SVD, 18=terminator,
/// 19=primary root dir (empty), 20=Joliet root dir (holds the file), 21=payload.
fn joliet_only_iso(name_utf16be: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut img = vec![0u8; 22 * SECTOR];
    let put = |img: &mut [u8], sector: usize, off: usize, bytes: &[u8]| {
        let a = sector * SECTOR + off;
        img[a..a + bytes.len()].copy_from_slice(bytes);
    };

    // Volume descriptors carry "CD001" at +1 and a 34-byte root record at +156.
    // Primary (type 1) → root dir at LBA 19; Joliet SVD (type 2, escape at +88)
    // → root dir at LBA 20; then the set terminator (type 255).
    put(&mut img, 16, 0, &[1]);
    put(&mut img, 16, 1, b"CD001");
    put(
        &mut img,
        16,
        156,
        &dir_record(19, SECTOR as u32, true, &[0]),
    );

    put(&mut img, 17, 0, &[2]);
    put(&mut img, 17, 1, b"CD001");
    put(&mut img, 17, 88, &[0x25, 0x2f, 0x45]); // Joliet UCS-2 escape sequence
    put(
        &mut img,
        17,
        156,
        &dir_record(20, SECTOR as u32, true, &[0]),
    );

    put(&mut img, 18, 0, &[255]);
    put(&mut img, 18, 1, b"CD001");

    // Primary root dir (LBA 19): "." and ".." only — NO files.
    let mut prim = dir_record(19, SECTOR as u32, true, &[0]);
    prim.extend(dir_record(19, SECTOR as u32, true, &[1]));
    put(&mut img, 19, 0, &prim);

    // Joliet root dir (LBA 20): "." , ".." , and the payload file at LBA 21.
    let mut jol = dir_record(20, SECTOR as u32, true, &[0]);
    jol.extend(dir_record(20, SECTOR as u32, true, &[1]));
    jol.extend(dir_record(21, payload.len() as u32, false, name_utf16be));
    put(&mut img, 20, 0, &jol);

    put(&mut img, 21, 0, payload);
    img
}

/// UTF-16BE encode an ASCII string (Joliet stores names as UCS-2 big-endian).
fn utf16be(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_be_bytes()).collect()
}

#[test]
fn joliet_only_file_is_extracted() {
    let iso = joliet_only_iso(&utf16be("Invoice.pdf.lnk"), EICAR);
    let mut budget = Budget::new(Limits::default());
    let entries = extract(Format::Iso, &iso, &mut budget).expect("iso extract");
    assert!(
        entries
            .iter()
            .any(|e| e.data.windows(EICAR.len()).any(|w| w == EICAR)),
        "a file listed only in the Joliet tree must still be extracted"
    );
    assert!(
        entries.iter().any(|e| e.name == "Invoice.pdf.lnk"),
        "the Joliet long name should be recovered; got {:?}",
        entries.iter().map(|e| &e.name).collect::<Vec<_>>()
    );
}

#[test]
fn file_in_both_trees_is_emitted_once() {
    // Same payload extent referenced from both the primary and Joliet roots must
    // be extracted a single time (dedup by extent), not twice.
    let mut iso = joliet_only_iso(&utf16be("dup.bin"), EICAR);
    // Add the same file (extent LBA 21) to the primary root at LBA 19, after
    // its "." / ".." records.
    let mut prim = dir_record(19, SECTOR as u32, true, &[0]);
    prim.extend(dir_record(19, SECTOR as u32, true, &[1]));
    prim.extend(dir_record(21, EICAR.len() as u32, false, b"DUP.BIN;1"));
    let a = 19 * SECTOR;
    iso[a..a + prim.len()].copy_from_slice(&prim);

    let mut budget = Budget::new(Limits::default());
    let entries = extract(Format::Iso, &iso, &mut budget).expect("iso extract");
    let hits = entries
        .iter()
        .filter(|e| e.data.windows(EICAR.len()).any(|w| w == EICAR))
        .count();
    assert_eq!(
        hits, 1,
        "a file in both trees must be extracted exactly once"
    );
}
