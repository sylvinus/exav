//! ISO enumeration must never drop content quietly.
//!
//! An ISO's directory tree can be truncated, corrupt, or larger than the walk
//! guard. In every one of those cases files exist in the image that exav did not
//! examine — and the containing file must not be reportable as clean on that
//! basis. Each case here was a silent `break`/`continue` before.

use exav_unpack::{extract, Budget, Format, Limits};

const SECTOR: usize = 2048;

/// Build a minimal ISO 9660: a primary volume descriptor at sector 16 pointing
/// at a root directory, then `files` as records in that directory.
fn iso(files: &[(&str, u64, u64)], root_len: u64) -> Vec<u8> {
    let mut img = vec![0u8; SECTOR * 20];
    // Primary volume descriptor.
    let pvd = 16 * SECTOR;
    img[pvd] = 1;
    img[pvd + 1..pvd + 6].copy_from_slice(b"CD001");
    // Root directory record sits at offset 156 of the PVD, 34 bytes.
    let rd = pvd + 156;
    img[rd] = 34;
    img[rd + 2..rd + 6].copy_from_slice(&18u32.to_le_bytes()); // root at sector 18
    img[rd + 10..rd + 14].copy_from_slice(&(root_len as u32).to_le_bytes());
    img[rd + 25] = 0x02; // directory
    img[rd + 32] = 1;
    // Volume descriptor set terminator.
    let term = 17 * SECTOR;
    img[term] = 0xff;
    img[term + 1..term + 6].copy_from_slice(b"CD001");

    // Root directory contents at sector 18.
    let mut p = 18 * SECTOR;
    for (name, lba, len) in files {
        let rec_len = 33 + name.len();
        img[p] = rec_len as u8;
        img[p + 2..p + 6].copy_from_slice(&(*lba as u32).to_le_bytes());
        img[p + 10..p + 14].copy_from_slice(&(*len as u32).to_le_bytes());
        img[p + 25] = 0;
        img[p + 32] = name.len() as u8;
        img[p + 33..p + 33 + name.len()].copy_from_slice(name.as_bytes());
        p += rec_len;
    }
    img
}

fn entries(blob: &[u8]) -> Vec<exav_unpack::Entry> {
    let mut b = Budget::new(Limits::default());
    extract(Format::Iso, blob, &mut b).unwrap_or_default()
}

#[test]
fn a_truncated_image_is_not_flagged_it_is_simply_short() {
    // The record claims a 10 MB file in a 40 KB image. Those bytes are ABSENT
    // from the file, not hidden in it — every byte that exists is scanned, so a
    // clean result is a real clean. exav scans for malware, it is not a
    // file-integrity validator (docs/QUIRKS.md). Over-reporting here would make
    // every damaged file noisy for no security gain.
    let blob = iso(&[("BIG.BIN", 19, 10 * 1024 * 1024)], 200);
    let e = entries(&blob);
    assert!(
        e.iter().all(|x| x.unsupported.is_none()),
        "truncation must not be reported as unreadable, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
}

#[test]
fn a_directory_extent_outside_the_image_is_not_flagged() {
    // Same reasoning: the directory block lies past the end of a truncated
    // image, so neither it nor the files it would name exist here.
    let blob = iso(&[], 200);
    let mut img = blob.clone();
    let rd = 16 * SECTOR + 156;
    img[rd + 2..rd + 6].copy_from_slice(&9999u32.to_le_bytes());
    let e = entries(&img);
    assert!(
        e.iter().all(|x| x.unsupported.is_none()),
        "an absent directory extent must not be reported, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
}

#[test]
fn a_corrupt_directory_record_is_reported() {
    // A non-zero but too-short record length makes the rest of the directory
    // unreachable. Stopping quietly would drop every file after it.
    let mut img = iso(&[("A.TXT", 19, 4)], 200);
    let p = 18 * SECTOR + 33 + "A.TXT".len();
    img[p] = 5; // non-zero, but < the 33-byte fixed area
    let e = entries(&img);
    assert!(
        e.iter().any(|x| x.unsupported.is_some()),
        "a corrupt record must be reported, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
}

#[test]
fn a_well_formed_member_is_still_extracted_normally() {
    // The counterweight: none of the above may make ordinary images noisy.
    let mut img = iso(&[("A.TXT", 19, 5)], 200);
    img[19 * SECTOR..19 * SECTOR + 5].copy_from_slice(b"hello");
    let e = entries(&img);
    assert!(
        e.iter()
            .any(|x| x.data == b"hello" && x.unsupported.is_none()),
        "a valid member must extract cleanly, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported, x.data.len()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn hitting_the_directory_walk_cap_is_reported() {
    // More directories than the walk guard allows. Stopping quietly would leave
    // the rest of the image unenumerated while it could still be called clean.
    // Each directory record points at another directory, so the walk queues
    // more than MAX_DIRS of them.
    let mut img = vec![0u8; SECTOR * 40];
    let pvd = 16 * SECTOR;
    img[pvd] = 1;
    img[pvd + 1..pvd + 6].copy_from_slice(b"CD001");
    let rd = pvd + 156;
    img[rd] = 34;
    img[rd + 2..rd + 6].copy_from_slice(&18u32.to_le_bytes());
    img[rd + 10..rd + 14].copy_from_slice(&2048u32.to_le_bytes());
    img[rd + 25] = 0x02;
    img[rd + 32] = 1;
    let term = 17 * SECTOR;
    img[term] = 0xff;
    img[term + 1..term + 6].copy_from_slice(b"CD001");

    // Root directory packed with subdirectory records, each pointing back at
    // sector 18 — a cycle, so the walk is bounded only by the count guard.
    let mut p = 18 * SECTOR;
    for i in 0..40 {
        let name = format!("D{i}");
        let rec_len = 33 + name.len();
        img[p] = rec_len as u8;
        img[p + 2..p + 6].copy_from_slice(&18u32.to_le_bytes());
        img[p + 10..p + 14].copy_from_slice(&2048u32.to_le_bytes());
        img[p + 25] = 0x02; // directory
        img[p + 32] = name.len() as u8;
        img[p + 33..p + 33 + name.len()].copy_from_slice(name.as_bytes());
        p += rec_len;
    }

    let e = entries(&img);
    assert!(
        e.iter().any(|x| x
            .unsupported
            .is_some_and(|r| r.contains("too many ISO directories"))),
        "hitting the directory cap must surface, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
}
