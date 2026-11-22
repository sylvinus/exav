//! ISO enumeration must never drop content quietly.
//!
//! An ISO's directory tree can be truncated, corrupt, or larger than the walk
//! guard. In every one of those cases files exist in the image that exav did not
//! examine, and the containing file must not be reportable as clean on that
//! basis. Each case here was a silent `break`/`continue` before.

use exav_unpack::{Budget, Format, Limits, extract};

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
    extract(Format::Iso, &blob, &mut b).unwrap_or_default()
}

#[test]
fn a_truncated_image_is_not_flagged_it_is_simply_short() {
    // The record claims a 10 MB file in a 40 KB image. Those bytes are ABSENT
    // from the file, not hidden in it: every byte that exists is scanned, so a
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
fn a_corrupt_directory_record_is_reported_when_streamed() {
    // The scanner walks every ISO through `walk`, where the same record used
    // to end the directory without a word.
    let mut img = iso(&[("A.TXT", 19, 4)], 200);
    let p = 18 * SECTOR + 33 + "A.TXT".len();
    img[p] = 5;
    let mut unsupported = Vec::new();
    let mut b = Budget::new(Limits::default());
    let _ = exav_unpack::walk(
        Format::Iso,
        &img,
        &mut b,
        &mut |m: &exav_unpack::MemberMeta, _: Option<exav_unpack::Member<'_>>, _: &mut Budget| {
            unsupported.extend(m.unsupported);
            None::<()>
        },
    );
    assert!(!unsupported.is_empty(), "a corrupt record must be reported");
}

#[test]
fn a_directory_that_lists_itself_is_walked_once() {
    // A subdirectory record pointing back at its own extent used to be queued
    // again and again until the directory limit, then reported as too many.
    let mut img = iso(&[("SUB", 18, 200), ("A.TXT", 19, 5)], 200);
    img[18 * SECTOR + 25] = 0x02; // the first record is a directory
    img[19 * SECTOR..19 * SECTOR + 5].copy_from_slice(b"hello");
    let e = entries(&img);
    assert!(
        e.iter().all(|x| x.unsupported.is_none()),
        "a loop is walked once, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
    assert!(e.iter().any(|x| x.data == b"hello"));
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
    // Each directory record points at a directory of its own, so the walk
    // queues more than MAX_DIRS of them.
    let mut img = vec![0u8; SECTOR * 60];
    let pvd = 16 * SECTOR;
    img[pvd] = 1;
    img[pvd + 1..pvd + 6].copy_from_slice(b"CD001");
    let rd = pvd + 156;
    img[rd] = 34;
    img[rd + 2..rd + 6].copy_from_slice(&18u32.to_le_bytes());
    img[rd + 10..rd + 14].copy_from_slice(&(40 * 2048u32).to_le_bytes());
    img[rd + 25] = 0x02;
    img[rd + 32] = 1;
    let term = 17 * SECTOR;
    img[term] = 0xff;
    img[term + 1..term + 6].copy_from_slice(b"CD001");

    // Root directory packed with subdirectory records, each naming a distinct
    // extent past the end of the image: none has anything in it, and each
    // still counts as a directory to walk.
    let mut p = 18 * SECTOR;
    for i in 0..1100u32 {
        let name = format!("D{i}");
        let rec_len = 33 + name.len();
        if (p % SECTOR) + rec_len > SECTOR {
            p = (p / SECTOR + 1) * SECTOR; // a record does not cross a sector
        }
        img[p] = rec_len as u8;
        img[p + 2..p + 6].copy_from_slice(&(1000 + i).to_le_bytes());
        img[p + 10..p + 14].copy_from_slice(&2048u32.to_le_bytes());
        img[p + 25] = 0x02; // directory
        img[p + 32] = name.len() as u8;
        img[p + 33..p + 33 + name.len()].copy_from_slice(name.as_bytes());
        p += rec_len;
    }

    let walk = |max_members: u64| {
        let mut limits = Limits::default();
        limits.max_members = max_members;
        extract(Format::Iso, &img, &mut Budget::new(limits))
    };
    // Each directory is a member: past the member limit the walk ends with the
    // limit (LIMITS-EXCEEDED), not quietly.
    let err = walk(100).expect_err("1100 directories are past a limit of 100");
    assert!(
        matches!(err.kind, exav_unpack::LimitKind::MaxFiles),
        "{err:?}"
    );
    // Under the default limit all of them are walked: no fixed cap of its own.
    let e = walk(100_000).expect("1100 directories are under the default limit");
    assert!(e.iter().all(|x| x.unsupported.is_none()), "{e:?}");
    // And `off` lifts it.
    assert!(walk(u64::MAX).is_ok());
}

/// The files found before the member limit stops the directory walk are
/// visited, and the walk then ends with the limit.
#[test]
fn the_files_found_before_the_member_limit_are_visited() {
    let mut img = vec![0u8; SECTOR * 60];
    let pvd = 16 * SECTOR;
    img[pvd] = 1;
    img[pvd + 1..pvd + 6].copy_from_slice(b"CD001");
    let rd = pvd + 156;
    img[rd] = 34;
    img[rd + 2..rd + 6].copy_from_slice(&18u32.to_le_bytes());
    img[rd + 10..rd + 14].copy_from_slice(&(40 * 2048u32).to_le_bytes());
    img[rd + 25] = 0x02;
    img[rd + 32] = 1;
    let term = 17 * SECTOR;
    img[term] = 0xff;
    img[term + 1..term + 6].copy_from_slice(b"CD001");
    // A file at sector 59, then directories past the end of the image.
    img[59 * SECTOR..59 * SECTOR + 5].copy_from_slice(b"hello");
    let mut p = 18 * SECTOR;
    let mut record = |p: &mut usize, name: &str, lba: u32, len: u32, flags: u8| {
        let rec_len = 33 + name.len();
        if (*p % SECTOR) + rec_len > SECTOR {
            *p = (*p / SECTOR + 1) * SECTOR;
        }
        img[*p] = rec_len as u8;
        img[*p + 2..*p + 6].copy_from_slice(&lba.to_le_bytes());
        img[*p + 10..*p + 14].copy_from_slice(&len.to_le_bytes());
        img[*p + 25] = flags;
        img[*p + 32] = name.len() as u8;
        img[*p + 33..*p + 33 + name.len()].copy_from_slice(name.as_bytes());
        *p += rec_len;
    };
    record(&mut p, "A.TXT", 59, 5, 0);
    for i in 0..1100u32 {
        record(&mut p, &format!("D{i}"), 1000 + i, 2048, 0x02);
    }
    let mut limits = Limits::default();
    limits.max_members = 100;
    let mut seen = Vec::new();
    let end = exav_unpack::walk(
        Format::Iso,
        &img,
        &mut Budget::new(limits),
        &mut |m: &exav_unpack::MemberMeta, _: Option<exav_unpack::Member<'_>>, _: &mut Budget| {
            seen.push(m.name.clone());
            None::<()>
        },
    );
    assert_eq!(seen, ["A.TXT"]);
    let err = end.expect_err("1100 directories are past a limit of 100");
    assert!(
        matches!(err.kind, exav_unpack::LimitKind::MaxFiles),
        "{err:?}"
    );
}

/// The bytes of the directories read are charged to the scan budget: a
/// hundred directories that overlap, each declared 80 sectors long, are 16 MB
/// of reads in an image of 400 KB, and a count of directories does not say so.
#[test]
fn directories_that_overlap_are_charged_to_the_scan_budget() {
    let mut img = vec![0u8; SECTOR * 200];
    let pvd = 16 * SECTOR;
    img[pvd] = 1;
    img[pvd + 1..pvd + 6].copy_from_slice(b"CD001");
    let rd = pvd + 156;
    img[rd] = 34;
    img[rd + 2..rd + 6].copy_from_slice(&18u32.to_le_bytes());
    // The root is two sectors, which hold the records.
    img[rd + 10..rd + 14].copy_from_slice(&(2 * SECTOR as u32).to_le_bytes());
    img[rd + 25] = 0x02;
    img[rd + 32] = 1;
    let term = 17 * SECTOR;
    img[term] = 0xff;
    img[term + 1..term + 6].copy_from_slice(b"CD001");

    let mut p = 18 * SECTOR;
    for i in 0..100u32 {
        let name = format!("D{i}");
        let rec_len = 33 + name.len();
        if (p % SECTOR) + rec_len > SECTOR {
            p = (p / SECTOR + 1) * SECTOR;
        }
        img[p] = rec_len as u8;
        // Directory `i` begins at sector 20 + `i` and is declared 80 sectors.
        img[p + 2..p + 6].copy_from_slice(&(20 + i).to_le_bytes());
        img[p + 10..p + 14].copy_from_slice(&(80 * SECTOR as u32).to_le_bytes());
        img[p + 25] = 0x02;
        img[p + 32] = name.len() as u8;
        img[p + 33..p + 33 + name.len()].copy_from_slice(name.as_bytes());
        p += rec_len;
    }

    let walk = |max_scanned_bytes: u64| {
        let mut limits = Limits::default();
        limits.max_scanned_bytes = max_scanned_bytes;
        extract(Format::Iso, &img, &mut Budget::new(limits))
    };
    let err = walk(1 << 20).expect_err("16 MB of directory reads under a budget of 1 MiB");
    assert!(
        matches!(err.kind, exav_unpack::LimitKind::MaxScanSize),
        "{err:?}"
    );
    // The default budget, and none, walk them all.
    for budget in [Limits::default().max_scanned_bytes, u64::MAX] {
        let e = walk(budget).expect("the directories are within the budget");
        assert!(e.iter().all(|x| x.unsupported.is_none()), "{e:?}");
    }
}
