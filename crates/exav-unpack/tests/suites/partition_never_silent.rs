//! GPT partition-table walking must never drop regions quietly.
//!
//! A partition table describes where the real filesystems live. Anything that
//! ends the walk early leaves those regions unscanned, and a disk image is
//! exactly the kind of container an attacker picks precisely because the
//! interesting bytes are one level down.
//!
//! Each case here was a silent `break`/`return Ok(None)` before.

use exav_unpack::{extract_each, Budget, Entry, Format, Limits};

const SECTOR: usize = 512;
const ENTRY_SIZE: u32 = 128;

/// Build a GPT image: protective MBR at LBA0, header at LBA1, entries at LBA2,
/// and `parts` as (first_lba, last_lba) pairs.
fn gpt(parts: &[(u64, u64)], num_entries: u32, entry_size: u32, entries_lba: u64) -> Vec<u8> {
    let mut img = vec![0u8; SECTOR * 64];
    // GPT header at LBA1.
    let h = SECTOR;
    img[h..h + 8].copy_from_slice(b"EFI PART");
    img[h + 72..h + 80].copy_from_slice(&entries_lba.to_le_bytes());
    img[h + 80..h + 84].copy_from_slice(&num_entries.to_le_bytes());
    img[h + 84..h + 88].copy_from_slice(&entry_size.to_le_bytes());

    let base = entries_lba as usize * SECTOR;
    for (i, (first, last)) in parts.iter().enumerate() {
        let e = base + i * entry_size as usize;
        if e + 56 > img.len() {
            break;
        }
        // Non-zero type GUID marks the slot as used.
        img[e..e + 16].copy_from_slice(&[0x11u8; 16]);
        img[e + 32..e + 40].copy_from_slice(&first.to_le_bytes());
        img[e + 40..e + 48].copy_from_slice(&last.to_le_bytes());
    }
    img
}

/// Collect every emitted member, including any produced before a mid-way error
/// — the scanner consumes them through a visitor, so this is what it sees.
fn emitted(blob: &[u8]) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut b = Budget::new(Limits::default());
    let _ = extract_each(
        Format::Partition,
        blob,
        &mut b,
        &mut |e: Entry, _: &mut Budget| {
            out.push(e);
            None::<()>
        },
    );
    out
}

fn reported(e: &[Entry]) -> Vec<&'static str> {
    e.iter().filter_map(|x| x.unsupported).collect()
}

#[test]
fn a_well_formed_table_is_walked_without_complaint() {
    // Baseline: none of the reporting below may fire on an ordinary image.
    let img = gpt(&[(4, 8), (10, 14)], 2, ENTRY_SIZE, 2);
    let e = emitted(&img);
    assert!(!e.is_empty(), "partitions should be emitted");
    assert!(
        reported(&e).is_empty(),
        "a healthy table must not report anything, got {:?}",
        reported(&e)
    );
}

#[test]
fn an_implausible_entry_stride_is_reported_not_treated_as_empty() {
    // Refusing to walk a nonsense stride is right; returning "nothing found" is
    // not — the partitions are still there, exav just didn't read them.
    let img = gpt(&[(4, 8)], 1, 7, 2); // 7 is below the 128-byte minimum
    let e = emitted(&img);
    assert!(
        !reported(&e).is_empty(),
        "an unwalkable partition table must surface, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
}

#[test]
fn an_entry_table_past_the_end_of_the_image_is_reported() {
    // The header points the entry array outside the image: the partitions it
    // describes exist in the layout but cannot be read here.
    let img = gpt(&[], 4, ENTRY_SIZE, 9999);
    let e = emitted(&img);
    assert!(
        !reported(&e).is_empty(),
        "an unreadable entry table must surface, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
}

#[test]
fn hitting_the_partition_cap_is_reported() {
    // More used slots than the walk guard allows. Stopping quietly would leave
    // the remaining partitions unscanned while the image could still be clean.
    let parts: Vec<(u64, u64)> = (0..200).map(|i| (4 + i * 2, 5 + i * 2)).collect();
    // Declare more entries than MAX_PARTS so the cap, not the count, ends it.
    let img = gpt(&parts, 200, ENTRY_SIZE, 2);
    let e = emitted(&img);
    assert!(
        reported(&e)
            .iter()
            .any(|r| r.contains("too many GPT partitions")),
        "hitting the partition cap must surface, got {:?}",
        reported(&e)
    );
}

/// Build an APM (Apple Partition Map) image: `ER` block at sector 0, then one
/// `PM` entry per sector, with the first entry declaring `map_entries`.
fn apm(declared: u32, real: usize) -> Vec<u8> {
    let mut img = vec![0u8; SECTOR * 64];
    img[0..2].copy_from_slice(b"ER");
    for i in 0..real {
        let base = (i + 1) * SECTOR;
        if base + 16 > img.len() {
            break;
        }
        img[base..base + 2].copy_from_slice(b"PM");
        img[base + 4..base + 8].copy_from_slice(&declared.to_be_bytes());
        img[base + 8..base + 12].copy_from_slice(&(4 + i as u32 * 2).to_be_bytes());
        img[base + 12..base + 16].copy_from_slice(&2u32.to_be_bytes());
    }
    img
}

#[test]
fn hitting_the_apm_partition_cap_is_reported() {
    // Same clamp bug as GPT, in the Apple Partition Map path: `.min(MAX_PARTS)`
    // on a parsed count discards the rest without a word.
    let img = apm(500, 60);
    let e = emitted(&img);
    assert!(
        reported(&e)
            .iter()
            .any(|r| r.contains("too many APM partitions")),
        "hitting the APM cap must surface, got {:?}",
        reported(&e)
    );
}

#[test]
fn a_well_formed_apm_map_is_walked_without_complaint() {
    let img = apm(4, 4);
    let e = emitted(&img);
    assert!(
        reported(&e).is_empty(),
        "a healthy APM map must not report anything, got {:?}",
        reported(&e)
    );
}
