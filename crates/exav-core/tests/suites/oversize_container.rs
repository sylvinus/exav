//! A file past `limits.max_buffer_bytes` is scanned in full, or reported as over the
//! size limit, whichever entry point sees it.
//!
//! Past that size the file is read through a block cache rather than held,
//! and everything that can run that way does. What cannot is named as the
//! size limit: a container whose format is read whole, and the parts of a
//! scan that need spill space when the host provides none.
//!
//! [`scan_path`] and [`scan_seekable`] reach that decision by separate routes:
//! one buffers from a `File`, the other from a `Read + Seek` that may be an
//! HTTP range source, and the daemon picks between them by verb. Two routes
//! and one rule, so the rule needs a test on both or they drift.

use exav_core::spill::{Spill, SpillReader, SpillWriter};
use exav_core::unpack::spill::MemSpill;
use exav_core::{
    AllMatchOutcome, ScanOptions, Scanner, Verdict, analyze_all_seekable, loader, scan_path,
    scan_seekable,
};
use exav_unpack::zip_write::{FileOptions, Method, ZipWriter};
use std::io::Write;
use std::sync::Arc;

fn scanner() -> Scanner {
    let mut l = loader::Builder::new();
    l.add_named_bytes("t.ndb", b"Zzz.Never:0:*:deadbeefdeadbeefdead\n", true);
    l.build().expect("build database")
}

/// An ARJ main header followed by padding. ARJ is a container that is not
/// walked off a stream, so it takes the buffer-or-refuse path rather than the
/// member-by-member one, which is the path under test. The body is deliberately
/// not a valid archive: the point is that exav refuses *before* it would find
/// that out.
#[cfg(feature = "all-formats")]
fn oversize_arj() -> Vec<u8> {
    // `60 EA`, the header's size, the header and its CRC-32.
    let header = [0u8; 30];
    let mut v = vec![0x60, 0xEA, header.len() as u8, 0];
    v.extend_from_slice(&header);
    v.extend_from_slice(&crc32fast::hash(&header).to_le_bytes());
    v.resize(64 * 1024, 0);
    v
}

fn tiny_object_limit() -> ScanOptions {
    let mut o = ScanOptions::default();
    o.limits.max_buffer_bytes = 4096;
    o
}

#[test]
#[cfg(feature = "all-formats")]
fn scan_seekable_refuses_an_oversize_container() {
    let db = scanner();
    let blob = oversize_arj();
    let size = blob.len() as u64;
    let report =
        scan_seekable(&db, std::io::Cursor::new(blob), size, &tiny_object_limit()).expect("scan");
    match report.verdict {
        Verdict::LimitsExceeded { .. } => {}
        other => panic!(
            "an oversize ARJ was never unpacked, so its members were never scanned. \
             Expected LIMITS-EXCEEDED, got {other:?}, which renders as OK."
        ),
    }
}

#[test]
#[cfg(feature = "all-formats")]
fn scan_path_refuses_the_same_container() {
    let db = scanner();
    let dir =
        std::env::temp_dir().join(format!("exav-oversize-{}-{}", std::process::id(), line!()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let path = dir.join("big.arj");
    std::fs::File::create(&path)
        .expect("create")
        .write_all(&oversize_arj())
        .expect("write");

    let report = scan_path(&db, &path, &tiny_object_limit()).expect("scan");
    let _ = std::fs::remove_dir_all(&dir);
    match report.verdict {
        Verdict::LimitsExceeded { .. } => {}
        other => panic!("expected LIMITS-EXCEEDED from scan_path, got {other:?}"),
    }
}

/// A ZIP is walked member by member at any size, and past the cap its own
/// bytes get the full engine read through the cache. A member that large, or
/// text whose normalised views are that large, needs spill space: without it
/// that is the size limit, named as one, and with it the scan is complete.
#[test]
fn an_oversize_streamed_container_or_member_is_a_limit() {
    let db = scanner();
    let zip_of = |members: &[(String, Vec<u8>)]| {
        let mut z = ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let stored = FileOptions::default().method(Method::Stored);
        for (name, body) in members {
            z.start_file(name.as_str(), stored).unwrap();
            z.write_all(body).unwrap();
        }
        z.finish().unwrap().into_inner()
    };
    let many_small: Vec<_> = (0..64)
        .map(|i| (format!("m{i}.bin"), vec![0u8; 200]))
        .collect();
    let many_small = zip_of(&many_small);
    let report = scan_seekable(
        &db,
        std::io::Cursor::new(many_small.clone()),
        many_small.len() as u64,
        &tiny_object_limit(),
    )
    .expect("scan");
    assert_eq!(
        report.verdict,
        Verdict::Clean,
        "every member and byte was scanned"
    );

    let one_large = vec![("big.txt".to_string(), vec![b'a'; 64 * 1024])];
    let flat = vec![b'a'; 64 * 1024];
    for blob in [zip_of(&one_large), flat] {
        let mut spilling = tiny_object_limit();
        spilling.spill = Some(std::sync::Arc::new(MemSpill::new()));
        let report = scan_seekable(
            &db,
            std::io::Cursor::new(blob.clone()),
            blob.len() as u64,
            &spilling,
        )
        .expect("scan");
        assert_eq!(report.verdict, Verdict::Clean, "a spill completes the scan");
        let size = blob.len() as u64;
        let report = scan_seekable(
            &db,
            std::io::Cursor::new(blob.clone()),
            size,
            &tiny_object_limit(),
        )
        .expect("scan");
        match report.verdict {
            Verdict::LimitsExceeded { reason } => {
                assert!(reason.contains("--max-object-bytes"), "{reason}")
            }
            other => panic!("expected LIMITS-EXCEEDED, got {other:?}"),
        }
        // Under ClamAV's naming it is the size alert ClamAV raises.
        let mut alert = tiny_object_limit();
        alert.alert_exceeds_max = true;
        let report = scan_seekable(&db, std::io::Cursor::new(blob), size, &alert).expect("scan");
        match report.verdict {
            Verdict::Infected { signature, .. } => {
                assert_eq!(signature, "Heuristics.Limits.Exceeded.MaxFileSize")
            }
            other => panic!("expected the MaxFileSize alert, got {other:?}"),
        }
    }
}

/// A DMG is walked off its source, decompressing only what the filesystem
/// reaches, so its files are scanned at any size.
#[cfg(feature = "all-formats")]
#[test]
fn an_oversize_disk_image_has_its_files_scanned() {
    let mut l = loader::Builder::new();
    // "hello hfs+", the one file on the image.
    l.add_named_bytes("t.ndb", b"Zzz.InDmg:0:*:68656c6c6f206866732b\n", true);
    let db = l.build().expect("build database");
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../exav-unpack/tests/fixtures/dmg/hfs_plus_udzo.dmg"
    );
    let blob = std::fs::read(path).unwrap();
    assert!(blob.len() > 4096);
    assert!(!blob.windows(10).any(|w| w == b"hello hfs+"), "compressed");
    let size = blob.len() as u64;
    let report =
        scan_seekable(&db, std::io::Cursor::new(blob), size, &tiny_object_limit()).expect("scan");
    match report.verdict {
        Verdict::Infected { signature, .. } => assert_eq!(signature, "Zzz.InDmg"),
        other => panic!("expected the file on the image to be found, got {other:?}"),
    }
}

/// A file inside a filesystem that is past the limit is read as it goes and
/// scanned from spill space, or is the size limit where there is none. The
/// image is compressed, so the signature is in no byte of it: only the file
/// holds it.
#[cfg(feature = "all-formats")]
#[test]
fn an_oversize_file_in_a_filesystem_is_scanned_from_spill_space() {
    // `frag.bin` of the fixture tree: 100000 bytes, made by `pat` with seed 9.
    let pat = |seed: u32, n: usize| -> Vec<u8> {
        (0..n)
            .map(|i| {
                if (i / 64) % 2 == 0 {
                    (((i as u32).wrapping_mul(2654435761)).wrapping_add(seed.wrapping_mul(40503))
                        >> 13) as u8
                } else {
                    b"abcdefghij0123456789"[(i + seed as usize) % 20]
                }
            })
            .collect()
    };
    // The bytes of `pat` repeat from one seed to another at some offsets, so
    // the window is one that no other file of the tree has.
    let file = pat(9, 100000);
    let hex: String = file[38400..38424]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut l = loader::Builder::new();
    l.add_named_bytes("t.ndb", format!("Zzz.InFile:0:*:{hex}\n").as_bytes(), true);
    let db = l.build().expect("build database");
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../exav-unpack/tests/fixtures/fs/squashfs_gzip.img.gz"
    );
    let mut image = Vec::new();
    std::io::Read::read_to_end(
        &mut flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap()),
        &mut image,
    )
    .unwrap();
    assert!(
        !image.windows(24).any(|w| w == &file[38400..38424]),
        "compressed"
    );
    let size = image.len() as u64;

    let mut spilling = tiny_object_limit();
    spilling.spill = Some(std::sync::Arc::new(MemSpill::new()));
    let report =
        scan_seekable(&db, std::io::Cursor::new(image.clone()), size, &spilling).expect("scan");
    match report.verdict {
        Verdict::Infected { signature, .. } => assert_eq!(signature, "Zzz.InFile"),
        other => panic!("expected the file to be found, got {other:?}"),
    }

    let report =
        scan_seekable(&db, std::io::Cursor::new(image), size, &tiny_object_limit()).expect("scan");
    match report.verdict {
        Verdict::LimitsExceeded { reason } => {
            assert!(reason.contains("--max-object-bytes"), "{reason}")
        }
        other => panic!(
            "expected LIMITS-EXCEEDED without spill space, got {other:?} {:?}",
            report.findings
        ),
    }
}

#[test]
fn oversize_flat_content_is_a_limit_too() {
    // Text past the cap has its normalised views made in spill space. With
    // none, those views were not scanned, so the file was not fully scanned.
    let db = scanner();
    let blob = vec![b'a'; 64 * 1024];
    let size = blob.len() as u64;
    let report =
        scan_seekable(&db, std::io::Cursor::new(blob), size, &tiny_object_limit()).expect("scan");
    match report.verdict {
        Verdict::LimitsExceeded { .. } => {}
        other => panic!("text past the cap had no views scanned; got {other:?}"),
    }
}

// ---- A member over the hold limit that is cut short, or cannot be spilled ----

const HOLD: u64 = 4096;

/// Spill space that cannot be made, or whose files cannot be written.
struct BrokenSpill {
    at_create: bool,
}

struct BrokenFile;

impl Spill for BrokenSpill {
    fn create(&self) -> Result<Box<dyn SpillWriter>, String> {
        if self.at_create {
            return Err("no room".to_string());
        }
        Ok(Box::new(BrokenFile))
    }
}

impl SpillWriter for BrokenFile {
    fn write(&mut self, _: &[u8]) -> Result<(), String> {
        Err("disk full".to_string())
    }

    fn finish(self: Box<Self>) -> Result<Box<dyn SpillReader>, String> {
        Err("disk full".to_string())
    }
}

/// How a scan ended, the same for the first-match and the all-matches walk.
#[derive(Debug, PartialEq)]
enum Got {
    Found,
    Clean,
    Limits(String),
    Unscannable(String),
    Other(String),
}

fn is_eicar(name: &str) -> bool {
    name.to_ascii_uppercase().contains("EICAR")
}

fn first_match(blob: &[u8], opts: &ScanOptions) -> Got {
    let report = scan_seekable(
        &Scanner::builtin(),
        std::io::Cursor::new(blob.to_vec()),
        blob.len() as u64,
        opts,
    )
    .expect("scan");
    match report.verdict {
        Verdict::Infected { signature, .. } if is_eicar(&signature) => Got::Found,
        Verdict::Clean => Got::Clean,
        Verdict::LimitsExceeded { reason } => Got::Limits(reason),
        Verdict::Unscannable { reason } => Got::Unscannable(reason),
        other => Got::Other(format!("{other:?}")),
    }
}

fn all_matches(blob: &[u8], opts: &ScanOptions) -> Got {
    let (names, outcome) = analyze_all_seekable(
        &Scanner::builtin(),
        std::io::Cursor::new(blob.to_vec()),
        blob.len() as u64,
        opts,
    )
    .expect("scan");
    if names.iter().any(|(n, _)| is_eicar(n)) {
        return Got::Found;
    }
    match outcome {
        AllMatchOutcome::Complete => Got::Clean,
        AllMatchOutcome::LimitsExceeded(r) => Got::Limits(r),
        AllMatchOutcome::Unscannable(r) => Got::Unscannable(r),
        other => Got::Other(format!("{other:?}")),
    }
}

/// One gzip member three ways: whole, ended early, and damaged after a part
/// that decodes. Its payload is 200000 bytes of 16 letters in random order, so
/// the stream is large and EICAR, which the deflate coder does not leave as
/// plain text, is in no byte of the file.
struct Gzips {
    whole: Vec<u8>,
    cut: Vec<u8>,
    damaged: Vec<u8>,
}

/// The payload with EICAR at `at`, if any.
fn gzips(at: Option<usize>) -> Gzips {
    let mut s = 0x9E37_79B9_7F4A_7C15u64;
    let mut payload: Vec<u8> = (0..200_000)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            b'a' + (s >> 32) as u8 % 16
        })
        .collect();
    let eicar = exav_core::unpack::eicar();
    if let Some(at) = at {
        payload[at..at + eicar.len()].copy_from_slice(eicar);
    }
    // Every block flushed to a byte boundary, none of them the last.
    let mut open = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    open.write_all(&payload).unwrap();
    open.flush().unwrap();
    let mut cut = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];
    cut.extend_from_slice(open.get_ref());
    let mut damaged = cut.clone();
    // A final block of the reserved type.
    damaged.extend_from_slice(&[0x07, 0, 0, 0, 0, 0, 0, 0, 0]);
    let mut whole = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    whole.write_all(&payload).unwrap();
    let whole = whole.finish().unwrap();
    for gz in [&whole, &cut, &damaged] {
        assert!(gz.len() > 50_000, "{}", gz.len());
        assert!(!gz.windows(eicar.len()).any(|w| w == eicar), "plain text");
    }
    Gzips {
        whole,
        cut,
        damaged,
    }
}

fn tar_of(name: &str, data: &[u8]) -> Vec<u8> {
    let mut ar = tar::Builder::new(Vec::new());
    let mut h = tar::Header::new_gnu();
    h.set_size(data.len() as u64);
    h.set_cksum();
    ar.append_data(&mut h, name, data).unwrap();
    ar.into_inner().unwrap()
}

/// The same member at the top, in a tar, and in a tar in a tar.
fn nested(gz: &[u8]) -> [(&'static str, Vec<u8>); 3] {
    let in_tar = tar_of("m.gz", gz);
    let in_tars = tar_of("inner.tar", &in_tar);
    [
        ("file", gz.to_vec()),
        ("tar", in_tar),
        ("tar in tar", in_tars),
    ]
}

fn spilling(cache: bool) -> ScanOptions {
    let mut o = ScanOptions::default();
    o.limits.max_buffer_bytes = HOLD;
    o.spill = Some(Arc::new(MemSpill::new()));
    if cache {
        // Two blocks of 1 KiB: the spilled member is read back through evictions.
        o.object_cache_block_bytes = 1024;
        o.object_cache_bytes = 2048;
    }
    o
}

/// A member over the hold limit that fails to decode part way is spilled up to
/// the failure, and what was spilled is scanned, as a member under the limit
/// is. EICAR is inside the 4 KiB held before the spill, or only in the spill
/// file.
#[test]
fn a_spilled_member_cut_short_or_damaged_is_scanned_up_to_the_failure() {
    let mut wrong = Vec::new();
    for at in [1000, 10_000] {
        let gz = gzips(Some(at));
        for (how, bad) in [("cut", &gz.cut), ("damaged", &gz.damaged)] {
            for (where_, blob) in nested(bad) {
                for cache in [false, true] {
                    let opts = spilling(cache);
                    for (walk, got) in [
                        ("first match", first_match(&blob, &opts)),
                        ("all matches", all_matches(&blob, &opts)),
                    ] {
                        if got != Got::Found {
                            wrong.push(format!(
                                "EICAR at {at}, {how}, {where_}, cache {cache}, {walk}: {got:?}"
                            ));
                        }
                    }
                }
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// The rule for a member under the limit holds for a spilled one: a stream
/// that ends early has its rest absent, so a clean prefix is OK; damage with
/// bytes after it leaves them unread, so it is not.
#[test]
fn a_spilled_member_without_malware_follows_the_rule_of_a_held_one() {
    let gz = gzips(None);
    let mut wrong = Vec::new();
    for (where_, blob) in nested(&gz.cut) {
        for (walk, got) in [
            ("first match", first_match(&blob, &spilling(false))),
            ("all matches", all_matches(&blob, &spilling(false))),
        ] {
            if got != Got::Clean {
                wrong.push(format!("cut, {where_}, {walk}: {got:?}"));
            }
        }
    }
    for (where_, blob) in nested(&gz.damaged) {
        for (walk, got) in [
            ("first match", first_match(&blob, &spilling(false))),
            ("all matches", all_matches(&blob, &spilling(false))),
        ] {
            match got {
                Got::Unscannable(r) if r.contains("salvaged") => {}
                other => wrong.push(format!("damaged, {where_}, {walk}: {other:?}")),
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

fn tar_of_parts(parts: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut ar = tar::Builder::new(Vec::new());
    for (name, data) in parts {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_cksum();
        ar.append_data(&mut h, name, &data[..]).unwrap();
    }
    ar.into_inner().unwrap()
}

/// The three parts of `whole` cut at equal lengths, named `stem.001` to `.003`.
fn three_parts(stem: &str, whole: &[u8]) -> Vec<(String, Vec<u8>)> {
    let each = whole.len().div_ceil(3);
    whole
        .chunks(each)
        .enumerate()
        .map(|(i, c)| (format!("{stem}.{:03}", i + 1), c.to_vec()))
        .collect()
}

/// The parts of a byte-split set are held in memory to be rejoined once the
/// container has been walked. A part over the hold limit is scanned where it
/// lies and cannot be held, so a set with one is not rejoined: it is never OK.
/// Here every part is over the limit.
#[test]
fn a_byte_split_set_in_a_tar_with_every_part_over_the_hold_limit_is_never_ok() {
    let gz = gzips(Some(150_000)).whole;
    let binary: Vec<u8> = (0..90_000u32).map(|i| (i * 7 % 251) as u8).collect();
    let mut wrong = Vec::new();
    // What is reported with no spill: the gzip part, over the limit when
    // decoded too, ranks above the set.
    for (what, parts, without_spill) in [
        ("gzip in parts", three_parts("p.gz", &gz), "limit"),
        (
            "other bytes in parts",
            three_parts("p.bin", &binary),
            "unscannable",
        ),
    ] {
        assert!(
            parts.iter().all(|(_, p)| p.len() as u64 > HOLD),
            "parts over the limit"
        );
        let tar = tar_of_parts(&parts);
        for spill in [true, false] {
            let mut opts = ScanOptions::default();
            opts.limits.max_buffer_bytes = HOLD;
            if spill {
                opts.spill = Some(Arc::new(MemSpill::new()));
            }
            for (walk, got) in [
                ("first match", first_match(&tar, &opts)),
                ("all matches", all_matches(&tar, &opts)),
            ] {
                let ok = match (&got, spill, without_spill) {
                    (Got::Unscannable(r), _, "unscannable") | (Got::Unscannable(r), true, _) => {
                        r.contains("could not be held for rejoining")
                    }
                    (Got::Limits(r), false, "limit") => r.contains("could not be spilled"),
                    _ => false,
                };
                if !ok {
                    wrong.push(format!("{what}, spill {spill}, {walk}: {got:?}"));
                }
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// With checksums verified, a member that fails to decode is not scanned in
/// part, held or spilled: it is reported.
#[cfg(feature = "checksums")]
#[test]
fn a_spilled_member_that_fails_to_decode_is_reported_when_checksums_are_verified() {
    let gz = gzips(Some(10_000));
    let mut opts = spilling(false);
    opts.verify_checksums = true;
    for (where_, blob) in nested(&gz.damaged) {
        for (walk, got) in [
            ("first match", first_match(&blob, &opts)),
            ("all matches", all_matches(&blob, &opts)),
        ] {
            assert!(
                matches!(got, Got::Unscannable(_)),
                "{where_}, {walk}: {got:?}"
            );
        }
    }
}

/// A member over the hold limit that cannot be spilled has the bytes already
/// read scanned: a detection in them is reported, and if there is none the
/// size limit is, as for a file over `--max-input-bytes`.
#[test]
fn a_member_that_cannot_be_spilled_has_its_first_bytes_scanned() {
    let spills: [(&str, Option<Arc<dyn Spill>>); 3] = [
        ("spilling off", None),
        (
            "no spill file",
            Some(Arc::new(BrokenSpill { at_create: true })),
        ),
        (
            "spill write fails",
            Some(Arc::new(BrokenSpill { at_create: false })),
        ),
    ];
    let mut wrong = Vec::new();
    for (label, spill) in spills {
        let mut opts = ScanOptions::default();
        opts.limits.max_buffer_bytes = HOLD;
        opts.spill = spill;
        for at in [1000, 10_000] {
            // Whole, cut short and damaged: the bytes read are the same.
            let gz = gzips(Some(at));
            for (how, bad) in [
                ("whole", &gz.whole),
                ("cut", &gz.cut),
                ("damaged", &gz.damaged),
            ] {
                for (where_, blob) in nested(bad) {
                    for (walk, got) in [
                        ("first match", first_match(&blob, &opts)),
                        ("all matches", all_matches(&blob, &opts)),
                    ] {
                        let ok = match (&got, at) {
                            (Got::Found, 1000) => true,
                            (Got::Limits(r), 10_000) => {
                                r.contains("could not be spilled")
                                    && r.contains("--max-object-bytes")
                                    && r.contains(&format!("first {HOLD} bytes"))
                            }
                            _ => false,
                        };
                        if !ok {
                            wrong.push(format!(
                                "{label}, EICAR at {at}, {how}, {where_}, {walk}: {got:?}"
                            ));
                        }
                    }
                }
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// Under `--alert-exceeds-max` the size alert is the report for a member whose
/// first bytes hold nothing, and a detection in them still wins.
#[test]
fn a_detection_in_the_first_bytes_of_an_unspilled_member_wins_over_the_size_alert() {
    let mut opts = ScanOptions::default();
    opts.limits.max_buffer_bytes = HOLD;
    opts.alert_exceeds_max = true;
    for (at, want) in [
        (1000, "EICAR"),
        (10_000, "Heuristics.Limits.Exceeded.MaxFileSize"),
    ] {
        let gz = gzips(Some(at));
        for (where_, blob) in nested(&gz.whole) {
            let report = scan_seekable(
                &Scanner::builtin(),
                std::io::Cursor::new(blob.clone()),
                blob.len() as u64,
                &opts,
            )
            .expect("scan");
            match report.verdict {
                Verdict::Infected { signature, .. } => assert!(
                    signature
                        .to_ascii_uppercase()
                        .contains(&want.to_ascii_uppercase()),
                    "EICAR at {at}, {where_}: {signature}"
                ),
                other => panic!("EICAR at {at}, {where_}: {other:?}"),
            }
        }
    }
}
