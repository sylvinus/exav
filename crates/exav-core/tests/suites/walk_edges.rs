//! Edges of the recursive walk of containers: a member that is its own
//! container, and the depth a plain member may sit at.
//!
//! The payload is EICAR inside a gzip or a deflated ZIP member, so it is in no
//! byte of the file and is found only by unpacking down to it.

use std::io::Write;

use exav_core::{
    AllMatchOutcome, ScanOptions, Scanner, Verdict, analyze_all_seekable, scan_seekable,
};
use exav_unpack::zip_write::{FileOptions, Method, ZipWriter};

fn eicar() -> &'static [u8] {
    exav_core::unpack::eicar()
}

/// EICAR and enough after it that the deflate coder does not store the data
/// as it is.
fn payload() -> Vec<u8> {
    let mut p = eicar().to_vec();
    p.extend(std::iter::repeat_n(b'A', 2000));
    p
}

fn has_eicar(bytes: &[u8]) -> bool {
    bytes.windows(eicar().len()).any(|w| w == eicar())
}

fn gzip_of_payload() -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(&payload()).unwrap();
    let gz = e.finish().unwrap();
    assert!(!has_eicar(&gz), "plain text");
    gz
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

fn first_match(blob: &[u8], opts: &ScanOptions) -> Got {
    let report = scan_seekable(
        &Scanner::builtin(),
        std::io::Cursor::new(blob.to_vec()),
        blob.len() as u64,
        opts,
    )
    .expect("scan");
    match report.verdict {
        Verdict::Infected { signature, .. } if signature.to_ascii_uppercase().contains("EICAR") => {
            Got::Found
        }
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
    if names
        .iter()
        .any(|(n, _)| n.to_ascii_uppercase().contains("EICAR"))
    {
        return Got::Found;
    }
    match outcome {
        AllMatchOutcome::Complete => Got::Clean,
        AllMatchOutcome::LimitsExceeded(r) => Got::Limits(r),
        AllMatchOutcome::Unscannable(r) => Got::Unscannable(r),
        other => Got::Other(format!("{other:?}")),
    }
}

/// Scan `blob` both ways under `opts` and fail with every walk that is not `want`.
fn both(blob: &[u8], opts: &ScanOptions, label: &str, want: impl Fn(&Got) -> bool) {
    let mut wrong = Vec::new();
    for (walk, got) in [
        ("first match", first_match(blob, opts)),
        ("all matches", all_matches(blob, opts)),
    ] {
        if !want(&got) {
            wrong.push(format!("{label}, {walk}: {got:?}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// A Mach-O universal binary (big-endian table, 20-byte records) of the given
/// `(offset, size)` slices, then `body` at `at`.
fn fat(slices: &[(u32, u32)], at: usize, body: &[u8]) -> Vec<u8> {
    let mut f = 0xCAFE_BABEu32.to_be_bytes().to_vec();
    f.extend((slices.len() as u32).to_be_bytes());
    for (offset, size) in slices {
        for field in [7u32, 3, *offset, *size, 0] {
            f.extend(field.to_be_bytes());
        }
    }
    assert!(f.len() <= at);
    f.resize(at, 0);
    f.extend_from_slice(body);
    f
}

/// A member that is the whole of its container is skipped: it would be typed
/// as the same container and yield the same member until the recursion limit
/// was spent, and the sibling that holds the payload would never be reached.
/// The reader of a universal binary names a slice from offset 0 to the end,
/// which a real one never does.
#[test]
fn a_member_that_is_its_container_is_skipped_by_bytes_and_by_range() {
    let gz = gzip_of_payload();
    let at = 8 + 2 * 20;
    // Zeros after the payload make the container larger than it.
    let mut body = gz.clone();
    body.resize(gz.len() + 4000, 0);
    let total = at + body.len();
    let blob = fat(
        &[(0, total as u32), (at as u32, gz.len() as u32)],
        at,
        &body,
    );
    assert_eq!(blob.len(), total);
    assert!(!has_eicar(&blob));

    // Held: the slice is a member of the same bytes.
    let default = ScanOptions::default();
    both(&blob, &default, "held", |g| *g == Got::Found);

    // Past the hold limit: the slice is named by its range, which is all of
    // the container. The payload still fits under the limit.
    let mut ranged = ScanOptions::default();
    ranged.limits.max_buffer_bytes = payload().len() as u64 + 10;
    assert!(blob.len() as u64 > ranged.limits.max_buffer_bytes);
    both(&blob, &ranged, "by range", |g| *g == Got::Found);
}

/// An MBR whose first entry starts at sector 0 and takes the whole disk, next
/// to an entry that makes it a partition table: the first partition is the
/// disk, byte for byte.
#[test]
fn a_partition_that_is_the_whole_disk_is_skipped() {
    let gz = gzip_of_payload();
    let mut disk = vec![0u8; 1024];
    let entry = |disk: &mut Vec<u8>, at: usize, lba: u32, sectors: u32| {
        disk[at + 4] = 0x83;
        disk[at + 8..at + 12].copy_from_slice(&lba.to_le_bytes());
        disk[at + 12..at + 16].copy_from_slice(&sectors.to_le_bytes());
    };
    entry(&mut disk, 446, 0, 2);
    entry(&mut disk, 462, 1, 1);
    disk[510..512].copy_from_slice(&[0x55, 0xAA]);
    disk[512..512 + gz.len()].copy_from_slice(&gz);

    both(&disk, &ScanOptions::default(), "mbr", |g| *g == Got::Found);
}

fn zip_of(name: &str, data: &[u8], deflated: bool) -> Vec<u8> {
    let mut z = ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let method = if deflated {
        Method::Deflated
    } else {
        Method::Stored
    };
    z.start_file(name, FileOptions::default().method(method))
        .unwrap();
    z.write_all(data).unwrap();
    z.finish().unwrap().into_inner()
}

/// The depth limit is on containers: one at the limit is not opened, but a
/// plain member that sits at the limit is scanned. `outer.zip` is at depth 0,
/// `inner.zip` at 1, `leaf.txt` at 2.
#[test]
fn a_plain_member_at_the_depth_limit_is_scanned_and_a_container_is_not_opened() {
    let leaf = zip_of("leaf.txt", &payload(), true);
    let nested = zip_of("inner.zip", &leaf, false);
    assert!(!has_eicar(&nested));
    for (depth, found) in [(0, false), (1, false), (2, true), (3, true), (16, true)] {
        let mut opts = ScanOptions::default();
        opts.limits.max_recursion = depth;
        both(&nested, &opts, &format!("depth {depth}"), |g| {
            match (g, found) {
                (Got::Found, true) => true,
                (Got::Limits(r), false) => r.contains(&format!("recursion depth exceeds {depth}")),
                _ => false,
            }
        });
    }
}

/// A ZIP of the given `(name, data, deflated)` members, in order.
fn zip_of_many(members: &[(&str, &[u8], bool)]) -> Vec<u8> {
    let mut z = ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, data, deflated) in members {
        let method = if *deflated {
            Method::Deflated
        } else {
            Method::Stored
        };
        z.start_file(name, FileOptions::default().method(method))
            .unwrap();
        z.write_all(data).unwrap();
    }
    z.finish().unwrap().into_inner()
}

/// A spill whose files cannot be asked for: the host's code panics.
struct PanickingSpill;

impl exav_core::spill::Spill for PanickingSpill {
    fn create(&self) -> Result<Box<dyn exav_core::spill::SpillWriter>, String> {
        panic!("the host's spill panicked");
    }
}

/// Code that is not a reader panics while a member is taken: here the host's
/// `Spill`, asked for a file by a member over the hold limit. The panic is a
/// reason at that member, not the container's decoder panicking, and the
/// members after it are scanned.
#[test]
#[cfg_attr(target_family = "wasm", ignore = "a panic aborts under WASI")]
fn a_panic_of_the_host_while_a_member_is_taken_is_a_reason_at_that_member_and_the_next_are_scanned()
{
    let zip = zip_of_many(&[
        ("small.txt", b"nothing here", true),
        ("big.bin", &vec![b'A'; 10_000], true),
        ("after.txt", &payload(), true),
    ]);
    assert!(!has_eicar(&zip), "plain text");
    let mut opts = ScanOptions::default();
    opts.limits.max_buffer_bytes = 4096;
    opts.spill = Some(std::sync::Arc::new(PanickingSpill));
    both(&zip, &opts, "host spill panics, payload after", |g| {
        *g == Got::Found
    });
    // With nothing to find after it, the member that panicked is a reason.
    let zip = zip_of_many(&[
        ("small.txt", b"nothing here", true),
        ("big.bin", &vec![b'A'; 10_000], true),
        ("after.txt", b"nothing either", true),
    ]);
    both(&zip, &opts, "host spill panics, nothing after", |g| {
        matches!(g, Got::Unscannable(r)
            if r == "a panic while the object was being examined: it was not fully examined")
    });
    // Without the member that panics, the one after it is found.
    let zip = zip_of_many(&[
        ("small.txt", b"nothing here", true),
        ("after.txt", &payload(), true),
    ]);
    both(&zip, &opts, "control", |g| *g == Got::Found);
}

/// A spill whose files take what is written and fail on every read.
struct UnreadableSpill;

struct UnreadableWriter(u64);

struct Unreadable(u64);

impl exav_core::spill::Spill for UnreadableSpill {
    fn create(&self) -> Result<Box<dyn exav_core::spill::SpillWriter>, String> {
        Ok(Box::new(UnreadableWriter(0)))
    }
}

impl exav_core::spill::SpillWriter for UnreadableWriter {
    fn write(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.0 += bytes.len() as u64;
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<Box<dyn exav_core::spill::SpillReader>, String> {
        Ok(Box::new(Unreadable(self.0)))
    }
}

impl std::io::Read for Unreadable {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("the spill file is gone"))
    }
}

impl std::io::Seek for Unreadable {
    fn seek(&mut self, to: std::io::SeekFrom) -> std::io::Result<u64> {
        Ok(match to {
            std::io::SeekFrom::End(_) => self.0,
            std::io::SeekFrom::Start(n) => n,
            std::io::SeekFrom::Current(_) => 0,
        })
    }
}

/// A member written to the spill and then not readable from it was not
/// scanned: the container is not clean, and the members after it are still
/// scanned.
#[test]
fn a_spilled_member_that_cannot_be_read_back_is_not_clean() {
    let zip = zip_of_many(&[
        ("big.bin", &vec![b'A'; 10_000], true),
        ("after.txt", &payload(), true),
    ]);
    assert!(!has_eicar(&zip), "plain text");
    let mut opts = ScanOptions::default();
    opts.limits.max_buffer_bytes = 4096;
    opts.spill = Some(std::sync::Arc::new(UnreadableSpill));
    both(&zip, &opts, "after.txt held", |g| *g == Got::Found);
    let zip = zip_of_many(&[("big.bin", &vec![b'A'; 10_000], true)]);
    both(
        &zip,
        &opts,
        "unreadable",
        |g| matches!(g, Got::Unscannable(r) if r.contains("spilled member unreadable")),
    );
}

/// A detection in what a stream member holds stands when the charge for the
/// member's own bytes, made once its visit is over, runs past the scan budget.
#[test]
fn a_detection_inside_a_stream_member_wins_over_its_charge() {
    let mut body = vec![b'.'; 190_000];
    body.extend_from_slice(eicar());
    let mut ar = tar::Builder::new(Vec::new());
    let mut h = tar::Header::new_gnu();
    h.set_size(body.len() as u64);
    h.set_cksum();
    ar.append_data(&mut h, "pad.txt", &body[..]).unwrap();
    let tar = ar.into_inner().unwrap();
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(&tar).unwrap();
    let gz = e.finish().unwrap();
    assert!(!has_eicar(&gz), "plain text");
    let mut opts = ScanOptions::default();
    // The tar's file fits, and so does the tar, but not the two together.
    opts.limits.max_scanned_bytes = 300_000;
    both(&gz, &opts, "charged after the visit", |g| *g == Got::Found);
}

/// A text view written to the spill and then not readable from it was not
/// matched: the object is not clean.
#[test]
fn a_spilled_view_that_cannot_be_read_back_is_not_clean() {
    // A text, which has normalised views and no reader of what it shows.
    let text = b"some words of text\n".repeat(600);
    let mut opts = ScanOptions::default();
    opts.limits.max_buffer_bytes = 4096;
    opts.spill = Some(std::sync::Arc::new(UnreadableSpill));
    both(
        &text,
        &opts,
        "unreadable view",
        |g| matches!(g, Got::Unscannable(r) if r.contains("the spill file is gone")),
    );
}

/// A stored member over the hold limit is read where it lies in its container,
/// so the walk does not see its bytes go by: it is charged to the budget of
/// scanned bytes by its length, once.
#[test]
fn a_stored_member_read_in_place_is_charged_to_the_scan_budget_by_its_length() {
    let member = vec![b'B'; 100_000];
    let zip = zip_of_many(&[("big.bin", &member, false)]);
    let mut opts = ScanOptions::default();
    opts.limits.max_buffer_bytes = 16 * 1024;
    // The text of the member is viewed from a spill, which is not what is measured.
    opts.spill = Some(std::sync::Arc::new(
        exav_core::unpack::spill::MemSpill::new(),
    ));
    assert!(opts.limits.max_buffer_bytes < member.len() as u64);
    for (budget, within) in [
        (member.len() as u64 - 1, false),
        (member.len() as u64, true),
        (member.len() as u64 + 1, true),
    ] {
        opts.limits.max_scanned_bytes = budget;
        both(&zip, &opts, &format!("budget {budget}"), |g| {
            match (g, within) {
                (Got::Clean, true) => true,
                (Got::Limits(r), false) => r.contains(&format!("scanned bytes > {budget}")),
                _ => false,
            }
        });
    }
}

/// An object found in another one, as a payload decoded from its text, sits a
/// level below it and is decoded only while the object is below the limit.
/// The depth is on the object that carries the payload: a script at depth `d`
/// has its payload decoded when `d` is under `max_recursion`. At the limit the
/// payload is not decoded, and the scan says so: a limit, not a clean verdict.
#[test]
fn a_payload_decoded_from_a_text_is_decoded_below_the_depth_limit_and_a_limit_at_it() {
    use base64::Engine as _;
    let mut pe = vec![0u8; 2048];
    pe[0] = b'M';
    pe[1] = b'Z';
    pe[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    pe[0x40..0x44].copy_from_slice(b"PE\x00\x00");
    pe[0x80..0x80 + eicar().len()].copy_from_slice(eicar());
    let b64 = base64::engine::general_purpose::STANDARD.encode(&pe);
    let script = format!(
        "# dropper\r\n$PEBytes = \"{b64}\"\r\nInvoke-ReflectivePEInjection -PEBytes $PEBytes\r\n"
    )
    .into_bytes();
    assert!(!has_eicar(&script));
    // The script at the top is at depth 0, in a ZIP at depth 1.
    let zipped = zip_of("dropper.ps1", &script, true);
    assert!(!has_eicar(&zipped));
    for (blob, label, at) in [(&script, "top", 0u32), (&zipped, "member", 1u32)] {
        for depth in 0..4 {
            let mut opts = ScanOptions::default();
            opts.limits.max_recursion = depth;
            let found = at < depth;
            both(
                blob,
                &opts,
                &format!("{label} script, limit {depth}"),
                |g| {
                    match (g, found) {
                        (Got::Found, true) => true,
                        // A ZIP at the limit is not opened, a script at the
                        // limit does not have its payload decoded: each says so.
                        (Got::Limits(r), false) => r.contains("recursion depth exceeds"),
                        _ => false,
                    }
                },
            );
        }
    }
}

/// The limit is said only when there is a payload that would have been decoded:
/// a script with nothing encoded in it, at the limit, is clean. The same for
/// the assets of a page.
#[test]
fn a_text_at_the_depth_limit_with_nothing_to_decode_is_clean_and_with_an_asset_is_a_limit() {
    use base64::Engine as _;
    let plain = b"# a script\r\nWrite-Host 'nothing encoded here'\r\n".to_vec();
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png.extend_from_slice(&[0, 0, 0, 13]);
    png.extend_from_slice(b"IHDR");
    png.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0]);
    png.extend_from_slice(&[0; 4]);
    png.extend_from_slice(eicar());
    png.extend_from_slice(&[0u8; 64]);
    let b64 = base64::engine::general_purpose::STANDARD.encode(&png);
    let page =
        format!("<html><body><img src=\"data:image/png;base64,{b64}\"></body></html>").into_bytes();
    let bare = b"<html><body><p>no assets</p></body></html>".to_vec();
    for (blob, label, limit_is_said) in [
        (&plain, "plain script", false),
        (&bare, "page with no asset", false),
        (&page, "page with an asset", true),
    ] {
        // Depth 0 is the limit: the text is at the limit.
        let mut opts = ScanOptions::default();
        opts.limits.max_recursion = 0;
        both(blob, &opts, label, |g| match (g, limit_is_said) {
            (Got::Clean, false) => true,
            (Got::Limits(r), true) => r.contains("recursion depth exceeds 0"),
            _ => false,
        });
        // One level of room: the asset is decoded, and is found.
        opts.limits.max_recursion = 1;
        both(blob, &opts, label, |g| {
            matches!((g, limit_is_said), (Got::Clean, false) | (Got::Found, true))
        });
    }
    // Where a bound is an alert, it is the alert.
    let mut opts = ScanOptions::default();
    opts.limits.max_recursion = 0;
    opts.alert_exceeds_max = true;
    match first_match(&page, &opts) {
        Got::Other(verdict) => assert!(verdict.contains("MaxRecursion"), "{verdict}"),
        other => panic!("{other:?}"),
    }
}

/// A scanner that knows three marker strings, by name.
fn marker_scanner() -> Scanner {
    let hex = |s: &str| s.bytes().map(|b| format!("{b:02x}")).collect::<String>();
    let mut l = exav_core::loader::Builder::new();
    let ndb = format!(
        "Test.First:0:*:{}\nTest.Second:0:*:{}\n",
        hex("marker-first-aaaa"),
        hex("marker-second-bbbb"),
    );
    l.add_named_bytes("t.ndb", ndb.as_bytes(), true);
    l.build().expect("build database")
}

/// A spill that counts the files it is asked for, and fails them.
struct CountingSpill(std::sync::atomic::AtomicUsize);

impl exav_core::spill::Spill for CountingSpill {
    fn create(&self) -> Result<Box<dyn exav_core::spill::SpillWriter>, String> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err("no spill".to_string())
    }
}

/// A detection ends the walk of the container: the members before it were
/// scanned (a clean one, and one that reports a reason, do not mask it) and
/// those after it are not reached. All-matches goes on to them.
#[test]
fn a_detection_ends_the_walk_with_the_members_before_it_scanned_and_those_after_it_not() {
    let zip = zip_of_many(&[
        ("clean.txt", b"nothing to see", true),
        ("first.txt", b"marker-first-aaaa", true),
        ("big.bin", &vec![b'A'; 10_000], true),
        ("second.txt", b"marker-second-bbbb", true),
    ]);
    let spill = std::sync::Arc::new(CountingSpill(Default::default()));
    let mut opts = ScanOptions::default();
    opts.limits.max_buffer_bytes = 4096;
    opts.spill = Some(spill.clone());
    let db = marker_scanner();
    let report = scan_seekable(
        &db,
        std::io::Cursor::new(zip.clone()),
        zip.len() as u64,
        &opts,
    )
    .expect("scan");
    match report.verdict {
        Verdict::Infected { signature, .. } => {
            assert!(signature.contains("Test.First"), "{signature}")
        }
        other => panic!("{other:?}"),
    }
    // `big.bin` was not reached: no file was asked of the spill for it.
    assert_eq!(spill.0.load(std::sync::atomic::Ordering::SeqCst), 0);
    // All matches does not stop: it reaches `big.bin` (whose spill fails, which
    // is reported as the member not scanned) and the member after it.
    let (names, outcome) = analyze_all_seekable(
        &db,
        std::io::Cursor::new(zip.clone()),
        zip.len() as u64,
        &opts,
    )
    .expect("scan");
    let names: Vec<_> = names.into_iter().map(|(n, _)| n).collect();
    assert!(names.iter().any(|n| n.contains("Test.First")), "{names:?}");
    assert!(names.iter().any(|n| n.contains("Test.Second")), "{names:?}");
    assert_eq!(spill.0.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(
        matches!(outcome, AllMatchOutcome::LimitsExceeded(_)),
        "{outcome:?}"
    );
}

/// Script Encoder's marker alone, four bytes a large file of any kind holds by
/// chance, is no encoded script: past the object limit such a file is clean,
/// as clamscan says. With a blob's header behind it, the file is read as one.
#[test]
fn a_script_encoder_marker_by_chance_is_no_encoded_script() {
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut blob: Vec<u8> = (0..3 << 20)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect();
    blob[2 << 20..][..4].copy_from_slice(b"#@~^");
    let mut opts = ScanOptions::default();
    opts.limits.max_buffer_bytes = 1 << 20;
    both(&blob, &opts, "a marker", |g| *g == Got::Clean);
    blob[(2 << 20) + 4..][..8].copy_from_slice(b"AAAAAA==");
    both(&blob, &opts, "a blob's header", |g| {
        matches!(g, Got::Limits(_))
    });
}
