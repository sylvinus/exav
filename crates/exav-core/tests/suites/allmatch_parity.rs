//! `--all-matches` must be a **superset** of a normal scan, never a subset.
//!
//! It is easy to assume this holds by construction and it does not. The two
//! paths are separate walks — `deep_analyze` stops at the first detection,
//! `collect_all` visits everything — and any capability added to one and not the
//! other silently changes *which signatures run*, not just how many names come
//! back.
//!
//! That happened: `collect_all` typed every extracted member with plain content
//! detection, while the first-match path forces textual OLE2 streams to type as
//! `Ole`. The 5,210 `Target:2` logical signatures in a live `main`+`daily` set
//! (plus 813 in `.ndb`) therefore never ran on macro streams under `--all-matches`,
//! and a real PowerPoint dropper that a normal scan flagged came back clean. It
//! surfaced only because a corpus diff against clamscan bucketed it as an exav
//! false negative.
//!
//! This test pins the invariant rather than the one bug.

use exav_core::{analyze, analyze_all, loader, ScanOptions, Scanner};
use std::io::Write;

/// A macro-stream signature: `Target:2` (OLE2) with a literal body, the exact
/// shape of the `Ppt.Malware.Sload` signatures that exposed the gap.
const MACRO_SIG_BODY: &[u8] = b"Attribute VB_Name = \"exavProbeModule\"";

/// Carried by the builtin baseline, so a scanner with no database still detects
/// it — which is what lets the depth test below use `Scanner::builtin()`.
const EICAR: &[u8] = br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;

fn scanner() -> Scanner {
    let hex: String = MACRO_SIG_BODY.iter().map(|b| format!("{b:02x}")).collect();
    let mut l = loader::Builder::new();
    l.add_named_bytes(
        "t.ndb",
        format!("Test.OleMacro:2:*:{hex}\n").as_bytes(),
        true,
    );
    l.build().expect("build database")
}

/// An OLE2 document carrying the macro text in a stream. The stream itself is
/// plain text, so content detection alone would type it as text — which is
/// precisely why the container's type has to be forced onto it.
fn ole_with_macro() -> Vec<u8> {
    let cursor = std::io::Cursor::new(Vec::<u8>::new());
    let mut cf = cfb::CompoundFile::create(cursor).expect("create OLE2");
    cf.create_storage("/VBA").expect("create /VBA storage");
    {
        let mut s = cf.create_stream("/VBA/Module1").expect("create stream");
        s.write_all(b"\r\n").unwrap();
        s.write_all(MACRO_SIG_BODY).unwrap();
        s.write_all(b"\r\nSub AutoOpen()\r\nEnd Sub\r\n").unwrap();
        s.flush().unwrap();
    }
    cf.flush().expect("flush");
    cf.into_inner().into_inner()
}

#[test]
fn allmatch_is_a_superset_of_a_normal_scan() {
    let db = scanner();
    let doc = ole_with_macro();

    let normal = matches!(
        analyze(&db, &doc, &ScanOptions::default()).verdict,
        exav_core::Verdict::Infected { .. }
    );
    let all: Vec<String> = analyze_all(&db, &doc, &ScanOptions::default())
        .into_iter()
        .map(|(n, _)| n)
        .collect();

    assert!(
        normal,
        "the fixture must be detected by a normal scan, or this test proves nothing"
    );
    assert!(
        all.iter().any(|n| n == "Test.OleMacro"),
        "--all-matches dropped a detection a normal scan makes: {all:?}. \
         `collect_all` must apply the same forced member type as `deep_analyze` — \
         a textual OLE2 stream is scanned AS `Ole` so `Target:2` signatures run."
    );
}

/// A PE header claiming 40 sections it does not have — `pe::looks_broken`.
fn broken_pe() -> Vec<u8> {
    let mut out = b"MZ".to_vec();
    out.extend(std::iter::repeat_n(0u8, 58));
    out.extend(64u32.to_le_bytes()); // e_lfanew
    out.extend(b"PE\0\0");
    out.extend(0x014cu16.to_le_bytes()); // machine
    out.extend(40u16.to_le_bytes()); // sections, none of which follow
    out.extend(std::iter::repeat_n(0u8, 12));
    out.extend(224u16.to_le_bytes()); // optional header size
    out.extend(0x0102u16.to_le_bytes()); // characteristics
    out.extend([0x0b, 0x01]); // PE32 magic
    out.extend(std::iter::repeat_n(0u8, 222));
    out
}

#[test]
fn allmatch_runs_the_same_heuristics_as_a_normal_scan() {
    // The superset invariant is not only about signatures. Every heuristic the
    // walk runs — broken executables, broken media, partition intersection, the
    // PDF obfuscated-name check, DLP, phishing, Authenticode — has to run under
    // `--all-matches` too, and each is a separate place a second traversal could
    // silently omit one. Sharing one walk is what makes that structural; this
    // pins it against a representative pair.
    let db = scanner();
    let pe = broken_pe();
    let opts = ScanOptions {
        alert_broken: true,
        ..ScanOptions::default()
    };

    let normal = matches!(
        analyze(&db, &pe, &opts).verdict,
        exav_core::Verdict::Infected { .. }
    );
    assert!(
        normal,
        "the fixture must trip the broken-executable heuristic on a normal \
         scan, or this test proves nothing"
    );

    let all: Vec<String> = analyze_all(&db, &pe, &opts)
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    assert!(
        all.iter().any(|n| n == "Heuristics.Broken.Executable"),
        "--all-matches did not run a heuristic a normal scan runs; got {all:?}"
    );
}

#[test]
#[cfg(feature = "dlp")]
fn allmatch_reports_structured_data_findings() {
    // DLP is the other shape: driven by its own thresholds rather than by
    // `--detect heuristics`, and applied at every recursion level.
    let db = scanner();
    let doc = "4111111111111111\n".repeat(40).into_bytes();
    let opts = ScanOptions {
        structured_cc_count: Some(5),
        ..ScanOptions::default()
    };

    assert!(
        matches!(
            analyze(&db, &doc, &opts).verdict,
            exav_core::Verdict::Infected { .. }
        ),
        "the fixture must trip the DLP threshold on a normal scan"
    );
    let all: Vec<String> = analyze_all(&db, &doc, &opts)
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    assert!(
        all.iter()
            .any(|n| n == "Heuristics.Structured.CreditCardNumber"),
        "--all-matches dropped a DLP finding a normal scan makes; got {all:?}"
    );
}

/// gzip, bzip2 and xz of the SAME body: 6 MiB of filler with EICAR at the very
/// end, so nothing short of reaching the end finds it.
///
/// Committed as fixtures rather than built in the test because only gzip has a
/// pure-Rust encoder in the dependency graph — `xz2` and `bzip2` are bindings to
/// C libraries, and exav does not take those, not even for tests. They are tiny
/// (124 B to 6 KiB) precisely because the body compresses so well, which is the
/// property under test.
fn compressor_fixture(name: &str) -> Vec<u8> {
    let p = format!(
        "{}/tests/fixtures/compressors/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

#[test]
#[cfg(all(feature = "gzip", feature = "bzip2", feature = "xz"))]
fn every_single_stream_compressor_streams_its_content() {
    // gzip, bzip2 and xz are the same shape: one stream whose output can be
    // orders of magnitude larger than the file. Each has to be walked as a
    // stream, or content past the per-member cap is never reached — and then
    // which compressor a payload happens to be wrapped in decides whether it is
    // found, which is not a property a scanner may have.
    let db = Scanner::builtin();
    let opts = ScanOptions {
        limits: exav_core::unpack::Limits {
            max_buffer_bytes: 1024 * 1024,
            ..Default::default()
        },
        ..ScanOptions::default()
    };

    for name in ["p.gz", "p.bz2", "p.xz"] {
        let blob = compressor_fixture(name);
        assert!(
            blob.len() < 64 * 1024,
            "{name} should be far smaller than the cap, or it is not testing \
             the decompressed reach"
        );
        let v = analyze(&db, &blob, &opts).verdict;
        assert!(
            matches!(v, exav_core::Verdict::Infected { .. }),
            "{name} did not reach content past the per-member cap: {v:?}"
        );
    }
}

/// A ZIP holding one deflated member far larger than a per-member cap, with the
/// payload at the very END so a truncated prefix cannot contain it.
fn zip_with_oversized_member(payload_tail: &[u8]) -> Vec<u8> {
    let mut body = vec![b'Z'; 6 * 1024 * 1024];
    body.extend_from_slice(payload_tail);
    let mut out = Vec::new();
    {
        let mut z = zip::ZipWriter::new(std::io::Cursor::new(&mut out));
        let o: zip::write::FileOptions<'_, ()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        z.start_file("big.bin", o).unwrap();
        std::io::Write::write_all(&mut z, &body).unwrap();
        z.finish().unwrap();
    }
    out
}

/// Wrap `data` as the single member of a tar, to push it one level deeper.
fn tar_wrapping(name: &str, data: &[u8]) -> Vec<u8> {
    let mut ar = tar::Builder::new(Vec::new());
    let mut h = tar::Header::new_gnu();
    h.set_size(data.len() as u64);
    h.set_cksum();
    ar.append_data(&mut h, name, data).unwrap();
    ar.into_inner().unwrap()
}

#[test]
#[cfg(all(feature = "zip", feature = "tar"))]
fn nesting_depth_does_not_change_what_a_scan_finds() {
    // A container whose members can be streamed must be walked that way at every
    // depth. When only the OUTERMOST container streamed, the same ZIP answered
    // differently depending on whether it was the file handed in or a member of
    // a tar: FOUND at depth 0, "archive member exceeds size budget" at depth 1,
    // because the buffered member walk caps a member at `max_buffer_bytes`.
    //
    // Identical bytes must give an identical verdict wherever they sit.
    let db = Scanner::builtin();
    let inner = zip_with_oversized_member(EICAR);
    let nested = tar_wrapping("inner.zip", &inner);
    // A cap far below the member's decompressed size, so buffering cannot reach
    // the payload at its end.
    let opts = ScanOptions {
        limits: exav_core::unpack::Limits {
            max_buffer_bytes: 1024 * 1024,
            ..Default::default()
        },
        ..ScanOptions::default()
    };

    let flat = analyze(&db, &inner, &opts).verdict;
    let deep = analyze(&db, &nested, &opts).verdict;
    assert!(
        matches!(flat, exav_core::Verdict::Infected { .. }),
        "the fixture must be detected at depth 0, or this test proves nothing; \
         got {flat:?}"
    );
    assert!(
        matches!(deep, exav_core::Verdict::Infected { .. }),
        "the same ZIP one level deeper was not detected: {deep:?}"
    );
}

/// An MBR whose first two partition entries claim overlapping sectors.
fn overlapping_mbr() -> Vec<u8> {
    let mut d = vec![0u8; 512 * 4096];
    let mut ent = |off: usize, start: u32, count: u32| {
        d[off + 1..off + 4].copy_from_slice(&[1, 1, 1]);
        d[off + 4] = 0x83;
        d[off + 5..off + 8].copy_from_slice(&[0xfe, 0xff, 0xff]);
        d[off + 8..off + 12].copy_from_slice(&start.to_le_bytes());
        d[off + 12..off + 16].copy_from_slice(&count.to_le_bytes());
    };
    ent(446, 2048, 1000);
    ent(446 + 16, 2500, 1000);
    d[510] = 0x55;
    d[511] = 0xAA;
    d
}

#[test]
fn a_streamed_container_gets_the_whole_object_checks_too() {
    // Some checks need the whole object rather than one member: overlapping ZIP
    // records, overlapping MBR partitions, broken media and executable headers.
    // A walk that holds one member at a time has to read the object again to
    // run them, and a partition map is a container that takes that walk — so
    // this is the case where the two ways in could disagree.
    //
    // What a scan does must not depend on how the bytes arrived.
    let db = Scanner::builtin();
    let img = overlapping_mbr();
    let opts = ScanOptions {
        alert_partition_intersection: true,
        ..ScanOptions::default()
    };

    let buffered = analyze(&db, &img, &opts).verdict;
    let streamed = exav_core::scan_seekable(
        &db,
        std::io::Cursor::new(img.clone()),
        img.len() as u64,
        &opts,
    )
    .expect("scan")
    .verdict;

    assert!(
        matches!(buffered, exav_core::Verdict::Infected { .. }),
        "the fixture must trip the heuristic on the buffered walk, or this \
         test proves nothing; got {buffered:?}"
    );
    assert!(
        matches!(streamed, exav_core::Verdict::Infected { .. }),
        "the same image scanned as a seekable stream missed a check the \
         buffered walk makes; got {streamed:?}"
    );
}

/// A stored-only ZIP of `n` distinct members.
fn zip_of_members(n: usize) -> Vec<u8> {
    let mut members = Vec::new();
    for i in 0..n {
        // Distinct bodies so nothing can be deduplicated by content, and large
        // enough that re-scanning the archive once per member dominates the
        // timing. At 4 KiB the quadratic term is only a few hundred milliseconds
        // against this suite's EICAR-only database — small enough that the
        // assertion below would not fire.
        members.push((
            format!("member{i:04}.bin"),
            vec![b'a' + (i % 26) as u8; 65536],
        ));
    }
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in &members {
        let crc = crc32(data);
        let offset = out.len() as u32;
        out.extend_from_slice(b"PK\x03\x04");
        for v in [20u16, 0, 0, 0, 0] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);

        central.extend_from_slice(b"PK\x01\x02");
        for v in [20u16, 20, 0, 0, 0, 0] {
            central.extend_from_slice(&v.to_le_bytes());
        }
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        for _ in 0..4 {
            central.extend_from_slice(&0u16.to_le_bytes());
        }
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let cd_offset = out.len() as u32;
    let cd_len = central.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(b"PK\x05\x06");
    for v in [0u16, 0, members.len() as u16, members.len() as u16] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&cd_len.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn crc32(data: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xEDB8_8320
            } else {
                c >> 1
            };
        }
    }
    !c
}

#[test]
fn allmatch_does_not_re_carve_a_container_into_itself() {
    // The superset invariant above says all-match must not do LESS than a normal
    // scan. This is the other side: it must not do vastly MORE of the same work.
    //
    // Every ZIP member's local file header is an embedded-archive offset. A walk
    // that carves those *and* extracts the container re-extracts the archive
    // from each member in turn — O(members^2) — and finds nothing extraction
    // has not already reached. A container's contents come from opening it.
    //
    // Asserted as a RATIO against the first-match walk over the identical input,
    // rather than an absolute time: the two do comparable work when this holds,
    // so the machine cancels out. The quadratic form is ~25x on this fixture,
    // loose enough not to be flaky and tight enough to catch.
    let db = scanner();
    // 150 x 64 KiB ~= 9.8 MB. Linear feeds the matcher ~20 MB; the quadratic
    // re-carve feeds it ~1.4 GB, which is well inside the default 10 GB
    // scan-byte cap and so runs to completion rather than being masked by it.
    let blob = zip_of_members(150);
    let opts = ScanOptions::default();

    // Warm both paths so neither pays a one-off setup cost in the measurement.
    let _ = analyze(&db, &blob, &opts);
    let _ = analyze_all(&db, &blob, &opts);

    let t0 = std::time::Instant::now();
    let _ = analyze(&db, &blob, &opts);
    let first_match = t0.elapsed();

    let t1 = std::time::Instant::now();
    let _ = analyze_all(&db, &blob, &opts);
    let all_match = t1.elapsed();

    // Guard the premise: if the first-match walk is immeasurably fast the ratio
    // is meaningless, so compare against a floor as well.
    let floor = std::time::Duration::from_millis(1);
    let base = first_match.max(floor);
    assert!(
        all_match < base * 25,
        "all-match took {all_match:?} against {first_match:?} for the same \
         150-member ZIP. That is the quadratic re-carve returning: a container's \
         members are reached by extraction, so the embedded-archive carve must \
         not also run on a buffer that was opened as a container."
    );
}

/// Two signatures in ONE member must both be reported under `--all-matches`,
/// whichever walk the member arrived on.
///
/// A member of a streamed container is scanned as a reader. If that path scans
/// the member's bytes with a first-match sink rather than the caller's, the
/// second signature in the same member is found by neither: the walk moves on to
/// the next member believing this one is accounted for. The buffered walk hands
/// its own sink down, so it reports both — the same bytes then answer
/// differently depending on the container they sit in, which is the divergence
/// `--all-matches` exists to not have.
#[test]
#[cfg(feature = "zip")]
fn allmatch_reports_every_signature_inside_a_single_streamed_member() {
    const SIG_A: &[u8] = b"exavProbeAlphaSignatureBody";
    const SIG_B: &[u8] = b"exavProbeBetaSignatureBody";

    let hex = |b: &[u8]| -> String { b.iter().map(|x| format!("{x:02x}")).collect() };
    let mut l = loader::Builder::new();
    l.add_named_bytes(
        "two.ndb",
        format!(
            "Test.ProbeA:0:*:{}\nTest.ProbeB:0:*:{}\n",
            hex(SIG_A),
            hex(SIG_B)
        )
        .as_bytes(),
        true,
    );
    let db = l.build().expect("build database");

    let mut member = Vec::new();
    member.extend_from_slice(b"leading filler bytes\n");
    member.extend_from_slice(SIG_A);
    member.extend_from_slice(b"\nseparating filler bytes\n");
    member.extend_from_slice(SIG_B);
    member.extend_from_slice(b"\ntrailing filler bytes\n");

    let opts = ScanOptions::default();
    let names = |r: Vec<(String, exav_core::Method)>| -> Vec<String> {
        let mut v: Vec<String> = r.into_iter().map(|(s, _)| s).collect();
        v.sort();
        v.dedup();
        v
    };

    // Baseline: the same bytes handed in directly.
    let bare = names(analyze_all(&db, &member, &opts));
    assert_eq!(
        bare.len(),
        2,
        "the two probe signatures must both fire on the bare buffer, else this \
         test cannot tell a walk difference from a database problem: {bare:?}"
    );

    // ZIP is a streamable format, so this member arrives as a reader. Deflated,
    // not Stored: a stored member's bytes appear verbatim in the container, so
    // the top-level raw scan would find both signatures without the walk ever
    // being involved — and the test would pass no matter what the walk did.
    let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    z.start_file(
        "payload.txt",
        zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated),
    )
    .expect("start zip member");
    z.write_all(&member).expect("write zip member");
    let zipped = z.finish().expect("finish zip").into_inner();

    let inside = names(analyze_all(&db, &zipped, &opts));
    assert_eq!(
        inside, bare,
        "a member of a STREAMED container reported {inside:?} under --all-matches \
         but the identical bytes report {bare:?} on their own. The streamed \
         member path must hand the caller's sink down, not scan the member with \
         a first-match sink."
    );
}

/// A YARA-only detection has to survive `--all-matches`.
///
/// The two cores run their passes independently, so a matcher wired into one
/// and not the other does not fail loudly — it returns an empty detection list
/// with a `Complete` outcome, which renders as OK. A file whose only detection
/// is a YARA rule then reports clean under `--all-matches` while a normal scan
/// calls it infected.
///
/// This is the same class as the `Target:2` gap this suite was written for: two
/// walks, one capability, and nothing holding them together but a test.
#[test]
#[cfg(feature = "yara")]
fn a_yara_only_detection_survives_allmatch() {
    let mut l = loader::Builder::new();
    l.add_named_bytes(
        "t.yar",
        br#"rule exav_allmatch_probe { strings: $a = "exavYaraOnlyProbe" condition: $a }"#,
        true,
    );
    let db = l.build().expect("build database");
    let data = b"....exavYaraOnlyProbe....".to_vec();
    let opts = ScanOptions::default();

    let normal = matches!(
        analyze(&db, &data, &opts).verdict,
        exav_core::Verdict::Infected { .. }
    );
    assert!(
        normal,
        "the probe must be detected by a normal scan, or this test proves nothing"
    );

    let all = analyze_all(&db, &data, &opts);
    assert!(
        !all.is_empty(),
        "a normal scan reports this file infected on a YARA rule, and --all-matches \
         returned no detections at all. An empty list renders as OK, so this is a \
         silent clean rather than a missing name."
    );
}
