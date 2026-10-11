//! ZIP members compressed with a codec the `zip` crate itself can't decode
//! (LZMA method 14, BZIP2 method 12) must still be decompressed by exav's own
//! decoders and scanned — a payload behind an exotic codec must not hide. And one
//! undecodable member must never abort the whole archive.

use exav_unpack::{extract, Budget, Format, Limits};

const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR";

fn fixture(name: &str) -> Vec<u8> {
    let p = format!("{}/tests/fixtures/zip/{name}", env!("CARGO_MANIFEST_DIR"));
    exav_unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

fn any_has_eicar(entries: &[exav_unpack::Entry]) -> bool {
    entries
        .iter()
        .any(|e| e.data.windows(EICAR.len()).any(|w| w == EICAR))
}

#[test]
#[cfg(feature = "lzip")]
fn zip_lzma_member_is_decoded() {
    let blob = fixture("eicar_lzma.zip");
    let mut budget = Budget::new(Limits::default());
    let entries = extract(Format::Zip, &blob, &mut budget).unwrap();
    assert!(
        any_has_eicar(&entries),
        "EICAR in an LZMA (method 14) ZIP member must be decoded and present"
    );
}

/// The same member on the streamed walk the top-level scan takes: decoded once,
/// and not also reported as a codec nothing could decode.
#[test]
#[cfg(feature = "lzip")]
fn zip_lzma_member_is_decoded_once_when_streamed() {
    use exav_unpack::{walk, Member, MemberMeta};
    let blob = fixture("eicar_lzma.zip");
    let mut budget = Budget::new(Limits::default());
    let mut seen = Vec::new();
    let mut visit = |m: &MemberMeta, content: Option<Member<'_>>, _: &mut Budget| {
        let data = match content {
            None => Vec::new(),
            Some(Member::Bytes(d)) => d,
            Some(Member::Stream(r)) => {
                let mut d = Vec::new();
                r.read_to_end(&mut d).unwrap();
                d
            }
        };
        seen.push((m.name.clone(), m.unsupported, data));
        None::<()>
    };
    walk(Format::Zip, &blob, &mut budget, &mut visit).unwrap();
    assert_eq!(
        seen.len(),
        1,
        "{:?}",
        seen.iter().map(|s| (&s.0, s.1)).collect::<Vec<_>>()
    );
    assert_eq!(seen[0].1, None);
    assert!(seen[0].2.windows(EICAR.len()).any(|w| w == EICAR));

    // Too large to hold is a limit, and says which one.
    let mut limits = Limits::default();
    limits.max_buffer_bytes = 16;
    let mut budget = Budget::new(limits);
    let blob = fixture("eicar_lzma.zip");
    let mut visit = |_: &MemberMeta, _: Option<Member<'_>>, _: &mut Budget| None::<()>;
    let hit = walk(Format::Zip, &blob, &mut budget, &mut visit).unwrap_err();
    assert!(
        !hit.is_corrupt() && hit.reason.contains("--max-object-bytes"),
        "{hit:?}"
    );
}

/// Dual indexing: a member present only as a Local File Header (not in the
/// central directory) must still be extracted — this defeats central/local
/// mismatch hiding.
#[test]
fn zip_orphan_local_header_is_scanned() {
    let blob = fixture("orphan_local.zip");
    let mut budget = Budget::new(Limits::default());
    let entries = extract(Format::Zip, &blob, &mut budget).unwrap();
    assert!(
        any_has_eicar(&entries),
        "EICAR in an orphan local header (absent from the central directory) must be extracted"
    );
    assert!(
        entries.iter().any(|e| e.name == "hidden.txt"),
        "the orphan member's name should be recovered"
    );
}

/// An encrypted ZIP using a common malware-distribution password ("infected")
/// is cracked with NO caller-supplied password — exav's built-in default list.
#[test]
#[cfg(feature = "decrypt")]
fn zip_default_password_infected_is_cracked() {
    let blob = fixture("eicar_infected.zip");
    // Empty pool: only the built-in DEFAULT_ZIP_PASSWORDS can crack this.
    let mut budget = Budget::new(Limits::default());
    let entries = extract(Format::Zip, &blob, &mut budget).unwrap();
    assert!(
        any_has_eicar(&entries),
        "an 'infected'-password ZIP must be cracked by the built-in default list"
    );
}

/// A ZIP whose central directory is missing/corrupt (no EOCD) must NOT error as
/// LimitsExceeded — exav falls back to the local-header scan and salvages the
/// member, so a payload in a forged/truncated archive is still found. (Regression
/// from the diff campaign: such files were mislabeled `LIMITS-EXCEEDED`.)
#[test]
fn zip_corrupt_central_dir_salvages_local_member() {
    // A single stored local file header (EICAR), with NO central directory / EOCD.
    let mut z = Vec::new();
    z.extend_from_slice(b"PK\x03\x04");
    z.extend_from_slice(&20u16.to_le_bytes()); // version needed
    z.extend_from_slice(&0u16.to_le_bytes()); // flags
    z.extend_from_slice(&0u16.to_le_bytes()); // method = stored
    z.extend_from_slice(&0u16.to_le_bytes()); // mod time
    z.extend_from_slice(&0u16.to_le_bytes()); // mod date
    z.extend_from_slice(&0u32.to_le_bytes()); // crc32 (not verified by the scanner)
    z.extend_from_slice(&(EICAR.len() as u32).to_le_bytes()); // compressed size
    z.extend_from_slice(&(EICAR.len() as u32).to_le_bytes()); // uncompressed size
    let name = b"payload.bin";
    z.extend_from_slice(&(name.len() as u16).to_le_bytes());
    z.extend_from_slice(&0u16.to_le_bytes()); // extra len
    z.extend_from_slice(name);
    z.extend_from_slice(EICAR);

    let mut budget = Budget::new(Limits::default());
    let entries =
        extract(Format::Zip, &z, &mut budget).expect("corrupt-cdir ZIP must salvage, not error");
    assert!(
        any_has_eicar(&entries),
        "the local-header member must be salvaged when the central directory is gone"
    );
}

/// A ZIP member compressed with XZ (method 95) must be decoded via exav's own
/// xz decoder and scanned — the `zip` crate can't handle it.
#[test]
#[cfg(feature = "xz")]
fn zip_xz_member_is_decoded() {
    let blob = fixture("eicar_xz.zip");
    let mut budget = Budget::new(Limits::default());
    let entries = extract(Format::Zip, &blob, &mut budget).unwrap();
    assert!(
        any_has_eicar(&entries),
        "EICAR in an XZ (method 95) ZIP member must be decoded and present"
    );
}

#[test]
#[cfg(feature = "bzip2")]
fn zip_bzip2_member_is_decoded() {
    let blob = fixture("eicar_bzip2.zip");
    let mut budget = Budget::new(Limits::default());
    let entries = extract(Format::Zip, &blob, &mut budget).unwrap();
    assert!(
        any_has_eicar(&entries),
        "EICAR in a BZIP2 (method 12) ZIP member must be decoded and present"
    );
}

/// PKZIP 1.x methods: Shrink (1), Reduce (2-5), Implode (6). The fixtures are
/// from the `zip` crate's own test data (zip-rs/zip2, MIT), each holding the
/// same 1092-byte text.
const LEGACY: [&str; 3] = [
    "legacy_shrink.zip",
    "legacy_reduce.zip",
    "legacy_implode.zip",
];

#[test]
fn legacy_methods_are_decoded() {
    use exav_unpack::{walk, Member, MemberMeta};
    for name in LEGACY {
        let blob = fixture(name);
        let entries = extract(Format::Zip, &blob, &mut Budget::new(Limits::default())).unwrap();
        assert_eq!(entries.len(), 1, "{name}");
        assert_eq!(entries[0].unsupported, None, "{name}");
        assert_eq!(entries[0].data.len(), 1092, "{name}");
        assert!(entries[0].data.starts_with(b"The play of Hamlet"), "{name}");

        let mut got = Vec::new();
        let mut visit = |m: &MemberMeta, content: Option<Member<'_>>, b: &mut Budget| {
            got.push((
                m.unsupported,
                content.map(|c| c.into_bytes(m, b).unwrap().0),
            ));
            None::<()>
        };
        walk(
            Format::Zip,
            &blob,
            &mut Budget::new(Limits::default()),
            &mut visit,
        )
        .unwrap();
        assert_eq!(got.len(), 1, "{name}");
        assert_eq!(got[0].0, None, "{name}");
        assert_eq!(got[0].1.as_ref().map(Vec::len), Some(1092), "{name}");
    }
}

/// A one-member ZIP holding `data` as method 6 (Implode) with the given flags.
fn implode_zip(flags: u16, data: &[u8]) -> Vec<u8> {
    let name = b"a";
    let mut z = Vec::new();
    z.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
    for v in [20u16, flags, 6, 0, 0] {
        z.extend_from_slice(&v.to_le_bytes());
    }
    for v in [0u32, data.len() as u32, 16] {
        z.extend_from_slice(&v.to_le_bytes());
    }
    z.extend_from_slice(&[1, 0, 0, 0]);
    z.extend_from_slice(name);
    z.extend_from_slice(data);
    let cd = z.len() as u32;
    z.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
    for v in [20u16, 20, flags, 6, 0, 0] {
        z.extend_from_slice(&v.to_le_bytes());
    }
    for v in [0u32, data.len() as u32, 16] {
        z.extend_from_slice(&v.to_le_bytes());
    }
    for v in [1u16, 0, 0, 0, 0] {
        z.extend_from_slice(&v.to_le_bytes());
    }
    z.extend_from_slice(&[0; 4]);
    z.extend_from_slice(&0u32.to_le_bytes());
    z.extend_from_slice(name);
    let cd_len = z.len() as u32 - cd;
    z.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    for v in [0u16, 0, 1, 1] {
        z.extend_from_slice(&v.to_le_bytes());
    }
    z.extend_from_slice(&cd_len.to_le_bytes());
    z.extend_from_slice(&cd.to_le_bytes());
    z.extend_from_slice(&0u16.to_le_bytes());
    z
}

/// Fuzz finding (2026-10-10, `unpack`): an Implode tree whose size byte is 255
/// overflowed `byte + 1` in `zip` 8.6.0 (`legacy/implode.rs:29`). Containment
/// turned the panic into "decoder panicked", but the member was lost and the
/// archive reported as corrupt; the bad tree must be an ordinary decode error.
#[test]
fn implode_tree_size_255_is_not_a_panic() {
    // flags 0b110: 8K window and a literal tree, so the first byte is a tree size.
    let blob = implode_zip(0b110, &[0xff; 40]);
    let mut budget = Budget::new(Limits::default());
    let outcome = format!("{:?}", extract(Format::Zip, &blob, &mut budget));
    assert!(!outcome.contains("panicked"), "{outcome}");
}

/// The `zip` crate decodes these methods whole, into a buffer it reserves from
/// the member's declared size. Over the buffer limit, the member is not
/// decoded and the limit is reported.
#[test]
fn legacy_methods_over_the_buffer_limit_are_a_limit() {
    use exav_unpack::{walk, Member, MemberMeta};
    for name in LEGACY {
        let blob = fixture(name);
        let mut limits = Limits::default();
        limits.max_buffer_bytes = 1000;
        let mut visited = 0;
        let mut visit = |_: &MemberMeta, _: Option<Member<'_>>, _: &mut Budget| {
            visited += 1;
            None::<()>
        };
        let hit = walk(Format::Zip, &blob, &mut Budget::new(limits), &mut visit).unwrap_err();
        assert_eq!(visited, 0, "{name}");
        assert!(
            !hit.is_corrupt() && hit.reason.contains("--max-object-bytes"),
            "{name}: {hit:?}"
        );
    }
}

/// A member in a codec the `zip` crate lacks, larger than the buffer limit,
/// is decoded as it is read, and the member after it is still reached.
#[test]
#[cfg(feature = "bzip2")]
fn a_large_raw_decoded_member_streams_and_the_walk_goes_on() {
    use exav_unpack::{walk, Member, MemberMeta};
    // big.bin: 20000 bytes, bzip2 (method 12); after.txt: deflated.
    let blob = fixture("bzip2_large_then_small.zip");
    let mut limits = Limits::default();
    limits.max_buffer_bytes = 8192;
    let mut budget = Budget::new(limits);
    let mut seen = Vec::new();
    let mut visit = |m: &MemberMeta, content: Option<Member<'_>>, _: &mut Budget| {
        let mut d = Vec::new();
        if let Some(Member::Stream(r)) = content {
            r.read_to_end(&mut d).unwrap();
        }
        seen.push((m.name.clone(), m.unsupported, d.len()));
        None::<()>
    };
    walk(Format::Zip, &blob, &mut budget, &mut visit).unwrap();
    assert_eq!(
        seen,
        [
            ("big.bin".to_string(), None, 20000),
            ("after.txt".to_string(), None, 72)
        ]
    );
}

/// `1-big.bin` in the `*_large_then_small` archives below: 40000 bytes of
/// numbered lines, ending in the EICAR string, so a decoder that stops early
/// loses the marker.
fn large_member() -> Vec<u8> {
    let lines: Vec<u8> = (0..700u32)
        .flat_map(|i| {
            format!(
                "{i:05} the quick brown fox jumps over the lazy dog {}\n",
                i * 7919 % 10007
            )
            .into_bytes()
        })
        .collect();
    // In two pieces, so that no scanner flags this file.
    let eicar = concat!(
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-",
        "STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    )
    .as_bytes();
    let mut big = lines.repeat(2);
    big.truncate(40000 - eicar.len());
    big.extend_from_slice(eicar);
    big
}

const SMALL_MEMBER: &[u8] = b"the member after the large one, which the walk must still reach\n";

/// A ZIP of `1-big.bin` as `big` (already compressed with `method`) and
/// `2-after.txt` stored, central directory included.
fn zip_large_then_small(method: u16, big: &[u8]) -> Vec<u8> {
    zip_of(&[
        ("1-big.bin", method, big, crc(&large_member()), 40000),
        (
            "2-after.txt",
            0,
            SMALL_MEMBER,
            crc(SMALL_MEMBER),
            SMALL_MEMBER.len() as u32,
        ),
    ])
}

fn crc(d: &[u8]) -> u32 {
    let mut c = flate2::Crc::new();
    c.update(d);
    c.sum()
}

/// A ZIP of `(name, method, raw data, crc, uncompressed size)` members, central
/// directory included.
fn zip_of(members: &[(&str, u16, &[u8], u32, u32)]) -> Vec<u8> {
    let mut z = Vec::new();
    let mut cd = Vec::new();
    for (name, m, data, crc, usize) in members {
        let at = z.len() as u32;
        let fields = |v: &mut Vec<u8>| {
            v.extend_from_slice(&20u16.to_le_bytes()); // version needed
            v.extend_from_slice(&0u16.to_le_bytes()); // flags
            v.extend_from_slice(&m.to_le_bytes());
            v.extend_from_slice(&[0; 4]); // time, date
            v.extend_from_slice(&crc.to_le_bytes());
            v.extend_from_slice(&(data.len() as u32).to_le_bytes());
            v.extend_from_slice(&usize.to_le_bytes());
            v.extend_from_slice(&(name.len() as u16).to_le_bytes());
            v.extend_from_slice(&0u16.to_le_bytes()); // extra
        };
        z.extend_from_slice(b"PK\x03\x04");
        fields(&mut z);
        z.extend_from_slice(name.as_bytes());
        z.extend_from_slice(data);
        cd.extend_from_slice(b"PK\x01\x02");
        cd.extend_from_slice(&20u16.to_le_bytes()); // version made by
        fields(&mut cd);
        cd.extend_from_slice(&[0; 6]); // comment length, disk, internal attrs
        cd.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        cd.extend_from_slice(&at.to_le_bytes());
        cd.extend_from_slice(name.as_bytes());
    }
    let cd_at = z.len() as u32;
    z.extend_from_slice(&cd);
    z.extend_from_slice(b"PK\x05\x06");
    z.extend_from_slice(&[0; 4]); // disk numbers
    z.extend_from_slice(&(members.len() as u16).to_le_bytes());
    z.extend_from_slice(&(members.len() as u16).to_le_bytes());
    z.extend_from_slice(&(cd.len() as u32).to_le_bytes());
    z.extend_from_slice(&cd_at.to_le_bytes());
    z.extend_from_slice(&0u16.to_le_bytes());
    z
}

/// Each member the streamed walk over `blob` visits, once, as
/// `(name, unsupported, bytes)`, and how the walk ended.
type Seen = Vec<(String, Option<&'static str>, Vec<u8>)>;

/// The streamed walk over `blob` with a buffer far smaller than the large
/// member.
fn walk_small_buffer(blob: &[u8]) -> Seen {
    let (seen, end) = walk_with_buffer(blob, 8192);
    end.unwrap();
    seen
}

fn walk_with_buffer(blob: &[u8], max_buffer: u64) -> (Seen, Result<(), exav_unpack::LimitHit>) {
    use exav_unpack::{walk, Member, MemberMeta};
    let mut limits = Limits::default();
    limits.max_buffer_bytes = max_buffer;
    let mut seen = Vec::new();
    let mut visit = |m: &MemberMeta, content: Option<Member<'_>>, _: &mut Budget| {
        let mut d = Vec::new();
        match content {
            Some(Member::Stream(r)) => {
                r.read_to_end(&mut d).unwrap();
            }
            Some(Member::Bytes(b)) => d = b,
            None => {}
        }
        seen.push((m.name.clone(), m.unsupported, d));
        None::<()>
    };
    let end = walk(Format::Zip, &blob, &mut Budget::new(limits), &mut visit).map(|_| ());
    (seen, end)
}

fn assert_both_members_whole(what: &str, blob: &[u8]) {
    let seen = walk_small_buffer(blob);
    let summary: Vec<_> = seen.iter().map(|s| (&s.0, s.1, s.2.len())).collect();
    assert_eq!(seen.len(), 2, "{what}: each member once: {summary:?}");
    assert_eq!(seen[0].0, "1-big.bin", "{what}: {summary:?}");
    assert_eq!(seen[0].1, None, "{what}: {summary:?}");
    assert!(
        seen[0].2 == large_member(),
        "{what}: the large member differs"
    );
    assert_eq!(seen[1].0, "2-after.txt", "{what}: {summary:?}");
    assert_eq!(seen[1].2, SMALL_MEMBER, "{what}: {summary:?}");
}

/// A member larger than the buffer limit, in each codec the `zip` crate lacks,
/// is decoded as it is read, whole and once, and the member after it is
/// still reached. The Deflate64, BZip2 and LZMA archives were written by
/// 7-Zip 25.01 (`7z a -tzip -mm=<method> -mx=9 x.zip 1-big.bin 2-after.txt`,
/// LZMA with `-md=4k`), so the codecs are read as a real writer emits them.
/// LZMA's window is allocated whole, so a dictionary over the limit is a
/// limit instead (`zip_lzma_member_is_decoded_once_when_streamed`).
#[test]
#[cfg(all(feature = "bzip2", feature = "lzip"))]
fn a_large_member_in_any_codec_streams_and_the_walk_goes_on() {
    for name in [
        "7z_deflate64_large_then_small.zip",
        "7z_bzip2_large_then_small.zip",
        "7z_lzma_large_then_small.zip",
    ] {
        assert_both_members_whole(name, &fixture(name));
    }
}

/// `7z_ppmd_large_then_small.zip` was written by 7-Zip 25.01 at `-mx=9`, which
/// for PPMd means order 12, a 1 MB model and the cut-off restore method
/// (members start `0b 10`). The model is allocated whole, so it takes a buffer
/// limit of 1 MB; below that each member is a limit, not damage.
#[test]
fn a_ppmd_member_written_by_7zip_is_decoded_whole() {
    let blob = fixture("7z_ppmd_large_then_small.zip");
    let (seen, end) = walk_with_buffer(&blob, 1 << 20);
    end.unwrap();
    let summary: Vec<_> = seen.iter().map(|s| (&s.0, s.1, s.2.len())).collect();
    assert_eq!(seen.len(), 2, "{summary:?}");
    assert_eq!((seen[0].0.as_str(), seen[0].1), ("1-big.bin", None));
    assert!(seen[0].2 == large_member(), "the large member differs");
    assert_eq!(
        (seen[1].0.as_str(), seen[1].1, &seen[1].2[..]),
        ("2-after.txt", None, SMALL_MEMBER)
    );

    let (seen, end) = walk_with_buffer(&blob, (1 << 20) - 1);
    assert!(seen.is_empty(), "{seen:?}");
    let limit = end.unwrap_err();
    assert!(!limit.is_corrupt(), "{limit:?}");
}

/// `ppmd_7zip.zip`, written by 7-Zip 25.01:
/// `7z a -tzip -mm=PPMd -mo=6 ppmd_7zip.zip known.txt`, then the same with
/// `-mo=16` for `order16.txt`, which is `known.txt` three times. Both are 1 MB
/// models with the restart method.
fn ppmd_7zip_known() -> Vec<u8> {
    let mut t = b"exav PPMd ZIP fixture\n".to_vec();
    for i in 1..=40 {
        t.extend_from_slice(
            format!("line {i:02}: the quick brown fox jumps over the lazy dog\n").as_bytes(),
        );
    }
    t
}

#[test]
fn zip_ppmd_members_written_by_7zip_are_decoded() {
    let mut budget = Budget::new(Limits::default());
    let entries = extract(Format::Zip, &fixture("ppmd_7zip.zip"), &mut budget).unwrap();
    let got: Vec<_> = entries
        .iter()
        .map(|e| (e.name.as_str(), e.unsupported, e.data.clone()))
        .collect();
    let known = ppmd_7zip_known();
    assert_eq!(
        got,
        [
            ("known.txt", None, known.clone()),
            ("order16.txt", None, known.repeat(3))
        ]
    );
}

/// The same for zstd (method 93), written by ruzstd's encoder.
#[test]
#[cfg(feature = "zstd")]
fn a_large_zstd_member_streams_and_the_walk_goes_on() {
    let big = ruzstd::encoding::compress_to_vec(
        &large_member()[..],
        ruzstd::encoding::CompressionLevel::Fastest,
    );
    assert_both_members_whole("zstd", &zip_large_then_small(93, &big));
}

/// The same for XZ (method 95), written by lzma-rust2's XZ writer.
#[test]
#[cfg(feature = "xz")]
fn a_large_xz_member_streams_and_the_walk_goes_on() {
    use std::io::Write;
    let mut w =
        lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(6)).unwrap();
    w.write_all(&large_member()).unwrap();
    let big = w.finish().unwrap();
    assert_both_members_whole("xz", &zip_large_then_small(95, &big));
}

// --- Orphan local headers must never be silently dropped --------------------
//
// A credible local file header the central directory doesn't cover *is* a member
// the target will extract. If exav can't decode it, it has to say so, or the
// containing file could be reported clean on a scan that never looked inside.

/// Build a bare local file header plus payload, with no central directory at
/// all, so the whole archive is reached through the orphan-scan path.
fn lfh(name: &str, method: u16, flags: u16, payload: &[u8], declared_comp: Option<u32>) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"PK\x03\x04");
    v.extend_from_slice(&20u16.to_le_bytes()); // version needed
    v.extend_from_slice(&flags.to_le_bytes());
    v.extend_from_slice(&method.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes()); // mod time
    v.extend_from_slice(&0u16.to_le_bytes()); // mod date
    v.extend_from_slice(&0u32.to_le_bytes()); // crc
    v.extend_from_slice(&declared_comp.unwrap_or(payload.len() as u32).to_le_bytes());
    v.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // uncompressed
    v.extend_from_slice(&(name.len() as u16).to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes()); // extra len
    v.extend_from_slice(name.as_bytes());
    v.extend_from_slice(payload);
    v
}

/// [`lfh`] declaring `usize` as the uncompressed size, for a codec that
/// decodes to the declared size.
fn lfh_sized(name: &str, method: u16, payload: &[u8], usize: u32) -> Vec<u8> {
    let mut v = lfh(name, method, 0, payload, None);
    v[22..26].copy_from_slice(&usize.to_le_bytes());
    v
}

fn orphan_entries(blob: &[u8]) -> Vec<exav_unpack::Entry> {
    let mut budget = Budget::new(Limits::default());
    extract(Format::Zip, &blob, &mut budget).unwrap()
}

#[test]
fn orphan_stored_member_is_extracted() {
    let e = orphan_entries(&lfh("hidden.txt", 0, 0, EICAR, None));
    assert!(any_has_eicar(&e), "a stored orphan member must be scanned");
    assert!(e.iter().any(|x| x.name == "hidden.txt"));
}

#[test]
fn orphan_encrypted_member_is_reported_not_dropped() {
    // Flag bit 0 set: encrypted. The orphan path has no central-directory CRC to
    // drive the password check, so it must report rather than stay silent.
    let e = orphan_entries(&lfh(
        "secret.bin",
        0,
        0x0001,
        b"\x00\x01\x02\x03opaque",
        None,
    ));
    let m = e
        .iter()
        .find(|x| x.name == "secret.bin")
        .expect("the encrypted orphan member must still be reported");
    assert!(m.encrypted, "must be flagged encrypted");
    assert!(m.unsupported.is_some(), "must carry an unsupported reason");
}

#[test]
fn orphan_unsupported_codec_is_reported_not_dropped() {
    // Method 9 (Deflate64) is a known method exav has no decoder for.
    let e = orphan_entries(&lfh("packed.bin", 9, 0, b"\xff\xfe\xfd\xfc\xfb\xfa", None));
    let m = e
        .iter()
        .find(|x| x.name == "packed.bin")
        .expect("an undecodable orphan member must still be reported");
    assert!(
        m.unsupported.is_some(),
        "an unsupported codec must surface, not vanish"
    );
}

#[test]
fn orphan_member_with_a_nonsense_method_is_read_as_stored() {
    // Method 47506 is in no version of APPNOTE. Live APK packers stamp exactly
    // this on `AndroidManifest.xml` — together with a corrupt central directory,
    // so the member is reachable only through the orphan scan. Gating that scan on
    // a recognised method drops the one member the packer went to the trouble of
    // hiding, and the archive then scans clean. Android reads such a member as
    // stored, and so does exav.
    let e = orphan_entries(&lfh(
        "AndroidManifest.xml",
        47506,
        0,
        b"\x03\x00\x08\x00payload",
        None,
    ));
    let m = e
        .iter()
        .find(|x| x.name == "AndroidManifest.xml")
        .expect("a member with an unrecognised method must still be reported");
    assert_eq!(m.unsupported, None);
    assert_eq!(m.data, b"\x03\x00\x08\x00payload");
}

#[test]
fn a_chance_signature_with_a_nonsense_method_is_still_rejected() {
    // The counterweight to the test above: with the method no longer decisive, the
    // name is what separates a member from four bytes that happened to spell
    // `PK\x03\x04`. A name of raw binary corroborates nothing, so the header must
    // still be refused — otherwise every ordinary file carrying those bytes turns
    // unscannable.
    let e = orphan_entries(&lfh("\u{1}\u{2}\u{1b}\u{7f}", 47506, 0, b"junk", None));
    assert!(
        e.is_empty(),
        "a chance PK\\x03\\x04 must not become a member, got {:?}",
        e.iter().map(|x| &x.name).collect::<Vec<_>>()
    );
}

#[test]
fn orphan_streaming_member_without_sizes_is_reported() {
    // Data-descriptor flag with no in-line compressed size: nothing to carve,
    // but the member exists.
    let e = orphan_entries(&lfh("stream.bin", 8, 0x0008, b"", Some(0)));
    let m = e
        .iter()
        .find(|x| x.name == "stream.bin")
        .expect("a deferred-size orphan member must still be reported");
    assert!(m.unsupported.is_some());
}

#[test]
fn orphan_directory_entry_is_not_reported() {
    // A zero-length directory entry carries no content, so skipping it hides
    // nothing and must not manufacture an UNSCANNABLE.
    let e = orphan_entries(&lfh("adir/", 0, 0, b"", Some(0)));
    assert!(
        !e.iter().any(|x| x.name == "adir/"),
        "a directory entry should not be reported as unscannable"
    );
}

/// A deflated member declaring 0 compressed and 0 uncompressed bytes is an
/// empty member: Python's zipfile reads it as `b''`. Civil 3D writes such
/// members in the ZIPs it keeps in DXF XRECORDs. Checked through the central
/// directory (streamed walk and buffered extraction) and as an orphan.
#[test]
fn a_deflated_member_of_zero_bytes_is_empty() {
    use exav_unpack::{walk, Member, MemberMeta};
    let blob = zip_of(&[
        ("empty.txt", 8, b"", 0, 0),
        ("after.txt", 0, EICAR, crc(EICAR), EICAR.len() as u32),
    ]);
    let want = vec![
        ("empty.txt".to_string(), None, Ok(()), Vec::new()),
        ("after.txt".to_string(), None, Ok(()), EICAR.to_vec()),
    ];

    let mut seen = Vec::new();
    let mut visit = |m: &MemberMeta, content: Option<Member<'_>>, _: &mut Budget| {
        let mut d = Vec::new();
        let read = match content {
            Some(Member::Stream(r)) => r.read_to_end(&mut d).map(drop).map_err(|e| e.to_string()),
            Some(Member::Bytes(b)) => {
                d = b;
                Ok(())
            }
            None => Ok(()),
        };
        seen.push((m.name.clone(), m.unsupported, read, d));
        None::<()>
    };
    walk(
        Format::Zip,
        &blob,
        &mut Budget::new(Limits::default()),
        &mut visit,
    )
    .unwrap();
    assert_eq!(seen, want, "streamed");

    let got: Vec<_> = orphan_entries(&blob)
        .into_iter()
        .map(|e| (e.name, e.unsupported, Ok::<(), String>(()), e.data))
        .collect();
    assert_eq!(got, want, "buffered");

    let got = orphan_entries(&lfh("empty.txt", 8, 0, b"", None));
    let got: Vec<_> = got.iter().map(|e| (&e.name, e.unsupported)).collect();
    assert!(got.iter().all(|e| e.1.is_none()), "orphan: {got:?}");
}

#[test]
fn chance_pk34_bytes_are_not_treated_as_members() {
    // `PK\x03\x04` occurs by chance in ordinary binaries. Treating a chance hit
    // as a member would make ordinary files spuriously UNSCANNABLE.
    let mut blob = vec![0u8; 4096];
    for (i, c) in blob.iter_mut().enumerate() {
        *c = (i % 251) as u8;
    }
    // Implausible header: reserved flag bits set, unknown method, NUL in name.
    blob[100..104].copy_from_slice(b"PK\x03\x04");
    blob[106..108].copy_from_slice(&0x0080u16.to_le_bytes()); // reserved flag bit
    blob[108..110].copy_from_slice(&0x5555u16.to_le_bytes()); // unknown method
    let mut budget = Budget::new(Limits::default());
    let entries = extract(Format::Zip, &blob, &mut budget).unwrap_or_default();
    assert!(
        entries.is_empty(),
        "a chance PK\\x03\\x04 must not become a member: {entries:?}"
    );
}

/// A member whose local header defers its sizes to a trailing data descriptor
/// must still be carved and scanned — on a live corpus this was the single
/// biggest source of UNSCANNABLE, i.e. the most content exav declined to look at.
#[test]
fn orphan_streaming_member_with_data_descriptor_is_recovered() {
    use std::io::Write;
    let mut deflated = Vec::new();
    {
        let mut e = flate2::write::DeflateEncoder::new(&mut deflated, flate2::Compression::fast());
        e.write_all(EICAR).unwrap();
        e.finish().unwrap();
    }
    // Local header with flag bit 3 set and both sizes zeroed, as a streaming
    // writer emits, then the data, then the descriptor carrying the real sizes.
    let mut blob = lfh("streamed.txt", 8, 0x0008, &[], Some(0));
    blob.extend_from_slice(&deflated);
    blob.extend_from_slice(b"PK\x07\x08");
    blob.extend_from_slice(&0u32.to_le_bytes()); // crc (unchecked here)
    blob.extend_from_slice(&(deflated.len() as u32).to_le_bytes());
    blob.extend_from_slice(&(EICAR.len() as u32).to_le_bytes());

    let e = orphan_entries(&blob);
    assert!(
        any_has_eicar(&e),
        "a deferred-size member must be carved via its data descriptor, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
}

#[test]
fn orphan_streaming_member_without_a_descriptor_falls_back_to_the_next_header() {
    use std::io::Write;
    let mut deflated = Vec::new();
    {
        let mut e = flate2::write::DeflateEncoder::new(&mut deflated, flate2::Compression::fast());
        e.write_all(EICAR).unwrap();
        e.finish().unwrap();
    }
    // No data descriptor at all: deflate self-terminates, so running to the next
    // local header recovers the member anyway.
    let mut blob = lfh("streamed.txt", 8, 0x0008, &[], Some(0));
    blob.extend_from_slice(&deflated);
    blob.extend_from_slice(&lfh("second.txt", 0, 0, b"harmless", None));

    let e = orphan_entries(&blob);
    assert!(
        any_has_eicar(&e),
        "must recover via the next-header boundary"
    );
}

#[test]
fn orphan_stored_member_with_deferred_size_is_reported_not_guessed() {
    // A STORED member has no self-terminating stream, so without a descriptor
    // there is no honest way to know where it ends — guessing would absorb the
    // following headers into its content. Must be reported, not invented.
    let blob = lfh("stored.bin", 0, 0x0008, b"", Some(0));
    let e = orphan_entries(&blob);
    if let Some(m) = e.iter().find(|x| x.name == "stored.bin") {
        assert!(
            m.unsupported.is_some(),
            "must be reported, not silently dropped"
        );
    }
}

// --- Sizes after the data (general-purpose bit 3) ----------------------------
//
// A writer that cannot seek back, such as one writing to a pipe, sets bit 3,
// leaves the sizes in the local header zero, and puts them in a data
// descriptor after the member data. Without the central directory, the
// descriptor is the only place the sizes are.

/// `known.txt`, the one member of each `dd_*.zip`.
fn dd_known() -> Vec<u8> {
    let mut t = b"exav data descriptor fixture\n".to_vec();
    for i in 1..=40 {
        t.extend_from_slice(
            format!("line {i:02}: the quick brown fox jumps over the lazy dog\n").as_bytes(),
        );
    }
    t
}

/// Each written as a stream: bit 3 set, sizes zero in the local header, a
/// signed data descriptor after the data. `dd_7zip_<method>.zip`: 7-Zip 25.01,
/// `7z a -tzip -mm=<method> -so x.zip known.txt > out` (LZMA with its end
/// marker, flag bit 1). `dd_python_*.zip`: Python 3.13 `zipfile` over an
/// unseekable stream; the `zip64` ones with `force_zip64=True`, which puts a
/// ZIP64 extra field in the local header and 8-byte sizes in the descriptor.
/// Paired with whether this build has the codec.
const DATA_DESCRIPTOR_FIXTURES: [(&str, bool); 9] = [
    ("dd_7zip_deflate.zip", true),
    ("dd_7zip_deflate64.zip", true),
    ("dd_7zip_bzip2.zip", cfg!(feature = "bzip2")),
    ("dd_7zip_lzma.zip", cfg!(feature = "lzip")),
    ("dd_7zip_ppmd.zip", true),
    ("dd_7zip_xz.zip", cfg!(feature = "xz")),
    ("dd_python_stored.zip", true),
    ("dd_python_stored_zip64.zip", true),
    ("dd_python_lzma_zip64.zip", cfg!(feature = "lzip")),
];

/// The archive cut where its central directory starts: the member, found only
/// by the local-header scan.
fn orphaned(zip: &[u8]) -> Vec<u8> {
    let cd = zip.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
    zip[..cd].to_vec()
}

/// `member` with its data descriptor's signature removed, which APPNOTE
/// 4.3.9.3 makes optional.
fn unsigned_descriptor(member: &[u8]) -> Vec<u8> {
    let sig = member.windows(4).rposition(|w| w == b"PK\x07\x08").unwrap();
    [&member[..sig], &member[sig + 4..]].concat()
}

/// `member` in front of a valid one-member ZIP, whose central directory does
/// not list it.
fn hidden_before_a_zip(member: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    z.start_file("carrier.txt", zip::write::SimpleFileOptions::default())
        .unwrap();
    z.write_all(SMALL_MEMBER).unwrap();
    [member, &z.finish().unwrap().into_inner()].concat()
}

#[test]
fn orphan_members_with_a_data_descriptor_are_decoded_whole() {
    let known = dd_known();
    let mut wrong = Vec::new();
    for (name, built) in DATA_DESCRIPTOR_FIXTURES {
        if !built {
            continue;
        }
        let zip = fixture(name);
        let member = orphaned(&zip);
        let unsigned = unsigned_descriptor(&member);
        for (what, blob) in [
            ("listed", &zip),
            ("orphan", &member),
            ("orphan, unsigned descriptor", &unsigned),
        ] {
            let got: Vec<_> = orphan_entries(blob)
                .into_iter()
                .map(|e| (e.name, e.unsupported, e.data))
                .collect();
            if got != [("known.txt".to_string(), None, known.clone())] {
                let summary: Vec<_> = got.iter().map(|g| (&g.0, g.1, g.2.len())).collect();
                wrong.push(format!("{name}, {what}: {summary:?}"));
            }
        }
        // The streamed walk reads only the space the central directory leaves
        // unclaimed, which here ends where the member's descriptor does.
        for (what, m) in [("hidden", &member), ("hidden, unsigned", &unsigned)] {
            let (seen, end) = walk_with_buffer(&hidden_before_a_zip(m), 16 << 20);
            end.unwrap();
            let want = [
                ("carrier.txt".to_string(), None, SMALL_MEMBER.to_vec()),
                ("known.txt".to_string(), None, known.clone()),
            ];
            if seen != want {
                let summary: Vec<_> = seen.iter().map(|s| (&s.0, s.1, s.2.len())).collect();
                wrong.push(format!("{name}, {what}: {summary:?}"));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// The same for zstd (method 93), which no writer at hand puts in a ZIP: the
/// member from ruzstd's encoder, behind a header and a descriptor laid out as
/// in `dd_7zip_*.zip`.
#[test]
#[cfg(feature = "zstd")]
fn orphan_zstd_member_with_a_data_descriptor_is_decoded() {
    let known = dd_known();
    let packed =
        ruzstd::encoding::compress_to_vec(&known[..], ruzstd::encoding::CompressionLevel::Fastest);
    let mut member = lfh("known.txt", 93, 0x0008, &[], Some(0));
    member.extend_from_slice(&packed);
    member.extend_from_slice(b"PK\x07\x08");
    member.extend_from_slice(&0u32.to_le_bytes()); // CRC-32, not checked here
    member.extend_from_slice(&(packed.len() as u32).to_le_bytes());
    member.extend_from_slice(&(known.len() as u32).to_le_bytes());
    for blob in [member.clone(), unsigned_descriptor(&member)] {
        let got: Vec<_> = orphan_entries(&blob)
            .into_iter()
            .map(|e| (e.name, e.unsupported, e.data))
            .collect();
        assert!(got == [("known.txt".to_string(), None, known.clone())]);
    }
}

/// `zip64_python_lzma.zip`: Python 3.13 `zipfile`, `force_zip64=True`, to a
/// file: both sizes `0xFFFFFFFF` in the local header and given in its ZIP64
/// extra field. Read from the header alone, the member ran past the end of the
/// file and was dropped as truncated.
#[test]
#[cfg(feature = "lzip")]
fn orphan_zip64_member_is_decoded() {
    let zip = fixture("zip64_python_lzma.zip");
    for blob in [&zip[..], &orphaned(&zip)] {
        let got: Vec<_> = orphan_entries(blob)
            .into_iter()
            .map(|e| (e.name, e.unsupported, e.data))
            .collect();
        assert!(
            got == [("known.txt".to_string(), None, dd_known())],
            "{:?}",
            got.iter()
                .map(|g| (&g.0, g.1, g.2.len()))
                .collect::<Vec<_>>()
        );
    }
}

/// A descriptor with 8-byte sizes behind a header without the ZIP64 field,
/// against APPNOTE 4.3.9.2. Read with 4-byte sizes, its uncompressed size is
/// the compressed size's high half, zero, which would decode nothing; the
/// member is decoded to its end marker instead.
#[test]
fn a_zero_size_in_a_descriptor_is_not_taken_at_its_word() {
    let member = orphaned(&fixture("dd_7zip_ppmd.zip"));
    let sig = member.windows(4).rposition(|w| w == b"PK\x07\x08").unwrap();
    let field = |o: usize| u64::from(u32::from_le_bytes(member[o..o + 4].try_into().unwrap()));
    let (comp, usz) = (field(sig + 8), field(sig + 12));
    let mut blob = member[..sig + 8].to_vec();
    blob.extend_from_slice(&comp.to_le_bytes());
    blob.extend_from_slice(&usz.to_le_bytes());
    let got: Vec<_> = orphan_entries(&blob)
        .into_iter()
        .map(|e| (e.name, e.unsupported, e.data))
        .collect();
    assert!(
        got == [("known.txt".to_string(), None, dd_known())],
        "{:?}",
        got.iter()
            .map(|g| (&g.0, g.1, g.2.len()))
            .collect::<Vec<_>>()
    );
}

/// With no descriptor at all, a codec that marks its own end is decoded up to
/// it, as far as the next header.
#[test]
fn orphan_member_without_its_descriptor_is_decoded_to_its_end_marker() {
    let known = dd_known();
    for (name, built) in [
        ("dd_7zip_lzma.zip", cfg!(feature = "lzip")),
        ("dd_7zip_ppmd.zip", true),
    ] {
        if !built {
            continue;
        }
        let member = orphaned(&fixture(name));
        let sig = member.windows(4).rposition(|w| w == b"PK\x07\x08").unwrap();
        let mut blob = member[..sig].to_vec();
        blob.extend_from_slice(&lfh("second.txt", 0, 0, b"harmless", None));
        let entries = orphan_entries(&blob);
        let got: Vec<_> = entries
            .iter()
            .map(|e| (e.name.as_str(), e.unsupported, e.data.len()))
            .collect();
        assert_eq!(
            got,
            [("known.txt", None, known.len()), ("second.txt", None, 8)],
            "{name}"
        );
        assert!(entries[0].data == known, "{name}: content differs");
    }
}

/// Cut short with no descriptor and another header right after the cut, a
/// member is decoded as far as it goes: those bytes are scanned, and the
/// member says it was not decoded whole, whichever codec 7-Zip wrote it with.
/// Bytes follow the cut, so nothing says the rest of the member is absent.
#[test]
fn orphan_member_cut_short_yields_its_prefix_marked_part_way() {
    let known = dd_known();
    let data_start = 30 + "known.txt".len();
    let mut wrong = Vec::new();
    for (name, built) in DATA_DESCRIPTOR_FIXTURES {
        if !built || !name.starts_with("dd_7zip_") {
            continue;
        }
        let member = orphaned(&fixture(name));
        let sig = member.windows(4).rposition(|w| w == b"PK\x07\x08").unwrap();
        let mut blob = member[..(data_start + sig) / 2].to_vec();
        blob.extend_from_slice(&lfh("second.txt", 0, 0, b"harmless", None));
        let entries = orphan_entries(&blob);
        let first = entries.iter().find(|e| e.name == "known.txt").unwrap();
        // Every decoder but bzip2's hands out what it decoded before the input
        // ran out; bzip2 decodes by block, and this member is one block.
        let streams = !name.contains("bzip2");
        if first.unsupported.is_none()
            || !known.starts_with(&first.data)
            || (streams && first.data.is_empty())
        {
            wrong.push(format!(
                "{name}: {:?}, {} bytes",
                first.unsupported,
                first.data.len()
            ));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// The same cut with nothing after it: the member is cut off by the end of the
/// file. What decodes of it is scanned and the member is not reported: every
/// byte present was decoded, and the rest is absent.
#[test]
fn orphan_member_cut_at_the_end_of_the_file_yields_its_prefix_unreported() {
    let known = dd_known();
    let data_start = 30 + "known.txt".len();
    let mut wrong = Vec::new();
    for (name, built) in DATA_DESCRIPTOR_FIXTURES {
        if !built || !name.starts_with("dd_7zip_") {
            continue;
        }
        let member = orphaned(&fixture(name));
        let sig = member.windows(4).rposition(|w| w == b"PK\x07\x08").unwrap();
        let entries = orphan_entries(&member[..(data_start + sig) / 2]);
        let streams = !name.contains("bzip2");
        let ok = match &entries[..] {
            [e] => {
                e.name == "known.txt"
                    && e.unsupported.is_none()
                    && known.starts_with(&e.data)
                    && !(streams && e.data.is_empty())
            }
            _ => false,
        };
        if !ok {
            wrong.push(format!("{name}: {:?}", entry_summary(&entries)));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

// --- Members cut off by the end of the file, every codec ---------------------
//
// `cut_<codec>.zip` holds one member, `member.txt` ([`cut_content`]). Written by
// 7-Zip 25.01, `7z a -tzip -mm=<method> cut_<codec>.zip member.txt`, method
// Copy, Deflate, Deflate64, BZip2 (with `-md=100k`, so the content spans two
// blocks), LZMA, PPMd or XZ; `cut_zstd.zip` by Python 3.13 around the frame of
// `zstd -1 --no-check` (zstd 1.5.7), which 7-Zip extracts. Masked: the content
// holds EICAR. Cut [`CUT_CLEAN`] percent into its compressed data, each
// archive gives a prefix without EICAR under `7z x`; cut [`CUT_FOUND`] percent
// in, a prefix with it. With [`DAMAGE_LEN`] bytes of 0xFF written
// [`DAMAGE_AT`] percent in, `7z x` reports a data error for each.

const CUT_CLEAN: usize = 25;
const CUT_FOUND: usize = 90;
const DAMAGE_AT: usize = 10;
const DAMAGE_LEN: usize = 256;

/// `(codec, built in this build, content is the large one)`.
const CUT_FIXTURES: [(&str, bool, bool); 8] = [
    ("stored", true, false),
    ("deflate", true, false),
    ("deflate64", true, false),
    ("bzip2", cfg!(feature = "bzip2"), true),
    ("lzma", cfg!(feature = "lzip"), false),
    ("ppmd", true, false),
    ("xz", cfg!(feature = "xz"), false),
    ("zstd", cfg!(feature = "zstd"), true),
];

/// How many bytes `7z x` gives from each fixture cut [`CUT_CLEAN`] and
/// [`CUT_FOUND`] percent into its compressed data, in [`CUT_FIXTURES`] order.
const CUT_7ZIP: [(usize, usize); 8] = [
    (8209, 29552),
    (7084, 29363),
    (7084, 29363),
    (0, 99996),
    (7058, 29310),
    (7343, 29341),
    (7012, 29401),
    (0, 131072),
];

/// How far short of 7-Zip a prefix may fall: decoders stop at different
/// points of the last bytes they hold.
const CUT_SLACK: usize = 512;

/// `n` bytes of words, as the script that wrote the fixtures drew them.
fn cut_text(n: usize, seed: u32) -> Vec<u8> {
    let words: Vec<&str> = "the quick brown fox jumps over lazy dog exav scans every member \
         of an archive cut short at the end of the file and keeps what it decoded\n"
        .split(' ')
        .collect();
    let mut x = seed;
    let mut out = Vec::with_capacity(n + 16);
    while out.len() < n {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        out.extend_from_slice(words[(x >> 16) as usize % words.len()].as_bytes());
        out.push(b' ');
        if (x >> 8).is_multiple_of(13) {
            out.extend_from_slice(format!("{} ", x % 100_000).as_bytes());
        }
    }
    out.truncate(n);
    out
}

/// `member.txt`: text, EICAR, text. The large one, for the codecs that decode
/// by block (bzip2, zstd), has EICAR in its first block.
fn cut_content(large: bool) -> Vec<u8> {
    let (before, after) = if large {
        (60_000, 90_000)
    } else {
        (16_384, 16_384)
    };
    [
        cut_text(before, 7),
        exav_unpack::eicar().to_vec(),
        cut_text(after, 8),
    ]
    .concat()
}

/// Where the first member's data starts, and its compressed size, from its
/// local header.
fn first_member(zip: &[u8]) -> (usize, usize) {
    let u16_at = |o: usize| usize::from(u16::from_le_bytes([zip[o], zip[o + 1]]));
    let comp = u32::from_le_bytes(zip[18..22].try_into().unwrap()) as usize;
    (30 + u16_at(26) + u16_at(28), comp)
}

fn entry_summary(entries: &[exav_unpack::Entry]) -> Vec<(&str, Option<&str>, usize)> {
    entries
        .iter()
        .map(|e| (e.name.as_str(), e.unsupported, e.data.len()))
        .collect()
}

/// A member cut off by the end of the file has what decodes of it scanned, and
/// is not reported, whatever its codec and wherever the cut: every byte
/// present was decoded, and the rest is absent.
#[test]
fn orphan_member_cut_off_by_the_end_of_the_file_is_decoded_not_reported() {
    let mut wrong = Vec::new();
    for ((codec, built, large), (clean, found)) in CUT_FIXTURES.into_iter().zip(CUT_7ZIP) {
        if !built {
            continue;
        }
        let zip = fixture(&format!("cut_{codec}.zip"));
        let content = cut_content(large);
        let (start, comp) = first_member(&zip);
        let whole = orphan_entries(&zip[..start + comp]);
        if !matches!(&whole[..], [e] if e.unsupported.is_none() && e.data == content) {
            wrong.push(format!("{codec}, whole: {:?}", entry_summary(&whole)));
        }
        // One byte in, the cut is inside the codec's own header, if it has one.
        let cuts = [
            (1, false, 0),
            (comp * CUT_CLEAN / 100, false, clean),
            (comp * CUT_FOUND / 100, true, found),
        ];
        for (cut, eicar, oracle) in cuts {
            let got = orphan_entries(&zip[..start + cut]);
            let ok = matches!(&got[..], [e] if e.name == "member.txt"
                && e.unsupported.is_none()
                && content.starts_with(&e.data)
                && e.data.len() + CUT_SLACK >= oracle)
                && any_has_eicar(&got) == eicar;
            if !ok {
                wrong.push(format!("{codec}, cut at {cut}: {:?}", entry_summary(&got)));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// Damage part way through a member, with the rest of it after the damage, is
/// reported: those bytes are present and were not decoded. Stored data has no
/// structure to damage. The deflate decoders do not see this damage and
/// decode on to the stream's end, past the declared size, which is what says
/// so there.
#[test]
fn orphan_member_damaged_part_way_is_reported() {
    let mut wrong = Vec::new();
    for (codec, built, _) in CUT_FIXTURES {
        if !built || codec == "stored" {
            continue;
        }
        let mut zip = fixture(&format!("cut_{codec}.zip"));
        let (start, comp) = first_member(&zip);
        let at = start + comp * DAMAGE_AT / 100;
        zip[at..at + DAMAGE_LEN].fill(0xff);
        let got = orphan_entries(&zip[..start + comp]);
        if !matches!(&got[..], [e] if e.unsupported.is_some()) {
            wrong.push(format!("{codec}: {:?}", entry_summary(&got)));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// A member left out of the central directory whose extent runs into the
/// member after it is reported: the bytes past its span are present, as that
/// member's.
#[test]
fn hidden_member_running_into_the_next_one_is_reported() {
    let zip = fixture("cut_deflate.zip");
    let (start, comp) = first_member(&zip);
    let blob = hidden_before_a_zip(&zip[..start + comp / 2]);
    let (seen, end) = walk_with_buffer(&blob, 16 << 20);
    end.unwrap();
    let summary: Vec<_> = seen.iter().map(|s| (&s.0, s.1, s.2.len())).collect();
    assert!(
        seen.iter().any(|s| s.0 == "member.txt" && s.1.is_some()),
        "{summary:?}"
    );
}

/// ZIP method 98 (PPMd variant I rev. 1) on the orphan-header path, against a
/// stream from the reference `ppmd-rust` PPMd8 encoder.
#[test]
fn zip_ppmd_member_is_decoded() {
    use std::io::Write;

    const ORDER: u32 = 8;
    const MEM_MB: u32 = 17;

    let mut stream = Vec::new();
    {
        let mut enc = ppmd_rust::Ppmd8Encoder::new(
            &mut stream,
            ORDER,
            MEM_MB << 20,
            ppmd_rust::RestoreMethod::Restart,
        )
        .expect("build reference PPMd8 encoder");
        enc.write_all(EICAR).expect("encode");
        enc.finish(false).expect("finish");
    }

    // APPNOTE 5.10.4: (order - 1) + ((MB - 1) << 4) + (restore << 12).
    let w: u16 = ((ORDER - 1) as u16) | (((MEM_MB - 1) as u16) << 4);
    let mut member = w.to_le_bytes().to_vec();
    member.extend_from_slice(&stream);

    let blob = lfh_sized("ppmd.txt", 98, &member, EICAR.len() as u32);
    let entries = orphan_entries(&blob);
    assert!(
        any_has_eicar(&entries),
        "a PPMd (method 98) member must be decoded, got {:?}",
        entries
            .iter()
            .map(|e| (&e.name, e.unsupported, e.data.len()))
            .collect::<Vec<_>>()
    );
}

/// A deflate member that decompresses past the per-member budget must be
/// reported as metadata-only, not returned as its truncated prefix — a prefix
/// reads as a complete member and would be scanned, and found clean, on partial
/// content.
#[test]
fn orphan_member_over_the_size_budget_is_reported_not_truncated() {
    use std::io::Write;
    let big = vec![b'A'; 4 * 1024 * 1024];
    let mut deflated = Vec::new();
    {
        let mut e = flate2::write::DeflateEncoder::new(&mut deflated, flate2::Compression::best());
        e.write_all(&big).unwrap();
        e.finish().unwrap();
    }
    let blob = lfh("huge.bin", 8, 0, &deflated, None);

    let mut limits = Limits::default();
    limits.max_buffer_bytes = 64 * 1024; // far below the 4 MiB member
    let mut budget = Budget::new(limits);
    let entries = extract(Format::Zip, &blob, &mut budget).unwrap_or_default();
    if let Some(m) = entries.iter().find(|e| e.name == "huge.bin") {
        assert!(
            m.unsupported.is_some(),
            "an over-budget member must be metadata-only, got {} bytes of data",
            m.data.len()
        );
    }
}
