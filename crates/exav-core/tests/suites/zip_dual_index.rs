//! ZIP dual indexing, at the verdict level.
//!
//! A ZIP carries two indexes: the central directory at the end, and a local file
//! header in front of every member. Readers use the central directory, so a
//! member left out of it is invisible to them while the extractor on the target
//! machine still unpacks it. exav therefore scans the raw bytes for local headers
//! the central directory doesn't cover.
//!
//! The verdict is the point. Finding the orphan and scanning it must yield
//! `Infected`; failing to *decode* one must yield `Unscannable`, never `Clean` —
//! a member exav could not read is content it did not examine, and reporting the
//! containing file clean on that basis is exactly the silent-clean bug.

use exav_core::{analyze, ScanOptions, Scanner, Verdict};

fn eicar() -> &'static [u8] {
    exav_core::unpack::eicar()
}

/// A bare local file header plus payload — no central directory, so every member
/// is reached through the orphan scan.
fn lfh(name: &str, method: u16, flags: u16, payload: &[u8], declared_comp: Option<u32>) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"PK\x03\x04");
    v.extend_from_slice(&20u16.to_le_bytes());
    v.extend_from_slice(&flags.to_le_bytes());
    v.extend_from_slice(&method.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&declared_comp.unwrap_or(payload.len() as u32).to_le_bytes());
    v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    v.extend_from_slice(&(name.len() as u16).to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(name.as_bytes());
    v.extend_from_slice(payload);
    v
}

#[test]
fn orphan_member_carrying_eicar_is_found() {
    let db = Scanner::builtin();
    let blob = lfh("hidden.txt", 0, 0, eicar(), None);
    match analyze(&db, &blob, &ScanOptions::default()).verdict {
        Verdict::Infected { signature, .. } => assert!(
            signature.to_ascii_uppercase().contains("EICAR"),
            "unexpected signature {signature}"
        ),
        other => panic!("EICAR hidden in an orphan local header must be FOUND, got {other:?}"),
    }
}

#[test]
fn undecodable_orphan_member_is_not_clean() {
    // Deflate64 (method 9) bytes that do not decode: the first block has the
    // reserved type 3. The member is present and the target would extract it;
    // exav cannot read it, so the honest answer is "not fully scanned".
    let db = Scanner::builtin();
    let blob = lfh(
        "packed.bin",
        9,
        0,
        b"\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8",
        None,
    );
    assert!(
        !matches!(
            analyze(&db, &blob, &ScanOptions::default()).verdict,
            Verdict::Clean
        ),
        "an orphan member exav could not decode must never be reported Clean"
    );
}

#[test]
fn encrypted_orphan_member_is_not_clean() {
    let db = Scanner::builtin();
    let blob = lfh(
        "secret.bin",
        0,
        0x0001,
        b"\x11\x22\x33\x44opaque-bytes",
        None,
    );
    assert!(
        !matches!(
            analyze(&db, &blob, &ScanOptions::default()).verdict,
            Verdict::Clean
        ),
        "an encrypted orphan member must never be reported Clean"
    );
}

/// The header declares more data than the file holds. Those bytes are absent
/// from the file, not hidden in it, and every byte present was scanned
/// (docs/QUIRKS.md).
#[test]
fn a_truncated_archive_is_clean_not_flagged() {
    let db = Scanner::builtin();
    let blob = lfh("cut.bin", 0, 0, b"only-a-few-bytes", Some(50_000));
    let v = analyze(&db, &blob, &ScanOptions::default()).verdict;
    assert!(matches!(v, Verdict::Clean), "got {v:?}");
}

/// `cut_<codec>.zip` from exav-unpack's fixtures: one member, text with EICAR
/// in the middle, written by 7-Zip 25.01 (zstd: Python around a `zstd` frame).
/// See exav-unpack's `zip_codecs` suite for how each was made, and the cuts
/// and damage 7-Zip was checked against.
fn cut_fixture(codec: &str) -> (Vec<u8>, usize, usize) {
    let p = format!(
        "{}/../exav-unpack/tests/fixtures/zip/cut_{codec}.zip",
        env!("CARGO_MANIFEST_DIR")
    );
    let zip = exav_core::unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"));
    let u16_at = |o: usize| usize::from(u16::from_le_bytes([zip[o], zip[o + 1]]));
    let comp = u32::from_le_bytes(zip[18..22].try_into().unwrap()) as usize;
    let start = 30 + u16_at(26) + u16_at(28);
    (zip, start, comp)
}

const CUT_CODECS: [&str; 8] = [
    "stored",
    "deflate",
    "deflate64",
    "bzip2",
    "lzma",
    "ppmd",
    "xz",
    "zstd",
];

/// A ZIP cut off inside its one member, as a download that stopped or the
/// first part of a split ZIP: EICAR in what remains is found, and a prefix
/// without it is clean, not partial, whatever the codec.
#[test]
fn a_zip_cut_off_inside_a_member_is_scanned_as_far_as_it_goes() {
    let db = Scanner::builtin();
    let mut wrong = Vec::new();
    for codec in CUT_CODECS {
        let (zip, start, comp) = cut_fixture(codec);
        for (pct, found) in [(25, false), (90, true)] {
            let v = analyze(
                &db,
                &zip[..start + comp * pct / 100],
                &ScanOptions::default(),
            )
            .verdict;
            let ok = match &v {
                Verdict::Infected { signature, .. } => {
                    found && signature.to_ascii_uppercase().contains("EICAR")
                }
                Verdict::Clean => !found,
                _ => false,
            };
            if !ok {
                wrong.push(format!("{codec}, cut at {pct}%: {v:?}"));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// Damage part way through a member found by its local header, the rest of it
/// after the damage: those bytes are present and were not decoded, so a clean
/// prefix is not clean. 256 bytes of 0xFF a tenth of the way in, which 7-Zip
/// reports as a data error in each. The deflate decoders do not see this
/// damage and decode on, EICAR included: `FOUND`, the member still reported.
#[test]
fn an_orphan_member_damaged_part_way_is_not_clean() {
    let db = Scanner::builtin();
    let mut wrong = Vec::new();
    for codec in CUT_CODECS.into_iter().filter(|c| *c != "stored") {
        let (mut zip, start, comp) = cut_fixture(codec);
        let at = start + comp / 10;
        zip[at..at + 256].fill(0xff);
        let v = analyze(&db, &zip[..start + comp], &ScanOptions::default()).verdict;
        let ok = match &v {
            Verdict::Unscannable { .. } => true,
            Verdict::Infected { .. } => codec.starts_with("deflate"),
            _ => false,
        };
        if !ok {
            wrong.push(format!("{codec}: {v:?}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// A deflated member cut off by the end of the file, EICAR in the part that
/// remains: only decoding what is present finds it.
#[test]
fn eicar_in_what_remains_of_a_cut_deflated_member_is_found() {
    use std::io::Write;
    let mut plain = eicar().to_vec();
    let mut seed = 0x2545_f491_u32;
    while plain.len() < 32 << 10 {
        seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        plain.push(b'a' + (seed >> 16) as u8 % 26);
    }
    let mut deflated = Vec::new();
    {
        let mut e = flate2::write::DeflateEncoder::new(&mut deflated, flate2::Compression::fast());
        e.write_all(&plain).unwrap();
        e.finish().unwrap();
    }
    let mut blob = lfh("cut.bin", 8, 0, &deflated, None);
    blob[22..26].copy_from_slice(&(plain.len() as u32).to_le_bytes());
    blob.truncate(30 + "cut.bin".len() + deflated.len() / 2);
    let db = Scanner::builtin();
    match analyze(&db, &blob, &ScanOptions::default()).verdict {
        Verdict::Infected { signature, .. } => assert!(
            signature.to_ascii_uppercase().contains("EICAR"),
            "unexpected signature {signature}"
        ),
        other => panic!("EICAR in the present half must be FOUND, got {other:?}"),
    }
}

#[test]
fn ordinary_file_with_chance_pk34_stays_clean() {
    // The counterweight: `PK\x03\x04` occurs by chance in ordinary binaries, and
    // treating a chance hit as an unreadable member would make clean files
    // spuriously not-clean. Only structurally credible headers count.
    let db = Scanner::builtin();
    let mut blob: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
    blob[100..104].copy_from_slice(b"PK\x03\x04");
    blob[106..108].copy_from_slice(&0x0080u16.to_le_bytes()); // reserved flag bit set
    blob[108..110].copy_from_slice(&0x5555u16.to_le_bytes()); // not a real method
    blob[2000..2004].copy_from_slice(b"PK\x03\x04");
    blob[2026..2028].copy_from_slice(&0u16.to_le_bytes()); // zero-length name
    match analyze(&db, &blob, &ScanOptions::default()).verdict {
        Verdict::Clean => {}
        other => panic!("chance PK\\x03\\x04 bytes must not affect the verdict, got {other:?}"),
    }
}

#[test]
fn damaged_jar_with_hundreds_of_orphans_is_fully_scanned() {
    // The shape this was found on: a real JAR whose End Of Central Directory
    // record is gone, so no reader can enumerate it — 400+ members reachable
    // only as local headers. A few hundred members is ordinary for a JAR, so
    // capping the orphan scan below that would silently leave most of the
    // archive unscanned. EICAR sits in the 300th member, past any small cap.
    let db = Scanner::builtin();
    let mut blob = Vec::new();
    for i in 0..400 {
        let payload: &[u8] = if i == 300 {
            eicar()
        } else {
            b"harmless filler"
        };
        blob.extend_from_slice(&lfh(&format!("pkg/cls{i}.class"), 0, 0, payload, None));
    }
    // No central directory and no EOCD at all, exactly as observed.
    match analyze(&db, &blob, &ScanOptions::default()).verdict {
        Verdict::Infected { signature, .. } => assert!(
            signature.to_ascii_uppercase().contains("EICAR"),
            "unexpected signature {signature}"
        ),
        other => panic!("EICAR in the 300th orphan member must be FOUND, got {other:?}"),
    }
}

/// `packed` as a writer that cannot seek back writes it: general-purpose bit
/// 3, both sizes zero in the local header, and a data descriptor after the
/// data carrying them (APPNOTE 4.3.9).
fn streamed(name: &str, method: u16, flags: u16, packed: &[u8], size: usize) -> Vec<u8> {
    let mut v = lfh(name, method, flags | 0x0008, &[], Some(0));
    v.extend_from_slice(packed);
    v.extend_from_slice(b"PK\x07\x08");
    v.extend_from_slice(&0u32.to_le_bytes()); // CRC-32, not checked here
    v.extend_from_slice(&(packed.len() as u32).to_le_bytes());
    v.extend_from_slice(&(size as u32).to_le_bytes());
    v
}

/// `member` in front of a valid one-member ZIP whose central directory leaves
/// it out.
fn hidden_before_a_zip(member: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    z.start_file("readme.txt", zip::write::SimpleFileOptions::default())
        .unwrap();
    z.write_all(b"nothing to see here").unwrap();
    [member, &z.finish().unwrap().into_inner()].concat()
}

/// A PPMd member (method 98) and an LZMA one (method 14) each decode to
/// their declared size, which a streamed member gives only in its data
/// descriptor. Taken from the local header, it was zero: both decoded to an
/// empty member that looked complete, and the archive scanned clean.
#[test]
fn streamed_orphan_members_carrying_eicar_are_found() {
    use std::io::Write;
    let db = Scanner::builtin();

    // APPNOTE 5.10.4 parameters (order 6, 1 MB, restart), then the reference
    // `ppmd-rust` PPMd8 stream, with an end marker as 7-Zip writes it.
    let mut ppmd = (6u16 - 1).to_le_bytes().to_vec();
    let mut enc =
        ppmd_rust::Ppmd8Encoder::new(&mut ppmd, 6, 1 << 20, ppmd_rust::RestoreMethod::Restart)
            .unwrap();
    enc.write_all(eicar()).unwrap();
    enc.finish(true).unwrap();

    // The LZMA member of `eicar_lzma.zip`, written by 7-Zip with an end
    // marker (flag bit 1): the EICAR string, then padding.
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../exav-unpack/tests/fixtures/zip/eicar_lzma.zip"
    );
    let zip = std::fs::read(path).unwrap();
    let field = |o: usize| u32::from_le_bytes(zip[o..o + 4].try_into().unwrap()) as usize;
    let start = 30 + usize::from(u16::from_le_bytes([zip[26], zip[27]]));
    assert_eq!((&zip[..4], zip[8], zip[28]), (&b"PK\x03\x04"[..], 14, 0));
    let lzma = &zip[start..start + field(18)];

    for (what, member) in [
        ("PPMd", streamed("eicar.com", 98, 0, &ppmd, eicar().len())),
        ("LZMA", streamed("eicar.txt", 14, 0x0002, lzma, field(22))),
    ] {
        for (layout, blob) in [
            ("no central directory", member.clone()),
            (
                "left out of a central directory",
                hidden_before_a_zip(&member),
            ),
        ] {
            match analyze(&db, &blob, &ScanOptions::default()).verdict {
                Verdict::Infected { signature, .. } => assert!(
                    signature.to_ascii_uppercase().contains("EICAR"),
                    "{what}, {layout}: unexpected signature {signature}"
                ),
                other => panic!("{what}, {layout}: EICAR must be FOUND, got {other:?}"),
            }
        }
    }
}
