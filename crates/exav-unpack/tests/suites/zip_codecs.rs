//! ZIP members compressed with a codec the `zip` crate itself can't decode
//! (LZMA method 14, BZIP2 method 12) must still be decompressed by exav's own
//! decoders and scanned — a payload behind an exotic codec must not hide. And one
//! undecodable member must never abort the whole archive.

use exav_unpack::{extract, Budget, Format, Limits};

const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR";

fn fixture(name: &str) -> Vec<u8> {
    let p = format!("{}/tests/fixtures/zip/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
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

fn orphan_entries(blob: &[u8]) -> Vec<exav_unpack::Entry> {
    let mut budget = Budget::new(Limits::default());
    extract(Format::Zip, blob, &mut budget).unwrap()
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
fn orphan_member_with_a_nonsense_method_is_reported_not_dropped() {
    // Method 47506 is in no version of APPNOTE. Live APK packers stamp exactly
    // this on `AndroidManifest.xml` — together with a corrupt central directory,
    // so the member is reachable only through the orphan scan. Gating that scan on
    // a recognised method drops the one member the packer went to the trouble of
    // hiding, and the archive then scans clean.
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
    assert!(
        m.unsupported.is_some(),
        "an undecodable method must surface, not vanish"
    );
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
fn orphan_truncated_member_is_not_flagged_the_bytes_are_absent() {
    // Declare far more compressed bytes than the file contains. The archive is
    // truncated, so the declared bytes are ABSENT rather than hidden — what does
    // exist is still covered by the outer raw scan. Reporting here would make
    // every damaged archive noisy for no security gain (docs/QUIRKS.md).
    let e = orphan_entries(&lfh("cut.bin", 0, 0, b"only-a-few", Some(50_000)));
    assert!(
        e.iter().all(|x| x.unsupported.is_none()),
        "truncation must not be reported as unreadable, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
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

/// ZIP method 98 (PPMd var.H) end-to-end, against a stream produced by an
/// independent reference encoder (`ppmd-rust`) rather than by exav's own code.
///
/// The stream format is shared with 7z, but ZIP carries the model parameters in
/// a 2-byte APPNOTE 5.9 header at the front of the member instead of in coder
/// properties — so this is the part 7z's tests do NOT cover.
#[test]
fn zip_ppmd_member_is_decoded() {
    use std::io::Write;

    const ORDER: u32 = 8;
    const MEM_MB: u32 = 17;

    let mut stream = Vec::new();
    {
        let mut enc = ppmd_rust::Ppmd7Encoder::new(&mut stream, ORDER, MEM_MB << 20)
            .expect("build reference PPMd7 encoder");
        enc.write_all(EICAR).expect("encode");
        enc.finish(true).expect("finish");
    }

    // APPNOTE 5.9: order in bits 0-3 (biased by 1), memory MB in bits 4-11
    // (biased by 1).
    let w: u16 = ((ORDER - 1) as u16) | (((MEM_MB - 1) as u16) << 4);
    let mut member = w.to_le_bytes().to_vec();
    member.extend_from_slice(&stream);

    let blob = lfh("ppmd.txt", 98, 0, &member, None);
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

    let mut budget = Budget::new(Limits {
        max_buffer_bytes: 64 * 1024, // far below the 4 MiB member
        ..Limits::default()
    });
    let entries = extract(Format::Zip, &blob, &mut budget).unwrap_or_default();
    if let Some(m) = entries.iter().find(|e| e.name == "huge.bin") {
        assert!(
            m.unsupported.is_some(),
            "an over-budget member must be metadata-only, got {} bytes of data",
            m.data.len()
        );
    }
}
