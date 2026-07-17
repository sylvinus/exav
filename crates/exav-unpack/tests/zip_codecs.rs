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
