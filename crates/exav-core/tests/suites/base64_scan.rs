//! End-to-end test for the base64-embedded-executable scan: a text/script
//! carrier that stashes a PE as a base64 string (the PowerShell reflective-loader
//! pattern) is detected when — and only when — `decode_base64` is on.

use base64::Engine;
use exav_core::{ScanOptions, Scanner, Verdict, analyze};

// The standard EICAR test string — the built-in DB carries a signature for it.
// Assembled at runtime; see `exav_core::unpack::eicar` for why it is never a
// literal anywhere in this tree.
fn eicar() -> &'static [u8] {
    exav_core::unpack::eicar()
}

/// A minimal but structurally valid PE (MZ + e_lfanew → `PE\0\0`) that embeds the
/// EICAR string, padded so its base64 encoding exceeds the scan's minimum run.
fn eicar_pe() -> Vec<u8> {
    let mut pe = vec![0u8; 2048];
    pe[0] = b'M';
    pe[1] = b'Z';
    pe[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    pe[0x40..0x44].copy_from_slice(b"PE\x00\x00");
    pe[0x80..0x80 + eicar().len()].copy_from_slice(eicar());
    pe
}

fn script_with_base64(pe: &[u8]) -> Vec<u8> {
    let b64 = base64::engine::general_purpose::STANDARD.encode(pe);
    format!(
        "# dropper\r\n$PEBytes = \"{b64}\"\r\nInvoke-ReflectivePEInjection -PEBytes $PEBytes\r\n"
    )
    .into_bytes()
}

#[test]
fn base64_embedded_pe_detected_by_default() {
    let db = Scanner::builtin();
    let blob = script_with_base64(&eicar_pe());
    match analyze(&db, &blob, &ScanOptions::default()).verdict {
        Verdict::Infected { signature, .. } => {
            assert!(
                signature.to_ascii_lowercase().contains("eicar"),
                "expected EICAR from the decoded PE, got {signature}"
            );
        }
        other => panic!("expected the base64-embedded PE to be detected, got {other:?}"),
    }
}

/// The `.sfp` allowlist applies to every object, a payload decoded out of
/// another included: the PE whose SHA-256 is on it is not reported, and the
/// carrier is then clean.
#[test]
fn an_allowlisted_decoded_payload_is_not_reported() {
    use sha2::{Digest, Sha256};
    // Not a multiple of 3 bytes: its base64 ends in padding, and the hash
    // matches only if the bytes before it are decoded too.
    let pe = eicar_pe();
    assert_ne!(pe.len() % 3, 0);
    let sha: String = Sha256::digest(&pe)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut b = exav_core::loader::Builder::new();
    b.add_named_bytes(
        "x.sfp",
        format!("{sha}:{}:Allowed.Pe\n", pe.len()).as_bytes(),
        false,
    );
    let db = b.build().unwrap();
    let blob = script_with_base64(&pe);
    let v = analyze(&db, &blob, &ScanOptions::default()).verdict;
    assert!(matches!(v, Verdict::Clean), "{v:?}");
    // The entry is what clears it.
    assert!(matches!(
        analyze(&Scanner::builtin(), &blob, &ScanOptions::default()).verdict,
        Verdict::Infected { .. }
    ));
}

#[test]
fn base64_scan_off_leaves_it_clean() {
    // With decoding disabled (as under --clamav-compat / --no-base64) the base64
    // text is inert — the PE never materializes, so the script scans clean.
    let db = Scanner::builtin();
    let blob = script_with_base64(&eicar_pe());
    let mut opts = ScanOptions::default();
    opts.decode_base64 = false;
    assert!(
        matches!(analyze(&db, &blob, &opts).verdict, Verdict::Clean),
        "base64 scan disabled should leave the carrier clean"
    );
}

// ---- What the scan decodes, and what it says when it stops ------------------

/// A decoy: it starts as an executable, so the scan decodes it, and it is none.
fn decoy() -> Vec<u8> {
    let mut d = vec![0u8; 2048];
    d[0] = b'M';
    d[1] = b'Z';
    d
}

/// A PE that is valid and holds nothing.
fn clean_pe() -> Vec<u8> {
    let mut pe = vec![0u8; 2048];
    pe[0] = b'M';
    pe[1] = b'Z';
    pe[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    pe[0x40..0x44].copy_from_slice(b"PE\x00\x00");
    pe
}

fn script_with_all(runs: &[Vec<u8>]) -> Vec<u8> {
    let mut s = String::from("# dropper\r\n");
    for (i, r) in runs.iter().enumerate() {
        let b64 = base64::engine::general_purpose::STANDARD.encode(r);
        s.push_str(&format!("$p{i} = \"{b64}\"\r\n"));
    }
    s.into_bytes()
}

fn verdict_of(blob: &[u8]) -> Verdict {
    let eicar = eicar();
    assert!(
        !blob.windows(eicar.len()).any(|w| w == eicar),
        "the string must not be in the file's bytes"
    );
    analyze(&Scanner::builtin(), blob, &ScanOptions::default()).verdict
}

fn limited(v: &Verdict) -> bool {
    matches!(v, Verdict::LimitsExceeded { reason } if reason.contains("base64"))
}

#[test]
fn a_payload_behind_many_decoys_is_found_or_the_scan_says_it_stopped() {
    let payload = eicar_pe();
    // Within the number of runs it tries.
    let mut runs = vec![decoy(); 20];
    runs.push(payload.clone());
    assert!(matches!(
        verdict_of(&script_with_all(&runs)),
        Verdict::Infected { .. }
    ));
    // Past it: not a clean file.
    let mut runs = vec![decoy(); 80];
    runs.push(payload);
    let v = verdict_of(&script_with_all(&runs));
    assert!(limited(&v), "{v:?}");
}

#[test]
fn a_payload_behind_many_executables_is_found_or_the_scan_says_it_stopped() {
    let payload = eicar_pe();
    let mut runs = vec![clean_pe(); 5];
    runs.push(payload.clone());
    assert!(matches!(
        verdict_of(&script_with_all(&runs)),
        Verdict::Infected { .. }
    ));
    let mut runs = vec![clean_pe(); 12];
    runs.push(payload);
    let v = verdict_of(&script_with_all(&runs));
    assert!(limited(&v), "{v:?}");
}

#[test]
fn a_script_behind_a_long_run_of_high_bytes_is_still_read_as_text() {
    let mut blob = vec![0xE9u8; 4000];
    blob.extend_from_slice(b"\r\n");
    blob.extend_from_slice(&script_with_base64(&eicar_pe()));
    // Text over most of the file, and bytes over the start of it.
    let mut long = blob.clone();
    long.extend_from_slice(&vec![b'#'; 20000]);
    assert!(
        matches!(verdict_of(&long), Verdict::Infected { .. }),
        "{:?}",
        verdict_of(&long)
    );
}

/// A ZIP with a member of deflated EICAR and a member of bytes that do not
/// compress, which is also how it comes to be long enough for the scan to read.
fn zip_with_payload() -> Vec<u8> {
    use std::io::Write;
    let deflated = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    let stored =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    z.start_file("e.com", deflated).unwrap();
    z.write_all(&[eicar(), b"\n"].concat().repeat(40)).unwrap();
    z.start_file("pad.bin", stored).unwrap();
    let mut x = 0x2545_f491u32;
    let pad: Vec<u8> = (0..1500)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect();
    z.write_all(&pad).unwrap();
    z.finish().unwrap().into_inner()
}

#[test]
fn a_zip_in_base64_in_a_script_is_opened() {
    let b64 = base64::engine::general_purpose::STANDARD.encode(zip_with_payload());
    let blob = format!("var z = atob(\"{b64}\");\r\nsave(z, 'invoice.zip');\r\n").into_bytes();
    assert!(
        matches!(verdict_of(&blob), Verdict::Infected { .. }),
        "{:?}",
        verdict_of(&blob)
    );
}

#[test]
fn a_zip_in_a_data_uri_of_a_page_is_opened() {
    let b64 = base64::engine::general_purpose::STANDARD.encode(zip_with_payload());
    let blob = format!(
        "<html><body><a download=\"invoice.zip\" href=\"data:application/zip;base64,{b64}\">invoice</a></body></html>"
    )
    .into_bytes();
    assert!(
        matches!(verdict_of(&blob), Verdict::Infected { .. }),
        "{:?}",
        verdict_of(&blob)
    );
}

#[test]
fn a_run_that_only_starts_like_a_zip_is_not_an_archive() {
    // PK\x03\x04 and noise: a coincidence of four bytes must not make a file
    // that fails to open.
    let mut noise = b"PK\x03\x04".to_vec();
    noise.resize(2000, 0x41);
    let b64 = base64::engine::general_purpose::STANDARD.encode(&noise);
    let blob = format!("var z = \"{b64}\";\r\n").into_bytes();
    assert!(
        matches!(verdict_of(&blob), Verdict::Clean),
        "{:?}",
        verdict_of(&blob)
    );
}

#[test]
fn a_small_script_behind_a_block_of_high_bytes_is_read_as_text() {
    // Under one sample, and a fifth of it bytes that are not text.
    let mut blob = vec![0xE9u8; 500];
    blob.extend_from_slice(b"\r\n");
    blob.extend_from_slice(&script_with_base64(&eicar_pe()));
    assert!(blob.len() < 8192);
    assert!(
        matches!(verdict_of(&blob), Verdict::Infected { .. }),
        "{:?}",
        verdict_of(&blob)
    );
}
