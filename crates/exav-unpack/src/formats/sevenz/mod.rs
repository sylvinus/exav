//! Pure-Rust 7z (LZMA/7z) archive reader.
//!
//! Inspired by [`sevenz-rust2`](https://github.com/hasenbanck/sevenz-rust2)
//! (Apache-2.0), re-implemented natively for `#![forbid(unsafe_code)]` and
//! to use our own PPMd7 model (zero-`unsafe`) instead of `ppmd-rust`.
//!
//! Supports: LZMA, LZMA2, Copy, BCJ (x86/ARM/ARM64), Delta, BZip2, Deflate,
//! PPMd7, and AES-256 (data streams + `-mhe=on` encrypted headers, password
//! required). Writing is not supported.

#[cfg(feature = "decrypt")]
mod aes;
mod decode;
mod entry;
mod header;
mod parse;

pub(crate) use entry::{extract_sevenz, stream_sevenz};

#[cfg(test)]
mod tests {
    use crate::{detect, extract, Budget, Format, Limits};
    use std::collections::HashMap;
    use std::fs;

    fn fixture(name: &str) -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/7z")
            .join(name);
        fs::read(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
    }

    fn extract_entries(blob: &[u8]) -> HashMap<String, Vec<u8>> {
        let mut budget = Budget::new(Limits::default());
        let entries =
            extract(Format::SevenZip, blob, &mut budget).expect("extract should not fail");
        entries.into_iter().map(|e| (e.name, e.data)).collect()
    }

    #[test]
    fn lzma2_extracts_all_files() {
        let data = fixture("lzma2.7z");
        assert_eq!(detect(&data), Some(Format::SevenZip));
        let files = extract_entries(&data);
        assert_eq!(files.len(), 4, "expected 4 files, got {files:?}");
        assert!(files.contains_key("readme.txt"));
        assert!(files.contains_key("small.txt"));
        assert!(files.contains_key("random.bin"));
        assert!(files.contains_key("src/main.rs"));
        assert_eq!(files["readme.txt"], b"Hello from LZMA2\n");
        assert_eq!(files["small.txt"], b"small file\n");
    }

    #[test]
    fn lzma_extracts_all_files() {
        let data = fixture("lzma.7z");
        assert_eq!(detect(&data), Some(Format::SevenZip));
        let files = extract_entries(&data);
        assert_eq!(files.len(), 4);
        assert_eq!(files["readme.txt"], b"Hello from LZMA2\n");
        assert_eq!(files["small.txt"], b"small file\n");
    }

    #[test]
    fn bzip2_extracts_all_files() {
        let data = fixture("bzip2.7z");
        assert_eq!(detect(&data), Some(Format::SevenZip));
        let files = extract_entries(&data);
        assert_eq!(files.len(), 4);
        assert_eq!(files["readme.txt"], b"Hello from LZMA2\n");
    }

    #[test]
    fn deflate_extracts_all_files() {
        let data = fixture("deflate.7z");
        assert_eq!(detect(&data), Some(Format::SevenZip));
        let files = extract_entries(&data);
        assert_eq!(files.len(), 4);
        assert_eq!(files["readme.txt"], b"Hello from LZMA2\n");
    }

    #[test]
    fn copy_extracts_single_file() {
        let data = fixture("copy.7z");
        assert_eq!(detect(&data), Some(Format::SevenZip));
        let files = extract_entries(&data);
        assert_eq!(files.len(), 1);
        assert_eq!(files["readme.txt"], b"Hello from LZMA2\n");
    }

    #[test]
    fn lzma2_solid_extracts_all_files() {
        let data = fixture("lzma2_solid.7z");
        assert_eq!(detect(&data), Some(Format::SevenZip));
        let files = extract_entries(&data);
        assert_eq!(
            files.len(),
            4,
            "expected 4 files (dirs excluded), got {files:?}"
        );
        assert!(files.contains_key("readme.txt"));
        assert!(files.contains_key("small.txt"));
        assert!(files.contains_key("random.bin"));
        assert!(files.contains_key("src/main.rs"));
        assert_eq!(files["readme.txt"], b"Hello from LZMA2\n");
        assert_eq!(files["small.txt"], b"small file\n");
    }

    #[test]
    fn lzma2_nonsolid_extracts_all_files() {
        let data = fixture("lzma2_nonsolid.7z");
        assert_eq!(detect(&data), Some(Format::SevenZip));
        let files = extract_entries(&data);
        assert_eq!(files.len(), 2);
        assert_eq!(files["readme.txt"], b"Hello from LZMA2\n");
        assert_eq!(files["small.txt"], b"small file\n");
    }

    #[test]
    fn ppmd_extracts_all_files() {
        let data = fixture("ppmd.7z");
        assert_eq!(detect(&data), Some(Format::SevenZip));
        let files = extract_entries(&data);
        assert_eq!(files.len(), 2);
        assert_eq!(files["readme.txt"], b"Hello from LZMA2\n");
        assert_eq!(files["small.txt"], b"small file\n");
    }

    #[test]
    fn encrypted_header_emits_unsupported() {
        let data = fixture("encrypted_header.7z");
        assert_eq!(detect(&data), Some(Format::SevenZip));
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::SevenZip, &data, &mut budget).expect("should not error");
        assert!(!entries.is_empty(), "should emit at least one entry");
        assert!(
            entries
                .iter()
                .any(|e| e.encrypted && e.unsupported.is_some()),
            "encrypted 7z must report unsupported: {:?}",
            entries
                .iter()
                .map(|e| (&e.name, e.encrypted, e.unsupported))
                .collect::<Vec<_>>()
        );
    }

    /// Extract with a candidate password list.
    #[cfg(feature = "decrypt")]
    fn extract_entries_pw(blob: &[u8], passwords: &[&str]) -> HashMap<String, Vec<u8>> {
        let pws = passwords.iter().map(|s| s.to_string()).collect();
        let mut budget = Budget::with_passwords(Limits::default(), pws);
        let entries =
            extract(Format::SevenZip, blob, &mut budget).expect("extract should not fail");
        entries.into_iter().map(|e| (e.name, e.data)).collect()
    }

    /// A real 7-Zip archive with an AES-encrypted *header* (`7z a -psecret
    /// -mhe=on`) decrypts with the password — the encoded header itself is
    /// decrypted so the file listing and content are recovered.
    #[cfg(feature = "decrypt")]
    #[test]
    fn mhe_encrypted_header_decrypts_with_password() {
        let data = fixture("eicar_mhe.7z");
        let files = extract_entries_pw(&data, &["secret"]);
        assert!(files.contains_key("eicar.txt"), "file list: {files:?}");
        assert!(
            files["eicar.txt"].windows(5).any(|w| w == b"EICAR"),
            "encrypted-header 7z must decrypt to EICAR"
        );
    }

    /// The same `-mhe` archive with no password is reported encrypted, never a
    /// silent clean.
    #[test]
    fn mhe_encrypted_header_no_password_is_unsupported() {
        let data = fixture("eicar_mhe.7z");
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::SevenZip, &data, &mut budget).expect("should not error");
        assert!(
            entries
                .iter()
                .any(|e| e.encrypted && e.unsupported.is_some()),
            "no-password -mhe must report unsupported: {entries:?}"
        );
    }

    /// Real 7-Zip-produced AES-256 archives (password `hunter2`) decrypt back to
    /// the original bytes — end-to-end proof the SHA-256 KDF matches 7-Zip. The
    /// fixtures were made with `7z a -phunter2 -mhe=off`.
    #[cfg(feature = "decrypt")]
    #[test]
    fn aes_lzma2_decrypts_with_password() {
        let data = fixture("aes_lzma2.7z");
        let files = extract_entries_pw(&data, &["hunter2"]);
        let (_, body) = files
            .iter()
            .find(|(n, _)| n.ends_with("a.txt"))
            .expect("a.txt");
        assert!(
            body.windows(16).any(|w| w == b"EICAR-7Z-AES-MAR"),
            "decrypted body must contain the marker: {:?}",
            String::from_utf8_lossy(body)
        );
    }

    /// A stored (uncompressed) AES stream: the CRC gate must accept the right
    /// password and reject a wrong one (which yields plausible garbage).
    #[cfg(feature = "decrypt")]
    #[test]
    fn aes_stored_crc_gates_password() {
        let data = fixture("aes_stored.7z");
        // Correct password → recovered.
        let ok = extract_entries_pw(&data, &["hunter2"]);
        assert!(ok
            .values()
            .any(|v| v.windows(16).any(|w| w == b"EICAR-7Z-AES-MAR")));
        // Wrong password → no plaintext member; reported unsupported instead.
        let mut budget = Budget::with_passwords(Limits::default(), vec!["wrongpw".into()]);
        let entries = extract(Format::SevenZip, &data, &mut budget).expect("no error");
        assert!(
            entries
                .iter()
                .all(|e| e.unsupported.is_some() || !e.data.windows(5).any(|w| w == b"EICAR")),
            "wrong password must not surface plaintext"
        );
        assert!(entries
            .iter()
            .any(|e| e.encrypted && e.unsupported.is_some()));
    }

    /// A solid multi-file AES block decrypts all members with one password.
    #[cfg(feature = "decrypt")]
    #[test]
    fn aes_solid_decrypts_all_members() {
        let data = fixture("aes_solid.7z");
        let files = extract_entries_pw(&data, &["nope", "hunter2"]); // 2nd password works
        let joined: Vec<u8> = files.values().flatten().copied().collect();
        assert!(joined.windows(16).any(|w| w == b"EICAR-7Z-AES-MAR"));
        assert!(joined.windows(15).any(|w| w == b"SECOND-FILE-MAR"));
    }

    /// Without a password an AES archive is still reported encrypted/unsupported.
    #[test]
    fn aes_without_password_unsupported() {
        let data = fixture("aes_lzma2.7z");
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::SevenZip, &data, &mut budget).expect("no error");
        assert!(entries
            .iter()
            .any(|e| e.encrypted && e.unsupported.is_some()));
    }

    /// Fuzz regressions: crafted 7z headers with absurd stream/file counts must
    /// fail gracefully (Err or empty), never panic (integer overflow / capacity
    /// overflow). Reproducers minimized by the `unpack` fuzz target.
    #[test]
    fn fuzz_malformed_headers_do_not_panic() {
        for name in [
            "fuzz_coder_stream_overflow.7z",
            "fuzz_num_files_overflow.7z",
        ] {
            let data = fixture(name);
            let mut budget = Budget::new(Limits::default());
            // Must return (Ok or Err) without panicking.
            let _ = extract(Format::SevenZip, &data, &mut budget);
        }
    }

    #[test]
    fn sevenz_rust2_roundtrip() {
        use sevenz_rust2::{ArchiveEntry, ArchiveWriter};
        use std::io::Cursor;

        let payload = b"hello exav inside 7zip archive";
        let mut sink = Cursor::new(Vec::new());
        {
            let mut w = ArchiveWriter::new(&mut sink).unwrap();
            w.push_archive_entry(
                ArchiveEntry::new_file("payload.bin"),
                Some(Cursor::new(payload.to_vec())),
            )
            .unwrap();
            w.finish().unwrap();
        }
        let blob = sink.into_inner();
        assert_eq!(detect(&blob), Some(Format::SevenZip));
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::SevenZip, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, payload);
    }
}
