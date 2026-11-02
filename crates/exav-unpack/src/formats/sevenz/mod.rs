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
mod bcj2;
pub(crate) mod decode;
mod entry;
mod header;
mod parse;

pub(crate) use entry::walk;

#[cfg(test)]
mod tests {
    use crate::{Budget, Format, Limits, detect, extract};
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
            extract(Format::SevenZip, &blob, &mut budget).expect("extract should not fail");
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
            extract(Format::SevenZip, &blob, &mut budget).expect("extract should not fail");
        entries.into_iter().map(|e| (e.name, e.data)).collect()
    }

    /// A real 7-Zip archive with an AES-encrypted *header* (`7z a -psecret
    /// -mhe=on`) decrypts with the password: the encoded header itself is
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
    /// the original bytes: end-to-end proof the SHA-256 KDF matches 7-Zip. The
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
        assert!(
            ok.values()
                .any(|v| v.windows(16).any(|w| w == b"EICAR-7Z-AES-MAR"))
        );
        // Wrong password → no plaintext member; reported unsupported instead.
        let mut budget = Budget::with_passwords(Limits::default(), vec!["wrongpw".into()]);
        let entries = extract(Format::SevenZip, &data, &mut budget).expect("no error");
        assert!(
            entries
                .iter()
                .all(|e| e.unsupported.is_some() || !e.data.windows(5).any(|w| w == b"EICAR")),
            "wrong password must not surface plaintext"
        );
        assert!(
            entries
                .iter()
                .any(|e| e.encrypted && e.unsupported.is_some())
        );
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

    /// 150 members of one encrypted solid block (`7z a -ppw -ms=on`). The key
    /// is derived with 2^19 SHA-256 rounds, and each member derived it again
    /// for every password up to the right one, with the block decrypted each
    /// time: 7 seconds for these 150 members, and it grows with their number
    /// and with the cycles power the archive asks for. Done once per block, it
    /// is a fraction of a second.
    #[cfg(feature = "decrypt")]
    #[test]
    #[cfg_attr(target_family = "wasm", ignore = "timing")]
    fn the_members_of_an_encrypted_solid_block_are_decrypted_once() {
        let data = fixture("aes_solid_many.7z");
        let t = std::time::Instant::now();
        let files = extract_entries_pw(&data, &["a", "b", "c", "d", "pw"]);
        assert!(t.elapsed().as_secs() < 3, "took {:?}", t.elapsed());
        assert_eq!(files.len(), 150);
        for (name, body) in &files {
            let n = name.trim_start_matches('m').trim_end_matches(".txt");
            assert_eq!(
                body,
                format!("member {n} of the solid block\n").as_bytes(),
                "{name}"
            );
        }
    }

    /// 40 folders (7-Zip gives the folders of an archive one key), each with a
    /// CRC that no password satisfies, tried with five passwords at 2^19 rounds:
    /// the keys are derived once each, not once for each folder (200 times, 2 s
    /// in a release build; and 2000 folders took 20 s, 30 at 2^24 took 9 s). Every
    /// member is still reported encrypted.
    #[cfg(feature = "decrypt")]
    #[test]
    fn a_scan_derives_the_key_of_a_password_once_for_all_the_folders() {
        let data = fixture("aes_40_folders_2p19.7z");
        let words = ["a", "b", "c", "d", "e"].map(String::from).to_vec();
        let mut budget = Budget::with_passwords(Limits::default(), words);
        let entries = extract(Format::SevenZip, &data, &mut budget).unwrap();
        assert_eq!(entries.len(), 40);
        assert!(
            entries
                .iter()
                .all(|e| e.encrypted && e.unsupported.is_some())
        );
        assert_eq!(budget.kdf.sevenz_spent(), 5 << 19);
    }

    /// Without a password an AES archive is still reported encrypted/unsupported.
    #[test]
    fn aes_without_password_unsupported() {
        let data = fixture("aes_lzma2.7z");
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::SevenZip, &data, &mut budget).expect("no error");
        assert!(
            entries
                .iter()
                .any(|e| e.encrypted && e.unsupported.is_some())
        );
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

    /// A filter in front of LZMA, which decodes to the size its coder
    /// declares. Written by 7-Zip 25.01 from the 2149-byte `known.txt` of the
    /// ZIP data-descriptor fixtures: `7z a -t7z -m0=BCJ -m1=LZMA` and
    /// `-m0=Delta:4 -m1=LZMA`.
    #[test]
    fn filter_and_lzma_chains_from_7zip_decode() {
        let mut known = b"exav data descriptor fixture\n".to_vec();
        for i in 1..=40 {
            known.extend_from_slice(
                format!("line {i:02}: the quick brown fox jumps over the lazy dog\n").as_bytes(),
            );
        }
        for name in ["bcj_lzma.7z", "delta_lzma.7z"] {
            let files = extract_entries(&fixture(name));
            assert_eq!(files.len(), 1, "{name}");
            assert!(files.get("known.txt") == Some(&known), "{name}");
        }
    }

    /// Code-like bytes: noise with x86 `call rel32` (high byte 0x00 or 0xFF,
    /// the ones the filter converts), ARM `BL` and ARM64 `BL`/`ADRP` words
    /// every few dozen bytes.
    fn branchy_payload() -> Vec<u8> {
        let mut seed = 0x2545_f491_u32;
        let mut out = Vec::with_capacity(256 * 1024);
        while out.len() < 256 * 1024 {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            let r = seed.to_le_bytes();
            match seed % 5 {
                0 => out.extend([0xE8, r[0], r[1], 0x00, 0x00]),
                1 => out.extend([0xE9, r[0], r[1], 0xFF, 0xFF]),
                2 => out.extend([r[0], r[1], r[2], 0xEB]),
                3 => out.extend([r[0], r[1], r[2], 0x94]),
                _ => out.extend([r[0] | 0x80, r[1], r[2], 0x90 | (r[3] & 0x0F)]),
            }
            out.extend(&r[..seed as usize % 4]);
        }
        out
    }

    /// Each branch filter undoes what 7-Zip's encoder did: the member comes out
    /// byte for byte as it went in.
    #[test]
    fn branch_filters_round_trip() {
        use sevenz_rust2::{ArchiveEntry, ArchiveWriter, EncoderMethod};
        use std::io::Cursor;

        let payload = branchy_payload();
        for filter in [
            EncoderMethod::BCJ_X86_FILTER,
            EncoderMethod::BCJ_ARM_FILTER,
            EncoderMethod::BCJ_ARM64_FILTER,
        ] {
            let mut sink = Cursor::new(Vec::new());
            {
                let mut w = ArchiveWriter::new(&mut sink).unwrap();
                w.set_content_methods(vec![EncoderMethod::LZMA2.into(), filter.into()]);
                w.push_archive_entry(
                    ArchiveEntry::new_file("code.bin"),
                    Some(Cursor::new(payload.clone())),
                )
                .unwrap();
                w.finish().unwrap();
            }
            let mut budget = Budget::new(Limits::default());
            let entries = extract(Format::SevenZip, &sink.into_inner(), &mut budget).unwrap();
            assert_eq!(entries.len(), 1, "{filter:?}");
            assert!(entries[0].data == payload, "{filter:?} altered the member");
        }
    }

    /// Every member `walk` hands over, a streamed one read to its end, and how
    /// the walk ended.
    type Walked = (Vec<(String, Vec<u8>, Option<&'static str>)>, bool);

    fn walked_from(
        src: &dyn crate::source::ByteSource,
        mut budget: Budget,
    ) -> (Walked, Result<(), crate::LimitHit>) {
        use crate::Member;
        let mut out = Vec::new();
        let end = crate::walk(
            Format::SevenZip,
            src,
            &mut budget,
            &mut |meta, content, _| {
                let data = match content {
                    None => Vec::new(),
                    Some(Member::Bytes(b)) => b,
                    Some(Member::Stream(r)) => {
                        let mut b = Vec::new();
                        let _ = r.read_to_end(&mut b);
                        b
                    }
                };
                out.push((meta.name.clone(), data, meta.unsupported));
                None::<()>
            },
        );
        ((out, end.is_ok()), end.map(|_| ()))
    }

    fn cache_of(blob: &[u8]) -> crate::source::BlockCache<std::io::Cursor<Vec<u8>>> {
        // Blocks and a capacity far under the archive, so it is never in memory.
        crate::source::BlockCache::with_sizes(std::io::Cursor::new(blob.to_vec()), 64, 4 * 64)
            .unwrap()
    }

    /// An archive on a source that is not in memory gives the members it gives
    /// when it is, under a buffer limit far under the archive.
    #[test]
    fn an_archive_on_a_source_that_is_not_in_memory_gives_the_same_members() {
        for name in [
            "lzma2.7z",
            "lzma.7z",
            "bzip2.7z",
            "deflate.7z",
            "copy.7z",
            "ppmd.7z",
            "lzma2_solid.7z",
            "lzma2_nonsolid.7z",
            "bcj_lzma.7z",
            "delta_lzma.7z",
            "ppmd_plain_header.7z",
            "many_entries.7z",
        ] {
            let blob = fixture(name);
            let (held, _) = walked_from(&blob.as_slice(), Budget::new(Limits::default()));
            // PPMd holds its model, which is 64 KiB at the least.
            let limits = Limits {
                max_buffer_bytes: if name.starts_with("ppmd") {
                    1 << 20
                } else {
                    1000
                },
                ..Limits::default()
            };
            let (cached, end) = walked_from(&cache_of(&blob), Budget::new(limits));
            end.unwrap_or_else(|h| panic!("{name}: {h:?}"));
            assert_eq!(held.0, cached.0, "{name}");
            assert!(!held.0.is_empty(), "{name}");
        }
    }

    /// A solid folder of three files, stored, so that the third starts 6000
    /// bytes into it.
    fn solid_of_three() -> (Vec<u8>, Vec<Vec<u8>>) {
        use sevenz_rust2::{ArchiveEntry, ArchiveWriter, EncoderMethod, SourceReader};
        use std::io::Cursor;
        let files: Vec<Vec<u8>> = vec![
            (0..3000u32).map(|i| (i * 7 % 251) as u8).collect(),
            (0..3000u32).map(|i| (i * 13 % 241) as u8).collect(),
            b"the tail".to_vec(),
        ];
        let mut sink = Cursor::new(Vec::new());
        {
            let mut w = ArchiveWriter::new(&mut sink).unwrap();
            w.set_content_methods(vec![EncoderMethod::COPY.into()]);
            let entries = ["a", "b", "c"]
                .iter()
                .map(|n| ArchiveEntry::new_file(n))
                .collect();
            let readers = files
                .iter()
                .map(|f| SourceReader::new(Cursor::new(f.clone())))
                .collect();
            w.push_archive_entries(entries, readers).unwrap();
            w.finish().unwrap();
        }
        (sink.into_inner(), files)
    }

    /// A member far into a solid folder is read, not reported: it starts past
    /// the buffer limit, which a folder streamed through is not held under.
    #[test]
    fn a_member_far_into_a_solid_folder_is_read_not_reported() {
        let (blob, files) = solid_of_three();
        let limits = Limits {
            max_buffer_bytes: 1000,
            ..Limits::default()
        };
        let ((got, _), end) = walked_from(&cache_of(&blob), Budget::new(limits));
        end.unwrap();
        let want: Vec<_> = ["a", "b", "c"]
            .iter()
            .zip(&files)
            .map(|(n, f)| (n.to_string(), f.clone(), None))
            .collect();
        assert_eq!(got, want);
    }

    /// The members before the one wanted are decoded and dropped, which counts
    /// against the scan budget: a folder that declares more than it allows is
    /// not decoded to reach a member.
    #[test]
    fn what_is_skipped_to_reach_a_member_counts_against_the_scan_budget() {
        let (blob, _) = solid_of_three();
        // A visitor that reads no member, so that reaching the third skips the
        // 6000 bytes of the two before it.
        let reached = |scanned: u64| {
            let mut budget = Budget::new(Limits {
                max_scanned_bytes: scanned,
                ..Limits::default()
            });
            let mut names = Vec::new();
            let end = crate::walk(
                Format::SevenZip,
                &blob.as_slice(),
                &mut budget,
                &mut |meta, _, _| {
                    names.push(meta.name.clone());
                    None::<()>
                },
            );
            (names, end)
        };
        let (names, end) = reached(1 << 20);
        end.unwrap();
        assert_eq!(names, ["a", "b", "c"]);
        let (names, end) = reached(5000);
        assert_eq!(names, ["a", "b"], "c is not reached");
        assert!(end.is_err_and(|h| !h.is_corrupt()));
    }

    /// A folder decoded whole, as an encrypted one is, is held under the buffer
    /// limit, read from where it is in the source.
    #[cfg(feature = "decrypt")]
    #[test]
    fn an_encrypted_folder_is_held_under_the_buffer_limit_and_read_from_the_source() {
        let blob = fixture("aes_stored.7z");
        let limits = Limits {
            max_buffer_bytes: 4096,
            ..Limits::default()
        };
        let budget = Budget::with_passwords(limits, vec!["hunter2".into()]);
        let ((got, _), end) = walked_from(&cache_of(&blob), budget);
        end.unwrap();
        assert!(
            got.iter()
                .any(|(_, d, _)| d.windows(16).any(|w| w == b"EICAR-7Z-AES-MAR"))
        );
        // Under a limit the packed bytes do not fit, it is the limit.
        let limits = Limits {
            max_buffer_bytes: 32,
            ..Limits::default()
        };
        let budget = Budget::with_passwords(limits, vec!["hunter2".into()]);
        let (_, end) = walked_from(&cache_of(&blob), budget);
        let hit = end.unwrap_err();
        assert!(!hit.is_corrupt(), "{}", hit.reason);
    }
}
