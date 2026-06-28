//! Pure-Rust 7z (LZMA/7z) archive reader.
//!
//! Inspired by [`sevenz-rust2`](https://github.com/hasenbanck/sevenz-rust2)
//! (Apache-2.0), re-implemented natively for `#![forbid(unsafe_code)]` and
//! to use our own PPMd7 model (zero-`unsafe`) instead of `ppmd-rust`.
//!
//! Supports: LZMA, LZMA2, Copy, BCJ (x86/ARM/ARM64), Delta, BZip2, Deflate,
//! PPMd7. Encryption and writing are not supported.

mod decode;
mod entry;
mod header;
mod parse;

pub(crate) use entry::extract_sevenz;

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
