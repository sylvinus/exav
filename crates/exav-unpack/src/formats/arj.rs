#![allow(unused_imports)]
use crate::*;
use std::io::{Cursor, Read};

/// ARJ: decode each member with the vendored `arj_parse` reader.
///
/// Header parsing and encryption code vendored from
/// [unarc-rs](https://github.com/mkrueger/unarc-rs) (MIT OR Apache-2.0,
/// copyright Mike Krüger). Methods 1-3 are LHA `-lh6-`-compatible (decoded
/// via `delharc`), method 4 is ARJ's own "fastest" codec, method 0 is stored;
/// members are CRC-32 verified only when checksum verification is enabled (off by default).
pub(crate) fn extract_arj<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    use crate::formats::arj_parse::arj_archive::ArjArchive;
    use crate::formats::arj_parse::local_file_header::{
        CompressionMethod, FileType as ArjFileType,
    };

    // `ArjArchive` owns the whole input (it seeks by absolute offset). Bound that
    // buffer by the global peak-buffer limit.
    if data.len() as u64 > budget.limits.max_buffer_bytes {
        return Err(LimitHit::new("arj archive exceeds max-buffer".to_string()));
    }
    // A main header that will not parse means the archive cannot be opened at
    // all. Reported `corrupt` (→ Unscannable), never silently clean.
    //
    // No local-header salvage here, unlike ZIP: the vendored reader is built
    // around a main header, and an ARJ local file header is a different
    // structure it cannot be started from. Recovering members without a main
    // header is a new capability rather than a fallback, and pretending
    // otherwise would report an archive as walked when nothing was enumerated.
    let mut arc = ArjArchive::new(data.to_vec())
        .ok_or_else(|| LimitHit::corrupt("arj: invalid header or CRC".to_string()))?;
    // Candidate passwords for garbled (encrypted) members. ARJ's GOST/garble
    // decryptors are wired to the same pool as every other archive.
    arc.set_passwords(&budget.passwords);

    while let Some(header) = arc.get_next_entry() {
        budget.count_entry()?;
        let supported = matches!(
            header.compression_method,
            CompressionMethod::Stored
                | CompressionMethod::CompressedMost
                | CompressionMethod::Compressed
                | CompressionMethod::CompressedFaster
                | CompressionMethod::CompressedFastest
        );
        if matches!(header.file_type, ArjFileType::Directory) || !supported {
            // A directory carries no content, so skipping it hides nothing. An
            // unsupported compression method is different: the member is there
            // and the victim's extractor will unpack it, so report rather than
            // step over it.
            if !supported && !matches!(header.file_type, ArjFileType::Directory) {
                if let Some(r) = visit(
                    Entry::unsupported(
                        header.name.clone(),
                        header.compressed_size as u64,
                        false,
                        "unsupported ARJ compression method",
                    ),
                    budget,
                ) {
                    return Ok(Some(r));
                }
            }
            if !arc.skip(&header) {
                return Err(LimitHit::corrupt("arj: truncated entry".to_string()));
            }
            continue;
        }
        let cap = budget.reserve()?;
        if header.original_size as u64 > cap {
            // Too big to decompress within budget — but its metadata is still
            // valid, so yield a metadata-only member rather than abandoning the
            // archive. `.cdb` name/size signatures still match, and the members
            // after this one still get scanned.
            if let Some(r) = visit(
                Entry::unsupported(
                    header.name.clone(),
                    header.original_size as u64,
                    false,
                    "ARJ member exceeds size budget",
                ),
                budget,
            ) {
                return Ok(Some(r));
            }
            if !arc.skip(&header) {
                return Err(LimitHit::corrupt("arj: truncated entry".to_string()));
            }
            continue;
        }
        let name = header.name.clone();
        let buf = match arc.read(&header, budget.should_verify_checksums()) {
            Some(b) => b,
            // A garbled member we couldn't decrypt (no password worked / none
            // supplied) is surfaced as an encrypted member — never a silent skip,
            // and it must not abort the rest of the archive.
            None if header.is_garbled() => {
                if let Some(r) = visit(
                    Entry::unsupported(
                        name,
                        header.original_size as u64,
                        true,
                        "encrypted ARJ member",
                    ),
                    budget,
                ) {
                    return Ok(Some(r));
                }
                continue;
            }
            // A member that will not decompress costs only itself. Aborting here
            // strands every member after it: the archive is walked no further and
            // nothing reports what was skipped, so a payload sitting behind one
            // damaged member is never scanned. Same rule the ZIP walkers follow.
            None => {
                if let Some(r) = visit(
                    Entry::unsupported(
                        name,
                        header.original_size as u64,
                        false,
                        "ARJ member failed to decompress",
                    ),
                    budget,
                ) {
                    return Ok(Some(r));
                }
                continue;
            }
        };
        ratio_guard(header.compressed_size as u64, buf.len() as u64, budget)?;
        budget.commit(buf.len() as u64);
        if let Some(r) = visit(Entry::new(name, buf), budget) {
            return Ok(Some(r));
        }
    }
    // The iterator can only say "no more entries". If it stopped on a malformed
    // header rather than the archive's end marker, everything after that point
    // was never enumerated — say so instead of returning as though the archive
    // had been walked to the end. A wrong header CRC in particular must not be
    // able to hide the rest of an archive.
    if arc.stopped_early() {
        budget.count_entry()?;
        if let Some(r) = visit(
            Entry::unsupported(
                "<arj-headers-truncated>".to_string(),
                0,
                false,
                "malformed ARJ header; remaining members not enumerated",
            ),
            budget,
        ) {
            return Ok(Some(r));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use crate::{extract, Budget, Format, Limits};

    /// A garbled (encrypted, `arj -g`) member is decrypted with a pool password
    /// and its plaintext recovered — identical to the unencrypted `sample.arj`.
    #[test]
    fn garbled_member_decrypts_with_pool_password() {
        let data = include_bytes!("../../tests/fixtures/sample_garbled.arj");
        let mut budget = Budget::with_passwords(Limits::default(), vec!["secret".to_string()]);
        let entries = extract(Format::Arj, data, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "payload.txt");
        assert_eq!(entries[0].data, b"INNER-ARJ-PAYLOAD-12345");
    }

    /// A decoy password before the real one still finds it (pool tried in order).
    #[test]
    fn garbled_member_decrypts_with_pool_second_password() {
        let data = include_bytes!("../../tests/fixtures/sample_garbled.arj");
        let mut budget = Budget::with_passwords(
            Limits::default(),
            vec!["decoy".to_string(), "secret".to_string()],
        );
        let entries = extract(Format::Arj, data, &mut budget).unwrap();
        assert_eq!(entries[0].data, b"INNER-ARJ-PAYLOAD-12345");
    }

    /// A garbled member with no/wrong password is surfaced as an encrypted member
    /// (never a silent skip) and must not abort the archive.
    #[test]
    fn garbled_member_wrong_password_is_encrypted_not_error() {
        let data = include_bytes!("../../tests/fixtures/sample_garbled.arj");
        let mut budget = Budget::with_passwords(Limits::default(), vec!["wrong".to_string()]);
        let entries = extract(Format::Arj, data, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(
            entries[0].encrypted && entries[0].data.is_empty(),
            "wrong password must yield an encrypted (metadata-only) member"
        );
    }

    #[test]
    fn extracts_arj_member() {
        // A method-1 (LH6) ARJ holding payload.txt = "INNER-ARJ-PAYLOAD-12345".
        let data = include_bytes!("../../tests/fixtures/sample.arj");
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Arj, data, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "payload.txt");
        assert_eq!(entries[0].data, b"INNER-ARJ-PAYLOAD-12345");
    }

    /// A header that declares less than it holds must be an error, not a panic.
    ///
    /// The header reader walks fixed-width fields off a slice whose length the
    /// archive chose. Any declared size that runs out mid-field is ordinary
    /// attacker input — and the CRC is over the header bytes, so an attacker
    /// computes a valid one for whatever length they like. `extract` wraps the
    /// decoder in a panic boundary, so this calls `extract_arj` directly: the
    /// decoder itself has to hold.
    ///
    /// Every length from 0 up past the largest fixed field is covered, because
    /// each one runs out at a different field.
    #[test]
    fn arj_short_header_no_panic() {
        for hsize in 0u16..40 {
            let header_data = vec![0u8; hsize as usize];
            let crc = crc32fast::hash(&header_data);

            // [60 EA] [hsize LE] [header bytes] [CRC32 LE]
            let mut data = vec![0x60, 0xEA];
            data.extend_from_slice(&hsize.to_le_bytes());
            data.extend_from_slice(&header_data);
            data.extend_from_slice(&crc.to_le_bytes());

            let mut budget = Budget::new(Limits::default());
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                super::extract_arj::<()>(&data, &mut budget, &mut |_, _| None)
            }));
            assert!(
                result.is_ok(),
                "the ARJ decoder panicked on a header declaring {hsize} bytes"
            );
        }
    }

    /// A back-reference is `res.len() - 1 - back_ptr`, so a reference equal to
    /// the output written so far underflows. An empty output has nothing to
    /// point back at, which makes the first token of a stream the easiest place
    /// to reach it.
    #[test]
    fn arj_fastest_back_reference_bounds() {
        use super::super::arj_parse::decode_fastest::decode_fastest;
        // The bit patterns that decode to a back-reference are not obvious from
        // the outside, so sweep short inputs instead of hand-crafting one: any
        // stream whose first token is a match hits the empty-output case.
        for seed in 0u16..=u16::MAX {
            let bytes = seed.to_be_bytes();
            let r = std::panic::catch_unwind(|| decode_fastest(&bytes, 64));
            assert!(
                r.is_ok(),
                "decode_fastest panicked on the two-byte stream {bytes:02x?}"
            );
        }
    }
}
