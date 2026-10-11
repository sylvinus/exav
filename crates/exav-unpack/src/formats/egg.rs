//! EGG — ESTsoft's successor to ALZ, ordinary in Korea and rare elsewhere.
//!
//! Implemented from ESTsoft's published *EGG Format Specification v1.0*. No
//! vendor code was consulted: the spec documents the layout completely, which is
//! the only thing needed here.
//!
//! **Every block carries a CRC-32 of its decompressed bytes**, which the tests
//! check the decoders against: the external oracle this project requires
//! before shipping a decoder, supplied by the format itself. A block that
//! decodes in full and fails it is scanned all the same, as a ZIP member is,
//! and reported only when checksums are verified
//! ([`crate::Budget::set_verify_checksums`]).
//!
//! The archive is a chain of self-describing records. Each extension field is
//! `magic(4) | flags(1) | size(2 or 4) | data`, and a run of them ends at a stop
//! marker — so an unknown field is skipped by length rather than guessed at, and
//! a future EGG version stays readable. AZO is ESTsoft's own undocumented
//! algorithm, decoded by a port of the one permissively licensed implementation
//! (`formats::azo`).

use crate::{Budget, Entry, Format, LimitHit, Sink};

/// Ends any run of extension fields, and the archive itself.
const END: u32 = 0x08E2_8222;
const FILE_HEADER: u32 = 0x0A85_90E3;
const BLOCK_HEADER: u32 = 0x02B5_0C13;
const FILENAME_HEADER: u32 = 0x0A85_91AC;
const ENCRYPT_HEADER: u32 = 0x08D1_470F;

/// Compression algorithms, from the block header's low byte.
const STORE: u8 = 0;
const DEFLATE: u8 = 1;
const BZIP2: u8 = 2;
const AZO: u8 = 3;
const LZMA: u8 = 4;

fn le_u32(d: &[u8], at: usize) -> Option<u32> {
    crate::bytes::at(d, at, 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn le_u16(d: &[u8], at: usize) -> Option<u16> {
    crate::bytes::at(d, at, 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

/// One extension field, already located by its magic.
struct Field {
    magic: u32,
    /// Offset of the field's payload within the archive.
    body: usize,
    /// Offset just past the field. The payload is `body..next`.
    next: usize,
}

/// Read the extension field at `at`, or `None` if it is the stop marker or the
/// buffer is too short. Unknown magics parse identically — that is the point of
/// the length prefix.
fn field(d: &[u8], at: usize) -> Option<Field> {
    let magic = le_u32(d, at)?;
    if magic == END {
        return None;
    }
    let flags = *d.get(at.checked_add(4)?)?;
    // Bit 0 selects a 4-byte length; everything else in the flag byte is the
    // field's own business and must not change how far to skip.
    let len_at = at.checked_add(5)?;
    let (len, hdr) = if flags & 0x01 != 0 {
        (le_u32(d, len_at)? as usize, 9)
    } else {
        (le_u16(d, len_at)? as usize, 7)
    };
    let body = at.checked_add(hdr)?;
    Some(Field {
        magic,
        body,
        next: body.checked_add(len)?,
    })
}

/// Walk a run of extension fields from `at`, returning the offset just past the
/// stop marker along with the filename and whether the run declared encryption.
fn extension_run(d: &[u8], mut at: usize) -> (usize, Option<String>, bool) {
    let mut name = None;
    let mut encrypted = false;
    // Bounded so a field claiming zero length cannot spin forever.
    for _ in 0..64 {
        let Some(f) = field(d, at) else { break };
        match f.magic {
            FILENAME_HEADER => {
                if let Some(raw) = d.get(f.body..f.next) {
                    name = Some(String::from_utf8_lossy(raw).into_owned());
                }
            }
            ENCRYPT_HEADER => encrypted = true,
            _ => {}
        }
        if f.next <= at {
            break; // no forward progress: refuse to loop
        }
        at = f.next;
    }
    // Past the stop marker, when there is one.
    (at.saturating_add(4), name, encrypted)
}

pub(crate) fn extract_egg<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    if !super::sniff::is(data, Format::Egg) {
        return Ok(None);
    }
    // EGG header: magic(4) version(2) header-id(4) reserved(4).
    let mut p = 14usize;
    // Archive-level extension fields (split / solid / global encryption).
    let (after_global, _, global_encrypted) = extension_run(data, p);
    p = after_global;

    let mut emitted = 0usize;
    let mut name: Option<String> = None;
    let mut encrypted = global_encrypted;
    let mut index = 0usize;

    while p.saturating_add(4) <= data.len() {
        let Some(magic) = le_u32(data, p) else { break };
        match magic {
            END => break,
            FILE_HEADER => {
                // magic(4) file-id(4) file-length(8), then this file's fields.
                let after = p.saturating_add(16);
                let (next, n, enc) = extension_run(data, after);
                name = n;
                encrypted = global_encrypted || enc;
                p = next;
            }
            BLOCK_HEADER => {
                let Some(hdr) = crate::bytes::at(data, p.saturating_add(4), 14) else {
                    break;
                };
                let algo = hdr[0];
                let uncomp = u32::from_le_bytes([hdr[2], hdr[3], hdr[4], hdr[5]]) as u64;
                let comp = u32::from_le_bytes([hdr[6], hdr[7], hdr[8], hdr[9]]) as usize;
                let crc = u32::from_le_bytes([hdr[10], hdr[11], hdr[12], hdr[13]]);
                // The block's own extension fields, then its payload.
                let (body, _, _) = extension_run(data, p.saturating_add(18));
                let Some(end) = body.checked_add(comp) else {
                    break;
                };
                // A block cut by the end of the file: what is there is
                // decoded, the rest is absent.
                let rest_absent = end > data.len();
                let Some(raw) = data.get(body..end.min(data.len())) else {
                    break;
                };
                p = end.min(data.len());
                index += 1;
                emitted += 1;

                let member = name
                    .clone()
                    .unwrap_or_else(|| format!("egg-member-{index}"));
                budget.count_entry()?;
                let cap = budget.reserve()?;
                let entry = if encrypted {
                    Entry::unsupported(member, uncomp, true, "encrypted EGG member")
                } else {
                    match decode_block(algo, raw, uncomp, cap) {
                        Some(s) if !s.over_cap && (s.undecoded || s.cut_short) => {
                            // Decoded as far as the block goes. Its CRC-32
                            // covers bytes that did not decode, so it cannot
                            // be checked; damage, or a stream that ended
                            // with bytes of the block after it, is reported.
                            crate::ratio_guard(raw.len() as u64, s.data.len() as u64, budget)?;
                            budget.commit(s.data.len() as u64);
                            let why = s.part_way(rest_absent).then_some(
                                "EGG block failed to decode part way; the bytes before the \
                                 failure were scanned",
                            );
                            Entry {
                                unsupported: why,
                                ..Entry::new(member, s.data)
                            }
                        }
                        // Decoded in full. A CRC-32 mismatch after that
                        // hides nothing: the bytes are scanned, as a ZIP
                        // member's are, and reported only when checksums
                        // are verified.
                        Some(s)
                            if !s.over_cap
                                && (!budget.should_verify_checksums() || crc32(&s.data) == crc) =>
                        {
                            crate::ratio_guard(raw.len() as u64, s.data.len() as u64, budget)?;
                            budget.commit(s.data.len() as u64);
                            Entry::new(member, s.data)
                        }
                        Some(s) if !s.over_cap => Entry::unsupported(
                            member,
                            uncomp,
                            false,
                            "EGG block did not match its recorded CRC-32 after decoding",
                        ),
                        Some(_) => Entry::unsupported(
                            member,
                            uncomp,
                            false,
                            "EGG block exceeds the per-member decompression budget",
                        ),
                        None => Entry::unsupported(
                            member,
                            uncomp,
                            false,
                            "EGG block uses a compression method exav cannot decode",
                        ),
                    }
                };
                if let Some(r) = visit(entry, budget) {
                    return Ok(Some(r));
                }
            }
            // An unrecognised record at member level: stop rather than guess at
            // a length and walk into the middle of something.
            _ => break,
        }
    }

    if emitted == 0 {
        budget.count_entry()?;
        return Ok(visit(
            Entry::unsupported(
                "egg-archive".to_string(),
                data.len() as u64,
                global_encrypted,
                "EGG archive: no member could be read",
            ),
            budget,
        ));
    }
    Ok(None)
}

/// Decompress one block, keeping what decoded before an error. `None` for an
/// algorithm exav cannot decode.
fn decode_block(algo: u8, raw: &[u8], uncomp: u64, cap: u64) -> Option<crate::Salvaged> {
    use crate::salvage;
    use std::io::Cursor;
    match algo {
        STORE => Some(crate::Salvaged {
            data: raw[..raw.len().min(cap as usize)].to_vec(),
            over_cap: raw.len() as u64 > cap,
            undecoded: false,
            cut_short: (raw.len() as u64) < uncomp,
        }),
        DEFLATE => Some(salvage(crate::inflate::Inflate::new(raw), cap)),
        BZIP2 => Some(salvage(
            super::bzip2_rs::DecoderReader::new(Cursor::new(raw)),
            cap,
        )),
        LZMA => {
            // An LZMA block is not a bare stream. It opens with a 4-byte codec
            // record — algorithm, flags, then a u16 property length — followed by
            // that many LZMA1 property bytes and the stream itself.
            //
            // The spec's block section does not describe this, so it was read off
            // real archives: the length always reads 5, the five bytes are the
            // usual `5d` + 32-bit dictionary size, and the byte after them is the
            // 0x00 that opens every LZMA range-coded stream. The result matching
            // the block's CRC-32 (tests/suites/egg.rs) is what settles it.
            let prop_len = le_u16(raw, 2)? as usize;
            let props_at = 4;
            let props = *raw.get(props_at)?;
            let dict = crate::bounded_dict(le_u32(raw, props_at + 1)?, cap);
            let stream = raw.get(props_at + prop_len..)?;
            // LZMA1 carries no end marker here, so the decoder is told how much
            // to produce; `uncomp` comes from the block header the CRC covers.
            let lzma = lzma_rust2::LzmaStream::new_with_props(uncomp, props, dict, None).ok()?;
            Some(salvage(super::lzma::SansIo::new(stream, lzma), cap))
        }
        // ESTsoft's own algorithm. The spec does not document it; the decoder is
        // ported from the one permissively licensed implementation (see
        // `formats::azo`), and checked against the block CRC by the tests.
        AZO => super::azo::decompress(raw, cap).map(|data| crate::Salvaged {
            data,
            over_cap: false,
            undecoded: false,
            cut_short: false,
        }),
        _ => None,
    }
}

/// CRC-32 (IEEE), as EGG records it.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Limits;

    // The magic itself is tested in `formats::sniff`, which owns it.

    /// A field at the top of the address space is past the end of the data,
    /// whichever way its offsets are added; the run ends there.
    #[test]
    fn a_field_at_the_top_of_the_address_space_ends_the_run() {
        let d = [0u8; 64];
        for at in [usize::MAX, usize::MAX - 3, usize::MAX - 8] {
            assert_eq!(le_u32(&d, at), None);
            assert_eq!(le_u16(&d, at), None);
            assert!(field(&d, at).is_none());
            assert_eq!(extension_run(&d, at), (at.saturating_add(4), None, false));
        }
    }

    fn members(blob: &[u8]) -> Vec<Entry> {
        let mut b = Budget::new(Limits::default());
        let mut seen = Vec::new();
        let _ = extract_egg(blob, &mut b, &mut |e: Entry, _: &mut Budget| {
            seen.push(e);
            None::<()>
        });
        seen
    }

    #[test]
    fn a_recognised_archive_is_never_clean() {
        // Magic only, nothing behind it.
        let seen = members(b"EGGA\x01\x00padding");
        assert_eq!(seen.len(), 1, "exactly one report");
        assert!(
            seen[0].unsupported.is_some(),
            "must surface as unscannable, not pass as clean"
        );
        assert!(seen[0].data.is_empty(), "nothing is invented");
    }

    #[test]
    fn a_stored_member_round_trips() {
        let payload = b"the quick brown fox\n";
        let blob = build_egg("hello.txt", STORE, payload, crc32(payload));
        let seen = members(&blob);
        assert_eq!(seen.len(), 1, "got {seen:?}");
        assert_eq!(seen[0].name, "hello.txt");
        assert_eq!(seen[0].data, payload, "stored member must round-trip");
        assert!(seen[0].unsupported.is_none());
    }

    /// Every byte of the block was read, so the mismatch hides nothing.
    #[test]
    fn a_block_whose_crc_disagrees_after_a_full_decode_is_delivered() {
        let payload = b"the quick brown fox\n";
        let blob = build_egg("hello.txt", STORE, payload, crc32(payload) ^ 1);
        let seen = members(&blob);
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].data, payload, "{seen:?}");
        assert!(seen[0].unsupported.is_none(), "{seen:?}");
    }

    #[cfg(feature = "checksums")]
    #[test]
    fn a_block_whose_crc_disagrees_is_reported_when_checksums_are_verified() {
        let payload = b"the quick brown fox\n";
        let blob = build_egg("hello.txt", STORE, payload, crc32(payload) ^ 1);
        let mut b = Budget::new(Limits::default());
        b.set_verify_checksums(true);
        let mut seen = Vec::new();
        let _ = extract_egg(&blob, &mut b, &mut |e: Entry, _: &mut Budget| {
            seen.push(e);
            None::<()>
        });
        assert_eq!(seen.len(), 1);
        assert!(seen[0].unsupported.is_some(), "{seen:?}");
        assert!(seen[0].data.is_empty(), "{seen:?}");
    }

    /// AZO decodes now (see `formats::azo`), but a block that is not a valid AZO
    /// stream must still be reported rather than turned into something.
    #[test]
    fn a_malformed_azo_block_is_reported_rather_than_guessed_at() {
        let blob = build_egg("secret.bin", AZO, b"\x00\x01\x02\x03", 0);
        let seen = members(&blob);
        assert_eq!(seen.len(), 1);
        assert!(seen[0].unsupported.is_some(), "{seen:?}");
        assert!(seen[0].data.is_empty());
    }

    /// A minimal single-block EGG, built to the spec's layout.
    fn build_egg(name: &str, algo: u8, body: &[u8], crc: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"EGGA");
        v.extend_from_slice(&0x0100u16.to_le_bytes());
        v.extend_from_slice(&1u32.to_le_bytes()); // header id
        v.extend_from_slice(&0u32.to_le_bytes()); // reserved
        v.extend_from_slice(&END.to_le_bytes()); // no archive-level fields

        v.extend_from_slice(&FILE_HEADER.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes()); // file id
        v.extend_from_slice(&(body.len() as u64).to_le_bytes());
        // Filename extension field.
        v.extend_from_slice(&FILENAME_HEADER.to_le_bytes());
        v.push(0); // 2-byte size
        v.extend_from_slice(&(name.len() as u16).to_le_bytes());
        v.extend_from_slice(name.as_bytes());
        v.extend_from_slice(&END.to_le_bytes());

        v.extend_from_slice(&BLOCK_HEADER.to_le_bytes());
        v.push(algo);
        v.push(0); // hint
        v.extend_from_slice(&(body.len() as u32).to_le_bytes()); // uncompressed
        v.extend_from_slice(&(body.len() as u32).to_le_bytes()); // compressed
        v.extend_from_slice(&crc.to_le_bytes());
        v.extend_from_slice(&END.to_le_bytes());
        v.extend_from_slice(body);
        v.extend_from_slice(&END.to_le_bytes());
        v
    }
}
