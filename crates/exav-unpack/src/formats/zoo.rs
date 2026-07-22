//! ZOO — Rahul Dhesi's 1986 archive format.
//!
//! Old, and that is exactly why it is worth opening. A format no modern scanner
//! bothers with is a place to hide something: the container is still trivially
//! unpackable by anyone who wants the payload, while a scanner that does not
//! know it sees compressed noise and reports `OK`.
//!
//! Two codecs: **LZD**, a 13-bit LZW variant, and **LZH**, Dhesi's own — which
//! is `lh5` on the wire, so `delharc` decodes it, despite ZOO sharing nothing
//! else with LHA. Structures are in [`super::zoo_parse`].
//!
//! **Deleted members are extracted too.** ZOO marks a member deleted by setting
//! a flag in its directory entry and leaves the bytes in place, exactly like the
//! NTFS MFT records `formats/ntfs.rs` walks. A scanner wants those bytes: they
//! are still in the file the victim has.
//!
//! **A CRC mismatch is reported, not thrown away.** ZOO records a CRC-16 per
//! member. Bytes that fail it are still emitted — a tampered member is the
//! interesting case, and dropping it would be a silent skip — but the entry
//! carries the mismatch so a caller can tell decoded-and-verified from
//! decoded-and-doubtful.

use super::zoo_parse::{crc16_arc, DirEntry, Header, Method, DIRENT_HEADER_SIZE, ZOO_HEADER_SIZE};
use crate::{Budget, Entry, LimitHit, Sink};

/// Bound on the directory walk; hitting it is reported, never a quiet stop.
const MAX_ENTRIES: usize = 20_000;

pub(crate) fn is_zoo(data: &[u8]) -> bool {
    super::sniff::is(data, crate::Format::Zoo)
}

/// Decode one member's bytes, or `None` with the reason.
fn decode(method: Method, raw: &[u8], org_size: u32, cap: u64) -> Result<Vec<u8>, &'static str> {
    match method {
        Method::Stored => Ok(raw.to_vec()),
        Method::Lzw => {
            let mut out = Vec::new();
            salzweg::decoder::VariableDecoder::decode(
                raw,
                &mut out,
                8,
                salzweg::Endianness::LittleEndian,
                salzweg::CodeSizeStrategy::Default,
            )
            .map_err(|_| "ZOO member could not be LZW-decoded")?;
            Ok(out)
        }
        Method::Lh5 => {
            use delharc::decode::Decoder;
            // `org_size` decides the output length, so it is capped first: a
            // crafted entry declaring 4 GB must not allocate it.
            let want = (org_size as u64).min(cap) as usize;
            let mut dec = delharc::decode::DecoderAny::new_from_compression(
                delharc::CompressionMethod::Lh5,
                raw,
            );
            let mut out = vec![0u8; want];
            dec.fill_buffer(&mut out)
                .map_err(|_| "ZOO member could not be LZH-decoded")?;
            Ok(out)
        }
        Method::Unknown(_) => Err("ZOO member uses a compression method exav does not decode"),
    }
}

pub(crate) fn extract_zoo<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    if !is_zoo(data) {
        return Ok(None);
    }
    let Some(header) = data.get(..ZOO_HEADER_SIZE).and_then(Header::parse) else {
        // The magic said ZOO; failing to read the header leaves every member
        // unexamined, which must not pass quietly.
        budget.count_entry()?;
        return Ok(visit(
            Entry::unsupported(
                "<zoo-archive>".to_string(),
                data.len() as u64,
                false,
                "ZOO archive header could not be read",
            ),
            budget,
        ));
    };

    let mut at = header.start as usize;
    let mut seen = 0usize;
    // The directory is a chain of offsets, and a crafted archive can point one
    // entry back at another. Visiting an offset twice is the cycle.
    let mut visited = std::collections::HashSet::new();
    loop {
        if !visited.insert(at) {
            budget.count_entry()?;
            return Ok(visit(
                Entry::unsupported(
                    "<zoo-directory>".to_string(),
                    0,
                    false,
                    "ZOO directory chain loops back on itself; the rest is unreachable",
                ),
                budget,
            ));
        }
        let Some(fixed) = data.get(at..).and_then(|b| b.get(..DIRENT_HEADER_SIZE)) else {
            budget.count_entry()?;
            return Ok(visit(
                Entry::unsupported(
                    "<zoo-directory>".to_string(),
                    0,
                    false,
                    "ZOO directory entry runs past the end of the archive; the \
                     members after that point are unreachable",
                ),
                budget,
            ));
        };
        let Some(entry) = DirEntry::parse(fixed) else {
            budget.count_entry()?;
            return Ok(visit(
                Entry::unsupported(
                    "<zoo-directory>".to_string(),
                    0,
                    false,
                    "ZOO directory chain broke; the members after that point are \
                     unreachable",
                ),
                budget,
            ));
        };
        // A zero data offset marks the end-of-directory sentinel entry: it names
        // nothing and holds nothing.
        if entry.offset == 0 && entry.org_size == 0 {
            break;
        }
        seen += 1;
        if seen > MAX_ENTRIES {
            budget.count_entry()?;
            return Ok(visit(
                Entry::unsupported(
                    format!("<zoo-entries-beyond-{MAX_ENTRIES}>"),
                    0,
                    false,
                    "too many ZOO members to walk them all",
                ),
                budget,
            ));
        }

        let var = data
            .get(at + DIRENT_HEADER_SIZE..)
            .map(|b| &b[..b.len().min(entry.var_dir_len as usize)])
            .unwrap_or(&[]);
        let name = entry.path(var);

        budget.count_entry()?;
        let cap = budget.reserve()?;
        if entry.org_size as u64 > cap {
            if let Some(r) = visit(
                Entry::unsupported(
                    name,
                    entry.size_now as u64,
                    false,
                    "ZOO member exceeds the per-member size budget",
                ),
                budget,
            ) {
                return Ok(Some(r));
            }
        } else {
            let raw = data
                .get(entry.offset as usize..)
                .map(|b| &b[..b.len().min(entry.size_now as usize)]);
            let decoded = match raw {
                None => Err("ZOO member data lies past the end of the archive"),
                Some(raw) if (raw.len() as u32) < entry.size_now => {
                    Err("ZOO member data is truncated")
                }
                Some(raw) => decode(entry.method, raw, entry.org_size, cap),
            };
            match decoded {
                Ok(bytes) => {
                    // The CRC is what separates a correct decode from a merely
                    // plausible one — a subtly wrong codec emits bytes, not an
                    // error. The bytes are still emitted; the entry says so.
                    let ok = crc16_arc(&bytes) == entry.crc16;
                    budget.commit(bytes.len() as u64);
                    let mut e = Entry::new(name, bytes);
                    e.comp_size = entry.size_now as u64;
                    if !ok {
                        e.unsupported = Some(
                            "ZOO member failed its recorded CRC-16; the bytes were \
                                  scanned but may be wrong",
                        );
                    }
                    if let Some(r) = visit(e, budget) {
                        return Ok(Some(r));
                    }
                }
                Err(reason) => {
                    // One member exav cannot decode must not stop the rest: the
                    // directory chain is still intact, so keep walking.
                    if let Some(r) = visit(
                        Entry::unsupported(name, entry.size_now as u64, false, reason),
                        budget,
                    ) {
                        return Ok(Some(r));
                    }
                }
            }
        }

        if entry.next == 0 {
            break;
        }
        at = entry.next as usize;
    }
    Ok(None)
}
