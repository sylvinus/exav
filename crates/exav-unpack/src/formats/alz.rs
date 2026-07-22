//! ALZ — the ESTsoft archive format, ordinary in Korea and rare elsewhere.
//!
//! exav had no code for it, which is the worst shape a gap can take: an
//! unrecognised container gets a raw pattern scan, matches nothing because its
//! members are compressed, and comes back **`OK`**.
//!
//! The structure is documented by the zlib-licensed `unalz` (permissive, so
//! consulting it is compatible with this crate's MIT licence). It was validated
//! against `unalz` and `unar` as external oracles rather than against itself: on
//! a real archive the first member's declared sizes (1,171,458 compressed /
//! 1,195,080 uncompressed) and name matched both tools exactly. That is what
//! pins the layout — a decoder checked only against its own output emits
//! plausible bytes rather than errors, which is the failure mode this project
//! refuses to ship.

use crate::{Budget, Entry, Format, LimitHit, Sink};

fn is_alz(d: &[u8]) -> bool {
    super::sniff::is(d, Format::Alz)
}

/// Walk an ALZ archive and emit each member.
///
/// After the 8-byte file header each member is a `BLZ\x01` local header: name
/// length, attributes, DOS timestamp, a descriptor byte whose **high nibble is
/// the byte width of the two size fields**, then method, CRC-32, the two sizes,
/// and the name. Methods are 0 stored, 1 bzip2, 2 deflate.
pub(crate) fn extract_alz<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    if !is_alz(data) {
        return Ok(None);
    }
    /// `BLZ\x01` — introduces one member.
    const LOCAL: &[u8] = b"BLZ\x01";
    /// Low nibble of the descriptor: the member is encrypted and carries a
    /// 12-byte verification block before its data.
    const DESC_ENCRYPTED: u8 = 0x01;

    let mut p = 8usize; // file header
    let mut emitted = 0usize;
    while p + 4 <= data.len() {
        if &data[p..p + 4] != LOCAL {
            break; // central directory (`CLZ\x01`) or trailing data
        }
        p += 4;
        let Some(h) = data.get(p..p + 9) else { break };
        let name_len = u16::from_le_bytes([h[0], h[1]]) as usize;
        let descriptor = h[7];
        p += 9;

        // A directory entry carries no size fields and no data.
        let width = (descriptor >> 4) as usize;
        if width == 0 {
            budget.count_entry()?;
            p += name_len;
            continue;
        }
        let Some(m) = data.get(p..p + 6) else { break };
        let method = m[0];
        p += 6; // method, unknown, crc32
        let Some(sizes) = data.get(p..p + width * 2) else {
            break;
        };
        let comp = le_uint(&sizes[..width]);
        let uncomp = le_uint(&sizes[width..]);
        p += width * 2;
        let Some(name) = data.get(p..p + name_len) else {
            break;
        };
        let name = String::from_utf8_lossy(name).into_owned();
        p += name_len;
        let encrypted = descriptor & DESC_ENCRYPTED != 0;
        if encrypted {
            p += 12; // verification block
        }
        let Ok(comp_usize) = usize::try_from(comp) else {
            break;
        };
        let Some(body) = data.get(p..p.saturating_add(comp_usize)) else {
            break;
        };
        p += comp_usize;
        emitted += 1;

        budget.count_entry()?;
        let cap = budget.reserve()?;
        let entry = if encrypted {
            Entry::unsupported(name, uncomp, true, "encrypted ALZ member")
        } else {
            match decode_alz_member(method, body, cap) {
                // Truncated at the per-member cap: the bytes we have are real,
                // but the member was not seen in full, so it must not read as
                // fully scanned.
                Some((_, true)) => Entry::unsupported(
                    name,
                    uncomp,
                    false,
                    "ALZ member exceeds the per-member decompression budget",
                ),
                Some((out, false)) => {
                    crate::ratio_guard(body.len() as u64, out.len() as u64, budget)?;
                    budget.commit(out.len() as u64);
                    Entry::new(name, out)
                }
                None => Entry::unsupported(
                    name,
                    uncomp,
                    false,
                    "ALZ member uses a compression method exav cannot decode",
                ),
            }
        };
        if let Some(r) = visit(entry, budget) {
            return Ok(Some(r));
        }
    }
    if emitted == 0 {
        // Recognised as ALZ but no member came out: say so rather than let the
        // file pass as scanned.
        budget.count_entry()?;
        return Ok(visit(
            Entry::unsupported(
                "alz-archive".to_string(),
                data.len() as u64,
                false,
                "ALZ archive: no member could be read",
            ),
            budget,
        ));
    }
    Ok(None)
}

/// Little-endian integer of 1, 2, 4 or 8 bytes.
fn le_uint(b: &[u8]) -> u64 {
    let mut v = 0u64;
    for (i, &x) in b.iter().enumerate().take(8) {
        v |= u64::from(x) << (i * 8);
    }
    v
}

/// Decompress one ALZ member. `None` for a method exav cannot decode, which the
/// caller turns into an `unsupported` entry rather than a silent skip.
fn decode_alz_member(method: u8, body: &[u8], cap: u64) -> Option<(Vec<u8>, bool)> {
    use std::io::Cursor;
    match method {
        0 => Some((body.to_vec(), body.len() as u64 > cap)),
        #[cfg(feature = "bzip2")]
        1 => crate::bounded_read(bzip2_rs::DecoderReader::new(Cursor::new(body)), cap).ok(),
        2 => crate::bounded_read(flate2::read::DeflateDecoder::new(Cursor::new(body)), cap).ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Limits;

    // The magic itself is tested in `formats::sniff`, which owns it.

    #[test]
    fn a_recognised_archive_is_never_clean() {
        let mut b = Budget::new(Limits::default());
        let mut seen = Vec::new();
        let _ = extract_alz(
            b"ALZ\x01padding here",
            &mut b,
            &mut |e: Entry, _: &mut Budget| {
                seen.push(e);
                None::<()>
            },
        );
        assert_eq!(seen.len(), 1, "exactly one report");
        assert!(
            seen[0].unsupported.is_some(),
            "must surface as unscannable, not pass as clean"
        );
        assert!(seen[0].data.is_empty(), "nothing is invented");
    }
}
