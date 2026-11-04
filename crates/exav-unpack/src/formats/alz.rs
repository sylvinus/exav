//! ALZ: the ESTsoft archive format, ordinary in Korea and rare elsewhere.
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
//! pins the layout: a decoder checked only against its own output emits
//! plausible bytes rather than errors, which is the failure mode this project
//! refuses to ship.

use crate::{Budget, Entry, Format, Sink};

fn is_alz(d: &[u8]) -> bool {
    super::sniff::is(d, Format::Alz)
}

/// Walk an ALZ archive and emit each member.
///
/// After the 8-byte file header each member is a `BLZ\x01` local header: name
/// length, attributes, DOS timestamp, a descriptor byte whose **high nibble is
/// the byte width of the two size fields**, then method, CRC-32, the two sizes,
/// and the name. Methods are 0 stored, 1 bzip2, 2 deflate.
pub(crate) fn extract_alz(data: &[u8], budget: &mut Budget, visit: Sink) -> crate::Extracted {
    if !is_alz(data) {
        return Ok(None);
    }
    /// `BLZ\x01`: introduces one member.
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
        let Some(h) = crate::bytes::at(data, p, 9) else {
            break;
        };
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
        let Some(m) = crate::bytes::at(data, p, 6) else {
            break;
        };
        let method = m[0];
        p += 6; // method, unknown, crc32
        let Some(sizes) = crate::bytes::at(data, p, width * 2) else {
            break;
        };
        let comp = le_uint(&sizes[..width]);
        let uncomp = le_uint(&sizes[width..]);
        p += width * 2;
        let Some(name) = crate::bytes::at(data, p, name_len) else {
            break;
        };
        let name = String::from_utf8_lossy(name).into_owned();
        p += name_len;
        let encrypted = descriptor & DESC_ENCRYPTED != 0;
        if encrypted {
            p += 12; // verification block
        }
        let comp_usize = usize::try_from(comp).unwrap_or(usize::MAX);
        let end = p.saturating_add(comp_usize);
        // A member cut by the end of the file: what is there is decoded, the
        // rest is absent.
        let rest_absent = end > data.len();
        let Some(body) = data.get(p..end.min(data.len())) else {
            break;
        };
        p = end.min(data.len());
        emitted += 1;

        budget.count_entry()?;
        let cap = budget.reserve()?;
        let over = "ALZ member exceeds the per-member decompression budget";
        // Larger than its room: a stored member by the bytes it stores, a
        // compressed one by the size it says when all of it is in the file.
        let said_over = match method {
            0 => body.len() as u64 > cap,
            _ => !rest_absent && uncomp > cap,
        };
        let entry = if encrypted {
            Entry::unsupported(name, uncomp, true, "encrypted ALZ member")
        } else if said_over {
            // Not decoded, nothing charged.
            Entry::over_limit(name, uncomp, over)
        } else {
            match decode_alz_member(method, body, cap) {
                // Truncated at the per-member cap: the bytes we have are real,
                // but the member was not seen in full, so it must not read as
                // fully scanned. What was decoded is charged.
                Some(s) if s.over_cap => {
                    budget.commit(s.data.len() as u64);
                    Entry::over_limit(name, uncomp, over)
                }
                Some(s) => {
                    budget.commit(s.data.len() as u64);
                    let why = s.part_way(rest_absent).then_some(
                        "ALZ member failed to decode part way; the bytes before the failure \
                         were scanned",
                    );
                    Entry {
                        unsupported: why,
                        ..Entry::new(name, s.data)
                    }
                }
                None => Entry::unsupported(
                    name,
                    uncomp,
                    false,
                    "ALZ member uses a compression method exav cannot decode",
                )
                .of_kind(crate::tree::ReasonKind::Unsupported),
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

/// Decompress one ALZ member, keeping what decoded before an error. `None` for
/// a method exav cannot decode, which the caller turns into an `unsupported`
/// entry rather than a silent skip.
fn decode_alz_member(method: u8, body: &[u8], cap: u64) -> Option<crate::Salvaged> {
    use crate::salvage;
    use std::io::Cursor;
    match method {
        0 => Some(crate::Salvaged {
            data: body[..body.len().min(cap as usize)].to_vec(),
            over_cap: body.len() as u64 > cap,
            undecoded: false,
            cut_short: false,
        }),
        1 => Some(salvage(
            super::bzip2_rs::DecoderReader::new(Cursor::new(body)),
            cap,
        )),
        2 => Some(salvage(crate::inflate::Inflate::new(body), cap)),
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
                None
            },
        );
        assert_eq!(seen.len(), 1, "exactly one report");
        assert!(
            seen[0].unsupported.is_some(),
            "must surface as unscannable, not pass as clean"
        );
        assert!(seen[0].data.is_empty(), "nothing is invented");
    }

    /// The members of an archive of one, of `method`, that says it is `comp`
    /// bytes compressed and 1 GiB uncompressed, over the default room.
    fn said_over(method: u8, comp: u32, body: &[u8]) -> Vec<Entry> {
        one_member(method, comp, 1 << 30, body)
    }

    /// The members of an archive of one, of `method`, that says it is `comp`
    /// bytes compressed and `uncomp` uncompressed.
    fn one_member(method: u8, comp: u32, uncomp: u32, body: &[u8]) -> Vec<Entry> {
        let mut alz = b"ALZ\x01\x0a\x00\x00\x00BLZ\x01".to_vec();
        alz.extend_from_slice(&5u16.to_le_bytes());
        // Attributes, time, sizes 4 bytes wide, then the method, CRC-32.
        alz.extend_from_slice(&[0x20, 0, 0, 0, 0, 0x40, 0, method, 0, 0, 0, 0, 0]);
        alz.extend_from_slice(&comp.to_le_bytes());
        alz.extend_from_slice(&uncomp.to_le_bytes());
        alz.extend_from_slice(b"a.txt");
        alz.extend_from_slice(body);
        let mut b = Budget::new(Limits::default());
        let mut seen = Vec::new();
        extract_alz(&alz, &mut b, &mut |e: Entry, _: &mut Budget| {
            seen.push(e);
            None
        })
        .unwrap();
        seen
    }

    /// A member said to be over the room is read when what it says is not all
    /// in the file: a stored one is the bytes it stores, and a compressed one
    /// the file ends inside is what of it is here.
    #[test]
    fn a_member_said_over_the_room_is_read_when_that_is_not_in_the_file() {
        use std::io::Write;
        let body = b"some bytes";
        let got = said_over(0, body.len() as u32, body);
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].data, body, "stored: {got:?}");
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
        e.write_all(body).unwrap();
        let deflated = e.finish().unwrap();
        let got = said_over(2, deflated.len() as u32 + 100, &deflated);
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].data, body, "cut: {got:?}");
    }

    /// A method other than stored, bzip2 and deflate is reported as a method
    /// not decoded, not as damage.
    #[test]
    fn an_unknown_method_is_reported_as_unsupported() {
        let body = b"some bytes";
        let got = one_member(3, body.len() as u32, body.len() as u32, body);
        assert_eq!(got.len(), 1, "{got:?}");
        assert!(got[0].data.is_empty(), "{got:?}");
        assert_eq!(
            got[0].unsupported,
            Some("ALZ member uses a compression method exav cannot decode")
        );
        assert_eq!(
            got[0].reason_kind,
            Some(crate::tree::ReasonKind::Unsupported)
        );
    }
}
