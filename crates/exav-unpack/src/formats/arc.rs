//! ARC — the SEA archive format, and the PKARC/PAK variants that extend it.
//!
//! It predates ZIP, and it is still opened by The Unarchiver, by 7-Zip's `arc`
//! handler and by Microsoft's RecursiveExtractor, which is reason enough: exav's
//! rule is the union of what a victim's tools will open, not what is fashionable.
//! Until this landed, an `.arc` was not recognised at all, so its members went
//! unscanned with nothing said.
//!
//! Implemented from the public ARC format description. All fields are
//! **little-endian**.
//!
//! ```text
//! 1A | method | name[13] | comp_size u32 | date u16 | time u16 | crc16 u16
//!    | orig_size u32 | data...
//! ```
//!
//! repeated until a `1A 00` end marker. Method 1 is the one exception: it is the
//! original 1985 layout, which has no `orig_size` field, so its header is four
//! bytes shorter.
//!
//! Every member carries a **CRC-16 of its uncompressed bytes**, and exav checks
//! it on each one. That is what makes the less-common methods safe to attempt: a
//! decoder that is subtly wrong produces plausible bytes rather than an error,
//! and without the check those bytes would be scanned as if they were the file.

use crate::{Budget, Entry, LimitHit, Sink};

/// Every header starts with this marker.
const MARKER: u8 = 0x1A;
/// Header length, and the shorter one used by the original method 1.
const HEADER_LEN: usize = 29;
const HEADER_LEN_V1: usize = 25;
/// Methods above this are not defined by any ARC/PAK variant exav knows of, so
/// a byte beyond it means the header is not really a header.
const MAX_METHOD: u8 = 30;
/// Names are a fixed 13-byte NUL-padded field.
const NAME_LEN: usize = 13;

/// The run-length escape used by the "packed" method and applied after the LZW
/// stage of the crunched ones.
const DLE: u8 = 0x90;

/// LZW parameters shared by the crunched and squashed methods.
const CLEAR: u16 = 256;
const FIRST_FREE: u16 = 257;
const MIN_WIDTH: u32 = 9;

/// Guard on the member count; hitting it is reported, never a quiet stop.
const MAX_MEMBERS: usize = 4096;

fn le_u16(d: &[u8], off: usize) -> u16 {
    d.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .unwrap_or(0)
}

fn le_u32(d: &[u8], off: usize) -> u32 {
    d.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .unwrap_or(0)
}

/// CRC-16/ARC: the reflected `0xA001` polynomial, zero-initialised, taken over
/// the member's *uncompressed* bytes.
fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xA001
            } else {
                crc >> 1
            };
        }
    }
    crc
}

/// Is there a plausible member header at `off`?
///
/// `1A` plus a method byte is two bytes of signature, which is far too little on
/// its own — the lesson the DMG detector learned the hard way. The name carries
/// the rest of the weight: it must be printable ASCII terminated by a NUL inside
/// the thirteen-byte field.
///
/// Note what is *not* required. Real `arc` leaves whatever was in memory after
/// the terminator, so the bytes past the NUL are frequently garbage; demanding
/// NUL padding rejects most genuine archives while happening to accept the
/// tidier ones, which is the worst of both.
fn plausible_header(data: &[u8], off: usize) -> bool {
    let Some(h) = data.get(off..off + HEADER_LEN_V1) else {
        return false;
    };
    if h[0] != MARKER || h[1] == 0 || h[1] > MAX_METHOD {
        return false;
    }
    let name = &h[2..2 + NAME_LEN];
    match name.iter().position(|&b| b == 0) {
        // An empty name is not a real member.
        None | Some(0) => false,
        Some(nul) => name[..nul].iter().all(|&b| (0x20..=0x7E).contains(&b)),
    }
}

/// Where the member whose header is at `off` ends, i.e. the next header's offset.
fn next_header(data: &[u8], off: usize) -> Option<usize> {
    let method = *data.get(off + 1)?;
    let header_len = if method == 1 {
        HEADER_LEN_V1
    } else {
        HEADER_LEN
    };
    let comp_size = le_u32(data, off + 15) as usize;
    off.checked_add(header_len)?.checked_add(comp_size)
}

/// A header on its own is two bytes of magic and a name that could be
/// coincidence. What settles it is that the member's declared size lands
/// somewhere meaningful: the end-of-archive marker, another header, or the end
/// of a truncated file. Arbitrary data does not chain.
pub(crate) fn is_arc(data: &[u8]) -> bool {
    if !plausible_header(data, 0) {
        return false;
    }
    let Some(next) = next_header(data, 0) else {
        return false;
    };
    // A member whose data runs past the end is a truncated archive, which is
    // still an archive.
    if next >= data.len() {
        return true;
    }
    data.get(next..next + 2) == Some(&[MARKER, 0][..]) || plausible_header(data, next)
}

/// Undo the run-length coding: `DLE n` repeats the preceding byte, and `DLE 00`
/// is a literal `DLE`.
fn unpack_rle(src: &[u8], cap: usize) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(src.len());
    let mut last: u8 = 0;
    let mut i = 0usize;
    while i < src.len() {
        let b = src[i];
        i += 1;
        if b != DLE {
            out.push(b);
            last = b;
        } else {
            let n = *src.get(i)?;
            i += 1;
            if n == 0 {
                out.push(DLE);
                last = DLE;
            } else {
                // The run count includes the byte already emitted.
                for _ in 1..n {
                    out.push(last);
                }
            }
        }
        if out.len() > cap {
            return None;
        }
    }
    Some(out)
}

/// LZW as the crunched and squashed methods use it: codes packed
/// least-significant-bit first, a clear code at 256, and a width that grows from
/// nine bits as the table fills. Unlike Unix `compress` there is no padding to
/// group boundaries, which is why this cannot reuse `formats/lzw.rs`.
fn lzw(src: &[u8], max_width: u32, cap: usize) -> Option<Vec<u8>> {
    if !(MIN_WIDTH..=16).contains(&max_width) {
        return None;
    }
    let table_cap = 1usize << max_width;
    let mut prefix = vec![0u16; table_cap];
    let mut suffix = vec![0u8; table_cap];
    let mut next = FIRST_FREE;
    let mut width = MIN_WIDTH;
    let mut prev: Option<u16> = None;
    let mut out: Vec<u8> = Vec::new();
    let mut stack: Vec<u8> = Vec::new();

    let total_bits = (src.len() as u64) * 8;
    let mut bitpos: u64 = 0;

    loop {
        if bitpos + width as u64 > total_bits {
            break; // the stream ends here; what decoded stands
        }
        let mut code: u32 = 0;
        for i in 0..width {
            let b = bitpos + i as u64;
            let bit = (src[(b / 8) as usize] >> (b % 8)) & 1;
            code |= (bit as u32) << i;
        }
        bitpos += width as u64;
        let code = code as u16;

        if code == CLEAR {
            next = FIRST_FREE;
            width = MIN_WIDTH;
            prev = None;
            continue;
        }

        stack.clear();
        let mut c = code;
        if code >= next {
            // KwKwK: the code is the one about to be defined, so it expands to
            // the previous string followed by its own first byte.
            let p = prev?;
            stack.push(first_byte(&prefix, p));
            c = p;
        }
        while c >= 256 {
            stack.push(suffix[c as usize]);
            c = prefix[c as usize];
        }
        stack.push(c as u8);
        if out.len() + stack.len() > cap {
            return None;
        }
        out.extend(stack.iter().rev());

        if let Some(p) = prev {
            if (next as usize) < table_cap {
                prefix[next as usize] = p;
                suffix[next as usize] = *stack.last()?;
                next += 1;
            }
        }
        prev = Some(code);

        if (next as usize) >= (1usize << width) && width < max_width {
            width += 1;
        }
    }
    Some(out)
}

/// The first byte of the string a code expands to, found by walking the prefix
/// chain down to a literal.
fn first_byte(prefix: &[u16], mut c: u16) -> u8 {
    while c >= 256 {
        c = prefix[c as usize];
    }
    c as u8
}

/// What each method needs doing to it. `None` means exav has no decoder.
fn decode(method: u8, body: &[u8], orig_size: usize) -> Option<Vec<u8>> {
    match method {
        // Stored, in both the original and the current layout.
        1 | 2 => Some(body.to_vec()),
        // Packed: run-length only.
        3 => unpack_rle(body, orig_size),
        // Crunched with a fixed 12-bit table. Method 5 has no run-length stage;
        // 6 and 7 do (7 differs only in how the *encoder* hashes, which the
        // decoder never sees).
        5 => lzw(body, 12, orig_size),
        6 | 7 => unpack_rle(&lzw(body, 12, orig_size * 2)?, orig_size),
        // Crunched with a variable-width table, the width capped by a byte that
        // precedes the code stream.
        8 => {
            let (&max_width, rest) = body.split_first()?;
            unpack_rle(&lzw(rest, max_width as u32, orig_size * 2)?, orig_size)
        }
        // Squashed: the same variable-width table at 13 bits, no run-length
        // stage and no leading width byte.
        9 => lzw(body, 13, orig_size),
        _ => None,
    }
}

fn method_name(method: u8) -> &'static str {
    match method {
        4 => "ARC member is squeezed (Huffman), which exav does not decode",
        10 => "ARC member is crushed (PAK), which exav does not decode",
        11 => "ARC member is distilled (PAK), which exav does not decode",
        _ => "ARC member uses a compression method exav does not decode",
    }
}

pub(crate) fn extract_arc<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    if !is_arc(data) {
        return Ok(None);
    }
    let mut pos = 0usize;
    let mut members = 0usize;

    while pos + HEADER_LEN_V1 <= data.len() {
        if data[pos] != MARKER {
            break;
        }
        let method = data[pos + 1];
        if method == 0 {
            break; // end-of-archive marker
        }
        if !plausible_header(data, pos) {
            // The chain is walked header to header, so a header that will not
            // parse hides every member behind it.
            budget.count_entry()?;
            return Ok(visit(
                Entry::unsupported(
                    format!("<arc-header@{pos}>"),
                    0,
                    false,
                    "malformed ARC header; the members after it are unreachable",
                ),
                budget,
            ));
        }
        members += 1;
        if members > MAX_MEMBERS {
            budget.count_entry()?;
            if let Some(r) = visit(
                Entry::unsupported(
                    format!("<arc-members-beyond-{MAX_MEMBERS}>"),
                    0,
                    false,
                    "too many ARC members to enumerate them all",
                ),
                budget,
            ) {
                return Ok(Some(r));
            }
            break;
        }

        let name = {
            let raw = &data[pos + 2..pos + 2 + NAME_LEN];
            let end = raw.iter().position(|&b| b == 0).unwrap_or(NAME_LEN);
            String::from_utf8_lossy(&raw[..end]).into_owned()
        };
        let comp_size = le_u32(data, pos + 15) as usize;
        // Method 1 predates the `orig_size` field; its data is stored, so the
        // compressed size is the original size.
        let (crc, orig_size, header_len) = if method == 1 {
            (le_u16(data, pos + 23), comp_size, HEADER_LEN_V1)
        } else {
            (
                le_u16(data, pos + 23),
                le_u32(data, pos + 25) as usize,
                HEADER_LEN,
            )
        };

        let body_start = pos + header_len;
        // A body running past the end means the archive is truncated: those
        // bytes are absent rather than hidden, so what exists is still read.
        let body_end = body_start.saturating_add(comp_size).min(data.len());
        let Some(body) = data.get(body_start..body_end) else {
            break;
        };

        budget.count_entry()?;
        let cap = budget.reserve()? as usize;
        if orig_size > cap {
            if let Some(r) = visit(
                Entry::unsupported(
                    name,
                    comp_size as u64,
                    false,
                    "ARC member exceeds the per-member size budget",
                ),
                budget,
            ) {
                return Ok(Some(r));
            }
        } else {
            let decoded = decode(method, body, orig_size);
            // The archive records a CRC-16 per member. A decoder that is subtly
            // wrong yields plausible bytes rather than an error, so this is what
            // separates content from garbage.
            let entry = match decoded {
                Some(b) if b.len() == orig_size && crc16(&b) == crc => {
                    budget.commit(b.len() as u64);
                    Entry::new(name, b)
                }
                Some(_) => Entry::unsupported(
                    name,
                    comp_size as u64,
                    false,
                    "ARC member did not match its recorded CRC after decoding",
                ),
                None => Entry::unsupported(name, comp_size as u64, false, method_name(method)),
            };
            if let Some(r) = visit(entry, budget) {
                return Ok(Some(r));
            }
        }

        let next = body_start.saturating_add(comp_size);
        if next <= pos {
            break; // no progress — malformed
        }
        pos = next;
    }
    Ok(None)
}
