//! Unix `compress` (`.Z`) — LZW as specified by the original `compress(1)`.
//!
//! Every Unix reads `.Z`: libarchive/`bsdtar`, macOS, `gzip -d`, 7-Zip. It is
//! also old enough that a lot of tooling treats it as inert, which is exactly
//! what makes it usable as a wrapper.
//!
//! Format (public, and unchanged since 1985):
//!
//! ```text
//! 1F 9D  magic
//! xx     flags: bit 7 = block mode, bits 0-4 = max code width (9..=16)
//! ...    LZW codes, LSB-first, width growing from 9 bits as the table fills
//! ```
//!
//! Two details differ from the GIF/TIFF LZW that general-purpose crates
//! implement, which is why this is written out rather than delegated:
//!
//! * **The code stream is written in groups of eight codes.** Whenever the code
//!   width changes — on a table reset *and* on every width increase — the writer
//!   pads to the next multiple of `width * 8` bits before continuing. A decoder
//!   that skips the padding only on reset stays in step until the first width
//!   change and then reads garbage. Verified against `compress -b16`/`-b12`
//!   output from ncompress 5.0, which is where this was originally got wrong.
//! * **Block mode** reserves code 256 as a table reset.
//! * The width increases once the table reaches `1 << width` entries.
//!
//! The group boundary is measured from a base that MOVES to each padding point
//! — the reference restarts its input buffer there — and from the start of the
//! code stream, after the 3-byte header. Getting either of those wrong decodes
//! the first few hundred bytes correctly and then silently produces garbage,
//! which is why this is checked against real `compress` output rather than a
//! round-trip against a matching encoder.

use crate::{Budget, Entry, LimitHit, Sink};

const INIT_WIDTH: u32 = 9;
const MAX_WIDTH_LIMIT: u32 = 16;
const CLEAR: u16 = 256;
const FIRST_FREE: u16 = 257;

pub(crate) fn extract_lzw<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    if !super::sniff::is(data, crate::Format::Lzw) {
        return Ok(None);
    }
    budget.count_entry()?;
    let cap = budget.reserve()?;
    let (out, truncated) = match decompress(data, cap) {
        Some(v) => v,
        // A stream we cannot decode at all: the bytes are here and unread, so
        // report rather than drop.
        None => {
            return Ok(visit(
                Entry::unsupported(
                    "lzw-content".to_string(),
                    data.len() as u64,
                    false,
                    "malformed Unix compress (.Z) stream",
                ),
                budget,
            ))
        }
    };
    if truncated {
        return Ok(visit(
            Entry::unsupported(
                "lzw-content".to_string(),
                out.len() as u64,
                false,
                "Unix compress (.Z) stream exceeds the per-member size budget",
            ),
            budget,
        ));
    }
    if out.is_empty() {
        return Ok(None);
    }
    budget.commit(out.len() as u64);
    Ok(visit(Entry::new("lzw-content".to_string(), out), budget))
}

/// Decode the LZW stream. Returns `(bytes, hit_cap)`; `None` only when the
/// header itself is unusable. A stream that ends mid-code is *truncated*, not
/// corrupt: everything decoded so far is returned, matching the salvage rule for
/// sequential streams (docs/QUIRKS.md).
fn decompress(data: &[u8], cap: u64) -> Option<(Vec<u8>, bool)> {
    let max_width = (data[2] & 0x1f) as u32;
    let block_mode = data[2] & 0x80 != 0;
    if !(INIT_WIDTH..=MAX_WIDTH_LIMIT).contains(&max_width) {
        return None;
    }

    // `prefix`/`suffix` are the classic parallel arrays: entry `c` extends
    // entry `prefix[c]` by the byte `suffix[c]`.
    let table_cap = 1usize << max_width;
    let mut prefix = vec![0u16; table_cap];
    let mut suffix = vec![0u8; table_cap];
    let mut next: u16 = if block_mode { FIRST_FREE } else { CLEAR };
    let mut width = INIT_WIDTH;

    let mut out: Vec<u8> = Vec::new();
    let mut stack: Vec<u8> = Vec::new();
    let mut prev: Option<u16> = None;

    // Bit cursor over the code stream (after the 3-byte header).
    let bits = &data[3..];
    let total_bits = (bits.len() as u64) * 8;
    let mut bitpos: u64 = 0;

    // Codes are written in groups of eight, and on any width change the writer
    // pads to the next group boundary at the OLD width. The boundary is measured
    // from a base that MOVES to each padding point, not from the start of the
    // file: the reference restarts its input buffer there, so a decoder that
    // aligns absolutely drifts after the first width change.
    let mut base: u64 = 0;
    let align_to_group = |pos: u64, base: u64, width: u32| -> u64 {
        let group = (width as u64) * 8;
        base + (pos - base).div_ceil(group) * group
    };

    let read_code = |bitpos: &mut u64, width: u32| -> Option<u16> {
        if *bitpos + width as u64 > total_bits {
            return None;
        }
        let mut v: u32 = 0;
        for i in 0..width {
            let b = *bitpos + i as u64;
            let byte = bits[(b / 8) as usize];
            let bit = (byte >> (b % 8)) & 1;
            v |= (bit as u32) << i; // LSB-first
        }
        *bitpos += width as u64;
        Some(v as u16)
    };

    loop {
        // Widen before reading, mirroring the writer: it grows the code width as
        // soon as the table reaches `(1 << width) - 1` entries, and pads to the
        // next group boundary at the old width as it does so.
        if width < max_width && next as u32 >= (1u32 << width) {
            bitpos = align_to_group(bitpos, base, width);
            base = bitpos;
            width += 1;
        }
        let Some(code) = read_code(&mut bitpos, width) else {
            break; // ran out of input: truncated, keep what we have
        };

        if block_mode && code == CLEAR {
            // A reset is also a width change: pad at the width in force, then
            // start over at the initial width.
            bitpos = align_to_group(bitpos, base, width);
            base = bitpos;
            next = FIRST_FREE;
            width = INIT_WIDTH;
            prev = None;
            continue;
        }

        // Rebuild the string for `code` by walking the prefix chain.
        stack.clear();
        let mut cur = code;
        if cur >= next {
            // KwKwK: the code refers to the entry being defined right now.
            let p = prev?;
            stack.push(first_byte(&prefix, &suffix, p));
            cur = p;
        }
        let mut guard = 0usize;
        while cur >= 256 {
            if cur as usize >= table_cap || guard > table_cap {
                return None; // cyclic or out-of-range chain: unusable header state
            }
            stack.push(suffix[cur as usize]);
            cur = prefix[cur as usize];
            guard += 1;
        }
        stack.push(cur as u8);
        for &b in stack.iter().rev() {
            out.push(b);
        }
        if out.len() as u64 > cap {
            out.truncate(cap as usize);
            return Some((out, true));
        }

        // Define the next table entry from the previous code plus this string's
        // first byte.
        if let Some(p) = prev {
            if (next as usize) < table_cap {
                prefix[next as usize] = p;
                suffix[next as usize] = *stack.last().unwrap_or(&0);
                next += 1;
            }
        }
        prev = Some(code);
    }
    Some((out, false))
}

/// First byte of the string a code expands to.
fn first_byte(prefix: &[u16], suffix: &[u8], mut c: u16) -> u8 {
    let mut guard = 0usize;
    while c >= 256 {
        if c as usize >= prefix.len() || guard > prefix.len() {
            return 0;
        }
        c = prefix[c as usize];
        guard += 1;
        let _ = suffix;
    }
    c as u8
}
