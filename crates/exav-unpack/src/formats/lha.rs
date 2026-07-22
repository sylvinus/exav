#![allow(unused_imports)]
use crate::*;
use std::io::{BufReader, Cursor, Read, Seek, Write};

/// The largest header this reader will let a level-3 archive declare.
///
/// A level-2 header states its total in sixteen bits, so the format itself caps
/// it at 64 KiB. Level 3 has room for four gigabytes and spends it on a
/// filename and a short chain of extended records — kilobytes in practice. One
/// mebibyte is sixteen times what level 2 can even express, which is enough
/// headroom that refusing something larger cannot plausibly turn away a real
/// archive.
///
/// **This bounds the amplification, it does not remove it.** Anyone reading
/// this constant can declare one byte under it and still make a small file
/// reserve a megabyte, so the ratio is capped rather than the attack prevented.
/// That is the most a per-format check can do: the reservation happens inside
/// the reader, before any budget sees a byte. Removing the class needs an
/// allocator that refuses — the reason to keep this number as low as the format
/// allows is that it is the only lever this layer has.
const MAX_PLAUSIBLE_HEADER: u64 = 1 << 20;

/// Whether the header declares a size worth handing to the reader.
///
/// The reader sizes its buffer from a header length field *before* reading the
/// bytes that field describes, so a header naming four gigabytes reserves four
/// gigabytes from an archive of a few hundred. That allocation happens inside
/// the decoder, where neither [`Budget`] nor the panic boundary can see it: a
/// budget counts what an extractor yields, and an allocation failure aborts
/// rather than unwinding.
///
/// The test is deliberately weaker than "does the header fit in `data`". A
/// declared size longer than the slice is *not* on its own a reason to refuse:
/// this extractor is also handed carved and embedded regions, where a genuine
/// archive's header can legitimately describe more than the bytes in hand.
/// Refusing those would turn an archive a real extractor opens into an
/// `Unscannable` — and a payload nobody scanned is worth more to an attacker
/// than a payload nobody could allocate.
///
/// So both conditions must hold: the header must reach past the end of what we
/// have *and* claim a size no archiver ever writes. That is the region where
/// the reader cannot succeed either — it would allocate, read short, and fail —
/// which keeps this check aligned with the answer the decoder would have given.
fn header_worth_reading(data: &[u8]) -> bool {
    // Too short to carry a level byte. The reader reports that truncation
    // itself, and does so without over-reserving.
    if data.len() < 21 {
        return true;
    }
    let declared = match data[20] {
        // Levels 0 and 1 size the header with a single byte, so the worst
        // over-declaration is a couple of hundred bytes.
        0 | 1 => return true,
        2 => u64::from(u16::from_le_bytes([data[0], data[1]])),
        // Level 3 is the only one that states its total in 32 bits, and so the
        // only one that can name a size no machine will satisfy.
        3 => match data.get(24..28) {
            Some(b) => u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])),
            None => return true,
        },
        // A level this reader may define and this check does not: leave the
        // judgement to the reader rather than guess against it.
        _ => return true,
    };
    declared <= data.len() as u64 || declared <= MAX_PLAUSIBLE_HEADER
}

/// LHA/LZH: decode each member with the pure-Rust `delharc` reader.
pub(crate) fn extract_lha<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    if !header_worth_reading(data) {
        return Err(LimitHit::corrupt(
            "lha: header declares a size no archive carries".into(),
        ));
    }
    let mut dec = delharc::LhaDecodeReader::new(Cursor::new(data))
        .map_err(|e| LimitHit::new(format!("lha: {e}")))?;
    loop {
        let header = dec.header();
        let is_dir = header.is_directory();
        let name = header.parse_pathname_to_str();
        if !is_dir && dec.is_decoder_supported() {
            budget.count_entry()?;
            let cap = budget.reserve()?;
            let (buf, truncated) =
                bounded_read(&mut dec, cap).map_err(|e| LimitHit::new(format!("lha read: {e}")))?;
            if truncated {
                return Err(LimitHit::new(format!("lha member '{name}' exceeds budget")));
            }
            budget.commit(buf.len() as u64);
            if let Some(r) = visit(Entry::new(name, buf), budget) {
                return Ok(Some(r));
            }
        }
        match dec.next_file() {
            Ok(true) => {}
            Ok(false) => break,
            Err(e) => return Err(LimitHit::new(format!("lha: {e}"))),
        }
    }
    Ok(None)
}
