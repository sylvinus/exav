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
fn header_worth_reading(head: &[u8], len: u64) -> bool {
    // Too short to carry a level byte. The reader reports that truncation
    // itself, and does so without over-reserving.
    if head.len() < 21 {
        return true;
    }
    let declared = match head[20] {
        // Levels 0 and 1 size the header with a single byte, so the worst
        // over-declaration is a couple of hundred bytes.
        0 | 1 => return true,
        2 => u64::from(u16::from_le_bytes([head[0], head[1]])),
        // Level 3 is the only one that states its total in 32 bits, and so the
        // only one that can name a size no machine will satisfy.
        3 => match head.get(24..28) {
            Some(b) => u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])),
            None => return true,
        },
        // A level this reader may define and this check does not: leave the
        // judgement to the reader rather than guess against it.
        _ => return true,
    };
    declared <= len || declared <= MAX_PLAUSIBLE_HEADER
}

/// Walk an LHA/LZH archive: `delharc`'s per-member decoder is already a
/// `Read`, so each member is decoded as it is read. A member with an
/// unsupported compression method is reported, not skipped; directories are
/// ignored.
pub(crate) fn walk<T>(
    src: &dyn crate::source::ByteSource,
    budget: &mut Budget,
    visit: crate::stream::Visit<T>,
) -> Result<Option<T>, LimitHit> {
    use crate::stream::{emit_stream, MemberMeta};
    check_first_header(src)?;
    let mut dec = delharc::LhaDecodeReader::new(crate::source::Reader::new(src))
        .map_err(|e| LimitHit::new(format!("lha: {e}")))?;
    loop {
        if !dec.header().is_directory() {
            budget.count_entry()?;
            let header = dec.header();
            let meta = MemberMeta {
                name: header.parse_pathname_to_str(),
                comp_size: header.compressed_size,
                size: Some(header.original_size),
                encrypted: false,
                unsupported: None,
            };
            let visited = if dec.is_decoder_supported() {
                emit_stream(&meta, &mut dec, budget, visit)?
            } else {
                let meta = MemberMeta {
                    unsupported: Some("unsupported LHA compression method"),
                    ..meta
                };
                visit(&meta, None, budget)
            };
            if let Some(t) = visited {
                return Ok(Some(t));
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

/// Refuse an archive whose first header would make the reader reserve more
/// than any archive carries (see [`header_worth_reading`]).
pub(crate) fn check_first_header(src: &dyn crate::source::ByteSource) -> Result<(), LimitHit> {
    if header_worth_reading(&src.window(0, 28), src.len() as u64) {
        return Ok(());
    }
    Err(LimitHit::corrupt(
        "lha: header declares a size no archive carries".into(),
    ))
}
