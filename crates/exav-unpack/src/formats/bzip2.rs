//! bzip2: one member, every concatenated stream decoded in turn as it is read.
use crate::source::{ByteSource, Reader};
use crate::stream::{emit_stream, single_meta, Visit};
use crate::{Budget, LimitHit};
use std::io::Read;

pub(crate) fn walk<T>(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<T>,
) -> Result<Option<T>, LimitHit> {
    budget.count_entry()?;
    let mut dec = content_reader(src, budget.limits().max_buffer_bytes);
    emit_stream(
        &single_meta("bzip2-content", src, None),
        &mut dec,
        budget,
        visit,
    )
}

/// A reader over the decompressed content of `data`, every concatenated stream
/// of it (`pbzip2` writes multi-stream files, and the payload can live in a
/// later one; `DecoderReader` decodes only the first).
///
/// bzip2's decoder buffers a full block ahead, so the exact stream boundary
/// can't be recovered from the decoder. Instead the input is split on the
/// `BZh[1-9]` stream magic. A single stream, the common case, is handed back
/// as a decoder over the input. With several magics, each slice between them
/// must decode on its own, or the input is one stream with a `BZh` inside its
/// compressed data (about 1 in 2^32 per position). A reader that has handed
/// bytes to the scanner cannot take them back, so that is settled first, by
/// decoding each slice with its output discarded, and only then is the
/// content streamed the way it turned out.
pub(crate) fn content_reader(data: &dyn ByteSource, cap: u64) -> Box<dyn Read + '_> {
    let starts = stream_starts(data);
    let one = || -> Box<dyn Read + '_> {
        Box::new(super::bzip2_rs::DecoderReader::new(Reader::new(data)))
    };
    if starts.len() <= 1 {
        return one();
    }
    let bounds: Vec<(usize, usize)> = starts
        .iter()
        .enumerate()
        .map(|(i, &s)| (s, starts.get(i + 1).copied().unwrap_or(data.len())))
        .collect();
    // A stream that decoded in full and failed a block CRC is whole.
    let each_decodes = bounds.iter().all(|&(s, e)| {
        let mut slice = super::bzip2_rs::DecoderReader::new(Reader::range(data, s, e));
        std::io::copy(
            &mut (&mut slice).take(cap.saturating_add(1)),
            &mut std::io::sink(),
        )
        .map_or_else(|e| crate::is_checksum_mismatch(&e), |_| true)
    });
    if !each_decodes {
        return one();
    }
    Box::new(Streams {
        parts: bounds
            .into_iter()
            .map(|(s, e)| {
                Box::new(super::bzip2_rs::DecoderReader::new(Reader::range(
                    data, s, e,
                ))) as Box<dyn Read + '_>
            })
            .collect(),
        mismatch: None,
    })
}

/// Streams read one after another. A checksum mismatch in one is reported
/// once all of them are read, so it does not cost the streams after it.
struct Streams<'a> {
    parts: std::collections::VecDeque<Box<dyn Read + 'a>>,
    mismatch: Option<std::io::Error>,
}

impl Read for Streams<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        while let Some(part) = self.parts.front_mut() {
            match part.read(buf) {
                Ok(0) => {
                    self.parts.pop_front();
                }
                Err(e) if crate::is_checksum_mismatch(&e) => {
                    self.mismatch = Some(e);
                    self.parts.pop_front();
                }
                r => return r,
            }
        }
        self.mismatch.take().map_or(Ok(0), Err)
    }
}

/// Offsets of bzip2 stream headers (`BZh` followed by a `1`-`9` block-size).
fn stream_starts(data: &dyn ByteSource) -> Vec<usize> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(off) = data.find(b"BZh", from, data.len()) {
        if matches!(data.window(off + 3, 1).first(), Some(b'1'..=b'9')) {
            out.push(off);
        }
        from = off + 1;
    }
    out
}
