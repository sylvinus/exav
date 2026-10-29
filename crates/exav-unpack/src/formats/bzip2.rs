//! bzip2: one member, every concatenated stream decoded in turn as it is read.
use crate::source::{ByteSource, Reader};
use crate::stream::{Visit, emit_stream, single_meta};
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
    let one = || -> Box<dyn Read + '_> { Box::new(Recovering::new(data, 0, data.len())) };
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
        // Either one stream with a `BZh` in its compressed data, or streams of
        // which a later one is cut short or damaged. The first is read whole as
        // one stream. The ones behind the first are read as far as they go in
        // either case, so that what a later stream holds is scanned and a
        // false split costs only a stream that decodes to nothing.
        let mut parts: std::collections::VecDeque<Box<dyn Read + '_>> =
            std::collections::VecDeque::new();
        parts.push_back(one());
        for &(s, e) in bounds.iter().skip(1) {
            parts.push_back(Box::new(AsFarAsItGoes(Recovering::new(data, s, e))));
        }
        return Box::new(Streams {
            parts,
            mismatch: None,
        });
    }
    Box::new(Streams {
        parts: bounds
            .into_iter()
            .map(|(s, e)| Box::new(Recovering::new(data, s, e)) as Box<dyn Read + '_>)
            .collect(),
        mismatch: None,
    })
}

/// A reader that ends where the one inside it fails.
struct AsFarAsItGoes<R>(R);

impl<R: Read> Read for AsFarAsItGoes<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        Ok(self.0.read(buf).unwrap_or(0))
    }
}

/// One stream of `data[start..end]`, decoded; a stream cut short, whose last
/// block the decoder holds back because it looks ahead past the end of the
/// input (a cut inside the ten bytes of the trailer loses the whole block, and
/// `bzip2 -dc` writes it), is decoded again behind zeros that stand for the
/// missing bytes, from where the first pass stopped, and the cut is reported
/// once the block is out.
struct Recovering<'a> {
    data: &'a dyn ByteSource,
    range: (usize, usize),
    first: super::bzip2_rs::DecoderReader<Reader<'a>>,
    /// Bytes `first` produced, to skip in the second pass.
    produced: u64,
    second: Option<
        super::bzip2_rs::DecoderReader<std::io::Chain<Reader<'a>, std::io::Take<std::io::Repeat>>>,
    >,
    skip: u64,
    cut: Option<(std::io::ErrorKind, String)>,
}

impl<'a> Recovering<'a> {
    fn new(data: &'a dyn ByteSource, start: usize, end: usize) -> Self {
        Recovering {
            data,
            range: (start, end),
            first: super::bzip2_rs::DecoderReader::new(Reader::range(data, start, end)),
            produced: 0,
            second: None,
            skip: 0,
            cut: None,
        }
    }
}

impl Read for Recovering<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if let Some(second) = &mut self.second {
                if self.skip > 0 {
                    let mut scratch = [0u8; 4096];
                    let want = scratch.len().min(self.skip as usize);
                    match second.read(&mut scratch[..want]) {
                        Ok(n) if n > 0 => {
                            self.skip -= n as u64;
                            continue;
                        }
                        _ => return Err(self.cut_error()),
                    }
                }
                return match second.read(buf) {
                    Ok(0) | Err(_) => Err(self.cut_error()),
                    Ok(n) => Ok(n),
                };
            }
            match self.first.read(buf) {
                Ok(n) => {
                    self.produced += n as u64;
                    return Ok(n);
                }
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    self.cut = Some((e.kind(), e.to_string()));
                    self.skip = self.produced;
                    let (start, end) = self.range;
                    self.second = Some(super::bzip2_rs::DecoderReader::new(
                        Reader::range(self.data, start, end).chain(std::io::repeat(0).take(16)),
                    ));
                }
                Err(e) => return Err(e),
            }
        }
    }
}

impl Recovering<'_> {
    fn cut_error(&mut self) -> std::io::Error {
        let (kind, msg) = self.cut.clone().unwrap_or((
            std::io::ErrorKind::UnexpectedEof,
            "bzip2: stream cut short".into(),
        ));
        std::io::Error::new(kind, msg)
    }
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
