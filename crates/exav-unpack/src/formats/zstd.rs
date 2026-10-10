//! Zstandard: one member, every frame of the file decoded in turn as it is
//! read. Skippable frames carry no content and are passed over.
use std::io::{self, BufRead, BufReader, Read};

use ruzstd::decoding::errors::{FrameDecoderError, ReadFrameHeaderError};
use ruzstd::decoding::{BlockDecodingStrategy, FrameDecoder};

use crate::source::{ByteSource, Reader};
use crate::stream::{emit_stream, single_meta, Visit};
use crate::{Budget, LimitHit};

pub(crate) fn walk<T>(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<T>,
) -> Result<Option<T>, LimitHit> {
    budget.count_entry()?;
    emit_stream(
        &single_meta("zstd-content", src, None),
        &mut ZstdReader::new(Reader::new(src)),
        budget,
        visit,
    )
}

/// The concatenation of an input's frames, as `zstd -d` outputs it. A decoder
/// that stopped after the first frame would leave the rest of the input unread
/// while the member looked complete.
///
/// `ruzstd` holds back the last window of a frame until the frame ends, so a
/// frame that fails would take up to a window of decoded bytes with it. On an
/// error the frame is ended here, with an empty last block, and what was
/// decoded before the error is handed over first. The error is
/// `UnexpectedEof` when the input ran out, `InvalidData` otherwise.
pub(crate) struct ZstdReader<R> {
    source: Tracked<BufReader<R>>,
    decoder: FrameDecoder,
    in_frame: bool,
    failed: Option<io::Error>,
}

/// A reader that remembers it ran dry.
struct Tracked<R> {
    inner: R,
    ended: bool,
}

impl<R: Read> Read for Tracked<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.ended |= n == 0 && !buf.is_empty();
        Ok(n)
    }
}

impl<R: Read> ZstdReader<R> {
    pub(crate) fn new(inner: R) -> Self {
        ZstdReader {
            source: Tracked {
                inner: BufReader::new(inner),
                ended: false,
            },
            decoder: FrameDecoder::new(),
            in_frame: false,
            failed: None,
        }
    }

    fn error(&self, e: FrameDecoderError) -> io::Error {
        let kind = match self.source.ended {
            true => io::ErrorKind::UnexpectedEof,
            false => io::ErrorKind::InvalidData,
        };
        io::Error::new(kind, e)
    }
}

impl<R: Read> Read for ZstdReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if !self.in_frame {
                if let Some(e) = self.failed.take() {
                    return Err(e);
                }
                if self.source.inner.fill_buf()?.is_empty() {
                    return Ok(0);
                }
                match self.decoder.init(&mut self.source) {
                    Ok(()) => self.in_frame = true,
                    // Its content is no one's: a skippable frame cut short
                    // ends the input with nothing lost.
                    Err(FrameDecoderError::ReadFrameHeaderError(
                        ReadFrameHeaderError::SkipFrame { length, .. },
                    )) => {
                        let skip = u64::from(length);
                        io::copy(&mut (&mut self.source).take(skip), &mut io::sink())?;
                        continue;
                    }
                    Err(e) => return Err(self.error(e)),
                }
            }
            // The same loop `ruzstd`'s `StreamingDecoder` runs: decoding is by
            // block, and a block's bytes are only collectable once it is done.
            while self.decoder.can_collect() < buf.len() && !self.decoder.is_finished() {
                let wanted = buf.len() - self.decoder.can_collect();
                let strategy = BlockDecodingStrategy::UptoBytes(wanted);
                if let Err(e) = self.decoder.decode_blocks(&mut self.source, strategy) {
                    let e = self.error(e);
                    // An empty raw block flagged last (RFC 8878 3.1.1.2), and
                    // the 4-byte checksum, read only if the frame has one.
                    const LAST: [u8; 7] = [1, 0, 0, 0, 0, 0, 0];
                    if self
                        .decoder
                        .decode_blocks(&LAST[..], BlockDecodingStrategy::All)
                        .is_err()
                    {
                        return Err(e);
                    }
                    self.failed = Some(e);
                }
            }
            let n = self.decoder.read(buf)?;
            if n > 0 {
                return Ok(n);
            }
            if !self.decoder.is_finished() {
                return Ok(0);
            }
            self.in_frame = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{extract, Budget, Format, Limits};
    use ruzstd::encoding::{compress_to_vec, CompressionLevel};

    #[test]
    fn every_frame_is_decoded() {
        let mut blob = compress_to_vec(&b"first frame "[..], CompressionLevel::Fastest);
        // A skippable frame: magic 0x184D2A50, a 4-byte length, then data.
        blob.extend_from_slice(&0x184D_2A50u32.to_le_bytes());
        blob.extend_from_slice(&3u32.to_le_bytes());
        blob.extend_from_slice(b"xyz");
        blob.extend(compress_to_vec(
            &b"PAYLOAD in frame two"[..],
            CompressionLevel::Fastest,
        ));
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Zstd, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, b"first frame PAYLOAD in frame two");
    }
}
