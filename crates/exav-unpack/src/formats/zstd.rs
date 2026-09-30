//! Zstandard: one member, every frame of the file decoded in turn as it is
//! read. Skippable frames carry no content and are passed over.
use std::io::{self, Read, Seek, SeekFrom};

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
    let mut frames = Frames {
        source: Reader::new(src),
        len: src.len() as u64,
        decoder: FrameDecoder::new(),
        in_frame: false,
    };
    emit_stream(
        &single_meta("zstd-content", src, None),
        &mut frames,
        budget,
        visit,
    )
}

/// The concatenation of a file's frames, as `zstd -d` outputs it. A decoder
/// that stopped after the first frame would leave the rest of the file unread
/// while the member looked complete.
struct Frames<R> {
    source: R,
    len: u64,
    decoder: FrameDecoder,
    in_frame: bool,
}

impl<R: Read + Seek> Read for Frames<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if !self.in_frame {
                if self.source.stream_position()? >= self.len {
                    return Ok(0);
                }
                match self.decoder.init(&mut self.source) {
                    Ok(()) => self.in_frame = true,
                    Err(FrameDecoderError::ReadFrameHeaderError(
                        ReadFrameHeaderError::SkipFrame { length, .. },
                    )) => {
                        self.source.seek(SeekFrom::Current(i64::from(length)))?;
                        continue;
                    }
                    Err(e) => return Err(io::Error::other(e)),
                }
            }
            // The same loop `ruzstd`'s `StreamingDecoder` runs: decoding is by
            // block, and a block's bytes are only collectable once it is done.
            while self.decoder.can_collect() < buf.len() && !self.decoder.is_finished() {
                let wanted = buf.len() - self.decoder.can_collect();
                self.decoder
                    .decode_blocks(&mut self.source, BlockDecodingStrategy::UptoBytes(wanted))
                    .map_err(io::Error::other)?;
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
