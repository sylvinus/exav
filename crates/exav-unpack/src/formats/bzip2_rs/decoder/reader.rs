use std::io::{self, Read, Result};

use super::{Decoder, ReadState, WriteState};

/// A high-level decoder that wraps a [`Read`] and implements [`Read`], yielding decompressed bytes
pub struct DecoderReader<R> {
    decoder: Decoder,

    reader: R,
    /// The reader has returned 0.
    input_ended: bool,
}

impl<R> DecoderReader<R> {
    /// Construct a new decoder from something implementing [`Read`]
    // NSIS alone uses only `new_nsis`.
    #[cfg(any(
        feature = "bzip2",
        feature = "sevenz",
        feature = "alz",
        feature = "egg",
        feature = "dmg",
        test
    ))]
    pub fn new(reader: R) -> Self {
        Self {
            decoder: Decoder::new(),

            reader,
            input_ended: false,
        }
    }
}

#[cfg(feature = "nsis")]
impl<R: Read> DecoderReader<io::Chain<R, io::Take<io::Repeat>>> {
    /// As [`DecoderReader::new`], for NSIS's bzip2 (see [`Decoder::new_nsis`]).
    /// The bit reader looks up to 8 bytes ahead, which a standard stream's
    /// 10-byte trailer always leaves room for and NSIS's one-byte end marker
    /// does not: zeros past the input keep the last block decodable, and the
    /// end marker is read before any of them.
    pub fn new_nsis(reader: R) -> Self {
        Self {
            decoder: Decoder::new_nsis(),

            reader: reader.chain(io::repeat(0).take(16)),
            input_ended: false,
        }
    }
}

impl<R: Read> Read for DecoderReader<R> {
    /// Decompress bzip2 data from the underlying reader. A block whose bits
    /// run out once the reader has none left is an `UnexpectedEof` error: the
    /// stream was cut short. A block cut short is not decoded at all, as the
    /// inverse transform needs all of it.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut read_zero = false;
        let mut tmp_buf = [0; 1024];

        loop {
            let state = match self.decoder.read(buf) {
                Ok(state) => state,
                Err(e) if e.is_truncated() && self.input_ended => {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, e))
                }
                Err(e) => return Err(e.into()),
            };
            match state {
                ReadState::NeedsWrite(space) => {
                    let read = self.reader.read(&mut tmp_buf[..space.min(1024)])?;

                    if read_zero && self.decoder.header_block.is_none() {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "The reader is empty?",
                        ));
                    }
                    read_zero = read == 0;
                    self.input_ended |= read_zero;

                    match self.decoder.write(&tmp_buf[..read])? {
                        WriteState::NeedsRead => unreachable!(),
                        WriteState::Written(written) => assert_eq!(written, read),
                    };
                }
                ReadState::Read(n) => return Ok(n),
                ReadState::Eof => return Ok(0),
            }
        }
    }
}
