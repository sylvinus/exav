use std::io::{self, Read, Result};

use super::{Decoder, ReadState, WriteState};

/// A high-level decoder that wraps a [`Read`] and implements [`Read`], yielding decompressed bytes
pub struct DecoderReader<R> {
    decoder: Decoder,

    reader: R,
}

impl<R> DecoderReader<R> {
    /// Construct a new decoder from something implementing [`Read`]
    pub fn new(reader: R) -> Self {
        Self {
            decoder: Decoder::new(),

            reader,
        }
    }
}

impl<R: Read> Read for DecoderReader<R> {
    /// Decompress bzip2 data from the underlying reader
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut read_zero = false;
        let mut tmp_buf = [0; 1024];

        loop {
            match self.decoder.read(buf)? {
                ReadState::NeedsWrite(space) => {
                    let read = self.reader.read(&mut tmp_buf[..space.min(1024)])?;

                    if read_zero && self.decoder.header_block.is_none() {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "The reader is empty?",
                        ));
                    }
                    read_zero = read == 0;

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
