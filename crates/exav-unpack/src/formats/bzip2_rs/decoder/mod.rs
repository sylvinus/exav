//! bzip2 decoding APIs

pub use self::error::DecoderError;
pub use self::reader::DecoderReader;
use super::bitreader::BitReader;
use super::block::Block;
use super::header::Header;

mod error;
mod reader;

/// A low-level decoder implementation
///
/// This decoder does no IO by itself, instead enough data
/// has to be written to it in order for it to be able
/// to decode the next block. After that the decompressed content
/// for the block can be read until all of the data from the block
/// has been exhausted.
/// Repeating this process for every block in sequence will result
/// into the entire file being decompressed.
pub struct Decoder {
    header_block: Option<(Header, Block)>,

    skip_bits: usize,
    in_buf: Vec<u8>,

    eof: bool,
}

/// State returned by [`Decoder::write`]
pub enum WriteState {
    /// Enough data has already been written to [`Decoder`]
    /// in order for it to be able to decode the next block.
    /// Now call [`Decoder::read`] to read the decompressed data.
    NeedsRead,
    /// N. number of bytes have been written.
    Written(usize),
}

/// State returned by [`Decoder::read`]
pub enum ReadState {
    /// Not enough data has been written to the underlying [`Decoder`]
    /// in order to allow the next block to be decoded. Call
    /// [`Decoder::write`] to write more data. If the end of the file
    /// has been reached, call [`Decoder::write`] with an empty buffer.
    NeedsWrite(usize),
    /// N. number of data has been read
    Read(usize),
    /// The end of the compressed file has been reached and
    /// there is no more data to read
    Eof,
}

impl Decoder {
    /// Construct a new [`Decoder`], ready to decompress a new bzip2 file
    pub fn new() -> Self {
        Self {
            header_block: None,

            skip_bits: 0,
            in_buf: Vec::new(),

            eof: false,
        }
    }

    fn space(&self) -> usize {
        match &self.header_block {
            Some((_, block)) if block.is_reading() => 0,
            Some((header, _)) => {
                let max_length = max_compressed_block(header) + (self.skip_bits / 8) + 1;
                max_length - self.in_buf.len()
            }
            None => {
                Header::from_raw_blocksize(1)
                    .expect("blocksize is valid")
                    .max_blocksize() as usize
                    + 4
            }
        }
    }

    /// Write more compressed data into this [`Decoder`]
    ///
    /// See the documentation for [`WriteState`] to decide
    /// what to do next.
    pub fn write(&mut self, buf: &[u8]) -> Result<WriteState, DecoderError> {
        let space = self.space();

        match &mut self.header_block {
            Some((_, block)) if block.is_reading() => Ok(WriteState::NeedsRead),
            Some((header, block)) => {
                let written = space.min(buf.len());

                self.in_buf.extend_from_slice(&buf[..written]);

                let minimum = (self.skip_bits / 8) + max_compressed_block(header);
                if buf.is_empty() || self.in_buf.len() >= minimum {
                    block.set_ready_for_read();
                }

                Ok(WriteState::Written(written))
            }
            None => {
                let written = space.min(buf.len());
                self.in_buf.extend_from_slice(&buf[..written]);

                if self.in_buf.len() < 4 {
                    return Ok(WriteState::Written(buf.len()));
                }

                let header = Header::parse(self.in_buf[..4].try_into().unwrap())?;
                let block = Block::new(header.clone());
                self.header_block = Some((header, block));

                self.skip_bits = 4 * 8;

                if written == buf.len() {
                    return Ok(WriteState::Written(written));
                }

                match self.write(&buf[written..])? {
                    WriteState::NeedsRead => unreachable!(),
                    WriteState::Written(n) => Ok(WriteState::Written(n + written)),
                }
            }
        }
    }

    /// Read more decompressed data from this [`Decoder`]
    ///
    /// See the documentation for [`ReadState`] to decide
    /// what to do next.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<ReadState, DecoderError> {
        match &mut self.header_block {
            Some(_) if self.eof => Ok(ReadState::Eof),
            Some((_, block)) if block.is_not_ready() => Ok(ReadState::NeedsWrite(self.space())),
            Some((_, block)) => {
                let mut reader = BitReader::new(&self.in_buf);
                reader.advance_by(self.skip_bits);

                let ready_for_read = block.is_ready_for_read();

                let read = block.read(&mut reader, buf)?;

                if read == 0 {
                    if !buf.is_empty() {
                        self.eof = ready_for_read;
                    }

                    return Ok(ReadState::NeedsWrite(self.space()));
                }

                if read == 0 && !buf.is_empty() {
                    self.eof = true;
                }

                self.skip_bits = reader.position();

                if block.is_not_ready() {
                    let bytes = self.skip_bits / 8;

                    self.in_buf.drain(..bytes);

                    self.skip_bits -= bytes * 8;
                }

                Ok(ReadState::Read(read))
            }
            None => Ok(ReadState::NeedsWrite(self.space())),
        }
    }
}

/// The most bytes one compressed block can take: every symbol (at most one per
/// block byte, plus end-of-block) at the longest code, 20 bits, plus the block
/// header, selectors (up to 32767 at 7 bits) and code tables (under 8 KiB).
/// Upstream buffered only the block size, which a block of incompressible data
/// exceeds.
fn max_compressed_block(header: &Header) -> usize {
    (header.max_blocksize() as usize + 1) * 20 / 8 + 64 * 1024
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}
