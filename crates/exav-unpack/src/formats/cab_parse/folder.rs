use std::io::{self, Read, Seek, SeekFrom};

use byteorder::{LittleEndian, ReadBytesExt};

use crate::formats::cab_parse::ctype::{CompressionType, Decompressor};

/// A cab folder decoded as a **forward-only `Read`**: CFDATA blocks are read and
/// decompressed one at a time — the LZX/MSZIP decompressor retains only its
/// window/dictionary — so the whole decompressed folder is never buffered. The
/// extractor hands each file a `take(size)` window of it; what is read is
/// bounded by the scan budget, as any streamed member is.
pub(crate) struct FolderReader<'a, R: Read + Seek> {
    reader: &'a mut R,
    decompressor: Decompressor,
    blocks_left: u16,
    out: Vec<u8>,
    out_pos: usize,
}

impl<'a, R: Read + Seek> FolderReader<'a, R> {
    pub(crate) fn new(
        reader: &'a mut R,
        first_data_offset: u32,
        num_data_blocks: u16,
        compression_type: CompressionType,
    ) -> io::Result<Self> {
        let decompressor = compression_type.into_decompressor()?;
        reader.seek(SeekFrom::Start(first_data_offset as u64))?;
        Ok(Self {
            reader,
            decompressor,
            blocks_left: num_data_blocks,
            out: Vec::new(),
            out_pos: 0,
        })
    }

    /// Decompress the next CFDATA block into `out`. Returns `false` at the last
    /// block.
    fn refill(&mut self) -> io::Result<bool> {
        if self.blocks_left == 0 {
            return Ok(false);
        }
        let _checksum = self.reader.read_u32::<LittleEndian>()?;
        let compressed_size = self.reader.read_u16::<LittleEndian>()? as usize;
        let uncompressed_size = self.reader.read_u16::<LittleEndian>()? as usize;
        let mut compressed = vec![0u8; compressed_size];
        self.reader.read_exact(&mut compressed)?;
        self.out = self
            .decompressor
            .decompress(compressed, uncompressed_size)?;
        self.out_pos = 0;
        self.blocks_left -= 1;
        Ok(true)
    }
}

impl<R: Read + Seek> Read for FolderReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.out_pos >= self.out.len() {
            if !self.refill()? {
                return Ok(0);
            }
        }
        let n = (self.out.len() - self.out_pos).min(buf.len());
        buf[..n].copy_from_slice(&self.out[self.out_pos..self.out_pos + n]);
        self.out_pos += n;
        Ok(n)
    }
}
