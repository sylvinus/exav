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
    /// The error that ended the last block short, raised once what the block
    /// did decode has been read.
    pending: Option<io::Error>,
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
            pending: None,
        })
    }

    /// Decompress the next CFDATA block into `out`. Returns `false` at the last
    /// block. A block that fails, or that the file ends inside, leaves the
    /// bytes it did decode in `out` and its error for the call after they are
    /// read; nothing is decoded past it.
    fn refill(&mut self) -> io::Result<bool> {
        if let Some(e) = self.pending.take() {
            self.blocks_left = 0;
            return Err(e);
        }
        if self.blocks_left == 0 {
            return Ok(false);
        }
        let _checksum = self.reader.read_u32::<LittleEndian>()?;
        let compressed_size = self.reader.read_u16::<LittleEndian>()? as usize;
        let uncompressed_size = self.reader.read_u16::<LittleEndian>()? as usize;
        let mut compressed = Vec::new();
        (&mut *self.reader)
            .take(compressed_size as u64)
            .read_to_end(&mut compressed)?;
        let cut = compressed.len() < compressed_size;
        let decoded = self
            .decompressor
            .decompress(compressed, uncompressed_size, cut);
        self.out = decoded.data;
        self.out_pos = 0;
        self.blocks_left -= 1;
        // A cut block that decoded in full is only followed by the cut.
        self.pending = decoded
            .error
            .or_else(|| cut.then(|| io::Error::new(io::ErrorKind::UnexpectedEof, "CAB block cut")));
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
