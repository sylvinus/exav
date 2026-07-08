use std::io::{self, Read, Seek, SeekFrom};

use byteorder::{LittleEndian, ReadBytesExt};

use crate::formats::cab_parse::ctype::{CompressionType, Decompressor};

pub(crate) struct Folder {
    decompressed_data: Vec<u8>,
}

/// A cab folder decoded as a **forward-only `Read`**: CFDATA blocks are read and
/// decompressed one at a time — the LZX/MSZIP decompressor retains only its
/// window/dictionary — so the whole decompressed folder is never buffered. Used
/// by the streaming extractor to hand each file a `take(size)` window. Mirrors
/// [`Folder::new`]'s block loop; total output is bounded by `max_buffer` for
/// parity with the buffered path.
pub(crate) struct FolderReader<'a, R: Read + Seek> {
    reader: &'a mut R,
    decompressor: Decompressor,
    blocks_left: u16,
    out: Vec<u8>,
    out_pos: usize,
    max_buffer: u64,
    produced: u64,
}

impl<'a, R: Read + Seek> FolderReader<'a, R> {
    pub(crate) fn new(
        reader: &'a mut R,
        first_data_offset: u32,
        num_data_blocks: u16,
        compression_type: CompressionType,
        max_buffer: u64,
    ) -> io::Result<Self> {
        let decompressor = compression_type.into_decompressor()?;
        reader.seek(SeekFrom::Start(first_data_offset as u64))?;
        Ok(Self {
            reader,
            decompressor,
            blocks_left: num_data_blocks,
            out: Vec::new(),
            out_pos: 0,
            max_buffer,
            produced: 0,
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
        let decompressed = self
            .decompressor
            .decompress(compressed, uncompressed_size)?;
        self.produced = self.produced.saturating_add(decompressed.len() as u64);
        if self.produced > self.max_buffer {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "cab folder exceeds max-buffer",
            ));
        }
        self.out = decompressed;
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

impl Folder {
    pub(crate) fn new<R: Read + Seek>(
        reader: &mut R,
        first_data_offset: u32,
        num_data_blocks: u16,
        compression_type: CompressionType,
        max_buffer: u64,
    ) -> io::Result<Folder> {
        let mut decompressor = compression_type.into_decompressor()?;
        let mut decompressed_data = Vec::new();

        if num_data_blocks == 0 {
            return Ok(Folder { decompressed_data });
        }

        reader.seek(SeekFrom::Start(first_data_offset as u64))?;

        for _ in 0..num_data_blocks {
            let _checksum = reader.read_u32::<LittleEndian>()?;
            let compressed_size = reader.read_u16::<LittleEndian>()? as usize;
            let uncompressed_size = reader.read_u16::<LittleEndian>()? as usize;
            let mut compressed_data = vec![0u8; compressed_size];
            reader.read_exact(&mut compressed_data)?;
            let decompressed = decompressor.decompress(compressed_data, uncompressed_size)?;
            decompressed_data.extend_from_slice(&decompressed);
            // Bound the decompressed folder by the global peak-buffer limit: a
            // CFDATA run can amplify far beyond the compressed input.
            if decompressed_data.len() as u64 > max_buffer {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "cab folder exceeds max-buffer",
                ));
            }
        }

        Ok(Folder { decompressed_data })
    }

    pub(crate) fn decompressed_data(&self) -> &[u8] {
        &self.decompressed_data
    }
}
