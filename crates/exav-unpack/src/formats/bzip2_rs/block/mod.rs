//! bzip2 low-level block APIs

use std::mem;

use tinyvec::ArrayVec;

pub use self::error::BlockError;
use super::bitreader::BitReader;
#[cfg(target_pointer_width = "64")]
use super::bitreader::CachedBitReader;
use super::crc::Hasher;
use super::header::Header;
use super::huffman::HuffmanTree;
use super::move_to_front::MoveToFrontDecoder;

mod bwt;
mod error;

const BLOCK_MAGIC: u64 = 0x314159265359;
const FINAL_MAGIC: u64 = 0x177245385090;
/// NSIS's bzip2 marks a block, and the end of the stream, with one byte each,
/// and carries no checksum and no randomised bit.
const NSIS_BLOCK: u64 = 0x31;
const NSIS_FINAL: u64 = 0x17;

pub(crate) struct Block {
    header: Header,
    nsis: bool,

    tt: Vec<u32>,
    pre_rle_used: u32,
    t_pos: u32,
    last_byte: i16,
    byte_repeats: u8,
    repeats: u8,

    hasher: Hasher,
    expected_crc: u32,
    /// A block decoded in full and failed its CRC. The blocks after it are
    /// still decoded; the mismatch is reported at the end of the stream.
    crc_failed: bool,

    state: State,
}

enum State {
    ReadyForRead,
    Reading,
    NotReady,
}

impl Block {
    pub fn new(header: Header, nsis: bool) -> Self {
        let max_blocksize = header.max_blocksize();

        Self {
            header,
            nsis,

            tt: Vec::with_capacity(max_blocksize as usize),
            pre_rle_used: 0,
            t_pos: 0,
            last_byte: -1,
            byte_repeats: 0,
            repeats: 0,

            hasher: Hasher::new(),
            expected_crc: 0,
            crc_failed: false,

            state: State::NotReady,
        }
    }

    pub fn is_ready_for_read(&self) -> bool {
        match self.state {
            State::ReadyForRead => true,
            State::Reading | State::NotReady => false,
        }
    }

    pub fn is_reading(&self) -> bool {
        match self.state {
            State::Reading => true,
            State::ReadyForRead | State::NotReady => false,
        }
    }

    pub fn is_not_ready(&self) -> bool {
        match self.state {
            State::NotReady => true,
            State::ReadyForRead | State::Reading => false,
        }
    }

    pub fn set_ready_for_read(&mut self) {
        self.state = State::ReadyForRead;
    }

    pub fn read(
        &mut self,
        reader: &mut BitReader<'_>,
        out: &mut [u8],
    ) -> Result<usize, BlockError> {
        match &self.state {
            State::ReadyForRead => {
                let magic = reader
                    .read_u64(if self.nsis { 8 } else { 48 })
                    .ok_or_else(|| BlockError::truncated("next magic truncated"))?;
                match magic {
                    NSIS_BLOCK if self.nsis => {
                        self.read_block(reader)?;
                        self.state = State::Reading;

                        self.read(reader, out)
                    }
                    NSIS_FINAL if self.nsis => {
                        self.state = State::NotReady;
                        Ok(0)
                    }
                    BLOCK_MAGIC if !self.nsis => {
                        self.read_block(reader)?;
                        self.state = State::Reading;

                        self.read(reader, out)
                    }
                    FINAL_MAGIC if !self.nsis => {
                        let _crc = reader
                            .read_u32(32)
                            .ok_or_else(|| BlockError::truncated("whole stream crc truncated"))?;

                        // TODO: check whole stream crc

                        self.state = State::NotReady;
                        // Reported once, so a read after it ends the stream.
                        if std::mem::take(&mut self.crc_failed) {
                            return Err(BlockError::checksum("bad crc"));
                        }
                        Ok(0)
                    }
                    _ => {
                        self.state = State::NotReady;
                        Err(BlockError::new("bad magic value found"))
                    }
                }
            }
            State::Reading => {
                let n = self.read_from_block(out)?;
                if n == 0 && !out.is_empty() {
                    self.state = State::NotReady;
                }

                Ok(n)
            }
            State::NotReady => Err(BlockError::new("not ready")),
        }
    }

    pub fn read_from_block(&mut self, out: &mut [u8]) -> Result<usize, BlockError> {
        let mut read = 0;

        while (self.repeats > 0 || self.pre_rle_used < (self.tt.len() as u32)) && read < out.len() {
            if self.repeats > 0 {
                out[read] = self.last_byte as u8;
                read += 1;

                self.repeats -= 1;
                if self.repeats == 0 {
                    self.last_byte = -1;
                }
                continue;
            }

            self.t_pos = self.tt[self.t_pos as usize];
            let b = self.t_pos as u8;
            self.t_pos >>= 8;
            self.pre_rle_used += 1;

            if self.byte_repeats == 3 {
                self.repeats = b;
                self.byte_repeats = 0;
                continue;
            }

            if self.last_byte == i16::from(b) {
                self.byte_repeats += 1;
            } else {
                self.byte_repeats = 0;
            }
            self.last_byte = i16::from(b);

            out[read] = b;
            read += 1;
        }

        if read == 0 && !out.is_empty() {
            self.state = State::NotReady;

            let crc = self.hasher.finalyze();
            self.crc_failed |= !self.nsis && self.expected_crc != crc;
            return Ok(0);
        }

        self.hasher.update(&out[..read]);
        Ok(read)
    }

    pub fn read_block(&mut self, reader: &mut BitReader<'_>) -> Result<(), BlockError> {
        self.hasher = Hasher::new();
        self.tt.clear();

        if !self.nsis {
            self.expected_crc = reader
                .read_u32(32)
                .ok_or_else(|| BlockError::truncated("crc truncated"))?;

            let randomised = reader
                .read_bool()
                .ok_or_else(|| BlockError::truncated("randomised truncated"))?;
            if randomised {
                return Err(BlockError::new("randomised expected to be 'normal'"));
            }
        }

        let orig_ptr = reader
            .read_u32(24)
            .ok_or_else(|| BlockError::truncated("orig ptr truncated"))?;

        let mut huffman_used_symbols = ArrayVec::<[u8; 16]>::new();
        let mut huffman_used_bitmaps = ArrayVec::<[u8; 256]>::new();

        for i in 0..16 {
            if reader
                .read_bool()
                .ok_or_else(|| BlockError::truncated("symbol range truncated"))?
            {
                huffman_used_symbols.push(i);
            }
        }

        for symbol_range in huffman_used_symbols {
            for symbol in 0..16 {
                if reader
                    .read_bool()
                    .ok_or_else(|| BlockError::truncated("symbol range truncated"))?
                {
                    huffman_used_bitmaps.push(symbol_range * 16 + symbol);
                }
            }
        }

        if huffman_used_bitmaps.is_empty() {
            return Err(BlockError::new("huffman no symbols in input"));
        }

        let huffman_groups = reader
            .read_u8(3)
            .ok_or_else(|| BlockError::truncated("huffmann groups truncated"))?;
        if !(2..=6).contains(&huffman_groups) {
            return Err(BlockError::new("invalid number of huffman trees"));
        }

        let selectors_used = reader
            .read_u16(15)
            .ok_or_else(|| BlockError::truncated("selectors used truncated"))?;

        let mut selectors_list = vec![0u8; usize::from(selectors_used)];

        let mut move_to_front_decoder = MoveToFrontDecoder::new();
        for selector_item in selectors_list.iter_mut().rev() {
            let mut trees = 0;

            while reader
                .read_bool()
                .ok_or_else(|| BlockError::truncated("selector truncated"))?
            {
                trees += 1;

                if trees >= huffman_groups {
                    return Err(BlockError::new("tree index too large"));
                }
            }

            *selector_item = move_to_front_decoder.decode(trees);
        }

        // limited in lenght of huffman_used_symbols
        let mut symbols = [0u8; 256];
        symbols[..huffman_used_bitmaps.len()].copy_from_slice(&huffman_used_bitmaps);
        let mut move_to_front_decoder_2 = MoveToFrontDecoder::new_from_symbols(symbols);

        let mut huffman_trees = ArrayVec::<[HuffmanTree; 6]>::new();

        let mut lengths = ArrayVec::<[u8; super::LEN_258]>::new();
        lengths.set_len(huffman_used_bitmaps.len() + 2);

        for _ in 0..huffman_groups {
            let mut length = reader
                .read_u8(5)
                .ok_or_else(|| BlockError::truncated("huffman group length truncated"))?;

            for length_item in &mut *lengths {
                loop {
                    if !(1..=20).contains(&length) {
                        return Err(BlockError::new("huffman length out of range"));
                    }

                    if !reader
                        .read_bool()
                        .ok_or_else(|| BlockError::truncated("length bit1 truncated"))?
                    {
                        break;
                    }

                    if reader
                        .read_bool()
                        .ok_or_else(|| BlockError::truncated("length bit2 truncated"))?
                    {
                        length -= 1;
                    } else {
                        length += 1;
                    }
                }

                *length_item = length;
            }

            let tree = HuffmanTree::new(&lengths).map_err(BlockError::new)?;
            huffman_trees.push(tree);
        }

        let selector = selectors_list
            .pop()
            .ok_or_else(|| BlockError::new("no tree selectors given"))?;
        let mut current_huffman_tree = huffman_trees
            .get(usize::from(selector))
            .ok_or_else(|| BlockError::new("tree selector out of range"))?;

        let mut repeat = 0u32;
        let mut repeat_power = 0u32;
        let mut c = [0u32; 256];

        let mut decoded = 0;
        #[cfg(target_pointer_width = "64")]
        let mut r = CachedBitReader::new(reader)
            .ok_or_else(|| BlockError::truncated("huffman bitstream truncated"))?;
        loop {
            if decoded == 50 {
                let selector = selectors_list.pop().ok_or_else(|| {
                    BlockError::new("insufficient selector indices for number of symbols")
                })?;

                current_huffman_tree = huffman_trees
                    .get(usize::from(selector))
                    .ok_or_else(|| BlockError::new("tree selector out of range"))?;
                decoded = 0;
            }

            #[cfg(target_pointer_width = "64")]
            let v = {
                let read = r.read();
                let v = current_huffman_tree.decode(&mut r);

                if r.overflowed() {
                    r.restore(reader, read);
                    r.refresh(reader)
                        .ok_or_else(|| BlockError::truncated("huffman bitstream truncated"))?;

                    current_huffman_tree.decode(&mut r)
                } else {
                    v
                }
            };
            #[cfg(not(target_pointer_width = "64"))]
            let v = current_huffman_tree.decode(reader);

            let v = v.ok_or_else(|| BlockError::truncated("huffman bitstream truncated"))?;
            decoded += 1;

            if v < 2 {
                if repeat == 0 {
                    repeat_power = 1;
                }
                repeat += repeat_power << v;
                repeat_power <<= 1;

                if repeat > 2 * 1024 * 1024 {
                    return Err(BlockError::new("repeat count too large"));
                }
                continue;
            }

            let old_repeat = mem::replace(&mut repeat, 0);
            if old_repeat > 0 {
                if old_repeat > self.header.max_blocksize() - (self.tt.len() as u32) {
                    return Err(BlockError::new("repeats past end of block"));
                }

                let b = move_to_front_decoder_2.first();
                // extend self.tt with `b` repeated `old_repeat` times
                let new_len = self.tt.len() + old_repeat as usize;
                self.tt.resize(new_len, u32::from(b));
                c[usize::from(b)] += old_repeat;
            }

            if usize::from(v) == (huffman_used_bitmaps.len() + 2) - 1 {
                break;
            }

            let b = move_to_front_decoder_2.decode((v - 1) as u8);
            if self.tt.len() >= self.header.max_blocksize() as usize {
                return Err(BlockError::new("data exceeds block size"));
            }

            self.tt.push(u32::from(b));
            c[usize::from(b)] += 1;
        }
        #[cfg(target_pointer_width = "64")]
        r.restore(reader, r.read());

        if (orig_ptr as usize) >= self.tt.len() {
            return Err(BlockError::new("orig_ptr out of bounds"));
        }

        self.pre_rle_used = 0;
        self.t_pos = bwt::inverse_bwt(&mut self.tt, orig_ptr as usize, c);
        self.last_byte = -1;
        self.byte_repeats = 0;
        self.repeats = 0;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use super::super::DecoderReader;

    fn roundtrip(data: &[u8], level: u32) {
        let mut enc = ::bzip2::write::BzEncoder::new(Vec::new(), ::bzip2::Compression::new(level));
        enc.write_all(data).unwrap();
        let bz = enc.finish().unwrap();
        let mut out = Vec::new();
        DecoderReader::new(&bz[..])
            .read_to_end(&mut out)
            .unwrap_or_else(|e| panic!("level {level}, {} bytes: {e}", data.len()));
        assert!(
            out == data,
            "level {level}, {} bytes: output differs",
            data.len()
        );
    }

    #[test]
    fn decodes_what_the_reference_encoder_writes() {
        let mut x: u32 = 1;
        let noise: Vec<u8> = (0..230_000)
            .map(|_| {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                (x >> 16) as u8
            })
            .collect();
        let text = b"the quick brown fox jumps over the lazy dog\n".repeat(6000);
        let runs: Vec<u8> = (0..=255u8).flat_map(|b| vec![b; 1000]).collect();
        for level in [1, 5, 9] {
            roundtrip(b"", level);
            roundtrip(b"a", level);
            roundtrip(&text, level);
            roundtrip(&runs, level);
            roundtrip(&noise, level);
        }
    }
}
