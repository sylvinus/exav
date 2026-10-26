//! xz streams whose integrity check `xz4rust` does not read, decoded without it.
//!
//! The format has sixteen check types: none, CRC32, CRC64 and SHA-256 are
//! defined, and the rest reserved. The decoder reads none, CRC32 and CRC64 and
//! refuses the others, but liblzma and the `xz` tool decode a stream with a
//! check they do not support and warn that its integrity is unchecked. A scanner
//! should look at the data either way, so a stream with such a check is
//! rewritten as it is read: the same blocks with no check fields, an index
//! without the check sizes in its records, and a header and footer saying "no
//! check". The data are not touched.
//!
//! Only a stream that opens with an unsupported check is rewritten, and the
//! streams after it that do the same. A stream with a check the decoder reads
//! passes through byte for byte, as the rest of the input after it does.

use std::io::{self, Read};

const MAGIC: [u8; 6] = [0xFD, b'7', b'z', b'X', b'Z', 0];
/// The largest index read: a record is a few bytes.
const MAX_INDEX: usize = 64 << 20;

/// Bytes of the check field for a check type (xz file format, 2.1.1.2).
fn check_size(id: u8) -> usize {
    if id == 0 {
        0
    } else {
        4 << ((id - 1) / 3)
    }
}

/// Whether `xz4rust` reads the check.
fn supported(id: u8) -> bool {
    matches!(id, 0 | 1 | 4)
}

fn bad(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("xz: {what}"))
}

/// A variable-length integer, as xz codes sizes: 7 bits a byte, low first.
fn vli_bytes(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    while v >= 0x80 {
        out.push(v as u8 | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
    out
}

/// The VLI at the start of `b`, and the bytes it takes.
fn vli_at(b: &[u8]) -> Option<(u64, usize)> {
    let mut v = 0u64;
    for (i, &byte) in b.iter().take(9).enumerate() {
        v |= u64::from(byte & 0x7F) << (7 * i);
        if byte & 0x80 == 0 {
            return Some((v, i + 1));
        }
    }
    None
}

enum Mode {
    /// Nothing read yet, or between streams.
    Header,
    /// Handing the input on unchanged.
    Pass,
    /// In a stream being rewritten: at the start of a block or the index.
    Block,
    /// In the LZMA2 data of a block, at the start of a chunk.
    Chunks {
        header: u64,
        data: u64,
    },
    /// After a block's data, `header + data` bytes into it.
    Tail {
        header: u64,
        data: u64,
    },
    /// In a block whose compressed size its header gives, `left` bytes to go.
    Sized {
        left: u64,
        header: u64,
        data: u64,
    },
    Done,
}

pub(crate) struct NoCheck<R> {
    inner: R,
    mode: Mode,
    /// Bytes of check field to leave out of each block.
    strip: usize,
    out: Vec<u8>,
    at: usize,
}

impl<R: Read> NoCheck<R> {
    pub(crate) fn new(inner: R) -> Self {
        NoCheck {
            inner,
            mode: Mode::Header,
            strip: 0,
            out: Vec::new(),
            at: 0,
        }
    }

    /// Up to `n` bytes of the input; fewer at its end.
    fn take(&mut self, n: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; n];
        let mut got = 0;
        while got < n {
            match self.inner.read(&mut buf[got..]) {
                Ok(0) => break,
                Ok(k) => got += k,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        buf.truncate(got);
        Ok(buf)
    }

    /// Hands on what `take` got of `n` bytes; `None` and the end of the input
    /// when it got fewer.
    fn copy(&mut self, n: usize) -> io::Result<Option<()>> {
        let b = self.take(n)?;
        let whole = b.len() == n;
        self.out.extend_from_slice(&b);
        if !whole {
            self.mode = Mode::Done;
        }
        Ok(whole.then_some(()))
    }

    /// A VLI read from the input, byte by byte, and its bytes.
    fn read_vli(&mut self) -> io::Result<(u64, Vec<u8>)> {
        let mut raw = Vec::new();
        loop {
            let b = self.take(1)?;
            let Some(&byte) = b.first() else {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "xz: index cut short",
                ));
            };
            raw.push(byte);
            if byte & 0x80 == 0 || raw.len() == 9 {
                break;
            }
        }
        vli_at(&raw)
            .map(|(v, _)| (v, raw))
            .ok_or_else(|| bad("bad index number"))
    }

    /// The 12 bytes that open a stream, `first` of them already read.
    fn start(&mut self, mut header: Vec<u8>) -> io::Result<()> {
        header.extend(self.take(12 - header.len())?);
        let id = header.get(7).map(|b| b & 0x0F);
        match id {
            Some(id)
                if header.len() == 12
                    && header[..6] == MAGIC
                    && header[6] == 0
                    && header[7] >> 4 == 0
                    && !supported(id) =>
            {
                self.strip = check_size(id);
                self.out.extend_from_slice(&MAGIC);
                self.out.extend_from_slice(&[0, 0]);
                self.out
                    .extend_from_slice(&crc32fast::hash(&[0, 0]).to_le_bytes());
                self.mode = Mode::Block;
            }
            _ => {
                self.out.extend_from_slice(&header);
                self.mode = Mode::Pass;
            }
        }
        Ok(())
    }

    /// One piece of the stream, rewritten into `out`.
    fn step(&mut self) -> io::Result<()> {
        match std::mem::replace(&mut self.mode, Mode::Done) {
            Mode::Header => {
                let first = self.take(4)?;
                if first.is_empty() {
                    return Ok(());
                }
                // Zero padding between streams goes on as it is.
                if first == [0; 4] {
                    self.out.extend_from_slice(&first);
                    self.mode = Mode::Header;
                    return Ok(());
                }
                self.start(first)
            }
            Mode::Block => {
                let b = self.take(1)?;
                match b.first() {
                    None => Ok(()),
                    Some(0) => self.index(),
                    Some(&size) => self.block_header(size),
                }
            }
            Mode::Sized { left, header, data } => {
                let n = left.min(64 << 10) as usize;
                if self.copy(n)?.is_some() {
                    self.mode = if left > n as u64 {
                        Mode::Sized {
                            left: left - n as u64,
                            header,
                            data,
                        }
                    } else {
                        Mode::Tail { header, data }
                    };
                }
                Ok(())
            }
            Mode::Chunks { header, data } => self.chunk(header, data),
            Mode::Tail { header, data } => {
                let pad = (4 - (header + data) % 4) % 4;
                if self.copy(pad as usize)?.is_some() {
                    // The check field is left out.
                    let skipped = self.take(self.strip)?;
                    self.mode = if skipped.len() == self.strip {
                        Mode::Block
                    } else {
                        Mode::Done
                    };
                }
                Ok(())
            }
            Mode::Pass | Mode::Done => Ok(()),
        }
    }

    /// A block header of `(size + 1) * 4` bytes, `size` being its first byte.
    fn block_header(&mut self, size: u8) -> io::Result<()> {
        let len = (usize::from(size) + 1) * 4;
        let rest = self.take(len - 1)?;
        self.out.push(size);
        self.out.extend_from_slice(&rest);
        if rest.len() < len - 1 {
            return Ok(());
        }
        let flags = rest[0];
        // The compressed size, when the header says it; the uncompressed size
        // follows it and is not needed.
        let compressed = if flags & 0x40 != 0 {
            Some(vli_at(&rest[1..]).ok_or_else(|| bad("bad block header"))?.0)
        } else {
            None
        };
        let header = len as u64;
        self.mode = match compressed {
            Some(left) => Mode::Sized {
                left,
                header,
                data: left,
            },
            None => Mode::Chunks { header, data: 0 },
        };
        Ok(())
    }

    /// One chunk of LZMA2 data: a control byte, its sizes, its bytes.
    fn chunk(&mut self, header: u64, data: u64) -> io::Result<()> {
        let Some(&control) = self.take(1)?.first() else {
            return Ok(());
        };
        self.out.push(control);
        let (fields, props) = match control {
            0 => {
                self.mode = Mode::Tail {
                    header,
                    data: data + 1,
                };
                return Ok(());
            }
            1 | 2 => (2, 0),
            0x80..=0xFF => (4, usize::from(control >= 0xC0)),
            _ => return Err(bad("bad LZMA2 chunk")),
        };
        let sizes = self.take(fields + props)?;
        self.out.extend_from_slice(&sizes);
        if sizes.len() < fields + props {
            return Ok(());
        }
        let packed = if control < 3 {
            usize::from(u16::from_be_bytes([sizes[0], sizes[1]])) + 1
        } else {
            usize::from(u16::from_be_bytes([sizes[2], sizes[3]])) + 1
        };
        let total = 1 + (fields + props) as u64 + packed as u64;
        if self.copy(packed)?.is_some() {
            self.mode = Mode::Chunks {
                header,
                data: data + total,
            };
        }
        Ok(())
    }

    /// The index and the footer, rewritten for a stream with no check fields.
    fn index(&mut self) -> io::Result<()> {
        let (count, count_raw) = self.read_vli()?;
        let mut taken = 1 + count_raw.len();
        let mut index = vec![0u8];
        index.extend_from_slice(&vli_bytes(count));
        for _ in 0..count {
            let (unpadded, a) = self.read_vli()?;
            let (uncompressed, b) = self.read_vli()?;
            taken += a.len() + b.len();
            let unpadded = unpadded
                .checked_sub(self.strip as u64)
                .filter(|&n| n > 0)
                .ok_or_else(|| bad("bad index record"))?;
            index.extend_from_slice(&vli_bytes(unpadded));
            index.extend_from_slice(&vli_bytes(uncompressed));
            if taken > MAX_INDEX {
                return Err(bad("index too large"));
            }
        }
        // The padding and the CRC-32 of the input's index: ours are made anew.
        let padding = (4 - taken % 4) % 4;
        if self.take(padding + 4)?.len() < padding + 4 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "xz: index cut short",
            ));
        }
        index.resize(index.len().next_multiple_of(4), 0);
        let crc = crc32fast::hash(&index);
        let backward = ((index.len() + 4) / 4 - 1) as u32;
        let footer = self.take(12)?;
        if footer.len() < 12 || footer[10..] != *b"YZ" {
            return Err(bad("bad stream footer"));
        }
        self.out.extend_from_slice(&index);
        self.out.extend_from_slice(&crc.to_le_bytes());
        let mut tail = backward.to_le_bytes().to_vec();
        tail.extend_from_slice(&[0, 0]);
        self.out
            .extend_from_slice(&crc32fast::hash(&tail).to_le_bytes());
        self.out.extend_from_slice(&tail);
        self.out.extend_from_slice(b"YZ");
        self.mode = Mode::Header;
        Ok(())
    }
}

impl<R: Read> Read for NoCheck<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.at < self.out.len() {
                let n = (self.out.len() - self.at).min(buf.len());
                buf[..n].copy_from_slice(&self.out[self.at..self.at + n]);
                self.at += n;
                return Ok(n);
            }
            self.out.clear();
            self.at = 0;
            match self.mode {
                Mode::Pass => return self.inner.read(buf),
                Mode::Done => return Ok(0),
                _ => self.step()?,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whatever the bytes, reading ends: with data or an error, never a panic
    /// or a loop. Streams with a byte changed, or cut.
    #[test]
    fn damaged_streams_end() {
        let seeds = [
            &include_bytes!("../../tests/fixtures/xz_checks/reserved_12.xz")[..],
            &include_bytes!("../../tests/fixtures/xz_checks/sha256.xz")[..],
        ];
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for seed in seeds {
            for _ in 0..3000 {
                let mut blob = seed.to_vec();
                for _ in 0..1 + next() % 3 {
                    let at = next() as usize % blob.len();
                    blob[at] = next() as u8;
                }
                blob.truncate(1 + next() as usize % blob.len());
                let mut out = Vec::new();
                let _ = NoCheck::new(&blob[..]).read_to_end(&mut out);
            }
        }
    }
}
