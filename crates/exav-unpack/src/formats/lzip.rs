//! lzip: one member, every lzip member of the file decoded in turn as it is
//! read.
//!
//! Members are framed here, from the lzip manual: a 6-byte header (`LZIP`,
//! version 1, the coded dictionary size), an LZMA stream ended by its end
//! marker (`lzma_rust2`'s decoder), and a 20-byte trailer: the CRC-32 and
//! size of the member's data, and the member's own size. A trailer that
//! disagrees with what its member decoded to is a checksum mismatch, reported
//! once every member has been decoded, so it does not cost the members after
//! it.
use std::io::{self, Read};

use lzma_rust2::LzmaStream;

use super::lzma::SansIo;
use crate::source::{ByteSource, Reader};
use crate::stream::{stream_single, Visit};
use crate::{Budget, LimitHit};

const HEADER: usize = 6;
const TRAILER: usize = 20;

pub(crate) fn walk<T>(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<T>,
) -> Result<Option<T>, LimitHit> {
    let mut source = Reader::new(src);
    stream_single(&mut source, budget, visit, "lzip-content", |_| {
        Ok(Box::new(Members::new(src)) as Box<dyn Read + '_>)
    })
}

/// The dictionary size a header's last byte codes: bits 4-0 the base 2
/// logarithm of a base size, bits 7-5 how many sixteenths of it to take off.
fn dict_size(b: u8) -> Option<u32> {
    let log = u32::from(b & 0x1F);
    if !(12..=29).contains(&log) {
        return None;
    }
    let base = 1u32 << log;
    let size = base - base / 16 * u32::from(b >> 5);
    (size >= 1 << 12).then_some(size)
}

/// The decoded data of every member of an lzip file, in turn.
struct Members<'a> {
    src: &'a dyn ByteSource,
    /// Where the current or next member starts.
    at: usize,
    member: Option<SansIo<Reader<'a>, LzmaStream>>,
    crc: crc32fast::Hasher,
    size: u64,
    members: usize,
    bad_trailer: bool,
    done: bool,
}

impl<'a> Members<'a> {
    fn new(src: &'a dyn ByteSource) -> Self {
        Members {
            src,
            at: 0,
            member: None,
            crc: crc32fast::Hasher::new(),
            size: 0,
            members: 0,
            bad_trailer: false,
            done: false,
        }
    }

    /// Up to `n` bytes at `at`, fewer where the object ends. Read through a
    /// [`Reader`], so a source that fails says so.
    fn bytes_at(&self, at: usize, n: usize) -> io::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(n);
        Reader::range(self.src, at, at.saturating_add(n)).read_to_end(&mut out)?;
        Ok(out)
    }

    /// Start the member at `at`. `false` when there is none: what follows
    /// the last member is not one, and is ignored, as `lzip -d` does.
    fn start(&mut self) -> io::Result<bool> {
        let h = self.bytes_at(self.at, HEADER)?;
        let dict = if h.len() == HEADER && h.starts_with(b"LZIP\x01") {
            dict_size(h[5])
        } else {
            None
        };
        let Some(dict) = dict else {
            if self.members == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "lzip: not an lzip member",
                ));
            }
            return Ok(false);
        };
        let body = Reader::range(self.src, self.at + HEADER, self.src.len());
        // lzip fixes lc 3, lp 0, pb 2, and its streams end with a marker.
        let lzma = LzmaStream::new(u64::MAX, 3, 0, 2, dict, None)?;
        self.member = Some(SansIo::new(body, lzma));
        self.crc = crc32fast::Hasher::new();
        self.size = 0;
        Ok(true)
    }

    /// Check the trailer of the member whose stream just ended, and move to
    /// what follows it.
    fn finish(&mut self, member: SansIo<Reader<'a>, LzmaStream>) -> io::Result<()> {
        let s = member.stream();
        let used = s.total_in() - s.unused_input().len() as u64;
        let end = usize::try_from(used)
            .ok()
            .and_then(|n| (self.at + HEADER).checked_add(n))
            .unwrap_or(usize::MAX);
        let t = self.bytes_at(end, TRAILER)?;
        if t.len() < TRAILER {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "lzip: member trailer cut short",
            ));
        }
        let le = |at: usize| u64::from_le_bytes(t[at..at + 8].try_into().unwrap());
        let crc = u32::from_le_bytes([t[0], t[1], t[2], t[3]]);
        let decoded = std::mem::take(&mut self.crc).finalize();
        let member_size = (end + TRAILER - self.at) as u64;
        self.bad_trailer |= crc != decoded || le(4) != self.size || le(12) != member_size;
        self.members += 1;
        self.at = end + TRAILER;
        Ok(())
    }
}

impl Read for Members<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.done {
                return Ok(0);
            }
            let Some(member) = self.member.as_mut() else {
                match self.start() {
                    Ok(true) => continue,
                    Ok(false) => {
                        self.done = true;
                        if self.bad_trailer {
                            return Err(crate::checksum_mismatch("lzip CRC-32 or size"));
                        }
                        return Ok(0);
                    }
                    Err(e) => {
                        self.done = true;
                        return Err(e);
                    }
                }
            };
            match member.read(buf) {
                Ok(0) => {
                    if let Some(m) = self.member.take() {
                        if let Err(e) = self.finish(m) {
                            self.done = true;
                            return Err(e);
                        }
                    }
                }
                Ok(n) => {
                    self.crc.update(&buf[..n]);
                    self.size += n as u64;
                    return Ok(n);
                }
                Err(e) => {
                    self.done = true;
                    return Err(e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::dict_size;

    /// 0xD3 is the lzip manual's example, 2^19 - 6 * 2^15 = 320 KiB; sizes
    /// run from 4 KiB to 512 MiB.
    #[test]
    fn dictionary_sizes_decode_as_the_manual_gives_them() {
        assert_eq!(dict_size(0xD3), Some(320 << 10));
        assert_eq!(dict_size(0x0C), Some(4 << 10));
        assert_eq!(dict_size(0x1D), Some(512 << 20));
        assert_eq!(dict_size(0x2C), None);
        assert_eq!(dict_size(0x0B), None);
        assert_eq!(dict_size(0x1E), None);
    }
}
