//! Deflate decoding that keeps what it decoded before an error, and tells a
//! failed checksum from damaged data.
//!
//! flate2's `Read` decoders drop the output of the call that fails, which can
//! be a whole read buffer of content sitting right before the damage.

// Each format uses a part of this module; see `cap_prealloc` for why the
// feature lists are not spelled out.
#![allow(dead_code)]

use std::io::{self, BufRead, Read};

use flate2::{Crc, Decompress, FlushDecompress, Status};

use crate::checksum_mismatch;

/// Raw deflate over a buffered source.
pub(crate) struct Inflate<R> {
    src: R,
    state: Decompress,
    /// Decoded bytes not yet handed over, and how many of them were.
    out: Vec<u8>,
    given: usize,
    /// Why decoding stopped, once the bytes decoded before it are handed over.
    broken: Option<String>,
    ended: bool,
}

/// Room for a whole deflate window per call. miniz_oxide decodes into its
/// 32 KiB window and, on failure, copies out only what the caller's buffer
/// holds; every later call fails at once, so the rest would be lost.
const OUT: usize = 64 * 1024;

impl<R: BufRead> Inflate<R> {
    pub(crate) fn new(src: R) -> Self {
        Self {
            src,
            state: Decompress::new(false),
            out: Vec::new(),
            given: 0,
            broken: None,
            ended: false,
        }
    }

    /// The source, positioned right after the deflate data once it has ended.
    fn source(&mut self) -> &mut R {
        &mut self.src
    }

    /// Start over on a new deflate stream from the current source position.
    fn restart(&mut self) {
        self.state.reset(false);
        self.out.clear();
        self.given = 0;
        self.ended = false;
    }
}

impl<R: BufRead> Inflate<R> {
    /// Decode the next run of output into `self.out`. `Ok(false)` once the
    /// stream has ended.
    fn fill(&mut self) -> io::Result<bool> {
        if let Some(why) = &self.broken {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, why.clone()));
        }
        if self.ended {
            return Ok(false);
        }
        self.out.resize(OUT, 0);
        loop {
            let input = self.src.fill_buf()?;
            let eof = input.is_empty();
            let (in0, out0) = (self.state.total_in(), self.state.total_out());
            let flush = if eof {
                FlushDecompress::Finish
            } else {
                FlushDecompress::None
            };
            let res = self.state.decompress(input, &mut self.out, flush);
            let used = (self.state.total_in() - in0) as usize;
            let made = (self.state.total_out() - out0) as usize;
            self.src.consume(used);
            self.out.truncate(made);
            self.given = 0;
            match res {
                Ok(Status::StreamEnd) => {
                    self.ended = true;
                    return Ok(made > 0);
                }
                Ok(_) if made > 0 => return Ok(true),
                Ok(_) if eof => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "deflate stream ends before its last block",
                    ))
                }
                Ok(_) => self.out.resize(OUT, 0),
                Err(e) => {
                    let why = format!("corrupt deflate stream: {e}");
                    self.broken = Some(why.clone());
                    if made > 0 {
                        return Ok(true);
                    }
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, why));
                }
            }
        }
    }
}

impl<R: BufRead> Read for Inflate<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.given == self.out.len() && !self.fill()? {
            return Ok(0);
        }
        let n = buf.len().min(self.out.len() - self.given);
        buf[..n].copy_from_slice(&self.out[self.given..self.given + n]);
        self.given += n;
        Ok(n)
    }
}

/// The deflate data of a zlib stream (RFC 1950), or `None` when its header is
/// not one. The trailing Adler-32 is not checked: a mismatch after a full
/// decode hides nothing.
pub(crate) fn zlib_body(data: &[u8]) -> Option<Inflate<&[u8]>> {
    zlib_reader(data).ok().flatten()
}

/// [`zlib_body`] over a reader: the error is the reader's, `UnexpectedEof`
/// when the input ends inside the 2-byte header.
pub(crate) fn zlib_reader<R: BufRead>(mut src: R) -> io::Result<Option<Inflate<R>>> {
    let mut h = [0u8; 2];
    src.read_exact(&mut h)?;
    let [cmf, flg] = h;
    let deflate = cmf & 0x0f == 8 && cmf >> 4 <= 7;
    let preset_dictionary = flg & 0x20 != 0;
    let check = (u16::from(cmf) << 8 | u16::from(flg)) % 31 == 0;
    Ok((deflate && check && !preset_dictionary).then(|| Inflate::new(src)))
}

/// A gzip file (RFC 1952), every member in turn, with each trailer checked
/// here so a CRC-32 or size mismatch after a full decode is reported as a
/// checksum mismatch rather than as damage. It is reported once every member
/// has been decoded, so one bad trailer does not cost the members after it.
/// Bytes after the last member that do not start another one are ignored, as
/// `gzip -d` does.
pub(crate) struct Gunzip<R> {
    body: Inflate<R>,
    crc: Crc,
    state: GzState,
    members: u32,
    bad_trailer: bool,
}

#[derive(Clone, Copy, PartialEq)]
enum GzState {
    Header,
    Body,
    Done,
}

impl<R: BufRead> Gunzip<R> {
    pub(crate) fn new(src: R) -> Self {
        Self {
            body: Inflate::new(src),
            crc: Crc::new(),
            state: GzState::Header,
            members: 0,
            bad_trailer: false,
        }
    }

    /// Read a member header. `false` when the source holds no further member.
    fn header(&mut self) -> io::Result<bool> {
        let first = self.members == 0;
        let src = self.body.source();
        for magic in [0x1f, 0x8b] {
            let next = src.fill_buf()?.first().copied();
            match next {
                Some(b) if b == magic => src.consume(1),
                _ if !first => return Ok(false),
                None => return Err(io::ErrorKind::UnexpectedEof.into()),
                Some(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "not a gzip stream",
                    ))
                }
            }
        }
        let mut fixed = [0u8; 8];
        src.read_exact(&mut fixed)?;
        let [method, flags, ..] = fixed;
        if method != 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("gzip member uses compression method {method}"),
            ));
        }
        if flags & 0x04 != 0 {
            let mut len = [0u8; 2];
            src.read_exact(&mut len)?;
            skip(src, u16::from_le_bytes(len).into())?;
        }
        for field in [0x08, 0x10] {
            if flags & field != 0 {
                skip_string(src)?;
            }
        }
        if flags & 0x02 != 0 {
            skip(src, 2)?;
        }
        Ok(true)
    }

    fn trailer(&mut self) -> io::Result<()> {
        let mut t = [0u8; 8];
        self.body.source().read_exact(&mut t)?;
        let crc = u32::from_le_bytes([t[0], t[1], t[2], t[3]]);
        let size = u32::from_le_bytes([t[4], t[5], t[6], t[7]]);
        if crc != self.crc.sum() || size != self.crc.amount() {
            self.bad_trailer = true;
        }
        Ok(())
    }
}

impl<R: BufRead> Read for Gunzip<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            match self.state {
                GzState::Done => return Ok(0),
                GzState::Header => {
                    if self.header()? {
                        self.body.restart();
                        self.crc.reset();
                        self.members += 1;
                        self.state = GzState::Body;
                    } else {
                        self.state = GzState::Done;
                        if self.bad_trailer {
                            return Err(checksum_mismatch("gzip CRC-32 or size"));
                        }
                    }
                }
                GzState::Body => {
                    let n = self.body.read(buf)?;
                    if n > 0 {
                        self.crc.update(&buf[..n]);
                        return Ok(n);
                    }
                    // `Inflate` returns 0 only once its stream has ended.
                    self.trailer()?;
                    self.state = GzState::Header;
                }
            }
        }
    }
}

/// Wraps a member's decoded bytes, which must have CRC-32 `expected`; a
/// mismatch at the end is a checksum mismatch.
pub(crate) struct CrcCheck<R> {
    inner: R,
    crc: Crc,
    expected: u32,
    reported: bool,
}

impl<R: Read> CrcCheck<R> {
    pub(crate) fn new(inner: R, expected: u32) -> Self {
        Self {
            inner,
            crc: Crc::new(),
            expected,
            reported: false,
        }
    }
}

impl<R: Read> Read for CrcCheck<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n == 0 && !buf.is_empty() && !self.reported && self.crc.sum() != self.expected {
            self.reported = true;
            return Err(checksum_mismatch("zip CRC-32"));
        }
        self.crc.update(&buf[..n]);
        Ok(n)
    }
}

fn skip<R: BufRead>(src: &mut R, n: u64) -> io::Result<()> {
    if io::copy(&mut src.take(n), &mut io::sink())? < n {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(())
}

/// Skip a NUL-terminated header field without holding it.
fn skip_string<R: BufRead>(src: &mut R) -> io::Result<()> {
    loop {
        let buf = src.fill_buf()?;
        if buf.is_empty() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        match buf.iter().position(|&b| b == 0) {
            Some(i) => {
                src.consume(i + 1);
                return Ok(());
            }
            None => {
                let n = buf.len();
                src.consume(n);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn deflate_broken_after(prefix: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(prefix).unwrap();
        e.flush().unwrap();
        let mut raw = e.get_ref().clone();
        raw.push(0x06);
        raw.extend_from_slice(&[0x5a; 64]);
        raw
    }

    fn gzip(payload: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(payload).unwrap();
        e.finish().unwrap()
    }

    fn read_all(mut r: impl Read) -> (Vec<u8>, Option<io::Error>) {
        let mut out = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            match r.read(&mut chunk) {
                Ok(0) => return (out, None),
                Ok(n) => out.extend_from_slice(&chunk[..n]),
                Err(e) => return (out, Some(e)),
            }
        }
    }

    /// Everything decoded before the damage is handed over, then the error.
    #[test]
    fn the_bytes_before_the_damage_are_kept() {
        let prefix: Vec<u8> = (0..20_000u32).flat_map(|i| i.to_le_bytes()).collect();
        let (out, err) = read_all(Inflate::new(&deflate_broken_after(&prefix)[..]));
        assert_eq!(out, prefix);
        assert!(crate::decode_error_hides_content(&err.unwrap()));
    }

    #[test]
    fn a_truncated_stream_is_not_damage() {
        let full = gzip(&[7u8; 50_000]);
        let (_, err) = read_all(Gunzip::new(&full[..full.len() / 2]));
        assert!(!crate::decode_error_hides_content(&err.unwrap()));
    }

    /// Every member is decoded before a bad trailer is reported, and the
    /// report is a checksum mismatch.
    #[test]
    fn a_bad_trailer_costs_no_member() {
        let mut first = gzip(b"first ");
        let n = first.len();
        first[n - 8] ^= 1;
        let mut file = first;
        file.extend(gzip(b"second"));
        file.extend_from_slice(&[0; 32]);
        let (out, err) = read_all(Gunzip::new(&file[..]));
        assert_eq!(out, b"first second");
        assert!(!crate::decode_error_hides_content(&err.unwrap()));

        let (out, err) = read_all(Gunzip::new(&gzip(b"intact")[..]));
        assert_eq!(out, b"intact");
        assert!(err.is_none());
    }

    #[test]
    fn header_fields_are_skipped() {
        let mut e = flate2::GzBuilder::new()
            .filename("name.txt")
            .comment("a comment")
            .extra(vec![1, 2, 3])
            .write(Vec::new(), flate2::Compression::default());
        e.write_all(b"payload").unwrap();
        let (out, err) = read_all(Gunzip::new(&e.finish().unwrap()[..]));
        assert_eq!(out, b"payload");
        assert!(err.is_none());
    }

    #[test]
    fn a_zlib_body_decodes_without_its_checksum() {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(b"zlib payload").unwrap();
        let mut z = e.finish().unwrap();
        let n = z.len();
        z[n - 1] ^= 1;
        let (out, err) = read_all(zlib_body(&z).unwrap());
        assert_eq!(out, b"zlib payload");
        assert!(err.is_none());
        assert!(zlib_body(b"not zlib").is_none());
    }
}
