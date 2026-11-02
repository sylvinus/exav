//! All IO functionality needed for TIFF decoding
use std::io::{self, BufRead, BufReader, Read, Seek, Take};

/// Byte order of the TIFF file.
#[derive(Clone, Copy, Debug)]
pub enum ByteOrder {
    /// little endian byte order
    LittleEndian,
    /// big endian byte order
    BigEndian,
}

/// Reader that is aware of the byte order.
#[derive(Debug)]
pub struct EndianReader<R> {
    reader: R,
    pub(crate) byte_order: ByteOrder,
}

impl<R: Read> EndianReader<R> {
    pub fn new(reader: R, byte_order: ByteOrder) -> Self {
        Self { reader, byte_order }
    }

    pub fn inner(&mut self) -> &mut R {
        &mut self.reader
    }

    pub fn goto_offset(&mut self, offset: u64) -> io::Result<()>
    where
        R: Seek,
    {
        self.reader.seek(io::SeekFrom::Start(offset))?;
        Ok(())
    }

    /// Reads an u16
    #[inline(always)]
    pub fn read_u16(&mut self) -> Result<u16, io::Error> {
        let mut n = [0u8; 2];
        self.reader.read_exact(&mut n)?;
        Ok(match self.byte_order {
            ByteOrder::LittleEndian => u16::from_le_bytes(n),
            ByteOrder::BigEndian => u16::from_be_bytes(n),
        })
    }

    /// Reads an i8
    #[inline(always)]
    pub fn read_i8(&mut self) -> Result<i8, io::Error> {
        let mut n = [0u8; 1];
        self.reader.read_exact(&mut n)?;
        Ok(match self.byte_order {
            ByteOrder::LittleEndian => i8::from_le_bytes(n),
            ByteOrder::BigEndian => i8::from_be_bytes(n),
        })
    }

    /// Reads an i16
    #[inline(always)]
    pub fn read_i16(&mut self) -> Result<i16, io::Error> {
        let mut n = [0u8; 2];
        self.reader.read_exact(&mut n)?;
        Ok(match self.byte_order {
            ByteOrder::LittleEndian => i16::from_le_bytes(n),
            ByteOrder::BigEndian => i16::from_be_bytes(n),
        })
    }

    /// Reads an u32
    #[inline(always)]
    pub fn read_u32(&mut self) -> Result<u32, io::Error> {
        let mut n = [0u8; 4];
        self.reader.read_exact(&mut n)?;
        Ok(match self.byte_order {
            ByteOrder::LittleEndian => u32::from_le_bytes(n),
            ByteOrder::BigEndian => u32::from_be_bytes(n),
        })
    }

    /// Reads an i32
    #[inline(always)]
    pub fn read_i32(&mut self) -> Result<i32, io::Error> {
        let mut n = [0u8; 4];
        self.reader.read_exact(&mut n)?;
        Ok(match self.byte_order {
            ByteOrder::LittleEndian => i32::from_le_bytes(n),
            ByteOrder::BigEndian => i32::from_be_bytes(n),
        })
    }

    /// Reads an u64
    #[inline(always)]
    pub fn read_u64(&mut self) -> Result<u64, io::Error> {
        let mut n = [0u8; 8];
        self.reader.read_exact(&mut n)?;
        Ok(match self.byte_order {
            ByteOrder::LittleEndian => u64::from_le_bytes(n),
            ByteOrder::BigEndian => u64::from_be_bytes(n),
        })
    }

    /// Reads an i64
    #[inline(always)]
    pub fn read_i64(&mut self) -> Result<i64, io::Error> {
        let mut n = [0u8; 8];
        self.reader.read_exact(&mut n)?;
        Ok(match self.byte_order {
            ByteOrder::LittleEndian => i64::from_le_bytes(n),
            ByteOrder::BigEndian => i64::from_be_bytes(n),
        })
    }

    /// Reads an f32
    #[inline(always)]
    pub fn read_f32(&mut self) -> Result<f32, io::Error> {
        let mut n = [0u8; 4];
        self.reader.read_exact(&mut n)?;
        Ok(f32::from_bits(match self.byte_order {
            ByteOrder::LittleEndian => u32::from_le_bytes(n),
            ByteOrder::BigEndian => u32::from_be_bytes(n),
        }))
    }

    /// Reads an f64
    #[inline(always)]
    pub fn read_f64(&mut self) -> Result<f64, io::Error> {
        let mut n = [0u8; 8];
        self.reader.read_exact(&mut n)?;
        Ok(f64::from_bits(match self.byte_order {
            ByteOrder::LittleEndian => u64::from_le_bytes(n),
            ByteOrder::BigEndian => u64::from_be_bytes(n),
        }))
    }
}

//
// # READERS
//

/// Type alias for the deflate Reader
#[cfg(true)]
pub type DeflateReader<R> = flate2::read::ZlibDecoder<R>;

/// exav: YCbCr stored with the chroma sampled `h` by `v` times less often than
/// the luma, as TIFF 6.0 lays it out: in units of `h` by `v` pixels, each its
/// `h * v` luma values (row by row) then one Cb and one Cr, the units in raster
/// order. The unit rows are read and given back as `width` pixels of
/// Y, Cb, Cr to a row, `rows` of them, the chroma repeated over its unit.
pub struct YcbcrUnits<R: Read> {
    inner: R,
    width: usize,
    rows: usize,
    h: usize,
    v: usize,
    pixels: Vec<u8>,
    at: usize,
    given: usize,
}

impl<R: Read> YcbcrUnits<R> {
    pub fn new(inner: R, width: usize, rows: usize, h: usize, v: usize) -> Self {
        Self {
            inner,
            width,
            rows,
            h,
            v,
            pixels: Vec::new(),
            at: 0,
            given: 0,
        }
    }
}

impl<R: Read> Read for YcbcrUnits<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.at == self.pixels.len() {
            if self.given >= self.rows {
                return Ok(0);
            }
            let unit = self.h * self.v + 2;
            let mut raw = vec![0u8; self.width.div_ceil(self.h) * unit];
            self.inner.read_exact(&mut raw)?;
            self.pixels.clear();
            self.at = 0;
            for r in 0..self.v {
                for x in 0..self.width {
                    let u = &raw[x / self.h * unit..][..unit];
                    self.pixels
                        .extend_from_slice(&[u[r * self.h + x % self.h], u[unit - 2], u[unit - 1]]);
                }
            }
            self.given += self.v;
        }
        let n = buf.len().min(self.pixels.len() - self.at);
        buf[..n].copy_from_slice(&self.pixels[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

/// exav: a zlib stream read for the viewer, which does not check the Adler-32
/// of what it has decoded: libtiff's readers go on past a wrong one, and some
/// writers got it wrong (OpenCV's `multipage.tif`). A stream that does not
/// start as zlib does is left to the zlib reader.
#[cfg(true)]
pub fn lenient_zlib<'r, R: Read + 'r>(mut reader: R) -> io::Result<Box<dyn Read + 'r>> {
    let mut head = [0u8; 2];
    reader.read_exact(&mut head)?;
    let check = u16::from_be_bytes(head);
    // Deflate, a window of 32 KiB at most, no preset dictionary, a valid check.
    if head[0] & 0x0f == 8 && head[0] >> 4 <= 7 && head[1] & 0x20 == 0 && check % 31 == 0 {
        Ok(Box::new(flate2::read::DeflateDecoder::new(reader)))
    } else {
        Ok(Box::new(DeflateReader::new(io::Cursor::new(head).chain(reader))))
    }
}

/// exav: the LZMA2 data of an `.xz` stream with one block, as libtiff writes
/// `LZMA` (34925) strips: `lzma_stream_encoder` with the LZMA2 filter and, by
/// default, no check. Only the stream header and the block header are read;
/// the data run to LZMA2's own end marker. `window` bounds the dictionary
/// that is allocated: no more than the strip decodes to is ever looked back
/// on. For the viewer's reader only.
pub fn xz_lzma2<'r, R: Read + 'r>(mut reader: R, window: u32) -> io::Result<Box<dyn Read + 'r>> {
    let bad = |what| io::Error::new(io::ErrorKind::InvalidData, what);
    let mut head = [0u8; 13];
    reader.read_exact(&mut head)?;
    if head[..6] != [0xFD, b'7', b'z', b'X', b'Z', 0] || head[12] == 0 {
        return Err(bad("lzma: not an xz stream"));
    }
    // The block header: its size, its flags, optional sizes, then the filters.
    let mut block = vec![0u8; usize::from(head[12]) * 4 + 3];
    reader.read_exact(&mut block)?;
    let flags = block[0];
    let mut at = 1;
    for bit in [0x40, 0x80] {
        if flags & bit != 0 {
            while *block.get(at).ok_or_else(|| bad("lzma: bad block header"))? & 0x80 != 0 {
                at += 1;
            }
            at += 1;
        }
    }
    // The filters: LZMA2 (0x21) with one byte of properties, behind a delta
    // filter (0x03, one byte: the distance less one) that libtiff puts in for a
    // horizontal predictor.
    let mut delta = None;
    let mut dict = None;
    for i in 0..=(flags & 3) {
        let Some(&[id, 1, p]) = block.get(at..at + 3).and_then(|b| <&[u8; 3]>::try_from(b).ok())
        else {
            return Err(bad("lzma: unknown filter"));
        };
        at += 3;
        match (id, i == flags & 3) {
            (0x03, false) if delta.is_none() => delta = Some(usize::from(p) + 1),
            (0x21, true) if p <= 40 => dict = Some(u64::from(2 | (p & 1)) << (p / 2 + 11)),
            _ => return Err(bad("lzma: unknown filter")),
        }
    }
    let dict = dict.ok_or_else(|| bad("lzma: no LZMA2 filter"))?.min(u64::from(window)) as u32;
    let lzma = Lzma2Reader::new(reader, dict);
    Ok(match delta {
        Some(distance) => Box::new(DeltaReader::new(lzma, distance)),
        None => Box::new(lzma),
    })
}

/// exav: the xz delta filter undone: each byte is a difference from the one
/// `distance` bytes before it.
pub struct DeltaReader<R: Read> {
    inner: R,
    history: Vec<u8>,
    at: usize,
}

impl<R: Read> DeltaReader<R> {
    fn new(inner: R, distance: usize) -> Self {
        Self {
            inner,
            history: vec![0; distance],
            at: 0,
        }
    }
}

impl<R: Read> Read for DeltaReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        for b in &mut buf[..n] {
            *b = b.wrapping_add(self.history[self.at]);
            self.history[self.at] = *b;
            self.at = (self.at + 1) % self.history.len();
        }
        Ok(n)
    }
}

/// exav: raw LZMA2 data, for the viewer's reader only.
pub struct Lzma2Reader<R: Read> {
    inner: R,
    stream: lzma_rust2::Lzma2Stream,
    input: Box<[u8]>,
    start: usize,
    end: usize,
    ended: bool,
    done: bool,
}

impl<R: Read> Lzma2Reader<R> {
    /// `dict` is the window the decoder keeps: no more than the strip decodes to
    /// is ever looked back on.
    pub fn new(inner: R, dict: u32) -> Self {
        Self {
            inner,
            stream: lzma_rust2::Lzma2Stream::new(dict.max(4096)),
            input: vec![0; 4096].into_boxed_slice(),
            start: 0,
            end: 0,
            ended: false,
            done: false,
        }
    }
}

impl<R: Read> Read for Lzma2Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use lzma_rust2::{Action, Status};
        if buf.is_empty() || self.done {
            return Ok(0);
        }
        loop {
            if self.start == self.end && !self.ended {
                self.start = 0;
                self.end = self.inner.read(&mut self.input)?;
                self.ended = self.end == 0;
            }
            let action = if self.ended {
                Action::Finish
            } else {
                Action::Run
            };
            let r = self
                .stream
                .process(&self.input[self.start..self.end], buf, action)?;
            self.start += r.bytes_consumed;
            if r.status == Status::StreamEnd {
                self.done = true;
                return Ok(r.bytes_produced);
            }
            if r.bytes_produced > 0 {
                return Ok(r.bytes_produced);
            }
            if self.ended {
                // Cut short: what was decoded is all there is.
                self.done = true;
                return Ok(0);
            }
            if r.bytes_consumed == 0 && self.start < self.end {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "lzma: decoder made no progress",
                ));
            }
        }
    }
}

/// exav: ThunderScan (`ThunderScan`, 32809), 4-bit samples as runs, deltas and
/// raw values, for the viewer's reader only. `rows` rows of `width` pixels, each
/// padded to a byte; a row the data ends in, and the rows after it, keep the
/// pixels decoded and are black. libtiff's `tif_thunder.c` is the reference.
pub fn thunder_scan(data: &[u8], width: usize, rows: usize) -> Vec<u8> {
    const TWO_BIT: [i32; 4] = [0, 1, 0, -1];
    const THREE_BIT: [i32; 8] = [0, 1, 2, 3, 0, -3, -2, -1];
    let stride = width.div_ceil(2);
    let mut out = vec![0u8; stride.saturating_mul(rows)];
    let mut input = data.iter();
    for row in out.chunks_exact_mut(stride.max(1)) {
        let mut put = |at: usize, v: u32| {
            row[at / 2] |= if at % 2 == 0 { (v as u8) << 4 } else { v as u8 };
        };
        let (mut pixels, mut last) = (0usize, 0u32);
        while pixels < width {
            let Some(&n) = input.next() else {
                return out;
            };
            let n = u32::from(n);
            match n & 0xC0 {
                0x00 => {
                    for _ in 0..(n & 0x3F).min((width - pixels) as u32) {
                        put(pixels, last);
                        pixels += 1;
                    }
                }
                0x40 => {
                    for (shift, skip) in [(4, 2), (2, 2), (0, 2)] {
                        let code = ((n >> shift) & 3) as usize;
                        if code != skip && pixels < width {
                            last = (last as i32 + TWO_BIT[code]) as u32 & 0xF;
                            put(pixels, last);
                            pixels += 1;
                        }
                    }
                }
                0x80 => {
                    for shift in [3, 0] {
                        let code = ((n >> shift) & 7) as usize;
                        if code != 4 && pixels < width {
                            last = (last as i32 + THREE_BIT[code]) as u32 & 0xF;
                            put(pixels, last);
                            pixels += 1;
                        }
                    }
                }
                _ => {
                    last = n & 0xF;
                    put(pixels, last);
                    pixels += 1;
                }
            }
        }
    }
    out
}

//
// ## LZW Reader
//

/// Reader that decompresses LZW streams
#[cfg(true)]
pub struct LZWReader<R: Read> {
    reader: BufReader<Take<R>>,
    decoder: weezl::decode::Decoder,
    // exav: in the viewer's reader, output is decoded a block at a time and
    // handed out from there. A caller asking for a few bytes at a time (a tile
    // row, then its padding) can make `weezl` end a valid stream short.
    block: Option<(Vec<u8>, usize, usize)>,
    // exav: whether the start of the stream was looked at for the old-style
    // LZW that libtiff reads (only done in the viewer's reader).
    probed: bool,
}

#[cfg(true)]
impl<R: Read> LZWReader<R> {
    /// Wraps a reader
    pub fn new(reader: R, compressed_length: usize) -> LZWReader<R> {
        let configuration =
            weezl::decode::Configuration::with_tiff_size_switch(weezl::BitOrder::Msb, 8)
                .with_yield_on_full_buffer(true);
        Self {
            reader: BufReader::with_capacity(
                (32 * 1024).min(compressed_length),
                reader.take(u64::try_from(compressed_length).unwrap()),
            ),
            decoder: configuration.build(),
            block: super::viewer_codecs().then(|| (vec![0; 64 * 1024], 0, 0)),
            probed: !super::viewer_codecs(),
        }
    }
}

#[cfg(true)]
impl<R: Read> Read for LZWReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.probed {
            self.probed = true;
            // Old-style LZW (TIFF 5.0) starts 0x00 and an odd byte: its codes
            // are least significant bit first and grow a code late, as in GIF.
            let head = self.reader.fill_buf()?;
            if head.len() >= 2 && head[0] == 0 && head[1] & 1 == 1 {
                self.decoder = weezl::decode::Configuration::new(weezl::BitOrder::Lsb, 8)
                    .with_yield_on_full_buffer(true)
                    .build();
            }
        }
        let Some((mut block, mut at, mut end)) = self.block.take() else {
            return self.decode_into(buf);
        };
        if at == end {
            let n = self.decode_into(&mut block);
            (at, end) = (0, *n.as_ref().unwrap_or(&0));
            if let Err(e) = n {
                self.block = Some((block, at, end));
                return Err(e);
            }
        }
        let n = buf.len().min(end - at);
        buf[..n].copy_from_slice(&block[at..at + n]);
        self.block = Some((block, at + n, end));
        Ok(n)
    }
}

#[cfg(true)]
impl<R: Read> LZWReader<R> {
    fn decode_into(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let result = self.decoder.decode_bytes(self.reader.fill_buf()?, buf);
            self.reader.consume(result.consumed_in);

            match result.status {
                Ok(weezl::LzwStatus::Ok) => {
                    if result.consumed_out == 0 {
                        continue;
                    } else {
                        return Ok(result.consumed_out);
                    }
                }
                Ok(weezl::LzwStatus::NoProgress) => {
                    // exav: weezl can give the last bytes of output and
                    // say `NoProgress` in the same call, when the input is all
                    // taken and the end code is still to be read; and it can
                    // take the last input bytes and give nothing. Neither is a
                    // panic: the first is data, the second asks again, and the
                    // call after it gives the error below.
                    if result.consumed_out > 0 {
                        return Ok(result.consumed_out);
                    }
                    if result.consumed_in > 0 {
                        continue;
                    }
                    assert!(self.reader.buffer().is_empty());
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "no lzw end code found",
                    ));
                }
                Ok(weezl::LzwStatus::Done) => {
                    return Ok(result.consumed_out);
                }
                Err(err) => return Err(io::Error::new(io::ErrorKind::InvalidData, err)),
            }
        }
    }
}

//
// ## PackBits Reader
//

/// Internal state machine for the PackBitsReader.
enum PackBitsReaderState {
    Header,
    Literal,
    Repeat { value: u8 },
}

/// Reader that unpacks Apple's `PackBits` format
pub struct PackBitsReader<R: Read> {
    reader: Take<R>,
    state: PackBitsReaderState,
    count: usize,
}

impl<R: Read> PackBitsReader<R> {
    /// Wraps a reader
    pub fn new(reader: R, length: u64) -> Self {
        Self {
            reader: reader.take(length),
            state: PackBitsReaderState::Header,
            count: 0,
        }
    }
}

impl<R: Read> Read for PackBitsReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while let PackBitsReaderState::Header = self.state {
            if self.reader.limit() == 0 {
                return Ok(0);
            }
            let mut header: [u8; 1] = [0];
            self.reader.read_exact(&mut header)?;
            let h = header[0] as i8;
            if (-127..=-1).contains(&h) {
                let mut data: [u8; 1] = [0];
                self.reader.read_exact(&mut data)?;
                self.state = PackBitsReaderState::Repeat { value: data[0] };
                self.count = (1 - h as isize) as usize;
            } else if h >= 0 {
                self.state = PackBitsReaderState::Literal;
                self.count = h as usize + 1;
            } else {
                // h = -128 is a no-op.
            }
        }

        let length = buf.len().min(self.count);
        let actual = match self.state {
            PackBitsReaderState::Literal => self.reader.read(&mut buf[..length])?,
            PackBitsReaderState::Repeat { value } => {
                for b in &mut buf[..length] {
                    *b = value;
                }

                length
            }
            PackBitsReaderState::Header => unreachable!(),
        };

        self.count -= actual;
        if self.count == 0 {
            self.state = PackBitsReaderState::Header;
        }
        Ok(actual)
    }
}

#[cfg(true)]
pub struct Group4Reader<R: Read> {
    decoder: fax34::decoder::Group4Decoder<io::Bytes<io::BufReader<io::Take<R>>>>,
    line_buf: io::Cursor<Vec<u8>>,
    height: u16,
    width: u16,
    y: u16,
}

#[cfg(true)]
impl<R: Read> Group4Reader<R> {
    pub fn new(
        dimensions: (u32, u32),
        reader: R,
        compressed_length: u64,
    ) -> crate::image_codecs::tiff::TiffResult<Self> {
        let width = u16::try_from(dimensions.0)?;
        let height = u16::try_from(dimensions.1)?;

        Ok(Self {
            decoder: fax34::decoder::Group4Decoder::new(
                io::BufReader::new(reader.take(compressed_length)).bytes(),
                width,
            )?,
            line_buf: io::Cursor::new(Vec::with_capacity(width.into())),
            width,
            height,
            y: 0,
        })
    }
}

#[cfg(true)]
impl<R: Read> Read for Group4Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Either we have not read any line or we are at the end of a line.
        if self.line_buf.position() as usize == self.line_buf.get_ref().len()
            && self.y < self.height
        {
            let next = self.decoder.advance().map_err(std::io::Error::other)?;

            match next {
                fax34::decoder::DecodeStatus::End => (),
                fax34::decoder::DecodeStatus::Incomplete => {
                    self.y += 1;

                    // We known `transitions` yields exactly `self.width` items (per doc).
                    // FIXME: performance. We do not need an individual pixel iterator, filling
                    // memory especially for long runs can be much quicker. The `transitions` are
                    // the positions at which each run-length ends, i.e. the prefix sum of run
                    // lengths. Runs in fax4 start with white.
                    let transitions = fax34::decoder::pels(self.decoder.transition(), self.width);

                    let buffer = self.line_buf.get_mut();
                    buffer.resize(usize::from(self.width).div_ceil(8), 0u8);

                    let target = &mut buffer[..];

                    // Note: it may seem strange to treat black as 0b1 and white as 0b0 despite all
                    // our streams by default decoding as-if PhotometricInterpretation::BlackIsMin.
                    // This is however consistent with libtiff. It seems that fax4's "White"
                    // differs from what libtiff thinks of as "White". For content, a line of data
                    // is in runlength encoding of white-black-white-black always starting with
                    // white. In libtiff, the loop always does both colors in one go and the
                    // structure is:
                    //
                    // ```
                    // for (; runs < erun; runs += 2)
                    //   // white run
                    //       do { *lp++ = 0L; } while (…)
                    //   // black run
                    //       do { *lp++ = -1L; } while (…)
                    // ```
                    //
                    // So indeed the Fax4::White run is implemented by filling with zeros.
                    let mut bits = transitions.map(|c| match c {
                        fax34::Color::Black => true,
                        fax34::Color::White => false,
                    });

                    // Assemble bits in MSB as per our library representation for buffer.
                    for byte in target {
                        let mut val = 0;

                        for (idx, bit) in bits.by_ref().take(8).enumerate() {
                            val |= u8::from(bit) << (7 - idx % 8);
                        }

                        *byte = val;
                    }

                    self.line_buf.set_position(0);
                }
            }
        }

        self.line_buf.read(buf)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_packbits() {
        let encoded = vec![
            0xFE, 0xAA, 0x02, 0x80, 0x00, 0x2A, 0xFD, 0xAA, 0x03, 0x80, 0x00, 0x2A, 0x22, 0xF7,
            0xAA,
        ];
        let encoded_len = encoded.len();

        let buff = io::Cursor::new(encoded);
        let mut decoder = PackBitsReader::new(buff, encoded_len as u64);

        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).unwrap();

        let expected = vec![
            0xAA, 0xAA, 0xAA, 0x80, 0x00, 0x2A, 0xAA, 0xAA, 0xAA, 0xAA, 0x80, 0x00, 0x2A, 0x22,
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        ];
        assert_eq!(decoded, expected);
    }
}
