use crate::*;

/// The dictionary size exav is willing to allocate for an XZ stream. Matches the
/// decoder's own allocation cap below — one number, not two that can drift.
pub const XZ_MAX_DICT: u64 = 64 * 1024 * 1024;

/// Walk an `.xz` file: one member, every stream decoded in turn as it is read.
pub(crate) fn walk<T>(
    src: &dyn crate::source::ByteSource,
    budget: &mut Budget,
    visit: crate::stream::Visit<T>,
) -> Result<Option<T>, LimitHit> {
    use crate::stream::{emit_stream, single_meta};
    budget.count_entry()?;
    let mut dec = content_reader(src);
    emit_stream(
        &single_meta("xz-content", src, None),
        &mut dec,
        budget,
        visit,
    )
}

/// The dictionary size an XZ stream *declares*, if it can be read from the first
/// block's LZMA2 filter properties.
///
/// This is a bomb signal, not a parse step: the declared size is what a decoder
/// must allocate before a single byte is produced, so an absurd value costs
/// memory whether or not the stream contains anything. ClamAV alerts on it
/// (`Heuristics.XZ.DicSizeLimit`) with no flag to turn it off.
///
/// Returns `None` when the stream is not XZ, is truncated, or uses a filter
/// chain this does not model — never a guess.
pub fn declared_dict_size(data: &[u8]) -> Option<u64> {
    /// `\xFD 7 z X Z \0` then 2 flag bytes and a CRC32.
    const STREAM_HEADER: usize = 12;
    const LZMA2_FILTER_ID: u64 = 0x21;

    if data.len() < STREAM_HEADER + 2 || !data.starts_with(b"\xfd7zXZ\x00") {
        return None;
    }
    let blk = &data[STREAM_HEADER..];
    // A block header size byte of 0 is the index indicator: no blocks at all.
    let hdr_len = (*blk.first()? as usize).checked_mul(4)?;
    if hdr_len == 0 || hdr_len > blk.len() {
        return None;
    }
    let flags = *blk.get(1)?;
    let filter_count = (flags & 0x03) as usize + 1;
    let mut p = 2usize;
    // Optional compressed / uncompressed size fields precede the filter chain.
    if flags & 0x40 != 0 {
        p = skip_varint(blk, p)?;
    }
    if flags & 0x80 != 0 {
        p = skip_varint(blk, p)?;
    }
    for _ in 0..filter_count {
        let (id, np) = read_varint(blk, p)?;
        let (prop_len, np) = read_varint(blk, np)?;
        let prop_len = usize::try_from(prop_len).ok()?;
        let props = blk.get(np..np.checked_add(prop_len)?)?;
        if id == LZMA2_FILTER_ID {
            // One property byte; bits 0..5 encode the dictionary size. 40 is the
            // largest legal value and means 4 GiB.
            let b = u32::from(*props.first()?);
            if b > 40 {
                return None;
            }
            // `(2 | (b & 1)) << (b / 2 + 11)`, exactly as the format defines it.
            // The largest legal property, 40, yields 4 GiB — which needs 64 bits,
            // so the arithmetic is done there rather than clamped to `u32::MAX`
            // (that was off by one byte and made the boundary untestable).
            return Some(u64::from(2 | (b & 1)) << (b / 2 + 11));
        }
        p = np.checked_add(prop_len)?;
    }
    None
}

fn read_varint(d: &[u8], mut p: usize) -> Option<(u64, usize)> {
    let mut v: u64 = 0;
    for i in 0..9 {
        let b = *d.get(p)?;
        p += 1;
        v |= u64::from(b & 0x7f) << (i * 7);
        if b & 0x80 == 0 {
            return Some((v, p));
        }
    }
    None
}

fn skip_varint(d: &[u8], p: usize) -> Option<usize> {
    read_varint(d, p).map(|(_, np)| np)
}

/// A `Read` over the decompressed content of `data`, for the streaming path.
///
/// `xz4rust` exposes a block-based decoder rather than a `Read`, so this pulls
/// blocks on demand and hands out what they produced. That is what lets a `.xz`
/// decompressing to gigabytes be scanned without ever being held: the file on
/// disk is bounded, its output is not.
///
/// Concatenated streams need no special handling here: the decoder resets at
/// each end-of-stream and carries on, so multi-stream files stream like any
/// other.
pub(crate) fn content_reader(
    data: &dyn crate::source::ByteSource,
) -> XzReader<crate::source::Reader<'_>> {
    XzReader::new(crate::source::Reader::new(data))
}

/// Every stream of an `.xz` input read from `input`, decoded as it is read.
pub(crate) struct XzReader<R> {
    input: R,
    inbuf: Vec<u8>,
    in_pos: usize,
    in_len: usize,
    /// The decoder owns its dictionary allocation, so its lifetime is
    /// independent of the input; `'static` keeps it out of the caller's way.
    decoder: xz4rust::XzDecoder<'static>,
    /// Decoded bytes not yet handed to the caller. A single `decode` call can
    /// produce more than the caller asked for, and those bytes cannot be
    /// re-derived, so they wait here.
    staged: Vec<u8>,
    taken: usize,
    done: bool,
}

impl<R: std::io::Read> XzReader<R> {
    pub(crate) fn new(input: R) -> Self {
        XzReader {
            input,
            inbuf: vec![0; 8192],
            in_pos: 0,
            in_len: 0,
            decoder: xz4rust::XzDecoder::with_alloc_dict_size(8192, XZ_MAX_DICT as usize),
            staged: Vec::new(),
            taken: 0,
            done: false,
        }
    }

    /// Refill the input buffer once it is used up. `false` at the end of the
    /// input.
    fn fill(&mut self) -> std::io::Result<bool> {
        if self.in_pos == self.in_len {
            self.in_pos = 0;
            self.in_len = loop {
                match self.input.read(&mut self.inbuf) {
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    r => break r?,
                }
            };
        }
        Ok(self.in_pos < self.in_len)
    }
}

impl<R: std::io::Read> std::io::Read for XzReader<R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.taken < self.staged.len() {
                let n = (self.staged.len() - self.taken).min(out.len());
                out[..n].copy_from_slice(&self.staged[self.taken..self.taken + n]);
                self.taken += n;
                return Ok(n);
            }
            if self.done {
                return Ok(0);
            }
            self.staged.clear();
            self.taken = 0;
            if !self.fill()? {
                self.done = true;
                return Ok(0);
            }
            let mut buf = [0u8; 8192];
            match self
                .decoder
                .decode(&self.inbuf[self.in_pos..self.in_len], &mut buf)
            {
                Ok(result) => {
                    self.staged
                        .extend_from_slice(&buf[..result.output_produced()]);
                    self.in_pos += result.input_consumed();
                    if let xz4rust::XzNextBlockResult::EndOfStream(_, _) = result {
                        self.decoder.reset();
                        // Concatenated streams may be separated by zero padding.
                        loop {
                            if !self.fill()? {
                                self.done = true;
                                break;
                            }
                            if self.inbuf[self.in_pos] != 0 {
                                break;
                            }
                            self.in_pos += 1;
                        }
                    }
                }
                Err(xz4rust::XzError::NeedsLargerInputBuffer) => {
                    self.in_pos = self.in_len;
                }
                // A malformed stream is corruption, not a limit. Surfacing it as
                // an io error lets the caller report Unscannable without killing
                // the enclosing container's sibling members.
                Err(e) => return Err(std::io::Error::other(format!("xz: {e}"))),
            }
        }
    }
}
