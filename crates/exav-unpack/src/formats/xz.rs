use crate::*;

pub(crate) fn extract_xz<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    budget.count_entry()?;
    let cap = budget.reserve()?;
    let (out, truncated) = decode_xz(data, cap)?;
    if truncated {
        return Err(LimitHit::new("xz member exceeds budget".to_string()));
    }
    ratio_guard(data.len() as u64, out.len() as u64, budget)?;
    budget.commit(out.len() as u64);
    Ok(visit(Entry::new("xz-content".to_string(), out), budget))
}

/// The dictionary size exav is willing to allocate for an XZ stream. Matches the
/// decoder's own allocation cap below — one number, not two that can drift.
pub const XZ_MAX_DICT: u64 = 64 * 1024 * 1024;

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
/// Concatenated streams need no special handling here — the decoder resets at
/// each end-of-stream and carries on, so multi-stream files stream like any
/// other. (bzip2 cannot do this: recovering from a spurious stream magic needs
/// re-reading the whole input, which a reader that has already emitted bytes
/// cannot do.)
pub(crate) fn content_reader(data: &[u8]) -> XzReader<'_> {
    XzReader {
        data,
        input_pos: 0,
        decoder: xz4rust::XzDecoder::with_alloc_dict_size(8192, XZ_MAX_DICT as usize),
        staged: Vec::new(),
        taken: 0,
        done: false,
    }
}

pub(crate) struct XzReader<'a> {
    data: &'a [u8],
    input_pos: usize,
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

impl std::io::Read for XzReader<'_> {
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
            let mut buf = [0u8; 8192];
            let feed = self.data[self.input_pos..].len().min(buf.len());
            if feed == 0 {
                self.done = true;
                return Ok(0);
            }
            match self
                .decoder
                .decode(&self.data[self.input_pos..self.input_pos + feed], &mut buf)
            {
                Ok(result) => {
                    self.staged
                        .extend_from_slice(&buf[..result.output_produced()]);
                    self.input_pos += result.input_consumed();
                    if let xz4rust::XzNextBlockResult::EndOfStream(_, _) = result {
                        self.decoder.reset();
                        // Concatenated streams may be separated by zero padding.
                        while self.input_pos < self.data.len() && self.data[self.input_pos] == 0 {
                            self.input_pos += 1;
                        }
                        if self.input_pos >= self.data.len() {
                            self.done = true;
                        }
                    }
                }
                Err(xz4rust::XzError::NeedsLargerInputBuffer) => {
                    self.input_pos += feed;
                }
                // A malformed stream is corruption, not a limit. Surfacing it as
                // an io error lets the caller report Unscannable without killing
                // the enclosing container's sibling members.
                Err(e) => return Err(std::io::Error::other(format!("xz: {e}"))),
            }
        }
    }
}

/// Decode all concatenated XZ streams using xz4rust's block-based API
/// (pure Rust, no unsafe, zero runtime deps with no_unsafe + no sha256). Shared
/// with the ZIP path (method 95 = XZ) via [`super::zip`].
pub(crate) fn decode_xz(data: &[u8], cap: u64) -> Result<(Vec<u8>, bool), LimitHit> {
    let mut decoder = xz4rust::XzDecoder::with_alloc_dict_size(8192, XZ_MAX_DICT as usize);
    let mut out = Vec::new();
    let mut input_pos = 0;
    let mut out_buf = [0u8; 8192];

    loop {
        let remaining = cap.saturating_sub(out.len() as u64);
        if remaining == 0 {
            return Ok((out, true));
        }

        let feed = data[input_pos..].len().min(out_buf.len());
        if feed == 0 {
            break;
        }

        match decoder.decode(&data[input_pos..input_pos + feed], &mut out_buf) {
            Ok(result) => {
                let produced = result.output_produced();
                if produced > 0 {
                    out.extend_from_slice(&out_buf[..produced]);
                    // Check budget after each output chunk (catches bombs).
                    if out.len() as u64 > cap {
                        return Ok((out, true));
                    }
                }
                input_pos += result.input_consumed();
                if let xz4rust::XzNextBlockResult::EndOfStream(_, _) = result {
                    decoder.reset();
                    // Skip padding zeros between concatenated streams
                    while input_pos < data.len() && data[input_pos] == 0 {
                        input_pos += 1;
                    }
                    if input_pos >= data.len() {
                        break;
                    }
                }
            }
            Err(xz4rust::XzError::NeedsLargerInputBuffer) => {
                input_pos += feed;
            }
            Err(e) => {
                // A malformed/undecodable xz stream is a *corruption*, not a
                // resource limit. Marking it `corrupt` makes it an Unscannable
                // signal that does NOT abort the enclosing container: a bad `.xz`
                // member inside a tar must not stop the sibling members (which may
                // carry the actual detection) from being scanned.
                return Err(LimitHit::corrupt(format!("xz: {e}")));
            }
        }
    }
    Ok((out, false))
}
