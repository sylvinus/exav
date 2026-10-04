//! 7z codec dispatch: wraps existing decoders (lzma-rust2, bzip2-rs, flate2,
//! our own ppmd7) into a `Box<dyn Read>` pipeline.

use super::header::Coder;
use super::parse::*;
use crate::formats::lzma::SansIo;
use crate::LimitHit;
use lzma_rust2::filter::bcj::BcjReader;
use std::io::{self, Read};

/// Return true if `id` is a codec we can decode.
pub(super) fn is_known_codec(id: &[u8]) -> bool {
    id == ID_COPY
        || id == ID_LZMA
        || id == ID_LZMA2
        || id == ID_PPMD
        || id == ID_BZIP2
        || id == ID_DEFLATE
        || id == ID_BCJ_X86
        || id == ID_BCJ2
        || id == ID_BCJ_ARM
        || id == ID_BCJ_ARM64
        || id == ID_DELTA
}

/// Wrap a coder around an existing reader, returning a new boxed reader.
/// `password` is the passphrase to try for an AES-encrypted coder (ignored by
/// every other codec); `None` (or a build without the `decrypt` feature) leaves
/// AES reported as unsupported.
pub(super) fn wrap_coder(
    inner: Box<dyn Read>,
    coder: &Coder,
    expected_size: usize,
    password: Option<&str>,
    max_buffer: u64,
) -> Result<Box<dyn Read>, LimitHit> {
    let _ = password;
    match coder.method_id.as_slice() {
        x if x == ID_COPY => Ok(inner),

        #[cfg(feature = "decrypt")]
        x if x == ID_AES => {
            let reader = super::aes::Aes7zReader::new(inner, &coder.properties, password)?;
            Ok(Box::new(reader))
        }

        x if x == ID_LZMA => {
            if coder.properties.is_empty() {
                return Err(LimitHit::corrupt("7z: LZMA properties too short".into()));
            }
            let props = coder.properties[0];
            let dict_size = if coder.properties.len() >= 5 {
                u32::from_le_bytes([
                    coder.properties[1],
                    coder.properties[2],
                    coder.properties[3],
                    coder.properties[4],
                ])
            } else {
                // `props` is an attacker byte; `1u32 << props` panics (shift
                // overflow) for any `props >= 32`. This fallback (properties < 5
                // bytes) is a corrupt-input path anyway, so clamp the shift to a
                // valid dictionary width rather than panic.
                if props < 200 {
                    1u32 << props.min(31)
                } else {
                    1u32 << 11
                }
            };
            // Bound the up-front dictionary allocation. `expected_size` is a
            // header var-int and nothing else bounds it, so it is no ceiling on
            // its own; `max_buffer` is. Keep the declared output as the tighter
            // of the two: a dictionary larger than the bytes it will be used to
            // look back into cannot be consulted.
            let dict_size = crate::bounded_dict(dict_size, (expected_size as u64).min(max_buffer));
            let lzma = lzma_rust2::LzmaStream::new_with_props(
                expected_size as u64,
                props,
                dict_size,
                None,
            )
            .map_err(|e| LimitHit::corrupt(format!("7z: LZMA init: {e}")))?;
            Ok(Box::new(SansIo::new(inner, lzma)))
        }

        x if x == ID_LZMA2 => {
            if coder.properties.is_empty() {
                return Err(LimitHit::corrupt("7z: LZMA2 properties too short".into()));
            }
            let dict_size_bits = coder.properties[0] as u32;
            let dict_size = if dict_size_bits == 40 {
                0xFFFFFFFF
            } else if dict_size_bits > 40 {
                return Err(LimitHit::corrupt("7z: LZMA2 dict too large".into()));
            } else {
                (2 | (dict_size_bits & 1)) << (dict_size_bits / 2 + 11)
            };
            let lzma2 = lzma_rust2::Lzma2Stream::new(dict_size);
            Ok(Box::new(SansIo::new(inner, lzma2)))
        }

        x if x == ID_PPMD => {
            if coder.properties.len() < 5 {
                return Err(LimitHit::corrupt("7z: PPMD properties too short".into()));
            }
            let order = coder.properties[0] as u32;
            let mem_size = u32::from_le_bytes([
                coder.properties[1],
                coder.properties[2],
                coder.properties[3],
                coder.properties[4],
            ]);

            let ppmd_reader =
                Ppmd7ZReader::new(inner, order, mem_size, expected_size as u64, max_buffer)?;
            Ok(Box::new(ppmd_reader))
        }

        x if x == ID_BZIP2 => {
            let decoder = crate::formats::bzip2_rs::DecoderReader::new(inner);
            Ok(Box::new(decoder))
        }

        x if x == ID_DEFLATE => {
            let decoder = crate::inflate::Inflate::new(std::io::BufReader::new(inner));
            Ok(Box::new(decoder))
        }

        x if x == ID_BCJ_X86 => Ok(Box::new(BcjReader::new_x86(inner, 0))),
        x if x == ID_BCJ_ARM => Ok(Box::new(BcjReader::new_arm(inner, 0))),
        x if x == ID_BCJ_ARM64 => Ok(Box::new(BcjReader::new_arm64(inner, 0))),

        x if x == ID_DELTA => {
            let distance = if coder.properties.is_empty() {
                1
            } else {
                (coder.properties[0] as usize) + 1
            };
            let filter = DeltaFilter::new(inner, distance);
            Ok(Box::new(filter))
        }

        other => Err(LimitHit::corrupt(format!(
            "7z: unsupported codec {:02x?}",
            other
        ))),
    }
}

// ─── Our own PPMd7 reader for 7z ───────────────────────────────────────────

/// A 7z PPMd coder's output, `size` bytes, decoded as it is read.
///
/// The packed input is read whole on the first `read`, bounded by
/// `max_buffer`. A stream that runs out, that goes inconsistent, or that meets
/// an end marker before `size` bytes is an `InvalidData` error after the bytes
/// decoded before it.
pub(crate) struct Ppmd7ZReader<R: Read> {
    inner: Option<R>,
    order: u32,
    mem_size: u32,
    model: Option<crate::formats::ppmd7::Ppmd7<crate::formats::ppmd7::SevenZRangeDecoder>>,
    remaining: u64,
    max_buffer: u64,
    /// An error met after some bytes of a `read` were already decoded,
    /// returned by the next `read`.
    pending: Option<&'static str>,
    done: bool,
}

impl<R: Read> Ppmd7ZReader<R> {
    pub(crate) fn new(
        inner: R,
        order: u32,
        mem_size: u32,
        size: u64,
        max_buffer: u64,
    ) -> Result<Self, LimitHit> {
        if !(2..=64).contains(&order) {
            return Err(LimitHit::corrupt(format!(
                "7z: PPMD order {order} out of range [2, 64]"
            )));
        }
        if mem_size < 2048 {
            return Err(LimitHit::corrupt(format!(
                "7z: PPMD memory size {mem_size} too small"
            )));
        }
        // The model arena is `mem_size` bytes and the field is a full u32, so a
        // tiny archive can otherwise ask for ~4 GiB before decoding anything.
        // The allocation is fallible, so this is not a crash, but the caller's
        // buffer cap is what says how much memory this scan may claim, and the
        // model has to answer to it like everything else. The ZIP method-98
        // reader refuses the same way.
        if u64::from(mem_size) > max_buffer {
            return Err(LimitHit::new(format!(
                "7z: PPMD model memory {mem_size} exceeds max-buffer {max_buffer}"
            )));
        }

        Ok(Self {
            inner: Some(inner),
            order,
            mem_size,
            model: None,
            remaining: size,
            max_buffer,
            pending: None,
            done: false,
        })
    }

    fn init(
        &mut self,
        inner: R,
    ) -> Result<crate::formats::ppmd7::Ppmd7<crate::formats::ppmd7::SevenZRangeDecoder>, LimitHit>
    {
        use crate::formats::ppmd7::{Ppmd7, SevenZRangeDecoder};
        let (buf, truncated) = crate::bounded_read(inner, self.max_buffer)
            .map_err(|e| LimitHit::corrupt(format!("7z: PPMD read: {e}")))?;
        if truncated {
            return Err(LimitHit::new("7z PPMD input exceeds max-buffer".into()));
        }
        let rc = SevenZRangeDecoder::new(buf);
        if !rc.init_ok() {
            return Err(LimitHit::corrupt(
                "7z: PPMD range decoder init failed".into(),
            ));
        }
        Ppmd7::new(rc, self.order, self.mem_size)
            .ok_or_else(|| LimitHit::corrupt("7z: PPMD model init failed".into()))
    }
}

impl<R: Read> Read for Ppmd7ZReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use crate::formats::ppmd7::SYM_END;
        if let Some(reason) = self.pending.take() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, reason));
        }
        if buf.is_empty() || self.remaining == 0 || self.done {
            return Ok(0);
        }
        if let Some(inner) = self.inner.take() {
            match self.init(inner) {
                Ok(model) => self.model = Some(model),
                Err(e) => {
                    self.done = true;
                    return Err(io::Error::new(io::ErrorKind::InvalidData, e));
                }
            }
        }
        let Some(model) = self.model.as_mut() else {
            return Ok(0);
        };

        let want = usize::try_from(self.remaining).map_or(buf.len(), |r| r.min(buf.len()));
        let mut n = 0;
        let mut error = None;
        while n < want {
            let sym = model.decode_symbol();
            // A symbol decoded while the input ran out was decoded from
            // padding, not from the stream.
            if model.out_of_data() {
                error = Some("7z: PPMD stream truncated");
                break;
            }
            if sym == SYM_END {
                error = Some("7z: PPMD stream ended before its declared size");
                break;
            }
            if sym < 0 {
                error = Some("7z: PPMD stream is corrupt");
                break;
            }
            buf[n] = sym as u8;
            n += 1;
        }
        self.remaining -= n as u64;
        if self.remaining == 0 {
            self.model = None;
        }
        let Some(reason) = error else {
            return Ok(n);
        };
        self.model = None;
        self.done = true;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, reason));
        }
        self.pending = Some(reason);
        Ok(n)
    }
}

// ─── Delta filter ──────────────────────────────────────────────────────────

struct DeltaFilter<R: Read> {
    inner: R,
    distance: usize,
    history: Vec<u8>,
    pos: usize,
}

impl<R: Read> DeltaFilter<R> {
    fn new(inner: R, distance: usize) -> Self {
        Self {
            inner,
            distance,
            history: vec![0u8; distance],
            pos: 0,
        }
    }
}

impl<R: Read> Read for DeltaFilter<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        for byte in buf.iter_mut().take(n) {
            let prev = self.history[self.pos % self.distance];
            *byte = byte.wrapping_add(prev);
            self.history[self.pos % self.distance] = *byte;
            self.pos += 1;
        }
        Ok(n)
    }
}

#[cfg(test)]
mod ppmd_tests {
    use super::*;
    use std::io::Write;

    /// `data` through the reference `ppmd-rust` PPMd7 (variant H) encoder.
    fn encode(data: &[u8], order: u32, mem: u32, end_marker: bool) -> Vec<u8> {
        let mut packed = Vec::new();
        let mut enc = ppmd_rust::Ppmd7Encoder::new(&mut packed, order, mem).unwrap();
        enc.write_all(data).unwrap();
        enc.finish(end_marker).unwrap();
        packed
    }

    fn text(n: usize) -> Vec<u8> {
        (0..n as u32)
            .flat_map(|i| format!("{i:06} the quick brown fox {}\n", i * 7919 % 101).into_bytes())
            .take(n)
            .collect()
    }

    /// Reads `size` bytes of `packed` in `chunk`-byte reads: what came out,
    /// and how the read ended.
    fn read(packed: &[u8], size: u64, chunk: usize) -> (Vec<u8>, io::Result<()>) {
        let mut r = Ppmd7ZReader::new(packed, 6, 1 << 20, size, 1 << 24).unwrap();
        let mut out = Vec::new();
        let mut buf = vec![0u8; chunk];
        loop {
            match r.read(&mut buf) {
                Ok(0) => return (out, Ok(())),
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(e) => return (out, Err(e)),
            }
        }
    }

    #[test]
    fn decodes_to_the_declared_size_in_reads_of_any_size() {
        let data = text(50_000);
        for end_marker in [false, true] {
            let packed = encode(&data, 6, 1 << 20, end_marker);
            for chunk in [1, 7, 4096, 1 << 20] {
                let (out, end) = read(&packed, data.len() as u64, chunk);
                assert!(
                    end.is_ok(),
                    "chunk {chunk}, end marker {end_marker}: {end:?}"
                );
                assert!(out == data, "chunk {chunk}, end marker {end_marker}");
            }
            let (out, end) = read(&packed, 1000, 4096);
            assert!(end.is_ok() && out == data[..1000]);
        }
    }

    /// Cut short, the stream yields what it decoded, then an error, read in
    /// any chunk size.
    #[test]
    fn a_stream_cut_short_is_an_error_after_a_correct_prefix() {
        let data = text(50_000);
        let packed = encode(&data, 6, 1 << 20, false);
        for cut in [0, 1, 5, 6, 100, packed.len() / 2, packed.len() - 1] {
            for chunk in [1, 4096] {
                let (out, end) = read(&packed[..cut], data.len() as u64, chunk);
                assert!(end.is_err(), "cut {cut}, chunk {chunk}");
                assert!(
                    out.len() < data.len() && data.starts_with(&out),
                    "cut {cut}, chunk {chunk}: not a prefix"
                );
            }
        }
    }

    #[test]
    fn an_end_marker_before_the_declared_size_is_an_error() {
        let data = text(5000);
        let packed = encode(&data, 6, 1 << 20, true);
        let (out, end) = read(&packed, data.len() as u64 + 1, 4096);
        assert!(end.is_err());
        assert!(out == data, "what came before the end marker is delivered");
    }
}
