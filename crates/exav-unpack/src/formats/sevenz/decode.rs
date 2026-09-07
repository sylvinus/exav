//! 7z codec dispatch: wraps existing decoders (lzma-rust2, bzip2-rs, flate2,
//! our own ppmd7) into a `Box<dyn Read>` pipeline.

use super::header::Coder;
use super::parse::*;
use crate::LimitHit;
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
            // of the two — a dictionary larger than the bytes it will be used to
            // look back into cannot be consulted.
            let dict_size = crate::bounded_dict(dict_size, (expected_size as u64).min(max_buffer));
            let decoder = lzma_rust2::LzmaReader::new_with_props(
                inner,
                expected_size as u64,
                props,
                dict_size,
                None,
            )
            .map_err(|e| LimitHit::corrupt(format!("7z: LZMA init: {e}")))?;
            Ok(Box::new(decoder))
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
            let decoder = lzma_rust2::Lzma2Reader::new(inner, dict_size, None);
            Ok(Box::new(decoder))
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

            let ppmd_reader = Ppmd7ZReader::new(inner, order, mem_size, max_buffer)?;
            Ok(Box::new(ppmd_reader))
        }

        x if x == ID_BZIP2 => {
            let decoder = bzip2_rs::DecoderReader::new(inner);
            Ok(Box::new(decoder))
        }

        x if x == ID_DEFLATE => {
            let decoder = flate2::read::DeflateDecoder::new(std::io::BufReader::new(inner));
            Ok(Box::new(decoder))
        }

        x if x == ID_BCJ_X86 => {
            let filter = BcjX86Filter::new(inner, max_buffer);
            Ok(Box::new(filter))
        }

        x if x == ID_BCJ_ARM => {
            let filter = BcjArmFilter::new(inner, max_buffer);
            Ok(Box::new(filter))
        }

        x if x == ID_BCJ_ARM64 => {
            let filter = BcjArm64Filter::new(inner, max_buffer);
            Ok(Box::new(filter))
        }

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

pub(crate) struct Ppmd7ZReader<R: Read> {
    inner: R,
    buffer: Vec<u8>,
    pos: usize,
    order: u32,
    mem_size: u32,
    initialized: bool,
    decoded_data: Vec<u8>,
    max_buffer: u64,
}

impl<R: Read> Ppmd7ZReader<R> {
    pub(crate) fn new(
        inner: R,
        order: u32,
        mem_size: u32,
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
        // The allocation is fallible, so this is not a crash — but the caller's
        // buffer cap is what says how much memory this scan may claim, and the
        // model has to answer to it like everything else. The ZIP method-98 path
        // clamps for the same reason.
        if u64::from(mem_size) > max_buffer {
            return Err(LimitHit::new(format!(
                "7z: PPMD model memory {mem_size} exceeds max-buffer {max_buffer}"
            )));
        }

        Ok(Self {
            inner,
            buffer: Vec::new(),
            pos: 0,
            order,
            mem_size,
            initialized: false,
            decoded_data: Vec::new(),
            max_buffer,
        })
    }

    fn init_and_decode(&mut self) -> Result<(), LimitHit> {
        // Bound both the compressed input and the decoded output by the global
        // peak-buffer limit — PPMd amplifies heavily.
        let (buf, truncated) = crate::bounded_read(&mut self.inner, self.max_buffer)
            .map_err(|e| LimitHit::corrupt(format!("7z: PPMD read: {e}")))?;
        if truncated {
            return Err(LimitHit::new("7z PPMD input exceeds max-buffer".into()));
        }
        self.buffer = buf;

        use crate::formats::ppmd7::{Ppmd7, SevenZRangeDecoder, SYM_END};

        if self.buffer.is_empty() {
            return Ok(());
        }

        let rc = SevenZRangeDecoder::new(&self.buffer);
        if !rc.init_ok() {
            return Err(LimitHit::corrupt(
                "7z: PPMD range decoder init failed".into(),
            ));
        }

        let mut model = Ppmd7::new(rc, self.order, self.mem_size)
            .ok_or_else(|| LimitHit::corrupt("7z: PPMD model init failed".into()))?;

        let mut out = Vec::new();
        loop {
            let sym = model.decode_symbol();
            if sym < 0 {
                if sym == SYM_END {
                    break;
                }
                return Err(LimitHit::corrupt("7z: PPMD decode error".into()));
            }
            out.push(sym as u8);
            if out.len() as u64 > self.max_buffer {
                return Err(LimitHit::new("7z PPMD output exceeds max-buffer".into()));
            }
        }

        self.decoded_data = out;
        self.initialized = true;
        Ok(())
    }
}

impl<R: Read> Read for Ppmd7ZReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.initialized {
            self.init_and_decode()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        }

        if self.pos >= self.decoded_data.len() {
            return Ok(0);
        }

        let available = &self.decoded_data[self.pos..];
        let to_copy = buf.len().min(available.len());
        buf[..to_copy].copy_from_slice(&available[..to_copy]);
        self.pos += to_copy;
        Ok(to_copy)
    }
}

// ─── BCJ x86 filter ────────────────────────────────────────────────────────

struct BcjX86Filter<R: Read> {
    inner: R,
    buf: Vec<u8>,
    pos: usize,
    max_buffer: u64,
}

impl<R: Read> BcjX86Filter<R> {
    fn new(inner: R, max_buffer: u64) -> Self {
        Self {
            inner,
            buf: Vec::new(),
            pos: 0,
            max_buffer,
        }
    }
}

impl<R: Read> Read for BcjX86Filter<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.buf.len() {
            let (data, truncated) = crate::bounded_read(&mut self.inner, self.max_buffer)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            if truncated {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "7z BCJ input exceeds max-buffer",
                ));
            }
            self.buf = data;
            apply_bcj_x86(&mut self.buf);
            self.pos = 0;
        }

        if self.pos >= self.buf.len() {
            return Ok(0);
        }

        let available = &self.buf[self.pos..];
        let to_copy = buf.len().min(available.len());
        buf[..to_copy].copy_from_slice(&available[..to_copy]);
        self.pos += to_copy;
        Ok(to_copy)
    }
}

fn apply_bcj_x86(data: &mut [u8]) {
    let mut i = 0;
    let mut ip: u32 = 0;

    while i + 4 < data.len() {
        let b = data[i];

        if b == 0xE8 || b == 0xE9 {
            let rel = i32::from_le_bytes([data[i + 1], data[i + 2], data[i + 3], data[i + 4]]);
            let addr = ip.wrapping_add(5).wrapping_add(rel as u32);
            data[i + 1] = addr as u8;
            data[i + 2] = (addr >> 8) as u8;
            data[i + 3] = (addr >> 16) as u8;
            data[i + 4] = (addr >> 24) as u8;
        }

        let len = match b {
            0x0F => {
                if i + 1 < data.len() {
                    match data[i + 1] {
                        0x80..=0x8F => 6,
                        _ => 2,
                    }
                } else {
                    1
                }
            }
            0x80..=0x83 => 6,
            0x88..=0x8B => 2,
            0xA1..=0xA3 => 5,
            0xB8..=0xBF => 5,
            0xC2..=0xC3 => 1,
            0xC8 => 4,
            0xE8 => 5,
            0xE9 => 5,
            0xEB => 2,
            0x68 => 5,
            0x6A => 2,
            0xFF => {
                if i + 1 < data.len() && (data[i + 1] & 0x38) == 0x10 {
                    6
                } else {
                    2
                }
            }
            _ => 1,
        };

        i += len;
        ip = ip.wrapping_add(len as u32);
    }
}

// ─── BCJ ARM filter ────────────────────────────────────────────────────────

struct BcjArmFilter<R: Read> {
    inner: R,
    buf: Vec<u8>,
    pos: usize,
    max_buffer: u64,
}

impl<R: Read> BcjArmFilter<R> {
    fn new(inner: R, max_buffer: u64) -> Self {
        Self {
            inner,
            buf: Vec::new(),
            pos: 0,
            max_buffer,
        }
    }
}

impl<R: Read> Read for BcjArmFilter<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.buf.len() {
            let (data, truncated) = crate::bounded_read(&mut self.inner, self.max_buffer)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            if truncated {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "7z BCJ input exceeds max-buffer",
                ));
            }
            self.buf = data;
            apply_bcj_arm(&mut self.buf);
            self.pos = 0;
        }
        if self.pos >= self.buf.len() {
            return Ok(0);
        }
        let available = &self.buf[self.pos..];
        let n = buf.len().min(available.len());
        buf[..n].copy_from_slice(&available[..n]);
        self.pos += n;
        Ok(n)
    }
}

fn apply_bcj_arm(data: &mut [u8]) {
    let mut i = 0;
    while i + 4 <= data.len() {
        let w = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        if (w >> 24) == 0xEB || (w >> 24) == 0xFB {
            let rel = (w & 0x00FFFFFF) << 2;
            let sign = if w & 0x00800000 != 0 {
                0xFF000000u32
            } else {
                0
            };
            let addr = (i as u32).wrapping_add(8).wrapping_add(sign | rel);
            let corrected = addr.wrapping_sub(i as u32);
            let new_rel = corrected >> 2;
            data[i] = (new_rel & 0xFF) as u8;
            data[i + 1] = ((new_rel >> 8) & 0xFF) as u8;
            data[i + 2] = ((new_rel >> 16) & 0xFF) as u8;
            data[i + 3] = (data[i + 3] & 0xF0) | ((new_rel >> 24) as u8 & 0x0F);
        }
        i += 4;
    }
}

// ─── BCJ ARM64 filter ──────────────────────────────────────────────────────

struct BcjArm64Filter<R: Read> {
    inner: R,
    buf: Vec<u8>,
    pos: usize,
    max_buffer: u64,
}

impl<R: Read> BcjArm64Filter<R> {
    fn new(inner: R, max_buffer: u64) -> Self {
        Self {
            inner,
            buf: Vec::new(),
            pos: 0,
            max_buffer,
        }
    }
}

impl<R: Read> Read for BcjArm64Filter<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.buf.len() {
            let (data, truncated) = crate::bounded_read(&mut self.inner, self.max_buffer)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            if truncated {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "7z BCJ input exceeds max-buffer",
                ));
            }
            self.buf = data;
            apply_bcj_arm64(&mut self.buf);
            self.pos = 0;
        }
        if self.pos >= self.buf.len() {
            return Ok(0);
        }
        let available = &self.buf[self.pos..];
        let n = buf.len().min(available.len());
        buf[..n].copy_from_slice(&available[..n]);
        self.pos += n;
        Ok(n)
    }
}

fn apply_bcj_arm64(data: &mut [u8]) {
    let mut i = 0;
    while i + 4 <= data.len() {
        let w = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        if (w >> 26) == 0x05 || (w >> 26) == 0x17 {
            let imm26 = w & 0x03FFFFFF;
            let sign = if imm26 & 0x02000000 != 0 {
                0xFC000000u32
            } else {
                0
            };
            let addr = (i as u32).wrapping_add(sign | (imm26 << 2));
            let corrected = addr.wrapping_sub(i as u32);
            let new_imm = corrected >> 2;
            data[i] = (new_imm & 0xFF) as u8;
            data[i + 1] = ((new_imm >> 8) & 0xFF) as u8;
            data[i + 2] = ((new_imm >> 16) & 0xFF) as u8;
            data[i + 3] = (data[i + 3] & 0xFC) | ((new_imm >> 24) as u8 & 0x03);
        }
        i += 4;
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
mod tests {
    use super::*;

    #[test]
    fn bcj_x86_basic() {
        let mut data = vec![0xE8, 0x10, 0x00, 0x00, 0x00];
        data.resize(1024, 0);
        apply_bcj_x86(&mut data);
        assert_eq!(data[0], 0xE8);
    }
}
