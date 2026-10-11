//! PPMd variant I revision 1 (PPMd8), the PPMd of ZIP method 98 (APPNOTE 5.10,
//! as 7-Zip and WinZip write it). Ported from `ppmd-rust` 1.5.0 (CC0-1.0 OR
//! MIT-0), itself a port of Igor Pavlov's 7-Zip `Ppmd8.c`, which implements
//! Dmitry Shkarin's public-domain PPMd var.I (2002). Not derived from UnRAR.
//!
//! The model (`model.rs`) is safe Rust over a bounds-checked arena, like the
//! PPMd7 one in `formats/ppmd7`, whose shared definitions, offset type, range
//! decoder trait and Subbotin range decoder it reuses. [`Ppmd8ZipReader`] is
//! the ZIP member decoder.

mod model;

use std::io::{self, Read};

use crate::formats::ppmd7::{RarRangeDecoder, SYM_END};
use crate::LimitHit;
pub(crate) use model::Ppmd8;

pub(crate) const PPMD8_MIN_ORDER: u32 = 2;
pub(crate) const PPMD8_MAX_ORDER: u32 = 16;
pub(crate) const PPMD8_MIN_MEM_SIZE: u32 = 2048;
/// Keeps every arena offset, alignment padding included, within `u32`.
pub(crate) const PPMD8_MAX_MEM_SIZE: u32 = u32::MAX - 12 * 3;

/// What the model does when its memory runs out.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum RestoreMethod {
    /// Start again from an empty model.
    Restart,
    /// Prune the model and keep going.
    CutOff,
}

/// A ZIP method-98 member's PPMd8 stream, the 2-byte parameter header already
/// read, decoded as it is read and stopped at the declared uncompressed size,
/// or with no size, at the stream's end marker.
///
/// The compressed bytes are read whole on the first `read`, bounded by
/// `max_buffer`, as the 7z PPMd reader does. A stream that runs out of input
/// is an `UnexpectedEof` error, one that goes inconsistent or ends before a
/// declared size an `InvalidData` error, either after the bytes decoded
/// before it.
pub(crate) struct Ppmd8ZipReader<R: Read> {
    inner: Option<R>,
    order: u32,
    mem_size: u32,
    restore: RestoreMethod,
    model: Option<Ppmd8<RarRangeDecoder>>,
    /// Bytes still to decode; `u64::MAX` when the size is unknown.
    remaining: u64,
    sized: bool,
    max_buffer: u64,
    /// An error met after some bytes of a `read` were already decoded,
    /// returned by the next `read`.
    pending: Option<(io::ErrorKind, &'static str)>,
    done: bool,
}

impl<R: Read> Ppmd8ZipReader<R> {
    /// `size` is the uncompressed size, `None` when unknown. Parameters out of
    /// PPMd8's range are corrupt; a model larger than `max_buffer` is a
    /// resource limit, refused before anything is allocated.
    pub(crate) fn new(
        inner: R,
        order: u32,
        mem_size: u32,
        restore: RestoreMethod,
        size: Option<u64>,
        max_buffer: u64,
    ) -> Result<Self, LimitHit> {
        if !(PPMD8_MIN_ORDER..=PPMD8_MAX_ORDER).contains(&order) {
            return Err(LimitHit::corrupt(format!(
                "zip: PPMd order {order} out of range [{PPMD8_MIN_ORDER}, {PPMD8_MAX_ORDER}]"
            )));
        }
        if !(PPMD8_MIN_MEM_SIZE..=PPMD8_MAX_MEM_SIZE).contains(&mem_size) {
            return Err(LimitHit::corrupt(format!(
                "zip: PPMd memory size {mem_size} out of range"
            )));
        }
        if u64::from(mem_size) > max_buffer {
            return Err(LimitHit::new(format!(
                "zip: PPMd model memory {mem_size} exceeds max-buffer {max_buffer}"
            )));
        }
        Ok(Self {
            inner: Some(inner),
            order,
            mem_size,
            restore,
            model: None,
            remaining: size.unwrap_or(u64::MAX),
            sized: size.is_some(),
            max_buffer,
            pending: None,
            done: false,
        })
    }

    fn init(&mut self, inner: R) -> io::Result<Ppmd8<RarRangeDecoder>> {
        let invalid = |e: LimitHit| io::Error::new(io::ErrorKind::InvalidData, e);
        let (buf, truncated) = crate::bounded_read(inner, self.max_buffer)
            .map_err(|e| invalid(LimitHit::corrupt(format!("zip: PPMd read: {e}"))))?;
        if truncated {
            return Err(invalid(LimitHit::new(
                "zip: PPMd input exceeds max-buffer".into(),
            )));
        }
        // The range decoder starts from the first four bytes.
        if buf.len() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "zip: PPMd stream truncated",
            ));
        }
        let rc = RarRangeDecoder::new(buf);
        if !rc.init_ok() {
            return Err(invalid(LimitHit::corrupt(
                "zip: PPMd range decoder init failed".into(),
            )));
        }
        Ppmd8::new(rc, self.order, self.mem_size, self.restore)
            .ok_or_else(|| invalid(LimitHit::new("zip: PPMd model allocation failed".into())))
    }
}

impl<R: Read> Read for Ppmd8ZipReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some((kind, reason)) = self.pending.take() {
            return Err(io::Error::new(kind, reason));
        }
        if buf.is_empty() || self.remaining == 0 || self.done {
            return Ok(0);
        }
        if let Some(inner) = self.inner.take() {
            match self.init(inner) {
                Ok(model) => self.model = Some(model),
                Err(e) => {
                    self.done = true;
                    return Err(e);
                }
            }
        }
        let Some(model) = self.model.as_mut() else {
            return Ok(0);
        };

        let want = usize::try_from(self.remaining).map_or(buf.len(), |r| r.min(buf.len()));
        let mut n = 0;
        let mut error = None;
        let mut ended = false;
        use io::ErrorKind::{InvalidData, UnexpectedEof};
        while n < want {
            let sym = model.decode_symbol();
            // A symbol decoded while the input ran out was decoded from
            // padding, not from the stream.
            if model.out_of_data() {
                error = Some((UnexpectedEof, "zip: PPMd stream truncated"));
                break;
            }
            if sym == SYM_END {
                match self.sized {
                    true => {
                        error = Some((
                            InvalidData,
                            "zip: PPMd stream ended before its declared size",
                        ))
                    }
                    false => ended = true,
                }
                break;
            }
            if sym < 0 {
                error = Some((InvalidData, "zip: PPMd stream is corrupt"));
                break;
            }
            buf[n] = sym as u8;
            n += 1;
        }
        self.remaining -= n as u64;
        if self.remaining == 0 || ended {
            self.model = None;
            self.done = true;
        }
        let Some((kind, reason)) = error else {
            return Ok(n);
        };
        self.model = None;
        self.done = true;
        if n == 0 {
            return Err(io::Error::new(kind, reason));
        }
        self.pending = Some((kind, reason));
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// The reference `ppmd-rust` PPMd8 encoder, restart method only: its
    /// cut-off path swaps a state with itself through `mem::swap`, which a
    /// debug build aborts on. Cut-off streams come from fixtures instead.
    fn encode(data: &[u8], order: u32, mem: u32, end_marker: bool) -> Vec<u8> {
        let mut packed = Vec::new();
        let mut enc = ppmd_rust::Ppmd8Encoder::new(
            &mut packed,
            order,
            mem,
            ppmd_rust::RestoreMethod::Restart,
        )
        .unwrap();
        enc.write_all(data).unwrap();
        enc.finish(end_marker).unwrap();
        packed
    }

    /// Reads `out_len` bytes of a bare PPMd8 stream through the ZIP reader,
    /// or `None` if it fails first.
    fn decode(
        data: &[u8],
        order: u32,
        mem: u32,
        restore: RestoreMethod,
        out_len: usize,
    ) -> Option<Vec<u8>> {
        let mut r =
            Ppmd8ZipReader::new(data, order, mem, restore, Some(out_len as u64), u64::MAX).ok()?;
        let mut out = Vec::new();
        r.read_to_end(&mut out).ok()?;
        (out.len() == out_len).then_some(out)
    }

    fn assert_decodes_to(packed: &[u8], data: &[u8], order: u32, mem: u32, restore: RestoreMethod) {
        let decoded = decode(packed, order, mem, restore, data.len())
            .unwrap_or_else(|| panic!("decode failed (order={order}, mem={mem}, {restore:?})"));
        assert!(
            decoded == data,
            "byte mismatch (order={order}, mem={mem}, {restore:?}), first at {:?}",
            decoded.iter().zip(data).position(|(a, b)| a != b)
        );
    }

    /// Encodes with the reference encoder, decodes with the port, and
    /// requires the original bytes back.
    fn roundtrip(data: &[u8], order: u32, mem: u32) {
        let packed = encode(data, order, mem, false);
        assert_decodes_to(&packed, data, order, mem, RestoreMethod::Restart);
    }

    /// Decodes `data.len()` symbols with the model alone and returns how often
    /// it restarted and cut off, and the most cut-off passes one restore took.
    fn restores(
        packed: &[u8],
        len: usize,
        order: u32,
        mem: u32,
        restore: RestoreMethod,
    ) -> (u32, u32, u32) {
        let rc = RarRangeDecoder::new(packed.to_vec());
        let mut model = Ppmd8::new(rc, order, mem, restore).unwrap();
        for _ in 0..len {
            assert!(model.decode_symbol() >= 0);
        }
        (model.restores.0, model.restores.1, model.max_cut_off_passes)
    }

    fn lcg_bytes(n: usize, seed: u32, alphabet: u32) -> Vec<u8> {
        let mut x = seed;
        (0..n)
            .map(|_| {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
                ((x >> 16) % alphabet) as u8
            })
            .collect()
    }

    /// Text with structure at several lengths, so high orders get used.
    fn text(n: usize) -> Vec<u8> {
        let words: Vec<&str> = "the |quick |brown |fox |jumps |over |lazy |dog |PPMd |\
                                variant |I |revision |one |model |\n"
            .split('|')
            .collect();
        let mut x = 7u32;
        let mut out = Vec::with_capacity(n + 16);
        while out.len() < n {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
            out.extend_from_slice(words[(x >> 16) as usize % words.len()].as_bytes());
            if (x >> 8).is_multiple_of(13) {
                out.extend_from_slice(format!("{} ", x % 10_000).as_bytes());
            }
        }
        out.truncate(n);
        out
    }

    /// `(name, original, order, memory, stream)`.
    type Fixture = (String, Vec<u8>, u32, u32, Vec<u8>);

    /// `tests/fixtures/ppmd8/cutoff_<input>_<len>_o<order>_m<mem>.ppmd8`:
    /// `<len>` bytes of `text`, or of `lcg_bytes` with seed 42 and 256 symbols
    /// (`random`) or seed 43 and 20 (`skewed`), encoded by `ppmd-rust` 1.5.0's
    /// `Ppmd8Encoder` with the cut-off method and no end marker, built in
    /// release, and checked against its `Ppmd8Decoder`.
    fn cut_off_fixtures() -> Vec<Fixture> {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/ppmd8");
        let mut out = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_stem().unwrap().to_str().unwrap().to_owned();
            let f: Vec<&str> = name.split('_').collect();
            let len: usize = f[2].parse().unwrap();
            let data = match f[1] {
                "text" => text(len),
                "random" => lcg_bytes(len, 42, 256),
                "skewed" => lcg_bytes(len, 43, 20),
                other => panic!("unknown input {other}"),
            };
            let order = f[3].trim_start_matches('o').parse().unwrap();
            let mem = f[4].trim_start_matches('m').parse().unwrap();
            let packed = std::fs::read(&path).unwrap();
            out.push((name, data, order, mem, packed));
        }
        assert!(out.len() >= 8, "fixtures missing from {dir}");
        out
    }

    #[test]
    fn model_matches_reference_small() {
        roundtrip(b"a", 2, 2048);
        roundtrip(b"abcabcabcabc", 3, 4096);
        roundtrip(&[0u8; 1000], 6, 1 << 16);
        roundtrip(&(0..=255u8).collect::<Vec<_>>(), 16, 1 << 16);
    }

    #[test]
    fn model_matches_reference_text() {
        let data = text(64 * 1024);
        for order in [2, 4, 6, 8, 16] {
            roundtrip(&data, order, 1 << 20);
        }
    }

    #[test]
    fn model_matches_reference_binary() {
        let random = lcg_bytes(32 * 1024, 0x1234_5678, 256);
        let skewed = lcg_bytes(32 * 1024, 0x9e37_79b9, 7);
        roundtrip(&random, 4, 1 << 16);
        roundtrip(&random, 16, 1 << 20);
        roundtrip(&skewed, 8, 1 << 18);
    }

    /// Small models fill up long before the input ends, so the stream goes
    /// through the restart path many times.
    #[test]
    fn model_matches_reference_through_restarts() {
        let inputs = [
            text(200 * 1024),
            lcg_bytes(100 * 1024, 42, 256),
            lcg_bytes(100 * 1024, 43, 20),
        ];
        for data in &inputs {
            for (order, mem) in [(2, 2048), (6, 4096), (16, 16 * 1024), (8, 64 * 1024)] {
                roundtrip(data, order, mem);
                let packed = encode(data, order, mem, false);
                let (restarts, cut_offs, _) =
                    restores(&packed, data.len(), order, mem, RestoreMethod::Restart);
                assert!(
                    restarts > 0,
                    "memory never ran out (order={order}, mem={mem})"
                );
                assert_eq!(cut_offs, 0);
            }
        }
    }

    /// The cut-off method prunes the model in place instead of restarting it,
    /// which the restart streams never reach.
    #[test]
    fn model_matches_reference_through_cut_offs() {
        let mut passes = 0;
        for (name, data, order, mem, packed) in cut_off_fixtures() {
            assert_decodes_to(&packed, &data, order, mem, RestoreMethod::CutOff);
            let (_, cut_offs, p) = restores(&packed, data.len(), order, mem, RestoreMethod::CutOff);
            assert!(cut_offs > 0, "{name}: the model was never cut off");
            passes = passes.max(p);
        }
        assert!(passes > 1, "every restore took a single pass");
        assert!(
            passes < 16,
            "{passes} passes: close to the model's limit of 64"
        );
    }

    /// The decoder stops at the declared size whether or not the encoder wrote
    /// an end marker, and an end marker met before it is an error.
    #[test]
    fn stops_at_the_declared_size() {
        let data = text(4096);
        let packed = encode(&data, 6, 1 << 20, true);
        assert_eq!(
            decode(&packed, 6, 1 << 20, RestoreMethod::Restart, 1000).as_deref(),
            Some(&data[..1000])
        );
        assert_eq!(
            decode(&packed, 6, 1 << 20, RestoreMethod::Restart, data.len()).as_deref(),
            Some(&data[..])
        );

        let read = |packed: &[u8], size| {
            let mut r =
                Ppmd8ZipReader::new(packed, 6, 1 << 20, RestoreMethod::Restart, size, u64::MAX)
                    .unwrap();
            let mut out = Vec::new();
            let end = r.read_to_end(&mut out).map(|_| ());
            (out, end)
        };
        let (out, end) = read(&packed, Some(5000));
        assert!(end.is_err(), "end marker before the declared size");
        assert_eq!(out, data, "everything before the end marker is delivered");

        // With no declared size, the end marker is the end.
        let (out, end) = read(&packed, None);
        assert!(end.is_ok() && out == data);
        // And without one, the stream runs out: everything, then an error.
        let (out, end) = read(&encode(&data, 6, 1 << 20, false), None);
        assert!(end.is_err() && out.starts_with(&data));
    }

    /// `(original, order, memory, restore method, stream)`.
    type Damaged = (Vec<u8>, u32, u32, RestoreMethod, Vec<u8>);

    /// One stream per restore method, each long enough to go through it.
    fn damage_inputs() -> Vec<Damaged> {
        let data = text(16 * 1024);
        let restart = encode(&data, 8, 4096, false);
        let (_, data_c, order_c, mem_c, cut) = cut_off_fixtures()
            .into_iter()
            .find(|f| f.0 == "cutoff_text_65536_o2_m8192")
            .unwrap();
        vec![
            (data, 8, 4096, RestoreMethod::Restart, restart),
            (data_c, order_c, mem_c, RestoreMethod::CutOff, cut),
        ]
    }

    /// Cutting the stream short: an error saying the input ran out, after a
    /// prefix of the original.
    #[test]
    fn truncated_stream_is_an_error_after_a_correct_prefix() {
        for (data, order, mem, restore, packed) in damage_inputs() {
            let mut cuts: Vec<usize> = (0..12).collect();
            cuts.extend((1..20).map(|i| packed.len() * i / 20));
            cuts.push(packed.len() - 1);
            for (cut, size) in cuts
                .into_iter()
                .flat_map(|c| [(c, Some(data.len() as u64)), (c, None)])
            {
                let mut r = Ppmd8ZipReader::new(&packed[..cut], order, mem, restore, size, 1 << 20)
                    .unwrap();
                let mut out = Vec::new();
                let end = r.read_to_end(&mut out).map(drop);
                assert!(
                    end.as_ref()
                        .is_err_and(|e| e.kind() == io::ErrorKind::UnexpectedEof),
                    "{restore:?}: cut at {cut} of {}, size {size:?}: {end:?}",
                    packed.len()
                );
                assert!(out.len() < data.len());
                assert_eq!(
                    out,
                    data[..out.len()],
                    "{restore:?}: cut at {cut}, size {size:?}: not a prefix"
                );
            }
        }
    }

    /// Flipped bits and garbage: whatever comes out, the decoder returns,
    /// within the declared size.
    #[test]
    fn damaged_stream_never_panics_or_overruns() {
        for (data, order, mem, restore, packed) in damage_inputs() {
            let size = data.len().min(16 * 1024);
            // Every bit of the first 16 bytes, then one bit every 29 bytes.
            let flips = (0..16)
                .flat_map(|p| (0..8).map(move |b| (p, b)))
                .chain((16..packed.len().min(4096)).step_by(29).map(|p| (p, p % 8)));
            for (pos, bit) in flips {
                let mut bad = packed.clone();
                bad[pos] ^= 1 << bit;
                let mut r =
                    Ppmd8ZipReader::new(&bad[..], order, mem, restore, Some(size as u64), 1 << 20)
                        .unwrap();
                let mut out = Vec::new();
                let _ = r.read_to_end(&mut out);
                assert!(out.len() <= size);
            }
        }
    }

    /// Junk decodes to junk until something gives, and a tiny cut-off model
    /// reaches the state where cutting off frees too little, on which the
    /// reference implementation loops forever.
    #[test]
    fn junk_input_terminates() {
        for restore in [RestoreMethod::Restart, RestoreMethod::CutOff] {
            for seed in 0..32 {
                let junk = lcg_bytes(4096, seed, 256);
                for (order, mem) in [(2, 2048), (16, 2048), (6, 1 << 16)] {
                    let size = Some(64 * 1024);
                    let mut r =
                        Ppmd8ZipReader::new(&junk[..], order, mem, restore, size, 1 << 20).unwrap();
                    let mut out = Vec::new();
                    let _ = r.read_to_end(&mut out);
                    assert!(out.len() <= 64 * 1024);
                }
            }
        }
    }

    #[test]
    fn parameters_are_checked_before_allocating() {
        let r = |order, mem, max| {
            Ppmd8ZipReader::new(&b""[..], order, mem, RestoreMethod::Restart, Some(1), max)
        };
        assert!(r(1, 1 << 20, u64::MAX).err().unwrap().is_corrupt());
        assert!(r(17, 1 << 20, u64::MAX).err().unwrap().is_corrupt());
        assert!(r(6, 2047, u64::MAX).err().unwrap().is_corrupt());
        let too_big = r(6, 1 << 20, (1 << 20) - 1).err().unwrap();
        assert!(!too_big.is_corrupt(), "a model over max-buffer is a limit");
        assert!(r(2, 1 << 20, 1 << 20).is_ok());
        assert!(r(16, 1 << 20, 1 << 20).is_ok());
    }
}
