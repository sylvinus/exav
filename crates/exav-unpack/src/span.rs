//! A ZIP split across files, read as one archive.
//!
//! `zip -s` (and PKZIP spanning) writes `x.z01`, `x.z02`, ..., `x.zip`: one
//! ZIP stream cut into parts, the central directory in the last. Joined end to
//! end the parts are the original stream, except that the central directory
//! records where each member starts as a part number and an offset within
//! that part. [`ZipSpan`] reads the parts as one stream and overlays the
//! directory with the same records rewritten to offsets in the joined stream,
//! all on one part, which any ZIP reader then reads as a single archive.

use crate::source::ByteSource;
use std::borrow::Cow;

/// The parts of a split ZIP, read as one archive (see the module docs).
pub struct ZipSpan {
    parts: Vec<Box<dyn ByteSource>>,
    /// Where each part starts in the joined stream.
    bases: Vec<u64>,
    len: u64,
    /// Rewritten ranges: `(offset, bytes)`, read in place of the parts' own.
    patches: Vec<(u64, Vec<u8>)>,
}

const EOCD: &[u8; 4] = b"PK\x05\x06";
const EOCD64: &[u8; 4] = b"PK\x06\x06";
const LOCATOR64: &[u8; 4] = b"PK\x06\x07";
const CDFH: &[u8; 4] = b"PK\x01\x02";

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        crate::bytes::at(b, at, 2)?.try_into().ok()?,
    ))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        crate::bytes::at(b, at, 4)?.try_into().ok()?,
    ))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        crate::bytes::at(b, at, 8)?.try_into().ok()?,
    ))
}

fn put(b: &mut [u8], at: usize, v: &[u8]) {
    b[at..at + v.len()].copy_from_slice(v);
}

impl ZipSpan {
    /// The parts, in order (`x.z01` first, `x.zip` last), as one archive.
    pub fn new(parts: Vec<Box<dyn ByteSource>>) -> Result<ZipSpan, String> {
        let mut bases = Vec::with_capacity(parts.len());
        let mut len = 0u64;
        for p in &parts {
            bases.push(len);
            len += p.len() as u64;
        }
        let mut span = ZipSpan {
            parts,
            bases,
            len,
            patches: Vec::new(),
        };
        span.patches = span.rewrite()?;
        Ok(span)
    }

    /// Where offset `off` of part `disk` is in the joined stream.
    fn absolute(&self, disk: u64, off: u64) -> Result<u64, String> {
        let base = usize::try_from(disk)
            .ok()
            .and_then(|d| self.bases.get(d))
            .ok_or_else(|| {
                format!(
                    "the directory names part {} of {}",
                    disk + 1,
                    self.parts.len()
                )
            })?;
        base.checked_add(off).ok_or_else(|| {
            format!(
                "the directory's offset in part {} is out of range",
                disk + 1
            )
        })
    }

    /// The end-of-directory records and the directory, rewritten.
    fn rewrite(&self) -> Result<Vec<(u64, Vec<u8>)>, String> {
        let last = self.parts.last().ok_or("no parts")?;
        // The end record is in the last part's final 64 KiB and 22 bytes.
        let from = last.len().saturating_sub(22 + 0xffff);
        let tail = last.window(from, last.len() - from);
        let at = tail
            .windows(4)
            .rposition(|w| w == EOCD)
            .ok_or("no end of central directory in the last part")?;
        let eocd_at = self.bases[self.parts.len() - 1] + (from + at) as u64;
        let mut eocd = self.read(eocd_at, 22);
        let (mut cd_disk, mut entries, mut cd_size, mut cd_off) = (
            u64::from(u16_at(&eocd, 6).ok_or("short end record")?),
            u64::from(u16_at(&eocd, 10).ok_or("short end record")?),
            u64::from(u32_at(&eocd, 12).ok_or("short end record")?),
            u64::from(u32_at(&eocd, 16).ok_or("short end record")?),
        );
        let mut patches = Vec::new();
        // Zip64: a locator just before the end record points at the Zip64 end
        // record, whose fields replace the 16- and 32-bit ones.
        let locator_at = eocd_at.checked_sub(20);
        let locator = locator_at
            .map(|a| self.read(a, 20))
            .filter(|l| l.starts_with(LOCATOR64));
        if let (Some(mut loc), Some(loc_at)) = (locator, locator_at) {
            let disk = u64::from(u32_at(&loc, 4).ok_or("short Zip64 locator")?);
            let at = self.absolute(disk, u64_at(&loc, 8).ok_or("short Zip64 locator")?)?;
            let mut e64 = self.read(at, 56);
            if !e64.starts_with(EOCD64) {
                return Err("the Zip64 locator points at no Zip64 end record".to_string());
            }
            cd_disk = u64::from(u32_at(&e64, 20).ok_or("short Zip64 end record")?);
            entries = u64_at(&e64, 32).ok_or("short Zip64 end record")?;
            cd_size = u64_at(&e64, 40).ok_or("short Zip64 end record")?;
            cd_off = u64_at(&e64, 48).ok_or("short Zip64 end record")?;
            let cd_at = self.absolute(cd_disk, cd_off)?;
            put(&mut e64, 16, &0u32.to_le_bytes());
            put(&mut e64, 20, &0u32.to_le_bytes());
            put(&mut e64, 24, &entries.to_le_bytes());
            put(&mut e64, 48, &cd_at.to_le_bytes());
            patches.push((at, e64));
            put(&mut loc, 4, &0u32.to_le_bytes());
            put(&mut loc, 8, &at.to_le_bytes());
            put(&mut loc, 16, &1u32.to_le_bytes());
            patches.push((loc_at, loc));
        }
        let cd_at = self.absolute(cd_disk, cd_off)?;
        let cd_len =
            usize::try_from(cd_size).map_err(|_| "central directory too large".to_string())?;
        let mut cd = self.read(cd_at, cd_len);
        if cd.len() != cd_len {
            return Err("the central directory runs past the last part".to_string());
        }
        let mut i = 0;
        for _ in 0..entries {
            if !crate::bytes::at(&cd, i, 4).is_some_and(|s| s == CDFH) {
                return Err("a central directory record is not where the last one ends".to_string());
            }
            let field = |at: usize| {
                u16_at(&cd, i + at)
                    .map(usize::from)
                    .ok_or("short directory record")
            };
            let (name, extra, comment) = (field(28)?, field(30)?, field(32)?);
            self.rebase(&mut cd, i, name, extra)?;
            i += 46 + name + extra + comment;
        }
        patches.push((cd_at, cd));
        put(&mut eocd, 4, &0u16.to_le_bytes());
        put(&mut eocd, 6, &0u16.to_le_bytes());
        let total = eocd[10..12].to_vec();
        put(&mut eocd, 8, &total);
        if u32_at(&eocd, 16) != Some(u32::MAX) {
            let at = u32::try_from(cd_at)
                .map_err(|_| "a directory past 4 GiB with no Zip64 record".to_string())?;
            put(&mut eocd, 16, &at.to_le_bytes());
        }
        patches.push((eocd_at, eocd));
        Ok(patches)
    }

    /// Point the directory record at `cd[i..]` at its member's offset in the
    /// joined stream, on part 0.
    fn rebase(&self, cd: &mut [u8], i: usize, name: usize, extra: usize) -> Result<(), String> {
        let short = "short directory record";
        let (usize32, csize32) = (
            u32_at(cd, i + 24).ok_or(short)?,
            u32_at(cd, i + 20).ok_or(short)?,
        );
        let (disk16, off32) = (
            u16_at(cd, i + 34).ok_or(short)?,
            u32_at(cd, i + 42).ok_or(short)?,
        );
        // The Zip64 extra field holds, in this order, each field whose short
        // form is all ones: sizes, offset, disk.
        let mut z64 = None;
        let mut e = i + 46 + name;
        let end = e + extra;
        while e + 4 <= end {
            let (id, size) = (
                u16_at(cd, e).ok_or(short)?,
                usize::from(u16_at(cd, e + 2).ok_or(short)?),
            );
            if id == 1 {
                z64 = Some((e + 4, e + 4 + size.min(end - e - 4)));
            }
            e += 4 + size;
        }
        let (mut off_at, mut disk_at) = (None, None);
        if let Some((mut p, stop)) = z64 {
            for (wide, width) in [(usize32 == u32::MAX, 8), (csize32 == u32::MAX, 8)] {
                if wide {
                    p += width;
                }
            }
            if off32 == u32::MAX && p + 8 <= stop {
                off_at = Some(p);
                p += 8;
            }
            if disk16 == u16::MAX && p + 4 <= stop {
                disk_at = Some(p);
            }
        }
        let disk = match disk_at {
            Some(at) => u64::from(u32_at(cd, at).ok_or(short)?),
            None => u64::from(disk16),
        };
        let off = match off_at {
            Some(at) => u64_at(cd, at).ok_or(short)?,
            None => u64::from(off32),
        };
        let abs = self.absolute(disk, off)?;
        match off_at {
            Some(at) => put(cd, at, &abs.to_le_bytes()),
            None => {
                let abs = u32::try_from(abs)
                    .map_err(|_| "a member past 4 GiB with no Zip64 record".to_string())?;
                put(cd, i + 42, &abs.to_le_bytes());
            }
        }
        match disk_at {
            Some(at) => put(cd, at, &0u32.to_le_bytes()),
            None => put(cd, i + 34, &0u16.to_le_bytes()),
        }
        Ok(())
    }

    /// `len` bytes of the parts as they are, from `off` of the joined stream.
    fn read(&self, off: u64, len: usize) -> Vec<u8> {
        // `len` is a size the archive declared.
        let mut out = Vec::with_capacity(crate::cap_prealloc(len));
        let end = off.saturating_add(len as u64).min(self.len);
        let mut at = off;
        while at < end {
            let k = self.bases.partition_point(|&b| b <= at) - 1;
            let inner = (at - self.bases[k]) as usize;
            let part = &self.parts[k];
            let want = ((end - at) as usize).min(part.len() - inner);
            let w = part.window(inner, want);
            out.extend_from_slice(&w);
            if w.len() < want {
                break;
            }
            at += want as u64;
        }
        out
    }
}

impl ByteSource for ZipSpan {
    fn len(&self) -> usize {
        usize::try_from(self.len).unwrap_or(usize::MAX)
    }

    fn window(&self, off: usize, len: usize) -> Cow<'_, [u8]> {
        let mut out = self.read(off as u64, len);
        let (from, to) = (off as u64, off as u64 + out.len() as u64);
        for (at, bytes) in &self.patches {
            let (s, e) = ((*at).max(from), (*at + bytes.len() as u64).min(to));
            if s < e {
                out[(s - from) as usize..(e - from) as usize]
                    .copy_from_slice(&bytes[(s - at) as usize..(e - at) as usize]);
            }
        }
        Cow::Owned(out)
    }

    fn read_error(&self) -> Option<String> {
        self.parts.iter().find_map(|p| p.read_error())
    }

    fn identity(&self) -> (usize, usize) {
        (self as *const Self as usize, self.len())
    }
}

#[cfg(all(test, feature = "zip"))]
mod tests {
    use super::*;

    /// A ZIP of three members, and where its directory and end record are.
    fn archive() -> (Vec<u8>, usize, usize) {
        use std::io::Write;
        let mut buf = std::io::Cursor::new(Vec::new());
        let mut zip = ::zip::ZipWriter::new(&mut buf);
        let stored = ::zip::write::SimpleFileOptions::default()
            .compression_method(::zip::CompressionMethod::Stored);
        for (name, n) in [("a.bin", 3000), ("b.txt", 10), ("c/d.bin", 5000)] {
            let opts = match name {
                "b.txt" => ::zip::write::SimpleFileOptions::default(),
                _ => stored,
            };
            zip.start_file(name, opts).unwrap();
            zip.write_all(&(0..n).map(|i| (i * 7 % 251) as u8).collect::<Vec<_>>())
                .unwrap();
        }
        zip.finish().unwrap();
        let blob = buf.into_inner();
        let eocd = blob.windows(4).rposition(|w| w == EOCD).unwrap();
        let cd = u32_at(&blob, eocd + 16).unwrap() as usize;
        (blob, cd, eocd)
    }

    /// `blob` cut at `cuts` the way `zip -s` writes a set: each member's
    /// directory record names its part and its offset there, and the end
    /// record the directory's.
    fn split(blob: &[u8], cd: usize, eocd: usize, cuts: &[usize]) -> Vec<Vec<u8>> {
        let mut b = blob.to_vec();
        let bounds: Vec<usize> = std::iter::once(0).chain(cuts.iter().copied()).collect();
        let at = |abs: usize| {
            let disk = bounds.iter().rposition(|&s| s <= abs).unwrap();
            (disk, abs - bounds[disk])
        };
        let mut i = cd;
        while b[i..i + 4] == *CDFH {
            let (disk, rel) = at(u32_at(&b, i + 42).unwrap() as usize);
            put(&mut b, i + 34, &(disk as u16).to_le_bytes());
            put(&mut b, i + 42, &(rel as u32).to_le_bytes());
            i += 46
                + [28, 30, 32]
                    .iter()
                    .map(|&f| u16_at(&b, i + f).unwrap() as usize)
                    .sum::<usize>();
        }
        let (cd_disk, cd_rel) = at(cd);
        put(&mut b, eocd + 4, &(cuts.len() as u16).to_le_bytes());
        put(&mut b, eocd + 6, &(cd_disk as u16).to_le_bytes());
        put(&mut b, eocd + 16, &(cd_rel as u32).to_le_bytes());
        let ends: Vec<usize> = cuts
            .iter()
            .copied()
            .chain(std::iter::once(b.len()))
            .collect();
        bounds
            .iter()
            .zip(&ends)
            .map(|(&s, &e)| b[s..e].to_vec())
            .collect()
    }

    /// Read through the span, a split archive is the archive it was cut from,
    /// byte for byte, wherever the cuts fall: inside members, inside the
    /// directory, right before the end record.
    #[test]
    fn a_split_zip_reads_as_its_archive() {
        let (blob, cd, eocd) = archive();
        for cuts in [
            vec![1],
            vec![100, 4000],
            vec![cd - 1, cd + 5],
            vec![eocd - 1],
            vec![10, 20, 30, eocd],
        ] {
            let parts = split(&blob, cd, eocd, &cuts);
            assert_ne!(
                parts.concat(),
                blob,
                "{cuts:?}: the split must change the directory"
            );
            let boxed = parts
                .into_iter()
                .map(|p| Box::new(p) as Box<dyn ByteSource>)
                .collect();
            let span = ZipSpan::new(boxed).unwrap();
            assert_eq!(span.window(0, span.len()).into_owned(), blob, "{cuts:?}");
            for (off, len) in [(0, 7), (cd - 3, 60), (eocd - 2, 30), (span.len() - 1, 9)] {
                assert_eq!(
                    span.window(off, len).into_owned(),
                    blob[off..(off + len).min(blob.len())],
                    "{cuts:?} {off}"
                );
            }
        }
    }

    /// A directory naming a part the set does not have is refused.
    #[test]
    fn a_part_too_few_is_refused() {
        let (blob, cd, eocd) = archive();
        let mut parts = split(&blob, cd, eocd, &[100, 4000]);
        parts.remove(1);
        let boxed = parts
            .into_iter()
            .map(|p| Box::new(p) as Box<dyn ByteSource>)
            .collect();
        assert!(ZipSpan::new(boxed).is_err());
    }
}
