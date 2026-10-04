// Vendored from `dmg-core` 0.1.2 (Apache-2.0, Albert Hui / SecurityRonin).
// Adapted to decode XZ runs with exav's `formats::xz` reader (`xz4rust`)
// instead of `lzma-rs`, and to keep what a run decodes before an error.

use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use base64::Engine;
use quick_xml::events::Event;
use quick_xml::Reader;

use crate::LimitHit;

const KOLY_MAGIC: u32 = 0x6B6F_6C79; // b"koly"
const MISH_MAGIC: u32 = 0x6D69_7368; // b"mish"
const KOLY_SIZE: u64 = 512;

const BLK_ZERO: u32 = 0x0000_0000;
const BLK_RAW: u32 = 0x0000_0001;
const BLK_IGNORE: u32 = 0x0000_0002;
const BLK_ADC: u32 = 0x8000_0004;
const BLK_ZLIB: u32 = 0x8000_0005;
const BLK_BZIP2: u32 = 0x8000_0006;
const BLK_LZFSE: u32 = 0x8000_0007;
const BLK_LZMA: u32 = 0x8000_0008;
const BLK_COMMENT: u32 = 0x7FFF_FFFE;
const BLK_TERM: u32 = 0xFFFF_FFFF;

const MAX_RUN_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
struct BlkxRun {
    entry_type: u32,
    sector_start: u64,
    sector_count: u64,
    data_offset: u64,
    data_length: u64,
}

#[derive(Debug, Clone)]
struct Partition {
    file_data_offset: u64,
    sector_base: u64,
    runs: Vec<BlkxRun>,
}

impl Partition {
    fn total_sectors(&self) -> u64 {
        self.runs
            .iter()
            .filter(|r| r.entry_type != BLK_COMMENT && r.entry_type != BLK_TERM)
            .map(|r| r.sector_start.saturating_add(r.sector_count))
            .max()
            .unwrap_or(0)
    }

    fn contains_sector(&self, vsec: u64) -> bool {
        if vsec < self.sector_base {
            return false;
        }
        let local = vsec - self.sector_base;
        local < self.total_sectors()
    }

    fn run_for(&self, local_sec: u64) -> Option<(usize, &BlkxRun)> {
        self.runs.iter().enumerate().find(|(_, r)| {
            r.entry_type != BLK_TERM
                && r.entry_type != BLK_COMMENT
                && local_sec >= r.sector_start
                && local_sec < r.sector_start.saturating_add(r.sector_count)
        })
    }
}

/// Decompressed runs kept, in bytes: a filesystem walk goes back and forth
/// between its B-tree nodes and the files' data.
const RUN_CACHE_BYTES: usize = 32 * 1024 * 1024;

pub(crate) struct DmgReader<R: Read + Seek> {
    inner: R,
    sector_count: u64,
    file_size: u64,
    partitions: Vec<Partition>,
    position: u64,
    /// Decompressed runs by (partition, run), the most recently used last,
    /// each with whether it failed to decode part way.
    runs: Vec<((usize, usize), Run)>,
    /// Set once a run decoded so far fails part way.
    damaged: Arc<AtomicBool>,
}

/// A run's decoded bytes, all of them or those before a failure.
struct Run {
    data: Vec<u8>,
    /// Decoding failed with compressed bytes of the run left unread, or
    /// produced more than the run declares: `data` is not the run's whole
    /// content, and whatever was read from it may not be.
    damaged: bool,
}

impl<R: Read + Seek> DmgReader<R> {
    fn open(mut reader: R) -> Result<Self, LimitHit> {
        let file_size = reader
            .seek(SeekFrom::End(0))
            .map_err(|e| LimitHit::corrupt(format!("UDIF: seek to end: {e}")))?;
        if file_size < KOLY_SIZE {
            return Err(LimitHit::corrupt("UDIF: file too small".into()));
        }

        reader
            .seek(SeekFrom::Start(file_size - KOLY_SIZE))
            .map_err(|e| LimitHit::corrupt(format!("UDIF: seek to koly: {e}")))?;
        let mut koly = [0u8; 512];
        reader
            .read_exact(&mut koly)
            .map_err(|e| LimitHit::corrupt(format!("UDIF: read koly: {e}")))?;

        let magic = u32::from_be_bytes(koly[0..4].try_into().unwrap());
        if magic != KOLY_MAGIC {
            return Err(LimitHit::corrupt("UDIF: missing koly magic".into()));
        }

        let xml_offset = u64::from_be_bytes(koly[216..224].try_into().unwrap());
        let xml_length = u64::from_be_bytes(koly[224..232].try_into().unwrap());
        let sector_count = u64::from_be_bytes(koly[492..500].try_into().unwrap());

        if xml_offset
            .checked_add(xml_length)
            .is_none_or(|end| end > file_size)
        {
            return Err(LimitHit::corrupt("UDIF: xml region out of bounds".into()));
        }

        reader
            .seek(SeekFrom::Start(xml_offset))
            .map_err(|e| LimitHit::corrupt(format!("UDIF: seek to xml: {e}")))?;
        let mut xml_bytes = vec![0u8; xml_length as usize];
        reader
            .read_exact(&mut xml_bytes)
            .map_err(|e| LimitHit::corrupt(format!("UDIF: read xml: {e}")))?;
        let xml = std::str::from_utf8(&xml_bytes)
            .map_err(|e| LimitHit::corrupt(format!("UDIF: bad xml utf8: {e}")))?;

        let partitions = parse_plist(xml)?;

        Ok(Self {
            inner: reader,
            sector_count,
            file_size,
            partitions,
            position: 0,
            runs: Vec::new(),
            damaged: Arc::new(AtomicBool::new(false)),
        })
    }

    /// The decompressed run `key`, decoded on first use.
    fn run_data(&mut self, key: (usize, usize), run: &BlkxRun, file_pos: u64) -> io::Result<&Run> {
        if let Some(i) = self.runs.iter().position(|(k, _)| *k == key) {
            let hit = self.runs.remove(i);
            self.runs.push(hit);
        } else {
            let expected = (run.sector_count as usize).saturating_mul(512);
            // A run's compressed form is not much larger than the run itself.
            if expected > MAX_RUN_BYTES || run.data_length > 2 * MAX_RUN_BYTES as u64 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "block decompressed size exceeds cap",
                ));
            }
            self.inner.seek(SeekFrom::Start(file_pos))?;
            let mut compressed = vec![0u8; run.data_length as usize];
            self.inner.read_exact(&mut compressed)?;
            let decompressed = decompress(run.entry_type, &compressed, expected)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            if decompressed.damaged {
                self.damaged.store(true, Ordering::Relaxed);
            }
            let mut held: usize = self.runs.iter().map(|(_, r)| r.data.len()).sum();
            while held + decompressed.data.len() > RUN_CACHE_BYTES && !self.runs.is_empty() {
                held -= self.runs.remove(0).1.data.len();
            }
            self.runs.push((key, decompressed));
        }
        Ok(&self.runs.last().expect("just pushed").1)
    }

    fn virtual_disk_size(&self) -> u64 {
        self.sector_count.saturating_mul(512)
    }
}

impl<R: Read + Seek> Read for DmgReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let disk_size = self.virtual_disk_size();
        if self.position >= disk_size {
            return Ok(0);
        }

        let vsec = self.position / 512;
        let sec_offset = self.position % 512;

        let (pi, part) = self
            .partitions
            .iter()
            .enumerate()
            .find(|(_, p)| p.contains_sector(vsec))
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "no partition"))?;

        let local_sec = vsec - part.sector_base;
        let (ri, run) = part
            .run_for(local_sec)
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "no run"))?;
        let run = run.clone();
        let file_data_offset = part.file_data_offset;

        let bytes_into_run = (local_sec - run.sector_start)
            .saturating_mul(512)
            .saturating_add(sec_offset);
        let run_total_bytes = run.sector_count.saturating_mul(512);
        let available_in_run = run_total_bytes.saturating_sub(bytes_into_run);
        let mut to_read = buf.len().min(available_in_run as usize);

        match run.entry_type {
            BLK_ZERO | BLK_IGNORE => {
                buf[..to_read].fill(0);
            }
            BLK_RAW => {
                let file_pos = file_data_offset
                    .checked_add(run.data_offset)
                    .and_then(|p| p.checked_add(bytes_into_run))
                    .filter(|&p| p.saturating_add(to_read as u64) <= self.file_size)
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "raw block out of file bounds")
                    })?;
                self.inner.seek(SeekFrom::Start(file_pos))?;
                self.inner.read_exact(&mut buf[..to_read])?;
            }
            BLK_ADC | BLK_ZLIB | BLK_BZIP2 | BLK_LZFSE | BLK_LZMA => {
                let file_pos = file_data_offset
                    .checked_add(run.data_offset)
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "block offset overflow")
                    })?;
                let comp_ok = file_pos
                    .checked_add(run.data_length)
                    .is_some_and(|end| end <= self.file_size);
                if !comp_ok {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "compressed block extends past end of file",
                    ));
                }
                let decompressed = self.run_data((pi, ri), &run, file_pos)?;
                let start = bytes_into_run as usize;
                if start >= decompressed.data.len() {
                    // Short of a damaged run: content left undecoded. Short
                    // of a whole one: the stream ended there.
                    return Err(if decompressed.damaged {
                        io::Error::new(io::ErrorKind::InvalidData, "run failed to decode part way")
                    } else {
                        io::Error::new(io::ErrorKind::UnexpectedEof, "decompressed run underrun")
                    });
                }
                let decompressed = &decompressed.data;
                let end = (start + to_read).min(decompressed.len());
                buf[..end - start].copy_from_slice(&decompressed[start..end]);
                // A run that decoded short ends here: the next read reports it.
                to_read = end - start;
            }
            t => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("unsupported block type {t:#010x}"),
                ));
            }
        }

        self.position += to_read as u64;
        Ok(to_read)
    }
}

impl<R: Read + Seek> Seek for DmgReader<R> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let pos = match to {
            SeekFrom::Start(p) => Some(p),
            SeekFrom::End(d) => self.virtual_disk_size().checked_add_signed(d),
            SeekFrom::Current(d) => self.position.checked_add_signed(d),
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek outside the disk"))?;
        self.position = pos;
        Ok(pos)
    }
}

/// The disk a DMG holds, read on demand: a UDIF image's runs are decompressed
/// as they are reached, and anything else is the disk itself.
pub(crate) enum Disk<R: Read + Seek> {
    Udif(DmgReader<R>),
    Raw(R),
}

pub(crate) fn disk<R: Read + Seek>(mut src: R) -> Result<Disk<R>, LimitHit> {
    let len = src
        .seek(SeekFrom::End(0))
        .map_err(|e| LimitHit::corrupt(format!("UDIF: seek to end: {e}")))?;
    let mut sig = [0u8; 4];
    let koly = len >= KOLY_SIZE
        && src.seek(SeekFrom::Start(len - KOLY_SIZE)).is_ok()
        && src.read_exact(&mut sig).is_ok()
        && u32::from_be_bytes(sig) == KOLY_MAGIC;
    if koly {
        return DmgReader::open(src).map(Disk::Udif);
    }
    Ok(Disk::Raw(src))
}

impl<R: Read + Seek> Disk<R> {
    /// Set once a run read so far failed to decode part way: what was read
    /// from it may not be the disk's content, read on or not.
    pub(crate) fn damage(&self) -> Arc<AtomicBool> {
        match self {
            Disk::Udif(d) => d.damaged.clone(),
            Disk::Raw(_) => Arc::new(AtomicBool::new(false)),
        }
    }
}

impl<R: Read + Seek> Read for Disk<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Disk::Udif(d) => d.read(buf),
            Disk::Raw(r) => r.read(buf),
        }
    }
}

impl<R: Read + Seek> Seek for Disk<R> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        match self {
            Disk::Udif(d) => d.seek(to),
            Disk::Raw(r) => r.seek(to),
        }
    }
}

/// Decode a run of `expected_len` bytes, keeping what decoded before an
/// error.
fn decompress(entry_type: u32, compressed: &[u8], expected_len: usize) -> Result<Run, LimitHit> {
    let cap = expected_len as u64;
    let s = match entry_type {
        // Not flate2's `ZlibDecoder`, which drops the output of the read
        // that fails.
        BLK_ZLIB => match crate::inflate::zlib_body(compressed) {
            Some(body) => crate::salvage(body, cap),
            None => {
                return Ok(Run {
                    data: Vec::new(),
                    damaged: true,
                })
            }
        },
        BLK_BZIP2 => crate::salvage(
            super::bzip2_rs::DecoderReader::new(Cursor::new(compressed)),
            cap,
        ),
        // ULMO blocks are XZ-framed (stream magic FD 37 7A 58 5A 00).
        BLK_LZMA => crate::salvage(super::xz::XzReader::new(Cursor::new(compressed)), cap),
        BLK_LZFSE => {
            let mut decoder = lzfse_rust::LzfseRingDecoder::default();
            crate::salvage(decoder.reader_bytes(compressed), cap)
        }
        BLK_ADC => {
            return Ok(Run {
                data: adc_decompress(compressed, expected_len),
                damaged: false,
            })
        }
        other => {
            return Err(LimitHit::corrupt(format!(
                "UDIF unsupported block type {other:#010x}"
            )))
        }
    };
    // The run's compressed bytes are all here, so a stream that runs out of
    // them hides nothing; one that decodes past the run's size is not the
    // run.
    Ok(Run {
        damaged: s.part_way(true) || s.over_cap,
        data: s.data,
    })
}

fn adc_decompress(input: &[u8], expected_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(crate::cap_prealloc(expected_len));
    let mut i = 0;
    while i < input.len() && out.len() < expected_len {
        let b = input[i];
        i += 1;
        if b & 0x80 != 0 {
            let n = (b & 0x7F) as usize + 1;
            let end = (i + n).min(input.len());
            out.extend_from_slice(&input[i..end]);
            i = end;
        } else if b & 0x40 != 0 {
            if i + 1 >= input.len() {
                break;
            }
            let len = (b & 0x3F) as usize + 4;
            let offset = ((input[i] as usize) << 8) | input[i + 1] as usize;
            i += 2;
            copy_back(&mut out, offset, len);
        } else {
            if i >= input.len() {
                break;
            }
            let len = ((b >> 2) & 0x0F) as usize + 3;
            let offset = (((b & 0x03) as usize) << 8) | input[i] as usize;
            i += 1;
            copy_back(&mut out, offset, len);
        }
    }
    out
}

fn copy_back(out: &mut Vec<u8>, offset: usize, len: usize) {
    for _ in 0..len {
        if out.len() <= offset {
            break;
        }
        let byte = out[out.len() - 1 - offset];
        out.push(byte);
    }
}

fn parse_plist(xml: &str) -> Result<Vec<Partition>, LimitHit> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut in_blkx = false;
    let mut in_data = false;
    let mut last_key = String::new();
    let mut partitions = Vec::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => match e.name().as_ref() {
                b"array" if last_key == "blkx" => {
                    in_blkx = true;
                }
                b"data" if in_blkx => {
                    in_data = true;
                }
                _ => {}
            },
            Ok(Event::Text(e)) => {
                // quick-xml 0.41 replaced `BytesText::unescape()` with
                // `xml10_content()` (decode + XML-1.0 entity unescape).
                let text = e.xml10_content().unwrap_or_default();
                let trimmed = text.trim();
                if e.is_empty() || trimmed.is_empty() {
                    continue;
                }
                if trimmed != "blkx" && !in_blkx {
                    last_key = trimmed.to_string();
                    continue;
                }
                if trimmed == "blkx" {
                    last_key = "blkx".to_string();
                    continue;
                }
                if in_data && in_blkx {
                    let cleaned: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
                    let raw = base64::engine::general_purpose::STANDARD
                        .decode(cleaned.as_bytes())
                        .map_err(|e| LimitHit::corrupt(format!("UDIF plist base64: {e}")))?;
                    let partition = parse_mish(&raw)?;
                    partitions.push(partition);
                    in_data = false;
                }
            }
            Ok(Event::End(e)) => {
                if e.name().as_ref() == b"array" {
                    in_blkx = false;
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(LimitHit::corrupt(format!("UDIF plist: {e}"))),
            _ => {}
        }
    }
    Ok(partitions)
}

fn parse_mish(data: &[u8]) -> Result<Partition, LimitHit> {
    if data.len() < 204 {
        return Err(LimitHit::corrupt("UDIF mish: too short".into()));
    }
    let magic = u32::from_be_bytes(data[0..4].try_into().unwrap());
    if magic != MISH_MAGIC {
        return Err(LimitHit::corrupt(format!(
            "UDIF mish: bad magic {magic:#010x}"
        )));
    }
    let sector_number = u64::from_be_bytes(data[8..16].try_into().unwrap());
    let file_data_offset = u64::from_be_bytes(data[24..32].try_into().unwrap());
    let block_descriptors = u32::from_be_bytes(data[200..204].try_into().unwrap()) as usize;

    let runs_start = 204;
    let run_size = 40;
    if data.len() < runs_start + block_descriptors * run_size {
        return Err(LimitHit::corrupt("UDIF mish: truncated run list".into()));
    }

    let mut runs = Vec::with_capacity(block_descriptors);
    for i in 0..block_descriptors {
        let o = runs_start + i * run_size;
        let entry_type = u32::from_be_bytes(data[o..o + 4].try_into().unwrap());
        let sector_start = u64::from_be_bytes(data[o + 8..o + 16].try_into().unwrap());
        let sector_count = u64::from_be_bytes(data[o + 16..o + 24].try_into().unwrap());
        let data_offset = u64::from_be_bytes(data[o + 24..o + 32].try_into().unwrap());
        let data_length = u64::from_be_bytes(data[o + 32..o + 40].try_into().unwrap());
        runs.push(BlkxRun {
            entry_type,
            sector_start,
            sector_count,
            data_offset,
            data_length,
        });
        if entry_type == BLK_TERM {
            break;
        }
    }

    Ok(Partition {
        file_data_offset,
        sector_base: sector_number,
        runs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// A UDIF image of `sectors` sectors in one run of `kind`, its bytes `run`.
    fn udif(kind: u32, sectors: u64, run: &[u8]) -> Vec<u8> {
        let mut mish = b"mish".to_vec();
        mish.extend_from_slice(&1u32.to_be_bytes());
        mish.extend_from_slice(&0u64.to_be_bytes()); // first sector
        mish.extend_from_slice(&sectors.to_be_bytes());
        mish.extend_from_slice(&0u64.to_be_bytes()); // data offset
        mish.resize(200, 0);
        mish.extend_from_slice(&2u32.to_be_bytes());
        let len = run.len() as u64;
        for (t, start, count, off, n) in
            [(kind, 0, sectors, 0, len), (BLK_TERM, sectors, 0, len, 0)]
        {
            mish.extend_from_slice(&t.to_be_bytes());
            mish.extend_from_slice(&0u32.to_be_bytes());
            for v in [start, count, off, n] {
                mish.extend_from_slice(&v.to_be_bytes());
            }
        }
        let xml = format!(
            "<plist><dict><key>resource-fork</key><dict><key>blkx</key><array><dict>\
             <key>Data</key><data>{}</data></dict></array></dict></dict></plist>",
            base64::engine::general_purpose::STANDARD.encode(&mish)
        );
        let mut f = run.to_vec();
        let mut koly = [0u8; 512];
        koly[..4].copy_from_slice(b"koly");
        koly[216..224].copy_from_slice(&len.to_be_bytes());
        koly[224..232].copy_from_slice(&(xml.len() as u64).to_be_bytes());
        koly[492..500].copy_from_slice(&sectors.to_be_bytes());
        f.extend_from_slice(xml.as_bytes());
        f.extend_from_slice(&koly);
        f
    }

    /// zlib of `data`; with `break_at`, a stored block whose length check
    /// fails written there, the rest of the stream after it.
    fn zlib(data: &[u8], break_at: Option<usize>) -> Vec<u8> {
        let at = break_at.unwrap_or(data.len());
        let mut w = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        w.write_all(&data[..at]).unwrap();
        w.flush().unwrap();
        if break_at.is_some() {
            w.get_mut()
                .extend_from_slice(&[0x00, 0x05, 0x00, 0x00, 0x00]);
        }
        w.write_all(&data[at..]).unwrap();
        w.finish().unwrap()
    }

    fn text(n: usize) -> Vec<u8> {
        (0..n).map(|i| b'a' + (i * 7 % 26) as u8).collect()
    }

    fn open(image: Vec<u8>) -> Disk<Cursor<Vec<u8>>> {
        let d = disk(Cursor::new(image)).unwrap();
        assert!(matches!(d, Disk::Udif(_)));
        d
    }

    fn read_at(d: &mut Disk<Cursor<Vec<u8>>>, at: u64, n: usize) -> io::Result<Vec<u8>> {
        d.seek(SeekFrom::Start(at))?;
        let mut b = vec![0; n];
        d.read_exact(&mut b)?;
        Ok(b)
    }

    #[test]
    fn a_run_damaged_part_way_keeps_its_decoded_bytes_and_is_flagged() {
        let t = text(4096);
        let mut d = open(udif(BLK_ZLIB, 8, &zlib(&t, Some(1024))));
        assert_eq!(read_at(&mut d, 0, 1024).unwrap(), t[..1024]);
        assert!(d.damage().load(Ordering::Relaxed));
        let past = read_at(&mut d, 2048, 16).unwrap_err();
        assert_eq!(past.kind(), io::ErrorKind::InvalidData, "{past}");
    }

    /// The stream ended whole before the run's size: nothing is left unread.
    #[test]
    fn a_run_shorter_than_it_declares_is_not_flagged() {
        let t = text(1024);
        let mut d = open(udif(BLK_ZLIB, 4, &zlib(&t, None)));
        assert_eq!(read_at(&mut d, 0, 1024).unwrap(), t);
        let past = read_at(&mut d, 1024, 16).unwrap_err();
        assert_eq!(past.kind(), io::ErrorKind::UnexpectedEof, "{past}");
        assert!(!d.damage().load(Ordering::Relaxed));
    }

    #[test]
    fn a_run_decoding_past_its_size_is_flagged() {
        let t = text(4096);
        let mut d = open(udif(BLK_ZLIB, 4, &zlib(&t, None)));
        assert_eq!(read_at(&mut d, 0, 2048).unwrap(), t[..2048]);
        assert!(d.damage().load(Ordering::Relaxed));
    }
}
