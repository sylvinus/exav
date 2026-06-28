// Vendored from `dmg-core` 0.1.2 (Apache-2.0, Albert Hui / SecurityRonin).
// Adapted to use `lzma-rust2` instead of `lzma-rs` for XZ decompression.

use std::io::{self, Cursor, Read, Seek, SeekFrom};

use base64::Engine;
use flate2::read::ZlibDecoder;
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

    fn run_for(&self, local_sec: u64) -> Option<&BlkxRun> {
        self.runs.iter().find(|r| {
            r.entry_type != BLK_TERM
                && r.entry_type != BLK_COMMENT
                && local_sec >= r.sector_start
                && local_sec < r.sector_start.saturating_add(r.sector_count)
        })
    }
}

struct DmgReader<R: Read + Seek> {
    inner: R,
    sector_count: u64,
    file_size: u64,
    partitions: Vec<Partition>,
    position: u64,
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
        })
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

        let part = self
            .partitions
            .iter()
            .find(|p| p.contains_sector(vsec))
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "no partition"))?;

        let local_sec = vsec - part.sector_base;
        let run = part
            .run_for(local_sec)
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "no run"))?;

        let bytes_into_run = (local_sec - run.sector_start)
            .saturating_mul(512)
            .saturating_add(sec_offset);
        let run_total_bytes = run.sector_count.saturating_mul(512);
        let available_in_run = run_total_bytes.saturating_sub(bytes_into_run);
        let to_read = buf.len().min(available_in_run as usize);

        match run.entry_type {
            BLK_ZERO | BLK_IGNORE => {
                buf[..to_read].fill(0);
            }
            BLK_RAW => {
                let file_pos = part
                    .file_data_offset
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
                let file_pos = part
                    .file_data_offset
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
                let expected = (run.sector_count as usize).saturating_mul(512);
                if expected > MAX_RUN_BYTES {
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
                let start = bytes_into_run as usize;
                if start >= decompressed.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "decompressed run underrun",
                    ));
                }
                let end = (start + to_read).min(decompressed.len());
                buf[..end - start].copy_from_slice(&decompressed[start..end]);
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

fn decompress(
    entry_type: u32,
    compressed: &[u8],
    expected_len: usize,
) -> Result<Vec<u8>, LimitHit> {
    let mut out = Vec::with_capacity(expected_len);
    let cap = expected_len as u64;
    match entry_type {
        BLK_ZLIB => {
            ZlibDecoder::new(Cursor::new(compressed))
                .take(cap)
                .read_to_end(&mut out)
                .map_err(|e| LimitHit::corrupt(format!("UDIF zlib: {e}")))?;
        }
        BLK_BZIP2 => {
            bzip2_rs::DecoderReader::new(Cursor::new(compressed))
                .take(cap)
                .read_to_end(&mut out)
                .map_err(|e| LimitHit::corrupt(format!("UDIF bzip2: {e}")))?;
        }
        BLK_LZMA => {
            // ULMO blocks are XZ-framed (stream magic FD 37 7A 58 5A 00).
            // xz4rust: pure Rust, no unsafe, zero runtime deps (no sha2).
            let mut decoder = xz4rust::XzDecoder::with_alloc_dict_size(8192, 64 * 1024 * 1024);
            let mut out_buf = [0u8; 8192];
            let mut pos = 0;
            loop {
                let feed = compressed[pos..].len().min(out_buf.len());
                if feed == 0 {
                    break;
                }
                match decoder.decode(&compressed[pos..pos + feed], &mut out_buf) {
                    Ok(result) => {
                        let produced = result.output_produced();
                        if produced > 0 {
                            out.extend_from_slice(&out_buf[..produced]);
                        }
                        pos += result.input_consumed();
                        if let xz4rust::XzNextBlockResult::EndOfStream(_, _) = result {
                            break;
                        }
                    }
                    Err(xz4rust::XzError::NeedsLargerInputBuffer) => {
                        pos += feed;
                    }
                    Err(e) => {
                        return Err(LimitHit::corrupt(format!("UDIF xz: {e}")));
                    }
                }
                if out.len() as u64 > cap {
                    return Err(LimitHit::corrupt("UDIF xz exceeds budget".to_string()));
                }
            }
        }
        BLK_LZFSE => {
            let mut decoder = lzfse_rust::LzfseRingDecoder::default();
            decoder
                .reader_bytes(compressed)
                .take(cap)
                .read_to_end(&mut out)
                .map_err(|e| LimitHit::corrupt(format!("UDIF lzfse: {e}")))?;
        }
        BLK_ADC => out = adc_decompress(compressed, expected_len),
        other => {
            return Err(LimitHit::corrupt(format!(
                "UDIF unsupported block type {other:#010x}"
            )))
        }
    }
    Ok(out)
}

fn adc_decompress(input: &[u8], expected_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(expected_len);
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
                let text = e.unescape().unwrap_or_default();
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

/// Decompress a UDIF DMG into a raw disk image.
///
/// Handles all UDIF codecs (zlib, bzip2, LZFSE, LZMA/XZ, ADC, raw) in pure
/// Rust. Vendored from `dmg-core` 0.1.2 (Apache-2.0, Albert Hui / SecurityRonin).
pub(crate) fn decompress_udif(data: &[u8]) -> Result<Vec<u8>, LimitHit> {
    if data.len() < 512 || &data[data.len() - 512..data.len() - 508] != b"koly" {
        return Ok(data.to_vec());
    }

    let mut reader = DmgReader::open(Cursor::new(data))?;

    let disk_size = reader.virtual_disk_size() as usize;
    let mut raw = Vec::with_capacity(disk_size);
    reader
        .read_to_end(&mut raw)
        .map_err(|e| LimitHit::corrupt(format!("UDIF decompress: {e}")))?;

    Ok(raw)
}
