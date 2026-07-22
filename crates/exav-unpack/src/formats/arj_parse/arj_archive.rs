#![allow(dead_code)]
use super::crypto::decrypt_arj_data;
use super::decode_fastest::decode_fastest;
use super::encryption::ArjEncryption;
use super::local_file_header::{CompressionMethod, LocalFileHeader};
use super::main_header::MainHeader;
use delharc::decode::Decoder;

const MAX_HEADER_SIZE: usize = 2600;
const ARJ_MAGIC_1: u8 = 0x60;
const ARJ_MAGIC_2: u8 = 0xEA;

fn read_header(data: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    let mut u8_buf = [0u8; 1];
    loop {
        if *pos >= data.len() {
            return None;
        }
        u8_buf[0] = data[*pos];
        *pos += 1;
        if u8_buf[0] != ARJ_MAGIC_1 {
            continue;
        }
        if *pos >= data.len() {
            return None;
        }
        u8_buf[0] = data[*pos];
        *pos += 1;
        if u8_buf[0] == ARJ_MAGIC_2 {
            break;
        }
    }

    if *pos + 2 > data.len() {
        return None;
    }
    let header_size = data[*pos] as u16 | (data[*pos + 1] as u16) << 8;
    *pos += 2;

    if header_size == 0 {
        return Some(Vec::new());
    }
    if header_size as usize > MAX_HEADER_SIZE {
        return None;
    }

    let hs = header_size as usize;
    if *pos + hs + 4 > data.len() {
        return None;
    }
    let header_bytes = data[*pos..*pos + hs].to_vec();
    *pos += hs;

    let mut crc = [0u8; 4];
    crc.copy_from_slice(&data[*pos..*pos + 4]);
    *pos += 4;

    let checksum = crc32fast::hash(&header_bytes);
    let expected = u32::from_le_bytes(crc);
    if checksum != expected {
        return None;
    }

    Some(header_bytes)
}

fn read_extended_headers(data: &[u8], pos: &mut usize) -> bool {
    loop {
        if *pos + 2 > data.len() {
            return false;
        }
        let ext_header_size = data[*pos] as u16 | (data[*pos + 1] as u16) << 8;
        *pos += 2;
        if ext_header_size == 0 {
            return true;
        }
        let ehs = ext_header_size as usize;
        if *pos + ehs + 4 > data.len() {
            return false;
        }
        let header = &data[*pos..*pos + ehs];
        *pos += ehs;

        let mut crc = [0u8; 4];
        crc.copy_from_slice(&data[*pos..*pos + 4]);
        *pos += 4;

        let checksum = crc32fast::hash(header);
        let expected = u32::from_le_bytes(crc);
        if checksum != expected {
            return false;
        }
    }
}

pub struct ArjArchive {
    data: Vec<u8>,
    pos: usize,
    passwords: Vec<String>,
    /// Set when header parsing failed part-way rather than reaching the archive's
    /// end marker. The iterator can only say "no more entries", so without this
    /// the caller cannot tell a clean end from a walk that stopped early — and
    /// members after the break would vanish silently.
    stopped_early: bool,
}

impl ArjArchive {
    pub fn new(data: Vec<u8>) -> Option<Self> {
        let mut pos = 0;
        let header_bytes = read_header(&data, &mut pos)?;
        if header_bytes.is_empty() {
            return None;
        }
        let _header = MainHeader::load_from(&header_bytes)?;
        read_extended_headers(&data, &mut pos);

        Some(Self {
            data,
            pos,
            passwords: Vec::new(),
            stopped_early: false,
        })
    }

    /// Candidate passwords tried against garbled (encrypted) members.
    pub fn set_passwords(&mut self, passwords: &[String]) {
        self.passwords = passwords.to_vec();
    }

    pub fn get_encryption_type(&self) -> Option<ArjEncryption> {
        let mut pos = 0;
        let header_bytes = read_header(&self.data, &mut pos)?;
        let header = MainHeader::load_from(&header_bytes)?;
        ArjEncryption::from_version(header.encryption_version, header.is_gabled())
    }

    pub fn get_next_entry(&mut self) -> Option<LocalFileHeader> {
        let Some(header_bytes) = read_header(&self.data, &mut self.pos) else {
            // A bad header CRC, an implausible header size or a truncated read.
            // Any of these ends the walk with members still ahead of us.
            self.stopped_early = true;
            return None;
        };
        if header_bytes.is_empty() {
            return None; // the archive's own end marker: a clean finish
        }
        let Some(hdr) = LocalFileHeader::load_from(&header_bytes) else {
            self.stopped_early = true;
            return None;
        };
        read_extended_headers(&self.data, &mut self.pos);
        Some(hdr)
    }

    /// Did enumeration stop on a malformed header rather than the end marker?
    /// When true, members after the break were never seen.
    pub fn stopped_early(&self) -> bool {
        self.stopped_early
    }

    pub fn skip(&mut self, header: &LocalFileHeader) -> bool {
        let skip_to = self.pos + header.compressed_size as usize;
        if skip_to <= self.data.len() {
            self.pos = skip_to;
            true
        } else {
            false
        }
    }

    pub fn read(&mut self, header: &LocalFileHeader, verify_checksum: bool) -> Option<Vec<u8>> {
        let end = self.pos + header.compressed_size as usize;
        if end > self.data.len() {
            self.skip(header);
            return None;
        }
        let raw = self.data[self.pos..end].to_vec();
        self.pos = end;

        if header.is_garbled() {
            // Garbled (encrypted) member: try each candidate password. The content
            // CRC-32 is the only reliable password check for garbled data, so it
            // is enforced here even when checksum verification is otherwise off —
            // otherwise a wrong password could yield right-sized garbage. Returns
            // `None` (→ surfaced as an encrypted member) when no password works.
            let enc = self.get_encryption_type();
            let ftime: u32 = header.date_time_modified.into();
            for pw in &self.passwords {
                let mut buf = raw.clone();
                decrypt_arj_data(&mut buf, enc, pw, header.password_modifier, ftime);
                if let Some(out) = self.decompress_chunk(
                    &buf,
                    header.original_size as usize,
                    &header.compression_method,
                ) {
                    if out.len() == header.original_size as usize
                        && crc32fast::hash(&out) == header.original_crc32
                    {
                        return Some(out);
                    }
                }
            }
            return None;
        }

        let uncompressed = self.decompress_chunk(
            &raw,
            header.original_size as usize,
            &header.compression_method,
        )?;

        if uncompressed.len() != header.original_size as usize {
            return None;
        }

        // Content CRC-32: only enforced when checksum verification is on. By
        // default a scanner scans the decompressed bytes regardless of the CRC
        // (a corrupted checksum must not hide the payload). The size check above
        // still guards against a truncated or garbage decode.
        if verify_checksum && crc32fast::hash(&uncompressed) != header.original_crc32 {
            return None;
        }

        Some(uncompressed)
    }

    fn decompress_chunk(
        &self,
        compressed: &[u8],
        original_size: usize,
        method: &CompressionMethod,
    ) -> Option<Vec<u8>> {
        match method {
            CompressionMethod::Stored => Some(compressed.to_vec()),
            CompressionMethod::CompressedMost
            | CompressionMethod::Compressed
            | CompressionMethod::CompressedFaster => {
                let mut decoder = delharc::decode::DecoderAny::new_from_compression(
                    delharc::CompressionMethod::Lh6,
                    compressed,
                );
                let mut decompressed_buffer = vec![0; original_size];
                decoder.fill_buffer(&mut decompressed_buffer).ok()?;
                Some(decompressed_buffer)
            }
            CompressionMethod::CompressedFastest => decode_fastest(compressed, original_size),
            CompressionMethod::NoDataNoCrc
            | CompressionMethod::NoData
            | CompressionMethod::Unknown(_) => None,
        }
    }
}
