//! The R2004 file organisation (ODA spec chapter 4), which R2010 to R2018
//! keep (spec 6 to 8): a file header encrypted with a fixed sequence, a page
//! map and a section map in system pages, and named sections made of data
//! pages, most of them compressed (spec 4.7).
//!
//! Nothing is allocated from a size the file gives before that size is
//! checked against what the file holds, or, for decompressed data, against
//! the byte budget the caller gives.

use super::Error;

/// Spec 4.1: the sequence the file header at 0x80 is XORed with.
const MAGIC: [u8; 0x6C] = {
    let mut out = [0u8; 0x6C];
    let mut seed: u32 = 1;
    let mut i = 0;
    while i < 0x6C {
        seed = seed.wrapping_mul(0x343FD).wrapping_add(0x269EC3);
        out[i] = (seed >> 16) as u8;
        i += 1;
    }
    out
};

const FILE_ID: &[u8; 12] = b"AcFssFcAJMB\0";
const PAGE_MAP: u32 = 0x4163_0E3B;
const SECTION_MAP: u32 = 0x4163_003B;
const DATA_PAGE: u32 = 0x4163_043B;
/// Spec 4.4: the first page is at 0x100.
const FIRST_PAGE: u64 = 0x100;
const SYSTEM_HEADER: usize = 0x14;
const DATA_HEADER: usize = 0x20;
/// The most one compressed page may expand to. Writers use 0x7400 (spec
/// 4.5); this only bounds the memory a damaged page size can take.
const MAX_PAGE: u64 = 1 << 24;

fn le32(d: &[u8], at: usize) -> Option<u32> {
    let b = d.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn le64(d: &[u8], at: usize) -> Option<u64> {
    let b = d.get(at..at.checked_add(8)?)?;
    let mut x = [0u8; 8];
    x.copy_from_slice(b);
    Some(u64::from_le_bytes(x))
}

/// The CRC-32 of spec 2.14.2: the reflected 0xEDB88320 one.
fn crc32(data: &[u8]) -> u32 {
    const TABLE: [u32; 256] = {
        let mut t = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            let mut c = i as u32;
            let mut k = 0;
            while k < 8 {
                c = if c & 1 != 0 {
                    (c >> 1) ^ 0xEDB8_8320
                } else {
                    c >> 1
                };
                k += 1;
            }
            t[i] = c;
            i += 1;
        }
        t
    };
    let mut crc = !0u32;
    for &b in data {
        crc = (crc >> 8) ^ TABLE[((crc ^ u32::from(b)) & 0xFF) as usize];
    }
    !crc
}

/// The page checksum of spec 4.2.
pub(super) fn checksum(seed: u32, data: &[u8]) -> u32 {
    let mut sum1 = seed & 0xFFFF;
    let mut sum2 = seed >> 16;
    for chunk in data.chunks(0x15B0) {
        for &b in chunk {
            sum1 += u32::from(b);
            sum2 += sum1;
        }
        sum1 %= 0xFFF1;
        sum2 %= 0xFFF1;
    }
    (sum2 << 16) | (sum1 & 0xFFFF)
}

/// Why compressed data could not be expanded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Inflate {
    /// The data ends inside an opcode or a literal run.
    Truncated,
    /// A copy reaches before the start of the output.
    BadOffset,
    /// The output would pass the limit.
    TooLong,
    /// An opcode of 0x00 to 0x0F, which the format does not use.
    Invalid,
}

/// Expand spec 4.7's LZ77 variant, at most `limit` bytes.
///
/// The spec gives the offsets as read; a copy starts one byte further back
/// than that (offset 0 is the last byte written). Without the one, the
/// objects of every R2004 to R2018 file in the test corpus refer before the
/// start of their page, and the header of an R2004 file reads
/// `cc cc e4 cd` where its doubles repeat `cc`.
pub(super) fn decompress(src: &[u8], limit: usize) -> Result<Vec<u8>, Inflate> {
    let mut out: Vec<u8> = Vec::with_capacity(limit.min(src.len().saturating_mul(4)));
    let mut i = 0usize;
    let byte = |i: &mut usize| -> Result<u8, Inflate> {
        let b = *src.get(*i).ok_or(Inflate::Truncated)?;
        *i += 1;
        Ok(b)
    };
    // A literal length; `None` when the next byte is an opcode.
    let literal_length = |i: &mut usize| -> Result<usize, Inflate> {
        let b = *src.get(*i).ok_or(Inflate::Truncated)?;
        if b & 0xF0 != 0 {
            return Ok(0);
        }
        *i += 1;
        if b != 0 {
            return Ok(usize::from(b) + 3);
        }
        let mut total = 0x0Fusize;
        loop {
            let b = byte(i)?;
            if b != 0 {
                return Ok(total + usize::from(b) + 3);
            }
            total += 0xFF;
        }
    };
    let long_count = |i: &mut usize| -> Result<usize, Inflate> {
        let b = byte(i)?;
        if b != 0 {
            return Ok(usize::from(b));
        }
        let mut total = 0xFFusize;
        loop {
            let b = byte(i)?;
            if b != 0 {
                return Ok(total + usize::from(b));
            }
            total += 0xFF;
        }
    };
    let two_byte = |i: &mut usize| -> Result<(usize, usize), Inflate> {
        let a = byte(i)?;
        let b = byte(i)?;
        Ok((
            (usize::from(a) >> 2) | (usize::from(b) << 6),
            usize::from(a & 3),
        ))
    };
    let literal = |out: &mut Vec<u8>, i: &mut usize, n: usize| -> Result<(), Inflate> {
        let end = i.checked_add(n).ok_or(Inflate::Truncated)?;
        let s = src.get(*i..end).ok_or(Inflate::Truncated)?;
        if out.len() + n > limit {
            return Err(Inflate::TooLong);
        }
        out.extend_from_slice(s);
        *i = end;
        Ok(())
    };

    let n = literal_length(&mut i)?;
    literal(&mut out, &mut i, n)?;
    while i < src.len() {
        let op = byte(&mut i)?;
        let (count, offset, lits) = match op {
            0x11 => break,
            0x10 | 0x12..=0x1F => {
                let count = if op == 0x10 {
                    long_count(&mut i)? + 9
                } else {
                    usize::from(op & 0x0F) + 2
                };
                let (offset, lits) = two_byte(&mut i)?;
                (count, offset + 0x3FFF, lits)
            }
            0x20..=0x3F => {
                let count = if op == 0x20 {
                    long_count(&mut i)? + 0x21
                } else {
                    usize::from(op) - 0x1E
                };
                let (offset, lits) = two_byte(&mut i)?;
                (count, offset, lits)
            }
            0x40..=0xFF => {
                let count = usize::from(op >> 4) - 1;
                let op2 = byte(&mut i)?;
                let offset = (usize::from(op2) << 2) | usize::from((op & 0x0C) >> 2);
                (count, offset, usize::from(op & 3))
            }
            _ => return Err(Inflate::Invalid),
        };
        let lits = if lits == 0 {
            literal_length(&mut i)?
        } else {
            lits
        };
        let back = offset + 1;
        if back > out.len() {
            return Err(Inflate::BadOffset);
        }
        if out.len() + count > limit {
            return Err(Inflate::TooLong);
        }
        // The copy may overlap what it writes.
        let from = out.len() - back;
        for k in 0..count {
            let b = out[from + k];
            out.push(b);
        }
        literal(&mut out, &mut i, lits)?;
    }
    Ok(out)
}

/// The decrypted file header (spec 4.1), the fields a reader needs.
#[derive(Clone, Copy, Debug)]
struct FileHeader {
    page_map_address: u64,
    section_map_id: u32,
    crc_ok: bool,
}

fn file_header(data: &[u8]) -> Option<FileHeader> {
    let raw = data.get(0x80..0x80 + 0x6C)?;
    let mut h = [0u8; 0x6C];
    for (o, (a, b)) in h.iter_mut().zip(raw.iter().zip(MAGIC.iter())) {
        *o = a ^ b;
    }
    if h.get(..12)? != FILE_ID {
        return None;
    }
    let stored = le32(&h, 0x68)?;
    h[0x68..0x6C].fill(0);
    Some(FileHeader {
        page_map_address: le64(&h, 0x54)?,
        section_map_id: le32(&h, 0x5C)?,
        crc_ok: crc32(&h) == stored,
    })
}

/// Whether `head` (0xEC bytes at least) has an R2004-style file header.
pub(super) fn has_file_header(head: &[u8]) -> bool {
    file_header(head).is_some()
}

/// A page of the section page map: its number and where it is.
#[derive(Clone, Copy, Debug)]
struct Page {
    number: i32,
    address: u64,
}

/// A page of a section (spec 4.5).
#[derive(Clone, Copy, Debug)]
struct PageRef {
    number: u32,
    start: u64,
}

/// A data section of the section map (spec 4.5).
#[derive(Clone, Debug)]
pub(super) struct Section {
    name: Vec<u8>,
    size: u64,
    page_size: u64,
    compressed: bool,
    encrypted: u32,
    pages: Vec<PageRef>,
}

impl Section {
    pub(super) fn is_encrypted(&self) -> bool {
        self.encrypted == 1
    }
}

/// The page map and the section map of an R2004 to R2018 file.
pub(super) struct Container<'a> {
    data: &'a [u8],
    /// Sorted by number.
    pages: Vec<Page>,
    sections: Vec<Section>,
    /// Bytes decompressing may still produce.
    budget: u64,
}

impl<'a> Container<'a> {
    /// Read the file header and the two maps. `budget` bounds every byte
    /// decompressed from here on, the maps' included.
    pub(super) fn open(
        data: &'a [u8],
        budget: u64,
        problems: &mut Vec<String>,
    ) -> Result<Container<'a>, Error> {
        let fh = file_header(data).ok_or(Error::NotDwg)?;
        if !fh.crc_ok {
            problems.push("the file header's CRC does not match".into());
        }
        let mut c = Container {
            data,
            pages: Vec::new(),
            sections: Vec::new(),
            budget,
        };
        let address = fh
            .page_map_address
            .checked_add(FIRST_PAGE)
            .ok_or_else(|| Error::Damaged("the page map address is out of range".into()))?;
        let map = c.system_page(address, PAGE_MAP, "section page map", problems)?;
        c.read_page_map(&map);
        let at = c
            .page(fh.section_map_id)
            .ok_or_else(|| Error::Damaged("the section map is not in the page map".into()))?;
        let map = c.system_page(at.address, SECTION_MAP, "section map", problems)?;
        c.read_section_map(&map, problems);
        Ok(c)
    }

    fn take_budget(&mut self, n: u64) -> bool {
        if n > self.budget {
            return false;
        }
        self.budget -= n;
        true
    }

    fn page(&self, number: u32) -> Option<Page> {
        let n = i32::try_from(number).ok()?;
        let i = self.pages.binary_search_by_key(&n, |p| p.number).ok()?;
        self.pages.get(i).copied()
    }

    /// A system page (spec 4.3): its header, then its compressed data.
    fn system_page(
        &mut self,
        address: u64,
        kind: u32,
        what: &str,
        problems: &mut Vec<String>,
    ) -> Result<Vec<u8>, Error> {
        let damaged = || Error::Damaged(format!("the {what} is unreadable"));
        let at = usize::try_from(address).map_err(|_| damaged())?;
        let head = at
            .checked_add(SYSTEM_HEADER)
            .and_then(|end| self.data.get(at..end))
            .ok_or_else(damaged)?;
        let field = |k: usize| le32(head, k).ok_or_else(damaged);
        if field(0)? != kind {
            return Err(damaged());
        }
        let size = field(4)?;
        let packed = field(8)? as usize;
        let method = field(12)?;
        let stored = field(16)?;
        let start = at + SYSTEM_HEADER;
        let body = start
            .checked_add(packed)
            .and_then(|end| self.data.get(start..end))
            .ok_or_else(damaged)?;
        let mut zeroed = [0u8; SYSTEM_HEADER];
        zeroed.copy_from_slice(head);
        zeroed[16..20].fill(0);
        if checksum(checksum(0, &zeroed), body) != stored {
            problems.push(format!("the {what} fails its checksum"));
        }
        if !self.take_budget(u64::from(size)) {
            return Err(Error::LimitExceeded(format!(
                "the {what} declares {size} bytes"
            )));
        }
        let size = size as usize;
        let out = if method == 2 {
            decompress(body, size).map_err(|_| damaged())?
        } else {
            body.to_vec()
        };
        if out.len() != size {
            return Err(damaged());
        }
        Ok(out)
    }

    /// Spec 4.4: a page number and size each; a negative number is a gap,
    /// followed by four more longs.
    fn read_page_map(&mut self, map: &[u8]) {
        let mut address = FIRST_PAGE;
        let mut at = 0usize;
        while let (Some(n), Some(size)) = (le32(map, at), le32(map, at + 4)) {
            at += 8;
            let number = n as i32;
            if number < 0 {
                at += 16;
            } else {
                self.pages.push(Page { number, address });
            }
            address = address.saturating_add(u64::from(size));
        }
        // Numbers are unique; the first of a repeated one is kept.
        self.pages.sort_by_key(|p| p.number);
        self.pages.dedup_by_key(|p| p.number);
    }

    /// Spec 4.5: a header of five longs, then each section's description
    /// and its pages.
    fn read_section_map(&mut self, map: &[u8], problems: &mut Vec<String>) {
        let Some(count) = le32(map, 0) else {
            return;
        };
        let mut at = 20usize;
        for _ in 0..count {
            let (Some(size), Some(pages), Some(page_size), Some(compressed), Some(encrypted)) = (
                le64(map, at),
                le32(map, at + 8),
                le32(map, at + 12),
                le32(map, at + 20),
                le32(map, at + 28),
            ) else {
                problems.push("the section map is cut short".into());
                return;
            };
            let Some(raw_name) = map.get(at + 32..at + 96) else {
                problems.push("the section map is cut short".into());
                return;
            };
            let end = raw_name.iter().position(|b| *b == 0).unwrap_or(64);
            let name = raw_name.get(..end).unwrap_or(&[]).to_vec();
            at += 96;
            // A page reference takes 16 bytes: the count cannot be more.
            let fits = (map.len().saturating_sub(at) / 16) as u64;
            if u64::from(pages) > fits {
                problems.push("the section map is cut short".into());
                return;
            }
            let mut refs = Vec::with_capacity(pages as usize);
            for _ in 0..pages {
                if let (Some(number), Some(start)) = (le32(map, at), le64(map, at + 8)) {
                    refs.push(PageRef { number, start });
                }
                at += 16;
            }
            self.sections.push(Section {
                name,
                size,
                page_size: u64::from(page_size),
                compressed: compressed == 2,
                encrypted,
                pages: refs,
            });
        }
    }

    pub(super) fn section_info(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == name.as_bytes())
    }

    /// The data of a named section, its pages decompressed and joined, the
    /// pages a writer left out (spec 4.5: they hold zeros) put back; `None`
    /// when the file has no such section. What cannot be read is said in
    /// `problems` and cut short.
    pub(super) fn section(
        &mut self,
        name: &str,
        problems: &mut Vec<String>,
    ) -> Result<Option<Vec<u8>>, Error> {
        let Some(s) = self.section_info(name).cloned() else {
            return Ok(None);
        };
        // Pages of zeros are left out, but a section of more of them than
        // of written pages is not one a writer makes: it would only make
        // this reader allocate.
        let page = s.page_size.min(MAX_PAGE);
        let most = (s.pages.len() as u64 + 1).saturating_mul(page);
        if s.size > most {
            problems.push(format!(
                "section {name} declares {} bytes, more than its pages hold",
                s.size
            ));
            return Ok(Some(Vec::new()));
        }
        let Some(size) = usize::try_from(s.size)
            .ok()
            .filter(|_| self.take_budget(s.size))
        else {
            return Err(Error::LimitExceeded(format!(
                "section {name} declares {} bytes",
                s.size
            )));
        };
        let mut out: Vec<u8> = Vec::new();
        for r in &s.pages {
            if out.len() >= size && size > 0 {
                problems.push(format!("section {name} has pages past its end"));
                break;
            }
            let Some(start) = usize::try_from(r.start).ok().filter(|v| *v <= size) else {
                problems.push(format!("a page of {name} starts past the section's end"));
                break;
            };
            if start < out.len() {
                problems.push(format!("the pages of {name} overlap"));
                break;
            }
            // Pages of zeros are not written (spec 4.5).
            out.resize(start, 0);
            match self.data_page(&s, r, problems)? {
                Some(mut page) => {
                    page.truncate(size - start);
                    out.extend_from_slice(&page);
                }
                None => {
                    problems.push(format!("a page of section {name} is unreadable"));
                    break;
                }
            }
        }
        out.resize(size, 0);
        Ok(Some(out))
    }

    /// One data page (spec 4.6): its masked header, then its data.
    ///
    /// What a page holds and expands to is taken from the budget too: page
    /// references may repeat a page, and pages of size 0 share an address,
    /// so without it a small file could have one page checked and expanded
    /// over and over.
    fn data_page(
        &mut self,
        s: &Section,
        r: &PageRef,
        problems: &mut Vec<String>,
    ) -> Result<Option<Vec<u8>>, Error> {
        let Some((address, body, mut head)) = self.page_body(r) else {
            return Ok(None);
        };
        let over = || Error::LimitExceeded("the pages of a section".into());
        if !self.take_budget(body.len() as u64) {
            return Err(over());
        }
        let data_sum = le32(&head, 0x1C).unwrap_or(0);
        let head_sum = le32(&head, 0x18).unwrap_or(0);
        head[0x18..0x1C].fill(0);
        if checksum(0, body) != data_sum || checksum(data_sum, &head) != head_sum {
            problems.push(format!("the page at {address:#X} fails its checksum"));
        }
        let out = if s.compressed {
            let most = s.page_size.min(MAX_PAGE).min(self.budget) as usize;
            match decompress(body, most) {
                Ok(out) => out,
                Err(_) => return Ok(None),
            }
        } else {
            body.to_vec()
        };
        if !self.take_budget(out.len() as u64) {
            return Err(over());
        }
        Ok(Some(out))
    }

    /// A data page's address, its stored bytes and its unmasked header.
    fn page_body(&self, r: &PageRef) -> Option<(u64, &'a [u8], [u8; DATA_HEADER])> {
        let page = self.page(r.number)?;
        let at = usize::try_from(page.address).ok()?;
        let raw = self.data.get(at..at.checked_add(DATA_HEADER)?)?;
        let mask = 0x4164_536B ^ (page.address as u32);
        let mut head = [0u8; DATA_HEADER];
        for (k, word) in raw.as_chunks::<4>().0.iter().enumerate() {
            let v = u32::from_le_bytes(*word) ^ mask;
            head[k * 4..k * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        if le32(&head, 0)? != DATA_PAGE {
            return None;
        }
        let stored_size = usize::try_from(le32(&head, 8)?).ok()?;
        let body_at = at + DATA_HEADER;
        let body = self.data.get(body_at..body_at.checked_add(stored_size)?)?;
        Some((page.address, body, head))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_header_mask_is_the_specifications() {
        // Spec 4.1 prints the first 0x5C bytes of what its code generates:
        // the first and last of them.
        assert_eq!(MAGIC[..4], [0x29, 0x23, 0xBE, 0x84]);
        assert_eq!(MAGIC[0x58..0x5C], [0x6B, 0xC4, 0x30, 0xB7]);
    }

    #[test]
    fn the_crc32_is_the_common_one() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn literal_lengths_and_copies_expand() {
        // Spec 4.7's examples: 0x05 is a run of 8, 0x00 0x02 one of 0x14.
        let mut src = vec![0x05];
        src.extend_from_slice(b"abcdefgh");
        // 0x48: copy (4 - 1) = 3 bytes from offset (0x01 << 2 | 2) + 1 = 7
        // back ("bcd"), then 0x48 & 3 = 0 so a literal length: 0x00 0x02
        // (0x14 bytes).
        src.extend_from_slice(&[0x48, 0x01, 0x00, 0x02]);
        src.extend_from_slice(&[b'z'; 0x14]);
        src.push(0x11);
        let out = decompress(&src, 1000).unwrap();
        let mut want = b"abcdefghbcd".to_vec();
        want.extend_from_slice(&[b'z'; 0x14]);
        assert_eq!(out, want);
        assert_eq!(decompress(&src, 10), Err(Inflate::TooLong));
        assert_eq!(decompress(&src[..12], 1000), Err(Inflate::Truncated));
        // A copy from before the start.
        assert_eq!(
            decompress(&[0x01, b'a', b'b', b'c', b'd', 0x48, 0x10, 0x11], 100),
            Err(Inflate::BadOffset)
        );
    }

    #[test]
    fn an_overlapping_copy_repeats_its_source() {
        // Five literals, then 0x24: 0x24 - 0x1E = 6 bytes from offset 1
        // (two back), and one literal (the low bits of the offset's first
        // byte).
        let src = [
            0x02,
            b'a',
            b'b',
            b'c',
            b'd',
            b'e',
            0x24,
            0x04 | 1,
            0x00,
            b'!',
            0x11,
        ];
        assert_eq!(decompress(&src, 100).unwrap(), b"abcdededede!");
        // 0x00 to 0x0F are not opcodes.
        assert_eq!(
            decompress(&[0x01, b'a', b'b', b'c', b'd', 0x05], 100),
            Err(Inflate::Invalid)
        );
    }
}
