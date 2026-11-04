//! Small R2004 drawings laid out as the ODA specification has them (4.1 to
//! 4.6), every page stored: a file header, a page map, a section map and the
//! data pages. For tests that need a drawing damaged in a way no converter
//! writes (a section the reader skips, a map that lies); shared by the tests
//! of exav-unpack and exav-core.

#![allow(dead_code)]

/// The sentinel before the header variables (spec 9).
pub const HEADER_START: [u8; 16] = [
    0xCF, 0x7B, 0x1F, 0x23, 0xFD, 0xDE, 0x38, 0xA9, 0x5F, 0x7C, 0x68, 0xB8, 0x4E, 0x6D, 0x33, 0x5F,
];
/// The sentinel before the classes (spec 10.1).
pub const CLASSES_START: [u8; 16] = [
    0x8D, 0xA1, 0xC4, 0xB8, 0xC4, 0xA9, 0xF8, 0xC5, 0xC0, 0xDC, 0xF4, 0x5F, 0xE7, 0xCF, 0xB6, 0x8A,
];
/// The compound file signature.
pub const OLE2: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// The most one page of a section holds (spec 4.5).
const PAGE_SIZE: u32 = 0x7400;

/// A section as the section map describes it, and the pages it is stored
/// in.
#[derive(Clone, Debug)]
pub struct Section {
    pub name: String,
    /// The size the section map gives.
    pub size: u64,
    /// The map's encryption flag: 1 for encrypted.
    pub encrypted: u32,
    /// The number of pages the map says, when not the number it lists.
    pub declared_pages: Option<u32>,
    /// Each page: where it starts in the section, and its stored bytes.
    pub pages: Vec<(u64, Vec<u8>)>,
}

impl Section {
    /// A section of one page holding `data`.
    pub fn new(name: &str, data: &[u8]) -> Section {
        Section {
            name: name.to_string(),
            size: data.len() as u64,
            encrypted: 0,
            declared_pages: None,
            pages: vec![(0, data.to_vec())],
        }
    }
}

#[derive(Clone, Debug)]
pub struct Drawing {
    pub sections: Vec<Section>,
    /// The number of sections the section map says it has, when not the
    /// number it holds.
    pub declared_sections: Option<u32>,
}

/// A drawing as bytes, and where its data pages are.
pub struct Built {
    pub bytes: Vec<u8>,
    /// Each data page: its section's name and its address.
    pub pages: Vec<(String, usize)>,
}

impl Drawing {
    /// A drawing of one LINE object (handle 1) that the reader opens
    /// without a note: header variables, objects, handles and classes.
    pub fn standard() -> Drawing {
        let mut header = HEADER_START.to_vec();
        header.extend_from_slice(&4u32.to_le_bytes());
        header.extend_from_slice(&[0; 6]);
        // The record: a size of 2 (an MS), then the type 0x13 (a BS).
        let objects = [0x02, 0x00, 0x44, 0xC0];
        // The map: a section of one entry (handle +1, offset +0) and its CRC,
        // then the empty section that ends the map.
        let handles = [0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02];
        // No classes: the highest number, two zeros and a true bit.
        let mut classes = CLASSES_START.to_vec();
        classes.extend_from_slice(&3u32.to_le_bytes());
        classes.extend_from_slice(&[0x80, 0x00, 0x20, 0, 0]);
        Drawing {
            sections: vec![
                Section::new("AcDb:Header", &header),
                Section::new("AcDb:AcDbObjects", &objects),
                Section::new("AcDb:Handles", &handles),
                Section::new("AcDb:Classes", &classes),
            ],
            declared_sections: None,
        }
    }

    pub fn section(&mut self, name: &str) -> &mut Section {
        self.sections
            .iter_mut()
            .find(|s| s.name == name)
            .unwrap_or_else(|| panic!("no section {name}"))
    }

    pub fn build(&self) -> Built {
        // Pages are numbered in file order: 1 the page map, 2 the section
        // map, then the data pages.
        let mut map = Vec::new();
        let count = self.declared_sections.unwrap_or(self.sections.len() as u32);
        for v in [count, 2, PAGE_SIZE, 0, 0] {
            map.extend_from_slice(&v.to_le_bytes());
        }
        let mut data_pages: Vec<(&str, &[u8])> = Vec::new();
        let mut next = 3u32;
        for s in &self.sections {
            map.extend_from_slice(&s.size.to_le_bytes());
            let pages = s.declared_pages.unwrap_or(s.pages.len() as u32);
            map.extend_from_slice(&pages.to_le_bytes());
            map.extend_from_slice(&PAGE_SIZE.to_le_bytes());
            // Unknown, not compressed, the section's number, encryption.
            for v in [0, 1, 0, s.encrypted] {
                map.extend_from_slice(&u32::to_le_bytes(v));
            }
            let mut name = [0u8; 64];
            name[..s.name.len()].copy_from_slice(s.name.as_bytes());
            map.extend_from_slice(&name);
            for (start, bytes) in &s.pages {
                map.extend_from_slice(&next.to_le_bytes());
                map.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                map.extend_from_slice(&start.to_le_bytes());
                data_pages.push((&s.name, bytes));
                next += 1;
            }
        }
        let page_map_len = 0x14 + 8 * (2 + data_pages.len());
        let section_map_len = 0x14 + map.len();
        let mut page_map = Vec::new();
        for (number, size) in [(1u32, page_map_len), (2, section_map_len)]
            .into_iter()
            .chain(
                data_pages
                    .iter()
                    .enumerate()
                    .map(|(i, (_, b))| (3 + i as u32, 0x20 + b.len())),
            )
        {
            page_map.extend_from_slice(&number.to_le_bytes());
            page_map.extend_from_slice(&(size as u32).to_le_bytes());
        }

        let mut out = vec![0u8; 0x100];
        out[..6].copy_from_slice(b"AC1018");
        out[0x80..0xEC].copy_from_slice(&file_header(2));
        out.extend_from_slice(&system_page(0x4163_0E3B, &page_map));
        out.extend_from_slice(&system_page(0x4163_003B, &map));
        let mut pages = Vec::new();
        for (i, (name, bytes)) in data_pages.iter().enumerate() {
            let address = out.len();
            out.extend_from_slice(&data_page(address, 3 + i as u32, bytes));
            pages.push((name.to_string(), address));
        }
        Built { bytes: out, pages }
    }
}

/// The page checksum of spec 4.2.
fn checksum(seed: u32, data: &[u8]) -> u32 {
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

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// The file header block at 0x80 (spec 4.1), encrypted: the file ID, the page
/// map at the first page, and the section map's page number.
fn file_header(section_map: u32) -> [u8; 0x6C] {
    let mut h = [0u8; 0x6C];
    h[..12].copy_from_slice(b"AcFssFcAJMB\0");
    h[0x5C..0x60].copy_from_slice(&section_map.to_le_bytes());
    let crc = crc32(&h);
    h[0x68..0x6C].copy_from_slice(&crc.to_le_bytes());
    let mut seed: u32 = 1;
    for b in &mut h {
        seed = seed.wrapping_mul(0x343FD).wrapping_add(0x269EC3);
        *b ^= (seed >> 16) as u8;
    }
    h
}

/// A system page (spec 4.3), its data stored.
fn system_page(kind: u32, body: &[u8]) -> Vec<u8> {
    let mut head = Vec::new();
    for v in [kind, body.len() as u32, body.len() as u32, 0, 0] {
        head.extend_from_slice(&v.to_le_bytes());
    }
    let sum = checksum(checksum(0, &head), body);
    head[16..20].copy_from_slice(&sum.to_le_bytes());
    head.extend_from_slice(body);
    head
}

/// A data page (spec 4.6) at `address`: the header masked with the address.
fn data_page(address: usize, section: u32, body: &[u8]) -> Vec<u8> {
    let mut head = [0u8; 0x20];
    head[..4].copy_from_slice(&0x4163_043Bu32.to_le_bytes());
    head[4..8].copy_from_slice(&section.to_le_bytes());
    head[8..12].copy_from_slice(&(body.len() as u32).to_le_bytes());
    head[12..16].copy_from_slice(&(body.len() as u32).to_le_bytes());
    let data_sum = checksum(0, body);
    head[0x1C..0x20].copy_from_slice(&data_sum.to_le_bytes());
    let head_sum = checksum(data_sum, &head);
    head[0x18..0x1C].copy_from_slice(&head_sum.to_le_bytes());
    let mask = 0x4164_536B ^ (address as u32);
    for word in head.as_chunks_mut::<4>().0 {
        let v = u32::from_le_bytes([word[0], word[1], word[2], word[3]]) ^ mask;
        word.copy_from_slice(&v.to_le_bytes());
    }
    let mut out = head.to_vec();
    out.extend_from_slice(body);
    out
}
