//! What a file is, from its first bytes (`contentType`, by exav's own
//! detection: see [`content`]), and a ZIP's central directory, read by
//! exav-unpack's ZIP reader from the last bytes of the file: what the Office
//! page needs to know of a DOCX or a PPTX (where the archive ends, how large
//! its members are) without a second ZIP reader in TypeScript. `inspect`
//! says whether a ZIP's directory goes past a limit, and why a file that
//! failed to open may be damaged or not what its name says, from the same
//! readers. `officeKinds` says which Office formats a compound file, a ZIP or
//! a PowerPoint 2 to 4 file is, for the page's choice of converter;
//! `zipOfficeKinds` says it of a ZIP from its first and last bytes, for the
//! choice of plugin.

mod content;
mod inspect;
mod office;

use exav_unpack::{Limits, TailDirectory, directory_in_tail};
use wasm_bindgen::prelude::*;

/// The content type of a `size`-byte file whose first bytes are `head`, or
/// "" when they prove none the viewer opens.
#[wasm_bindgen(js_name = contentType)]
pub fn content_type(head: &[u8], size: f64) -> String {
    // Saturating: a size past what the module addresses cannot be read past
    // `head` anyway.
    content::content_type(head, size as usize).to_string()
}

/// What exav's readers find of a `size`-byte file of format `kind` (a viewer
/// format id), from its first bytes `head` and last bytes `tail` (empty until
/// asked for).
#[wasm_bindgen]
pub struct Inspection {
    verdict: &'static str,
    needs: f64,
    reason: String,
}

#[wasm_bindgen]
impl Inspection {
    /// "valid", "not-inspected", "needs-tail", "signature-mismatch",
    /// "invalid-package", "missing-part", or a limit passed: "too-large",
    /// "too-compressed", "too-many-entries".
    #[wasm_bindgen(getter)]
    pub fn verdict(&self) -> String {
        self.verdict.to_string()
    }

    /// With "needs-tail": the offset from which the reader needs the file's
    /// bytes, else -1 (the end of the file, of a length of the caller's choice).
    #[wasm_bindgen(getter)]
    pub fn needs(&self) -> f64 {
        self.needs
    }

    /// With a limit: exav-unpack's reason for it.
    #[wasm_bindgen(getter)]
    pub fn reason(&self) -> String {
        self.reason.clone()
    }
}

/// What exav's readers find of the file. `max_*` are the limits of a ZIP's
/// directory, those of exav-unpack's `Limits`; 0 for none.
#[wasm_bindgen(js_name = inspect)]
pub fn inspect(
    kind: &str,
    head: &[u8],
    tail: &[u8],
    size: f64,
    max_extracted_bytes: f64,
    max_members: f64,
    max_compression_ratio: f64,
) -> Inspection {
    let bound = |n: f64| if n > 0.0 { n as u64 } else { u64::MAX };
    let mut limits = Limits::default();
    limits.max_extracted_bytes = bound(max_extracted_bytes);
    limits.max_members = bound(max_members);
    limits.max_compression_ratio = bound(max_compression_ratio);
    let found = inspect::inspect(kind, head, tail, size as u64, &limits);
    Inspection {
        verdict: found.verdict.as_str(),
        needs: found.needs.map_or(-1.0, |at| at as f64),
        reason: found.reason,
    }
}

/// Every content type `contentType` can give.
#[wasm_bindgen(js_name = contentTypes)]
pub fn content_types() -> Vec<String> {
    content::content_types()
        .into_iter()
        .map(String::from)
        .collect()
}

/// The Office formats a file may be, by the id of the converter that reads
/// each, from its container: a compound file's directory (`bytes` is the
/// whole file), a ZIP's member names (`bytes` is its first bytes), the
/// magic number or BinHex header of PowerPoint 2 to 4. `names` are the
/// members' names, each as its length in 4 bytes little endian, then its
/// UTF-8 bytes (an array of strings would need imports from the host).
#[wasm_bindgen(js_name = officeKinds)]
pub fn office_kinds(bytes: &[u8], names: &[u8]) -> Vec<String> {
    office::office_kinds(bytes, &unpack_names(names))
        .into_iter()
        .map(String::from)
        .collect()
}

/// What the reader made of a ZIP's last bytes, for the formats it may be.
#[wasm_bindgen]
pub struct ZipOffice {
    needs: f64,
    kinds: Vec<String>,
}

#[wasm_bindgen]
impl ZipOffice {
    /// The offset from which the reader needs the file's bytes, else -1.
    #[wasm_bindgen(getter)]
    pub fn needs(&self) -> f64 {
        self.needs
    }

    /// The formats, as `officeKinds` gives them; none while the reader needs more bytes.
    #[wasm_bindgen(getter)]
    pub fn kinds(&self) -> Vec<String> {
        self.kinds.clone()
    }
}

/// `officeKinds` of a `size`-byte ZIP whose first bytes are `head`, its
/// member names read from its last bytes `tail`.
#[wasm_bindgen(js_name = zipOfficeKinds)]
pub fn zip_office_kinds(head: &[u8], tail: &[u8], size: f64) -> ZipOffice {
    match office::zip_kinds_in_tail(head, tail, size as u64) {
        office::TailKinds::Kinds(kinds) => ZipOffice {
            needs: -1.0,
            kinds: kinds.into_iter().map(String::from).collect(),
        },
        office::TailKinds::Needs(at) => ZipOffice {
            needs: at as f64,
            kinds: Vec::new(),
        },
    }
}

fn unpack_names(mut packed: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    while let Some((len, rest)) = packed.split_first_chunk::<4>() {
        let Some((name, rest)) = rest.split_at_checked(u32::from_le_bytes(*len) as usize) else {
            break;
        };
        names.push(String::from_utf8_lossy(name).into_owned());
        packed = rest;
    }
    names
}

/// The viewer formats whose ZIP directory `inspect` checks against the limits.
#[wasm_bindgen(js_name = packageKinds)]
pub fn package_kinds() -> Vec<String> {
    inspect::package_kinds()
        .into_iter()
        .map(String::from)
        .collect()
}

/// What the reader made of a file's last bytes.
#[wasm_bindgen]
pub struct ZipTail {
    needs: f64,
    end: f64,
    names: Vec<String>,
    sizes: Vec<f64>,
    headers: Vec<f64>,
    found: bool,
}

#[wasm_bindgen]
impl ZipTail {
    /// Whether the reader opened the directory.
    #[wasm_bindgen(getter)]
    pub fn found(&self) -> bool {
        self.found
    }

    /// The offset from which more bytes are needed, else -1.
    #[wasm_bindgen(getter)]
    pub fn needs(&self) -> f64 {
        self.needs
    }

    /// Where the archive ends, comment included, when that is certain; else -1.
    #[wasm_bindgen(getter)]
    pub fn end(&self) -> f64 {
        self.end
    }

    /// The members' names, in the directory's order.
    #[wasm_bindgen(getter)]
    pub fn names(&self) -> Vec<String> {
        self.names.clone()
    }

    /// Their uncompressed sizes.
    #[wasm_bindgen(getter)]
    pub fn sizes(&self) -> Vec<f64> {
        self.sizes.clone()
    }

    /// Where their local headers are.
    #[wasm_bindgen(getter)]
    pub fn headers(&self) -> Vec<f64> {
        self.headers.clone()
    }
}

/// The directory of a `size`-byte file whose last bytes are `tail`.
#[wasm_bindgen(js_name = zipTail)]
pub fn zip_tail(tail: &[u8], size: f64) -> ZipTail {
    read(tail, size as u64)
}

fn read(tail: &[u8], size: u64) -> ZipTail {
    let mut out = ZipTail {
        needs: -1.0,
        end: -1.0,
        names: Vec::new(),
        sizes: Vec::new(),
        headers: Vec::new(),
        found: false,
    };
    match directory_in_tail(tail, size) {
        TailDirectory::Found(d) => {
            out.found = true;
            out.end = d.end.map_or(-1.0, |e| e as f64);
            for m in d.members {
                out.names.push(m.name);
                out.sizes.push(m.size as f64);
                out.headers.push(m.header as f64);
            }
        }
        TailDirectory::Needs(at) => out.needs = at as f64,
        TailDirectory::NotZip => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stored ZIP of `members`, its end record carrying `comment`, after
    /// `prefix` bytes that no offset counts; ZIP64 end records with `zip64`.
    pub(super) fn zip(
        members: &[(&str, &[u8])],
        comment: &[u8],
        prefix: usize,
        zip64: bool,
    ) -> Vec<u8> {
        let mut out = vec![b'x'; prefix];
        let mut central = Vec::new();
        for (name, data) in members {
            let at = (out.len() - prefix) as u32;
            let crc = crc(data);
            out.extend_from_slice(b"PK\x03\x04\x14\0\0\0\0\0\0\0\0\0");
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(data);
            central.extend_from_slice(b"PK\x01\x02\x14\0\x14\0\0\0\0\0\0\0\0\0");
            central.extend_from_slice(&crc.to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&[0; 12]);
            central.extend_from_slice(&at.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let cd = (out.len() - prefix) as u64;
        out.extend_from_slice(&central);
        let n = members.len() as u64;
        if zip64 {
            let rec = (out.len() - prefix) as u64;
            out.extend_from_slice(b"PK\x06\x06");
            out.extend_from_slice(&44u64.to_le_bytes());
            out.extend_from_slice(&[45, 0, 45, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            out.extend_from_slice(&n.to_le_bytes());
            out.extend_from_slice(&n.to_le_bytes());
            out.extend_from_slice(&(central.len() as u64).to_le_bytes());
            out.extend_from_slice(&cd.to_le_bytes());
            out.extend_from_slice(b"PK\x06\x07\0\0\0\0");
            out.extend_from_slice(&rec.to_le_bytes());
            out.extend_from_slice(&1u32.to_le_bytes());
            out.extend_from_slice(
                b"PK\x05\x06\0\0\0\0\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
            );
        } else {
            out.extend_from_slice(b"PK\x05\x06\0\0\0\0");
            out.extend_from_slice(&(n as u16).to_le_bytes());
            out.extend_from_slice(&(n as u16).to_le_bytes());
            out.extend_from_slice(&(central.len() as u32).to_le_bytes());
            out.extend_from_slice(&(cd as u32).to_le_bytes());
        }
        out.extend_from_slice(&(comment.len() as u16).to_le_bytes());
        out.extend_from_slice(comment);
        out
    }

    fn crc(data: &[u8]) -> u32 {
        let mut c = !0u32;
        for &b in data {
            c ^= u32::from(b);
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    (c >> 1) ^ 0xedb8_8320
                } else {
                    c >> 1
                };
            }
        }
        !c
    }

    fn whole(bytes: &[u8]) -> ZipTail {
        read(bytes, bytes.len() as u64)
    }

    #[test]
    fn names_are_unpacked_by_their_lengths() {
        let mut packed = Vec::new();
        let names = ["a\0b", "", "[Content_Types].xml"];
        for name in names {
            packed.extend_from_slice(&(name.len() as u32).to_le_bytes());
            packed.extend_from_slice(name.as_bytes());
        }
        assert_eq!(unpack_names(&packed), names);
        // A length past the bytes there are ends the list.
        packed.extend_from_slice(&100u32.to_le_bytes());
        packed.extend_from_slice(b"xy");
        assert_eq!(unpack_names(&packed), names);
        assert!(unpack_names(&[1, 0]).is_empty());
    }

    const DECK: &[(&str, &[u8])] = &[
        ("ppt/slides/slide1.xml", b"<a/>"),
        ("word/document.xml", b"hello world"),
    ];

    #[test]
    fn members_sizes_and_headers() {
        let t = whole(&zip(DECK, b"", 0, false));
        assert!(t.found);
        assert_eq!(t.names, ["ppt/slides/slide1.xml", "word/document.xml"]);
        assert_eq!(t.sizes, [4.0, 11.0]);
        assert_eq!(t.headers, [0.0, (30 + 21 + 4) as f64]);
    }

    #[test]
    fn end_is_after_the_comment() {
        let z = zip(DECK, b"a comment", 0, false);
        assert_eq!(whole(&z).end, z.len() as f64);
    }

    #[test]
    fn trailing_bytes_are_past_the_end() {
        let z = zip(DECK, b"c", 0, false);
        let mut long = z.clone();
        long.extend_from_slice(b"\n\0junk");
        let t = whole(&long);
        assert!(t.found);
        assert_eq!(t.end, z.len() as f64);
    }

    #[test]
    fn fake_end_records_in_the_tail_are_not_the_end() {
        let z = zip(DECK, b"", 0, false);
        let mut long = z.clone();
        // A ZIP64 locator naming nothing, then an end record that defers to it.
        long.extend_from_slice(b"PK\x06\x07\0\0\0\0");
        long.extend_from_slice(&7u64.to_le_bytes());
        long.extend_from_slice(&1u32.to_le_bytes());
        long.extend_from_slice(
            b"PK\x05\x06\0\0\0\0\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\0\0",
        );
        let t = whole(&long);
        assert!(t.found);
        assert_eq!(t.end, z.len() as f64);
    }

    #[test]
    fn a_later_record_the_reader_takes_gives_no_end() {
        let z = zip(DECK, b"", 0, false);
        let mut long = z.clone();
        // One member of two, from the start of the directory: the reader
        // takes it, and its directory does not run up to it.
        long.extend_from_slice(b"PK\x05\x06\0\0\0\0\x01\0\x01\0\x10\0\0\0\0\0\0\0\0\0");
        let t = whole(&long);
        assert!(t.found);
        assert_eq!(t.names.len(), 1);
        assert_eq!(t.end, -1.0);
    }

    #[test]
    fn zip64_end_is_found() {
        let z = zip(DECK, b"", 0, true);
        let mut long = z.clone();
        long.push(b'\n');
        let t = whole(&long);
        assert!(t.found, "ZIP64 directory not opened");
        assert_eq!(t.sizes, [4.0, 11.0]);
        assert_eq!(t.end, z.len() as f64);
    }

    #[test]
    fn prefix_shifts_headers() {
        let z = zip(DECK, b"", 100, false);
        let t = whole(&z);
        assert!(t.found);
        assert_eq!(t.headers[0], 100.0);
        assert_eq!(t.end, z.len() as f64);
    }

    #[test]
    fn damaged_directory_is_not_a_zip() {
        let mut z = zip(DECK, b"", 0, false);
        let cd = z.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
        z[cd..cd + 4].copy_from_slice(b"XXXX");
        let t = whole(&z);
        assert!(!t.found);
        assert_eq!(t.needs, -1.0);
        assert_eq!(t.end, -1.0);
    }

    #[test]
    fn not_a_zip() {
        let t = whole(b"%PDF-1.7 not a zip at all");
        assert!(!t.found);
        assert_eq!(t.needs, -1.0);
    }

    #[test]
    fn directory_before_the_tail_is_asked_for() {
        let big = vec![7u8; 200_000];
        let members: &[(&str, &[u8])] = &[("a.bin", &big), ("b.txt", b"b")];
        let z = zip(members, b"", 0, false);
        let cd = z.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
        // A tail that holds the end record but only part of the directory.
        let tail = &z[cd + 10..];
        let t = read(tail, z.len() as u64);
        assert!(!t.found);
        assert!(
            t.needs >= 0.0 && t.needs <= (cd + 10) as f64,
            "needs {}",
            t.needs
        );
        let t = read(&z[t.needs as usize..], z.len() as u64);
        assert!(t.found, "not found from {}", z.len() - cd);
        assert_eq!(t.headers, [0.0, (30 + 5 + 200_000) as f64]);
    }
}
