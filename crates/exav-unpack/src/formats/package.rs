//! The parts of a ZIP package (Office, OpenDocument, iWork) read by name.
//!
//! The directory is taken where the end record says, else as the extraction
//! walk opens one that is not there. A part of method Stored or Deflated is
//! decoded as the walk decodes a member: by this crate's inflate, its CRC-32
//! checked at the end. Other methods, and parts that cannot be decoded, are not
//! read. How much a part may hold is the caller's bound; none is set here.

use std::borrow::Cow;
use std::cell::RefCell;
use std::io::{Read, Seek, SeekFrom};
use std::rc::Rc;

use super::zip::plain_reader;
use crate::source::{ByteSource, Reader, read_capped};
use crate::zip_dir::{Directory, local_data_start, open_package};

/// What a package is read from when it is not in memory: a reader that
/// fetches what is asked for.
pub trait ReadSeek: Read + Seek {}
impl<T: Read + Seek + ?Sized> ReadSeek for T {}

/// The bytes are not a ZIP package, or could not be read as one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotZip(String);

impl std::fmt::Display for NotZip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for NotZip {}

/// Why a part was refused, as opposed to missing or unreadable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartError {
    /// The part is marked encrypted.
    Encrypted,
    /// The part holds more than the bound.
    TooLarge,
}

impl std::fmt::Display for PartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PartError::Encrypted => "encrypted package part",
            PartError::TooLarge => "package part too large",
        })
    }
}

impl std::error::Error for PartError {}

/// A reader as a source that holds nothing: a window is read where it lies,
/// so a reader that fetches ranges fetches only those asked for.
struct Direct<'a> {
    src: RefCell<Box<dyn ReadSeek + 'a>>,
    len: usize,
    error: RefCell<Option<String>>,
}

impl ByteSource for Direct<'_> {
    fn len(&self) -> usize {
        self.len
    }

    fn window(&self, off: usize, len: usize) -> Cow<'_, [u8]> {
        let end = off.saturating_add(len).min(self.len);
        let mut out = Vec::new();
        if off < end {
            let mut src = self.src.borrow_mut();
            let read = src
                .seek(SeekFrom::Start(off as u64))
                .and_then(|_| (&mut **src).take((end - off) as u64).read_to_end(&mut out));
            if let Err(e) = read {
                *self.error.borrow_mut() = Some(format!("read at {off} failed: {e}"));
            }
        }
        Cow::Owned(out)
    }

    fn read_error(&self) -> Option<String> {
        self.error.borrow().clone()
    }

    fn identity(&self) -> (usize, usize) {
        (self as *const Self as usize, self.len)
    }
}

/// An opened package: its directory, and its parts by name.
pub struct Package<'a> {
    dir: Directory,
    reader: Reader<'a>,
}

impl<'a> Package<'a> {
    /// The package held in `bytes`.
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Package<'a>, NotZip> {
        Self::open(Reader::shared(Rc::new(bytes)))
    }

    /// The package `reader` reads. Nothing is held: the bytes of the
    /// directory and of each part are read from it as they are asked for.
    pub fn from_reader(mut reader: Box<dyn ReadSeek + 'a>) -> Result<Package<'a>, NotZip> {
        let len = reader
            .seek(SeekFrom::End(0))
            .map_err(|e| e.to_string())
            .and_then(|n| usize::try_from(n).map_err(|e| e.to_string()))
            .map_err(NotZip)?;
        let direct = Direct {
            src: RefCell::new(reader),
            len,
            error: RefCell::new(None),
        };
        Self::open(Reader::shared(Rc::new(direct)))
    }

    fn open(mut reader: Reader<'a>) -> Result<Package<'a>, NotZip> {
        let dir = open_package(&mut reader).map_err(|e| NotZip(e.to_string()))?;
        Ok(Package { dir, reader })
    }

    /// The names of the first `max` entries of the directory.
    pub fn names(&self, max: usize) -> Vec<String> {
        let entries = self.dir.entries.iter().take(max);
        entries.map(|e| e.name_text().into_owned()).collect()
    }

    /// The size the directory gives the part when decoded, `None` when there
    /// is no part of that name.
    pub fn size(&self, name: &str) -> Option<u64> {
        let i = self.dir.index_of(name)?;
        Some(self.dir.entries[i].size)
    }

    /// The part, `None` when it is absent or cannot be read (a method that is
    /// not Stored or Deflated, a damaged stream, a wrong CRC-32); an error when
    /// it is encrypted or holds more than `max` bytes.
    pub fn read(&mut self, name: &str, max: u64) -> Result<Option<Vec<u8>>, PartError> {
        let Some(i) = self.dir.index_of(name) else {
            return Ok(None);
        };
        let entry = &self.dir.entries[i];
        let Some(start) = local_data_start(&mut self.reader, entry.header) else {
            return Ok(None);
        };
        if entry.encrypted() {
            return Err(PartError::Encrypted);
        }
        let stored = match entry.method {
            0 => true,
            8 => false,
            _ => return Ok(None),
        };
        if self.reader.seek(SeekFrom::Start(start)).is_err() {
            return Ok(None);
        }
        let raw = Box::new((&mut self.reader).take(entry.compressed));
        let empty = entry.compressed == 0 && entry.size == 0;
        let mut part = plain_reader(raw, stored, entry.crc, empty);
        let mut bytes = Vec::new();
        if read_capped(&mut part, &mut bytes, max.saturating_add(1)).is_err() {
            return Ok(None);
        }
        if bytes.len() as u64 > max {
            return Err(PartError::TooLarge);
        }
        Ok(Some(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zip_write::{FileOptions, Method, ZipWriter};
    use std::io::{Cursor, Write};

    fn package(parts: &[(&str, &[u8], Method)]) -> Vec<u8> {
        let mut z = ZipWriter::new(Cursor::new(Vec::new()));
        for (name, data, method) in parts {
            z.start_file(name, FileOptions::default().method(*method))
                .unwrap();
            z.write_all(data).unwrap();
        }
        z.finish().unwrap().into_inner()
    }

    fn two_parts() -> Vec<u8> {
        package(&[
            ("stored.xml", b"<stored/>", Method::Stored),
            ("deflated.xml", &b"<deflated/>".repeat(50), Method::Deflated),
        ])
    }

    fn position(bytes: &[u8], sig: &[u8]) -> usize {
        bytes.windows(sig.len()).position(|w| w == sig).unwrap()
    }

    #[test]
    fn stored_and_deflated_parts_are_read_by_name() {
        let bytes = two_parts();
        let mut p = Package::from_bytes(&bytes).unwrap();
        assert_eq!(p.names(10), ["stored.xml", "deflated.xml"]);
        assert_eq!(p.names(1), ["stored.xml"]);
        assert_eq!(p.read("stored.xml", 100).unwrap().unwrap(), b"<stored/>");
        assert_eq!(
            p.read("deflated.xml", 1000).unwrap().unwrap(),
            b"<deflated/>".repeat(50)
        );
        assert_eq!(p.size("stored.xml"), Some(9));
        assert_eq!(p.size("deflated.xml"), Some(550));
    }

    #[test]
    fn a_reader_gives_the_same_parts() {
        let bytes = two_parts();
        let mut p = Package::from_reader(Box::new(Cursor::new(bytes))).unwrap();
        assert_eq!(p.names(10), ["stored.xml", "deflated.xml"]);
        assert_eq!(
            p.read("deflated.xml", 1000).unwrap().unwrap(),
            b"<deflated/>".repeat(50)
        );
    }

    #[test]
    fn a_name_that_is_not_there_is_none() {
        let bytes = two_parts();
        let mut p = Package::from_bytes(&bytes).unwrap();
        assert_eq!(p.read("absent.xml", 100), Ok(None));
        assert_eq!(p.size("absent.xml"), None);
        // Names are matched whole.
        assert_eq!(p.read("stored", 100), Ok(None));
    }

    #[test]
    fn an_encrypted_part_is_refused() {
        let mut bytes = two_parts();
        // Bit 0 of the general purpose flags: in the local header of the
        // first part and in its central header.
        let local = position(&bytes, b"PK\x03\x04");
        bytes[local + 6] |= 1;
        let central = position(&bytes, b"PK\x01\x02");
        bytes[central + 8] |= 1;
        let mut p = Package::from_bytes(&bytes).unwrap();
        assert_eq!(p.read("stored.xml", 100), Err(PartError::Encrypted));
        // The other part is not.
        assert!(p.read("deflated.xml", 1000).unwrap().is_some());
    }

    #[test]
    fn a_part_past_the_bound_is_refused() {
        let bytes = two_parts();
        let mut p = Package::from_bytes(&bytes).unwrap();
        assert_eq!(p.read("stored.xml", 9).unwrap().unwrap().len(), 9);
        assert_eq!(p.read("stored.xml", 8), Err(PartError::TooLarge));
        assert_eq!(p.read("deflated.xml", 549), Err(PartError::TooLarge));
        // A part that inflates to much more than it holds stops at the bound.
        let bomb = package(&[("zeros", &vec![0u8; 8 << 20], Method::Deflated)]);
        let mut p = Package::from_bytes(&bomb).unwrap();
        assert_eq!(p.read("zeros", 1 << 10), Err(PartError::TooLarge));
        assert_eq!(p.read("zeros", 8 << 20).unwrap().unwrap().len(), 8 << 20);
    }

    #[test]
    fn a_part_with_a_wrong_checksum_is_unreadable() {
        for method in [Method::Stored, Method::Deflated] {
            let mut bytes = package(&[("a.xml", b"<a>some text</a>", method)]);
            // The CRC-32 is in the central header, at 16.
            let central = position(&bytes, b"PK\x01\x02");
            bytes[central + 16] ^= 0x55;
            let mut p = Package::from_bytes(&bytes).unwrap();
            assert_eq!(p.read("a.xml", 100), Ok(None), "{method:?}");
        }
    }

    #[test]
    fn a_package_with_bytes_before_it_is_opened() {
        let mut bytes = vec![b'M'; 1000];
        bytes.extend(two_parts());
        let mut p = Package::from_bytes(&bytes).unwrap();
        assert_eq!(p.names(10), ["stored.xml", "deflated.xml"]);
        assert_eq!(p.read("stored.xml", 100).unwrap().unwrap(), b"<stored/>");
    }

    #[test]
    fn a_damaged_directory_is_not_followed_past_the_file() {
        let bytes = two_parts();
        // Cut before the directory.
        let cut = &bytes[..position(&bytes, b"PK\x01\x02")];
        assert!(Package::from_bytes(cut).is_err());
        // Not a package at all.
        assert!(Package::from_bytes(b"not a zip").is_err());
        assert!(Package::from_bytes(&[]).is_err());
        // A part whose local header is not where the directory says.
        let mut lost = bytes.clone();
        let central = position(&lost, b"PK\x01\x02");
        lost[central + 42..central + 46].copy_from_slice(&0x7fff_0000u32.to_le_bytes());
        let mut p = Package::from_bytes(&lost).unwrap();
        assert_eq!(p.names(10).len(), 2);
        assert_eq!(p.read("stored.xml", 100), Ok(None));
        assert!(p.read("deflated.xml", 1000).unwrap().is_some());
    }
}
