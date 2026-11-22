//! ZIP packages (ODP, Keynote) read within the limits.

use crate::formats::office::common::package::MAX_NAMES;
use crate::formats::office::slides::error::{Error, Result};
use crate::formats::office::slides::limits::Budget;
use exav_unpack::package::{NotZip, Package, PartError};

/// What a package is read from: its bytes, or a reader that fetches the
/// parts asked for.
pub use exav_unpack::package::ReadSeek as Source;

pub struct Zip<'a>(Package<'a>);

fn not_zip(e: NotZip) -> Error {
    Error::NotFormat(format!("not a ZIP package: {e}"))
}

impl<'a> Zip<'a> {
    pub fn open(bytes: &'a [u8]) -> Result<Zip<'a>> {
        Package::from_bytes(bytes).map(Zip).map_err(not_zip)
    }

    pub fn from_source(source: Box<dyn Source + 'a>) -> Result<Zip<'a>> {
        Package::from_reader(source).map(Zip).map_err(not_zip)
    }

    pub fn names(&self) -> Vec<String> {
        self.0.names(MAX_NAMES)
    }

    /// A member, `None` when absent or unreadable; past `max` bytes, an
    /// error. Its bytes are charged to the budget.
    pub fn get(&mut self, name: &str, max: u64, budget: &mut Budget) -> Result<Option<Vec<u8>>> {
        let v = self.read(name, max)?;
        if let Some(v) = &v {
            budget.alloc(v.len() as u64)?;
        }
        Ok(v)
    }

    /// As `get`, the caller charging the bytes.
    pub fn read(&mut self, name: &str, max: u64) -> Result<Option<Vec<u8>>> {
        self.0.read(name, max).map_err(|e| match e {
            PartError::Encrypted => Error::Encrypted,
            PartError::TooLarge => Error::TooLarge("a package part"),
        })
    }
}

/// Text in Windows 1252.
pub fn latin1(b: &[u8]) -> String {
    crate::formats::office::common::codepage::decode(b, 1252)
}

/// A picture's format, by its first bytes.
pub fn image_ext(d: &[u8]) -> Option<&'static str> {
    Some(match d {
        [0x89, b'P', b'N', b'G', ..] => "png",
        [0xFF, 0xD8, ..] => "jpeg",
        [b'G', b'I', b'F', ..] => "gif",
        [b'B', b'M', ..] => "bmp",
        [b'I', b'I', 42, 0, ..] | [b'M', b'M', 0, 42, ..] => "tiff",
        [1, 0, 0, 0, _, _, _, _, ..] if d.len() > 44 && &d[40..44] == b" EMF" => "emf",
        [0xD7, 0xCD, 0xC6, 0x9A, ..] | [1, 0, 9, 0, ..] | [2, 0, 9, 0, ..] => "wmf",
        _ => {
            let head = String::from_utf8_lossy(&d[..d.len().min(512)]);
            if head.contains("<svg") {
                "svg"
            } else {
                return None;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{Error, Zip, image_ext};
    use crate::formats::office::common::package::PackageWriter;

    /// A member marked encrypted (bit 0 of its flags) is an encrypted
    /// document, not a missing part.
    #[test]
    fn an_encrypted_member_is_said_to_be_encrypted() {
        let mut w = PackageWriter::new(1 << 20);
        w.put("content.xml", b"<x/>", true).unwrap();
        let mut bytes = w.finish().unwrap();
        assert_eq!(
            Zip::open(&bytes)
                .unwrap()
                .read("content.xml", 100)
                .unwrap()
                .unwrap(),
            b"<x/>"
        );
        for i in 0..bytes.len().saturating_sub(10) {
            if bytes[i..].starts_with(b"PK\x03\x04") {
                bytes[i + 6] |= 1;
            } else if bytes[i..].starts_with(b"PK\x01\x02") {
                bytes[i + 8] |= 1;
            }
        }
        assert!(matches!(
            Zip::open(&bytes).unwrap().read("content.xml", 100),
            Err(Error::Encrypted)
        ));
    }

    #[test]
    fn picture_formats_by_their_bytes() {
        assert_eq!(image_ext(b"\x89PNG\r\n"), Some("png"));
        assert_eq!(image_ext(&[0xFF, 0xD8, 0xFF]), Some("jpeg"));
        assert_eq!(image_ext(b"<?xml version='1.0'?><svg>"), Some("svg"));
        assert_eq!(image_ext(b"VCLMTF"), None);
    }
}
