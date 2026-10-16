//! ZIP packages (ODP, Keynote) read within the limits.

use crate::formats::office::slides::error::{Error, Result};
use crate::formats::office::slides::limits::Budget;
use std::io::{Read, Seek};

/// What a package is read from: its bytes, or a reader that fetches the
/// parts asked for.
pub trait Source: Read + Seek {}
impl<T: Read + Seek> Source for T {}

pub struct Zip<'a> {
    z: zip::ZipArchive<Box<dyn Source + 'a>>,
}

impl<'a> Zip<'a> {
    pub fn open(bytes: &'a [u8]) -> Result<Zip<'a>> {
        Zip::from_source(Box::new(std::io::Cursor::new(bytes)))
    }

    pub fn from_source(source: Box<dyn Source + 'a>) -> Result<Zip<'a>> {
        let z = zip::ZipArchive::new(source)
            .map_err(|e| Error::NotFormat(format!("not a ZIP package: {e}")))?;
        Ok(Zip { z })
    }

    pub fn names(&self) -> Vec<String> {
        self.z
            .file_names()
            .take(1 << 16)
            .filter_map(|s| s.ok().map(|s| s.to_string()))
            .collect()
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
        let Ok(f) = self.z.by_name(name) else {
            return Ok(None);
        };
        if f.encrypted() {
            return Err(Error::Encrypted);
        }
        let mut v = Vec::new();
        if f.take(max + 1).read_to_end(&mut v).is_err() {
            return Ok(None);
        }
        if v.len() as u64 > max {
            return Err(Error::TooLarge("a package part"));
        }
        Ok(Some(v))
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
    use super::image_ext;

    #[test]
    fn picture_formats_by_their_bytes() {
        assert_eq!(image_ext(b"\x89PNG\r\n"), Some("png"));
        assert_eq!(image_ext(&[0xFF, 0xD8, 0xFF]), Some("jpeg"));
        assert_eq!(image_ext(b"<?xml version='1.0'?><svg>"), Some("svg"));
        assert_eq!(image_ext(b"VCLMTF"), None);
    }
}
