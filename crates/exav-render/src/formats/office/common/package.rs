//! ZIP packages (OpenDocument, OOXML, iWork) read and written within limits.

use std::io::{Cursor, Read, Seek, SeekFrom, Write};

/// Why a package part was not read or written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Not a ZIP archive.
    NotZip(String),
    /// A member is encrypted.
    Encrypted,
    /// A member inflates past the bound, or the output grew past its limit.
    TooLarge,
    /// The archive could not be written.
    Write(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NotZip(e) => write!(f, "not a ZIP package: {e}"),
            Error::Encrypted => f.write_str("encrypted package member"),
            Error::TooLarge => f.write_str("package part too large"),
            Error::Write(e) => write!(f, "writing the package: {e}"),
        }
    }
}

impl std::error::Error for Error {}

/// What a package is read from: its bytes, or a reader that fetches the
/// parts asked for.
pub trait Source: Read + Seek {}
impl<T: Read + Seek> Source for T {}

/// Opens `reader` as a ZIP archive. The directory is first taken where the
/// end record says, which reads only the end of the file; the crate's own
/// search for it, which also finds an archive that something precedes,
/// reads the whole file from its start, and comes second.
pub(crate) fn open_zip<R: Read + Seek>(
    mut reader: R,
) -> zip::result::ZipResult<zip::ZipArchive<R>> {
    let config = || zip::read::Config {
        archive_offset: zip::read::ArchiveOffset::Known(0),
    };
    if zip::ZipArchive::with_config(config(), &mut reader).is_ok() {
        return zip::ZipArchive::with_config(config(), reader);
    }
    zip::ZipArchive::new(reader)
}

pub struct Zip<'a> {
    z: zip::ZipArchive<Box<dyn Source + 'a>>,
}

impl<'a> Zip<'a> {
    pub fn open(bytes: &'a [u8]) -> Result<Zip<'a>, Error> {
        Zip::from_source(Box::new(Cursor::new(bytes)))
    }

    pub fn from_source(source: Box<dyn Source + 'a>) -> Result<Zip<'a>, Error> {
        let z = open_zip(source).map_err(|e| Error::NotZip(e.to_string()))?;
        Ok(Zip { z })
    }

    /// Member names, at most 65536 of them.
    pub fn names(&self) -> Vec<String> {
        self.z
            .file_names()
            .take(1 << 16)
            .filter_map(|s| s.ok().map(|s| s.to_string()))
            .collect()
    }

    /// The member's size when inflated, as its directory entry says.
    pub fn size(&mut self, name: &str) -> Option<u64> {
        self.z.by_name(name).ok().map(|f| f.size())
    }

    /// A member, `None` when absent or unreadable; past `max` bytes, an
    /// error.
    pub fn read(&mut self, name: &str, max: u64) -> Result<Option<Vec<u8>>, Error> {
        let f = match self.z.by_name(name) {
            Ok(f) => f,
            Err(zip::result::ZipError::UnsupportedArchive(m))
                if m == zip::result::ZipError::PASSWORD_REQUIRED =>
            {
                return Err(Error::Encrypted)
            }
            Err(_) => return Ok(None),
        };
        let mut v = Vec::new();
        if f.take(max + 1).read_to_end(&mut v).is_err() {
            return Ok(None);
        }
        if v.len() as u64 > max {
            return Err(Error::TooLarge);
        }
        Ok(Some(v))
    }
}

/// A ZIP archive written to memory, refused past `limit` bytes.
pub struct PackageWriter {
    z: zip::ZipWriter<Out>,
}

struct Out {
    buf: Cursor<Vec<u8>>,
    limit: u64,
}

impl Write for Out {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if self.buf.position() + b.len() as u64 > self.limit {
            return Err(std::io::Error::other("output too large"));
        }
        self.buf.write(b)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Seek for Out {
    fn seek(&mut self, p: SeekFrom) -> std::io::Result<u64> {
        self.buf.seek(p)
    }
}

fn werr(e: impl std::fmt::Display) -> Error {
    let s = e.to_string();
    if s.contains("too large") {
        Error::TooLarge
    } else {
        Error::Write(s)
    }
}

impl PackageWriter {
    pub fn new(limit: u64) -> PackageWriter {
        PackageWriter {
            z: zip::ZipWriter::new(Out {
                buf: Cursor::new(Vec::new()),
                limit,
            }),
        }
    }

    /// Adds a member, deflated or stored.
    pub fn put(&mut self, name: &str, data: &[u8], compress: bool) -> Result<(), Error> {
        let method = if compress {
            zip::CompressionMethod::Deflated
        } else {
            zip::CompressionMethod::Stored
        };
        let opt = zip::write::SimpleFileOptions::default()
            .compression_method(method)
            .compression_level(compress.then_some(6))
            .last_modified_time(zip::DateTime::default());
        self.z.start_file(name, opt).map_err(werr)?;
        self.z.write_all(data).map_err(werr)
    }

    /// The archive's bytes.
    pub fn finish(self) -> Result<Vec<u8>, Error> {
        let out = self.z.finish().map_err(werr)?;
        Ok(out.buf.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_bounds() {
        let mut w = PackageWriter::new(1 << 20);
        w.put("a.txt", b"hello", true).unwrap();
        w.put("b/c.bin", &[7u8; 5000], false).unwrap();
        let bytes = w.finish().unwrap();
        let mut z = Zip::open(&bytes).unwrap();
        assert_eq!(z.names().len(), 2);
        assert_eq!(z.read("a.txt", 100).unwrap().unwrap(), b"hello");
        assert_eq!(z.read("missing", 100).unwrap(), None);
        assert_eq!(z.read("b/c.bin", 100), Err(Error::TooLarge));
        assert!(matches!(Zip::open(b"nope"), Err(Error::NotZip(_))));
        // Bit 0 of the general purpose flags marks a member as encrypted.
        let mut e = bytes.clone();
        for i in 0..e.len().saturating_sub(10) {
            if e[i..].starts_with(b"PK\x03\x04") {
                e[i + 6] |= 1;
            } else if e[i..].starts_with(b"PK\x01\x02") {
                e[i + 8] |= 1;
            }
        }
        let mut z = Zip::open(&e).unwrap();
        assert_eq!(z.read("a.txt", 100), Err(Error::Encrypted));
        let mut small = PackageWriter::new(100);
        assert_eq!(small.put("x", &[1u8; 5000], false), Err(Error::TooLarge));
    }
}
