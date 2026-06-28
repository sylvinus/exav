//! Container-metadata signatures (`.cdb`): match a file *inside* a container
//! (zip/7z/tar/cab/mail/...) by the container type and the member's name,
//! sizes, encryption and position — without needing a content signature.
//!
//! Format:
//! `VirusName:ContainerType:ContainerSize:FileNameREGEX:FileSizeInContainer:
//!  FileSizeReal:IsEncrypted:FilePos:Res1:Res2[:MinFL[:MaxFL]]`

use serde::{Deserialize, Serialize};

use crate::filetype::FileType;

/// An inclusive numeric range constraint (`*`/empty = any, `n` = exact,
/// `n-m` = range).
#[derive(Clone, Copy, Serialize, Deserialize)]
enum Range {
    Any,
    Exact(u64),
    Between(u64, u64),
}

impl Range {
    fn parse(s: &str) -> Option<Range> {
        let s = s.trim();
        if s.is_empty() || s == "*" {
            return Some(Range::Any);
        }
        if let Some((a, b)) = s.split_once('-') {
            Some(Range::Between(
                a.trim().parse().ok()?,
                b.trim().parse().ok()?,
            ))
        } else {
            Some(Range::Exact(s.parse().ok()?))
        }
    }
    fn matches(&self, v: u64) -> bool {
        match *self {
            Range::Any => true,
            Range::Exact(x) => v == x,
            Range::Between(a, b) => v >= a && v <= b,
        }
    }
}

/// The container-type constraint.
#[derive(Serialize, Deserialize)]
enum CType {
    Any,
    /// A type we model.
    Is(FileType),
    /// A specific container type we don't produce — never matches.
    Unmodeled,
}

impl CType {
    fn parse(s: &str) -> CType {
        let s = s.trim();
        if s.is_empty() || s == "*" {
            return CType::Any;
        }
        match s {
            "CL_TYPE_ZIP" => CType::Is(FileType::Zip),
            "CL_TYPE_RAR" => CType::Is(FileType::Rar),
            "CL_TYPE_7Z" => CType::Is(FileType::SevenZip),
            "CL_TYPE_MSCAB" => CType::Is(FileType::Cab),
            "CL_TYPE_MAIL" => CType::Is(FileType::Email),
            "CL_TYPE_GZ" => CType::Is(FileType::Gzip),
            "CL_TYPE_BZ" => CType::Is(FileType::Bzip2),
            "CL_TYPE_XZ" => CType::Is(FileType::Xz),
            "CL_TYPE_OLE2" => CType::Is(FileType::Ole),
            "CL_TYPE_PDF" => CType::Is(FileType::Pdf),
            "CL_TYPE_ISO9660" => CType::Is(FileType::Iso),
            "CL_TYPE_LHA_LZH" => CType::Is(FileType::Lha),
            "CL_TYPE_ARJ" => CType::Is(FileType::Arj),
            "CL_TYPE_CPIO_OLD" | "CL_TYPE_CPIO_ODC" | "CL_TYPE_CPIO_NEWC" | "CL_TYPE_CPIO_CRC" => {
                CType::Is(FileType::Cpio)
            }
            "CL_TYPE_AR" => CType::Is(FileType::Ar),
            "CL_TYPE_XAR" => CType::Is(FileType::Xar),
            "CL_TYPE_POSIX_TAR" | "CL_TYPE_OLD_TAR" | "CL_TYPE_GNU_TAR" => CType::Is(FileType::Tar),
            _ => CType::Unmodeled,
        }
    }
    fn matches(&self, ft: FileType) -> bool {
        match self {
            CType::Any => true,
            CType::Is(t) => *t == ft,
            CType::Unmodeled => false,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct CdbSig {
    name: String,
    /// Whether the signature came from an unofficial (non-`.cvd`) database. The
    /// `.UNOFFICIAL` suffix is applied at report time (compat mode), not baked in.
    #[serde(default)]
    unofficial: bool,
    ctype: CType,
    csize: Range,
    /// The filename regex source; compiled lazily (regexes aren't serializable,
    /// so the cache stores the pattern and recompiles on first use).
    name_pat: Option<String>,
    #[serde(skip)]
    name_re: std::sync::OnceLock<Option<regex::bytes::Regex>>,
    size_in: Range,
    size_real: Range,
    encrypted: Option<bool>, // None = `*`
    pos: Range,
}

impl CdbSig {
    fn name_matches(&self, name: &[u8]) -> bool {
        match &self.name_pat {
            None => true,
            Some(p) => {
                let re = self
                    .name_re
                    .get_or_init(|| regex::bytes::Regex::new(p).ok());
                re.as_ref().map(|r| r.is_match(name)).unwrap_or(false)
            }
        }
    }
}

/// Metadata of one container member for `.cdb` matching.
pub struct Member<'a> {
    pub name: &'a str,
    pub size_in_container: u64,
    pub size_real: u64,
    pub encrypted: bool,
    /// 1-based position in the container.
    pub pos: u64,
}

#[derive(Default, Serialize, Deserialize)]
pub struct CdbDb {
    sigs: Vec<CdbSig>,
}

impl CdbDb {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn len(&self) -> usize {
        self.sigs.len()
    }
    pub fn is_empty(&self) -> bool {
        self.sigs.is_empty()
    }

    pub fn extend_from_text(&mut self, text: &str) {
        self.extend_from_text_prov(text, false);
    }

    /// As [`CdbDb::extend_from_text`], tagging each parsed signature's
    /// `unofficial` provenance.
    pub fn extend_from_text_prov(&mut self, text: &str, unofficial: bool) {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(mut sig) = parse_cdb(line) {
                sig.unofficial = unofficial;
                self.sigs.push(sig);
            }
        }
    }

    /// Return the first signature that matches the given member of a container
    /// of type `ct`/size `csize`, as `(clean_name, unofficial)`.
    pub fn matches(&self, ct: FileType, csize: u64, m: &Member) -> Option<(String, bool)> {
        for s in &self.sigs {
            if s.ctype.matches(ct)
                && s.csize.matches(csize)
                && s.size_in.matches(m.size_in_container)
                && s.size_real.matches(m.size_real)
                && s.pos.matches(m.pos)
                && s.encrypted.map(|e| e == m.encrypted).unwrap_or(true)
                && s.name_matches(m.name.as_bytes())
            {
                return Some((s.name.clone(), s.unofficial));
            }
        }
        None
    }
}

fn parse_cdb(line: &str) -> Option<CdbSig> {
    let f: Vec<&str> = line.split(':').collect();
    // Name + 9 mandatory fields (Res1, Res2 included); MinFL/MaxFL optional.
    if f.len() < 10 {
        return None;
    }
    let name_pat = {
        let r = f[3].trim();
        if r.is_empty() || r == "*" {
            None
        } else {
            // Validate it compiles now (reject a malformed sig at load), but
            // store the source and compile lazily at match time.
            regex::bytes::Regex::new(r).ok()?;
            Some(r.to_string())
        }
    };
    let encrypted = match f[6].trim() {
        "*" | "" => None,
        "1" => Some(true),
        "0" => Some(false),
        _ => return None,
    };
    Some(CdbSig {
        name: f[0].to_string(),
        unofficial: false,
        ctype: CType::parse(f[1]),
        csize: Range::parse(f[2])?,
        name_pat,
        name_re: std::sync::OnceLock::new(),
        size_in: Range::parse(f[4])?,
        size_real: Range::parse(f[5])?,
        encrypted,
        pos: Range::parse(f[7])?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cdb_matches_zip_member() {
        let mut db = CdbDb::new();
        // Any-size ZIP containing a file named like an invoice .exe, encrypted.
        db.extend_from_text("Test.Cdb:CL_TYPE_ZIP:*:(?i)invoice.*\\.exe:*:*:1:*:*:\n");
        let m = Member {
            name: "Invoice_2024.exe",
            size_in_container: 1000,
            size_real: 4096,
            encrypted: true,
            pos: 1,
        };
        assert_eq!(
            db.matches(FileType::Zip, 5000, &m)
                .map(|(n, _)| n)
                .as_deref(),
            Some("Test.Cdb")
        );
        // Wrong container type -> no match.
        assert!(db.matches(FileType::Tar, 5000, &m).is_none());
        // Not encrypted -> no match (sig requires encrypted=1).
        let m2 = Member {
            encrypted: false,
            ..m_clone(&m)
        };
        assert!(db.matches(FileType::Zip, 5000, &m2).is_none());
    }

    #[test]
    fn cdb_size_and_pos_ranges() {
        let mut db = CdbDb::new();
        db.extend_from_text("R:*:100-200:.*:*:1000-2000:*:2:x:y\n");
        let ok = Member {
            name: "f",
            size_in_container: 50,
            size_real: 1500,
            encrypted: false,
            pos: 2,
        };
        assert_eq!(
            db.matches(FileType::Zip, 150, &ok)
                .map(|(n, _)| n)
                .as_deref(),
            Some("R")
        );
        // container size out of range
        assert!(db.matches(FileType::Zip, 250, &ok).is_none());
        // wrong position
        let bad = Member {
            pos: 3,
            ..m_clone(&ok)
        };
        assert!(db.matches(FileType::Zip, 150, &bad).is_none());
    }

    fn m_clone<'a>(m: &Member<'a>) -> Member<'a> {
        Member {
            name: m.name,
            size_in_container: m.size_in_container,
            size_real: m.size_real,
            encrypted: m.encrypted,
            pos: m.pos,
        }
    }
}
