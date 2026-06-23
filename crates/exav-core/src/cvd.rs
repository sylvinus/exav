//! CVD/CLD signature-container parsing.
//!
//! A `.cvd` is a 512-byte ASCII header followed by a gzip-compressed tar of
//! database files (`*.ndb`, `*.hdb`, `*.hsb`, `*.ldb`, ...). A `.cld` is the
//! same header followed by an uncompressed tar. [`read`] returns the header
//! and the contained files for the loaders to consume.

use std::io::Cursor;

use crate::unpack::{bounded_read, Budget, Limits};

/// Parsed CVD header fields (colon-separated, first 512 bytes).
#[derive(Debug, Clone)]
pub struct CvdHeader {
    pub build_time: String,
    pub version: u32,
    pub signatures: u32,
    pub functionality_level: u32,
    pub md5: String,
    pub builder: String,
}

/// Parse the 512-byte `ClamAV-VDB:` header.
/// Layout: `ClamAV-VDB:btime:version:sigs:flevel:md5:dsig:builder:stime`.
pub fn parse_header(head: &[u8]) -> Result<CvdHeader, String> {
    if head.len() < 512 || !head.starts_with(b"ClamAV-VDB:") {
        return Err("not a CVD/CLD header".into());
    }
    let text = String::from_utf8_lossy(&head[..512]);
    let fields: Vec<&str> = text.trim_end().split(':').collect();
    if fields.len() < 7 {
        return Err(format!("malformed CVD header ({} fields)", fields.len()));
    }
    Ok(CvdHeader {
        build_time: fields[1].to_string(),
        version: fields[2].trim().parse().unwrap_or(0),
        signatures: fields[3].trim().parse().unwrap_or(0),
        functionality_level: fields[4].trim().parse().unwrap_or(0),
        md5: fields[5].to_string(),
        builder: fields.get(7).unwrap_or(&"").to_string(),
    })
}

/// A database file extracted from a CVD/CLD.
pub struct DbFile {
    pub name: String,
    pub data: Vec<u8>,
}

/// Bounds applied while extracting a CVD/CLD, to contain malformed or
/// hostile containers (the database is attacker-controllable in the threat
/// model).
#[derive(Debug, Clone)]
pub struct CvdLimits {
    /// Cap on the decompressed tar payload.
    pub max_tar_bytes: u64,
    /// Cap on the summed size of all extracted members.
    pub max_total_bytes: u64,
    /// Cap on the number of members.
    pub max_files: usize,
}

impl Default for CvdLimits {
    fn default() -> Self {
        // Generous enough for a real-world main.cvd (its decompressed
        // members total a few hundred MB) while still bounding a hostile or
        // malformed container.
        Self {
            max_tar_bytes: 2 * 1024 * 1024 * 1024,
            max_total_bytes: 2 * 1024 * 1024 * 1024,
            max_files: 100_000,
        }
    }
}

/// Read a CVD/CLD: parse the header and extract the contained db files.
pub fn read(data: &[u8]) -> Result<(CvdHeader, Vec<DbFile>), String> {
    read_with_limits(data, &CvdLimits::default())
}

/// As [`read`], with explicit bounds.
pub fn read_with_limits(
    data: &[u8],
    limits: &CvdLimits,
) -> Result<(CvdHeader, Vec<DbFile>), String> {
    let header = parse_header(data)?;
    let payload = &data[512..];

    // CVD payload is gzip-compressed; CLD is a raw tar. Bounded so an
    // oversized payload is rejected rather than silently truncated.
    let tar_bytes: Vec<u8> = if payload.starts_with(&[0x1f, 0x8b]) {
        use flate2::read::GzDecoder;
        let (out, truncated) =
            bounded_read(GzDecoder::new(Cursor::new(payload)), limits.max_tar_bytes)
                .map_err(|e| format!("cvd gunzip: {e}"))?;
        if truncated {
            return Err(format!(
                "cvd payload exceeds {} bytes",
                limits.max_tar_bytes
            ));
        }
        out
    } else {
        if payload.len() as u64 > limits.max_tar_bytes {
            return Err(format!(
                "cvd payload exceeds {} bytes",
                limits.max_tar_bytes
            ));
        }
        payload.to_vec()
    };

    // Reuse the archive budget for per-member size/count accounting (no
    // ratio or per-member cap beyond the shared total).
    let mut budget = Budget::new(Limits {
        max_recursion: 0,
        max_files: limits.max_files as u64,
        max_total_bytes: limits.max_total_bytes,
        max_ratio: u64::MAX,
        max_entry_bytes: limits.max_total_bytes,
    });

    let mut archive = tar::Archive::new(Cursor::new(tar_bytes));
    let mut files = Vec::new();
    for entry in archive.entries().map_err(|e| format!("cvd tar: {e}"))? {
        budget.count_entry().map_err(|h| h.reason)?;
        let mut entry = entry.map_err(|e| format!("cvd tar entry: {e}"))?;
        let name = entry
            .path()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        let cap = budget.reserve().map_err(|h| h.reason)?;
        let (buf, truncated) =
            bounded_read(&mut entry, cap).map_err(|e| format!("cvd read {name}: {e}"))?;
        if truncated {
            return Err(format!(
                "cvd members exceed {} bytes total",
                limits.max_total_bytes
            ));
        }
        budget.commit(buf.len() as u64);
        files.push(DbFile { name, data: buf });
    }
    Ok((header, files))
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    fn make_cvd() -> Vec<u8> {
        // Build a tiny tar with one .ndb file.
        let mut tar_buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_buf);
            let content = b"Test.Sig:0:*:deadbeef\n";
            let mut hdr = tar::Header::new_gnu();
            hdr.set_size(content.len() as u64);
            hdr.set_mode(0o644);
            hdr.set_cksum();
            builder
                .append_data(&mut hdr, "test.ndb", &content[..])
                .unwrap();
            builder.finish().unwrap();
        }
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&tar_buf).unwrap();
        let payload = gz.finish().unwrap();

        let mut header = "ClamAV-VDB:01 Jan 2026 00-00 +0000:58:1234:90:abcdef0123456789:dsig:exav-test:1700000000".to_string()
        .into_bytes();
        header.resize(512, b' ');
        header.extend_from_slice(&payload);
        header
    }

    #[test]
    fn parse_and_extract() {
        let cvd = make_cvd();
        let (hdr, files) = read(&cvd).unwrap();
        assert_eq!(hdr.version, 58);
        assert_eq!(hdr.signatures, 1234);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "test.ndb");
        assert!(files[0].data.starts_with(b"Test.Sig"));
    }

    #[test]
    fn rejects_non_cvd() {
        assert!(read(b"not a cvd").is_err());
    }

    fn cvd_with(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar_buf = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tar_buf);
            for (name, content) in members {
                let mut h = tar::Header::new_gnu();
                h.set_size(content.len() as u64);
                h.set_mode(0o644);
                h.set_cksum();
                b.append_data(&mut h, name, *content).unwrap();
            }
            b.finish().unwrap();
        }
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&tar_buf).unwrap();
        let payload = gz.finish().unwrap();
        let mut header =
            "ClamAV-VDB:01 Jan 2026 00-00 +0000:58:3:90:abcdef0123456789:dsig:exav-test:1700000000"
                .to_string()
                .into_bytes();
        header.resize(512, b' ');
        header.extend_from_slice(&payload);
        header
    }

    // Regression for the per-entry-only budget (review finding C1): the
    // summed member size must be bounded, not just each member.
    #[test]
    fn total_member_budget_enforced() {
        let big = vec![b'A'; 100];
        let cvd = cvd_with(&[("a.ndb", &big), ("b.ndb", &big), ("c.ndb", &big)]);
        let limits = CvdLimits {
            max_total_bytes: 150,
            ..Default::default()
        };
        assert!(read_with_limits(&cvd, &limits).is_err());
        assert!(read(&cvd).is_ok()); // default limits accept it
    }
}
