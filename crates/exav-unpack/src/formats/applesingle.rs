//! AppleSingle and AppleDouble (RFC 1740, appendices A and B).
//!
//! A header, a table of entry descriptors, and the entries stored as they are.
//! The data fork and the resource fork are the members, read where they lie.
//! The other entries (the real name, a comment, icons, dates, Finder and
//! file-system information, and entries applications define) are metadata
//! stored as they are, which the scan of the container's own bytes covers; the
//! real name names the members.
//!
//! ```text
//! magic        u32  0x00051600 AppleSingle, 0x00051607 AppleDouble
//! version      u32  0x00010000 or 0x00020000
//! filler       16 bytes (a home file system name in version 1)
//! entries      u16
//! descriptor   entries times: id u32, offset u32, length u32
//! ```
//!
//! All numbers are big-endian. AppleDouble is the same header without the data
//! fork: the `._name` files macOS writes next to a file on a foreign volume and
//! into `__MACOSX/` in a ZIP, most of which hold only Finder information.
//!
//! A fork that runs past the end of the file is read as far as the file goes,
//! and the read then fails: a fork not read in full is reported.

use std::borrow::Cow;
use std::io::{self, Read};

use crate::source::{ByteSource, Reader};
use crate::stream::{MemberMeta, Visit, emit_range};
use crate::{Budget, Format, LimitHit};

/// The fixed header, up to and including the entry count.
const HEADER: usize = 26;
/// One entry descriptor.
const DESCRIPTOR: usize = 12;

const DATA_FORK: u32 = 1;
const RESOURCE_FORK: u32 = 2;
const REAL_NAME: u32 = 3;

/// The most bytes of a real name read. HFS+ names are at most 255 UTF-16
/// units, so a longer one is not a name.
const NAME_MAX: usize = 1024;

/// The members' name when the file carries no real name.
const UNNAMED: &str = "applefile";

/// One entry descriptor: id, offset, length.
fn descriptor(table: &[u8], i: usize) -> Option<(u32, u64, u64)> {
    let d = crate::bytes::at(table, i.checked_mul(DESCRIPTOR)?, DESCRIPTOR)?;
    let be = |o: usize| u32::from_be_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]]);
    Some((be(0), u64::from(be(4)), u64::from(be(8))))
}

/// A real name as a member name: one path component, no control characters.
/// HFS allows `/` in a name (the Finder shows `:` for it), so it is not a
/// separator here.
fn member_name(raw: &[u8]) -> Option<String> {
    let s: String = String::from_utf8_lossy(raw)
        .chars()
        .filter(|c| !c.is_control())
        .map(|c| if c == '/' || c == '\\' { '_' } else { c })
        .collect();
    let s = s.trim();
    (!s.is_empty() && s != "." && s != "..").then(|| s.to_string())
}

/// The descriptor table the file holds: those of the declared count that are
/// in it whole.
fn table(src: &dyn ByteSource) -> Option<(Cow<'_, [u8]>, usize)> {
    let head = src.window(0, HEADER);
    if head.len() < HEADER || !super::sniff::is(&head, Format::AppleSingle) {
        return None;
    }
    let declared = usize::from(u16::from_be_bytes([head[24], head[25]]));
    let table = src.window(HEADER, declared * DESCRIPTOR);
    let n = table.len() / DESCRIPTOR;
    Some((table, n))
}

/// Walk an AppleSingle or AppleDouble file: its forks, streamed from where
/// they lie.
pub(crate) fn walk(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<()>,
) -> Result<Option<()>, LimitHit> {
    // A header cut short holds no fork: nothing of one is in the file.
    let Some((table, n)) = table(src) else {
        return Ok(None);
    };
    let name = (0..n)
        .filter_map(|i| descriptor(&table, i))
        .find(|&(id, _, _)| id == REAL_NAME)
        .and_then(|(_, off, size)| {
            let off = usize::try_from(off).ok()?;
            let size = usize::try_from(size).ok()?.min(NAME_MAX);
            member_name(&src.window(off, size))
        })
        .unwrap_or_else(|| UNNAMED.to_string());
    for i in 0..n {
        let Some((id, off, size)) = descriptor(&table, i) else {
            continue;
        };
        let name = match id {
            DATA_FORK => name.clone(),
            RESOURCE_FORK => format!("{name}.rsrc"),
            _ => continue,
        };
        if size == 0 {
            continue;
        }
        budget.count_entry()?;
        let mut meta = MemberMeta {
            name,
            comp_size: size,
            size: Some(size),
            ..MemberMeta::default()
        };
        let from = crate::bytes::to_usize(off);
        let mut fork = Fork {
            inner: Reader::range(src, from, from.saturating_add(crate::bytes::to_usize(size))),
            left: size,
        };
        // The declared length: one past the end of the file is reported.
        if let Some(t) = emit_range(&mut meta, (off, size), &mut fork, budget, visit)? {
            return Ok(Some(t));
        }
    }
    Ok(None)
}

/// A fork's bytes, an error where the file ends before the fork does: it was
/// not read in full.
struct Fork<'a> {
    inner: Reader<'a>,
    left: u64,
}

impl Read for Fork<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let want = buf
            .len()
            .min(usize::try_from(self.left).unwrap_or(usize::MAX));
        if want == 0 {
            return Ok(0);
        }
        let n = self.inner.read(&mut buf[..want])?;
        if n == 0 {
            return Err(io::Error::other(
                "AppleSingle fork cut short by the end of the file",
            ));
        }
        self.left -= n as u64;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Limits, Member};

    /// An AppleSingle (`double` false) or AppleDouble file of `entries`, laid
    /// out in order after the descriptor table.
    fn build(double: bool, entries: &[(u32, &[u8])]) -> Vec<u8> {
        let mut out = vec![0x00, 0x05, 0x16, if double { 0x07 } else { 0x00 }];
        out.extend_from_slice(&0x0002_0000u32.to_be_bytes());
        out.extend_from_slice(&[0; 16]);
        out.extend_from_slice(&(entries.len() as u16).to_be_bytes());
        let mut at = HEADER + entries.len() * DESCRIPTOR;
        for (id, data) in entries {
            out.extend_from_slice(&id.to_be_bytes());
            out.extend_from_slice(&(at as u32).to_be_bytes());
            out.extend_from_slice(&(data.len() as u32).to_be_bytes());
            at += data.len();
        }
        for (_, data) in entries {
            out.extend_from_slice(data);
        }
        out
    }

    type Seen = Vec<(String, Vec<u8>)>;

    fn walked(data: &[u8], limits: Limits) -> (Seen, Result<(), LimitHit>) {
        let mut budget = Budget::new(limits);
        let mut seen = Vec::new();
        let end = walk(&data, &mut budget, &mut |meta, content, _| {
            let mut bytes = Vec::new();
            if let Some(Member::Stream(r)) = content {
                r.read_to_end(&mut bytes).unwrap();
            }
            assert!(meta.unsupported.is_none());
            seen.push((meta.name.clone(), bytes));
            None::<()>
        });
        (seen, end.map(|_| ()))
    }

    #[test]
    fn both_forks_come_out_under_the_real_name() {
        let f = build(
            false,
            &[
                (REAL_NAME, b"Read Me"),
                (9, &[0; 32]),
                (DATA_FORK, b"the data fork"),
                (RESOURCE_FORK, b"the resource fork"),
            ],
        );
        let (seen, end) = walked(&f, Limits::default());
        end.unwrap();
        assert_eq!(
            seen,
            vec![
                ("Read Me".to_string(), b"the data fork".to_vec()),
                ("Read Me.rsrc".to_string(), b"the resource fork".to_vec()),
            ]
        );
    }

    #[test]
    fn an_appledouble_file_gives_its_resource_fork() {
        let f = build(true, &[(9, &[0; 32]), (RESOURCE_FORK, b"rsrc")]);
        let (seen, end) = walked(&f, Limits::default());
        end.unwrap();
        assert_eq!(seen, vec![("applefile.rsrc".to_string(), b"rsrc".to_vec())]);
        // Finder information alone: nothing to scan but the file itself.
        let f = build(true, &[(9, &[0; 32])]);
        let (seen, end) = walked(&f, Limits::default());
        end.unwrap();
        assert!(seen.is_empty());
    }

    #[test]
    fn a_real_name_is_one_path_component() {
        assert_eq!(member_name(b"a/b\\c").as_deref(), Some("a_b_c"));
        assert_eq!(member_name(b"..").as_deref(), None);
        assert_eq!(member_name(b"\x01\x02").as_deref(), None);
        assert_eq!(member_name(b" x\n").as_deref(), Some("x"));
        let f = build(false, &[(REAL_NAME, b"../../etc"), (DATA_FORK, b"d")]);
        let (seen, _) = walked(&f, Limits::default());
        assert_eq!(seen[0].0, ".._.._etc");
    }

    /// `(name, bytes read, the read failed, the declared range)` of each fork.
    #[allow(clippy::type_complexity)]
    fn forks(data: &[u8]) -> Vec<(String, Vec<u8>, bool, Option<(u64, u64)>)> {
        let mut seen = Vec::new();
        walk(
            &data,
            &mut Budget::new(Limits::default()),
            &mut |meta, content, _| {
                let mut bytes = Vec::new();
                let mut failed = false;
                if let Some(Member::Stream(r)) = content {
                    failed = r.read_to_end(&mut bytes).is_err();
                }
                seen.push((meta.name.clone(), bytes, failed, meta.range));
                None::<()>
            },
        )
        .unwrap();
        seen
    }

    #[test]
    fn a_fork_past_the_end_is_read_as_far_as_the_file_goes_and_reported() {
        let mut f = build(false, &[(DATA_FORK, b"0123456789")]);
        let at = f.len() - 10;
        f.truncate(f.len() - 4);
        // What the file holds, then a failed read; the range is the declared
        // one, so that the scanner can tell the file ends before it does.
        assert_eq!(
            forks(&f),
            vec![(
                UNNAMED.to_string(),
                b"012345".to_vec(),
                true,
                Some((at as u64, 10))
            )]
        );
        // A fork that starts past the end holds nothing and is reported too.
        f.truncate(at);
        assert_eq!(
            forks(&f),
            vec![(UNNAMED.to_string(), Vec::new(), true, Some((at as u64, 10)))]
        );
    }

    #[test]
    fn a_table_cut_short_gives_the_descriptors_it_holds() {
        let mut f = build(false, &[(DATA_FORK, b"ab"), (RESOURCE_FORK, b"cd")]);
        f[25] = 200;
        let (seen, end) = walked(&f, Limits::default());
        end.unwrap();
        assert_eq!(seen.len(), 2);
        // A header cut short holds nothing.
        let (seen, end) = walked(&f[..20], Limits::default());
        end.unwrap();
        assert!(seen.is_empty());
    }

    #[test]
    fn every_fork_is_counted() {
        let entries: Vec<(u32, &[u8])> = (0..10).map(|_| (DATA_FORK, &b"x"[..])).collect();
        let f = build(false, &entries);
        let limits = Limits {
            max_members: 3,
            ..Limits::default()
        };
        let (seen, end) = walked(&f, limits);
        assert_eq!(seen.len(), 3);
        assert!(!end.unwrap_err().is_corrupt());
    }
}
