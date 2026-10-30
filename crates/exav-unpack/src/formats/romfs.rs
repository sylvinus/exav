//! romfs: the files of an image, read where they lie.
//!
//! The smallest read-only filesystem Linux has, of boot floppies and the
//! firmware of small devices: nothing is compressed, so a file is the bytes
//! after its header. The image is a `Read + Seek`, read where the walk goes.
//! Only a file is ever held, bounded by the buffer limit.
//!
//! ```text
//! "-rom1fs-"  size  checksum  volume name         padded to 16 bytes
//! file header (16 bytes)   next header and type, a directory's first entry
//!                          (or a link's target), size, checksum
//!   name (null-ended, padded to 16), then the data (padded to 16)
//! ```
//!
//! All numbers are big-endian. A directory is the list of headers that its
//! first entry begins and each one's next header goes on with. A hard link is
//! read as the file it names. A symbolic link or a device node holds no file's
//! bytes and is not emitted. The checksums are not checked.

// Every sum and product on a header's number is checked or saturating here; a
// plain one fails the build, so the next edit cannot add the unchecked kind.
#![deny(clippy::arithmetic_side_effects)]

use std::collections::HashSet;
use std::io::{Read, Seek};

use super::vol::{Attrs, Emit, Got, List, Piece, Pieces, Vol, be32, give, read_file};
use crate::source::{ByteSource, Reader};
use crate::stream::Visit;
use crate::{Budget, LimitHit};

/// The most directories a path passes through.
const MAX_DEPTH: usize = 256;

/// The longest a name is, bytes.
const MAX_NAME: usize = 1024;

/// How many hard links are followed to a file.
const MAX_LINKS: usize = 8;

/// The kinds of header.
const HARD_LINK: u32 = 0;
const DIRECTORY: u32 = 1;
const FILE: u32 = 2;

/// Whether `data`, the start of an image, holds the name romfs begins with.
pub(crate) fn is_romfs(data: &[u8]) -> bool {
    super::sniff::is(data, crate::Format::Romfs)
}

/// A file header.
struct Header {
    kind: u32,
    executable: bool,
    next: u64,
    spec: u64,
    size: u64,
    name: String,
    /// Where the data begins.
    data: u64,
}

/// The next multiple of 16.
fn align(n: u64) -> u64 {
    n.saturating_add(15) & !15
}

/// The header at `at`.
fn header(v: &mut Vol, at: u64) -> Option<Header> {
    let h = v.at(at, 16)?;
    let word = be32(&h, 0);
    let mut name = Vec::new();
    let mut pos = at.checked_add(16)?;
    loop {
        let chunk = v.at(pos, 16)?;
        match chunk.iter().position(|&b| b == 0) {
            Some(end) => {
                name.extend_from_slice(&chunk[..end]);
                break;
            }
            None => name.extend_from_slice(&chunk),
        }
        if name.len() > MAX_NAME {
            return None;
        }
        pos = pos.checked_add(16)?;
    }
    // The name and its null end, padded to 16 bytes.
    let data = at
        .checked_add(16)?
        .checked_add(align((name.len() as u64).saturating_add(1)))?;
    Some(Header {
        kind: word & 7,
        executable: word & 8 != 0,
        next: u64::from(word & !15),
        spec: u64::from(be32(&h, 4)),
        size: u64::from(be32(&h, 8)),
        name: String::from_utf8_lossy(&name).into_owned(),
        data,
    })
}

/// The entries of the directory whose first header is at `first`: header and
/// place. The flag is false where the list is damaged. `left` counts the
/// headers the walk may still read.
fn entries(v: &mut Vol, first: u64, left: &mut u64, limit: usize) -> (Vec<(u64, Header)>, bool) {
    let mut out = Vec::new();
    let mut at = first;
    let mut seen = HashSet::new();
    while at != 0 {
        if *left == 0 || !seen.insert(at) {
            return (out, false);
        }
        *left = left.saturating_sub(1);
        let Some(h) = header(v, at) else {
            return (out, false);
        };
        let next = h.next;
        if h.name != "." && h.name != ".." {
            if out.len() >= limit {
                return (out, true);
            }
            out.push((at, h));
        }
        at = next;
    }
    (out, true)
}

/// The bytes of a file whose header is `h`: held when they are at most `cap`,
/// else read as they go.
fn file<'a>(v: &'a mut Vol<'_>, h: &Header, cap: u64) -> Got<'a> {
    let plan = List {
        pieces: vec![Piece::Disk(h.data, h.size)].into_iter(),
        intact: true,
    };
    read_file(v, Pieces::new(plan, h.size), h.size, cap)
}

/// Walk a romfs image given whole as a source.
pub(crate) fn walk<T>(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<T>,
) -> Result<Option<T>, LimitHit> {
    super::volumes::entries(budget, visit, "", |budget, sink| {
        walk_volume(Reader::new(src), src.len() as u64, budget, sink)
    })
}

/// Walk the romfs image `disk`, which is `len` bytes long, handing each file
/// to `visit`.
pub(crate) fn walk_volume<D: Read + Seek, R>(
    mut disk: D,
    len: u64,
    budget: &mut Budget,
    visit: Emit<R>,
) -> Result<Option<R>, LimitHit> {
    let max = crate::bytes::to_usize(budget.limits().max_buffer_bytes);
    let mut v = Vol {
        disk: &mut disk,
        len,
        max,
    };
    let head = v
        .at(0, crate::bytes::to_usize(len.min(64)))
        .unwrap_or_default();
    if !is_romfs(&head) {
        return Ok(None);
    }
    // Nothing is read from past the size the image says it has.
    v.len = v.len.min(u64::from(be32(&head, 8)));
    // The volume name, padded to 16 bytes, and then the header of the root.
    let name_end = head
        .get(16..)
        .and_then(|n| n.iter().position(|&b| b == 0))
        .unwrap_or(0);
    let root_at = 16u64.saturating_add(align((name_end as u64).saturating_add(1)));
    let Some(root) = header(&mut v, root_at).filter(|r| r.kind == DIRECTORY) else {
        return Err(LimitHit::corrupt(
            "romfs open: the root directory is unreadable".into(),
        ));
    };

    // One more than the member limit, so the entry past it is counted and the
    // walk stops there rather than ending short.
    let limit = crate::bytes::to_usize(budget.limits().max_members).saturating_add(1);
    // The headers of an image are disjoint, 16 bytes at the least each.
    let mut left = v.len / 16;
    let mut damaged = false;
    let mut seen: HashSet<u64> = HashSet::from([root.spec]);
    let mut stack = vec![(root.spec, String::new(), 0usize)];
    while let Some((first, prefix, depth)) = stack.pop() {
        let (list, intact) = entries(&mut v, first, &mut left, limit);
        damaged |= !intact;
        let mut below = Vec::new();
        for (_, h) in list {
            budget.count_entry()?;
            let path = if prefix.is_empty() {
                h.name.clone()
            } else {
                format!("{prefix}/{}", h.name)
            };
            // A hard link is the file it names.
            let mut target = h;
            let mut hops = 0usize;
            while target.kind == HARD_LINK && hops < MAX_LINKS {
                hops = hops.saturating_add(1);
                match header(&mut v, target.spec) {
                    Some(t) => {
                        target = Header {
                            name: target.name,
                            ..t
                        };
                    }
                    None => {
                        damaged = true;
                        break;
                    }
                }
            }
            // Links that lead only to links lead nowhere.
            if target.kind == HARD_LINK {
                damaged = true;
                continue;
            }
            match target.kind {
                DIRECTORY => {
                    if depth >= MAX_DEPTH {
                        damaged = true;
                    } else if seen.insert(target.spec) {
                        below.push((target.spec, path, depth.saturating_add(1)));
                    }
                }
                FILE => {
                    let attrs = Attrs {
                        mode: Some(if target.executable {
                            0o100755
                        } else {
                            0o100644
                        }),
                        mtime: None,
                    };
                    if let Some(r) = give(budget, &mut *visit, path, attrs, |cap| {
                        file(&mut v, &target, cap)
                    })? {
                        return Ok(Some(r));
                    }
                }
                // A link or a node holds no file's bytes.
                _ => {}
            }
        }
        stack.extend(below.into_iter().rev());
    }
    if damaged {
        return Err(LimitHit::corrupt(
            "romfs walk: the image is damaged; the files before the damage were scanned".into(),
        ));
    }
    Ok(None)
}

// The tests lay out their inputs by index arithmetic on small constants.
#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::super::vol::collected;
    use super::*;
    use crate::Limits;
    use std::io::Cursor;

    /// An image being written: headers at the places it is told.
    struct Img(Vec<u8>);

    impl Img {
        fn new() -> Img {
            let mut d = vec![0u8; 32];
            d[..8].copy_from_slice(b"-rom1fs-");
            d[16] = b'T';
            Img(d)
        }

        /// A header at `at` (which must be a multiple of 16), its data after
        /// the name; the place after it.
        fn put(
            &mut self,
            at: usize,
            next: u32,
            kind: u32,
            spec: u32,
            name: &str,
            data: &[u8],
        ) -> usize {
            let end = at + 16 + (name.len() + 1).div_ceil(16) * 16 + data.len().div_ceil(16) * 16;
            if self.0.len() < end.max(at + 16) {
                self.0.resize(end.max(at + 16), 0);
            }
            self.0[at..at + 4].copy_from_slice(&(next | kind).to_be_bytes());
            self.0[at + 4..at + 8].copy_from_slice(&spec.to_be_bytes());
            self.0[at + 8..at + 12].copy_from_slice(&(data.len() as u32).to_be_bytes());
            self.0[at + 16..at + 16 + name.len()].copy_from_slice(name.as_bytes());
            let d = at + 16 + (name.len() + 1).div_ceil(16) * 16;
            self.0[d..d + data.len()].copy_from_slice(data);
            end
        }

        fn finish(mut self) -> Vec<u8> {
            let n = self.0.len() as u32;
            self.0[8..12].copy_from_slice(&n.to_be_bytes());
            self.0
        }
    }

    type Member = (String, Vec<u8>, Option<&'static str>);

    fn walked(d: &[u8], limits: Limits) -> (Vec<Member>, Result<(), LimitHit>) {
        let mut out = Vec::new();
        let mut budget = Budget::new(limits);
        let len = d.len() as u64;
        let end = walk_volume(Cursor::new(d), len, &mut budget, &mut |e, _| {
            let e = e.whole();
            out.push((e.name, e.data, e.unsupported));
            None::<()>
        });
        (out, end.map(|_| ()))
    }

    /// A root (`.` at 32, `..` at 64, and the entries from 96) with a file `a`
    /// ("hi"), a folder `d` holding a file `b`, and a link `l` to `a`.
    fn tree() -> Img {
        let mut img = Img::new();
        img.put(32, 64, DIRECTORY, 32, ".", b"");
        img.put(64, 96, DIRECTORY, 32, "..", b"");
        // a at 96 (data after the name: 96 + 16 + 16 + 16 = 144), d at 144.
        img.put(96, 144, FILE, 0, "a", b"hi");
        img.put(144, 224, DIRECTORY, 176, "d", b"");
        // d's entries from 176: `.` is not listed, `b` is.
        img.put(176, 0, FILE, 0, "b", b"in d");
        // The link follows d in the root's list, after d's entries.
        img.put(224, 0, HARD_LINK, 96, "l", b"");
        img
    }

    #[test]
    fn the_files_of_a_tree_come_out_and_a_hard_link_is_the_file_it_names() {
        let (e, end) = walked(&tree().finish(), Limits::default());
        end.unwrap();
        let mut got: Vec<_> = e.iter().map(|m| (m.0.as_str(), m.1.as_slice())).collect();
        got.sort();
        assert_eq!(
            got,
            [("a", &b"hi"[..]), ("d/b", &b"in d"[..]), ("l", &b"hi"[..])]
        );
    }

    #[test]
    fn a_list_that_comes_back_to_a_header_ends_with_the_files_before_it() {
        let mut img = tree();
        // a's next is a.
        img.0[96..100].copy_from_slice(&(96u32 | FILE).to_be_bytes());
        let (e, end) = walked(&img.finish(), Limits::default());
        assert!(end.unwrap_err().is_corrupt());
        assert_eq!(e.iter().map(|m| m.0.as_str()).collect::<Vec<_>>(), ["a"]);
    }

    #[test]
    fn a_folder_that_lists_the_folder_it_is_in_is_walked_once() {
        let mut img = tree();
        // d's first entry is the root's first: its list is the root's.
        img.0[148..152].copy_from_slice(&96u32.to_be_bytes());
        let (e, end) = walked(&img.finish(), Limits::default());
        end.unwrap();
        let names: Vec<_> = e.iter().map(|m| m.0.as_str()).collect();
        assert_eq!(
            names.iter().filter(|n| n.ends_with('a')).count(),
            2,
            "{names:?}"
        );
        assert!(names.len() < 8, "{names:?}");
    }

    #[test]
    fn links_that_lead_only_to_links_end_the_walk_as_damaged() {
        let mut img = Img::new();
        img.put(32, 64, DIRECTORY, 32, ".", b"");
        img.put(64, 96, DIRECTORY, 32, "..", b"");
        img.put(96, 128, HARD_LINK, 128, "x", b"");
        img.put(128, 0, HARD_LINK, 96, "y", b"");
        let (e, end) = walked(&img.finish(), Limits::default());
        assert!(e.is_empty());
        assert!(end.unwrap_err().is_corrupt());
    }

    #[test]
    fn a_file_longer_than_the_image_is_reported_with_what_there_is() {
        let mut img = tree();
        img.0[96 + 8..96 + 12].copy_from_slice(&5000u32.to_be_bytes());
        let (e, end) = walked(&img.finish(), Limits::default());
        end.unwrap();
        let a = e.iter().find(|m| m.0 == "a").unwrap();
        assert_eq!(a.2, Some("file could not be read from the volume"));
    }

    #[test]
    fn the_entry_past_the_member_limit_is_counted_and_stops_the_walk() {
        let run = |max: u64| {
            let limits = Limits {
                max_members: max,
                ..Limits::default()
            };
            walked(&tree().finish(), limits)
        };
        // a, d, b and l.
        let (e, end) = run(4);
        end.unwrap();
        assert_eq!(e.len(), 3);
        let (_, end) = run(3);
        assert!(!end.unwrap_err().is_corrupt());
    }

    #[test]
    fn a_file_over_the_buffer_limit_is_read_as_it_goes_and_the_walk_goes_on() {
        let limits = Limits {
            max_buffer_bytes: 3,
            ..Limits::default()
        };
        let (held, _) = walked(&tree().finish(), Limits::default());
        let img = tree().finish();
        let len = img.len() as u64;
        let mut budget = Budget::new(limits);
        let (e, end) = collected(|emit| walk_volume(Cursor::new(&img[..]), len, &mut budget, emit));
        end.unwrap();
        // The same files, the same bytes, the long ones not held.
        assert_eq!(e.len(), held.len());
        for ((entry, streamed), (name, data, _)) in e.iter().zip(&held) {
            assert_eq!((&entry.name, &entry.data), (name, data));
            assert_eq!(*streamed, data.len() > 3, "{name}");
            assert_eq!(entry.unsupported, None, "{name}");
        }
        assert!(e.iter().any(|(_, streamed)| *streamed));
    }
}
