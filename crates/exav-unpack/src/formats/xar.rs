//! XAR archive extractor (macOS `.pkg` installers, `.xip` archives, some
//! Safari extensions).
//!
//! Layout: a 28-byte header, a zlib-compressed XML table of contents, then the
//! file heap. The TOC describes each file's data block as an offset/length into
//! the heap plus an encoding style. We parse the header, inflate the TOC, and
//! read each data block from the heap where it is, decoding it as it is read
//! (zlib, bzip2, LZMA), emitting members for the engine to recurse into. A
//! block in any other style is handed over as it is stored, and says so.
//! Neither the archive nor a member is held. The TOC XML is scanned with a
//! small targeted parser rather than a full XML dependency.

use crate::source::{ByteSource, Reader, Sub};
use crate::stream::{MemberMeta, Visit, emit_entry, emit_stream};
use crate::{Budget, Entry, LimitHit};
use flate2::read::ZlibDecoder;
use std::io::{BufReader, Read};

const MAGIC: &[u8] = b"xar!";

/// The magic of an xz file. A block in the `application/x-lzma` style that
/// starts with it is read as xz, not as LZMA-alone.
const XZ_MAGIC: &[u8] = b"\xfd7zXZ\0";

/// What a member says of a block in a style that is not read.
const STYLE_NOT_READ: &str =
    "XAR member in an encoding that is not read; its stored bytes were scanned";

/// How much of what is read from the source for a member is buffered.
const BUFFER: usize = 64 * 1024;

/// The most the table of contents inflates to.
const TOC_CAP: u64 = 64 * 1024 * 1024;

fn be_u16(d: &[u8], p: usize) -> u64 {
    crate::bytes::at(d, p, 2)
        .map(|b| u64::from(u16::from_be_bytes([b[0], b[1]])))
        .unwrap_or(0)
}

fn be_u64(d: &[u8], p: usize) -> u64 {
    crate::bytes::at(d, p, 8)
        .and_then(|b| <[u8; 8]>::try_from(b).ok())
        .map(u64::from_be_bytes)
        .unwrap_or(0)
}

/// Walk a XAR archive. The table of contents is read from the front of the
/// source and each member from its place in the heap.
pub(crate) fn walk(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<()>,
) -> Result<Option<()>, LimitHit> {
    let head = src.window(0, 28);
    if head.len() < 28 || !head.starts_with(MAGIC) {
        return Err(LimitHit::corrupt("xar: bad magic".to_string()));
    }
    let len = src.len();
    let header_size = crate::bytes::to_usize(be_u16(&head, 4));
    let toc_comp = crate::bytes::to_usize(be_u64(&head, 8));
    let toc_uncomp = be_u64(&head, 16);
    let toc_start = header_size;
    let toc_end = toc_start.saturating_add(toc_comp);
    if toc_end > len {
        return Err(LimitHit::corrupt("xar: truncated TOC".to_string()));
    }
    let heap_start = toc_end;

    // Inflate the TOC (bounded by its declared uncompressed size, capped).
    let mut toc = Vec::new();
    crate::source::read_capped(
        &mut ZlibDecoder::new(BufReader::with_capacity(
            BUFFER,
            Reader::range(src, toc_start, toc_end),
        )),
        &mut toc,
        toc_uncomp.min(TOC_CAP),
    )
    .map_err(|e| LimitHit::corrupt(format!("xar: TOC inflate: {e}")))?;
    let toc = String::from_utf8_lossy(&toc);

    for (label, blk) in DataBlocks::new(&toc) {
        let off = heap_start.saturating_add(blk.offset);
        let end = off.saturating_add(blk.length).min(len);
        // A zero-length block has nothing to scan; a block starting past EOF, or
        // one the bound above clamped short, is truncated: the declared bytes
        // are absent from this file rather than hidden in it, so what exists is
        // scanned and a clean result is honest. See docs/QUIRKS.md.
        if off >= len || blk.length == 0 {
            continue;
        }

        budget.count_entry()?;
        let name = member_name(label);
        let raw = BufReader::with_capacity(BUFFER, Reader::range(src, off, end));
        let meta = MemberMeta {
            name: name.clone(),
            comp_size: end.saturating_sub(off) as u64,
            size: Some(blk.size as u64),
            ..MemberMeta::default()
        };
        let found = match blk.style {
            // Heap data is zlib-wrapped.
            Style::Zlib => match crate::inflate::zlib_reader(raw) {
                Ok(Some(mut z)) => emit_stream(&meta, &mut z, budget, &mut *visit)?,
                // Cut inside the zlib header: no byte of the stream is here.
                Err(_) if off.saturating_add(blk.length) > len => {
                    emit_stream(&meta, &mut std::io::empty(), budget, &mut *visit)?
                }
                _ => {
                    // The TOC names this member and its bytes are in the heap;
                    // the stream just would not inflate. Dropping it would leave
                    // a file the archive contains with no trace in the result.
                    emit_entry(
                        Entry::unsupported(
                            name,
                            blk.size as u64,
                            false,
                            "XAR member would not inflate",
                        ),
                        budget,
                        &mut *visit,
                    )?
                }
            },
            Style::Bzip2 => {
                let block = Sub::new(src, off, end - off);
                let mut bz = super::bzip2::content_reader(&block, budget.limits().max_buffer_bytes);
                emit_stream(&meta, &mut bz, budget, &mut *visit)?
            }
            Style::Lzma => {
                let mut lz: Box<dyn Read + '_> =
                    if src.window(off, XZ_MAGIC.len()).as_ref() == XZ_MAGIC {
                        Box::new(super::xz::XzReader::new(raw))
                    } else {
                        super::lzmaalone::content_reader(raw)
                    };
                emit_stream(&meta, &mut *lz, budget, &mut *visit)?
            }
            Style::Stored | Style::Other => {
                let mut meta = meta;
                if blk.style == Style::Other {
                    meta.unsupported = Some(STYLE_NOT_READ);
                }
                let mut raw = raw;
                emit_stream(&meta, &mut raw, budget, &mut *visit)?
            }
        };
        if let Some(r) = found {
            return Ok(Some(r));
        }
    }
    Ok(None)
}

struct Block {
    offset: usize,
    length: usize,
    size: usize,
    style: Style,
}

/// How the bytes of a block are encoded, by the `style` of its `<encoding>`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Style {
    /// `application/octet-stream`, or no encoding named: as they are.
    Stored,
    /// `application/x-gzip` and `application/zlib`: a zlib stream.
    Zlib,
    /// `application/x-bzip2`.
    Bzip2,
    /// `application/x-lzma`: an LZMA-alone stream, or an xz file.
    Lzma,
    /// Any other, which is not read.
    Other,
}

impl Style {
    /// The style of the last `<encoding>` in `block`, the way the last
    /// `<offset>` is the one that counts.
    fn of(block: &str) -> Style {
        let Some(at) = block.rfind("<encoding") else {
            return Style::Stored;
        };
        let tag = &block[at + "<encoding".len()..];
        let tag = tag.split('>').next().unwrap_or(tag);
        match attribute(tag, "style") {
            Some("application/octet-stream") => Style::Stored,
            Some("application/x-gzip" | "application/zlib") => Style::Zlib,
            Some("application/x-bzip2") => Style::Bzip2,
            Some("application/x-lzma") => Style::Lzma,
            _ => Style::Other,
        }
    }
}

/// The value of the attribute `name`, in quotes, in the text of a tag.
fn attribute<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let mut from = 0;
    while let Some(p) = tag[from..].find(name) {
        let at = from + p;
        from = at + name.len();
        // The whole name: white space before it, and an equal sign after it.
        if !tag[..at].ends_with(|c: char| c.is_ascii_whitespace()) {
            continue;
        }
        let Some(value) = tag[from..].trim_start().strip_prefix('=') else {
            continue;
        };
        let value = value.trim_start();
        let quote = value.chars().next().filter(|c| matches!(c, '"' | '\''))?;
        return value[1..].split(quote).next();
    }
    None
}

/// The longest a member's name is taken from the TOC, bytes.
const MAX_NAME: usize = 4096;

/// A member's name: the label of its block, cut to [`MAX_NAME`] bytes.
fn member_name(label: &str) -> String {
    label[..back(label, label.len().min(MAX_NAME), 0)].to_string()
}

/// `at` moved back `n` bytes, then to the start of the character it is in.
fn back(s: &str, at: usize, n: usize) -> usize {
    let mut i = at.saturating_sub(n);
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// The TOC's `<data>` blocks, each paired with the text of the last
/// `<name>...</name>` before it (document order) for a human-readable label.
/// Names are cosmetic for scanning, so an approximate pairing is acceptable.
/// The TOC is read once, whatever the number of blocks.
struct DataBlocks<'a> {
    toc: &'a str,
    /// Where the next `<data>` is looked for.
    search: usize,
    /// The label of the blocks from here on.
    name: &'a str,
    /// `<name>` has been looked for in `toc[..name_scan]`.
    name_scan: usize,
    /// The text of the last `<name>`, while its `</name>` is not found: where
    /// it starts and how far the end has been looked for.
    open: Option<(usize, usize)>,
}

impl<'a> DataBlocks<'a> {
    fn new(toc: &'a str) -> Self {
        DataBlocks {
            toc,
            search: 0,
            name: "xar-file",
            name_scan: 0,
            open: None,
        }
    }
}

impl<'a> Iterator for DataBlocks<'a> {
    type Item = (&'a str, Block);

    fn next(&mut self) -> Option<Self::Item> {
        let toc = self.toc;
        let data_open = self.search + toc[self.search..].find("<data>")?;
        // A `<name>` after those already seen, or one cut by where the last
        // look stopped.
        let from = back(toc, self.name_scan, "<name>".len() - 1);
        if let Some(r) = toc[from..data_open].rfind("<name>") {
            let text = from + r + "<name>".len();
            self.open = Some((text, text));
        }
        self.name_scan = data_open;
        if let Some((text, looked)) = self.open {
            let from = back(toc, looked, "</name>".len() - 1).max(text);
            match toc[from..data_open].find("</name>") {
                Some(r) => {
                    self.name = &toc[text..from + r];
                    self.open = None;
                }
                None => self.open = Some((text, data_open)),
            }
        }
        let data_close = toc[data_open..]
            .find("</data>")
            .map(|r| data_open + r)
            .unwrap_or(toc.len());
        let block = &toc[data_open..data_close];
        let offset = inner_text(block, "offset")
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        let length = inner_text(block, "length")
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        let size = inner_text(block, "size")
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(length);
        let style = Style::of(block);
        // An unterminated `<data>` leaves `data_close == toc.len()`; clamp so the
        // next slice (`toc[search..]`) can never start past the end and panic.
        self.search = (data_close + 1).min(toc.len());
        Some((
            self.name,
            Block {
                offset,
                length,
                size,
                style,
            },
        ))
    }
}

/// Extract the text of the LAST `<tag>...</tag>` in `hay`.
fn inner_text(hay: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = hay.rfind(&open)? + open.len();
    let end = hay[start..].find(&close)? + start;
    Some(hay[start..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Format, Limits, Member, extract};
    use flate2::{Compression, write::ZlibEncoder};
    use std::io::Write;

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// An archive of `members`: name, bytes, and whether they are stored
    /// zlib-compressed in the heap.
    fn archive(members: &[(&str, &[u8], bool)]) -> Vec<u8> {
        let mut heap = Vec::new();
        let mut files = String::new();
        for (name, data, deflate) in members {
            let stored = if *deflate { zlib(data) } else { data.to_vec() };
            let style = if *deflate {
                "application/x-gzip"
            } else {
                "application/octet-stream"
            };
            files.push_str(&format!(
                "<file><name>{name}</name><data><offset>{}</offset><length>{}</length>\
                 <size>{}</size><encoding style=\"{style}\"/></data></file>",
                heap.len(),
                stored.len(),
                data.len()
            ));
            heap.extend_from_slice(&stored);
        }
        let toc_xml = format!("<xar><toc>{files}</toc></xar>");
        let toc_comp = zlib(toc_xml.as_bytes());
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&28u16.to_be_bytes()); // header_size
        buf.extend_from_slice(&1u16.to_be_bytes()); // version
        buf.extend_from_slice(&(toc_comp.len() as u64).to_be_bytes());
        buf.extend_from_slice(&(toc_xml.len() as u64).to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes()); // cksum alg
        buf.extend_from_slice(&toc_comp);
        buf.extend_from_slice(&heap);
        buf
    }

    #[test]
    fn extracts_one_gzip_member() {
        let payload = b"EICAR-ish payload bytes";
        let buf = archive(&[("evil.sh", payload, true)]);
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Xar, &buf, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "evil.sh");
        assert_eq!(entries[0].data, payload);
    }

    /// What `walk` gives of `buf` read from a source that is not in memory,
    /// under a buffer limit of `cap`: each member's name, bytes and whether
    /// it was read as it goes.
    fn off_a_source(buf: &[u8], cap: u64) -> Vec<(String, Vec<u8>, bool)> {
        let cache =
            crate::source::BlockCache::with_sizes(std::io::Cursor::new(buf.to_vec()), 64, 4 * 64)
                .unwrap();
        let mut budget = Budget::new(Limits {
            max_buffer_bytes: cap,
            ..Limits::default()
        });
        let mut out = Vec::new();
        crate::walk(Format::Xar, &cache, &mut budget, &mut |meta, content, _| {
            let (data, streamed) = match content {
                None => (Vec::new(), false),
                Some(Member::Bytes(b)) => (b, false),
                Some(Member::Stream(r)) => {
                    let mut b = Vec::new();
                    r.read_to_end(&mut b).unwrap();
                    (b, true)
                }
            };
            assert!(meta.unsupported.is_none(), "{}", meta.name);
            out.push((meta.name.clone(), data, streamed));
            None::<()>
        })
        .unwrap();
        out
    }

    #[test]
    fn members_are_read_as_they_go_from_a_source_that_is_not_in_memory() {
        let big: Vec<u8> = (0..70_000u32).map(|i| (i * 31 % 251) as u8).collect();
        let buf = archive(&[
            ("deflated.bin", &big, true),
            ("stored.bin", &big, false),
            ("small.txt", b"small", true),
        ]);
        let got = off_a_source(&buf, 100);
        assert_eq!(
            got,
            [
                ("deflated.bin".to_string(), big.clone(), true),
                ("stored.bin".to_string(), big, true),
                ("small.txt".to_string(), b"small".to_vec(), true),
            ]
        );
    }

    #[test]
    fn a_member_cut_short_by_the_end_of_the_archive_comes_out_as_far_as_it_goes() {
        let big: Vec<u8> = (0..70_000u32).map(|i| (i * 31 % 251) as u8).collect();
        let mut buf = archive(&[("stored.bin", &big, false)]);
        buf.truncate(buf.len() - 1000);
        let got = off_a_source(&buf, 100);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].1, big[..big.len() - 1000]);
    }

    /// An archive of the table of contents `toc` and the heap `heap`.
    fn with_toc(toc: &str, heap: &[u8]) -> Vec<u8> {
        let toc_comp = zlib(toc.as_bytes());
        let mut buf = MAGIC.to_vec();
        buf.extend_from_slice(&28u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&(toc_comp.len() as u64).to_be_bytes());
        buf.extend_from_slice(&(toc.len() as u64).to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&toc_comp);
        buf.extend_from_slice(heap);
        buf
    }

    fn names(buf: Vec<u8>) -> Vec<String> {
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Xar, &buf, &mut budget).unwrap();
        entries.into_iter().map(|e| e.name).collect()
    }

    #[test]
    fn a_table_of_many_blocks_is_read_once() {
        // Blocks with no name before them, then a file. Read once this takes
        // milliseconds; a search of the table for each block, minutes. The
        // time allowed is far above the first, and the loop stops at it.
        const BLOCKS: usize = 400_000;
        let mut toc = "<xar><toc>".to_string();
        toc += &"<data></data>".repeat(BLOCKS);
        toc += "<data><offset>0</offset><length>1</length></data></toc></xar>";
        let t = std::time::Instant::now();
        let mut n = 0;
        let mut last = None;
        for (label, block) in DataBlocks::new(&toc) {
            assert_eq!(label, "xar-file");
            assert!(
                t.elapsed().as_secs() < 10,
                "{n} blocks in {:?}",
                t.elapsed()
            );
            n += 1;
            last = Some(block);
        }
        assert_eq!(n, BLOCKS + 1);
        let last = last.unwrap();
        assert_eq!((last.offset, last.length), (0, 1));
    }

    #[test]
    fn a_block_is_named_by_the_last_whole_name_before_it() {
        let file = "<data><offset>0</offset><length>1</length></data>";
        // A name cut by the block, then whole after it; a long name, cut.
        let long = "é".repeat(MAX_NAME);
        let toc = format!(
            "<xar><name>a</name>{file}<name>b{file}</name>{file}<name>{long}</name>{file}</xar>"
        );
        let got = names(with_toc(&toc, b"x"));
        assert_eq!(got[..2], ["a", "a"]);
        assert!(got[2].starts_with("b<data>"), "{}", got[2]);
        assert_eq!(got[3], "é".repeat(MAX_NAME / 2));
    }

    /// An archive whose members are (`<encoding>` element or none, bytes as the
    /// heap holds them).
    fn archive_of(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut heap = Vec::new();
        let mut files = String::new();
        for (i, (encoding, stored)) in members.iter().enumerate() {
            files.push_str(&format!(
                "<file><name>m{i}</name><data><offset>{}</offset><length>{}</length>\
                 <size>{}</size>{encoding}</data></file>",
                heap.len(),
                stored.len(),
                stored.len()
            ));
            heap.extend_from_slice(stored);
        }
        with_toc(&format!("<xar><toc>{files}</toc></xar>"), &heap)
    }

    fn style(s: &str) -> String {
        format!("<encoding style=\"{s}\"/>")
    }

    fn bzip2(data: &[u8]) -> Vec<u8> {
        let mut e = ::bzip2::write::BzEncoder::new(Vec::new(), ::bzip2::Compression::best());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn xz(data: &[u8]) -> Vec<u8> {
        let mut w =
            lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(6)).unwrap();
        w.write_all(data).unwrap();
        w.finish().unwrap()
    }

    const LZMA_ALONE: &[u8] = include_bytes!("../../tests/fixtures/lzma_simple.lzma");
    const LZMA_ALONE_CONTENT: &[u8] = b"hello exav inside lzma";

    /// Each member: its bytes and what it says of itself.
    fn read(buf: &[u8]) -> Vec<(Vec<u8>, Option<&'static str>)> {
        let mut out = Vec::new();
        let mut budget = Budget::new(Limits::default());
        crate::walk(Format::Xar, &buf, &mut budget, &mut |meta, content, _| {
            let data = match content {
                None => Vec::new(),
                Some(Member::Bytes(b)) => b,
                Some(Member::Stream(r)) => {
                    let mut b = Vec::new();
                    r.read_to_end(&mut b).unwrap();
                    b
                }
            };
            out.push((data, meta.unsupported));
            None::<()>
        })
        .unwrap();
        out
    }

    /// A member in the `bzip2` or `LZMA` style is what it decodes to: it is
    /// scanned, not the compressed bytes.
    #[test]
    fn bzip2_and_lzma_members_are_decoded() {
        let big: Vec<u8> = (0..300_000u32).map(|i| (i * 31 % 251) as u8).collect();
        let (bz, lz) = (style("application/x-bzip2"), style("application/x-lzma"));
        let (one, two) = (bzip2(&big), [bzip2(b"first "), bzip2(b"second")].concat());
        let xz_of = xz(&big);
        let buf = archive_of(&[
            (&bz, &one[..]),
            (&bz, &two[..]),
            (&lz, LZMA_ALONE),
            (&lz, &xz_of[..]),
        ]);
        let got = read(&buf);
        assert_eq!(got.len(), 4);
        assert!(got[0].0 == big && got[0].1.is_none());
        assert_eq!(got[1], (b"first second".to_vec(), None));
        assert_eq!(got[2], (LZMA_ALONE_CONTENT.to_vec(), None));
        assert!(got[3].0 == big && got[3].1.is_none());
    }

    /// The same members off a source that is not in memory are read as they
    /// go.
    #[test]
    fn bzip2_and_lzma_members_are_read_as_they_go_from_a_source_not_in_memory() {
        let big: Vec<u8> = (0..70_000u32).map(|i| (i * 31 % 251) as u8).collect();
        let (bz, lz) = (style("application/x-bzip2"), style("application/x-lzma"));
        let (bzipped, xzipped) = (bzip2(&big), xz(&big));
        let buf = archive_of(&[(&bz, &bzipped[..]), (&lz, &xzipped[..]), (&lz, LZMA_ALONE)]);
        let got = off_a_source(&buf, 100);
        assert_eq!(
            got,
            [
                ("m0".to_string(), big.clone(), true),
                ("m1".to_string(), big, true),
                ("m2".to_string(), LZMA_ALONE_CONTENT.to_vec(), true),
            ]
        );
    }

    /// A style that is not read comes out as the bytes the heap holds, and says
    /// it was not read, so that a clean scan of it is not a clean one.
    #[test]
    fn a_style_that_is_not_read_is_reported() {
        for other in [
            "application/x-lzfse",
            "application/x-xz",
            "application/X-GZIP",
            "application/x-gzip ",
            "",
        ] {
            let got = read(&archive_of(&[(style(other).as_str(), b"stored bytes")]));
            assert_eq!(
                got,
                [(b"stored bytes".to_vec(), Some(STYLE_NOT_READ))],
                "{other:?}"
            );
        }
        // An encoding with no style.
        let got = read(&archive_of(&[("<encoding/>", b"stored bytes")]));
        assert_eq!(got, [(b"stored bytes".to_vec(), Some(STYLE_NOT_READ))]);
    }

    /// Stored is a style, and so is none: neither says anything.
    #[test]
    fn stored_members_say_nothing() {
        let got = read(&archive_of(&[
            (style("application/octet-stream").as_str(), b"one"),
            ("", b"two"),
        ]));
        assert_eq!(got, [(b"one".to_vec(), None), (b"two".to_vec(), None)]);
    }

    /// The style is read from the last `<encoding>` of the block, spelt as XML
    /// allows: quotes of either kind, white space around the equal sign.
    #[test]
    fn the_style_is_read_from_the_last_encoding_of_the_block() {
        let z = zlib(b"deflated");
        for tag in [
            "<encoding style='application/x-gzip'/>",
            "<encoding  style = \"application/x-gzip\" ></encoding>",
            "<encoding style=\"application/octet-stream\"/><encoding style=\"application/x-gzip\"/>",
            "<encoding\nstyle=\"application/zlib\"/>",
        ] {
            let got = read(&archive_of(&[(tag, &z)]));
            assert_eq!(got, [(b"deflated".to_vec(), None)], "{tag}");
        }
        // The first one is not the one that counts, and a style named
        // elsewhere in the block is not one.
        let got = read(&archive_of(&[(
            "<encoding style=\"application/x-gzip\"/><encoding style=\"application/octet-stream\"/>",
            b"stored",
        )]));
        assert_eq!(got, [(b"stored".to_vec(), None)]);
        let got = read(&archive_of(&[(
            "<extracted-checksum style=\"application/x-gzip\">0</extracted-checksum>",
            b"stored",
        )]));
        assert_eq!(got, [(b"stored".to_vec(), None)]);
    }

    /// A bzip2 or LZMA member that will not decode is damage, as it is in a file
    /// of its own: the member is not passed as clean.
    #[test]
    fn a_member_that_will_not_decode_is_not_passed_as_clean() {
        for (s, bytes) in [
            (
                "application/x-bzip2",
                &b"BZh9 this is not a bzip2 stream"[..],
            ),
            ("application/x-lzma", &b"not lzma at all, and not xz"[..]),
            ("application/x-lzma", &LZMA_ALONE[..LZMA_ALONE.len() - 4]),
        ] {
            let buf = archive_of(&[(style(s).as_str(), bytes)]);
            let mut budget = Budget::new(Limits::default());
            let r = extract(Format::Xar, &buf, &mut budget);
            let flagged = match r {
                Err(_) => true,
                Ok(entries) => entries.iter().any(|e| e.unsupported.is_some()),
            };
            assert!(flagged, "{s} {bytes:?}");
        }
    }
}
