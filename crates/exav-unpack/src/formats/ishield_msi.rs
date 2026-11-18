//! The files an InstallShield setup executable carries: the installer MSI and
//! its companions (`Setup.ini`, language tables, `MSIEng.isc`...), from
//! InstallShield 2009 on, behind the PE of the launcher.
//!
//! The layouts and the coding are read as ISx reads them (lifenjoiner, MIT,
//! `ISx.c` v0.3.11, commit 3c4177d; attributed in `NOTICE`):
//!
//! ```text
//! header   "InstallShield\0" or "ISSetupStream\0", a u16 file count, a u32
//!          type, 28 more bytes (46 in all)
//! record   (InstallShield\0) a 260-byte name, a u32 of flags, a u32, the u32
//!          length of the data, 8 bytes, a u16 that is non-zero when the data
//!          is inflated, 30 more bytes (312 in all); then the data
//! record   (ISSetupStream\0) a u32 length of the name in bytes, a u32 of
//!          flags, 2 bytes, the u32 length of the data, 8 bytes, the u16
//!          inflate word (24 in all), 24 more bytes if the type is 4, the
//!          UTF-16 name; then the data
//! ```
//!
//! The records follow one another, each with its data. Flag 4 codes the data
//! in blocks of 1024 bytes, flag 2 (without 4) in one run; flag 0 stores it as
//! it is. A coded byte is its nibbles swapped, XORed with a key byte and
//! inverted; the key is the name with each byte XORed with one of
//! `13 35 86 07` in turn, and starts again at every block (a coded file's
//! position within the block, for flag 4; within the file, for flag 2). Data
//! that is inflated is a zlib stream, after the coding.
//!
//! Members are streamed from where they lie. A file cut short by the end of
//! the installer, a count the records do not reach and an inflate that fails
//! are reported as the reason of a member; none of them reads clean.

use std::io::{self, Read};

use flate2::read::ZlibDecoder;

use super::sniff::IshieldHeader;
use crate::source::{ByteSource, Reader};
use crate::stream::{MemberMeta, Visit, emit_range, emit_stream};
use crate::tree::ReasonKind;
use crate::{Budget, LimitHit};

const HEADER: usize = 46;
const RECORD: usize = 312;
const NAME: usize = 260;
/// The attributes of a record of the second kind, before its name, and the
/// longest name it may have in bytes (260 UTF-16 units).
const STREAM_ATTRIBUTES: usize = 24;
const STREAM_NAME_MAX: usize = 520;
/// Mixed into the name to make a file's key.
const KEY_MIX: [u8; 4] = [0x13, 0x35, 0x86, 0x07];
/// The block a key starts again at, for the coding in blocks.
const BLOCK: u64 = 1024;
const FLAG_WHOLE: u32 = 2;
const FLAG_BLOCKS: u32 = 4;
/// The highest header type the layout above is known for.
const TYPE_MAX: u32 = 4;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Coding {
    Plain,
    Blocks,
    Whole,
}

struct Record {
    name: Vec<u8>,
    coding: Coding,
    /// The length of the data that follows the record.
    len: u32,
    inflated: bool,
}

fn le16(d: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        crate::bytes::at(d, o, 2)?.try_into().ok()?,
    ))
}

fn le32(d: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        crate::bytes::at(d, o, 4)?.try_into().ok()?,
    ))
}

fn coding_of(flags: u32) -> Coding {
    if flags & FLAG_BLOCKS != 0 {
        Coding::Blocks
    } else if flags & FLAG_WHOLE != 0 {
        Coding::Whole
    } else {
        Coding::Plain
    }
}

/// The record at `at` in `src` and where its data starts, `None` when the
/// installer ends before the record does or the record is not one.
/// `kind` and the header's `version` say what a record looks like.
fn record(
    src: &dyn ByteSource,
    at: u64,
    kind: IshieldHeader,
    version: u32,
) -> Option<(Record, u64)> {
    let at_usize = usize::try_from(at).ok()?;
    match kind {
        IshieldHeader::Msi => {
            let w = src.window(at_usize, RECORD);
            if w.len() < RECORD {
                return None;
            }
            let field = &w[..NAME];
            let name = field[..field.iter().position(|&b| b == 0).unwrap_or(NAME)].to_vec();
            let record = Record {
                coding: coding_of(le32(&w, NAME)?),
                len: le32(&w, NAME + 8)?,
                inflated: le16(&w, NAME + 20)? != 0,
                name,
            };
            Some((record, at + RECORD as u64))
        }
        IshieldHeader::Stream => {
            // The 24 bytes of attributes, 24 more in version 4, the name.
            let skip = if version == 4 { 24 } else { 0 };
            let w = src.window(at_usize, STREAM_ATTRIBUTES + skip + STREAM_NAME_MAX);
            let name_len = usize::try_from(le32(&w, 0)?).ok()?;
            if name_len == 0 || !name_len.is_multiple_of(2) || name_len > STREAM_NAME_MAX {
                return None;
            }
            let name_at = STREAM_ATTRIBUTES + skip;
            let units: Vec<u16> = crate::bytes::at(&w, name_at, name_len)?
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .take_while(|&u| u != 0)
                .collect();
            let record = Record {
                coding: coding_of(le32(&w, 4)?),
                len: le32(&w, 10)?,
                inflated: le16(&w, 22)? != 0,
                // The key is made from the name in UTF-8.
                name: String::from_utf16_lossy(&units).into_bytes(),
            };
            Some((record, at + (name_at + name_len) as u64))
        }
    }
}

/// A file's bytes with the coding undone, as they are read.
struct Decoded<'a> {
    raw: Reader<'a>,
    key: Vec<u8>,
    coding: Coding,
    /// Where in `key` the next byte's key byte is.
    at: usize,
    /// How far into its block the next byte is.
    in_block: u64,
}

impl Read for Decoded<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.raw.read(buf)?;
        if self.coding == Coding::Plain {
            return Ok(n);
        }
        for b in &mut buf[..n] {
            *b = !(self.key[self.at] ^ b.rotate_left(4));
            self.at += 1;
            if self.at == self.key.len() {
                self.at = 0;
            }
            self.in_block += 1;
            if self.in_block == BLOCK {
                self.in_block = 0;
                if self.coding == Coding::Blocks {
                    self.at = 0;
                }
            }
        }
        Ok(n)
    }
}

/// The key made from a file's name.
fn key_of(name: &[u8]) -> Vec<u8> {
    name.iter()
        .zip(KEY_MIX.iter().cycle())
        .map(|(a, b)| a ^ b)
        .collect()
}

const CUT: &str = "InstallShield installer file cut short by the end of the installer: \
                   the part there is was scanned";
const NO_KEY: &str = "InstallShield installer file coded with a key made from its name, \
                      which is empty: the stored bytes were scanned as they are";
const RECORDS: &str = "InstallShield installer whose file records cannot be read up to the count \
                       in its header: the files after them were not examined";
const NO_COUNT: &str = "InstallShield installer whose header counts no files, with a file record \
                        after it: that file and any after it were not examined";
const LAYOUT: &str = "InstallShield installer whose header is of a layout exav does not read: \
                      its files were not examined";

/// The member name of a record: its name as the installer gives it, or the
/// place it has in the list when it gives none.
fn member_name(r: &Record, index: usize) -> String {
    if r.name.is_empty() {
        return format!("<file-{index}>");
    }
    String::from_utf8_lossy(&r.name).into_owned()
}

/// Walk an InstallShield installer: each file its records list, coded and
/// inflated as the record says.
pub(crate) fn walk(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<()>,
) -> Result<Option<()>, LimitHit> {
    let head = src.window(0, src.len().min(crate::DETECT_HEAD));
    let Some((start, kind)) = super::sniff::ishield_msi_at(&head) else {
        return Ok(None);
    };
    drop(head);
    read_from(src, start, kind, budget, visit)
}

/// The files of the installer whose header, of `kind`, is at `start` in `src`.
fn read_from(
    src: &dyn ByteSource,
    start: usize,
    kind: IshieldHeader,
    budget: &mut Budget,
    visit: Visit<()>,
) -> Result<Option<()>, LimitHit> {
    let end = src.len() as u64;
    // The typing rule reads past the header, so it is all there.
    let header = src.window(start, HEADER);
    if header.len() < HEADER {
        return Ok(None);
    }
    let version = le32(&header, 16).unwrap_or(u32::MAX);
    if version > TYPE_MAX {
        budget.count_entry()?;
        let meta = MemberMeta {
            name: "ishield-msi".to_string(),
            comp_size: end,
            unsupported: Some(LAYOUT),
            reason_kind: Some(ReasonKind::Unsupported),
            ..MemberMeta::default()
        };
        return Ok(visit(&meta, None, budget));
    }
    let count = usize::from(le16(&header, 14).unwrap_or(0));
    if count == 0 {
        // The typing rule found a file record after this header.
        budget.count_entry()?;
        let meta = MemberMeta {
            name: "<ishield-msi-records>".to_string(),
            unsupported: Some(NO_COUNT),
            ..MemberMeta::default()
        };
        return Ok(visit(&meta, None, budget));
    }
    let mut at = start as u64 + HEADER as u64;
    let mut listed = 0usize;
    for index in 0..count {
        let Some((r, data_at)) = record(src, at, kind, version) else {
            break;
        };
        listed += 1;
        budget.count_entry()?;
        let len = u64::from(r.len);
        // What of the data the installer holds.
        let present = end.saturating_sub(data_at).min(len);
        let cut = present < len;
        let mut meta = MemberMeta {
            name: member_name(&r, index),
            comp_size: len,
            size: (!r.inflated && !cut).then_some(len),
            unsupported: cut.then_some(CUT),
            ..MemberMeta::default()
        };
        let key = key_of(&r.name);
        // A coded file with no name has no key: its bytes are what is there.
        let keyless = r.coding != Coding::Plain && key.is_empty();
        if keyless {
            meta.unsupported = Some(NO_KEY);
        }
        let coding = if keyless { Coding::Plain } else { r.coding };
        let inflate = r.inflated && !keyless;
        let from = usize::try_from(data_at).unwrap_or(usize::MAX);
        let to = usize::try_from(data_at + present).unwrap_or(usize::MAX);
        let raw = Reader::range(src, from, to);
        let stop = if coding == Coding::Plain && !inflate {
            // Stored as it stands: a range of the installer.
            let mut raw = raw;
            emit_range(&mut meta, (data_at, len), &mut raw, budget, visit)?
        } else {
            let mut stream: Box<dyn Read + '_> = Box::new(Decoded {
                raw,
                key,
                coding,
                at: 0,
                in_block: 0,
            });
            if inflate {
                stream = Box::new(ZlibDecoder::new(stream));
            }
            emit_stream(&meta, &mut stream, budget, visit)?
        };
        if let Some(t) = stop {
            return Ok(Some(t));
        }
        if cut {
            return Ok(None);
        }
        at = data_at + len;
    }
    if listed < count {
        budget.count_entry()?;
        let meta = MemberMeta {
            name: "<ishield-msi-records>".to_string(),
            unsupported: Some(RECORDS),
            ..MemberMeta::default()
        };
        return Ok(visit(&meta, None, budget));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Format, Limits, Member};
    use std::io::Write;

    /// One file of an installer the tests build.
    pub(crate) struct Spec<'a> {
        pub name: &'a str,
        pub data: &'a [u8],
        pub coding: Coding,
        pub inflate: bool,
    }

    pub(crate) fn file<'a>(name: &'a str, data: &'a [u8]) -> Spec<'a> {
        Spec {
            name,
            data,
            coding: Coding::Plain,
            inflate: false,
        }
    }

    /// A file as InstallShield 2009 to 2011 write them: coded in blocks, and inflated.
    pub(crate) fn packed<'a>(name: &'a str, data: &'a [u8]) -> Spec<'a> {
        Spec {
            coding: Coding::Blocks,
            inflate: true,
            ..file(name, data)
        }
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// `data` coded as an installer codes it.
    fn encode(name: &str, data: &[u8], coding: Coding) -> Vec<u8> {
        let key = key_of(name.as_bytes());
        data.iter()
            .enumerate()
            .map(|(i, &b)| {
                let at = match coding {
                    Coding::Blocks => i as u64 % BLOCK,
                    _ => i as u64,
                };
                (key[(at % key.len() as u64) as usize] ^ !b).rotate_left(4)
            })
            .collect()
    }

    /// The header and records of `files`, with `count` as the count.
    pub(crate) fn records(count: u16, files: &[Spec]) -> Vec<u8> {
        let mut out = b"InstallShield\0".to_vec();
        out.extend_from_slice(&count.to_le_bytes());
        out.resize(HEADER, 0);
        for f in files {
            let stored = if f.inflate {
                zlib(f.data)
            } else {
                f.data.to_vec()
            };
            let stored = match f.coding {
                Coding::Plain => stored,
                coding => encode(f.name, &stored, coding),
            };
            let mut r = vec![0u8; RECORD];
            r[..f.name.len()].copy_from_slice(f.name.as_bytes());
            let flags: u32 = match f.coding {
                Coding::Plain => 0,
                Coding::Whole => FLAG_WHOLE,
                Coding::Blocks => FLAG_WHOLE | FLAG_BLOCKS,
            };
            r[NAME..NAME + 4].copy_from_slice(&flags.to_le_bytes());
            r[NAME + 8..NAME + 12].copy_from_slice(&(stored.len() as u32).to_le_bytes());
            r[NAME + 20] = u8::from(f.inflate);
            out.extend_from_slice(&r);
            out.extend_from_slice(&stored);
        }
        out
    }

    /// The header and records of `files` in the layout of InstallShield 2015
    /// and later: `ISSetupStream\0`, UTF-16 names, the type `version`.
    fn stream_records(version: u32, files: &[Spec]) -> Vec<u8> {
        let mut out = b"ISSetupStream\0".to_vec();
        out.extend_from_slice(&(files.len() as u16).to_le_bytes());
        out.extend_from_slice(&version.to_le_bytes());
        out.resize(HEADER, 0);
        for f in files {
            let stored = if f.inflate {
                zlib(f.data)
            } else {
                f.data.to_vec()
            };
            let stored = match f.coding {
                Coding::Plain => stored,
                coding => encode(f.name, &stored, coding),
            };
            let name: Vec<u8> = f.name.encode_utf16().flat_map(u16::to_le_bytes).collect();
            let flags: u32 = match f.coding {
                Coding::Plain => 0,
                Coding::Whole => FLAG_WHOLE,
                Coding::Blocks => FLAG_WHOLE | FLAG_BLOCKS,
            };
            let mut attributes = vec![0u8; STREAM_ATTRIBUTES];
            attributes[..4].copy_from_slice(&(name.len() as u32).to_le_bytes());
            attributes[4..8].copy_from_slice(&flags.to_le_bytes());
            attributes[10..14].copy_from_slice(&(stored.len() as u32).to_le_bytes());
            attributes[22] = u8::from(f.inflate);
            out.extend_from_slice(&attributes);
            if version == 4 {
                out.extend_from_slice(&[0u8; 24]);
            }
            out.extend_from_slice(&name);
            out.extend_from_slice(&stored);
        }
        out
    }

    /// A setup executable of the second layout.
    fn build_stream(version: u32, files: &[Spec]) -> Vec<u8> {
        let mut out = b"MZ".to_vec();
        out.resize(STUB, 0x90);
        out.extend(stream_records(version, files));
        out
    }

    /// Where the installer starts in what [`build`] makes.
    const STUB: usize = 0x1000;

    /// A setup executable: a stub, then the installer.
    pub(crate) fn build(files: &[Spec]) -> Vec<u8> {
        let mut out = b"MZ".to_vec();
        out.resize(STUB, 0x90);
        out.extend(records(files.len() as u16, files));
        out
    }

    type Seen = Vec<(String, Vec<u8>, Option<&'static str>, bool)>;

    /// The members of the installer in `data`: name, bytes, reason, and
    /// whether the bytes were read to their end.
    fn walked(data: &[u8], limits: Limits) -> (Seen, Result<(), LimitHit>) {
        let mut budget = Budget::new(limits);
        let mut seen = Vec::new();
        let kind = if data.get(STUB..STUB + 2) == Some(b"IS".as_slice()) {
            IshieldHeader::Stream
        } else {
            IshieldHeader::Msi
        };
        let end = read_from(&data, STUB, kind, &mut budget, &mut |meta, content, _| {
            let mut bytes = Vec::new();
            let mut whole = true;
            if let Some(Member::Stream(r)) = content {
                whole = r.read_to_end(&mut bytes).is_ok();
            }
            seen.push((meta.name.clone(), bytes, meta.unsupported, whole));
            None::<()>
        });
        (seen, end.map(|_| ()))
    }

    fn payload(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 7 % 251) as u8).collect()
    }

    #[test]
    fn every_coding_gives_its_files() {
        let big = payload(5000);
        let files = [
            file("plain.ini", b"[Startup]"),
            Spec {
                coding: Coding::Blocks,
                ..file("blocks.bin", &big)
            },
            Spec {
                coding: Coding::Whole,
                ..file("whole.bin", &big[..3000])
            },
            Spec {
                inflate: true,
                ..file("inflated.bin", &big)
            },
            packed("both.msi", &big),
        ];
        let (seen, end) = walked(&build(&files), Limits::default());
        end.unwrap();
        let want: Seen = files
            .iter()
            .map(|f| (f.name.to_string(), f.data.to_vec(), None, true))
            .collect();
        assert_eq!(seen, want);
    }

    /// The key restarts at each block for the coding in blocks and runs on
    /// for the other: a file of two blocks and a bit shows which.
    #[test]
    fn the_key_restarts_at_a_block_only_for_the_coding_in_blocks() {
        let data = payload(2 * 1024 + 100);
        for coding in [Coding::Blocks, Coding::Whole] {
            let f = [Spec {
                coding,
                ..file("a.bin", &data)
            }];
            let (seen, end) = walked(&build(&f), Limits::default());
            end.unwrap();
            assert_eq!(seen[0].1, data);
        }
        // A name whose key is 5 bytes: 1024 is not a multiple of it.
        let name = "abcde";
        let blocks = [Spec {
            coding: Coding::Blocks,
            ..file(name, &data)
        }];
        let mut as_whole = build(&blocks);
        let flags_at = 0x1000 + HEADER + NAME;
        as_whole[flags_at] = FLAG_WHOLE as u8;
        let (seen, _) = walked(&as_whole, Limits::default());
        assert_ne!(
            seen[0].1, data,
            "read as one run, the blocks decode wrongly"
        );
        assert_eq!(
            &seen[0].1[..1024],
            &data[..1024],
            "the first block is the same"
        );
    }

    /// The key is made from the file's name, so a name that is changed after
    /// the data is coded gives a stream that does not inflate.
    #[test]
    fn a_name_that_is_not_the_one_the_file_was_coded_under_gives_no_stream() {
        let data = payload(4000);
        let mut bytes = build(&[packed("setup.msi", &data)]);
        bytes[0x1000 + HEADER] = b'S';
        let (seen, _) = walked(&bytes, Limits::default());
        assert_eq!(seen.len(), 1);
        assert!(!seen[0].3, "the inflate fails");
        assert!(seen[0].1.is_empty());
    }

    #[test]
    fn a_coded_file_with_no_name_is_reported_and_its_bytes_scanned() {
        let data = payload(300);
        let mut bytes = build(&[Spec {
            coding: Coding::Blocks,
            ..file("x", &data)
        }]);
        // The name is gone.
        bytes[0x1000 + HEADER] = 0;
        let (seen, end) = walked(&bytes, Limits::default());
        end.unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, "<file-0>");
        assert_eq!(seen[0].1.len(), 300);
        assert!(seen[0].2.is_some_and(|r| r.contains("empty")));
    }

    #[test]
    fn a_file_cut_by_the_end_is_reported_with_what_is_there() {
        let big = payload(5000);
        let files = [
            Spec {
                coding: Coding::Whole,
                ..file("a.bin", &big)
            },
            file("b.bin", b"never reached"),
        ];
        let bytes = build(&files);
        let cut = &bytes[..bytes.len() - 13 - 1000];
        let (seen, end) = walked(cut, Limits::default());
        end.unwrap();
        assert_eq!(seen.len(), 1, "{seen:?}");
        assert_eq!(seen[0].0, "a.bin");
        let got = seen[0].1.len();
        assert!(got < big.len() && got > 3000, "{got}");
        assert_eq!(seen[0].1, big[..got]);
        assert!(seen[0].2.is_some_and(|r| r.contains("cut short")));
    }

    #[test]
    fn a_length_past_the_end_costs_nothing() {
        let mut bytes = build(&[file("a.bin", b"abc")]);
        let at = 0x1000 + HEADER + NAME + 8;
        bytes[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        let (seen, end) = walked(&bytes, Limits::default());
        end.unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].1, b"abc");
        assert!(seen[0].2.is_some_and(|r| r.contains("cut short")));
    }

    #[test]
    fn a_count_the_records_do_not_reach_is_reported() {
        let files = [packed("a.msi", b"one"), file("b.ini", b"two")];
        let mut bytes = build(&files);
        bytes[0x1000 + 14..0x1000 + 16].copy_from_slice(&u16::MAX.to_le_bytes());
        let (seen, end) = walked(&bytes, Limits::default());
        end.unwrap();
        let names: Vec<&str> = seen.iter().map(|s| s.0.as_str()).collect();
        assert_eq!(names, ["a.msi", "b.ini", "<ishield-msi-records>"]);
        assert!(
            seen[2]
                .2
                .is_some_and(|r| r.contains("cannot be read up to the count"))
        );
        // A count the records meet exactly reports nothing more.
        let (seen, _) = walked(&build(&files), Limits::default());
        assert_eq!(seen.len(), 2);
    }

    /// The second layout, of versions 3 and 4, with a name that is not ASCII
    /// (the key is made from it in UTF-8).
    #[test]
    fn the_layout_of_the_setup_stream_gives_its_files() {
        let big = payload(5000);
        for version in [3, 4] {
            let files = [
                packed("Setup.msi", &big),
                Spec {
                    coding: Coding::Whole,
                    ..file("\u{e9}t\u{e9}.bin", &big[..3000])
                },
                file("Setup.ini", b"[Startup]"),
            ];
            let bytes = build_stream(version, &files);
            assert_eq!(crate::detect(&bytes), Some(Format::IshieldMsi), "{version}");
            let (seen, end) = walked(&bytes, Limits::default());
            end.unwrap();
            let want: Seen = files
                .iter()
                .map(|f| (f.name.to_string(), f.data.to_vec(), None, true))
                .collect();
            assert_eq!(seen, want, "version {version}");
            let mut by_walk = Vec::new();
            walk(
                &&bytes[..],
                &mut Budget::new(Limits::default()),
                &mut |m, _, _| {
                    by_walk.push(m.name.clone());
                    None::<()>
                },
            )
            .unwrap();
            assert_eq!(by_walk.len(), 3);
        }
    }

    /// The name of the second layout that is not a name, or a count of none,
    /// is not an installer; one that is cut is reported.
    #[test]
    fn the_setup_stream_tag_needs_a_header_that_holds() {
        let files = [packed("a.msi", b"one")];
        let good = build_stream(3, &files);
        assert_eq!(crate::detect(&good), Some(Format::IshieldMsi));
        for (what, at, value) in [
            ("no files", STUB + 14, 0u8),
            ("a type of 9", STUB + 16, 9),
            ("an odd name length", STUB + HEADER, 7),
            (
                "a control character in the name",
                STUB + HEADER + STREAM_ATTRIBUTES,
                1,
            ),
        ] {
            let mut bytes = good.clone();
            bytes[at] = value;
            assert_ne!(crate::detect(&bytes), Some(Format::IshieldMsi), "{what}");
        }
        // A record that cannot be read leaves files uncounted, and says so.
        let two = build_stream(3, &[packed("a.msi", b"one"), file("b.ini", b"two")]);
        let mut cut = two.clone();
        cut.truncate(cut.len() - 20);
        let (seen, end) = walked(&cut, Limits::default());
        end.unwrap();
        assert!(seen.iter().any(|s| s.2.is_some()), "{seen:?}");
    }

    #[test]
    fn a_header_that_counts_no_file_before_a_record_is_reported() {
        let mut bytes = build(&[packed("a.msi", b"one")]);
        bytes[STUB + 14..STUB + 16].copy_from_slice(&0u16.to_le_bytes());
        let (seen, end) = walked(&bytes, Limits::default());
        end.unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, "<ishield-msi-records>");
        assert!(seen[0].2.is_some_and(|r| r.contains("counts no files")));
    }

    #[test]
    fn a_header_of_another_type_is_reported_not_read() {
        let mut bytes = build(&[packed("a.msi", b"one")]);
        bytes[0x1000 + 16] = 9;
        let (seen, end) = walked(&bytes, Limits::default());
        end.unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, "ishield-msi");
        assert!(seen[0].2.is_some());
    }

    #[test]
    fn an_installer_is_typed_behind_its_stub_and_nothing_else_is() {
        let bytes = build(&[packed("a.msi", b"one"), file("b.ini", b"two")]);
        assert_eq!(crate::detect(&bytes), Some(Format::IshieldMsi));
        // The tag alone, in resources, does not type a file.
        let mut stub = b"MZ".to_vec();
        stub.resize(0x1000, 0x90);
        stub.extend_from_slice(b"InstallShield\0 and nothing after it");
        assert_ne!(crate::detect(&stub), Some(Format::IshieldMsi));
        // A first file that is not coded and inflated is not the layout.
        assert_ne!(
            crate::detect(&build(&[file("a.ini", b"one")])),
            Some(Format::IshieldMsi)
        );
    }

    #[test]
    fn a_decoy_before_the_header_does_not_hide_it() {
        let mut bytes = b"MZ".to_vec();
        bytes.resize(0x800, 0x90);
        bytes.extend_from_slice(b"InstallShield\0 in a resource\0");
        bytes.resize(0x1000, 0x90);
        bytes.extend(records(1, &[packed("a.msi", b"hello")]));
        let mut seen = Vec::new();
        walk(
            &&bytes[..],
            &mut Budget::new(Limits::default()),
            &mut |meta, content, _| {
                let mut got = Vec::new();
                if let Some(Member::Stream(r)) = content {
                    r.read_to_end(&mut got).unwrap();
                }
                seen.push((meta.name.clone(), got));
                None::<()>
            },
        )
        .unwrap();
        assert_eq!(seen, vec![("a.msi".to_string(), b"hello".to_vec())]);
    }

    #[test]
    fn an_installer_on_disk_is_read_where_it_lies() {
        let big = payload(300_000);
        let bytes = build(&[packed("a.msi", &big), file("b.ini", b"two")]);
        let (want, _) = walked(&bytes, Limits::default());
        let cached =
            crate::source::BlockCache::with_sizes(io::Cursor::new(bytes.clone()), 512, 4096)
                .unwrap();
        let mut budget = Budget::new(Limits::default());
        let mut seen = Vec::new();
        crate::walk(
            Format::IshieldMsi,
            &cached,
            &mut budget,
            &mut |meta, content, _| {
                let mut got = Vec::new();
                let mut whole = true;
                if let Some(Member::Stream(r)) = content {
                    whole = r.read_to_end(&mut got).is_ok();
                }
                seen.push((meta.name.clone(), got, meta.unsupported, whole));
                None::<()>
            },
        )
        .unwrap();
        assert_eq!(seen, want);
        assert_eq!(seen[0].1, big);
    }

    /// A few bytes that inflate to far more than the ratio allows are a bomb,
    /// not a file: the member is left out and the next one is read, and the
    /// walk ends with the limit.
    #[test]
    fn an_inflate_bomb_is_left_and_the_walk_goes_on() {
        let zeros = vec![0u8; 50 << 20];
        let bytes = build(&[packed("bomb.msi", &zeros), file("after.ini", b"two")]);
        let mut budget = Budget::new(Limits {
            max_compression_ratio: 100,
            max_buffer_bytes: 1 << 20,
            ..Limits::default()
        });
        let mut seen = Vec::new();
        let end = crate::walk(
            Format::IshieldMsi,
            &bytes,
            &mut budget,
            &mut |meta, content, _| {
                let mut got = Vec::new();
                if let Some(Member::Stream(r)) = content {
                    let _ = r.read_to_end(&mut got);
                }
                seen.push((meta.name.clone(), got));
                None::<()>
            },
        );
        let reason = end.unwrap_err().reason;
        assert!(reason.contains("compression ratio"), "{reason}");
        assert_eq!(
            seen.last().unwrap(),
            &("after.ini".to_string(), b"two".to_vec())
        );
    }

    /// An installer is typed as one whatever else its bytes hold.
    #[test]
    #[cfg(feature = "screnc")]
    fn an_installer_is_typed_before_the_marker_searches() {
        let mut bytes = build(&[packed("a.msi", b"hello"), file("b.ini", b"two")]);
        bytes.extend_from_slice(b"#@~^");
        assert_eq!(crate::detect(&bytes), Some(Format::IshieldMsi));
        // Held in memory or not, as `detect` reads an object of either kind.
        let cached =
            crate::source::BlockCache::with_sizes(io::Cursor::new(bytes), 512, 4096).unwrap();
        assert_eq!(crate::detect(&cached), Some(Format::IshieldMsi));
    }

    #[test]
    fn a_stored_file_is_a_range_of_the_installer() {
        let bytes = build(&[file("a.ini", b"[Startup]")]);
        let mut budget = Budget::new(Limits::default());
        let mut range = None;
        read_from(
            &&bytes[..],
            STUB,
            IshieldHeader::Msi,
            &mut budget,
            &mut |meta, _, _| {
                range = meta.range;
                None::<()>
            },
        )
        .unwrap();
        let at = STUB + HEADER + RECORD;
        assert_eq!(range, Some((at as u64, 9)));
        assert_eq!(&bytes[at..at + 9], b"[Startup]");
    }
}
