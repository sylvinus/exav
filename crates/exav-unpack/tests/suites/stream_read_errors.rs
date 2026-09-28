//! A source that fails part way is reported, never read as a short file.
//!
//! The streaming walk reads its container through `Read + Seek`, and for a
//! network range reader a failed read is an ordinary event. Taking it for end
//! of file drops every member past that point without a word.

use exav_unpack::{is_streamable, stream_members, Budget, Format, Limits, MemberMeta};
use std::io::{self, Read, Seek, SeekFrom};

/// Seeks anywhere in `len` bytes; every read fails.
struct Unreadable {
    pos: u64,
    len: u64,
}

impl Read for Unreadable {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("link down"))
    }
}

impl Seek for Unreadable {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        self.pos = match to {
            SeekFrom::Start(p) => p,
            SeekFrom::End(d) => self.len.saturating_add_signed(d),
            SeekFrom::Current(d) => self.pos.saturating_add_signed(d),
        };
        Ok(self.pos)
    }
}

#[test]
fn a_failing_source_is_reported_by_every_streamed_format() {
    let formats = [
        Format::Gzip,
        Format::Tar,
        Format::Bzip2,
        Format::Xz,
        Format::SevenZip,
        Format::Cab,
        Format::Zip,
        Format::Zstd,
        Format::Lzip,
        Format::Lha,
        Format::Ar,
        Format::Cpio,
        Format::Machofat,
        Format::Pyc,
        Format::Sfx,
        Format::Tnef,
        Format::Partition,
        Format::Iso,
        Format::OneNote,
        Format::Swf,
        Format::Szdd,
    ];
    let mut silent = Vec::new();
    for fmt in formats.into_iter().filter(|f| is_streamable(*f)) {
        let mut budget = Budget::new(Limits::default());
        // A member's bytes are read by the visitor, which sees their errors.
        let mut visit = |_: &MemberMeta, r: Option<&mut dyn Read>, _: &mut Budget| {
            io::copy(r?, &mut io::sink()).err().map(|e| e.to_string())
        };
        let src = Unreadable {
            pos: 0,
            len: 1 << 20,
        };
        match stream_members(fmt, src, &mut budget, &mut visit) {
            Err(hit) if hit.reason.contains("link down") => {}
            Ok(Some(seen)) if seen.contains("link down") => {}
            other => silent.push(format!("{fmt:?}: {other:?}")),
        }
    }
    assert!(
        silent.is_empty(),
        "read errors not reported:\n{}",
        silent.join("\n")
    );
}
