//! A volume read at the offsets its own structures give, for the filesystem
//! readers that walk one in place (NTFS, HFS+, APFS).

// Every sum and product on a header's number is checked or saturating here; a
// plain one fails the build, so the next edit cannot add the unchecked kind.
#![deny(clippy::arithmetic_side_effects)]
// Each build has the filesystems its features give it.
#![allow(dead_code)]

use std::cell::Cell;
use std::io::{self, Read, SeekFrom};
use std::rc::Rc;

use crate::{Budget, Entry, Mtime};

pub(crate) use crate::stream::Disk;

/// How much of the volume one read asks of it at once.
pub(crate) const STEP: usize = 1 << 20;

/// The volume, read at offsets the filesystem's own numbers give.
pub(crate) struct Vol<'a> {
    pub(crate) disk: &'a mut dyn Disk,
    pub(crate) len: u64,
    /// The most an on-disk structure (a table, an attribute list) is read
    /// whole: the buffer limit. Only NTFS reads whole structures of any size.
    pub(crate) max: usize,
}

impl Vol<'_> {
    /// `len` bytes at `off`, or `None` when they are not all in the volume.
    pub(crate) fn at(&mut self, off: u64, len: usize) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        self.append(off, len, &mut out).then_some(out)
    }

    /// Append `len` bytes at `off` to `out`, if they are all in the volume.
    /// They are read a step at a time, so what is held grows with what is read.
    pub(crate) fn append(&mut self, off: u64, len: usize, out: &mut Vec<u8>) -> bool {
        let Some(end) = off.checked_add(len as u64) else {
            return false;
        };
        if end > self.len || self.disk.seek(SeekFrom::Start(off)).is_err() {
            return false;
        }
        let base = out.len();
        let mut done = 0usize;
        while done < len {
            let step = len.saturating_sub(done).min(STEP);
            let from = base.saturating_add(done);
            out.resize(from.saturating_add(step), 0);
            if self.disk.read_exact(&mut out[from..]).is_err() {
                out.truncate(base);
                return false;
            }
            done = done.saturating_add(step);
        }
        true
    }
}

/// Why a file is reported when the volume does not give all of it and nothing
/// more is known.
pub(crate) const UNREADABLE: &str = "file could not be read from the volume";

/// What reading a file of a volume came to.
pub(crate) enum Got<'a> {
    Whole(Vec<u8>),
    /// What could be read of a file that breaks part way, and why it does.
    Partial(Vec<u8>, &'static str),
    /// A file held as [`Got::Whole`] or [`Got::Partial`] are (with why it
    /// breaks), that many of whose bytes are holes.
    Sparse(Vec<u8>, u64, Option<&'static str>),
    /// A file too long to hold, of that many bytes, to be read as it goes. It
    /// fails with an error where the volume stops giving its bytes. The cell
    /// counts the bytes of holes it has given.
    Stream(Box<dyn Read + 'a>, u64, Rc<Cell<u64>>),
    /// Longer than a member may be, of that many bytes, and not a file this
    /// reader can read as it goes: reported, and the walk goes on.
    Big(u64),
    Why(&'static str),
    /// Stored encrypted.
    Locked(&'static str),
}

impl Got<'_> {
    /// The member for the file at `path`. A file to be read as it goes is not
    /// one: [`give`] hands it over before it gets here.
    pub(crate) fn entry(self, path: String) -> Entry {
        match self {
            Got::Whole(d) => Entry::new(path, d),
            Got::Sparse(d, holes, why) => Entry {
                unsupported: why,
                holes,
                ..Entry::new(path, d)
            },
            Got::Partial(d, why) => Entry {
                unsupported: Some(why),
                ..Entry::new(path, d)
            },
            Got::Stream(_, size, _) => {
                Entry::unsupported(path, size, false, "file was not read as it goes")
            }
            Got::Big(size) => {
                Entry::over_limit(path, size, "file exceeds the per-member size budget")
            }
            Got::Why(why) => Entry::unsupported(path, 0, false, why),
            Got::Locked(why) => Entry::unsupported(path, 0, true, why),
        }
    }
}

/// A file a filesystem walker hands over.
pub(crate) enum Found<'a> {
    /// A member held whole.
    Held(Entry),
    /// A member read as it goes: its name, mode and time in the entry, which
    /// has no data, the reader of its bytes, and the count of the bytes of
    /// holes it has given.
    Read(Entry, &'a mut dyn Read, Rc<Cell<u64>>),
}

impl Found<'_> {
    /// The member whole, a file read as it goes read to its end, or to 32 MiB:
    /// a damaged volume can give a file of any length, holes and all.
    #[cfg(test)]
    pub(crate) fn whole(self) -> Entry {
        match self {
            Found::Held(e) => e,
            Found::Read(mut e, r, _) => {
                if let Err(err) = r.take(32 << 20).read_to_end(&mut e.data) {
                    e.unsupported = Some(Box::leak(err.to_string().into_boxed_str()));
                }
                e
            }
        }
    }
}

/// What a filesystem walker hands each file to.
pub(crate) type Emit<'a> = &'a mut dyn FnMut(Found<'_>, &mut Budget) -> Option<crate::Stop>;

/// What one step of producing a file's bytes came to.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    /// Bytes were appended, and there may be more.
    More,
    /// The file is over.
    End,
    /// The volume does not give the rest of the file, for that reason.
    Broken(&'static str),
}

/// The bytes of a file, produced a piece at a time.
pub(crate) trait Fill {
    /// Append the next bytes of the file to `out`, at most [`STEP`] of them
    /// (a file stored in units, one unit, which is within the buffer limit).
    /// Those of one call are all of a hole or none.
    fn fill(&mut self, v: &mut Vol, out: &mut Vec<u8>) -> Step;

    /// The bytes of holes appended so far.
    fn holes(&self) -> u64 {
        0
    }
}

/// A file read to its end where it is as long as `size`, which is held, so
/// it is within what a member may hold. What was read stays where the
/// volume stops giving more.
pub(crate) fn drain<'a>(fill: &mut dyn Fill, v: &mut Vol, size: u64) -> Got<'a> {
    let mut out = Vec::new();
    let end = loop {
        match fill.fill(v, &mut out) {
            Step::More => {}
            other => break other,
        }
    };
    let why = match end {
        Step::End if out.len() as u64 == size => None,
        Step::Broken(why) => Some(why),
        _ => Some(UNREADABLE),
    };
    match (fill.holes(), why) {
        (0, None) => Got::Whole(out),
        (0, Some(why)) => Got::Partial(out, why),
        (holes, why) => Got::Sparse(out, holes, why),
    }
}

/// A file of `size` bytes: held when it is within `cap`, else read as it goes.
#[inline]
pub(crate) fn read_file<'a, 'b, F: Fill + 'a>(
    v: &'a mut Vol<'b>,
    fill: F,
    size: u64,
    cap: u64,
) -> Got<'a>
where
    'b: 'a,
{
    read_boxed(v, Box::new(fill), size, cap)
}

/// [`read_file`], the one compiled copy.
fn read_boxed<'a, 'b>(
    v: &'a mut Vol<'b>,
    mut fill: Box<dyn Fill + 'a>,
    size: u64,
    cap: u64,
) -> Got<'a>
where
    'b: 'a,
{
    if size <= cap {
        return drain(&mut *fill, v, size);
    }
    let holes = Rc::new(Cell::new(0));
    Got::Stream(
        Box::new(Streamed {
            v,
            fill,
            buf: Vec::new(),
            at: 0,
            step: Step::More,
            hole: false,
            holes: Rc::clone(&holes),
        }),
        size,
        holes,
    )
}

/// A [`Fill`] as a `Read`.
struct Streamed<'a, 'b> {
    v: &'a mut Vol<'b>,
    fill: Box<dyn Fill + 'a>,
    buf: Vec<u8>,
    at: usize,
    step: Step,
    /// `buf` is a hole.
    hole: bool,
    /// The bytes of holes given so far.
    holes: Rc<Cell<u64>>,
}

impl Read for Streamed<'_, '_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            if let Some(rest) = self.buf.get(self.at..).filter(|r| !r.is_empty()) {
                let n = rest.len().min(out.len());
                out[..n].copy_from_slice(&rest[..n]);
                self.at = self.at.saturating_add(n);
                if self.hole {
                    self.holes.set(self.holes.get().saturating_add(n as u64));
                }
                return Ok(n);
            }
            match self.step {
                Step::End => return Ok(0),
                Step::Broken(why) => {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, why));
                }
                Step::More => {
                    self.buf.clear();
                    self.at = 0;
                    let before = self.fill.holes();
                    self.step = self.fill.fill(self.v, &mut self.buf);
                    self.hole = self.fill.holes() > before;
                }
            }
        }
    }
}

/// A stretch of a file.
#[derive(Clone, Copy)]
pub(crate) enum Piece {
    /// `len` bytes at `off` of the volume.
    Disk(u64, u64),
    /// `len` bytes of zeros: a hole, or what was never written.
    Zeros(u64),
}

/// What a [`Plan`] gives next.
pub(crate) enum Next {
    Piece(Piece),
    End,
    /// The volume does not say where the rest of the file is.
    Broken,
}

/// Where the stretches of a file are, in order, found as they are wanted.
pub(crate) trait Plan {
    fn next(&mut self, v: &mut Vol) -> Next;
}

/// A [`Plan`]'s stretches as the first `left` bytes of a file.
pub(crate) struct Pieces<'a> {
    plan: Box<dyn Plan + 'a>,
    left: u64,
    cur: Option<Piece>,
    holes: u64,
}

impl<'a> Pieces<'a> {
    pub(crate) fn new(plan: impl Plan + 'a, size: u64) -> Self {
        Pieces {
            plan: Box::new(plan),
            left: size,
            cur: None,
            holes: 0,
        }
    }
}

impl Fill for Pieces<'_> {
    fn holes(&self) -> u64 {
        self.holes
    }

    fn fill(&mut self, v: &mut Vol, out: &mut Vec<u8>) -> Step {
        if self.left == 0 {
            return Step::End;
        }
        let piece = match self.cur.take() {
            Some(p) => p,
            None => match self.plan.next(v) {
                Next::Piece(p) => p,
                // The file is longer than what the volume says it holds.
                Next::End | Next::Broken => return Step::Broken(UNREADABLE),
            },
        };
        let (Piece::Disk(_, len) | Piece::Zeros(len)) = piece;
        let take = len.min(self.left).min(STEP as u64);
        let n = crate::bytes::to_usize(take);
        let read = match piece {
            Piece::Disk(off, _) => v.append(off, n, out),
            Piece::Zeros(_) => {
                out.resize(out.len().saturating_add(n), 0);
                self.holes = self.holes.saturating_add(take);
                true
            }
        };
        if !read {
            return Step::Broken(UNREADABLE);
        }
        self.left = self.left.saturating_sub(take);
        // What is left of the piece, if any.
        let left = len.saturating_sub(take);
        if left > 0 {
            self.cur = Some(match piece {
                Piece::Disk(off, _) => Piece::Disk(off.saturating_add(take), left),
                Piece::Zeros(_) => Piece::Zeros(left),
            });
        }
        Step::More
    }
}

/// A plan that is a list of stretches, with a flag for whether the list is
/// whole where it ends.
pub(crate) struct List {
    pub(crate) pieces: std::vec::IntoIter<Piece>,
    pub(crate) intact: bool,
}

impl Plan for List {
    fn next(&mut self, _: &mut Vol) -> Next {
        match self.pieces.next() {
            Some(p) => Next::Piece(p),
            None if self.intact => Next::End,
            None => Next::Broken,
        }
    }
}

/// What a volume records of a file besides its bytes.
#[derive(Clone, Copy, Default)]
pub(crate) struct Attrs {
    /// `st_mode`.
    pub(crate) mode: Option<u32>,
    pub(crate) mtime: Option<Mtime>,
}

/// The file at `path`, read under the bounds a member has and handed to
/// `visit`: held when it fits, else read as it goes. The caller has counted
/// the member.
#[inline]
pub(crate) fn give<'a>(
    budget: &mut Budget,
    visit: Emit,
    path: String,
    attrs: Attrs,
    read: impl FnOnce(u64) -> Got<'a>,
) -> crate::Extracted {
    let cap = budget.reserve()?;
    Ok(hand(budget, visit, path, attrs, read(cap)))
}

/// What a volume gave of the file at `path`, handed to `visit`. The caller has
/// counted the member.
pub(crate) fn hand(
    budget: &mut Budget,
    visit: Emit,
    path: String,
    attrs: Attrs,
    got: Got<'_>,
) -> Option<crate::Stop> {
    let (mut entry, mut stream) = match got {
        Got::Stream(reader, size, holes) => {
            let mut e = Entry::new(path, Vec::new());
            e.comp_size = size;
            (e, Some((reader, holes)))
        }
        other => (other.entry(path), None),
    };
    entry.mode = attrs.mode;
    entry.mtime = attrs.mtime;
    match stream.as_mut() {
        Some((reader, holes)) => visit(Found::Read(entry, &mut **reader, Rc::clone(holes)), budget),
        None => {
            budget.commit(entry.data.len() as u64);
            visit(Found::Held(entry), budget)
        }
    }
}

/// The integer of `N` bytes at `off`, or 0 where the data ends: a record is
/// length-checked once, and its fields are then read without a check each.
fn field<const N: usize>(d: &[u8], off: usize) -> [u8; N] {
    crate::bytes::at(d, off, N)
        .and_then(|b| b.try_into().ok())
        .unwrap_or([0; N])
}

pub(crate) fn be16(d: &[u8], off: usize) -> u16 {
    u16::from_be_bytes(field(d, off))
}

pub(crate) fn be32(d: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(field(d, off))
}

pub(crate) fn be64(d: &[u8], off: usize) -> u64 {
    u64::from_be_bytes(field(d, off))
}

pub(crate) fn le16(d: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(field(d, off))
}

pub(crate) fn le32(d: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(field(d, off))
}

pub(crate) fn le64(d: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(field(d, off))
}

/// What a walk handed over, each member whole with whether it was read as it
/// goes, and what the walk returned. For the readers' tests.
#[cfg(test)]
pub(crate) fn collected<T>(run: impl FnOnce(Emit) -> T) -> (Vec<(Entry, bool)>, T) {
    let mut out = Vec::new();
    let end = run(&mut |found, _| {
        let streamed = matches!(found, Found::Read(..));
        out.push((found.whole(), streamed));
        None
    });
    (out, end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn a_read_is_all_in_the_volume_or_absent() {
        let mut c = Cursor::new((0u8..10).collect::<Vec<_>>());
        let mut v = Vol {
            disk: &mut c,
            len: 10,
            max: 1 << 20,
        };
        assert_eq!(v.at(2, 3), Some(vec![2, 3, 4]));
        assert_eq!(v.at(10, 0), Some(vec![]));
        assert_eq!(v.at(8, 3), None, "past the end");
        assert_eq!(v.at(u64::MAX, 2), None, "the sum overflows");
        let mut out = vec![9];
        assert!(!v.append(8, 3, &mut out));
        assert_eq!(out, [9], "a failed append leaves what was there");
    }

    fn plan(pieces: Vec<Piece>, intact: bool) -> List {
        List {
            pieces: pieces.into_iter(),
            intact,
        }
    }

    #[test]
    fn a_file_longer_than_a_step_is_read_in_steps_across_disk_and_holes() {
        let data: Vec<u8> = (0..STEP * 2 + 100).map(|i| (i % 251) as u8).collect();
        let mut c = Cursor::new(data.clone());
        let mut v = Vol {
            disk: &mut c,
            len: data.len() as u64,
            max: 1 << 20,
        };
        let size = (data.len() + STEP + 5) as u64;
        let pieces = vec![
            Piece::Disk(0, data.len() as u64),
            Piece::Zeros(STEP as u64 + 5),
        ];
        let got = read_file(&mut v, Pieces::new(plan(pieces, true), size), size, 10);
        let Got::Stream(mut r, n, holes) = got else {
            panic!("not read as it goes");
        };
        assert_eq!(n, size);
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        let mut want = data;
        want.resize(size as usize, 0);
        assert!(out == want, "the bytes differ");
        // The bytes of the hole are counted as given, the others not.
        assert_eq!(holes.get(), STEP as u64 + 5);
    }

    #[test]
    fn a_file_the_volume_stops_giving_is_read_up_to_there_and_then_fails() {
        let mut c = Cursor::new(vec![7u8; 100]);
        let mut v = Vol {
            disk: &mut c,
            len: 100,
            max: 1 << 20,
        };
        // The file is 300 bytes, and the volume has the first 100 of them.
        for pieces in [
            plan(vec![Piece::Disk(0, 100)], false),
            plan(vec![Piece::Disk(0, 100), Piece::Disk(100, 200)], true),
        ] {
            let got = read_file(&mut v, Pieces::new(pieces, 300), 300, 10);
            let Got::Stream(mut r, _, _) = got else {
                panic!("not read as it goes");
            };
            let mut out = Vec::new();
            let err = r.read_to_end(&mut out).expect_err("the end is not there");
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert_eq!(out, vec![7u8; 100]);
        }
    }

    #[test]
    fn a_file_within_the_limit_is_held_whole_or_short() {
        let mut c = Cursor::new(vec![7u8; 100]);
        let mut v = Vol {
            disk: &mut c,
            len: 100,
            max: 1 << 20,
        };
        let whole = read_file(
            &mut v,
            Pieces::new(plan(vec![Piece::Disk(0, 60)], true), 60),
            60,
            60,
        );
        assert!(matches!(&whole, Got::Whole(d) if *d == vec![7u8; 60]));
        drop(whole);
        // A file longer than what the plan holds is short, not whole.
        let short = read_file(
            &mut v,
            Pieces::new(plan(vec![Piece::Disk(0, 60)], true), 80),
            80,
            80,
        );
        assert!(matches!(short, Got::Partial(d, why) if d == vec![7u8; 60] && why == UNREADABLE));
    }

    /// A file of 4 steps of 10 bytes that breaks at the third, for its own
    /// reason.
    struct Breaks(u8);

    impl Fill for Breaks {
        fn fill(&mut self, _: &mut Vol, out: &mut Vec<u8>) -> Step {
            self.0 = self.0.saturating_add(1);
            if self.0 == 3 {
                return Step::Broken("this file breaks here");
            }
            out.extend_from_slice(&[self.0; 10]);
            Step::More
        }
    }

    /// What a file says of the way it breaks reaches the member, held or read
    /// as it goes, with the bytes before the break.
    #[test]
    fn a_file_that_breaks_part_way_gives_its_bytes_and_its_own_reason() {
        let mut c = Cursor::new(Vec::new());
        let mut v = Vol {
            disk: &mut c,
            len: 0,
            max: 1 << 20,
        };
        let mut want = vec![1u8; 10];
        want.extend([2u8; 10]);
        match read_file(&mut v, Breaks(0), 40, 40) {
            Got::Partial(d, why) => {
                assert_eq!(d, want);
                assert_eq!(why, "this file breaks here");
            }
            _ => panic!("not held short"),
        }
        let Got::Stream(mut r, ..) = read_file(&mut v, Breaks(0), 40, 10) else {
            panic!("not read as it goes");
        };
        let mut out = Vec::new();
        let err = r.read_to_end(&mut out).expect_err("the file breaks");
        assert_eq!(out, want);
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "this file breaks here");
        // The entry of a held one carries the reason.
        let e = Got::Partial(want, "this file breaks here").entry("f".into());
        assert_eq!(e.unsupported, Some("this file breaks here"));
        assert_eq!(e.data.len(), 20);
    }

    #[test]
    fn fields_are_read_in_their_order_and_zero_past_the_end() {
        let d = [1u8, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(be16(&d, 0), 0x0102);
        assert_eq!(le16(&d, 0), 0x0201);
        assert_eq!(be32(&d, 1), 0x0203_0405);
        assert_eq!(le32(&d, 1), 0x0504_0302);
        assert_eq!(be64(&d, 0), 0x0102_0304_0506_0708);
        assert_eq!(le64(&d, 0), 0x0807_0605_0403_0201);
        assert_eq!(be32(&d, 6), 0);
        assert_eq!(le64(&d, usize::MAX), 0);
    }
}
