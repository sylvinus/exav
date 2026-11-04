//! A message inside an object that is not typed as one.
//!
//! clamscan 1.4.3 parses a text file, or a file of binary data, as one message
//! when it holds two lines of a message's header block close enough to each
//! other: `MIME-Version:` and a later `Content-Type:`, `From:` and a later
//! `Content-Type:`, and the other pairs of [`PAIRS`]. The whole file is the
//! message, whatever comes before the headers. This finds where the header
//! block holding the first such pair starts, so that the one email reader can
//! be given the object from there.
//!
//! The names, the spellings, the offsets and the distances below are what
//! clamscan takes, measured one by one on files of text.
//!
//! An object not held in memory is searched as the one read of it goes
//! (`crate::pass`); one that is, by [`first_pair`].
// Only a build with the `email` feature reads the message.
#![cfg_attr(not(feature = "email"), allow(dead_code))]

use crate::byte_source::ByteSource;
use crate::filetype::field_name_len;

/// A header name, in the spellings clamscan takes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Name {
    MimeVersion,
    From,
    Received,
    MessageId,
    ContentType,
}

/// The longest a [`Name`] is with its colon.
const NAME_MAX: usize = 13;
/// The longest a [`Name`] is with its colon and the space after it.
const FIELD_MAX: usize = 14;

impl Name {
    /// How many bytes of `at` the name takes up to its colon, when `at` starts
    /// with the name, a colon and a space. Letters may be capitals where
    /// clamscan accepts them: any of the four of `MIME`, the first letter of
    /// `Version`, `From`, `Received`, `Message`, `Id`, `Content` and `Type`,
    /// and no other.
    fn colon_end(self, at: &[u8]) -> Option<usize> {
        let first = |set: &[u8; 2]| at.first().is_some_and(|c| set.contains(c));
        let rest = |from: usize, word: &[u8]| at.get(from..from + word.len()) == Some(word);
        let (len, spelt) = match self {
            Name::MimeVersion => (
                12,
                at.get(..4).is_some_and(|m| m.eq_ignore_ascii_case(b"mime"))
                    && at.get(4) == Some(&b'-')
                    && at.get(5).is_some_and(|c| matches!(c, b'V' | b'v'))
                    && rest(6, b"ersion"),
            ),
            Name::From => (4, first(b"Ff") && rest(1, b"rom")),
            Name::Received => (8, first(b"Rr") && rest(1, b"eceived")),
            Name::MessageId => (
                10,
                first(b"Mm")
                    && rest(1, b"essage-")
                    && at.get(8).is_some_and(|c| matches!(c, b'I' | b'i'))
                    && rest(9, b"d"),
            ),
            Name::ContentType => (
                12,
                first(b"Cc")
                    && rest(1, b"ontent-")
                    && at.get(8).is_some_and(|c| matches!(c, b'T' | b't'))
                    && rest(9, b"ype"),
            ),
        };
        (spelt && at.get(len) == Some(&b':') && at.get(len + 1) == Some(&b' ')).then_some(len + 1)
    }
}

/// Two header lines that make a message of a file, both at the start of a line.
struct Pair {
    a: Name,
    b: Name,
    /// The latest offset `a` starts at.
    a_max: usize,
    /// The furthest `b` starts after the colon of `a`.
    reach: usize,
}

/// The pairs that hold only near the start of a file.
const PAIRS: [Pair; 5] = [
    Pair {
        a: Name::MimeVersion,
        b: Name::ContentType,
        a_max: 1025,
        reach: 2050,
    },
    Pair {
        a: Name::From,
        b: Name::ContentType,
        a_max: 1025,
        reach: 2050,
    },
    Pair {
        a: Name::From,
        b: Name::MimeVersion,
        a_max: 1025,
        reach: 1026,
    },
    Pair {
        a: Name::Received,
        b: Name::ContentType,
        a_max: 2049,
        reach: 2050,
    },
    Pair {
        a: Name::MessageId,
        b: Name::ContentType,
        a_max: 1025,
        reach: 1026,
    },
];

/// `MIME-Version:` and `Content-Type:` hold at any offset when the second is
/// this close to the colon of the first.
const FAR_REACH: usize = 1026;

/// `Delivered-To:` and `Received:` hold anywhere on a line, in this order, when
/// the first starts at most this far in and the second this far after its colon.
const DELIVERED: &[u8] = b"Delivered-To:";
const DELIVERED_AT: usize = 1024;
const DELIVERED_REACH: usize = 256;
const RECEIVED: &[u8] = b"Received:";

/// How much of the start of an object holds every pair of [`PAIRS`] and a
/// `Delivered-To:` pair: where the farthest of them can end.
const HEAD: usize = {
    let mut most = DELIVERED_AT + DELIVERED.len() + DELIVERED_REACH + RECEIVED.len();
    let mut i = 0;
    while i < PAIRS.len() {
        let p = &PAIRS[i];
        let end = p.a_max + NAME_MAX + p.reach + FIELD_MAX;
        if end > most {
            most = end;
        }
        i += 1;
    }
    most
};

/// The bytes at the start of an object that clamscan types it from. A page of
/// HTML holds a message only where a pair ends inside them.
const TYPING: usize = 1024;

/// How far back a line is looked for at once.
const STEP: usize = 64 * 1024;

/// The most a [`Search`] copies of a window it is fed at once.
const PIECE: usize = 64 * 1024;

/// The offset of the first line of the first pair found in `src`, which is not
/// typed as a message. `whole` is for a text file, or binary data, which is
/// looked into all through; a page of HTML is looked into only at its start.
pub(crate) fn first_pair(src: &dyn ByteSource, whole: bool) -> Option<usize> {
    if !whole {
        return in_head(&src.window(0, TYPING));
    }
    let mut search = Search::new();
    let len = src.len();
    src.chunks(0, len, &mut |at, w| {
        search.feed(at, w, at + w.len() >= len);
        !search.done()
    });
    search.finish();
    search.found()
}

/// The first line in `head`, the start of an object, that makes a pair with a
/// later one, or the first `Delivered-To:` that does.
fn in_head(head: &[u8]) -> Option<usize> {
    let delivered = delivered(head);
    let mut i = 0;
    while i < head.len() && delivered.is_none_or(|d| i < d) {
        let line = &head[i..];
        for p in &PAIRS {
            if i <= p.a_max
                && let Some(n) = p.a.colon_end(line)
                && token_in(head, i + n, i + n + p.reach, p.b).is_some()
            {
                return Some(i);
            }
        }
        i += memchr::memchr(b'\n', line).map_or(head.len(), |k| k + 1);
    }
    delivered
}

/// The first `Delivered-To:` in `head` followed by a `Received:`.
fn delivered(head: &[u8]) -> Option<usize> {
    let end = head.len().min(DELIVERED_AT + DELIVERED.len());
    memchr::memmem::find_iter(&head[..end], DELIVERED).find(|&a| {
        let from = a + DELIVERED.len();
        let to = head.len().min(from + DELIVERED_REACH + RECEIVED.len());
        memchr::memmem::find(&head[from..to], RECEIVED).is_some()
    })
}

/// The start of the first line of `buf` that starts at or after `from`, no
/// later than `last`, with `name` on it.
fn token_in(buf: &[u8], from: usize, last: usize, name: Name) -> Option<usize> {
    let mut i = from;
    if i == 0 || buf.get(i - 1) != Some(&b'\n') {
        i += memchr::memchr(b'\n', buf.get(i..)?)? + 1;
    }
    while i <= last {
        let line = buf.get(i..)?;
        if name.colon_end(line).is_some() {
            return Some(i);
        }
        i += memchr::memchr(b'\n', line)? + 1;
    }
    None
}

/// The search of an object for the first pair, fed its bytes in order: the
/// start of it for the pairs that hold only there, and all of it for
/// `MIME-Version:` and `Content-Type:`. It holds the start, a thousand bytes
/// or so of what it has been fed, and a copy of one piece of it while that is
/// judged.
pub(crate) struct Search {
    /// The first [`HEAD`] bytes, until the pairs of the start are judged.
    head: Vec<u8>,
    /// The first line of the start that makes a pair, once they are judged.
    near: Option<usize>,
    near_judged: bool,
    /// The bytes fed from `carry_at` on that are not judged yet, and the one
    /// byte before them.
    carry: Vec<u8>,
    carry_at: usize,
    /// `MIME-Version:` lines that start before this are judged.
    judged: usize,
    /// `Content-Type:` lines that start before this have been looked at.
    unseen: usize,
    /// The first `MIME-Version:` line that makes a pair.
    far: Option<usize>,
    done: bool,
}

impl Search {
    /// What follows `MIME-V` on a line, with the `ersion` in lower case that
    /// every spelling has.
    const TAIL: &'static [u8] = b"ersion: ";
    /// The byte before the first line judged, which says it starts one.
    const BEHIND: usize = 1;
    /// The bytes after a line that a `Content-Type:` line in reach of it is
    /// found in: a line is judged when they have been fed.
    const AHEAD: usize = NAME_MAX + FAR_REACH + FIELD_MAX + 1;

    pub(crate) fn new() -> Self {
        Search {
            head: Vec::new(),
            near: None,
            near_judged: false,
            carry: Vec::new(),
            carry_at: 0,
            judged: 0,
            unseen: 0,
            far: None,
            done: false,
        }
    }

    /// Whether more bytes could change the answer.
    pub(crate) fn done(&self) -> bool {
        self.done
    }

    /// The first line that makes a pair, of the bytes fed so far.
    pub(crate) fn found(&self) -> Option<usize> {
        match (self.near, self.far) {
            (Some(n), Some(f)) => Some(n.min(f)),
            (n, f) => n.or(f),
        }
    }

    /// The bytes `at..at + w.len()` of the object, which follow the ones fed
    /// before; `last` if they are its last.
    ///
    /// An object held in memory comes as one window, and a piece is copied
    /// to be judged: it is taken [`PIECE`] bytes at a time.
    pub(crate) fn feed(&mut self, at: usize, w: &[u8], last: bool) {
        if w.len() <= PIECE {
            return self.feed_piece(at, w, last);
        }
        let mut from = 0;
        while from < w.len() && !self.done {
            let to = (from + PIECE).min(w.len());
            self.feed_piece(at + from, &w[from..to], last && to == w.len());
            from = to;
        }
    }

    fn feed_piece(&mut self, at: usize, w: &[u8], last: bool) {
        if self.done {
            return;
        }
        if !self.near_judged {
            let room = HEAD - self.head.len();
            self.head.extend_from_slice(&w[..w.len().min(room)]);
            if self.head.len() == HEAD || last {
                self.near = in_head(&self.head);
                self.near_judged = true;
            }
        }
        let mut buf = std::mem::take(&mut self.carry);
        buf.extend_from_slice(w);
        let base = self.carry_at;
        debug_assert_eq!(base + buf.len() - w.len(), at);
        let upto = if last {
            base + buf.len()
        } else {
            (base + buf.len()).saturating_sub(Self::AHEAD)
        };
        let finder = memchr::memmem::Finder::new(Self::TAIL);
        for p in finder.find_iter(&buf) {
            if self.far.is_some() {
                break;
            }
            // The line starts six bytes before, and is judged now if it starts
            // in `judged..upto`.
            let Some(a) = (base + p)
                .checked_sub(6)
                .filter(|a| (self.judged..upto).contains(a))
            else {
                continue;
            };
            let line = a - base;
            if (a > 0 && buf[line - 1] != b'\n')
                || Name::MimeVersion.colon_end(&buf[line..]).is_none()
            {
                continue;
            }
            let first = (a + NAME_MAX).max(self.unseen);
            let reach = a + NAME_MAX + FAR_REACH;
            if first <= reach {
                if token_in(&buf, first - base, reach - base, Name::ContentType).is_some() {
                    self.far = Some(a);
                } else {
                    self.unseen = reach + 1;
                }
            }
        }
        self.judged = self.judged.max(upto);
        let keep = self.judged.saturating_sub(Self::BEHIND).max(base);
        buf.drain(..keep - base);
        self.carry = buf;
        self.carry_at = keep;
        // A pair of the start that comes first is the answer; so is the first
        // `MIME-Version:` line, once the start is judged and none comes before.
        self.done = last
            || (self.near_judged
                && (self.far.is_some() || self.near.is_some_and(|n| self.judged > n)));
    }

    /// There are no more bytes.
    pub(crate) fn finish(&mut self) {
        if !self.done {
            let end = self.carry_at + self.carry.len();
            self.feed(end, &[], true);
        }
    }
}

/// Where the header block that holds the line at `a` starts: the first of the
/// lines above it that are header fields or folded onto one. Not read back
/// further than `back` bytes.
pub(crate) fn block_start(src: &dyn ByteSource, a: usize, back: usize) -> usize {
    let floor = a.saturating_sub(back);
    let Some(mut start) = line_start(src, a, floor) else {
        return a;
    };
    while start > floor {
        let Some(before) = line_start(src, start - 1, floor) else {
            break;
        };
        let len = start - 1 - before;
        // Enough of the line to tell a field from other text.
        let sample = src.window(before, len.min(FIELD_SAMPLE));
        if !header_line(&sample, len <= FIELD_SAMPLE) {
            break;
        }
        start = before;
    }
    start
}

/// A field name is at most 64 bytes long, and a colon follows.
const FIELD_SAMPLE: usize = 80;

/// Whether a line, or the start of one, is a header field or folded onto
/// one. A blank line, or a line of white space, is not.
fn header_line(sample: &[u8], whole: bool) -> bool {
    match sample.first() {
        None => false,
        Some(b' ' | b'\t') => !(whole && sample.trim_ascii().is_empty()),
        Some(_) => field_name_len(sample).is_some(),
    }
}

/// The offset the line holding byte `at` starts at: after the last line feed
/// before it. `None` when there is none from `floor` on, and `floor` is not
/// the start of the object.
fn line_start(src: &dyn ByteSource, at: usize, floor: usize) -> Option<usize> {
    let mut end = at;
    while end > floor {
        let from = end.saturating_sub(STEP).max(floor);
        let w = src.window(from, end - from);
        if let Some(k) = memchr::memrchr(b'\n', &w) {
            return Some(from + k + 1);
        }
        end = from;
    }
    (floor == 0).then_some(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::byte_source::BlockCache;
    use std::io::Cursor;

    const CT: &str = "Content-Type: text/plain";
    const MV: &str = "MIME-Version: 1.0";

    /// `n` bytes of one line, ending in a line feed; nothing for 0.
    fn filler(n: usize) -> Vec<u8> {
        match n {
            0 => vec![],
            _ => [vec![b'y'; n - 1], vec![b'\n']].concat(),
        }
    }

    /// `a` at offset `off`, then `b` starting `dist` bytes after the colon of
    /// `a`, each on a line of its own.
    fn pair(off: usize, a: &str, b: &str, dist: usize) -> Vec<u8> {
        let rest = a.len() + 1 - (a.find(':').unwrap() + 1);
        assert!(dist >= rest);
        [
            filler(off),
            a.as_bytes().to_vec(),
            b"\n".to_vec(),
            filler(dist - rest),
            b.as_bytes().to_vec(),
            b"\n".to_vec(),
        ]
        .concat()
    }

    fn found(data: &[u8], whole: bool) -> Option<usize> {
        first_pair(&data.to_vec(), whole)
    }

    fn message_start(src: &dyn ByteSource, whole: bool, back: usize) -> Option<usize> {
        first_pair(src, whole).map(|a| block_start(src, a, back))
    }

    /// Each pair holds at the latest offset and the furthest reach clamscan
    /// takes, and not a byte further either way.
    #[test]
    fn a_pair_holds_to_its_offset_and_reach_and_not_a_byte_beyond() {
        let rows: [(&str, &str, usize, usize); 5] = [
            (MV, CT, 1025, 2050),
            ("From: a@b", CT, 1025, 2050),
            ("From: a@b", MV, 1025, 1026),
            ("Received: from x by y", CT, 2049, 2050),
            ("Message-Id: <1@b>", CT, 1025, 1026),
        ];
        for (a, b, a_max, reach) in rows {
            assert_eq!(found(&pair(a_max, a, b, reach), true), Some(a_max), "{a}");
            assert_eq!(found(&pair(a_max, a, b, reach + 1), true), None, "{a}");
            assert_eq!(found(&pair(a_max + 1, a, b, reach), true), None, "{a}");
            // Nearer than any of that.
            assert_eq!(found(&pair(0, a, b, a.len() + 1), true), Some(0), "{a}");
        }
    }

    /// `MIME-Version:` and `Content-Type:` hold at any offset, within a shorter
    /// reach.
    #[test]
    fn mime_version_and_content_type_hold_at_any_offset_within_a_shorter_reach() {
        for off in [1026, 5000, 100_000, 3 << 20] {
            assert_eq!(found(&pair(off, MV, CT, 1026), true), Some(off), "{off}");
            assert_eq!(found(&pair(off, MV, CT, 1027), true), None, "{off}");
        }
    }

    /// `Delivered-To:` and `Received:` hold anywhere in a line, in that order.
    #[test]
    fn delivered_to_and_received_hold_anywhere_in_a_line() {
        let both = |off: usize, reach: usize| {
            [
                filler(off),
                b"x Delivered-To:".to_vec(),
                vec![b' '; reach],
                b"Received:".to_vec(),
            ]
            .concat()
        };
        let at = |off: usize| off + 2;
        // `Received:` follows with no line feed, and the colons need no space.
        assert_eq!(
            found(&[b"a\n".to_vec(), both(0, 256)].concat()[..], true),
            Some(at(2))
        );
        assert_eq!(found(&both(1022, 256), true), Some(at(1022)));
        assert_eq!(found(&both(1024, 256), true), None);
        assert_eq!(found(&both(0, 257), true), None);
        let reversed = b"Received:x Delivered-To:y".to_vec();
        assert_eq!(found(&reversed, true), None);
        // Both are spelt as written.
        assert_eq!(found(b"delivered-to: x received: y", true), None);
        assert_eq!(found(b"Delivered-To :x Received:y", true), None);
    }

    /// A name is spelt in capitals only where clamscan takes them, and is
    /// followed by a colon and a space.
    #[test]
    fn names_are_spelt_the_ways_clamscan_takes() {
        let rows: [(Name, &[&str], &[&str]); 5] = [
            (
                Name::MimeVersion,
                &[
                    "MIME-Version: ",
                    "mime-version: ",
                    "Mime-Version: ",
                    "mImE-version: ",
                    "MIME-version: ",
                ],
                &[
                    "MIME-VERSION: ",
                    "MIME-vErsion: ",
                    "Mime-VERSION: ",
                    "MIME_Version: ",
                ],
            ),
            (
                Name::From,
                &["From: ", "from: "],
                &["FROM: ", "fROM: ", "Frm: "],
            ),
            (
                Name::Received,
                &["Received: ", "received: "],
                &["RECEIVED: ", "ReceIved: "],
            ),
            (
                Name::MessageId,
                &[
                    "Message-Id: ",
                    "Message-id: ",
                    "message-Id: ",
                    "message-id: ",
                ],
                &["Message-ID: ", "MESSAGE-Id: ", "Message-I: "],
            ),
            (
                Name::ContentType,
                &[
                    "Content-Type: ",
                    "Content-type: ",
                    "content-Type: ",
                    "content-type: ",
                ],
                &[
                    "CONTENT-TYPE: ",
                    "Content-TYPE: ",
                    "Content-Typ: ",
                    "ContentType: ",
                ],
            ),
        ];
        for (name, yes, no) in rows {
            for s in yes {
                assert_eq!(name.colon_end(s.as_bytes()), Some(s.len() - 1), "{s}");
            }
            for s in no {
                assert_eq!(name.colon_end(s.as_bytes()), None, "{s}");
            }
            let word = std::str::from_utf8(&yes[0].as_bytes()[..yes[0].len() - 2]).unwrap();
            for bad in [":x", ":\t", " :", ":\n", ":\r\n"] {
                let s = format!("{word}{bad} ");
                assert_eq!(name.colon_end(s.as_bytes()), None, "{s:?}");
            }
        }
    }

    /// Both lines start a line, in this order, and nothing else is a pair.
    #[test]
    fn a_pair_is_two_lines_in_order() {
        let at_start = format!("{MV}\n{CT}\n");
        assert_eq!(found(at_start.as_bytes(), true), Some(0));
        let crlf = format!("hello\r\n{MV}\r\n{CT}\r\n");
        assert_eq!(found(crlf.as_bytes(), true), Some(7));
        for (text, why) in [
            (format!("x {MV}\n{CT}\n"), "first line not at a line start"),
            (format!("{MV}\nx {CT}\n"), "second line not at a line start"),
            (
                format!("x\r{MV}\n{CT}\n"),
                "a carriage return is no line start",
            ),
            (
                format!("{MV}\r{CT}\n"),
                "a carriage return is no line start",
            ),
            (format!("{MV}\n {CT}\n"), "second line folded"),
            (format!("{MV}\n\t{CT}\n"), "second line folded"),
            (format!("{CT}\n{MV}\n"), "wrong order"),
            (format!("{MV}\n"), "alone"),
            (format!("{CT}\n"), "alone"),
            (format!("{MV} {CT}\n"), "on one line"),
            (
                "From: a\nTo: b\nSubject: c\nDate: d\nMessage-ID: <1>\n\nhi\n".into(),
                "no pair",
            ),
            (
                "Content-Type: multipart/mixed; boundary=X\n\n--X\n".into(),
                "alone",
            ),
            (format!("\0{MV}\n{CT}\n"), "NUL before"),
        ] {
            assert_eq!(found(text.as_bytes(), true), None, "{why}: {text:?}");
        }
    }

    /// A page is looked into where clamscan types it, which is up to byte 1024,
    /// and a pair must end there.
    #[test]
    fn a_page_is_looked_into_only_at_its_start() {
        // `Content-Type: ` is 14 bytes: it ends at byte 1024 here.
        let page = |off: usize| [filler(off), format!("{MV}\n{CT}\n").into_bytes()].concat();
        assert_eq!(found(&page(992), false), Some(992));
        assert_eq!(found(&page(993), false), None);
        assert_eq!(found(&page(993), true), Some(993));
        let far = pair(5000, MV, CT, 30);
        assert_eq!(found(&far, false), None);
        assert_eq!(found(&far, true), Some(5000));
    }

    /// Where the message starts: the first line above the pair that is a header
    /// field or folded onto one, and no text or blank line.
    #[test]
    fn the_message_starts_at_the_header_block_that_holds_the_pair() {
        let start =
            |text: &str, whole: bool| message_start(&text.as_bytes().to_vec(), whole, usize::MAX);
        let block =
            "Cc: a@b\nContent-Type: multipart/mixed;\n\tboundary=\"X\"\nMIME-Version: 1.0\n";
        let body = "Content-Type: text/plain\n\nbody\n";
        let text = format!("A note.\nSome lines.\n\n{block}{body}");
        assert_eq!(start(&text, true), Some(text.find("Cc:").unwrap()));
        // Text without a blank line, then the block.
        let text = format!("Hello there\n{block}{body}");
        assert_eq!(start(&text, true), Some(12));
        // The block is the whole file.
        assert_eq!(start(&format!("{block}{body}"), true), Some(0));
        // A line that is a field name and no more is not a header: spaces in it.
        let text = format!("Dear Sir: hello\n{block}{body}");
        assert_eq!(start(&text, true), Some(16));
        // A line of white space ends the block like an empty one.
        let text = format!("Cc: x\n  \n{block}{body}");
        assert_eq!(start(&text, true), Some(9));
        // CRLF.
        let text = format!(
            "x\r\n\r\n{}{}",
            block.replace('\n', "\r\n"),
            body.replace('\n', "\r\n")
        );
        assert_eq!(start(&text, true), Some(5));
        // A `Delivered-To:` inside a line starts the message at the line.
        let text = "text\nsee also Delivered-To: me Received: you\nbody\n";
        assert_eq!(start(text, true), Some(5));
    }

    /// The block is read back no further than the limit it is given.
    #[test]
    fn a_long_header_block_is_read_back_no_further_than_the_limit() {
        let block: String = (0..1000).map(|i| format!("X-{i}: v\n")).collect();
        let text = format!("{block}{MV}\n{CT}\n");
        let a = block.len();
        let all = message_start(&text.as_bytes().to_vec(), true, usize::MAX).unwrap();
        assert_eq!(all, 0);
        let cut = message_start(&text.as_bytes().to_vec(), true, 500).unwrap();
        assert!(cut >= a - 500 && cut < a, "{cut}");
        assert_eq!(text.as_bytes()[cut - 1], b'\n');
        assert_eq!(message_start(&text.as_bytes().to_vec(), true, 0), Some(a));
    }

    /// Lines of `MIME-Version:` with a `Content-Type:` after them: the first
    /// that has it within its reach is the pair, whether the lines before it
    /// were looked at again or not.
    #[test]
    fn the_first_mime_version_line_with_a_content_type_in_reach_is_the_pair() {
        let line = format!("{MV}\n");
        let lines = 200;
        for off in [0, 1100] {
            let text = [
                filler(off),
                line.repeat(lines).into_bytes(),
                format!("{CT}\n").into_bytes(),
            ]
            .concat();
            let ct = off + lines * line.len();
            let want = (0..lines).map(|k| off + k * line.len()).find(|&a| {
                let after_colon = ct - (a + 13);
                after_colon <= 1026 || (a <= 1025 && after_colon <= 2050)
            });
            assert!(want.is_some());
            assert_eq!(found(&text, true), want, "{off}");
        }
        // And none of them has one.
        let none = [filler(1100), line.repeat(5000).into_bytes()].concat();
        assert_eq!(found(&none, true), None);
    }

    /// The answer does not depend on how the bytes are cut into windows, down
    /// to one byte at a time.
    #[test]
    fn the_search_gives_the_same_answer_whatever_the_windows() {
        let lines = format!("{MV}\n").repeat(60).into_bytes();
        let cases = [
            (pair(5000, MV, CT, 1026), Some(5000)),
            (pair(5000, MV, CT, 1027), None),
            (pair(300, "From: a@b", CT, 2050), Some(300)),
            (pair(1100, "Received: x", CT, 1500), Some(1100)),
            (
                [filler(700), b"Delivered-To:a Received:b".to_vec()].concat(),
                Some(700),
            ),
            (pair(1030, "From: a@b", CT, 100), None),
            // The third line is the first with a `Content-Type:` in reach.
            (
                [filler(3000), lines.clone(), format!("{CT}\n").into_bytes()].concat(),
                Some(3054),
            ),
            (b"hello\n".to_vec(), None),
            (vec![], None),
        ];
        for (data, want) in cases {
            assert_eq!(found(&data, true), want, "{} bytes", data.len());
            for size in [1, 2, 7, 61, 1000, 1054, 4097] {
                let mut search = Search::new();
                let mut at = 0;
                for w in data.as_slice().chunks(size) {
                    at += w.len();
                    search.feed(at - w.len(), w, at == data.len());
                }
                search.finish();
                assert_eq!(
                    search.found(),
                    want,
                    "{} bytes, windows of {size}",
                    data.len()
                );
            }
        }
    }

    /// An object that is not in memory is searched through its windows, and a
    /// pair across the seam of two of them, or the blocks of the cache, is found
    /// as it is anywhere else.
    #[test]
    fn an_object_read_through_a_cache_gives_the_same_answer() {
        let one_mib = 1 << 20;
        let mut cases = vec![
            (pair(5000, MV, CT, 1026), Some(5000)),
            (pair(5000, MV, CT, 1027), None),
            (pair(70_000, MV, CT, 40), Some(70_000)),
            (pair(300, "Received: x", CT, 2000), Some(300)),
            (pair(300, "Received: x", CT, 2051), None),
            (
                [filler(900), b"Delivered-To:a Received:b".to_vec()].concat(),
                Some(900),
            ),
        ];
        for off in 3000..3070 {
            cases.push((pair(off, MV, CT, 200), Some(off)));
        }
        // The first line in a window, the last, and the second line in the next:
        // windows are 4096 bytes here.
        for seam in [4096, 8192, one_mib] {
            for off in seam - 20..seam + 20 {
                cases.push((pair(off, MV, CT, 1026), Some(off)));
                cases.push((pair(off, MV, CT, 1027), None));
            }
        }
        // Lines of `MIME-Version:` across the seam, the `Content-Type:` line
        // after it.
        let lines = format!("{MV}\n").repeat(100).into_bytes();
        let at = one_mib - 50 * 18;
        let data = [filler(at), lines.clone(), format!("{CT}\n").into_bytes()].concat();
        let ct = at + lines.len();
        cases.push((
            data,
            Some((at..).step_by(18).find(|a| ct - (a + 13) <= 1026).unwrap()),
        ));
        for (data, want) in cases {
            assert_eq!(first_pair(&data, true), want, "{} bytes", data.len());
            let blocks: &[usize] = if data.len() < 100_000 {
                &[7, 61, 509]
            } else {
                &[4093]
            };
            for &block in blocks {
                let cache =
                    BlockCache::with_sizes(Cursor::new(data.clone()), block, 4 * block).unwrap();
                assert_eq!(first_pair(&cache, true), want, "block {block}");
                assert_eq!(
                    message_start(&cache, true, usize::MAX),
                    message_start(&data, true, usize::MAX),
                    "block {block}"
                );
            }
        }
    }
}
