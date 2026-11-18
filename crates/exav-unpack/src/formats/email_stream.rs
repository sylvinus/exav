//! Email past the buffer limit, read from its place in the source: a mailbox
//! split message by message at its `From ` lines, a message within the limit
//! read whole by [`super::email::extract_email`] as one in memory is, and a
//! larger one read part by part, each leaf's body decoded (base64,
//! quoted-printable) as it is read and handed over as it goes.
//!
//! What a message read part by part holds is one header block at a time,
//! under the buffer limit, the boundaries of the multiparts it is in, and a
//! line piece (see [`LINE_PIECE`]).

use super::email::MULTIPART_NOT_FOUND;
use crate::source::{ByteSource, Reader};
use crate::stream::{MemberMeta, Visit, emit_entry, emit_stream, whole};
use crate::{Budget, Entry, Format, LimitHit};
use std::io::{self, BufRead, BufReader, Read};

/// Deepest nesting of multiparts taken apart in a message read part by part:
/// the stack of their boundaries. A deeper one is handed over whole as one
/// part, reported as not taken apart.
const MAX_NESTED_MULTIPARTS: usize = 64;
/// The longest piece of a line read at once, plus the length of the longest
/// boundary read so far. A delimiter is a piece, so a longer line is body,
/// handed over in pieces.
const LINE_PIECE: u64 = 64 * 1024;

pub(crate) fn walk(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<()>,
) -> Result<Option<()>, LimitHit> {
    let max = budget.limits.max_buffer_bytes;
    if src.as_slice().is_some() || src.len() as u64 <= max {
        return whole(Format::Email, src, budget, visit);
    }
    let len = src.len();
    let mbox = src.window(0, 5).as_ref() == b"From ";
    let mut at = 0usize;
    let mut k = 0usize;
    while at < len {
        // A message of a mailbox starts after its `From ` line and ends
        // where the next one starts.
        let (from, to) = if mbox {
            let from = src.find(b"\n", at, len).map_or(len, |p| p + 1);
            let to = src
                .find(b"\nFrom ", from.saturating_sub(1), len)
                .map_or(len, |p| p + 1);
            (from, to.max(from))
        } else {
            (0, len)
        };
        let prefix = if mbox {
            format!("mbox-{k}/")
        } else {
            String::new()
        };
        let stopped = if (to - from) as u64 <= max {
            whole_message(src, from, to, &prefix, budget, visit)?
        } else {
            by_parts(src, from, to, &prefix, budget, visit)?
        };
        if stopped.is_some() {
            return Ok(stopped);
        }
        at = to;
        k += 1;
    }
    Ok(None)
}

/// A message within the buffer limit, read into memory and taken apart as
/// one in memory is, its members' names after `prefix`.
fn whole_message(
    src: &dyn ByteSource,
    from: usize,
    to: usize,
    prefix: &str,
    budget: &mut Budget,
    visit: Visit<()>,
) -> Result<Option<()>, LimitHit> {
    let data = src.window(from, to - from);
    let stopped = super::email::extract_email(&data, budget, &mut |mut e: Entry, budget| {
        e.name = format!("{prefix}{}", e.name);
        emit_entry(e, budget, visit).transpose()
    })?;
    stopped.transpose()
}

/// A line break, or none where a piece of a long line or the input ends.
#[derive(Clone, Copy, PartialEq)]
enum Brk {
    Crlf,
    Lf,
    None,
}

impl Brk {
    fn bytes(self) -> &'static [u8] {
        match self {
            Brk::Crlf => b"\r\n",
            Brk::Lf => b"\n",
            Brk::None => b"",
        }
    }
}

/// The lines of a message, a long one in pieces.
struct Lines<R> {
    r: BufReader<R>,
    /// The last piece read ended a line, so the next one starts one.
    at_start: bool,
    line: Vec<u8>,
    /// The most a piece holds.
    piece: u64,
    /// Bytes read so far, and where the last piece started.
    pos: u64,
    last: u64,
}

impl<R: Read> Lines<R> {
    fn new(r: R) -> Self {
        Lines {
            r: BufReader::with_capacity(64 * 1024, r),
            at_start: true,
            line: Vec::new(),
            piece: LINE_PIECE,
            pos: 0,
            last: 0,
        }
    }

    /// The next line or piece of one into `self.line`, without its break;
    /// `None` at the end. The flag says it starts a line.
    fn next(&mut self) -> io::Result<Option<(Brk, bool)>> {
        self.line.clear();
        let n = (&mut self.r)
            .take(self.piece)
            .read_until(b'\n', &mut self.line)?;
        if n == 0 {
            return Ok(None);
        }
        self.last = self.pos;
        self.pos += n as u64;
        let start = self.at_start;
        let brk = if self.line.last() == Some(&b'\n') {
            self.line.pop();
            if self.line.last() == Some(&b'\r') {
                self.line.pop();
                Brk::Crlf
            } else {
                Brk::Lf
            }
        } else {
            Brk::None
        };
        self.at_start = brk != Brk::None;
        Ok(Some((brk, start)))
    }
}

/// What ended a body: the delimiter of the multipart at that depth of the
/// stack, closing it or not, or the end of the message.
#[derive(Clone, Copy)]
enum End {
    Delim { depth: usize, close: bool },
    Eof,
}

/// The delimiter `line` is, of the innermost multipart it names.
fn delimiter(line: &[u8], stack: &[Vec<u8>]) -> Option<End> {
    let rest = line.strip_prefix(b"--")?.trim_ascii_end();
    stack.iter().enumerate().rev().find_map(|(depth, b)| {
        let after = rest.strip_prefix(b.as_slice())?;
        match after {
            b"" => Some(End::Delim {
                depth,
                close: false,
            }),
            b"--" => Some(End::Delim { depth, close: true }),
            _ => None,
        }
    })
}

/// The headers of a part that matter here.
#[derive(Default)]
struct Head {
    /// `type/subtype`, lowercased.
    mime: String,
    boundary: Option<Vec<u8>>,
    /// The transfer encoding, lowercased.
    encoding: String,
}

/// The value of parameter `name` in a header value (`; name="v"`).
fn param(value: &str, name: &str) -> Option<String> {
    value.split(';').skip(1).find_map(|p| {
        let (k, v) = p.split_once('=')?;
        if !k.trim().eq_ignore_ascii_case(name) {
            return None;
        }
        let v = v.trim();
        let v = v
            .strip_prefix('"')
            .map_or(v, |v| v.split('"').next().unwrap_or(v));
        Some(v.to_string())
    })
}

fn parse_head(block: &[u8]) -> Head {
    let text = String::from_utf8_lossy(block);
    let mut head = Head::default();
    // Unfolded: a line that starts with a space or a tab continues the last.
    let mut fields: Vec<String> = Vec::new();
    for line in text.split('\n') {
        let line = line.trim_end_matches('\r');
        match fields.last_mut() {
            Some(last) if line.starts_with([' ', '\t']) => {
                last.push(' ');
                last.push_str(line.trim_start());
            }
            _ => fields.push(line.to_string()),
        }
    }
    for f in &fields {
        let Some((name, value)) = f.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name.eq_ignore_ascii_case("content-type") && head.mime.is_empty() {
            head.mime = value
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            head.boundary = param(value, "boundary")
                .filter(|b| !b.is_empty())
                .map(String::into_bytes);
        } else if name.eq_ignore_ascii_case("content-transfer-encoding") && head.encoding.is_empty()
        {
            head.encoding = value.trim().to_ascii_lowercase();
        }
    }
    head
}

/// Base64 as mail readers decode it, fed a piece at a time: every byte outside
/// the alphabet is skipped, and padding ends a quantum, so that pieces encoded
/// apart and joined decode as they were. The in-memory reader decodes the
/// parts its parser could not with this too.
#[derive(Default)]
pub(super) struct LenientBase64 {
    acc: u32,
    bits: u32,
}

impl LenientBase64 {
    pub(super) fn feed(&mut self, data: &[u8], out: &mut Vec<u8>) {
        for &c in data {
            let v = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' => {
                    (self.acc, self.bits) = (0, 0);
                    continue;
                }
                _ => continue,
            };
            self.acc = (self.acc << 6) | u32::from(v);
            self.bits += 6;
            if self.bits >= 8 {
                self.bits -= 8;
                out.push((self.acc >> self.bits) as u8);
                self.acc &= (1 << self.bits) - 1;
            }
        }
    }
}

/// A transfer encoding a body is decoded from.
#[derive(Clone, Copy, PartialEq)]
enum Enc {
    Base64,
    Qp,
    Plain,
}

/// A leaf's body, decoded as it is read, up to the delimiter that ends it.
struct Body<'l, R> {
    lines: &'l mut Lines<R>,
    stack: &'l [Vec<u8>],
    enc: Enc,
    out: Vec<u8>,
    at: usize,
    /// The break of the last line, given once the next line is known not to
    /// be a delimiter: the break before one is the delimiter's.
    pending: Brk,
    end: Option<End>,
    b64: LenientBase64,
}

impl<R: Read> Body<'_, R> {
    /// Decode the next line into `out`, or note the end of the body.
    fn fill(&mut self) -> io::Result<()> {
        let Some((brk, start)) = self.lines.next()? else {
            self.end = Some(End::Eof);
            return Ok(());
        };
        if start && let Some(end) = delimiter(&self.lines.line, self.stack) {
            self.end = Some(end);
            return Ok(());
        }
        let line = &self.lines.line;
        match self.enc {
            Enc::Plain => {
                self.out.extend_from_slice(self.pending.bytes());
                self.out.extend_from_slice(line);
                self.pending = brk;
            }
            Enc::Base64 => self.b64.feed(line, &mut self.out),
            Enc::Qp => {
                self.out.extend_from_slice(self.pending.bytes());
                let line = match brk {
                    Brk::None => &line[..],
                    _ => line.trim_ascii_end(),
                };
                let (line, soft) = match line.strip_suffix(b"=") {
                    Some(l) if brk != Brk::None => (l, true),
                    _ => (line, false),
                };
                qp_decode(line, &mut self.out);
                self.pending = if soft { Brk::None } else { brk };
            }
        }
        Ok(())
    }
}

/// Quoted-printable: `=XX` is a byte, an `=` that is not one is kept.
fn qp_decode(line: &[u8], out: &mut Vec<u8>) {
    let hex = |c: u8| (c as char).to_digit(16);
    let mut i = 0;
    while i < line.len() {
        if line[i] == b'='
            && let (Some(h), Some(l)) = (
                line.get(i + 1).and_then(|&c| hex(c)),
                line.get(i + 2).and_then(|&c| hex(c)),
            )
        {
            out.push((h * 16 + l) as u8);
            i += 3;
        } else {
            out.push(line[i]);
            i += 1;
        }
    }
}

impl<R: Read> Read for Body<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.at >= self.out.len() {
            if self.end.is_some() {
                return Ok(0);
            }
            self.out.clear();
            self.at = 0;
            self.fill()?;
        }
        let n = (self.out.len() - self.at).min(buf.len());
        buf[..n].copy_from_slice(&self.out[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

/// Read lines up to a delimiter of `stack`, or the end, dropping them: a
/// multipart's preamble and epilogue. The flag says one of them was not
/// blank.
fn skip<R: Read>(lines: &mut Lines<R>, stack: &[Vec<u8>]) -> io::Result<(End, bool)> {
    let mut text = false;
    while let Some((_, start)) = lines.next()? {
        if start && let Some(end) = delimiter(&lines.line, stack) {
            return Ok((end, text));
        }
        text = text || !lines.line.trim_ascii().is_empty();
    }
    Ok((End::Eof, text))
}

/// A part's header block, up to the empty line that ends it, no larger than
/// `max`; or the delimiter that came first.
fn header_block<R: Read>(
    lines: &mut Lines<R>,
    stack: &[Vec<u8>],
    max: u64,
) -> Result<(Vec<u8>, Option<End>), LimitHit> {
    let mut block = Vec::new();
    loop {
        let Some((brk, start)) = lines.next().map_err(io_hit)? else {
            return Ok((block, Some(End::Eof)));
        };
        if start && lines.line.is_empty() && brk != Brk::None {
            return Ok((block, None));
        }
        if start && let Some(end) = delimiter(&lines.line, stack) {
            return Ok((block, Some(end)));
        }
        block.extend_from_slice(&lines.line);
        block.extend_from_slice(brk.bytes());
        if block.len() as u64 > max {
            return Err(LimitHit::new(format!(
                "email: a header block is over the {max}-byte buffer limit"
            )));
        }
    }
}

fn io_hit(e: io::Error) -> LimitHit {
    LimitHit::corrupt(format!("email: {e}"))
}

/// Why a message attached to a message is reported.
const ATTACHED_MESSAGE: &str =
    "email: attached message not taken apart, its parts read as its bytes";

/// Whether the parser of a message in memory takes this leaf apart as a
/// message of its own: `message/rfc822` or `message/global` that is not
/// encoded, or a part of a digest with no type.
fn is_attached_message(head: &Head, in_digest: bool) -> bool {
    let plain = !matches!(head.encoding.as_str(), "base64" | "quoted-printable");
    let message = matches!(head.mime.as_str(), "message/rfc822" | "message/global")
        || (head.mime.is_empty() && in_digest);
    plain && message
}

/// A leaf read from `lines` up to a delimiter of `stack` or the end, decoded
/// from `encoding` and handed over as `meta`: what the visitor stopped the
/// walk with, and what ended the body.
fn leaf<R: Read>(
    lines: &mut Lines<R>,
    stack: &[Vec<u8>],
    encoding: &str,
    meta: &MemberMeta,
    budget: &mut Budget,
    visit: Visit<()>,
) -> Result<(Option<()>, End), LimitHit> {
    budget.count_entry()?;
    let enc = match encoding {
        "base64" => Enc::Base64,
        "quoted-printable" => Enc::Qp,
        _ => Enc::Plain,
    };
    let mut body = Body {
        lines,
        stack,
        enc,
        out: Vec::new(),
        at: 0,
        pending: Brk::None,
        end: None,
        b64: LenientBase64::default(),
    };
    if let Some(t) = emit_stream(meta, &mut body, budget, visit)? {
        return Ok((Some(t), End::Eof));
    }
    // What the visitor left of the body, to find where it ends.
    io::copy(&mut body, &mut io::sink()).map_err(io_hit)?;
    Ok((None, body.end.unwrap_or(End::Eof)))
}

/// A message past the buffer limit, `[from, to)` of `src`, read part by part.
/// Its leaves are named `email-part-N` after `prefix`, N counting every part
/// in the order they come, multiparts too.
///
/// A multipart that is not taken apart is a leaf, and says so: one with no
/// boundary that can be read, one nested past the depth read, and one whose
/// delimiter never comes before the end or the delimiter of the multipart
/// around it. The parser of a message in memory finds a delimiter anywhere in
/// a line, and reads a boundary in forms this does not, so a message it takes
/// apart can come out here as one part. So does a message attached to the
/// message: its bytes are handed over, not its parts.
fn by_parts(
    src: &dyn ByteSource,
    from: usize,
    to: usize,
    prefix: &str,
    budget: &mut Budget,
    visit: Visit<()>,
) -> Result<Option<()>, LimitHit> {
    let max = budget.limits.max_buffer_bytes;
    let mut lines = Lines::new(Reader::range(src, from, to));
    let mut stack: Vec<Vec<u8>> = Vec::new();
    // For each multipart of the stack, whether it is a digest.
    let mut digest: Vec<bool> = Vec::new();
    let mut n = 0usize;
    loop {
        let (block, cut) = header_block(&mut lines, &stack, max)?;
        let mut head = parse_head(&block);
        drop(block);
        let index = n;
        n += 1;
        let name = format!("{prefix}email-part-{index}");
        let multipart = head.mime.starts_with("multipart/");
        let mut end = match cut {
            Some(end) => end,
            None if multipart && head.boundary.is_some() && stack.len() < MAX_NESTED_MULTIPARTS => {
                let boundary = head.boundary.take().unwrap_or_default();
                lines.piece = lines.piece.max(LINE_PIECE + boundary.len() as u64);
                stack.push(boundary);
                digest.push(head.mime == "multipart/digest");
                let body_at = lines.pos;
                let (end, text) = skip(&mut lines, &stack).map_err(io_hit)?;
                let own = matches!(end, End::Delim { depth, .. } if depth + 1 == stack.len());
                if text && !own {
                    // The delimiter of this multipart never came: what was
                    // read is its body, read again from where it lies.
                    let body_end = match end {
                        End::Eof => lines.pos,
                        End::Delim { .. } => lines.last,
                    };
                    let (a, b) = (from + body_at as usize, from + body_end as usize);
                    let mut again = Lines::new(Reader::range(src, a, b));
                    let meta = MemberMeta {
                        name,
                        unsupported: Some(MULTIPART_NOT_FOUND),
                        ..MemberMeta::default()
                    };
                    let (stopped, _) = leaf(&mut again, &[], &head.encoding, &meta, budget, visit)?;
                    if stopped.is_some() {
                        return Ok(stopped);
                    }
                }
                end
            }
            None => {
                let unsupported = if multipart {
                    Some(if head.boundary.is_some() {
                        "email: multipart nested too deep, its parts read as its bytes"
                    } else {
                        MULTIPART_NOT_FOUND
                    })
                } else if is_attached_message(&head, digest.last() == Some(&true)) {
                    Some(ATTACHED_MESSAGE)
                } else {
                    None
                };
                let meta = MemberMeta {
                    name,
                    unsupported,
                    ..MemberMeta::default()
                };
                let (stopped, end) =
                    leaf(&mut lines, &stack, &head.encoding, &meta, budget, visit)?;
                if stopped.is_some() {
                    return Ok(stopped);
                }
                end
            }
        };
        // A closing delimiter ends its multipart; what follows, up to a
        // delimiter of the one around it, is its epilogue.
        loop {
            match end {
                End::Eof => return Ok(None),
                End::Delim {
                    depth,
                    close: false,
                } => {
                    stack.truncate(depth + 1);
                    digest.truncate(depth + 1);
                    break;
                }
                End::Delim { depth, close: true } => {
                    stack.truncate(depth);
                    digest.truncate(depth);
                    if stack.is_empty() {
                        return Ok(None);
                    }
                    end = skip(&mut lines, &stack).map_err(io_hit)?.0;
                }
            }
        }
    }
}
