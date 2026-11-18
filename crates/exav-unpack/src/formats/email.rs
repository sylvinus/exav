#![allow(unused_imports)]
use crate::*;
use mail_parser::{Message, MessageParser, MessagePart, MimeHeaders, PartType};
use std::collections::HashSet;
use std::io::{BufReader, Cursor, Read, Seek, Write};
use std::ops::Deref;

/// Deepest chain of `message/rfc822` parts read.
const MAX_NESTED_MESSAGES: usize = 64;

/// A parsed message that is taken apart without recursion when it is dropped.
/// A message holds the messages attached to it, and dropping a chain of them
/// one inside the other takes a frame of the stack for each: 40,000 levels is
/// a 1.4 MB file.
struct Parsed<'a>(Option<Message<'a>>);

impl<'a> Deref for Parsed<'a> {
    type Target = Message<'a>;
    fn deref(&self) -> &Message<'a> {
        self.0.as_ref().expect("held until dropped")
    }
}

impl Drop for Parsed<'_> {
    fn drop(&mut self) {
        let mut pending: Vec<Message<'_>> = self.0.take().into_iter().collect();
        while let Some(mut msg) = pending.pop() {
            for part in &mut msg.parts {
                if let PartType::Message(inner) =
                    std::mem::replace(&mut part.body, PartType::Binary(Default::default()))
                {
                    pending.push(inner);
                }
            }
        }
    }
}

/// Why a multipart that was not taken apart is reported.
pub const MULTIPART_NOT_FOUND: &str =
    "email: multipart whose parts were not found, its body read as one part";

/// A leaf of a message: its name, its part, and its bytes.
type Leaf<'a> = (String, &'a MessagePart<'a>, &'a [u8]);

/// Whether a leaf calls itself a multipart: the parser found no delimiter of
/// its boundary, or no boundary, and left its body as one part.
fn is_lost_multipart(part: &MessagePart<'_>) -> bool {
    part.content_type()
        .is_some_and(|ct| ct.ctype().eq_ignore_ascii_case("multipart"))
}

/// The leaves of `msg` and of the messages attached to it, in order, named by
/// where they are: `email-part-3` and, in the message that is part 3,
/// `email-part-3-0`.
fn leaves<'a>(msg: &'a Message<'_>) -> Result<Vec<Leaf<'a>>, LimitHit> {
    let mut out = vec![];
    // The parts being read, the name of the message they belong to, the next
    // one to read.
    let mut stack: Vec<(&[MessagePart<'_>], String, usize)> =
        vec![(&msg.parts, "email-part".to_string(), 0)];
    while let Some((parts, name, i)) = stack.pop() {
        let Some(part) = parts.get(i) else { continue };
        stack.push((parts, name.clone(), i + 1));
        let leaf = format!("{name}-{i}");
        match &part.body {
            PartType::Text(t) | PartType::Html(t) => out.push((leaf, part, t.as_bytes())),
            PartType::Binary(b) | PartType::InlineBinary(b) => out.push((leaf, part, b.as_ref())),
            PartType::Message(inner) => {
                if stack.len() > MAX_NESTED_MESSAGES {
                    return Err(LimitHit::new(format!(
                        "email: messages attached to messages more than {MAX_NESTED_MESSAGES} deep"
                    )));
                }
                stack.push((&inner.parts, leaf, 0));
            }
            // The parts of a multipart are the ones after it.
            PartType::Multipart(_) => {}
        }
    }
    Ok(out)
}

/// The boundaries of the multiparts in `msg` and in the messages attached to
/// it, outer first. A multipart the parser found no delimiter of is a leaf,
/// not one of them: closing it would give it a delimiter and no parts.
fn boundaries(msg: &Message<'_>) -> Vec<String> {
    let mut out = Vec::new();
    let mut pending: Vec<&Message<'_>> = vec![msg];
    while let Some(m) = pending.pop() {
        for part in &m.parts {
            if matches!(part.body, PartType::Multipart(_))
                && let Some(b) = part.content_type().and_then(|ct| ct.attribute("boundary"))
            {
                out.push(b.to_string());
            }
            if let PartType::Message(inner) = &part.body {
                pending.push(inner);
            }
        }
    }
    out
}

/// The closing delimiters a message lacks: a multipart that is cut short, or
/// that its writer never closed, has its last part dropped by the parser, and
/// a mail reader shows that part. Inner multiparts are closed first.
fn missing_closings(msg: &Message<'_>, data: &[u8]) -> Vec<u8> {
    let boundaries = boundaries(msg);
    // One pass over the lines for all of them: a search for each boundary in
    // turn reads the whole message once per multipart.
    let wanted: HashSet<&[u8]> = boundaries.iter().map(String::as_bytes).collect();
    let mut closed: HashSet<&[u8]> = HashSet::new();
    for line in data.split(|&c| c == b'\n') {
        if let Some(b) = line
            .trim_ascii_end()
            .strip_prefix(b"--")
            .and_then(|l| l.strip_suffix(b"--"))
            && wanted.contains(b)
        {
            closed.insert(b);
        }
    }
    let mut out = Vec::new();
    for b in boundaries.iter().rev() {
        if !closed.contains(b.as_bytes()) {
            out.extend_from_slice(format!("\r\n--{b}--\r\n").as_bytes());
        }
    }
    out
}

/// The bytes of a base64 part the parser could not decode, decoded as the
/// streamed reader decodes a body (`LenientBase64`), as the mail readers that
/// show such a part do.
fn lenient_decode(part: &MessagePart<'_>) -> Option<Vec<u8>> {
    if !part.is_encoding_problem {
        return None;
    }
    let declared = part
        .headers
        .iter()
        .find(|h| {
            h.name
                .as_str()
                .eq_ignore_ascii_case("content-transfer-encoding")
        })?
        .value
        .as_text()?
        .trim()
        .to_ascii_lowercase();
    if declared != "base64" {
        return None;
    }
    let raw: &[u8] = match &part.body {
        PartType::Text(t) | PartType::Html(t) => t.as_bytes(),
        PartType::Binary(b) | PartType::InlineBinary(b) => b.as_ref(),
        _ => return None,
    };
    let mut out = Vec::with_capacity(raw.len() / 4 * 3);
    super::email_stream::LenientBase64::default().feed(raw, &mut out);
    Some(out)
}

/// `data` with the line breaks removed that fold a `Content-Type` or
/// `Content-Disposition` header next to the `=` of a parameter (`boundary=`,
/// a break, then `"x"`). The parser reads no value after such a fold, and a
/// multipart with no boundary is not taken apart. `None` when there is no such
/// fold. A line of a body that looks like such a header is changed the same
/// way.
fn unfold_parameters(data: &[u8]) -> Option<Vec<u8>> {
    let mut out: Option<Vec<u8>> = None;
    let mut copied = 0;
    // The line being read is, or continues, one of those headers.
    let mut structured = false;
    // The last line: where it starts, and where its break does.
    let (mut prev_start, mut prev_break) = (0, 0);
    let mut at = 0;
    while at < data.len() {
        let end = data[at..]
            .iter()
            .position(|&c| c == b'\n')
            .map_or(data.len(), |p| at + p + 1);
        let line = &data[at..end];
        if matches!(line.first(), Some(b' ' | b'\t')) {
            let prev_ends = data[prev_start..prev_break].trim_ascii_end().last();
            let starts = line.trim_ascii_start().first();
            if structured && (prev_ends == Some(&b'=') || starts == Some(&b'=')) {
                let out = out.get_or_insert_with(Vec::new);
                out.extend_from_slice(&data[copied..prev_break]);
                copied = at;
            }
        } else {
            let head = |name: &[u8]| {
                line.len() >= name.len() && line[..name.len()].eq_ignore_ascii_case(name)
            };
            structured = head(b"content-type:") || head(b"content-disposition:");
        }
        prev_start = at;
        prev_break = if line.ends_with(b"\r\n") {
            end - 2
        } else if line.ends_with(b"\n") {
            end - 1
        } else {
            end
        };
        at = end;
    }
    let mut out = out?;
    out.extend_from_slice(&data[copied..]);
    Some(out)
}

/// MIME email: emit each text/binary part (already base64/QP-decoded by the
/// parser), so attachments and bodies are scanned, those of attached messages
/// too.
///
/// Four things are added to what the parser gives. Three are what a mail
/// reader shows: the last part of a multipart nothing closed, a base64 part
/// with a stray byte in it (read as far as it decodes), and a file uuencoded
/// into a text part. The fourth is a report: a multipart the parser found no
/// delimiter of is handed over as one part, and says so.
pub(crate) fn extract_email(data: &[u8], budget: &mut Budget, visit: Sink) -> crate::Extracted {
    fn parse(bytes: &[u8]) -> Result<Message<'_>, LimitHit> {
        MessageParser::default()
            .parse(bytes)
            .ok_or_else(|| LimitHit::corrupt("email: parse failed".to_string()))
    }
    let first = Parsed(Some(parse(data)?));
    // A fold next to the `=` of a boundary hides it from the parser: read the
    // message again with the fold removed, if it was a multipart the parser
    // could not take apart.
    let unfolded = if leaves(&first)?.iter().any(|l| is_lost_multipart(l.1)) {
        unfold_parameters(data)
    } else {
        None
    };
    let (data, first) = match &unfolded {
        Some(bytes) => {
            drop(first);
            (bytes.as_slice(), Parsed(Some(parse(bytes)?)))
        }
        None => (data, first),
    };
    let closings = missing_closings(&first, data);
    let completed;
    let msg = if closings.is_empty() {
        first
    } else {
        completed = [data, closings.as_slice()].concat();
        drop(first);
        Parsed(Some(parse(&completed)?))
    };
    type Held<'a> = (String, std::borrow::Cow<'a, [u8]>, Option<&'static str>);
    let mut entries: Vec<Held<'_>> = Vec::new();
    for (name, part, bytes) in leaves(&msg)? {
        if let Some(decoded) = lenient_decode(part) {
            entries.push((format!("{name}-decoded"), decoded.into(), None));
        }
        let lost = is_lost_multipart(part) && !bytes.trim_ascii().is_empty();
        entries.push((name, bytes.into(), lost.then_some(MULTIPART_NOT_FOUND)));
    }
    for (name, bytes, unsupported) in entries {
        budget.count_entry()?;
        let cap = budget.reserve()?;
        if bytes.len() as u64 > cap {
            let name = crate::tree::quoted(&name);
            budget.over_cap(cap, bytes.len() as u64, format_args!("email part '{name}'"))?;
            continue;
        }
        budget.commit(bytes.len() as u64);
        let mut entry = Entry::new(name, bytes.to_vec());
        entry.unsupported = unsupported;
        if let Some(r) = visit(entry, budget) {
            return Ok(Some(r));
        }
        // A file uuencoded into the text, as old mailers sent attachments.
        #[cfg(feature = "uuencode")]
        if memchr::memmem::find(&bytes, b"begin ").is_some()
            && let Some(r) = super::uuencode::extract_uuencode(&bytes, budget, &mut *visit)?
        {
            return Ok(Some(r));
        }
    }
    Ok(None)
}
