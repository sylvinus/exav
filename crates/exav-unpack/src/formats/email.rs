#![allow(unused_imports)]
use crate::*;
use mail_parser::{Message, MessageParser, MessagePart, MimeHeaders, PartType};
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

/// A leaf of a message: its name, its part, and its bytes.
type Leaf<'a> = (String, &'a MessagePart<'a>, &'a [u8]);

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
/// it, outer first.
fn boundaries(msg: &Message<'_>) -> Vec<String> {
    let mut out = Vec::new();
    let mut pending: Vec<&Message<'_>> = vec![msg];
    while let Some(m) = pending.pop() {
        for part in &m.parts {
            if let Some(b) = part.content_type().and_then(|ct| ct.attribute("boundary")) {
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
    let mut out = Vec::new();
    for b in boundaries(msg).iter().rev() {
        let closing = format!("--{b}--");
        if memchr::memmem::find(data, closing.as_bytes()).is_none() {
            out.extend_from_slice(format!("\r\n{closing}\r\n").as_bytes());
        }
    }
    out
}

/// The text of a base64 or quoted-printable part the parser could not decode,
/// decoded as far as it goes: every byte outside the alphabet is skipped, as the
/// mail readers that show such a part do.
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
    let (mut acc, mut bits) = (0u32, 0u32);
    for &c in raw {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => continue,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// MIME email: emit each text/binary part (already base64/QP-decoded by the
/// parser), so attachments and bodies are scanned, those of attached messages
/// too.
///
/// Three things a mail reader shows that the parser leaves out are added: the
/// last part of a multipart nothing closed, a base64 part with a stray byte in
/// it (read as far as it decodes), and a file uuencoded into a text part.
pub(crate) fn extract_email<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    fn parse(bytes: &[u8]) -> Result<Message<'_>, LimitHit> {
        MessageParser::default()
            .parse(bytes)
            .ok_or_else(|| LimitHit::new("email: parse failed".to_string()))
    }
    let first = Parsed(Some(parse(data)?));
    let closings = missing_closings(&first, data);
    let completed;
    let msg = if closings.is_empty() {
        first
    } else {
        completed = [data, closings.as_slice()].concat();
        drop(first);
        Parsed(Some(parse(&completed)?))
    };
    let mut entries: Vec<(String, std::borrow::Cow<'_, [u8]>)> = Vec::new();
    for (name, part, bytes) in leaves(&msg)? {
        if let Some(decoded) = lenient_decode(part) {
            entries.push((format!("{name}-decoded"), decoded.into()));
        }
        entries.push((name, bytes.into()));
    }
    for (name, bytes) in entries {
        budget.count_entry()?;
        let cap = budget.reserve()?;
        if bytes.len() as u64 > cap {
            return Err(LimitHit::new("email part exceeds budget".to_string()));
        }
        budget.commit(bytes.len() as u64);
        if let Some(r) = visit(Entry::new(name.clone(), bytes.to_vec()), budget) {
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
