#![allow(unused_imports)]
use crate::*;
use mail_parser::{Message, MessageParser, MessagePart, PartType};
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

/// The leaves of `msg` and of the messages attached to it, in order, named by
/// where they are: `email-part-3` and, in the message that is part 3,
/// `email-part-3-0`.
fn leaves<'a>(msg: &'a Message<'_>) -> Result<Vec<(String, &'a [u8])>, LimitHit> {
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
            PartType::Text(t) | PartType::Html(t) => out.push((leaf, t.as_bytes())),
            PartType::Binary(b) | PartType::InlineBinary(b) => out.push((leaf, b.as_ref())),
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

/// MIME email: emit each text/binary part (already base64/QP-decoded by the
/// parser), so attachments and bodies are scanned, those of attached messages
/// too.
pub(crate) fn extract_email<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    let msg =
        Parsed(Some(MessageParser::default().parse(data).ok_or_else(
            || LimitHit::new("email: parse failed".to_string()),
        )?));
    for (name, bytes) in leaves(&msg)? {
        budget.count_entry()?;
        let cap = budget.reserve()?;
        if bytes.len() as u64 > cap {
            return Err(LimitHit::new("email part exceeds budget".to_string()));
        }
        budget.commit(bytes.len() as u64);
        if let Some(r) = visit(Entry::new(name, bytes.to_vec()), budget) {
            return Ok(Some(r));
        }
    }
    Ok(None)
}
