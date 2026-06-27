#![allow(unused_imports)]
use crate::*;
use std::io::{BufReader, Cursor, Read, Seek, Write};

/// MIME email: emit each text/binary part (already base64/QP-decoded by the
/// parser), so attachments and bodies are scanned.
pub(crate) fn extract_email<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    use mail_parser::{MessageParser, PartType};
    let msg = MessageParser::default()
        .parse(data)
        .ok_or_else(|| LimitHit::new("email: parse failed".to_string()))?;
    for (i, part) in msg.parts.iter().enumerate() {
        let bytes: Vec<u8> = match &part.body {
            PartType::Text(t) | PartType::Html(t) => t.as_bytes().to_vec(),
            PartType::Binary(b) | PartType::InlineBinary(b) => b.to_vec(),
            // Nested messages/multiparts are walked via their own parts.
            _ => continue,
        };
        budget.count_entry()?;
        let cap = budget.reserve()?;
        if bytes.len() as u64 > cap {
            return Err(LimitHit::new("email part exceeds budget".to_string()));
        }
        budget.commit(bytes.len() as u64);
        if let Some(r) = visit(Entry::new(format!("email-part-{i}"), bytes), budget) {
            return Ok(Some(r));
        }
    }
    Ok(None)
}
