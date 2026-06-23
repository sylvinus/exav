#![allow(unused_imports)]
use crate::*;
use std::io::{BufReader, Cursor, Read, Seek, Write};

/// MIME email: emit each text/binary part (already base64/QP-decoded by the
/// parser), so attachments and bodies are scanned.
pub(crate) fn extract_email(data: &[u8], budget: &mut Budget) -> Result<Vec<Entry>, LimitHit> {
    use mail_parser::{MessageParser, PartType};
    let msg = MessageParser::default()
        .parse(data)
        .ok_or_else(|| LimitHit::new("email: parse failed".to_string()))?;
    let mut entries = Vec::new();
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
        entries.push(Entry::new(format!("email-part-{i}"), bytes));
    }
    Ok(entries)
}
