//! The headers of an email a mail reader shows: who it is from and to, its
//! subject and date, with the display names and the RFC 2047 encoded words
//! decoded (mail-parser, the parser the scanner takes the message apart
//! with). The bodies are members of the message and are read as such.

use mail_parser::{Address, MessageParser};

use super::Out;

/// Whether `head` starts as a message does: a header line first, and at
/// least two of the headers every message has near the start.
pub(super) fn is_email(head: &[u8]) -> bool {
    let first = head.split(|&b| b == b'\n').next().unwrap_or_default();
    let colon = first.iter().position(|&b| b == b':');
    let header_first = colon.is_some_and(|c| {
        c > 0
            && first[..c]
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
    }) || first.starts_with(b"From ");
    if !header_first {
        return false;
    }
    let lower = head.to_ascii_lowercase();
    let at_line_start = |name: &[u8]| {
        lower.starts_with(name)
            || memchr::memmem::find_iter(&lower, name).any(|i| i > 0 && lower[i - 1] == b'\n')
    };
    [
        &b"from:"[..],
        b"to:",
        b"subject:",
        b"date:",
        b"received:",
        b"message-id:",
        b"mime-version:",
        b"return-path:",
    ]
    .iter()
    .filter(|h| at_line_start(h))
    .count()
        >= 2
}

pub(super) fn read(data: &[u8], out: &mut Out) {
    let Some(msg) = MessageParser::new().parse_headers(data) else {
        return;
    };
    for (name, address) in [
        ("From", msg.from()),
        ("Sender", msg.sender()),
        ("Reply-To", msg.reply_to()),
        ("To", msg.to()),
        ("Cc", msg.cc()),
        ("Bcc", msg.bcc()),
    ] {
        if let Some(a) = address {
            line(out, name, &addresses(a));
        }
    }
    if let Some(s) = msg.subject() {
        line(out, "Subject", s);
    }
    if let Some(d) = msg.date() {
        line(out, "Date", &d.to_rfc822());
    }
    // A body that is one HTML part, unencoded, is read as HTML too: what
    // follows header lines is HTML a reader may be shown whole.
    let (head, body) = split(data);
    let lower = head.to_ascii_lowercase();
    let multipart = memchr::memmem::find(&lower, b"multipart/").is_some();
    let start = body[..body.len().min(1024)].to_ascii_lowercase();
    if !multipart
        && super::HTML_MARKERS
            .iter()
            .any(|m| memchr::memmem::find(&start, m).is_some())
    {
        out.newline();
        super::html::read(&crate::html::decode(body), out);
    }
}

/// A message's header block and its body, apart at the first empty line.
fn split(data: &[u8]) -> (&[u8], &[u8]) {
    let crlf = memchr::memmem::find(data, b"\r\n\r\n").map(|i| (i, i + 4));
    let lf = memchr::memmem::find(data, b"\n\n").map(|i| (i, i + 2));
    match crlf.into_iter().chain(lf).min() {
        Some((end, body)) => (&data[..end], &data[body..]),
        None => (data, &[]),
    }
}

fn line(out: &mut Out, name: &str, value: &str) {
    if value.trim().is_empty() {
        return;
    }
    out.text(name);
    out.text(": ");
    out.text(value);
    out.newline();
}

/// The addresses of a header as a reader shows them: `Name <address>`, a
/// group by its name and its members.
fn addresses(a: &Address<'_>) -> String {
    let one = |name: Option<&str>, address: Option<&str>| match (name, address) {
        (Some(n), Some(a)) if !n.trim().is_empty() => format!("{n} <{a}>"),
        (_, Some(a)) => a.to_string(),
        (Some(n), None) => n.to_string(),
        (None, None) => String::new(),
    };
    let list = |addrs: &[mail_parser::Addr<'_>]| {
        addrs
            .iter()
            .map(|x| one(x.name.as_deref(), x.address.as_deref()))
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(", ")
    };
    match a {
        Address::List(l) => list(l),
        Address::Group(groups) => groups
            .iter()
            .map(|g| match g.name.as_deref() {
                Some(n) => format!("{n}: {};", list(&g.addresses)),
                None => list(&g.addresses),
            })
            .collect::<Vec<_>>()
            .join(", "),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_message_is_known_by_its_headers() {
        assert!(is_email(b"From: a@b.example\r\nTo: c@d.example\r\n\r\nhi"));
        assert!(is_email(
            b"Received: from x\r\n by y\r\nSubject: s\r\n\r\nbody"
        ));
        assert!(is_email(
            b"From a@b Mon Jan 1 00:00:00 2024\nFrom: a\nDate: x\n"
        ));
        assert!(!is_email(b"Subject: only one header\r\n\r\ntext"));
        assert!(!is_email(b"<html><body>From: a\nTo: b</body></html>"));
        assert!(!is_email(b"key: value\nother: value\n"));
    }
}
