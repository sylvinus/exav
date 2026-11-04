//! What a text is, going by its start: a script, a message, a page, or any
//! other text. These have no magic; the scanner types them to apply the
//! signatures of their type, and [`crate::tree::Typing`] reads a message as
//! one. The one place that tells them, so that the two cannot disagree.

use crate::Format;

/// What a text is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextKind {
    /// A script with a `#!` line.
    Script,
    /// A message: a mail header first, or the headers of a MIME document.
    Message,
    /// A page of HTML.
    Page,
    /// Any other text.
    Plain,
}

/// The kind of text `head`, the start of an object, is. `None` for what is not
/// text.
pub fn text_kind(head: &[u8]) -> Option<TextKind> {
    if head.starts_with(b"#!") {
        return Some(TextKind::Script);
    }
    // Before HTML: a message whose body is HTML is a message, however its
    // headers say so. The scanner gives it the views of a page.
    if is_message(head) {
        return Some(TextKind::Message);
    }
    if looks_like_html(head) {
        return Some(TextKind::Page);
    }
    // Mostly-printable content with no more specific type is ASCII/UTF-8 text.
    // ClamAV distinguishes text from binary so `Target:7` (text) signatures apply
    // only to text; mirroring that keeps text sigs off binary blobs.
    looks_textual(head).then_some(TextKind::Plain)
}

/// Whether `head` is a message: not a script, and a mail header first or the
/// headers of a MIME document.
pub fn is_message(head: &[u8]) -> bool {
    !head.starts_with(b"#!") && (starts_like_mail(head) || looks_like_email(head))
}

/// The kind of text that keeps its kind, when [`crate::detect`] gives `fmt` for
/// a string it finds in the object ([`crate::is_found_by_string`]); `None`
/// when `fmt` is what the object is.
///
/// A string in a text is not a header: the text keeps its type, its
/// `Target` signatures and its views, and the format is read as well. Where
/// the string is a header ([`crate::string_is_header`]) the format is what the
/// object is, as clamscan 1.4.3 types the same bytes, but a page and a message
/// that starts with a mail header keep theirs (XDP, AutoIt). A PDF header near
/// the start is no header: it makes a text, a script and a message told by its
/// MIME headers a PDF, as it does for clamscan, and not a page or a message
/// that starts with a mail header.
pub fn text_keeps(fmt: Format, head: &[u8]) -> Option<TextKind> {
    let header = crate::string_is_header(fmt, head);
    if header && matches!(fmt, Format::Pdf | Format::Screnc | Format::Binhex) {
        return None;
    }
    let own = text_kind(head)?;
    let page_or_mail = own == TextKind::Page || starts_like_mail(head);
    let keeps = match fmt {
        Format::Pdf => page_or_mail,
        Format::Xdp | Format::Autoit => !header || page_or_mail,
        _ => true,
    };
    keeps.then_some(own)
}

/// True if the head looks like text (ASCII *or* UTF-8) rather than binary.
/// Generous on purpose: a NUL byte or a high density of non-whitespace control
/// bytes marks binary, but high bytes (0x80..=0xff) are accepted so non-ASCII
/// UTF-8 text still types as text. Otherwise non-English text malware would
/// type as binary and lose its `Target:7` (ASCII-text) coverage.
pub fn looks_textual(buf: &[u8]) -> bool {
    let head = &buf[..buf.len().min(8192)];
    if head.is_empty() {
        return false;
    }
    let mut ctrl = 0usize;
    for &b in head {
        if b == 0 {
            return false; // NUL => binary
        }
        if b < 0x20 && !matches!(b, b'\t' | b'\n' | b'\r' | 0x0c) {
            ctrl += 1;
        }
    }
    ctrl * 20 < head.len() // < 5% non-whitespace control bytes
}

/// Heuristic HTML detection (HTML has no magic bytes). ClamAV types content as
/// HTML and applies `Target:3` signatures only to it; the scanner mirrors that
/// so an HTML-exploit sig does not fire on, say, obfuscated JavaScript that
/// merely contains `Uint32Array(0x..)`. Conservative: requires a real
/// structural tag in the (text-ish) head. Plain JS/text is left `Unknown` and
/// is still covered by `Target:7` text signatures.
pub fn looks_like_html(buf: &[u8]) -> bool {
    let head = &buf[..buf.len().min(8192)];
    // Must be text-ish (mostly printable); skip binary that happens to contain
    // an angle-bracket sequence.
    let printable = head
        .iter()
        .filter(|&&b| b == b'\t' || b == b'\n' || b == b'\r' || (0x20..=0x7e).contains(&b))
        .count();
    if head.is_empty() || printable * 10 < head.len() * 9 {
        return false;
    }
    let lower = head.to_ascii_lowercase();
    const MARKERS: &[&[u8]] = &[
        b"<!doctype html",
        b"<html",
        b"<head",
        b"<body",
        b"<script",
        b"<iframe",
        b"<title",
        b"<table",
        b"<style",
        b"<meta ",
        b"<div",
        b"<span",
        b"<a href",
        b"<img ",
    ];
    MARKERS
        .iter()
        .any(|m| memchr::memmem::find(&lower, m).is_some())
}

/// What a file starts with for ClamAV to type it as mail (`MBox`, `Exim`,
/// `Raw`, `Maildir` and `Mail file` in `clamscan --debug`), whatever follows:
/// no MIME header, no body, no second header. Case counts, the colon is
/// followed by a space, and nothing may come before: a blank line, a space or a
/// byte order mark first make it text. Measured with clamscan 1.4.3 over 260
/// header names; the other names a message starts with (`Cc`, `Reply-To`,
/// `Content-Type`, `MIME-Version`, `X-Mailer`, `X-Mozilla-Status`) do not type
/// it, and are left to [`looks_like_email`].
const MAIL_MAGICS: &[&[u8]] = &[
    b"From ",
    b"From: ",
    b"Received: ",
    b"Received-SPF: ",
    b"Return-Path: ",
    b"Return-path: ",
    b"To: ",
    b"Subject: ",
    b"Message-ID: ",
    b"Message-Id: ",
    b"Date: ",
    b"Delivered-To: ",
    b"Envelope-to: ",
    b"X-Original-To: ",
    b"X-Envelope-From: ",
    b"X-Apparently-To: ",
    b"X-Real-To: ",
    b"X-Sieve: ",
    b"X-UIDL: ",
];

/// Whether `buf` starts with one of the headers that type a message by itself.
pub fn starts_like_mail(buf: &[u8]) -> bool {
    MAIL_MAGICS.iter().any(|m| buf.starts_with(m))
}

/// How much of the start is read to judge a message by its headers.
const EMAIL_HEAD: usize = 64 * 1024;

/// The length of the name of the header field `line` starts with, when it
/// starts with one: some visible characters and a colon.
pub fn field_name_len(line: &[u8]) -> Option<usize> {
    let colon = line.iter().position(|&b| b == b':')?;
    let name = &line[..colon];
    (!name.is_empty() && name.len() <= 64 && name.iter().all(|b| b.is_ascii_graphic()))
        .then_some(colon)
}

/// Heuristic RFC822/MIME detection (email has no magic bytes), for the messages
/// [`starts_like_mail`] does not catch.
///
/// A header block that starts with a header field and carries a MIME header and
/// a header only mail has. Names are not case sensitive and the first field is
/// any: a mail client writes its own (`X-Mozilla-Status`, `X-Account-Key`)
/// ahead of the rest, and a gateway adds a long run of `Received` fields before
/// the MIME headers.
pub fn looks_like_email(buf: &[u8]) -> bool {
    let head = &buf[..buf.len().min(EMAIL_HEAD)];
    // The header block: up to the first empty line.
    let end = head
        .windows(2)
        .position(|w| w == b"\n\n")
        .into_iter()
        .chain(head.windows(4).position(|w| w == b"\r\n\r\n"))
        .min()
        .unwrap_or(head.len());
    let block = &head[..end];
    let field_name = |line: &[u8]| -> Option<String> {
        let colon = field_name_len(line)?;
        Some(String::from_utf8_lossy(&line[..colon]).to_ascii_lowercase())
    };
    let mut lines = block.split(|&b| b == b'\n');
    let Some(first) = lines.next().and_then(field_name) else {
        return false;
    };
    // Folded lines start with white space and name nothing.
    let names: Vec<String> = std::iter::once(first.clone())
        .chain(lines.filter_map(field_name))
        .collect();
    let has = |n: &str| names.iter().any(|x| x == n);
    let mime = has("mime-version") || has("content-type");
    const ONLY_MAIL: &[&str] = &[
        "received",
        "return-path",
        "from",
        "to",
        "subject",
        "date",
        "message-id",
        "delivered-to",
        "mime-version",
    ];
    // A part saved on its own starts with its `Content-Type`.
    mime && (first == "content-type" || ONLY_MAIL.iter().any(|n| has(n)))
}
