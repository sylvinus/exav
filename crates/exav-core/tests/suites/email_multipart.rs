//! A multipart message is taken apart as its writer meant it, or the scan
//! says it was not.
//!
//! The cases are a multipart whose delimiter never comes, a boundary longer
//! than the 64 KiB piece a line is read in, and a boundary folded onto the
//! next line. Each is a message past `limits.max_buffer_bytes` (read part by part
//! from a block cache), a message within it in a mailbox past it (read in
//! memory, message by message), or both. The marker is in the body in plain
//! text, or in a base64 attachment, so that it is found only if the parts are
//! told apart and the attachment is decoded.

use exav_core::unpack::spill::MemSpill;
use exav_core::{ScanOptions, Scanner, Verdict, loader, scan_path, scan_seekable};
use std::io::Cursor;

const MARKER: &[u8] = b"EXAV-EMAIL-MARKER";
const SIGNATURE: &str = "Zzz.InEmail";
const FROM_LINE: &str = "From sender@example.com Mon Jan  1 00:00:00 2024\n";

fn db() -> Scanner {
    let hex: String = MARKER.iter().map(|b| format!("{b:02x}")).collect();
    let mut l = loader::Builder::new();
    l.add_named_bytes("t.ndb", format!("{SIGNATURE}:0:*:{hex}\n").as_bytes(), true);
    l.build().expect("build database")
}

fn b64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for k in 0..4 {
            if k <= c.len() {
                s.push(A[(n >> (18 - 6 * k) & 63) as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

/// The marker in quoted-printable, so that it is not in the message's bytes.
fn marker_qp() -> String {
    let qp = format!("=45{}", &marker()[1..]);
    assert!(!qp.contains(marker()));
    qp
}

fn marker() -> &'static str {
    std::str::from_utf8(MARKER).unwrap()
}

/// A message of that `Content-Type` and body.
fn mime(content_type: &str, body: &str) -> String {
    format!(
        "From: a@example.com\nTo: b@example.com\nSubject: s\nMIME-Version: 1.0\n\
         Content-Type: {content_type}\n\n{body}"
    )
}

/// The same with a `Content-Transfer-Encoding` of its own.
fn mime_encoded(content_type: &str, encoding: &str, body: &str) -> String {
    format!(
        "From: a@example.com\nTo: b@example.com\nSubject: s\nMIME-Version: 1.0\n\
         Content-Type: {content_type}\nContent-Transfer-Encoding: {encoding}\n\n{body}"
    )
}

/// A text part of `filler` bytes, then an attachment whose base64 holds the
/// marker: found only if the two parts are told apart.
fn text_and_attachment(open: &str, close: &str, filler: usize) -> String {
    format!(
        "{open}\nContent-Type: text/plain\n\n{}\n{open}\n\
         Content-Type: application/octet-stream\nContent-Transfer-Encoding: base64\n\n{}\n{close}\n",
        "x".repeat(filler),
        b64(MARKER)
    )
}

/// A mailbox of small messages with `message` as the one after them.
fn mailbox(before: usize, message: &str) -> Vec<u8> {
    let mut out = String::new();
    for i in 0..before {
        out.push_str(&format!(
            "{FROM_LINE}From: s@example.com\nSubject: m{i}\n\n{}\n\n",
            "filler ".repeat(800)
        ));
    }
    out.push_str(FROM_LINE);
    out.push_str(message);
    out.push('\n');
    out.into_bytes()
}

fn options(hold: u64) -> ScanOptions {
    let mut o = ScanOptions::default();
    o.limits.max_buffer_bytes = hold;
    // A member past the limit is scanned whole, so that what a scan says of it
    // is what it holds, not that it was too large.
    o.spill = Some(std::sync::Arc::new(MemSpill::new()));
    o
}

/// The verdicts of the two entry points on `blob`; `tag` keeps the temporary
/// files of tests running together apart.
fn scan_both(blob: &[u8], limit: u64, tag: &str) -> Vec<Verdict> {
    assert!(
        blob.len() as u64 > limit,
        "{tag}: {} bytes is not past {limit}",
        blob.len()
    );
    let (db, opts) = (db(), options(limit));
    let seekable = scan_seekable(&db, Cursor::new(blob.to_vec()), blob.len() as u64, &opts)
        .expect("scan")
        .verdict;
    let dir = std::env::temp_dir().join(format!("exav-email-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let path = dir.join("mail.eml");
    std::fs::write(&path, blob).expect("write");
    let by_path = scan_path(&db, &path, &opts).expect("scan").verdict;
    let _ = std::fs::remove_dir_all(&dir);
    vec![seekable, by_path]
}

fn assert_infected(verdicts: &[Verdict]) {
    for v in verdicts {
        match v {
            Verdict::Infected { signature, .. } => assert_eq!(signature, SIGNATURE),
            other => panic!("the marker was not found: {other:?}"),
        }
    }
}

fn assert_unscannable(verdicts: &[Verdict]) {
    for v in verdicts {
        assert!(
            matches!(v, Verdict::Unscannable { .. }),
            "not reported as unread: {v:?}"
        );
    }
}

/// The delimiter of the multipart never comes, and the body, quoted-printable
/// as the message says, holds the marker.
fn no_delimiter(with_marker: bool, filler: usize) -> String {
    let tail = if with_marker {
        marker_qp()
    } else {
        "end".into()
    };
    mime_encoded(
        "multipart/mixed; boundary=\"NOPE\"",
        "quoted-printable",
        &format!("{}\n{tail}\n", "x".repeat(filler)),
    )
}

#[test]
fn a_message_past_the_limit_whose_multipart_has_no_delimiter_is_scanned() {
    let blob = no_delimiter(true, 20_000).into_bytes();
    assert_infected(&scan_both(&blob, 8192, "nodelim"));
}

#[test]
fn a_message_past_the_limit_whose_multipart_has_no_delimiter_is_not_clean() {
    let blob = no_delimiter(false, 20_000).into_bytes();
    assert_unscannable(&scan_both(&blob, 8192, "nodelim-clean"));
}

/// The message fits the limit, the mailbox does not: it is read in memory as
/// the third of the mailbox.
#[test]
fn a_mailbox_message_whose_multipart_has_no_delimiter_is_scanned() {
    let blob = mailbox(2, &no_delimiter(true, 100));
    assert_infected(&scan_both(&blob, 8192, "mbox-nodelim"));
}

#[test]
fn a_mailbox_message_whose_multipart_has_no_delimiter_is_not_clean() {
    let blob = mailbox(2, &no_delimiter(false, 100));
    assert_unscannable(&scan_both(&blob, 8192, "mbox-nodelim-clean"));
}

/// A boundary of 70,000 bytes: the delimiter lines are longer than the piece
/// a line is read in.
fn long_boundary() -> String {
    let boundary = "b".repeat(70_000);
    mime(
        &format!("multipart/mixed; boundary=\"{boundary}\""),
        &text_and_attachment(&format!("--{boundary}"), &format!("--{boundary}--"), 100),
    )
}

#[test]
fn a_message_past_the_limit_with_a_boundary_over_the_line_piece_is_scanned() {
    let blob = long_boundary().into_bytes();
    assert_infected(&scan_both(&blob, 200_000, "longb"));
}

#[test]
fn a_mailbox_message_with_a_boundary_over_the_line_piece_is_scanned() {
    let blob = mailbox(2, &long_boundary());
    assert_infected(&scan_both(&blob, 200_000, "mbox-longb"));
}

/// The boundary of a message, folded onto the next line after its `=`.
fn folded_boundary(filler: usize) -> String {
    mime(
        "multipart/mixed; boundary=\n \"XYZ\"",
        &text_and_attachment("--XYZ", "--XYZ--", filler),
    )
}

#[test]
fn a_message_past_the_limit_with_a_folded_boundary_is_scanned() {
    let blob = folded_boundary(20_000).into_bytes();
    assert_infected(&scan_both(&blob, 8192, "fold"));
}

/// The message fits the limit, the mailbox does not.
#[test]
fn a_mailbox_message_with_a_folded_boundary_is_scanned() {
    let blob = mailbox(2, &folded_boundary(100));
    assert_infected(&scan_both(&blob, 8192, "mbox-fold"));
}

/// Read in memory, with the default limit.
#[test]
fn a_message_within_the_limit_with_a_folded_boundary_is_scanned() {
    let blob = folded_boundary(100).into_bytes();
    let report = scan_seekable(
        &db(),
        Cursor::new(blob.clone()),
        blob.len() as u64,
        &ScanOptions::default(),
    )
    .expect("scan");
    assert_infected(&[report.verdict]);
}

/// An attached message past the limit, its attachment's base64 holding the
/// marker.
fn attached_message(filler: usize, inner_headers: &str) -> String {
    let inner = format!(
        "{inner_headers}Content-Type: multipart/mixed; boundary=\"IN\"\n\n{}",
        text_and_attachment("--IN", "--IN--", 100)
    );
    mime(
        "multipart/mixed; boundary=\"OUT\"",
        &format!(
            "--OUT\nContent-Type: text/plain\n\n{f}\n--OUT\nContent-Type: message/rfc822\n\n{inner}\n--OUT\nContent-Type: text/plain\n\n{f}\n--OUT--\n",
            f = "x".repeat(filler)
        ),
    )
}

/// The part-by-part reader hands the attached message over as its bytes; the
/// scanner types them as mail and takes the message apart in its turn.
#[test]
fn a_message_attached_to_a_message_past_the_limit_is_scanned() {
    let blob = attached_message(5_000, "From: c@example.com\nMIME-Version: 1.0\n").into_bytes();
    assert_infected(&scan_both(&blob, 8192, "attached"));
}

/// An attached message whose headers the scanner does not take for mail's
/// (no field only mail has, a type that is not the first field) is not taken
/// apart by it: the leaf says so.
#[test]
fn a_message_attached_to_a_message_past_the_limit_that_is_not_typed_as_mail_is_not_clean() {
    let blob = attached_message(5_000, "X-A: 1\n").into_bytes();
    assert_unscannable(&scan_both(&blob, 8192, "attached-untyped"));
}

/// A boundary in a form the part-by-part reader does not read (RFC 2231
/// continuations): the parts are not told apart, and the scan says so.
#[test]
fn a_message_past_the_limit_with_a_boundary_it_cannot_read_is_not_clean() {
    let blob = mime(
        "multipart/mixed; boundary*0=\"XY\"; boundary*1=\"Z\"",
        &text_and_attachment("--XYZ", "--XYZ--", 20_000),
    )
    .into_bytes();
    assert_unscannable(&scan_both(&blob, 8192, "rfc2231"));
}
