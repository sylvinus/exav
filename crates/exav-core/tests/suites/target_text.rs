//! Where `Target:0`, `3` (HTML), `4` (mail) and `7` (text) signatures match a
//! text-like file, each case first run through clamscan 1.4.3 with a
//! one-signature database:
//!
//! * a text file is matched lowercased and whitespace-collapsed by 0 and 7,
//!   its raw bytes by 0 alone; its HTML entities are not decoded;
//! * an HTML file is matched through its HTML view by 0 and 3, never by 7;
//! * a mail's raw bytes are matched by 4, which nothing else is;
//! * an RTF is matched raw by 0 alone, with no normalised view. exav gives it
//!   both views on purpose (see "A pure-ASCII RTF is text" in the quirks
//!   guide), which these tests pin as well.
//!
//! exav ran 3, 4 and 7 over raw bytes of any text-like type, and HTML and text
//! views over every one of them: matches clamscan cannot make.

use exav_core::{analyze, loader, ScanOptions, Scanner, Verdict};

fn scanner(target: u8, body: &str) -> Scanner {
    let hex: String = body.bytes().map(|b| format!("{b:02x}")).collect();
    let mut l = loader::Builder::new();
    l.add_named_bytes(
        "t.ndb",
        format!("Test.Target:{target}:*:{hex}\n").as_bytes(),
        true,
    );
    l.build().unwrap()
}

fn found(target: u8, body: &str, file: &[u8]) -> bool {
    let v = analyze(&scanner(target, body), file, &ScanOptions::default()).verdict;
    matches!(v, Verdict::Infected { .. })
}

const TEXT: &[u8] = b"Some text HELLO WORLD MARKER here\n";
const RTF: &[u8] = b"{\\rtf1\\ansi HELLO WORLD MARKER}\n";
const HTML: &[u8] = b"<html><body>HELLO WORLD MARKER</body></html>\n";
const MAIL: &[u8] =
    b"From: a@b.c\nTo: d@e.f\nSubject: hi\nContent-Type: text/plain\n\nbody HELLO WORLD MARKER\n";

#[test]
fn text_signatures_match_the_text_view_alone() {
    let lower = "hello world marker";
    let upper = "HELLO WORLD MARKER";
    assert!(found(0, lower, TEXT));
    assert!(found(7, lower, TEXT));
    assert!(!found(7, upper, TEXT), "never the raw bytes");
    assert!(!found(7, lower, HTML), "nor an HTML file");
    assert!(
        !found(0, lower, b"Some text &#104;ello world marker\n"),
        "a text file's entities are not decoded"
    );
}

#[test]
fn html_signatures_match_the_html_view_alone() {
    let lower = "hello world marker";
    assert!(found(3, lower, HTML));
    assert!(found(0, lower, HTML));
    assert!(!found(3, "HELLO WORLD MARKER", HTML), "never the raw bytes");
    assert!(!found(3, lower, TEXT), "nor a text file");
}

#[test]
fn mail_signatures_match_a_mails_raw_bytes() {
    assert!(found(4, "HELLO WORLD MARKER", MAIL));
    assert!(!found(4, "hello world marker", MAIL), "not a view");
    assert!(!found(4, "HELLO WORLD MARKER", TEXT), "nor a text file");
}

/// Wider than clamscan, on purpose: an RTF's views are matched as well.
#[test]
fn an_rtf_is_matched_through_its_views_too() {
    assert!(found(0, "HELLO WORLD MARKER", RTF));
    assert!(found(0, "hello world marker", RTF));
    assert!(found(7, "hello world marker", RTF));
    assert!(!found(7, "HELLO WORLD MARKER", RTF), "never the raw bytes");
}
