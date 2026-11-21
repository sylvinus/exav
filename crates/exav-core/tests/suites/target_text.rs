//! Where `Target:0`, `3` (HTML), `4` (mail) and `7` (text) signatures match a
//! text-like file, each case first run through clamscan 1.4.3 with a
//! one-signature database:
//!
//! * a text file is matched lowercased and whitespace-collapsed by 0 and 7,
//!   its raw bytes by 0 alone; its HTML entities are not decoded;
//! * an HTML file is matched through its HTML view by 0 and 3, and its
//!   scripts, lowercased and normalised as script, by 0, 3 and 7;
//! * a mail's raw bytes are matched by 4, which nothing else is;
//! * an RTF is matched raw by 0 alone, with no normalised view. exav gives it
//!   both views on purpose (see "A pure-ASCII RTF is text" in the quirks
//!   guide), which these tests pin as well.
//!
//! exav ran 3, 4 and 7 over raw bytes of any text-like type, and HTML and text
//! views over every one of them: matches clamscan cannot make.
//!
//! The clamscan cases hold under `ScanOptions::clamav_compat()`. With the
//! `visible-text` feature, the default options add a text view of the words a
//! reader sees in an HTML file (Markdown, Office XML and drawings too), which
//! `Target:7` signatures match: a widening on purpose, tested in `visible_text`.

use exav_core::{ScanOptions, Scanner, Verdict, analyze, loader};

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

/// As clamscan scans: no visible-text view.
fn found_compat(target: u8, body: &str, file: &[u8]) -> bool {
    let v = analyze(&scanner(target, body), file, &ScanOptions::clamav_compat()).verdict;
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
    assert!(!found_compat(7, lower, HTML), "nor an HTML file");
    assert!(
        !found(0, lower, b"Some text &#104;ello world marker\n"),
        "a text file's entities are not decoded"
    );
}

/// The visible-text view is what lets a text signature see an HTML file; its
/// markup is still not part of it.
#[cfg(feature = "visible-text")]
#[test]
fn text_signatures_see_the_words_of_an_html_file_by_default() {
    let lower = "hello world marker";
    assert!(found(7, lower, HTML));
    assert!(!found(7, "<body>hello world marker", HTML), "no tags");
    assert!(!found(7, "HELLO WORLD MARKER", HTML), "never the raw bytes");
}

/// The scripts of a page are matched as text and as HTML once normalised as
/// script, as clamscan 1.4.3 matches them; the rest of the page is no text.
#[test]
fn text_signatures_match_the_scripts_of_a_page() {
    // Only the script view joins the two strings and lowercases them.
    let page: &[u8] = b"<html><body><p>plain words</p><script>var abcdef=\"Evil\"+\"Marker\";</script></body></html>\n";
    for found in [found, found_compat] {
        assert!(found(7, "\"evilmarker\"", page));
        assert!(found(3, "\"evilmarker\"", page));
        assert!(!found(7, "var abcdef", page), "not the script as written");
    }
    assert!(
        !found_compat(7, "plain words", page),
        "nor the rest of the page"
    );
}

/// A signature written on clamscan 1.4.3's normalised script names a declared
/// identifier by its number, from `n000` in each script, and the others as
/// written. Each case below was run through clamscan with a one-signature
/// database.
#[test]
fn signatures_on_clamscans_script_names_match_the_page() {
    let one: &[u8] = b"<html><body><script>var Payload = 'abc'; document.write(Payload);</script></body></html>\n";
    let two: &[u8] = b"<html><body><script>var a=1;</script><script>var b=2; document.write(b);</script></body></html>\n";
    for found in [found, found_compat] {
        for page in [one, two] {
            assert!(found(3, "document.write(n000)", page));
            assert!(found(7, "document.write(n000)", page));
        }
        assert!(!found(3, "document.write(n001)", one));
        assert!(found(3, "var n000=\"abc\";document.write(n000)", one));
        assert!(!found(3, "var n000=\"abc\";document.write(n000)", two));
    }
    // The page as a whole, which only exav normalises, numbers the names of
    // its scripts as one.
    assert!(!found_compat(3, "document.write(n001)", two));
    assert!(found(3, "document.write(n001)", two));
}

#[test]
fn html_signatures_match_the_html_view_alone() {
    let lower = "hello world marker";
    assert!(found(3, lower, HTML));
    assert!(found(0, lower, HTML));
    assert!(!found(3, "HELLO WORLD MARKER", HTML), "never the raw bytes");
    assert!(!found(3, lower, TEXT), "nor a text file");
}

/// What follows a `//` comment is part of the script, the comment's text is
/// read as code, names differ by case and text that spells a tag is no tag.
/// Each case was run through clamscan 1.4.3 with a one-signature database.
#[test]
fn the_view_of_a_script_goes_on_after_a_comment_and_reads_the_page_as_it_is() {
    let comment: &[u8] =
        b"<html><body><script>var a=1; // note\ndocument.write(a);</script></body></html>\n";
    let case: &[u8] =
        b"<html><body><script>var Abc=1; var abc=2; document.write(Abc, abc);</script></body></html>\n";
    let text: &[u8] = b"<html><body><p>&lt;script&gt;var a=1;&lt;/script&gt;</p><script>var b=2; document.write(b);</script></body></html>\n";
    for found in [found, found_compat] {
        assert!(found(3, "var n000=1;note document.write(n000);", comment));
        assert!(found(7, "var n000=1;note document.write(n000);", comment));
        assert!(found(3, "document.write(n000,n001)", case));
        assert!(!found(3, "document.write(n000,n000)", case));
        assert!(found(3, "var n000=2;document.write(n000)", text));
    }
    // Only the whole page, which clamscan does not normalise, has that text
    // as script.
    assert!(!found_compat(3, "var n000=1;", text));
}

/// An HTML file is also run through the script normaliser as a whole, which
/// decodes what an event handler holds. clamscan normalises its script
/// elements only, so under compat there is no such view.
#[test]
fn a_page_is_normalised_as_a_whole_unless_compat() {
    let page: &[u8] = b"<html><body><a onclick=x=unescape('%65%76%69%6c')>y</a></body></html>\n";
    assert!(found(3, "x=\"evil\"", page));
    assert!(!found_compat(3, "x=\"evil\"", page));
}

/// The scripts of a page keep a call as clamscan 1.4.3 writes it (each case
/// was run through clamscan with a one-signature database); the whole page,
/// which only exav normalises and not under compat, decodes it.
fn decoded_by_the_whole_page_only(script: &str, left: &str, decoded: &str) {
    let page = format!("<html><body><script>{script}</script></body></html>\n");
    let page = page.as_bytes();
    for found in [found, found_compat] {
        assert!(found(3, left, page), "{left}");
    }
    assert!(found(3, decoded, page), "{decoded}");
    assert!(!found_compat(3, decoded, page), "{decoded}");
}

#[test]
fn from_char_code_is_decoded_by_the_whole_page_only() {
    decoded_by_the_whole_page_only(
        "var a=String.fromCharCode(60,98,62); document.write(a);",
        "var n000=string.fromcharcode(60,98,62);document.write(n000)",
        "var n000=\"<b>\";document.write(n000)",
    );
}

#[test]
fn decode_uri_is_decoded_by_the_whole_page_only() {
    decoded_by_the_whole_page_only(
        "var a=decodeURI(\"%41%42\"); document.write(a);",
        "var n000=decodeuri(\"%41%42\");document.write(n000)",
        "var n000=\"ab\";document.write(n000)",
    );
}

#[test]
fn a_nested_unescape_is_decoded_by_the_whole_page_only() {
    decoded_by_the_whole_page_only(
        "var a=unescape(unescape(\"%2541\")); document.write(a);",
        "var n000=unescape(\"%41\");document.write(n000)",
        "var n000=\"a\";document.write(n000)",
    );
}

/// A number and the letters after it are two tokens, in the scripts of a page
/// and in the whole page.
#[test]
fn a_number_is_written_apart_from_the_letters_after_it() {
    let page: &[u8] = b"<html><body><script>var a=50em; var b=0x1f; document.write(a+b);</script></body></html>\n";
    for found in [found, found_compat] {
        let split = "var n000=50 em;var n001=0 x1f;document.write(n000+n001)";
        assert!(found(3, split, page));
        assert!(!found(3, "var n000=50em;", page));
    }
}

#[test]
fn mail_signatures_match_a_mails_raw_bytes() {
    assert!(found(4, "HELLO WORLD MARKER", MAIL));
    assert!(!found(4, "hello world marker", MAIL), "not a view");
    assert!(!found(4, "HELLO WORLD MARKER", TEXT), "nor a text file");
}

/// A message by its first line alone, as clamscan types it, with no blank line
/// after its one header, so that nothing of it is a part of its own.
const HEADER_HTML: &[u8] = b"Date: Mon, 1 Jan 2024\n<html><body>HELLO WORLD MARKER</body></html>\n";
const HEADER_TEXT: &[u8] = b"To: a note\nSome text HELLO WORLD MARKER here\n";

/// Its raw bytes meet `Target:4`, and it keeps the views it had as markup or as
/// text before its first line made it a message.
#[test]
fn a_file_that_starts_with_a_mail_header_keeps_its_views() {
    let (lower, upper) = ("hello world marker", "HELLO WORLD MARKER");
    for compat in [false, true] {
        let find = |target, body, file| {
            if compat {
                found_compat(target, body, file)
            } else {
                found(target, body, file)
            }
        };
        assert!(find(4, upper, HEADER_HTML), "a message's raw bytes");
        assert!(find(3, lower, HEADER_HTML), "its HTML view");
        assert!(find(4, upper, HEADER_TEXT), "a message's raw bytes");
        assert!(find(7, lower, HEADER_TEXT), "its text view");
        assert!(!find(3, lower, HEADER_TEXT), "no HTML view for text");
    }
}

/// Wider than clamscan, on purpose: an RTF's views are matched as well.
#[test]
fn an_rtf_is_matched_through_its_views_too() {
    assert!(found(0, "HELLO WORLD MARKER", RTF));
    assert!(found(0, "hello world marker", RTF));
    assert!(found(7, "hello world marker", RTF));
    assert!(!found(7, "HELLO WORLD MARKER", RTF), "never the raw bytes");
}
