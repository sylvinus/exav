//! A string that `detect` finds a format by (the Script Encoder marker, an
//! XDP tag, the BinHex line, an AutoIt marker, a PDF header) does not take the
//! type of a page, a text, a script or a message that holds it: the signatures
//! of that type still apply, and the format is read as well.

use exav_core::{ScanOptions, Verdict, analyze, loader};

const WORD: &[u8] = b"evilphishmarker";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The name of the signature `line` (one `.ndb` line, without its name) finds
/// in `file`.
fn found(line: &str, file: &[u8]) -> Option<String> {
    let mut b = loader::Builder::new();
    b.add_named_bytes("t.ndb", format!("Exav.Test:{line}\n").as_bytes(), false);
    match analyze(&b.build().unwrap(), file, &ScanOptions::default()).verdict {
        Verdict::Infected { signature, .. } => Some(signature),
        _ => None,
    }
}

/// A signature for `WORD` for the files of `target`.
fn word(target: u8) -> String {
    format!("{target}:*:{}", hex(WORD))
}

const GUID: [u8; 16] = [
    0xA3, 0x48, 0x4B, 0xBE, 0x98, 0x6C, 0x4A, 0xA9, 0x99, 0x4C, 0x53, 0x0A, 0x86, 0xD6, 0x48, 0x7D,
];

/// Strings that are not the header of their format when they are in a text.
fn strings() -> Vec<Vec<u8>> {
    vec![
        b"#@~^".to_vec(),
        b"<xdp".to_vec(),
        b"(This file must be converted with BinHex 4.0)".to_vec(),
        b"AU3!EA05".to_vec(),
        b"AU3!EA06".to_vec(),
    ]
}

fn page(s: &[u8]) -> Vec<u8> {
    [
        &b"<html><body>"[..],
        s,
        b"<p>Login</p><script>var x=\"",
        WORD,
        b"\";</script></body></html>\n",
    ]
    .concat()
}

fn text(s: &[u8]) -> Vec<u8> {
    [
        &b"plain notes\nsome text with "[..],
        WORD,
        b" inside\n",
        s,
        b"\n",
    ]
    .concat()
}

fn script(s: &[u8]) -> Vec<u8> {
    [&b"#!/bin/sh\necho "[..], WORD, b"\n", s, b"\n"].concat()
}

fn message(first: &str, s: &[u8]) -> Vec<u8> {
    [
        first.as_bytes(),
        b"\nSubject: x\n\nhello ",
        WORD,
        b"\n",
        s,
        b"\n",
    ]
    .concat()
}

#[test]
fn a_page_holding_a_string_is_still_a_page() {
    let mut all = strings();
    all.push(b"%PDF-1.4".to_vec());
    all.push(b"<xdp:xdp xmlns:xdp=\"http://ns.adobe.com/xdp/\">".to_vec());
    all.push([&GUID[..], b"AU3!EA06"].concat());
    for s in all {
        let file = page(&s);
        assert_eq!(
            found(&word(3), &file).as_deref(),
            Some("Exav.Test"),
            "{s:?}"
        );
    }
}

#[test]
fn a_text_or_a_script_holding_a_string_is_still_text() {
    for s in strings() {
        for file in [text(&s), script(&s)] {
            assert_eq!(
                found(&word(7), &file).as_deref(),
                Some("Exav.Test"),
                "{s:?}"
            );
        }
    }
}

#[test]
fn a_message_holding_a_string_is_still_a_message() {
    let mut all = strings();
    all.push(b"%PDF-1.4".to_vec());
    for s in all {
        // Two of the headers that type a message by themselves; the third
        // is a message told by its MIME headers.
        for first in ["From: a@b", "Received: from x by y"] {
            let file = message(first, &s);
            assert_eq!(
                found(&word(4), &file).as_deref(),
                Some("Exav.Test"),
                "{first} {s:?}"
            );
        }
        // A PDF header types a message told by its MIME headers as a PDF.
        if s != b"%PDF-1.4" {
            let mime = message("MIME-Version: 1.0\nContent-Type: text/plain", &s);
            assert_eq!(
                found(&word(4), &mime).as_deref(),
                Some("Exav.Test"),
                "mime {s:?}"
            );
        }
    }
}

/// A PDF header near the start types a text as a PDF, as clamscan 1.4.3 does:
/// a text signature does not apply to it.
#[test]
fn a_pdf_header_in_a_text_still_types_it_as_a_pdf() {
    let file = text(b"%PDF-1.4");
    assert_eq!(found(&word(7), &file), None);
    assert_eq!(found(&word(0), &file).as_deref(), Some("Exav.Test"));
}

/// The compiled script's marker after its GUID types a text as AutoIt, as
/// clamscan 1.4.3 does, and the marker alone does not.
#[test]
fn a_compiled_autoit_marker_types_a_text_and_a_bare_one_does_not() {
    let guid = text(&[&GUID[..], b"AU3!EA06"].concat());
    assert_eq!(found(&word(7), &guid), None);
    assert_eq!(found(&word(0), &guid).as_deref(), Some("Exav.Test"));
    assert_eq!(
        found(&word(7), &text(b"AU3!EA06")).as_deref(),
        Some("Exav.Test")
    );
}

/// The published Script Encoder test vector; it decodes to a script that
/// calls `CreateObject("WScript.Shell")`.
const VECTOR: &[u8] = b"\x23\x40\x7e\x5e\x41\x41\x41\x41\x41\x41\x3d\x3d\x6a\x7f\x59\x7e\x6b\x50\x7b\x50\x5a\x4d\x2b\x6d\x4f\x2b\x7d\x34\x25\x2b\x31\x59\x63\x45\x71\x3f\x6d\x4d\x72\x77\x44\x52\x3f\x34\x6e\x73\x56\x72\x23\x40\x23\x40\x26\x64\x52\x5d\x3b\x09\x50\x45\x6d\x6d\x73\x6d\x63\x2b\x61\x6e\x72\x40\x23\x40\x26\x6e\x2d\x6d\x56\x63\x4a\x38\x51\x38\x4a\x62\x40\x23\x40\x26\x42\x42\x42\x42\x42\x42\x3d\x3d\x5e\x23\x7e\x40";

fn decoded_word() -> String {
    format!("0:*:{}", hex(b"CreateObject(\"WScript.Shell\")"))
}

/// A format found by a string in a text is read as well: a text, a page and a
/// script hold an encoded script, an XDP. A message does too, through its
/// body, which is scanned as an object of its own.
#[test]
fn the_format_a_string_names_is_read_as_well() {
    use base64::Engine;
    let payload = b"MEMBERPAYLOAD of the text suite";
    let member = format!("0:0:{}", hex(payload));
    let b64 = base64::engine::general_purpose::STANDARD.encode(payload);
    let xdp = format!("<xdp><pdf><chunk>{b64}</chunk></pdf></xdp>");
    for (what, file) in [
        (
            "page",
            [&b"<html><body>"[..], xdp.as_bytes(), b"</body></html>\n"].concat(),
        ),
        ("text", [&b"notes\n"[..], xdp.as_bytes(), b"\n"].concat()),
        (
            "script",
            [&b"#!/bin/sh\n"[..], xdp.as_bytes(), b"\n"].concat(),
        ),
        (
            "message",
            [&b"From: a@b\nSubject: x\n\n"[..], xdp.as_bytes(), b"\n"].concat(),
        ),
        (
            "message by MIME headers",
            [
                &b"MIME-Version: 1.0\nContent-Type: text/plain\n\n"[..],
                xdp.as_bytes(),
                b"\n",
            ]
            .concat(),
        ),
    ] {
        assert_eq!(
            found(&member, &file).as_deref(),
            Some("Exav.Test"),
            "{what}"
        );
    }
    for (what, file) in [
        ("text", [&b"notes\n"[..], VECTOR, b"\n"].concat()),
        (
            "page",
            [
                &b"<html><body><script>"[..],
                VECTOR,
                b"</script></body></html>",
            ]
            .concat(),
        ),
        (
            "message",
            [&b"From: a@b\nSubject: x\n\n"[..], VECTOR, b"\n"].concat(),
        ),
    ] {
        assert_eq!(
            found(&decoded_word(), &file).as_deref(),
            Some("Exav.Test"),
            "{what}"
        );
    }
}

/// A text that names XDP's tags, whose chunk is not base64, is a clean text;
/// an XDP whose chunk does not decode is not.
#[test]
fn a_text_naming_xdps_tags_is_not_an_unreadable_xdp() {
    let db = loader::Builder::new().build().unwrap();
    let verdict = |file: &[u8]| analyze(&db, file, &ScanOptions::default()).verdict;
    for file in [
        text(b"let s = \"<xdp><pdf><chunk>{b64}</chunk></pdf></xdp>\";"),
        text(b"<xdp:xdp xmlns:xdp=\"http://ns.adobe.com/xdp/\"><pdf><chunk>{b64}</chunk>"),
    ] {
        assert!(
            matches!(verdict(&file), Verdict::Clean),
            "{}",
            file.escape_ascii()
        );
    }
    let xdp = b"<?xml version=\"1.0\"?>\n<xdp:xdp xmlns:xdp=\"http://ns.adobe.com/xdp/\">\
<pdf><chunk>{b64}</chunk></pdf></xdp:xdp>\n";
    assert!(matches!(verdict(xdp), Verdict::Unscannable { .. }));
}
