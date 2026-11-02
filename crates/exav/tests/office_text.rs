//! The office formats' text through the command line (`visible-text-office`):
//! a DOC, an XLS and an RTF are matched as the words a reader sees, a link is
//! judged with `--detect phishing`, and a document whose text cannot be taken
//! out is `PARTIAL` (exit 3), never `OK`.

#![cfg(feature = "visible-text-office")]

use std::path::Path;
use std::process::Command;

#[path = "../src/tmpfile.rs"]
mod tmpfile;
use tmpfile::TempDir;

const DOC: &[u8] = include_bytes!("../../exav-render/tests/fixtures/office/docs/sample.doc");
const XLS: &[u8] = include_bytes!("../../exav-render/tests/fixtures/office/sheets/sample.xls");
const PPT: &[u8] = include_bytes!("../../exav-render/tests/fixtures/office/slides/sample.ppt");

/// A database of one text-view signature (`Target:7`) for `words`.
fn sigs(words: &str) -> TempDir {
    let d = TempDir::new().unwrap();
    let hex: String = words.bytes().map(|b| format!("{b:02x}")).collect();
    std::fs::write(
        d.path().join("t.ndb"),
        format!("Test.Office.Text:7:*:{hex}\n"),
    )
    .unwrap();
    d
}

/// Exit code and stdout of `exav` on `file`.
fn scan(db: &Path, file: &Path, extra: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_exav"))
        .arg("-d")
        .arg(db)
        .args(extra)
        .arg(file)
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

fn put(dir: &TempDir, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let p = dir.path().join(name);
    std::fs::write(&p, bytes).unwrap();
    p
}

#[test]
fn the_words_of_a_doc_an_xls_and_a_ppt_are_found() {
    let dir = TempDir::new().unwrap();
    for (name, bytes, words) in [
        ("report.doc", DOC, "revenue grew by twelve percent"),
        ("budget.xls", XLS, "merged note across three columns"),
        ("deck.ppt", PPT, "revenue up 12%"),
    ] {
        let file = put(&dir, name, bytes);
        let db = sigs(words);
        let (code, out) = scan(db.path(), &file, &[]);
        assert_eq!(code, 1, "{name}: {out}");
        assert!(out.contains("Test.Office.Text FOUND"), "{name}: {out}");
        // Words that are not in it: clean.
        let other = sigs("words that no fixture holds");
        let (code, out) = scan(other.path(), &file, &[]);
        assert_eq!(code, 0, "{name}: {out}");
    }
}

#[test]
fn a_link_that_says_one_site_and_goes_to_another_is_found_in_an_rtf() {
    let dir = TempDir::new().unwrap();
    let rtf = b"{\\rtf1\\ansi Sign in: {\\field{\\*\\fldinst HYPERLINK \"https://evil.example/steal\"}{\\fldrslt https://www.paypal.com/login}}\\par}";
    let file = put(&dir, "mail.rtf", rtf);
    let db = sigs("never present");
    let (code, out) = scan(db.path(), &file, &["--detect", "phishing"]);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("Heuristics.Phishing.Email.SpoofedDomain FOUND"),
        "{out}"
    );
    let (code, _) = scan(db.path(), &file, &[]);
    assert_eq!(code, 0);
}

#[test]
fn an_encrypted_doc_is_partial_not_ok() {
    let dir = TempDir::new().unwrap();
    let mut doc = DOC.to_vec();
    let at = (1..doc.len() / 512)
        .map(|s| s * 512)
        .find(|&o| doc[o] == 0xEC && doc[o + 1] == 0xA5)
        .expect("the FIB");
    // fEncrypted, bit 8 of the FIB's flags.
    doc[at + 0x0B] |= 0x01;
    let file = put(&dir, "locked.doc", &doc);
    let db = sigs("never present");
    let (code, out) = scan(db.path(), &file, &[]);
    assert_eq!(code, 3, "{out}");
    assert!(out.contains("PARTIAL"), "{out}");
    // The same file, not encrypted: OK.
    let ok = put(&dir, "plain.doc", DOC);
    assert_eq!(scan(db.path(), &ok, &[]).0, 0);
}
