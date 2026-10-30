//! `--text` on the office formats the XML parts do not reach: a match says
//! its sheet or slide, and a document whose text cannot be taken out is
//! reported unreadable.

#![cfg(feature = "text-office")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_exav-grep");

const XLS: &[u8] = include_bytes!("../../exav-render/tests/fixtures/office/sheets/sample.xls");
const PPT: &[u8] = include_bytes!("../../exav-render/tests/fixtures/office/slides/sample.ppt");
const DOC: &[u8] = include_bytes!("../../exav-render/tests/fixtures/office/docs/sample.doc");

/// A scratch directory unique to one test, removed when the test ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let d = std::env::temp_dir().join(format!("exav-grep-office-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("scratch dir");
        Scratch(d)
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let p = self.0.join(name);
        std::fs::write(&p, bytes).expect("write fixture");
        p
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(args: &[&str], file: &Path) -> Output {
    Command::new(BIN)
        .args(args)
        .arg(file)
        .output()
        .expect("spawn exav-grep")
}

fn code(o: &Output) -> i32 {
    o.status.code().expect("exited normally, not by signal")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn a_match_in_a_workbook_says_its_sheet() {
    let s = Scratch::new("xls");
    let f = s.write("budget.xls", XLS);
    let o = run(&["--text", "-F", "Second sheet"], &f);
    assert_eq!(code(&o), 0, "{}", stdout(&o));
    // The text, by sheet (the workbook's own stream is a member too, and its
    // bytes match as well).
    let line = format!("{}!text/sheet \"Notes\":2:Second sheet\t1\n", f.display());
    assert!(stdout(&o).contains(&line), "{}", stdout(&o));
    assert!(!stdout(&o).contains("sheet \"Budget\""), "{}", stdout(&o));
    // Another sheet's words are in that sheet.
    let o = run(&["--text", "-F", "Merged note"], &f);
    assert!(
        stdout(&o).contains(&format!("{}!text/sheet \"Budget\":", f.display())),
        "{}",
        stdout(&o)
    );
}

#[test]
fn a_match_in_a_presentation_says_its_slide() {
    let s = Scratch::new("ppt");
    let f = s.write("deck.ppt", PPT);
    let o = run(&["--text", "-F", "Second slide text"], &f);
    assert_eq!(code(&o), 0, "{}", stdout(&o));
    assert_eq!(
        stdout(&o),
        format!("{}!text/slide 2:2:Second slide text\n", f.display())
    );
}

#[test]
fn a_documents_words_are_found_without_its_formatting_and_one_block_is_the_text() {
    let s = Scratch::new("doc");
    let f = s.write("report.doc", DOC);
    let o = run(&["--text", "-F", "costs stayed flat"], &f);
    assert_eq!(code(&o), 0, "{}", stdout(&o));
    assert!(
        stdout(&o).starts_with(&format!("{}!text:", f.display())),
        "{}",
        stdout(&o)
    );
}

#[test]
fn an_encrypted_document_is_reported_unreadable_and_its_bytes_are_searched() {
    let s = Scratch::new("locked");
    let mut doc = DOC.to_vec();
    let at = (1..doc.len() / 512)
        .map(|n| n * 512)
        .find(|&o| doc[o] == 0xEC && doc[o + 1] == 0xA5)
        .expect("the FIB");
    doc[at + 0x0B] |= 0x01;
    let f = s.write("locked.doc", &doc);
    let o = run(&["--text", "-F", "no such words"], &f);
    // No match, and a part that could not be read: the search is incomplete.
    assert_eq!(code(&o), 3, "{}", stdout(&o));
    let all = format!("{}{}", stdout(&o), String::from_utf8_lossy(&o.stderr));
    assert!(
        all.contains("visible text") && all.contains("ncrypted"),
        "{all}"
    );
}

#[test]
fn without_text_the_bytes_are_searched_as_before() {
    let s = Scratch::new("bytes");
    let f = s.write("deck.ppt", PPT);
    let o = run(&["-a", "-F", "Second slide text"], &f);
    // The text is stored as UTF-16 or 8-bit in a compound file: the word
    // search on bytes may or may not see it, and never says a sheet or a slide.
    assert!(!stdout(&o).contains("!text"), "{}", stdout(&o));
}
