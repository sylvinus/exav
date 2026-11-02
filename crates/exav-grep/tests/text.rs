//! `--text`: a Markdown file is searched as the text a reader sees.

#![cfg(feature = "text")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_exav-grep");

/// A scratch directory unique to one test, removed when the test ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let d = std::env::temp_dir().join(format!("exav-grep-text-{}-{tag}", std::process::id()));
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

/// Minimal stored-member ZIP (local headers only: exav reads those).
fn zip_of(name: &str, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"PK\x03\x04");
    for n in [20u16, 0, 0, 0, 0] {
        v.extend_from_slice(&n.to_le_bytes());
    }
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&(body.len() as u32).to_le_bytes());
    v.extend_from_slice(&(body.len() as u32).to_le_bytes());
    v.extend_from_slice(&(name.len() as u16).to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(name.as_bytes());
    v.extend_from_slice(body);
    v
}

#[test]
fn words_split_by_marks_are_found_only_with_text() {
    let s = Scratch::new("marks");
    let f = s.write(
        "notes.md",
        b"# Title\n\nPlease *download* the **new** version.\n",
    );
    let with = run(&["--text", "-F", "Please download the new version"], &f);
    assert_eq!(code(&with), 0, "{}", stdout(&with));
    assert_eq!(
        stdout(&with),
        format!("{}!text:2:Please download the new version.\n", f.display())
    );
    // Without it, the bytes are searched, marks and all.
    assert_eq!(
        code(&run(&["-F", "Please download the new version"], &f)),
        1
    );
    // And what is in the bytes still is, with it, only as the reader sees it.
    assert_eq!(code(&run(&["--text", "-F", "**new**"], &f)), 1);
}

#[test]
fn a_link_is_followed_by_where_it_goes_and_an_entity_is_decoded() {
    let s = Scratch::new("links");
    let f = s.write(
        "a.markdown",
        b"Sign in at [https://www.paypal.com/login](https://evil.example/steal) &amp; pay\n",
    );
    let o = run(&["--text", "evil.example/steal"], &f);
    assert_eq!(code(&o), 0);
    assert!(
        stdout(&o).contains("https://www.paypal.com/login (https://evil.example/steal) & pay"),
        "{}",
        stdout(&o)
    );
}

#[test]
fn a_member_of_an_archive_is_searched_by_its_own_name() {
    let s = Scratch::new("zip");
    let body = b"Please *download* it\n";
    let md = s.write("a.zip", &zip_of("docs/readme.md", body));
    let o = run(&["--text", "-F", "Please download it"], &md);
    assert_eq!(code(&o), 0);
    assert_eq!(
        stdout(&o),
        format!(
            "{}!docs/readme.md!text:1:Please download it\n",
            md.display()
        )
    );
    let txt = s.write("b.zip", &zip_of("docs/readme.txt", body));
    assert_eq!(code(&run(&["--text", "-F", "Please download it"], &txt)), 1);
}

#[test]
fn html_is_searched_without_its_tags() {
    let s = Scratch::new("html");
    let f = s.write(
        "page.html",
        b"<html><body><p>Click <b>here</b> to <a href='http://evil.example/x'>go on</a></p></body></html>",
    );
    let o = run(
        &[
            "--text",
            "-F",
            "Click here to go on (http://evil.example/x)",
        ],
        &f,
    );
    assert_eq!(code(&o), 0, "{}", stdout(&o));
    assert_eq!(
        stdout(&o),
        format!(
            "{}!text:1:Click here to go on (http://evil.example/x)\n",
            f.display()
        )
    );
    assert_eq!(code(&run(&["-F", "Click here to go on"], &f)), 1);
}

#[cfg(feature = "text-pdf")]
#[test]
fn a_pdf_is_searched_as_its_text_besides_its_streams() {
    let s = Scratch::new("pdf");
    let content = "BT /F1 12 Tf 72 700 Td [(Pay to ev) 10 (il.exa) 5 (mple)] TJ ET";
    let pdf = format!(
        "%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n\
         3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<</Font<</F1 5 0 R>>>>/Contents 4 0 R>>endobj\n\
         4 0 obj<</Length {}>>\nstream\n{content}\nendstream\nendobj\n\
         5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica/Encoding/WinAnsiEncoding>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n",
        content.len()
    );
    let f = s.write("doc.pdf", pdf.as_bytes());
    let o = run(&["--text", "-F", "Pay to evil.example"], &f);
    assert_eq!(code(&o), 0, "{}", stdout(&o));
    assert_eq!(
        stdout(&o),
        format!("{}!text:1:Pay to evil.example\n", f.display())
    );
    assert_eq!(code(&run(&["-F", "Pay to evil.example"], &f)), 1);
}

#[test]
fn other_files_are_searched_as_they_are() {
    let s = Scratch::new("other");
    let f = s.write("notes.txt", b"a *b* c\n");
    let o = run(&["--text", "-F", "a *b* c"], &f);
    assert_eq!(code(&o), 0);
    assert_eq!(stdout(&o), format!("{}:1:a *b* c\n", f.display()));
}
