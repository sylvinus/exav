//! Structure nested as deep as the file is long.
//!
//! A reader that follows a group, a part or an object into the next one with
//! a call of its own uses a frame of the stack per level, and a level costs a
//! few bytes of input: a megabyte of `{` is a million levels. The stack of a
//! thread is a few hundred kilobytes (a worker of the scan, a viewer, a
//! WebAssembly host) and running out of it ends the process, not the file. Each
//! reader that has nesting is walked here on a small stack with its structure
//! as deep as 200 KB of input makes it. It may refuse the file or read it, but
//! it has to end, in seconds, and without a panic.

use super::extract_each;
use exav_unpack::{Budget, Entry, Format, Limits};
use std::time::{Duration, Instant};

const STACK: usize = 512 * 1024;
const LEVELS: usize = 50_000;

/// Walks `data` as `fmt` on a [`STACK`]-sized thread. The failure, if any.
fn walk_small(fmt: Format, data: Vec<u8>) -> Result<Duration, String> {
    let started = Instant::now();
    let r = std::thread::Builder::new()
        .stack_size(STACK)
        .spawn(move || {
            let mut limits = Limits::default();
            limits.max_buffer_bytes = 64 << 20;
            limits.max_extracted_bytes = 128 << 20;
            let mut budget = Budget::new(limits);
            let r = extract_each(fmt, &data, &mut budget, &mut |_: Entry, _: &mut Budget| {
                None::<()>
            });
            matches!(r, Err(e) if e.reason.contains("panicked"))
        })
        .unwrap()
        .join();
    match r {
        Err(_) => Err("overflowed its stack or panicked".into()),
        Ok(true) => Err("the decoder panicked".into()),
        Ok(false) => Ok(started.elapsed()),
    }
}

fn check(fmt: Format, name: &str, data: Vec<u8>) -> Option<String> {
    match walk_small(fmt, data) {
        Err(e) => Some(format!("{fmt:?} {name}: {e}")),
        Ok(took) if took > Duration::from_secs(20) => {
            Some(format!("{fmt:?} {name}: took {:.1} s", took.as_secs_f64()))
        }
        Ok(_) => None,
    }
}

fn assert_all(findings: Vec<Option<String>>) {
    let findings: Vec<String> = findings.into_iter().flatten().collect();
    assert!(findings.is_empty(), "\n{}", findings.join("\n"));
}

#[cfg(feature = "rtf")]
#[test]
fn rtf_groups() {
    let n = LEVELS * 4;
    let wrap = |open: &str, inner: &str, close: &str| {
        format!("{{\\rtf1 {}{inner}{}}}", open.repeat(n), close.repeat(n)).into_bytes()
    };
    assert_all(vec![
        check(Format::Rtf, "groups", wrap("{", "x", "}")),
        check(Format::Rtf, "unclosed", wrap("{", "x", "")),
        check(Format::Rtf, "destinations", wrap("{\\*\\foo ", "x", "}")),
        check(
            Format::Rtf,
            "objdata",
            wrap("{\\object{\\*\\objdata ", "41", "}}"),
        ),
        check(
            Format::Rtf,
            "fields",
            wrap("{\\field{\\*\\fldinst ", "x", "}}"),
        ),
        check(Format::Rtf, "pict", wrap("{\\pict ", "41", "}")),
        check(
            Format::Rtf,
            "shapes",
            wrap("{\\shp{\\*\\shpinst ", "x", "}}"),
        ),
        check(Format::Rtf, "tables", wrap("\\trowd{\\intbl ", "x", "}")),
    ]);
}

#[cfg(feature = "email")]
#[test]
fn mime_parts() {
    let n = LEVELS / 5;
    // multipart inside multipart, each with a boundary of its own.
    let mut nested = String::new();
    for i in 0..n {
        nested.push_str(&format!(
            "Content-Type: multipart/mixed; boundary=\"b{i}\"\r\n\r\n--b{i}\r\n"
        ));
    }
    nested.push_str("Content-Type: text/plain\r\n\r\nx\r\n");
    // multipart inside multipart with the one boundary.
    let mut same = String::from("Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n");
    for _ in 0..n * 4 {
        same.push_str("--b\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n\r\n");
    }
    let rfc822 = "Content-Type: message/rfc822\r\n\r\n".repeat(n * 4);
    let rfc822_headers = format!(
        "From: a@b\r\n{}\r\nx",
        "Content-Type: message/rfc822\r\n\r\nFrom: a@b\r\n".repeat(n * 4)
    );
    let comments = format!(
        "From: a@b\r\nSubject: {}x{}\r\n\r\nx",
        "(".repeat(n * 8),
        ")".repeat(n * 8)
    );
    let groups = format!("To: {}a@b;\r\n\r\nx", "g:".repeat(n * 8));
    let quoted = format!("Subject: =?utf-8?q?{}?=\r\n\r\nx", "=3D".repeat(n * 8));
    assert_all(
        [
            ("multipart", nested),
            ("same boundary", same),
            ("message/rfc822", rfc822),
            ("rfc822 with headers", rfc822_headers),
            ("comments", comments),
            ("group addresses", groups),
            ("encoded words", quoted),
        ]
        .into_iter()
        .map(|(name, s)| check(Format::Email, name, s.into_bytes()))
        .collect(),
    );
}

#[cfg(feature = "xdp")]
#[test]
fn xdp_elements() {
    let n = LEVELS * 2;
    let head = "<?xml version=\"1.0\"?><xdp:xdp xmlns:xdp=\"http://ns.adobe.com/xdp/\">";
    let nest = |open: &str, close: &str, inner: &str| {
        format!(
            "{head}{}{inner}{}</xdp:xdp>",
            open.repeat(n),
            close.repeat(n)
        )
        .into_bytes()
    };
    assert_all(vec![
        check(Format::Xdp, "elements", nest("<a>", "</a>", "")),
        check(Format::Xdp, "unclosed", nest("<a>", "", "")),
        check(
            Format::Xdp,
            "chunks",
            nest("<pdf><chunk>", "</chunk></pdf>", "QQ=="),
        ),
        check(Format::Xdp, "comments", nest("<!--", "", "")),
        check(Format::Xdp, "cdata", nest("<![CDATA[", "", "")),
    ]);
}

/// A PDF whose one object is `body`.
#[cfg(feature = "pdf")]
fn pdf_with(objects: &str) -> Vec<u8> {
    format!("%PDF-1.7\n{objects}trailer\n<</Root 1 0 R /Size 3>>\n%%EOF\n").into_bytes()
}

/// PDFs whose structure is as deep as `LEVELS` makes it.
#[cfg(any(feature = "pdf", feature = "text-pdf"))]
fn deep_pdfs() -> Vec<(&'static str, Vec<u8>)> {
    let n = LEVELS * 2;
    let arrays = format!("{}{}", "[".repeat(n), "]".repeat(n));
    let dicts = format!("{}{}", "<</A ".repeat(n), ">>".repeat(n));
    let names = "/A ".repeat(n);
    let strings = format!("{}x{}", "(".repeat(n), ")".repeat(n));
    let mixed = format!("{}{}", "[<</A ".repeat(n), ">>]".repeat(n));
    // A chain of pages, each the parent of the next: 20,000 objects.
    let mut tree = String::from("1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n");
    for i in 2..20_000 {
        tree.push_str(&format!(
            "{i} 0 obj\n<</Type/Pages/Kids[{} 0 R]/Count 1/Parent {} 0 R>>\nendobj\n",
            i + 1,
            i - 1
        ));
    }
    // Objects that refer to each other.
    let cycle = "1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n\
        2 0 obj\n<</Type/Pages/Kids[2 0 R 3 0 R]/Count 1/Parent 3 0 R>>\nendobj\n\
        3 0 obj\n<</Type/Pages/Kids[2 0 R]/Count 1/Parent 2 0 R>>\nendobj\n";
    // A content stream's own nesting.
    let content = format!("q {}BT (x) Tj ET {}", "q ".repeat(n), "Q ".repeat(n));
    let stream = format!(
        "1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n\
         2 0 obj\n<</Type/Pages/Kids[3 0 R]/Count 1>>\nendobj\n\
         3 0 obj\n<</Type/Page/Parent 2 0 R/Contents 4 0 R>>\nendobj\n\
         4 0 obj\n<</Length {}>>\nstream\n{content}\nendstream\nendobj\n",
        content.len()
    );
    let tj = format!(
        "1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n\
         2 0 obj\n<</Type/Pages/Kids[3 0 R]/Count 1>>\nendobj\n\
         3 0 obj\n<</Type/Page/Parent 2 0 R/Contents 4 0 R>>\nendobj\n\
         4 0 obj\n<</Length {}>>\nstream\nBT {}(x){} TJ ET\nendstream\nendobj\n",
        n * 2 + 14,
        "[".repeat(n),
        "]".repeat(n)
    );
    let obj = |body: &str| format!("1 0 obj\n{body}\nendobj\n");
    vec![
        ("arrays", pdf_with(&obj(&arrays))),
        ("dictionaries", pdf_with(&obj(&dicts))),
        ("names", pdf_with(&obj(&format!("[{names}]")))),
        ("strings", pdf_with(&obj(&strings))),
        ("arrays of dictionaries", pdf_with(&obj(&mixed))),
        ("page tree", pdf_with(&tree)),
        ("page cycle", pdf_with(cycle)),
        ("q/Q", pdf_with(&stream)),
        ("TJ arrays", pdf_with(&tj)),
    ]
}

#[cfg(feature = "pdf")]
#[test]
fn pdf_objects() {
    assert_all(
        deep_pdfs()
            .into_iter()
            .map(|(name, pdf)| check(Format::Pdf, name, pdf))
            .collect(),
    );
}

#[cfg(feature = "text-pdf")]
#[test]
fn pdf_text() {
    use exav_unpack::text::{Kind, extract};
    let mut findings = vec![];
    for (name, pdf) in deep_pdfs() {
        let started = Instant::now();
        let r = std::thread::Builder::new()
            .stack_size(STACK)
            .spawn(move || {
                extract(Kind::Pdf, &pdf, 1 << 22, &Limits::default())
                    .text
                    .len()
            })
            .unwrap()
            .join();
        findings.push(match r {
            Err(_) => Some(format!("Pdf text {name}: overflowed its stack or panicked")),
            Ok(_) if started.elapsed() > Duration::from_secs(20) => {
                Some(format!("Pdf text {name}: took {:?}", started.elapsed()))
            }
            Ok(_) => None,
        });
    }
    assert_all(findings);
}

#[cfg(feature = "text")]
#[test]
fn text_markup() {
    use exav_unpack::text::{Kind, XmlPart, extract};
    let n = LEVELS * 4;
    let run = |kind: Kind, name: &str, src: String| -> Option<String> {
        let started = Instant::now();
        let r = std::thread::Builder::new()
            .stack_size(STACK)
            .spawn(move || {
                extract(kind, src.as_bytes(), 1 << 22, &Limits::default())
                    .text
                    .len()
            })
            .unwrap()
            .join();
        match r {
            Err(_) => Some(format!("{kind:?} {name}: overflowed its stack or panicked")),
            Ok(_) if started.elapsed() > Duration::from_secs(20) => {
                Some(format!("{kind:?} {name}: took {:?}", started.elapsed()))
            }
            Ok(_) => None,
        }
    };
    let mut findings = vec![];
    let html = [
        ("tables", "<table><tr><td>".repeat(n)),
        ("lists", "<ul><li>".repeat(n)),
        ("formatting", "<b><i><u><font>".repeat(n)),
        ("unclosed blockquote", "<blockquote>".repeat(n)),
        ("select", "<select><option>".repeat(n)),
        ("svg", "<svg><g>".repeat(n)),
        ("template", "<template>".repeat(n)),
        ("nested forms", "<form><div>".repeat(n)),
        ("closing tags", "</div>".repeat(n)),
        ("math", "<math><mrow>".repeat(n)),
    ];
    for (name, src) in html {
        findings.push(run(Kind::Html, name, src));
    }
    let parts = [
        XmlPart::Word,
        XmlPart::Slide,
        XmlPart::SharedStrings,
        XmlPart::Sheet,
        XmlPart::Odf,
    ];
    for part in parts {
        let shapes = [
            ("elements", "<a>".repeat(n)),
            ("paragraphs", "<w:p><w:r><w:t>".repeat(n)),
            ("drawing", "<a:p><a:r><a:t>".repeat(n)),
            ("odf", "<text:p><text:span><text:a>".repeat(n)),
            ("tables", "<w:tbl><w:tr><w:tc>".repeat(n)),
            ("sheet", "<c><is><r><t>".repeat(n)),
        ];
        for (name, src) in shapes {
            findings.push(run(Kind::Xml(part), name, src));
        }
    }
    assert_all(findings);
}
