//! A Markdown document is matched through the text a reader sees as well as
//! its bytes: its words without the marks, entities decoded, and where each
//! link leads. Which files are Markdown is their name's: `.md` and
//! `.markdown`, the input's or a member's.

use exav_core::{analyze, loader, ScanOptions, Scanner, Verdict};

/// A one-signature database: `Target:7`, which a text view alone matches.
fn scanner(target: u8, body: &str) -> Scanner {
    let hex: String = body.bytes().map(|b| format!("{b:02x}")).collect();
    let mut l = loader::Builder::new();
    l.add_named_bytes(
        "t.ndb",
        format!("Test.Visible:{target}:*:{hex}\n").as_bytes(),
        true,
    );
    l.build().unwrap()
}

fn verdict(db: &Scanner, name: Option<&str>, file: &[u8], compat: bool) -> Verdict {
    let mut o = ScanOptions::default();
    o.filename = name.map(str::to_string);
    o.clamav_compat = compat;
    analyze(db, file, &o).verdict
}

fn found(target: u8, body: &str, name: Option<&str>, file: &[u8]) -> bool {
    matches!(
        verdict(&scanner(target, body), name, file, false),
        Verdict::Infected { .. }
    )
}

#[test]
fn the_words_are_matched_without_the_marks_between_them() {
    let md = b"Please *Download* the **new** version.\n";
    let sig = "please download the new version.";
    assert!(found(7, sig, Some("README.md"), md));
    assert!(found(7, sig, Some("notes.MARKDOWN"), md));
    // The same bytes under another name are text, whose view keeps the marks.
    assert!(!found(7, sig, Some("notes.txt"), md));
    assert!(!found(7, sig, None, md));
}

#[test]
fn an_entity_is_matched_as_the_character_it_is() {
    let md = b"Fish &amp; chips &lt;now&gt;\n";
    assert!(found(7, "fish & chips <now>", Some("a.md"), md));
    assert!(!found(7, "fish & chips <now>", Some("a.txt"), md));
}

#[test]
fn a_link_is_matched_as_its_label_and_where_it_goes() {
    let md = b"[Click here](https://evil.example/payload.exe) to continue\n";
    assert!(found(
        7,
        "click here (https://evil.example/payload.exe) to continue",
        Some("a.md"),
        md
    ));
    // The label names one site, the target another.
    let spoof = b"Sign in at [https://www.paypal.com/login](https://evil.example/steal)\n";
    assert!(found(
        7,
        "https://www.paypal.com/login (https://evil.example/steal)",
        Some("a.md"),
        spoof
    ));
    // A target the viewer would refuse is still seen.
    assert!(found(
        7,
        "run (javascript:alert(1))",
        Some("a.md"),
        b"[run](javascript:alert(1))\n"
    ));
}

#[test]
fn target_zero_signatures_see_it_too_and_html_ones_do_not() {
    let md = b"a *b* c\n";
    assert!(found(0, "a b c", Some("a.md"), md));
    assert!(!found(3, "a b c", Some("a.md"), md));
}

#[test]
fn the_bytes_are_still_matched_as_before() {
    assert!(found(0, "a *b* c", Some("a.md"), b"A *B* C\n"));
}

#[test]
fn not_under_clamav_compat() {
    let md = b"Please *download* it\n";
    let db = scanner(7, "please download it");
    assert!(matches!(
        verdict(&db, Some("a.md"), md, false),
        Verdict::Infected { .. }
    ));
    assert!(matches!(
        verdict(&db, Some("a.md"), md, true),
        Verdict::Clean
    ));
}

/// A stored-only ZIP holding one member.
fn zip_with(name: &str, data: &[u8]) -> Vec<u8> {
    let crc = {
        let mut c = !0u32;
        for &b in data {
            c ^= b as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    (c >> 1) ^ 0xEDB8_8320
                } else {
                    c >> 1
                };
            }
        }
        !c
    };
    let mut out = Vec::new();
    out.extend_from_slice(b"PK\x03\x04");
    for v in [20u16, 0, 0, 0, 0] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(data);
    let cd = out.len() as u32;
    let mut c = Vec::new();
    c.extend_from_slice(b"PK\x01\x02");
    for v in [20u16, 20, 0, 0, 0, 0] {
        c.extend_from_slice(&v.to_le_bytes());
    }
    c.extend_from_slice(&crc.to_le_bytes());
    c.extend_from_slice(&(data.len() as u32).to_le_bytes());
    c.extend_from_slice(&(data.len() as u32).to_le_bytes());
    c.extend_from_slice(&(name.len() as u16).to_le_bytes());
    for v in [0u16, 0, 0, 0] {
        c.extend_from_slice(&v.to_le_bytes());
    }
    c.extend_from_slice(&0u32.to_le_bytes());
    c.extend_from_slice(&0u32.to_le_bytes());
    c.extend_from_slice(name.as_bytes());
    let cl = c.len() as u32;
    out.extend_from_slice(&c);
    out.extend_from_slice(b"PK\x05\x06");
    for v in [0u16, 0, 1, 1] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&cl.to_le_bytes());
    out.extend_from_slice(&cd.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

#[test]
fn a_member_is_markdown_by_its_own_name() {
    let md = b"Please *download* the **new** version.\n";
    let sig = scanner(7, "please download the new version.");
    let yes = zip_with("docs/Readme.md", md);
    let no = zip_with("docs/readme.txt", md);
    assert!(matches!(
        verdict(&sig, None, &yes, false),
        Verdict::Infected { .. }
    ));
    assert!(matches!(verdict(&sig, None, &no, false), Verdict::Clean));
    // The archive's own name does not make its members Markdown.
    assert!(matches!(
        verdict(&sig, Some("x.md"), &no, false),
        Verdict::Clean
    ));
}

/// A one-page PDF, its text drawn by `content`, padded to `pad` bytes.
#[cfg(feature = "visible-text-pdf")]
fn pdf_with(content: &str, pad: usize) -> Vec<u8> {
    let mut v = format!(
        "%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n\
         2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n\
         3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<</Font<</F1 5 0 R>>>>/Contents 4 0 R>>endobj\n\
         4 0 obj<</Length {}>>\nstream\n{content}\nendstream\nendobj\n\
         5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica/Encoding/WinAnsiEncoding>>endobj\n\
         trailer<</Root 1 0 R>>\n%%EOF\n",
        content.len()
    )
    .into_bytes();
    if v.len() < pad {
        v.resize(pad, b'\n');
    }
    v
}

#[cfg(feature = "visible-text-pdf")]
#[test]
fn a_pdfs_text_is_matched_though_its_bytes_hold_it_in_pieces() {
    let pdf = pdf_with(
        "BT /F1 12 Tf 72 700 Td [(Pay to ev) 10 (il.exa) 5 (mple)] TJ ET",
        0,
    );
    assert!(found(7, "pay to evil.example", None, &pdf));
    assert!(found(0, "pay to evil.example", None, &pdf));
}

#[cfg(feature = "visible-text-pdf")]
#[test]
fn a_compressed_pdf_stream_is_read_through() {
    use std::io::Write;
    let content = "BT /F1 12 Tf 72 700 Td (Compressed bait text) Tj ET";
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    z.write_all(content.as_bytes()).unwrap();
    let z = z.finish().unwrap();
    let mut pdf = b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<</Font<</F1 5 0 R>>>>/Contents 4 0 R>>endobj\n".to_vec();
    pdf.extend_from_slice(
        format!(
            "4 0 obj<</Length {}/Filter/FlateDecode>>\nstream\n",
            z.len()
        )
        .as_bytes(),
    );
    pdf.extend_from_slice(&z);
    pdf.extend_from_slice(b"\nendstream\nendobj\n5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica/Encoding/WinAnsiEncoding>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n");
    assert!(found(7, "compressed bait text", None, &pdf));
}

#[test]
fn html_is_matched_without_its_tags() {
    let html = b"<html><body><p>Click <b>here</b> to <a href='http://evil.example/x'>continue</a></p></body></html>";
    assert!(found(
        7,
        "click here to continue (http://evil.example/x)",
        Some("mail.html"),
        html
    ));
    // Found by its content too, with no name.
    assert!(found(
        7,
        "click here to continue (http://evil.example/x)",
        None,
        html
    ));
    // A link whose label names another site.
    let spoof = b"<a href='https://evil.example/steal'>https://www.paypal.com/login</a>";
    assert!(found(
        7,
        "https://www.paypal.com/login (https://evil.example/steal)",
        None,
        spoof
    ));
}

fn phishing(name: &str, file: &[u8], alert: bool) -> Verdict {
    let mut o = ScanOptions::default();
    o.filename = Some(name.to_string());
    o.alert_phishing = alert;
    analyze(&scanner(7, "never present"), file, &o).verdict
}

#[test]
fn a_link_that_says_one_site_and_goes_to_another_is_phishing_in_markdown_too() {
    let md = b"Sign in at [https://www.paypal.com/login](https://evil.example/steal) today\n";
    match phishing("mail.md", md, true) {
        Verdict::Infected { signature, .. } => {
            assert_eq!(signature, "Heuristics.Phishing.Email.SpoofedDomain")
        }
        v => panic!("{v:?}"),
    }
    // Off unless asked for, as for HTML.
    assert!(matches!(phishing("mail.md", md, false), Verdict::Clean));
    // A link that is what it says is not.
    assert!(matches!(
        phishing(
            "mail.md",
            b"[www.paypal.com](https://www.paypal.com/login)\n",
            true
        ),
        Verdict::Clean
    ));
    // Nor a label that names no site.
    assert!(matches!(
        phishing("mail.md", b"[click here](https://evil.example/x)\n", true),
        Verdict::Clean
    ));
}

#[test]
fn an_html_link_whose_target_is_written_in_entities_is_judged_as_it_reads() {
    // The raw anchor reader sees `https&#58;//...`; the page reads `https://...`.
    let html = b"<a href=\"https&#58;//evil.example/x\">www.paypal.com</a>";
    assert!(matches!(
        phishing("mail.html", html, true),
        Verdict::Infected { .. }
    ));
}

#[test]
fn the_parts_of_an_office_file_are_matched_by_their_path() {
    let part = b"<w:document><w:body><w:p><w:r><w:t>Please down</w:t></w:r><w:r><w:t>load the</w:t></w:r><w:r><w:t xml:space=\"preserve\"> attachment</w:t></w:r></w:p></w:body></w:document>";
    let sig = scanner(7, "please download the attachment");
    let docx = zip_with("word/document.xml", part);
    let other = zip_with("word/other.xml", part);
    assert!(matches!(
        verdict(&sig, None, &docx, false),
        Verdict::Infected { .. }
    ));
    assert!(matches!(verdict(&sig, None, &other, false), Verdict::Clean));
}

#[test]
fn a_drawings_text_is_matched_without_its_formatting() {
    let dxf = "  0\nSECTION\n  2\nENTITIES\n  0\nMTEXT\n  8\n0\n 10\n0.0\n 20\n0.0\n 30\n0.0\n 40\n2.5\n  1\nPay\\Pnow\n  0\nENDSEC\n  0\nEOF\n";
    assert!(found(7, "pay now", Some("plan.dxf"), dxf.as_bytes()));
    assert!(!found(7, "pay now", Some("plan.txt"), b"Pay\\Pnow"));
}

#[test]
fn an_object_not_held_in_memory_is_not_reported_clean_when_it_has_text() {
    let db = scanner(7, "never present");
    // An HTML page: binary objects get no text view for the size to matter to.
    let mut page = b"<html><body><p>words</p></body></html>".to_vec();
    page.resize(16 * 1024, b' ');
    let verdict = |max: u64| {
        let mut o = ScanOptions::default();
        o.deep_analysis_max = max;
        o.filename = Some("page.html".to_string());
        analyze(&db, &page, &o).verdict
    };
    assert!(matches!(verdict(1 << 20), Verdict::Clean));
    // `analyze` holds the bytes whatever the limit; a larger input is read through a cache.
    let mut o = ScanOptions::default();
    o.deep_analysis_max = 4096;
    o.filename = Some("page.html".to_string());
    let v = exav_core::scan_seekable(
        &db,
        std::io::Cursor::new(page.clone()),
        page.len() as u64,
        &o,
    )
    .expect("scan")
    .verdict;
    assert!(!matches!(v, Verdict::Clean), "{v:?}");
}
