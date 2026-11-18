//! A Markdown document is matched through the text a reader sees as well as
//! its bytes: its words without the marks, entities decoded, and where each
//! link leads. Which files are Markdown is their name's: `.md` and
//! `.markdown`, the input's or a member's.

use exav_core::{ScanOptions, Scanner, Verdict, analyze, loader};

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

/// The drawings of exav-unpack's `fixtures/dwg/links/` (`make.py` there), one
/// to a version: a LINE whose hyperlink says https://www.paypal.com/login and
/// goes to https://evil.example/steal, three others whose links are what they
/// say, one to a view of the drawing, and an entity whose extended data is
/// another application's, with a string that looks like a link.
fn links_dwg(version: &str) -> Vec<u8> {
    use std::io::Read;
    let p = format!(
        "{}/../exav-unpack/tests/fixtures/dwg/links/{version}.dwg.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let gz = exav_core::unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"));
    let mut dwg = Vec::new();
    flate2::read::GzDecoder::new(&gz[..])
        .read_to_end(&mut dwg)
        .expect("gzip");
    dwg
}

const DWG_VERSIONS: [&str; 8] = [
    "R13", "R14", "R2000", "R2004", "R2007", "R2010", "R2013", "R2018",
];

#[test]
fn a_dwg_hyperlink_that_says_one_site_and_goes_to_another_is_phishing() {
    for v in DWG_VERSIONS {
        let dwg = links_dwg(v);
        match phishing("plan.dwg", &dwg, true) {
            Verdict::Infected { signature, .. } => {
                assert_eq!(signature, "Heuristics.Phishing.Email.SpoofedDomain", "{v}")
            }
            other => panic!("{v}: {other:?}"),
        }
        // Off unless asked for, as for the other documents.
        assert!(
            matches!(phishing("plan.dwg", &dwg, false), Verdict::Clean),
            "{v}"
        );
    }
}

/// What a hyperlink says and where it goes are in the drawing's text view,
/// for a signature to match, in every version.
#[test]
fn the_hyperlinks_of_a_dwg_are_matched_as_text() {
    for v in DWG_VERSIONS {
        let dwg = links_dwg(v);
        let name = Some("plan.dwg");
        assert!(found(7, "https://evil.example/steal", name, &dwg), "{v}");
        assert!(found(7, "https://www.paypal.com/login", name, &dwg), "{v}");
        assert!(found(7, "detail text display", name, &dwg), "{v}");
        // Whatever the file is called: it is known by its bytes.
        assert!(
            found(7, "https://example.org/docs/a%20b", None, &dwg),
            "{v}"
        );
        // Not a string of extended data that is another application's.
        assert!(
            !found(7, "https://other.example/not-a-link", name, &dwg),
            "{v}"
        );
    }
}

#[test]
fn a_link_is_judged_when_the_database_has_only_hash_signatures() {
    // Nothing for a text view to be matched against but the EICAR signature
    // every database holds, and the phishing check still has its say.
    let mut l = loader::Builder::new();
    l.add_named_bytes(
        "t.hdb",
        b"00112233445566778899aabbccddeeff:1234:Test.Hash\n",
        true,
    );
    let db = l.build().unwrap();
    let md = b"Sign in at [https://www.paypal.com/login](https://evil.example/steal) today\n";
    let mut o = ScanOptions::default();
    o.filename = Some("mail.md".to_string());
    o.alert_phishing = true;
    match analyze(&db, md, &o).verdict {
        Verdict::Infected { signature, .. } => {
            assert_eq!(signature, "Heuristics.Phishing.Email.SpoofedDomain")
        }
        v => panic!("{v:?}"),
    }
    o.alert_phishing = false;
    assert!(matches!(analyze(&db, md, &o).verdict, Verdict::Clean));
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
    // An OpenDocument file is read by its members' paths too, whatever it is
    // called and with or without a `mimetype` member.
    let odf = zip_with(
        "content.xml",
        b"<office:document-content><office:body><office:text><text:p>Please download the attachment</text:p></office:text></office:body></office:document-content>",
    );
    for name in [None, Some("x.zip")] {
        assert!(matches!(
            verdict(&sig, name, &odf, false),
            Verdict::Infected { .. }
        ));
    }
}

/// A part is read by its path after a member with the same bytes under a name
/// that has no text was scanned clean: a clean member is remembered by what
/// its scan reads, and the text view reads the name.
#[test]
fn a_part_after_its_copy_under_another_name_is_read() {
    let mut part = String::from(
        "<w:document><w:body><w:p><w:r><w:t>Please down</w:t></w:r><w:r><w:t>load the</w:t></w:r><w:r><w:t xml:space=\"preserve\"> attachment</w:t></w:r></w:p></w:body></w:document>",
    );
    // Past the size from which a clean member is remembered.
    part.push_str(&" ".repeat(128 * 1024));
    let sig = scanner(7, "please download the attachment");
    let docx = package(&[("word/other.xml", &part), ("word/document.xml", &part)]);
    assert!(matches!(
        verdict(&sig, None, &docx, false),
        Verdict::Infected { .. }
    ));
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
        o.limits.max_buffer_bytes = max;
        o.filename = Some("page.html".to_string());
        analyze(&db, &page, &o).verdict
    };
    assert!(matches!(verdict(1 << 20), Verdict::Clean));
    // `analyze` holds the bytes whatever the limit; a larger input is read through a cache.
    let mut o = ScanOptions::default();
    o.limits.max_buffer_bytes = 4096;
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

/// A deflated ZIP of `members`, as an office application writes a package.
fn package(members: &[(&str, &str)]) -> Vec<u8> {
    use std::io::Write;
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, data) in members {
        w.start_file(*name, zip::write::SimpleFileOptions::default())
            .unwrap();
        w.write_all(data.as_bytes()).unwrap();
    }
    w.finish().unwrap().into_inner()
}

fn docx_linking(label: &str, target: &str) -> Vec<u8> {
    docx_linking_after(&[], label, target)
}

/// As [`docx_linking`], with `first` as the members that come first.
fn docx_linking_after(first: &[(&str, &str)], label: &str, target: &str) -> Vec<u8> {
    let doc = format!(
        r#"<w:document xmlns:w="w" xmlns:r="r"><w:body><w:p><w:r><w:t>Your account: </w:t></w:r><w:hyperlink r:id="rId9"><w:r><w:t>{label}</w:t></w:r></w:hyperlink></w:p></w:body></w:document>"#
    );
    let rels = format!(
        r#"<Relationships><Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="{target}" TargetMode="External"/></Relationships>"#
    );
    let mut members = first.to_vec();
    members.extend([
        ("[Content_Types].xml", "<Types/>"),
        ("word/document.xml", &doc),
        ("word/_rels/document.xml.rels", &rels),
    ]);
    package(&members)
}

/// A package is read as one by its members, whatever it is called and in
/// whatever order a writer put them: here the document properties come first.
#[test]
fn a_docx_whose_first_member_is_not_a_part_is_read_under_any_name() {
    let spoof = docx_linking_after(
        &[("docProps/app.xml", "<Properties/>")],
        "https://www.paypal.com/signin",
        "https://evil.example/steal",
    );
    for name in [Some("x.zip"), Some("invoice.bin"), None] {
        let mut o = ScanOptions::default();
        o.filename = name.map(str::to_string);
        o.alert_phishing = true;
        match analyze(&scanner(7, "never present"), &spoof, &o).verdict {
            Verdict::Infected { signature, .. } => {
                assert_eq!(
                    signature, "Heuristics.Phishing.Email.SpoofedDomain",
                    "{name:?}"
                )
            }
            v => panic!("{name:?}: {v:?}"),
        }
        assert!(
            found(
                7,
                "www.paypal.com/signin (https://evil.example/steal)",
                name,
                &spoof
            ),
            "{name:?}"
        );
    }
}

#[test]
fn a_docx_link_whose_label_names_another_site_than_its_rels_target_is_phishing() {
    let spoof = docx_linking(
        "https://www.paypal.com/signin",
        "https://evil.example/steal",
    );
    match phishing("invoice.docx", &spoof, true) {
        Verdict::Infected { signature, .. } => {
            assert_eq!(signature, "Heuristics.Phishing.Email.SpoofedDomain")
        }
        v => panic!("{v:?}"),
    }
    assert!(matches!(
        phishing("invoice.docx", &spoof, false),
        Verdict::Clean
    ));
    let honest = docx_linking("www.paypal.com", "https://www.paypal.com/signin");
    assert!(matches!(
        phishing("invoice.docx", &honest, true),
        Verdict::Clean
    ));
    // The label and its target are one line of the text view.
    assert!(found(
        7,
        "www.paypal.com/signin (https://evil.example/steal)",
        Some("invoice.docx"),
        &spoof
    ));
}

#[test]
fn a_pdf_link_annotations_target_is_judged() {
    let pdf = b"%PDF-1.4\n\
        1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n\
        2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n\
        3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Annots [4 0 R] >> endobj\n\
        4 0 obj << /Type /Annot /Subtype /Link /Rect [0 0 100 20] /A << /S /URI /URI (https://www.paypal.com@evil.example/login) >> >> endobj\n\
        trailer << /Root 1 0 R >>\n%%EOF\n";
    match phishing("statement.pdf", pdf, true) {
        Verdict::Infected { signature, .. } => {
            assert_eq!(signature, "Heuristics.Phishing.Email.Cloaked.Username")
        }
        v => panic!("{v:?}"),
    }
    assert!(matches!(
        phishing("statement.pdf", pdf, false),
        Verdict::Clean
    ));
}

#[test]
fn an_emails_headers_are_matched_decoded() {
    let msg = b"From: =?UTF-8?B?U2VjdXJpdHkgVGVhbQ==?= <x@evil.example>\r\n\
                To: you@corp.example\r\n\
                Subject: =?UTF-8?Q?Urgent=3A_verify_your_account?=\r\n\
                MIME-Version: 1.0\r\n\
                Content-Type: text/plain\r\n\r\nHello\r\n";
    assert!(found(7, "subject: urgent: verify your account", None, msg));
    assert!(found(
        7,
        "from: security team <x@evil.example>",
        Some("m.eml"),
        msg
    ));
}

#[test]
fn an_ifc_models_names_and_property_values_are_matched() {
    let ifc = "ISO-10303-21;\nHEADER;\nFILE_SCHEMA(('IFC4'));\nENDSEC;\nDATA;\n\
               #1=IFCWALL('2O2Fr$t4X7Zf8NOew3FLOH',$,'Outer wall',$,$,$,$,$,$);\n\
               #2=IFCPROPERTYSINGLEVALUE('Note',$,IFCTEXT('Call +1 555 0100 to pay'),$);\n\
               #3=IFCCARTESIANPOINT((0.,0.,0.));\n\
               #4=IFCPROPERTYSINGLEVALUE('Pay',$,IFCLABEL('caf\\X2\\00E9\\X0\\ invoice'),$);\n\
               ENDSEC;\nEND-ISO-10303-21;\n";
    // A name and its value are one line; the escapes of STEP are decoded.
    assert!(found(
        7,
        "note call +1 555 0100 to pay",
        Some("m.ifc"),
        ifc.as_bytes()
    ));
    assert!(found(7, "pay café invoice", None, ifc.as_bytes()));
}

#[test]
fn the_speaker_notes_of_a_presentation_are_matched() {
    // Split across runs, so that only the text a reader sees holds the phrase.
    let notes = r#"<p:notes xmlns:p="p" xmlns:a="a"><p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>Tell them to wi</a:t></a:r><a:r><a:t>re the funds</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:notes>"#;
    let pptx = package(&[
        ("[Content_Types].xml", "<Types/>"),
        ("ppt/notesSlides/notesSlide1.xml", notes),
    ]);
    assert!(found(
        7,
        "tell them to wire the funds",
        Some("deck.pptx"),
        &pptx
    ));
    let content = r#"<office:document-content xmlns:office="o" xmlns:draw="d" xmlns:presentation="p" xmlns:text="t"><office:body><office:presentation><draw:page><presentation:notes><draw:frame><draw:text-box><text:p>Tell them to wi<text:span>re the funds</text:span></text:p></draw:text-box></draw:frame></presentation:notes></draw:page></office:presentation></office:body></office:document-content>"#;
    let odp = package(&[
        (
            "mimetype",
            "application/vnd.oasis.opendocument.presentation",
        ),
        ("content.xml", content),
    ]);
    assert!(found(
        7,
        "tell them to wire the funds",
        Some("deck.odp"),
        &odp
    ));
}
