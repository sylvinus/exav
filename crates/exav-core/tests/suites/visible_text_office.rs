//! The office formats' text (`visible-text-office`): a DOC, an XLS, a PPT, an
//! RTF, a flat OpenDocument file is matched through the words a reader sees,
//! its links are judged, and one whose text cannot be taken out is never
//! reported clean.

use exav_core::{ScanOptions, Scanner, Verdict, analyze, loader};

const DOC: &[u8] = include_bytes!("../../../exav-render/tests/fixtures/office/docs/sample.doc");
const XLS: &[u8] = include_bytes!("../../../exav-render/tests/fixtures/office/sheets/sample.xls");
const PPT: &[u8] = include_bytes!("../../../exav-render/tests/fixtures/office/slides/sample.ppt");

/// A one-signature database: `Target:7`, which a text view alone matches.
fn scanner(body: &str) -> Scanner {
    let hex: String = body.bytes().map(|b| format!("{b:02x}")).collect();
    let mut l = loader::Builder::new();
    l.add_named_bytes(
        "t.ndb",
        format!("Test.Visible:7:*:{hex}\n").as_bytes(),
        true,
    );
    l.build().unwrap()
}

fn verdict(db: &Scanner, name: &str, file: &[u8], phishing: bool) -> Verdict {
    let mut o = ScanOptions::default();
    o.filename = Some(name.to_string());
    o.alert_phishing = phishing;
    analyze(db, file, &o).verdict
}

fn found(words: &str, name: &str, file: &[u8]) -> bool {
    matches!(
        verdict(&scanner(words), name, file, false),
        Verdict::Infected { .. }
    )
}

#[test]
fn an_rtf_phrase_split_by_its_groups_is_matched_as_the_words() {
    let rtf = b"{\\rtf1\\ansi Please down{\\b load} the \\i attach\\i0 ment\\par}";
    assert!(found("please download the attachment", "mail.rtf", rtf));
    // The words of another document are not there.
    assert!(!found("please upload the attachment", "mail.rtf", rtf));
}

#[test]
fn the_words_of_a_doc_an_xls_and_a_ppt_are_matched() {
    assert!(found("revenue grew by twelve percent", "report.doc", DOC));
    assert!(found("merged note across three columns", "budget.xls", XLS));
    assert!(found("revenue up 12%", "deck.ppt", PPT));
    // A compound file is read by its name: another one is not read.
    assert!(!found("revenue up 12%", "deck.bin", PPT));
}

#[test]
fn a_flat_opendocument_file_is_matched_without_its_markup() {
    let fodt = br#"<office:document xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" office:mimetype="application/vnd.oasis.opendocument.text"><office:body><office:text><text:p>Wire the <text:span>funds</text:span> <text:s/>today</text:p></office:text></office:body></office:document>"#;
    assert!(found("wire the funds today", "invoice.fodt", fodt));
}

#[test]
fn a_link_that_says_one_site_and_goes_to_another_is_phishing_in_a_legacy_format_too() {
    let rtf = b"{\\rtf1\\ansi Sign in: {\\field{\\*\\fldinst HYPERLINK \"https://evil.example/steal\"}{\\fldrslt https://www.paypal.com/login}}\\par}";
    let db = scanner("never present");
    match verdict(&db, "mail.rtf", rtf, true) {
        Verdict::Infected { signature, .. } => {
            assert_eq!(signature, "Heuristics.Phishing.Email.SpoofedDomain")
        }
        v => panic!("{v:?}"),
    }
    assert!(matches!(
        verdict(&db, "mail.rtf", rtf, false),
        Verdict::Clean
    ));
}

/// The sample DOC with its FIB's encrypted flag set.
fn encrypted_doc() -> Vec<u8> {
    let mut d = DOC.to_vec();
    // The WordDocument stream starts a sector with the FIB's magic, 0xA5EC.
    let at = (1..d.len() / 512)
        .map(|s| s * 512)
        .find(|&o| d[o] == 0xEC && d[o + 1] == 0xA5)
        .expect("the FIB");
    // fEncrypted: bit 8 of the flags word at 0x0A.
    d[at + 0x0B] |= 0x01;
    d
}

#[test]
fn a_document_whose_text_cannot_be_read_is_not_reported_clean() {
    let db = scanner("never present");
    // Read, nothing found: clean.
    assert!(matches!(
        verdict(&db, "report.doc", DOC, false),
        Verdict::Clean
    ));
    // Encrypted: its text is not seen, and the scan says so.
    let v = verdict(&db, "report.doc", &encrypted_doc(), false);
    assert!(
        !matches!(v, Verdict::Clean | Verdict::Infected { .. }),
        "{v:?}"
    );
}

#[test]
fn a_damaged_document_whose_text_cannot_be_taken_out_makes_the_scan_incomplete() {
    // The FIB's fields erased: the reader refuses it as damaged, and nothing
    // else in the scan looks at what a reader would see.
    let mut d = DOC.to_vec();
    let at = (1..d.len() / 512)
        .map(|s| s * 512)
        .find(|&o| d[o] == 0xEC && d[o + 1] == 0xA5)
        .expect("the FIB");
    d[at + 0x20..at + 0x60].fill(0xFF);
    let db = scanner("never present");
    let v = verdict(&db, "broken.doc", &d, false);
    assert!(
        !matches!(v, Verdict::Clean | Verdict::Infected { .. }),
        "{v:?}"
    );
    // The same bytes under a name that is not an office document's: read as
    // nothing, clean.
    assert!(matches!(
        verdict(&db, "broken.bin", &d, false),
        Verdict::Clean
    ));
}

#[test]
fn a_file_that_only_looks_like_a_document_by_its_name_is_not_reported_incomplete() {
    // Not a compound file at all, under a .doc name: nothing to read.
    let db = scanner("never present");
    assert!(matches!(
        verdict(&db, "notes.doc", b"just some plain words", false),
        Verdict::Clean
    ));
}
