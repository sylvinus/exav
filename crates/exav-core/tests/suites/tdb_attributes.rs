//! TargetDescriptionBlock attributes: `HandlerType`, `Intermediates`, and the
//! `Container` types that were previously refused.
//!
//! Each expectation below was first established by running clamscan over the
//! same fixture with the same single-signature database, because every one of
//! them is a place where the obvious reading of the format is wrong:
//!
//! * `HandlerType:` looks like a match condition and is not: it re-types the
//!   file and rescans it, and the signature carrying it never alerts.
//! * `Intermediates:` is anchored at the *immediate* parent and reads
//!   right-to-left, so a chain may stop short of the outermost container but may
//!   not float in the middle of one.
//! * `Container:CL_TYPE_ANY` reads like "top level only" (a missing parent
//!   reports exactly that type) and behaves as an unconstrained wildcard.
//! * `Container:CL_TYPE_HTML` is satisfiable, which only holds because the
//!   assets a page carries inline get extracted from it.

use exav_core::{ScanOptions, Scanner, Verdict, analyze, loader};
use std::io::Write;

const MARK: &[u8] = b"exav-tdb-probe-marker-0123456789";

fn hex(b: &[u8]) -> String {
    b.iter().map(|c| format!("{c:02x}")).collect()
}

fn db(files: &[(&str, String)]) -> Scanner {
    let mut l = loader::Builder::new();
    for (name, text) in files {
        l.add_named_bytes(name, text.as_bytes(), true);
    }
    l.build().expect("build database")
}

fn found(db: &Scanner, blob: &[u8]) -> Option<String> {
    match analyze(db, blob, &ScanOptions::default()).verdict {
        Verdict::Infected { signature, .. } => Some(signature),
        _ => None,
    }
}

fn zip_of(name: &str, body: &[u8]) -> Vec<u8> {
    let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    z.start_file(name, zip::write::SimpleFileOptions::default())
        .unwrap();
    z.write_all(body).unwrap();
    z.finish().unwrap().into_inner()
}

// ---------------------------------------------------------------- HandlerType

/// The re-type must actually change what the file is scanned as, and it must do
/// so without the re-typing signature claiming the detection for itself.
#[test]
fn handler_type_retypes_the_file_and_stays_silent() {
    const TRIGGER: &[u8] = b"exav-handler-trigger-marker-xyz";
    const PDF_ONLY: &[u8] = b"exav-pdf-only-signature-marker";

    // Not a PDF by magic (no `%PDF` header anywhere) but carrying both the
    // trigger the re-type keys on and a payload only a PDF signature matches.
    let mut carrier = vec![0u8, 1, 2, 3];
    carrier.extend_from_slice(TRIGGER);
    carrier.extend_from_slice(b"\n\n");
    carrier.extend_from_slice(PDF_ONLY);

    let retype = (
        "t.ldb",
        format!(
            "Test.Retype;Engine:51-255,HandlerType:CL_TYPE_PDF,Target:0;0;{}\n",
            hex(TRIGGER)
        ),
    );
    let pdf_only = ("t.ndb", format!("Test.PdfOnly:10:*:{}\n", hex(PDF_ONLY)));

    assert_eq!(
        found(&db(&[retype.clone(), pdf_only.clone()]), &carrier).as_deref(),
        Some("Test.PdfOnly"),
        "the re-type must bring PDF signatures to bear, and must report the \
         signature that actually matched rather than the one that re-typed"
    );
    assert_eq!(
        found(&db(&[pdf_only]), &carrier),
        None,
        "without the re-type the same file is not a PDF and the PDF signature \
         must not fire, otherwise the test above proves nothing"
    );
    assert_eq!(
        found(&db(&[retype]), &carrier),
        None,
        "a HandlerType signature is an action, not an alert: on its own it has \
         nothing to report"
    );
}

// -------------------------------------------------------------- Intermediates

/// `Intermediates:A>B` requires B to be the immediate parent and A its parent:
/// a contiguous run ending at the file, not a loose subsequence.
#[test]
fn intermediates_anchor_at_the_immediate_parent() {
    let sig = (
        "t.ldb",
        format!(
            "Test.Inter;Engine:81-255,Intermediates:CL_TYPE_ZIP>CL_TYPE_ZIP,Target:0;0;{}\n",
            hex(MARK)
        ),
    );
    let db = db(&[sig]);

    let mut payload = MARK.to_vec();
    payload.extend_from_slice(b"\npadding to make it a plausible member\n");

    assert_eq!(found(&db, &payload), None, "no containers at all");
    assert_eq!(
        found(&db, &zip_of("payload.txt", &payload)),
        None,
        "one ZIP is one link short of the two the chain names"
    );
    assert!(
        found(&db, &zip_of("inner.zip", &zip_of("payload.txt", &payload))).is_some(),
        "ZIP inside ZIP is exactly the chain"
    );
    // Every match, held in memory.
    let every =
        |blob: &[u8]| !exav_core::analyze_all(&db, blob, &ScanOptions::default()).is_empty();
    assert!(!every(&zip_of("payload.txt", &payload)));
    assert!(every(&zip_of(
        "inner.zip",
        &zip_of("payload.txt", &payload)
    )));
    assert!(
        found(
            &db,
            &zip_of(
                "mid.zip",
                &zip_of("inner.zip", &zip_of("payload.txt", &payload))
            )
        )
        .is_some(),
        "a third ZIP outside the chain does not break it: the run is anchored \
         at the immediate parent and need not reach the outermost container"
    );
}

/// A member found clean is not scanned again where its bytes turn up a second
/// time, unless what a scan reads from its place differs: with another chain of
/// containers above it, a signature scoped to the chain can match.
#[test]
fn a_copy_found_clean_is_scanned_again_under_another_chain() {
    let db = db(&[(
        "t.ldb",
        format!(
            "Test.Inter;Engine:81-255,Intermediates:CL_TYPE_ZIP>CL_TYPE_ZIP,Target:0;0;{}\n",
            hex(MARK)
        ),
    )]);
    // Large enough to be remembered once found clean.
    let mut payload = MARK.to_vec();
    payload.extend_from_slice(&vec![b'x'; 80_000]);
    let nested = zip_of("inner.zip", &zip_of("a.bin", &payload));
    assert_eq!(
        found(&db, &zip_of("a.bin", &payload)),
        None,
        "one ZIP: a link short"
    );
    // The copy one level up is scanned first and is clean.
    let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default();
    z.start_file("a.bin", options).unwrap();
    z.write_all(&payload).unwrap();
    z.start_file("inner.zip", options).unwrap();
    z.write_all(&zip_of("a.bin", &payload)).unwrap();
    let both = z.finish().unwrap().into_inner();
    assert!(found(&db, &nested).is_some(), "the nested copy alone");
    assert!(
        found(&db, &both).is_some(),
        "the nested copy, after a copy found clean one level up"
    );
}

/// What is read from an object a second way (a ZIP appended to a PDF) is in the
/// same place as the object: the containers above the PDF are above it.
#[test]
fn intermediates_pass_through_a_second_reading() {
    let chain = |chain: &str| {
        db(&[(
            "t.ldb",
            format!(
                "Test.Inter;Engine:81-255,Intermediates:{chain},Target:0;0;{}\n",
                hex(MARK)
            ),
        )])
    };
    let mut payload = MARK.to_vec();
    payload.extend_from_slice(b"\npadding to make it a plausible member\n");
    let mut pdf = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n".to_vec();
    pdf.extend_from_slice(&zip_of("payload.txt", &payload));
    let in_zip = zip_of("doc.pdf", &pdf);

    let one = chain("CL_TYPE_ZIP");
    let two = chain("CL_TYPE_ZIP>CL_TYPE_ZIP");
    assert!(found(&one, &pdf).is_some(), "the appended ZIP is a ZIP");
    assert_eq!(found(&two, &pdf), None, "and nothing is above it");
    assert!(
        found(&two, &in_zip).is_some(),
        "the ZIP the PDF is a member of is above the appended ZIP"
    );
}

/// The same chain, for objects larger than `limits.max_buffer_bytes`: stored members
/// are read where they lie, through the cache of the input, and matched in the
/// one read of each.
#[test]
fn intermediates_hold_for_objects_read_through_the_cache() {
    let sig = (
        "t.ldb",
        format!(
            "Test.Inter;Engine:81-255,Intermediates:CL_TYPE_ZIP>CL_TYPE_ZIP,Target:0;0;{}\n",
            hex(MARK)
        ),
    );
    let db = db(&[sig]);
    let stored = |name: &str, body: &[u8]| {
        let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        z.start_file(name, options).unwrap();
        z.write_all(body).unwrap();
        z.finish().unwrap().into_inner()
    };
    let mut payload = MARK.to_vec();
    payload.extend_from_slice(&[b'x'; 1000]);
    let one = stored("payload.txt", &payload);
    let two = stored("inner.zip", &one);
    let mut opts = ScanOptions::default();
    opts.limits.max_buffer_bytes = 64;
    // The first match, and every match.
    let read = |blob: &[u8]| {
        let report =
            exav_core::scan_seekable(&db, std::io::Cursor::new(blob), blob.len() as u64, &opts)
                .unwrap();
        let (all, _) = exav_core::analyze_all_seekable(
            &db,
            std::io::Cursor::new(blob),
            blob.len() as u64,
            &opts,
        )
        .unwrap();
        (
            matches!(report.verdict, Verdict::Infected { .. }),
            !all.is_empty(),
        )
    };
    assert_eq!(read(&one), (false, false), "one ZIP is one link short");
    assert_eq!(
        read(&two),
        (true, true),
        "ZIP inside ZIP is exactly the chain"
    );
}

// ------------------------------------------------------------------ Container

/// Reading the layer logic, `CL_TYPE_ANY` should mean "no container at all",
/// since that is the type a missing parent reports. It does not: clamscan fires
/// such a signature at every depth, so exav treats it as unconstrained.
#[test]
fn container_any_is_a_wildcard_not_top_level_only() {
    let db = db(&[(
        "t.ldb",
        format!(
            "Test.Any;Engine:51-255,Container:CL_TYPE_ANY,Target:0;0;{}\n",
            hex(MARK)
        ),
    )]);
    let mut payload = MARK.to_vec();
    payload.extend_from_slice(b"\npadding\n");

    assert!(found(&db, &payload).is_some(), "top level");
    assert!(
        found(&db, &zip_of("payload.txt", &payload)).is_some(),
        "one deep"
    );
    assert!(
        found(&db, &zip_of("inner.zip", &zip_of("payload.txt", &payload))).is_some(),
        "two deep"
    );
}

/// A page's inline assets are content extracted from the page, so a signature
/// scoped to `Container:CL_TYPE_HTML` fires on them, and only on them. This is
/// how a phishing family pins a brand logo to the page impersonating the brand
/// without flagging every copy of the logo.
#[test]
#[cfg(feature = "base64scan")]
fn a_data_uri_asset_carries_its_page_as_its_container() {
    use base64::Engine as _;

    // A real PNG (magic + a chunk carrying the marker), so it is recognisable as
    // an asset rather than as base64 noise.
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png.extend_from_slice(&[0, 0, 0, 13]);
    png.extend_from_slice(b"IHDR");
    png.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0]);
    png.extend_from_slice(&[0; 4]);
    png.extend_from_slice(MARK);
    png.extend_from_slice(&[0u8; 64]);

    let b64 = base64::engine::general_purpose::STANDARD.encode(&png);
    let page =
        format!("<html><body><img src=\"data:image/png;base64,{b64}\"></body></html>").into_bytes();
    assert!(
        !page.windows(MARK.len()).any(|w| w == MARK),
        "the marker must survive only through the base64, or a raw scan of the \
         page would match and the container scoping would go untested"
    );

    let db = db(&[(
        "t.ldb",
        format!(
            "Test.InPage;Engine:51-255,Container:CL_TYPE_HTML,Target:0;0;{}\n",
            hex(MARK)
        ),
    )]);
    assert!(
        found(&db, &page).is_some(),
        "the asset must be pulled out of the page and scanned with the page as \
         its container"
    );
    assert_eq!(
        found(&db, &png),
        None,
        "the same asset on its own has no container and must not fire"
    );
}

/// What is decoded out of a text has the text, and the containers above the
/// text, on its ancestry: `Intermediates:` reads them for an asset of a page and
/// for a base64 run alike, whether the page is the input or a member.
#[test]
#[cfg(feature = "base64scan")]
fn what_is_decoded_out_of_a_page_has_the_page_and_its_containers_as_ancestry() {
    use base64::Engine as _;
    let b64 = |data: &[u8]| base64::engine::general_purpose::STANDARD.encode(data);

    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png.extend_from_slice(&[0, 0, 0, 13]);
    png.extend_from_slice(b"IHDR");
    png.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0]);
    png.extend_from_slice(&[0; 4]);
    png.extend_from_slice(MARK);
    png.extend_from_slice(&[0u8; 64]);
    let mut pe = vec![0u8; 2048];
    pe[..2].copy_from_slice(b"MZ");
    pe[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    pe[0x40..0x44].copy_from_slice(b"PE\0\0");
    pe[0x100..0x100 + MARK.len()].copy_from_slice(MARK);

    let asset_page = format!(
        "<html><body><img src=\"data:image/png;base64,{}\"></body></html>",
        b64(&png)
    )
    .into_bytes();
    let run_page = format!("<html><script>var x = \"{}\";</script></html>", b64(&pe)).into_bytes();
    for page in [&asset_page, &run_page] {
        assert!(!page.windows(MARK.len()).any(|w| w == MARK));
    }

    let sig = |chain: &str| {
        db(&[(
            "t.ldb",
            format!(
                "Test.Chain;Engine:51-255,Intermediates:{chain},Target:0;0;{}\n",
                hex(MARK)
            ),
        )])
    };
    for (what, page) in [("an asset", &asset_page), ("a base64 run", &run_page)] {
        let in_zip = zip_of("page.html", page);
        let page_only = sig("CL_TYPE_HTML");
        assert!(found(&page_only, page).is_some(), "{what}: its page");
        assert!(
            found(&page_only, &in_zip).is_some(),
            "{what}: its page, in a ZIP"
        );
        let zip_page = sig("CL_TYPE_ZIP>CL_TYPE_HTML");
        assert_eq!(
            found(&zip_page, page),
            None,
            "{what}: no ZIP above the page"
        );
        assert!(
            found(&zip_page, &in_zip).is_some(),
            "{what}: the ZIP above the page is on the chain"
        );
        let other = sig("CL_TYPE_RTF");
        assert_eq!(found(&other, page), None, "{what}: the page is not an RTF");
        assert_eq!(found(&other, &in_zip), None, "{what}: nor in a ZIP");
    }
}
