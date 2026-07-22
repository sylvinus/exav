//! TargetDescriptionBlock attributes: `HandlerType`, `Intermediates`, and the
//! `Container` types that were previously refused.
//!
//! Each expectation below was first established by running clamscan over the
//! same fixture with the same single-signature database, because every one of
//! them is a place where the obvious reading of the format is wrong:
//!
//! * `HandlerType:` looks like a match condition and is not — it re-types the
//!   file and rescans it, and the signature carrying it never alerts.
//! * `Intermediates:` is anchored at the *immediate* parent and reads
//!   right-to-left, so a chain may stop short of the outermost container but may
//!   not float in the middle of one.
//! * `Container:CL_TYPE_ANY` reads like "top level only" (a missing parent
//!   reports exactly that type) and behaves as an unconstrained wildcard.
//! * `Container:CL_TYPE_HTML` is satisfiable, which only holds because the
//!   assets a page carries inline get extracted from it.

use exav_core::{analyze, loader, ScanOptions, Scanner, Verdict};
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

    // Not a PDF by magic — no `%PDF` header anywhere — but carrying both the
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
         must not fire — otherwise the test above proves nothing"
    );
    assert_eq!(
        found(&db(&[retype]), &carrier),
        None,
        "a HandlerType signature is an action, not an alert: on its own it has \
         nothing to report"
    );
}

// -------------------------------------------------------------- Intermediates

/// `Intermediates:A>B` requires B to be the immediate parent and A its parent —
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
    assert!(
        found(
            &db,
            &zip_of(
                "mid.zip",
                &zip_of("inner.zip", &zip_of("payload.txt", &payload))
            )
        )
        .is_some(),
        "a third ZIP outside the chain does not break it — the run is anchored \
         at the immediate parent and need not reach the outermost container"
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
/// scoped to `Container:CL_TYPE_HTML` fires on them — and only on them. This is
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
