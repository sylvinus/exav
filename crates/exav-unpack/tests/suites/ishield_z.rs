//! InstallShield Z (`.z`) — the older installer archive.
//!
//! **The oracle is the plaintext.** `undhr.z` holds one file, and the upstream
//! project ships the original of it alongside as `undhr.md`. The assertion is
//! that what comes out matches that file byte for byte — nothing here trusts
//! the decoder's own output, which matters because the codec is PKWARE's DCL
//! "implode" and a subtly wrong implementation emits plausible text rather than
//! an error.
//!
//! Not to be confused with the `ISc(` InstallScript cabinet, which exav
//! recognises and does not open — see `formats/reported.rs` for why.
//!
//! Fixtures are the `unshield` project's own examples (MIT); see `NOTICE`.

use exav_unpack::{detect, extract_each, Budget, Entry, Format, Limits};

fn fixture(name: &str) -> Vec<u8> {
    let p = format!(
        "{}/tests/fixtures/ishieldz/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    exav_unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

fn members(blob: &[u8]) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut b = Budget::new(Limits::default());
    let _ = extract_each(
        Format::IshieldZ,
        blob,
        &mut b,
        &mut |e: Entry, _: &mut Budget| {
            out.push(e);
            None::<()>
        },
    );
    out
}

#[test]
fn an_installshield_z_archive_is_recognised() {
    assert_eq!(detect(&fixture("undhr.z")), Some(Format::IshieldZ));
    assert_eq!(detect(&fixture("demo.z")), Some(Format::IshieldZ));
}

#[test]
fn the_magic_alone_does_not_claim_a_file() {
    // Recognition is confirmed against the header's own arithmetic, because the
    // four magic bytes on their own would report an ordinary file as an archive
    // exav then could not open — a lie in the other direction.
    let mut fake = vec![0x13, 0x5D, 0x65, 0x8C];
    fake.extend(std::iter::repeat_n(0u8, 200));
    assert_eq!(detect(&fake), None, "a bare magic must not be enough");

    // And a real header whose declared size runs past the file is not one either.
    let mut truncated = fixture("undhr.z");
    truncated.truncate(2000);
    assert_ne!(
        detect(&truncated),
        Some(Format::IshieldZ),
        "a header claiming more bytes than exist is not a valid archive"
    );
}

#[test]
fn the_decompressed_member_matches_the_original_file() {
    // The whole point of the suite: `undhr.md` is what went in.
    let e = members(&fixture("undhr.z"));
    assert_eq!(
        e.len(),
        1,
        "got {:?}",
        e.iter().map(|x| &x.name).collect::<Vec<_>>()
    );
    assert!(
        e[0].unsupported.is_none(),
        "a healthy archive must not report anything unreadable: {:?}",
        e[0].unsupported
    );
    let want = fixture("undhr.md");
    assert_eq!(
        e[0].data.len(),
        want.len(),
        "decoded {} bytes, the original is {}",
        e[0].data.len(),
        want.len()
    );
    assert_eq!(
        e[0].data, want,
        "the DCL-imploded member must decode to the original byte for byte — a \
         codec that is subtly wrong emits plausible text, not an error"
    );
}

#[test]
fn the_payload_is_absent_from_the_raw_archive() {
    // Guards the premise: the member really is compressed, so extracting it is
    // doing work a raw scan of the container could not.
    let raw = fixture("undhr.z");
    let plain = fixture("undhr.md");
    let probe = &plain[..64.min(plain.len())];
    assert!(
        !raw.windows(probe.len()).any(|w| w == probe),
        "the plaintext is visible in the archive; this fixture proves nothing"
    );
}

#[test]
fn every_member_carries_its_name() {
    let e = members(&fixture("demo.z"));
    assert!(!e.is_empty(), "demo.z holds two files");
    assert!(
        e.iter().all(|x| !x.name.is_empty()),
        "a nameless member cannot be reported or matched by a `.cdb` signature"
    );
    assert!(
        e.iter().all(|x| !x.name.contains('\\')),
        "InstallShield writes backslash separators; they must be normalised: {:?}",
        e.iter().map(|x| &x.name).collect::<Vec<_>>()
    );
}

#[test]
fn a_member_past_the_budget_is_reported_not_skipped() {
    let mut b = Budget::new(Limits {
        max_buffer_bytes: 16,
        ..Limits::default()
    });
    let mut out = Vec::new();
    let _ = extract_each(
        Format::IshieldZ,
        &fixture("undhr.z"),
        &mut b,
        &mut |e: Entry, _: &mut Budget| {
            out.push(e);
            None::<()>
        },
    );
    assert!(
        out.iter().any(|x| x.unsupported.is_some()),
        "a member over the budget must be reported, got {:?}",
        out.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
}
