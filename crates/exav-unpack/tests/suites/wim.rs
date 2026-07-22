//! WIM — the Windows Imaging Format.
//!
//! Windows opens a `.wim` natively and 7-Zip opens one too, so it is an ordinary
//! delivery container. Its file data is chunk-compressed, meaning a payload
//! inside shows none of its bytes to a raw scan.
//!
//! The image records a **SHA-1 per resource**, which exav checks on every
//! decode. That is what these tests lean on: a chunk decoder that is subtly
//! wrong does not fail, it produces plausible bytes that are not the file, and a
//! signature that fails to match those looks exactly like a clean file. A
//! fixture that decoded wrongly would be reported unreadable and never reach the
//! digest comparison below.
//!
//! Fixtures come from **wimlib** (`wimcapture`), one per compression format,
//! plus `hard_LZX.wim` — 48 KiB of real x86-64 code (453 `E8` bytes, so LZX's
//! call translation has to be undone correctly) and 40 KB of incompressible
//! random data (which forces stored blocks), spanning several chunks.
//!
//! Regenerate with:
//! ```sh
//! for c in none XPRESS LZX LZMS; do wimcapture wsrc/ w_$c.wim --compress=$c; done
//! wimcapture hardsrc/ hard_LZX.wim --compress=LZX
//! ```

use exav_unpack::{detect, extract_each, Budget, Entry, Format, Limits};

/// `sha256sum` of the files that went into the images.
const EICAR: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
const NOTES: &str = "3b38534b3df987c96e0d6185b9e59289ad54806698c9ac1248afc85cad276af2";
const DEEP: &str = "0035fe0884edb216726d771c5bb354fd2150160459cacc18feb0c1f30bcc81a3";

fn fixture(name: &str) -> Vec<u8> {
    let p = format!("{}/tests/fixtures/wim/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn members(blob: &[u8]) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut b = Budget::new(Limits::default());
    let _ = extract_each(
        Format::Wim,
        blob,
        &mut b,
        &mut |e: Entry, _: &mut Budget| {
            out.push(e);
            None::<()>
        },
    );
    out
}

fn contents(name: &str) -> Vec<(String, String)> {
    let e = members(&fixture(name));
    assert!(
        e.iter().all(|x| x.unsupported.is_none()),
        "{name}: nothing should be unreadable, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
    let mut got: Vec<(String, String)> = e
        .iter()
        .map(|x| (x.name.clone(), sha256_hex(&x.data)))
        .collect();
    got.sort();
    got
}

fn expected() -> Vec<(String, String)> {
    let mut want = vec![
        ("eicar.com".to_string(), EICAR.to_string()),
        ("notes.txt".to_string(), NOTES.to_string()),
        ("sub/deep.txt".to_string(), DEEP.to_string()),
    ];
    want.sort();
    want
}

#[test]
fn a_wim_is_recognised_before_the_looser_sniffs() {
    // The DMG detector is structural rather than magic-based and will claim a
    // `.wim` if it gets the chance, which would leave the image extracted by the
    // wrong handler and its files unscanned.
    assert_eq!(detect(&fixture("w_none.wim")), Some(Format::Wim));
    assert_eq!(detect(&fixture("w_XPRESS.wim")), Some(Format::Wim));
}

#[test]
fn an_uncompressed_wim_yields_every_file_with_its_path() {
    // Names come from the metadata resource's directory tree, so this also
    // covers the nested path.
    assert_eq!(contents("w_none.wim"), expected());
}

#[test]
fn an_xpress_wim_decodes_every_chunk() {
    assert_eq!(
        contents("w_XPRESS.wim"),
        expected(),
        "each chunk is Huffman-coded with its own table; the decoded bytes must \
         match the SHA-1 the image records, not merely be produced"
    );
}

#[test]
fn an_lzx_wim_decodes_every_chunk() {
    // LZX is wimlib's default and the codec of most `install.wim` images.
    assert_eq!(contents("w_LZX.wim"), expected());
}

#[test]
fn lzx_handles_call_translation_and_stored_blocks() {
    // Two things a text-only fixture never reaches: LZX undoes an `E8` call
    // translation applied against a *fixed* nominal file size, and it stores
    // blocks verbatim when they will not compress. Both produce plausible
    // wrong bytes when handled wrongly rather than an error.
    const CODE: &str = "42d9770e142b0defce9ff0ad300b2f2133cc14efad8e2670bb57f44ec5ae0e4a";
    const RAND: &str = "77562b347b5395abe570206e171c681c8f6fbcbcca2e3ebffb40826fb08ce7c3";
    let mut want = vec![
        ("code.bin".to_string(), CODE.to_string()),
        ("rand.bin".to_string(), RAND.to_string()),
    ];
    want.sort();
    assert_eq!(contents("hard_LZX.wim"), want);
}

#[test]
fn resources_in_a_codec_exav_lacks_are_reported_not_passed_over() {
    // LZMS is not decoded yet. That costs coverage, and it must not cost a
    // clean verdict: the files are there and Windows reads them.
    let name = "w_LZMS.wim";
    let e = members(&fixture(name));
    assert!(
        e.iter().any(|x| x.unsupported.is_some()),
        "{name}: undecodable resources must be reported, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
    // The uncompressed resource in the same image must still come through: one
    // unsupported codec cannot be allowed to blank the whole file.
    assert!(
        e.iter().any(|x| sha256_hex(&x.data) == EICAR),
        "{name}: the uncompressed resource must still be extracted"
    );
}

#[test]
fn a_resource_that_decodes_to_the_wrong_bytes_is_not_handed_over() {
    // Corrupting a chunk's Huffman table makes the decoder emit *something*
    // rather than fail. The recorded SHA-1 is what separates content from
    // garbage; without checking it, those bytes would be scanned as the file and
    // the file would come back clean.
    let mut raw = fixture("w_XPRESS.wim");
    // Resource data starts right after the 208-byte header; scribble on the
    // first chunk's code-length table.
    for b in &mut raw[220..260] {
        *b ^= 0xFF;
    }

    let e = members(&raw);
    for m in &e {
        if m.unsupported.is_some() {
            continue;
        }
        let d = sha256_hex(&m.data);
        assert!(
            [EICAR, NOTES, DEEP].contains(&d.as_str()),
            "resource {} was handed over with content matching no input file",
            m.name
        );
    }
    assert!(
        e.iter().any(|x| x.unsupported.is_some()),
        "a corrupted chunk must leave something reported unreadable"
    );
}
