//! WIM — the Windows Imaging Format.
//!
//! Windows opens a `.wim` natively and 7-Zip opens one too, so it is an ordinary
//! delivery container. Its file data is chunk-compressed, meaning a payload
//! inside shows none of its bytes to a raw scan.
//!
//! A chunk decoder that is subtly wrong does not fail, it produces plausible
//! bytes that are not the file, and a signature that fails to match those looks
//! exactly like a clean file. So these tests compare every decoded resource
//! with the digest of the file that went in. The image's own SHA-1 per resource
//! is checked only when checksums are verified.
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

use super::extract_each;
use exav_unpack::{Budget, Entry, Format, Limits, detect};

/// `sha256sum` of the files that went into the images.
const EICAR: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
const NOTES: &str = "3b38534b3df987c96e0d6185b9e59289ad54806698c9ac1248afc85cad276af2";
const DEEP: &str = "0035fe0884edb216726d771c5bb354fd2150160459cacc18feb0c1f30bcc81a3";

pub(super) fn fixture(name: &str) -> Vec<u8> {
    let p = format!("{}/tests/fixtures/wim/{name}", env!("CARGO_MANIFEST_DIR"));
    exav_unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
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
         be the files', not merely be produced"
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

/// Every member of `blob` read from a source that is not in memory, under a
/// buffer limit of `cap`: its name, its bytes, whether it was read as it goes,
/// and the error that ended its read.
fn off_a_source(blob: &[u8], cap: u64) -> Vec<(String, Vec<u8>, bool, Option<String>)> {
    use exav_unpack::Member;
    use exav_unpack::source::BlockCache;
    let cache = BlockCache::with_sizes(std::io::Cursor::new(blob.to_vec()), 256, 4 * 256).unwrap();
    let mut limits = Limits::default();
    limits.max_buffer_bytes = cap;
    let mut budget = Budget::new(limits);
    let mut out = Vec::new();
    let end = exav_unpack::walk(Format::Wim, &cache, &mut budget, &mut |meta, content, _| {
        let (data, streamed, error) = match content {
            None => (Vec::new(), false, None),
            Some(Member::Bytes(b)) => (b, false, None),
            Some(Member::Stream(r)) => {
                let mut b = Vec::new();
                let e = r.read_to_end(&mut b).err().map(|e| e.to_string());
                (b, true, e)
            }
        };
        assert!(meta.unsupported.is_none(), "{}", meta.name);
        out.push((meta.name.clone(), data, streamed, error));
        None::<()>
    });
    end.unwrap();
    out
}

/// A resource past the buffer limit is decoded a chunk at a time off a source
/// that is not in memory, and comes out as the file that went in: the resources
/// of every codec, and the several chunks of the one that is 88 KB.
#[test]
fn resources_over_the_buffer_limit_are_read_as_they_go_off_a_source_not_in_memory() {
    for name in ["w_none.wim", "w_XPRESS.wim", "w_LZX.wim", "hard_LZX.wim"] {
        // The directory tree is held whole, under the limit, and is larger
        // than 400 bytes, so the names are not there: the bytes are.
        let mut got: Vec<String> = off_a_source(&fixture(name), 400)
            .into_iter()
            .map(|(n, d, streamed, error)| {
                assert_eq!(error, None, "{name}: {n}");
                assert!(streamed, "{name}: {n} is past the limit");
                sha256_hex(&d)
            })
            .collect();
        got.sort();
        let mut want: Vec<String> = contents(name).into_iter().map(|(_, h)| h).collect();
        want.sort();
        assert_eq!(got, want, "{name}");
    }
}

/// A chunk table that names a chunk past the end of its resource ends the
/// read with an error, where the table is read, and not with a panic or bytes
/// that are not the file's.
#[test]
fn a_chunk_past_the_end_of_its_resource_ends_the_read_with_an_error() {
    let mut raw = fixture("hard_LZX.wim");
    // Resource headers are at the start of the offset table: find the one for
    // the resource of more than one chunk, and make its second chunk start
    // far past its end.
    let le = |d: &[u8], at: usize| u64::from_le_bytes(d[at..at + 8].try_into().unwrap());
    let size = (le(&raw, 48) & 0x00FF_FFFF_FFFF_FFFF) as usize;
    let table = le(&raw, 56) as usize;
    let mut changed = 0;
    for e in (table..table + size).step_by(50) {
        let in_wim = (le(&raw, e) & 0x00FF_FFFF_FFFF_FFFF) as usize;
        let at = le(&raw, e + 8) as usize;
        let original = le(&raw, e + 16);
        let flags = raw[e + 7];
        if flags & 0x04 != 0 && original > 32768 {
            assert!(in_wim > 4, "the chunk table is in the resource");
            raw[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            changed += 1;
        }
    }
    assert!(changed > 0, "a resource of more than one chunk");
    let got = off_a_source(&raw, 400);
    let broken: Vec<_> = got.iter().filter(|m| m.3.is_some()).collect();
    assert!(
        !broken.is_empty(),
        "{:?}",
        got.iter().map(|m| &m.0).collect::<Vec<_>>()
    );
    for (name, data, streamed, error) in broken {
        assert!(*streamed, "{name}");
        assert!(error.as_ref().unwrap().contains("outside"), "{name}");
        // The first chunk ends where the second starts, which is not in it.
        assert!(data.is_empty(), "{name}");
    }
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

/// `blob` with the SHA-1 of every file resource wrong in its offset table (a
/// resource whose 24-byte header is at 48 in the image header: a 7-byte
/// size, the flags, the offset).
fn with_wrong_hashes(blob: &[u8]) -> Vec<u8> {
    let mut d = blob.to_vec();
    let le = |d: &[u8], at: usize| u64::from_le_bytes(d[at..at + 8].try_into().unwrap());
    let size = (le(&d, 48) & 0x00FF_FFFF_FFFF_FFFF) as usize;
    let at = le(&d, 56) as usize;
    for e in (at..at + size).step_by(50) {
        if d[e + 7] & 0x02 == 0 && le(&d, e + 16) > 0 {
            d[e + 30] ^= 1;
        }
    }
    d
}

/// A resource failing only its recorded SHA-1 decodes to the file all the
/// same and is handed over: a wrong checksum is no reason not to scan bytes
/// that are there. (Names come from the directory tree by hash, so these
/// lose theirs.)
#[test]
fn resources_failing_only_their_sha1_are_handed_over() {
    for name in ["w_XPRESS.wim", "w_LZX.wim"] {
        let e = members(&with_wrong_hashes(&fixture(name)));
        assert!(e.iter().all(|x| x.unsupported.is_none()), "{name}");
        let mut got: Vec<String> = e.iter().map(|x| sha256_hex(&x.data)).collect();
        got.sort();
        let mut want = vec![EICAR, NOTES, DEEP];
        want.sort();
        assert_eq!(got, want, "{name}");
    }
}

/// The members of `blob` with checksums verified. A resource is a stream whose
/// read fails at its end where its SHA-1 does not hold, which a scan treats as
/// the member not scanned, so it comes here as a member reported, with no data.
#[cfg(feature = "checksums")]
fn members_verified(blob: &[u8]) -> Vec<Entry> {
    use exav_unpack::Member;
    let mut out = Vec::new();
    let mut b = Budget::new(Limits::default());
    b.set_verify_checksums(true);
    let _ = exav_unpack::walk(Format::Wim, &blob, &mut b, &mut |meta, content, _| {
        let mut entry = Entry::new(meta.name.clone(), Vec::new());
        entry.unsupported = meta.unsupported;
        match content {
            Some(Member::Bytes(bytes)) => entry.data = bytes,
            Some(Member::Stream(r)) => {
                if r.read_to_end(&mut entry.data).is_err() {
                    entry.data.clear();
                    entry.unsupported = Some("stream read failed");
                }
            }
            None => {}
        }
        out.push(entry);
        None::<()>
    });
    out
}

/// With checksums verified, a resource failing its SHA-1 is reported.
#[cfg(feature = "checksums")]
#[test]
fn resources_failing_their_sha1_are_reported_when_checksums_are_verified() {
    let e = members_verified(&with_wrong_hashes(&fixture("w_LZX.wim")));
    assert_eq!(e.len(), 3);
    assert!(e.iter().all(|x| x.unsupported.is_some()));
}

#[cfg(feature = "checksums")]
#[test]
fn a_resource_that_decodes_to_the_wrong_bytes_is_not_handed_over() {
    // Corrupting a chunk's Huffman table makes the decoder emit *something*
    // rather than fail. With checksums verified, the recorded SHA-1 is what
    // separates content from garbage.
    let mut raw = fixture("w_XPRESS.wim");
    // Resource data starts right after the 208-byte header; scribble on the
    // first chunk's code-length table.
    for b in &mut raw[220..260] {
        *b ^= 0xFF;
    }

    let e = members_verified(&raw);
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
