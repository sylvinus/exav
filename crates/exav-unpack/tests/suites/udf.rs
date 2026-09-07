//! UDF — the filesystem on DVDs, Blu-rays and most `.iso` files written today.
//!
//! Two shapes matter. A **UDF-only** image carries no ISO 9660 tree at all, so
//! without UDF support every file in it is invisible while Windows and macOS
//! both mount it on double-click. A **bridge** image carries both filesystems
//! over the same extents, where the risk is the opposite one: walking both trees
//! naively scans every file twice.
//!
//! The expected digests are `7zz x` output on the same fixtures — 7-Zip's, not
//! this crate's. A filesystem walker validated against its own writer can agree
//! on a shared misreading of the spec.
//!
//! Regenerate with:
//! ```sh
//! genisoimage -udf -o bridge.iso -V TEST udfsrc/     # both filesystems
//! # then blank the `CD001` identifiers in sectors 16..19 to leave UDF alone
//! gzip -9 bridge.iso udf_only.iso
//! ```
//!
//! Stored gzipped because a UDF volume's descriptor sequences put the file data
//! past sector 256, making even a three-file image ~900 KiB of mostly zeroes.
//! The bytes inside are genisoimage's.

use exav_unpack::{detect, extract_each, Budget, Entry, Format, Limits};

/// `sha256sum` of what `7zz x` writes for each member.
const README_SHA256: &str = "8d2f3443b4461106fa29ee57260e553ee6acb25cc0a00a28a777013d2420985e";
const BIG_SHA256: &str = "c33e271d1d90b8d5615d100ea4a90d2f83adf72f0805935142f179b8c3838a73";
const PAYLOAD_SHA256: &str = "13d029085fab073b6c20dd01a423c97e324dc430ca8186795a2a367a23f11143";

fn fixture(name: &str) -> Vec<u8> {
    let p = format!("{}/tests/fixtures/udf/{name}", env!("CARGO_MANIFEST_DIR"));
    let raw = exav_unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"));
    let mut out = Vec::new();
    std::io::Read::read_to_end(
        &mut flate2::read::GzDecoder::new(std::io::Cursor::new(raw)),
        &mut out,
    )
    .unwrap_or_else(|e| panic!("gunzip {p}: {e}"));
    out
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
        Format::Iso,
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
fn a_udf_only_image_is_recognised_at_all() {
    // It has no `CD001`, so nothing but the UDF volume recognition sequence
    // identifies it. Falling through to "unknown blob" would leave every file
    // inside unscanned while the image still reported clean.
    let blob = fixture("udf_only.iso.gz");
    assert_eq!(detect(&blob), Some(Format::Iso));
}

#[test]
fn a_udf_only_image_yields_every_file_7zip_does() {
    let e = members(&fixture("udf_only.iso.gz"));
    assert!(
        e.iter().all(|x| x.unsupported.is_none()),
        "a healthy UDF image must not report anything unreadable, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );

    let mut got: Vec<(String, String)> = e
        .iter()
        .map(|x| (x.name.clone(), sha256_hex(&x.data)))
        .collect();
    got.sort();
    assert_eq!(
        got,
        vec![
            ("nested/big.bin".to_string(), BIG_SHA256.to_string()),
            (
                "nested/deeper/payload.zip".to_string(),
                PAYLOAD_SHA256.to_string()
            ),
            ("readme.txt".to_string(), README_SHA256.to_string()),
        ],
        "names and contents must match `7zz x` — including the nested paths and \
         the file that spans several blocks"
    );
}

#[test]
fn a_bridge_image_scans_each_file_once() {
    // Both filesystems name the same extents. Walking them independently would
    // hand the scanner every file twice, doubling the work on the commonest
    // kind of `.iso` there is.
    let e = members(&fixture("bridge.iso.gz"));
    assert_eq!(
        e.len(),
        3,
        "expected one member per file, got {:?}",
        e.iter().map(|x| &x.name).collect::<Vec<_>>()
    );
    let mut digests: Vec<String> = e.iter().map(|x| sha256_hex(&x.data)).collect();
    digests.sort();
    let mut want = vec![
        BIG_SHA256.to_string(),
        PAYLOAD_SHA256.to_string(),
        README_SHA256.to_string(),
    ];
    want.sort();
    assert_eq!(digests, want);
}

#[test]
fn a_udf_volume_that_cannot_be_read_says_so() {
    // Blanking every anchor volume descriptor — sector 256 and the two copies
    // at the end of the volume — leaves an image that announces UDF in its
    // recognition sequence and then gives no way in. Every file is still there;
    // exav simply cannot reach them, which is exactly the case that must never
    // pass as clean.
    let mut blob = fixture("udf_only.iso.gz");
    let sectors = blob.len() / 2048;
    for s in [256, sectors - 1, sectors - 257] {
        blob[s * 2048..s * 2048 + 16].fill(0);
    }

    let e = members(&blob);
    assert!(
        e.iter().any(|x| x.unsupported.is_some()),
        "an unreadable UDF volume must be reported, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
}
