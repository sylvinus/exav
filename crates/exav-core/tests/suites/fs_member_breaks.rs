//! A file of a filesystem image that breaks part way (its index or its coded
//! bytes are damaged) is scanned as far as it goes, and the scan is not clean:
//! the verdict says why the file breaks, not only that it could not be read.
//!
//! The image is exav-unpack's `erofs_z_lz4` (`fixtures/fs/make.sh`: what
//! `mkfs.erofs -zlz4` writes for the tree of `tree.py` and the files of
//! `zextras.py`). One byte of it is changed, at an offset found by changing
//! each byte in turn.

use std::io::Read;

use exav_core::{ScanOptions, Scanner, Verdict, analyze};

fn image(name: &str) -> Vec<u8> {
    let p = format!(
        "{}/../exav-unpack/tests/fixtures/fs/{name}.img.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let gz = exav_core::unpack::read_fixture(&p).unwrap_or_else(|e| panic!("{name}: {e}"));
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(&gz[..])
        .read_to_end(&mut out)
        .unwrap();
    out
}

fn verdict(img: &[u8]) -> Verdict {
    analyze(&Scanner::builtin(), img, &ScanOptions::default()).verdict
}

#[test]
fn a_compressed_file_that_breaks_makes_the_scan_unscannable_for_that_reason() {
    let img = image("erofs_z_lz4");
    assert_eq!(verdict(&img), Verdict::Clean);
    for (at, why) in [
        (2420, "did not decode to their extent"),
        (2398, "coded bytes could not be opened"),
        (2376, "map of extents"),
    ] {
        let mut damaged = img.clone();
        damaged[at] ^= 0xFF;
        match verdict(&damaged) {
            Verdict::Unscannable { reason } => {
                assert!(reason.contains(why), "byte {at}: {reason}");
            }
            other => panic!("byte {at}: {other:?}"),
        }
    }
}
