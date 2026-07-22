//! FAT — reading the filesystem, not carving the sectors.
//!
//! A raw disk is a pile of sectors. Carving finds a file whose magic sits at the
//! start of a contiguous run and misses everything else, so a **fragmented**
//! file — one written into a hole left by a deleted file and continuing past it
//! — comes back as disconnected pieces that will not decompress.
//!
//! The fixture is built to be exactly that case: three files written, the middle
//! one deleted, then a 12 KB payload written so it lands in the 4 KB hole and
//! continues after `c.bin`. Its cluster chain has **two runs**, and the payload
//! is a deflated ZIP, so the EICAR string appears nowhere in the image's bytes.
//! Only following the chain reassembles it.
//!
//! Built with `mtools` (`mformat`/`mcopy`/`mdel`), stored gzipped because a FAT
//! image is mostly empty space.
//!
//! Regenerate with:
//! ```sh
//! mformat -i fragmented.img -C -t 8 -h 2 -s 16 -c 1 ::
//! mcopy -i fragmented.img padA ::/a.bin; mcopy -i fragmented.img padB ::/b.bin
//! mcopy -i fragmented.img padC ::/c.bin; mdel -i fragmented.img ::/b.bin
//! mmd -i fragmented.img ::/sub; mcopy -i fragmented.img payload.zip ::/sub/p.zip
//! gzip -9 fragmented.img
//! ```

use exav_unpack::{detect, extract_each, Budget, Entry, Format, Limits};

/// `sha256sum` of the ZIP that was copied in, which is what following the
/// cluster chain has to reproduce.
const PAYLOAD: &str = "aa3029a89a5e657f2d4fa85d3c352d348c08d30b04b924417d7e8b2c3a6bb342";

fn fixture() -> Vec<u8> {
    let p = format!(
        "{}/tests/fixtures/fat/fragmented.img.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let raw = std::fs::read(&p).unwrap_or_else(|e| panic!("read {p}: {e}"));
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
        Format::Fat,
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
fn a_boot_sector_is_recognised_as_a_filesystem_not_a_partition_table() {
    // Both end in `55 AA`. Reading a volume boot record as a partition table
    // used to invent a partition covering the whole image, which then re-detected
    // the same way until the recursion budget was gone.
    assert_eq!(detect(&fixture()), Some(Format::Fat));
}

#[test]
fn a_fragmented_file_is_reassembled_from_its_cluster_chain() {
    let e = members(&fixture());
    assert!(
        e.iter().all(|x| x.unsupported.is_none()),
        "a healthy image must not report anything unreadable, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
    let p = e
        .iter()
        .find(|x| x.name.ends_with("p.zip"))
        .unwrap_or_else(|| {
            panic!(
                "the payload must be found, with its path; got {:?}",
                e.iter().map(|x| &x.name).collect::<Vec<_>>()
            )
        });
    assert_eq!(
        sha256_hex(&p.data),
        PAYLOAD,
        "the file spans two non-adjacent runs, so anything short of following \
         the chain returns fragments rather than the file"
    );
}

#[test]
fn files_come_back_with_their_directory_paths() {
    let e = members(&fixture());
    let mut names: Vec<&str> = e.iter().map(|x| x.name.as_str()).collect();
    names.sort();
    assert!(
        names.iter().any(|n| n.contains('/')),
        "a file in a subdirectory should carry its path, got {names:?}"
    );
}

#[test]
fn the_payload_is_absent_from_the_raw_image() {
    // Guards the premise: if EICAR were visible in the sectors, a raw scan would
    // find it without reading the filesystem and this fixture would prove
    // nothing about the cluster walk.
    const EICAR: &[u8] = br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;
    let img = fixture();
    assert!(!img.windows(EICAR.len()).any(|w| w == EICAR));
}

#[test]
fn a_corrupt_filesystem_is_reported_not_shrugged_off() {
    // The boot sector still says FAT, so the files are there and a real mount
    // would read them; failing to must not read as clean.
    let mut img = fixture();
    // Scribble over the file allocation table itself.
    for b in &mut img[512..2048] {
        *b = 0xFF;
    }
    let e = members(&img);
    assert!(
        e.is_empty() || e.iter().any(|x| x.unsupported.is_some()),
        "a filesystem that cannot be walked must be reported, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
}
