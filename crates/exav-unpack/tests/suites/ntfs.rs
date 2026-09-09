//! NTFS — reading files out of the master file table.
//!
//! VHD and VHDX are Windows-native, so a disk image aimed at a Windows victim
//! holds NTFS. A raw carve of the volume finds a file only where its magic
//! starts a contiguous run, which leaves a gap an attacker chooses the size of:
//! fragment a file and the carve sees pieces.
//!
//! The fixture is a real volume built with `mkntfs` and filled with `ntfscp`,
//! then edited so `payload.zip` occupies **two non-adjacent runs**. The edit is
//! not taken on trust — `ntfscat` reads the edited volume back to the same
//! digest, so an independent NTFS implementation agrees it is a valid two-run
//! file. The payload is a deflated ZIP, so EICAR appears nowhere in the volume's
//! bytes and only reassembly reaches it.
//!
//! Stored gzipped: an NTFS volume carries megabytes of `$LogFile` and `$UpCase`.
//!
//! Regenerate with:
//! ```sh
//! mkntfs -F -q -c 4096 -L exavtest ntfs.img
//! ntfscp ntfs.img payload.zip /payload.zip     # plus small.txt, eicar.com
//! # then split payload.zip's single run in two and re-apply the MFT fix-ups
//! ```

use exav_unpack::{detect, extract_each, Budget, Entry, Format, Limits};

/// `sha256sum` of what `ntfscat` returns for each file.
const PAYLOAD: &str = "49c7e4f4b184954a212c78c87c17705cd4c16f0b8c83a5cd6a750369c47957c5";
const SMALL: &str = "725445a66654be611d0a1c073b63c6d40bce0bb592b61e71db41f8de2cce6146";
const EICAR: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

/// The two-run list for `payload.zip`: four clusters, then four more one cluster
/// further on. Unique in the image.
const RUNLIST: [u8; 8] = [0x21, 0x04, 0x00, 0x0c, 0x11, 0x04, 0x04, 0x00];

fn fixture() -> Vec<u8> {
    let p = format!(
        "{}/tests/fixtures/ntfs/fragmented.img.gz",
        env!("CARGO_MANIFEST_DIR")
    );
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
        Format::Ntfs,
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
fn a_volume_is_recognised_from_its_boot_sector() {
    assert_eq!(detect(&fixture()), Some(Format::Ntfs));
}

#[test]
fn a_fragmented_file_is_reassembled_from_its_data_runs() {
    let e = members(&fixture());
    assert!(
        e.iter().all(|x| x.unsupported.is_none()),
        "a healthy volume must not report anything unreadable, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
    let p = e
        .iter()
        .find(|x| x.name == "payload.zip")
        .unwrap_or_else(|| {
            panic!(
                "the payload must be found; got {:?}",
                e.iter().map(|x| &x.name).collect::<Vec<_>>()
            )
        });
    assert_eq!(
        sha256_hex(&p.data),
        PAYLOAD,
        "the file spans two non-adjacent runs, so anything short of following \
         both returns fragments — and `ntfscat` returns this same digest"
    );
}

#[test]
fn a_resident_file_is_read_from_inside_its_record() {
    // A file small enough lives in the MFT record itself with no runs at all,
    // which is a different code path from every other file here.
    let e = members(&fixture());
    let s = e
        .iter()
        .find(|x| x.name == "small.txt")
        .expect("the resident file must be found");
    assert_eq!(sha256_hex(&s.data), SMALL);
}

#[test]
fn the_filesystems_own_metadata_is_not_emitted() {
    // `$MFT`, `$LogFile`, `$UpCase` and friends are filesystem internals, and
    // emitting them would spend the budget on megabytes of them. Nothing is lost:
    // the volume's raw bytes are pattern-scanned before this walk runs.
    let e = members(&fixture());
    assert!(
        !e.iter().any(|x| x.name.starts_with('$')),
        "metadata files should not be emitted, got {:?}",
        e.iter().map(|x| &x.name).collect::<Vec<_>>()
    );
    assert_eq!(e.len(), 3, "exactly the three user files");
}

#[test]
fn runs_that_do_not_cover_the_declared_size_are_reported_not_truncated() {
    // The failure mode that matters most. If the runs come up short — because
    // they were followed wrongly, or spill into an MFT record exav did not
    // reach — emitting what was gathered would hand the scanner a *prefix* of
    // the file and call it the file. A prefix that happens to exclude the
    // payload scans perfectly clean.
    //
    // Shrinking the first run from four clusters to two leaves the runs covering
    // six of eight, with the declared size unchanged.
    let mut img = fixture();
    let at = img
        .windows(RUNLIST.len())
        .position(|w| w == RUNLIST)
        .expect("the two-run list should be in the fixture");
    img[at + 1] = 0x02;

    let e = members(&img);
    let p = e
        .iter()
        .find(|x| x.name == "payload.zip")
        .expect("the file should still be listed");
    assert!(
        p.unsupported.is_some(),
        "a short read must be reported, not emitted as the whole file"
    );
    assert!(
        p.data.is_empty(),
        "and no partial content should be passed off as the file"
    );
}

#[test]
fn the_payload_is_absent_from_the_raw_volume() {
    // Guards the premise: if EICAR were visible in the sectors, a raw scan would
    // find it without reading the filesystem and none of this would be proven.
    let eicar_bytes = exav_unpack::eicar();
    let img = fixture();
    // `eicar.com` itself is stored in the clear, so search only for the copy
    // inside the deflated ZIP by checking it appears exactly once.
    let hits = img
        .windows(eicar_bytes.len())
        .filter(|w| *w == eicar_bytes)
        .count();
    assert_eq!(
        hits, 1,
        "only the plain eicar.com should be visible; the zipped copy must not be"
    );
    let e = members(&img);
    let z = e.iter().find(|x| x.name == "payload.zip").expect("payload");
    assert_eq!(sha256_hex(&z.data), PAYLOAD);
    let plain = e.iter().find(|x| x.name == "eicar.com").expect("eicar");
    assert_eq!(sha256_hex(&plain.data), EICAR);
}
