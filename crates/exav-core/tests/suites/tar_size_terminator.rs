//! POSIX lets a tar header's size field end in NUL, in a space, or in both, and
//! writers disagree. Every terminator a real writer emits must parse.
//!
//! This is asserted through `analyze` rather than through the unpacker's
//! `extract`, deliberately. There are TWO tar readers in the tree: `formats::tar`
//! (backed by the `tar` crate) serves the buffered `extract` path that
//! `exav-unpack list` uses, while the SCAN path streams and goes through
//! `parse_tar_headers`. Only the second one had the defect, so a test written
//! against `extract` passes while the scanner sees nothing — which is exactly how
//! this survived: listing a broken archive showed every member correctly.
//!
//! The failure was total and silent. An unparseable size ends the header walk, so
//! a first-member failure yields zero members and the archive scans as an empty
//! tar — clean. Every npm package tarball is written by node-tar, which uses the
//! space-then-NUL form.

use exav_core::{analyze, ScanOptions, Scanner, Verdict};

fn eicar() -> &'static [u8] {
    exav_core::unpack::eicar()
}

/// A single-member ustar archive whose size field uses `terminator`.
///
/// Built by hand because the writers that produce the interesting forms are not
/// available here: GNU tar, `--format=ustar`, `--format=pax` and python's
/// `tarfile` all emit digits-then-NUL, so no generated fixture reproduces the
/// node-tar form.
fn tar_with_size_terminator(name: &str, body: &[u8], size_field: &str) -> Vec<u8> {
    assert_eq!(size_field.len(), 12, "the size field is exactly 12 bytes");
    let mut h = [0u8; 512];
    h[..name.len()].copy_from_slice(name.as_bytes());
    h[100..108].copy_from_slice(b"0000644\0"); // mode
    h[108..116].copy_from_slice(b"0000000\0"); // uid
    h[116..124].copy_from_slice(b"0000000\0"); // gid
    h[124..136].copy_from_slice(size_field.as_bytes());
    h[136..148].copy_from_slice(b"00000000000\0"); // mtime
    h[156] = b'0'; // typeflag: regular file
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");

    // Checksum: computed with the checksum field itself read as spaces.
    h[148..156].copy_from_slice(b"        ");
    let sum: u32 = h.iter().map(|&b| b as u32).sum();
    let chk = format!("{sum:06o}\0 ");
    h[148..156].copy_from_slice(chk.as_bytes());

    let mut out = h.to_vec();
    out.extend_from_slice(body);
    out.resize(512 + body.len().div_ceil(512) * 512, 0);
    out.extend(vec![0u8; 1024]); // two zero blocks: end of archive
    out
}

/// GZIP the payload before it goes into the tar, so the archive holds no copy of
/// it in the clear.
///
/// This is what makes the tests below mean anything, and it took two attempts to
/// get right. A tar stores members verbatim, so a plain EICAR member is found by
/// the raw scan of the container with no header ever walked. Gzipping the whole
/// tar into a `.tgz` does not help either: the decompressed bytes are scanned
/// raw as well, and the payload is verbatim in those. Both versions passed
/// against the unfixed parser. Only a member that is ITSELF compressed forces
/// the walk — the payload cannot be reached without extracting the member.
/// The payload is padded with a long compressible run before being gzipped.
/// Deflate emits a STORED block for 68 bytes on their own, which leaves the
/// signature sitting in the clear inside the "compressed" member — the guard in
/// `finds_eicar` catches that, and the padding is what makes the block actually
/// compress.
fn gz(payload: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut data = payload.to_vec();
    data.extend(std::iter::repeat_n(b'A', 8192));
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(&data).unwrap();
    e.finish().unwrap()
}

fn finds_eicar_in(tar: &[u8]) -> bool {
    let db = Scanner::builtin();
    matches!(
        analyze(&db, tar, &ScanOptions::default()).verdict,
        Verdict::Infected { .. }
    )
}

fn finds_eicar(tar: &[u8]) -> bool {
    assert!(
        !tar.windows(eicar().len()).any(|w| w == eicar()),
        "the payload must not appear verbatim anywhere in the archive, or the \
         raw scan finds it without the tar walk being involved at all"
    );
    let db = Scanner::builtin();
    matches!(
        analyze(&db, tar, &ScanOptions::default()).verdict,
        Verdict::Infected { .. }
    )
}

#[test]
fn a_size_field_terminated_by_nul_is_parsed() {
    // GNU tar, ustar, pax, python tarfile. The control: this form always worked,
    // so if it ever fails the fixture itself is broken and the sibling test below
    // proves nothing.
    let body = gz(eicar());
    let blob = tar_with_size_terminator("payload.gz", &body, &format!("{:011o}\0", body.len()));
    assert!(
        finds_eicar(&blob),
        "digits-then-NUL is the most common form of all and must parse"
    );
}

#[test]
fn a_size_field_terminated_by_space_and_nul_is_parsed() {
    // node-tar, and therefore every npm package tarball: digits, a space, a NUL.
    let body = gz(eicar());
    let blob = tar_with_size_terminator("payload.gz", &body, &format!("{:010o} \0", body.len()));
    assert!(
        finds_eicar(&blob),
        "node-tar writes the size as digits then a space then a NUL; failing to \
         parse it ends the header walk at the first member, so the archive scans \
         as empty and every npm tarball becomes a blind spot"
    );
}

#[test]
fn a_size_field_terminated_by_a_space_alone_is_parsed() {
    // Permitted by POSIX and emitted by some older writers. Included because the
    // fix strips both characters from both ends rather than special-casing the
    // one form that was reported.
    let body = gz(eicar());
    let blob = tar_with_size_terminator("payload.gz", &body, &format!("{:011o} ", body.len()));
    assert!(
        finds_eicar(&blob),
        "a space-terminated size field is legal and must parse"
    );
}

/// The two tar readers must agree.
///
/// `formats::tar` (the `tar` crate) serves the buffered `extract` path that
/// `exav-unpack list` uses; the SCAN path streams through `parse_tar_headers`.
/// Only the second one had the size-terminator defect, so listing an affected
/// archive showed every member correctly while the scanner saw none — the
/// diagnostic tool actively contradicted the bug.
///
/// Pinning them together is what stops the next divergence hiding the same way.
#[test]
fn both_tar_readers_see_the_same_members() {
    use exav_unpack::{extract, Budget, Format, Limits};

    // A COMPRESSED member, so the payload appears nowhere verbatim: the raw scan
    // cannot reach it and only the streaming walk can. With a plain member this
    // test passes whatever the streaming reader does.
    let body = gz(eicar());
    for (label, field) in [
        ("gnu/ustar/pax/python", format!("{:011o}\0", body.len())),
        ("node-tar (npm)", format!("{:010o} \0", body.len())),
        ("space-terminated", format!("{:011o} ", body.len())),
    ] {
        let tar = tar_with_size_terminator("payload.gz", &body, &field);

        // Buffered reader, as `exav-unpack list` uses.
        let mut budget = Budget::new(Limits::default());
        let buffered: Vec<String> = extract(Format::Tar, &tar, &mut budget)
            .expect("buffered extract")
            .into_iter()
            .map(|e| e.name)
            .collect();

        // Streaming reader, as the scanner uses. Reached via a scan of the
        // gzipped archive, which is the only way in from this crate.
        let found_by_scan = finds_eicar_in(&tar);

        assert!(
            !buffered.is_empty(),
            "{label}: the buffered reader must see the member"
        );
        assert!(
            found_by_scan,
            "{label}: the streaming reader disagrees with the buffered one — \
             `exav-unpack list` would show this member while a scan misses it"
        );
    }
}
