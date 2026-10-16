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

use super::extract_each;
use exav_unpack::{detect, Budget, Entry, Format, Limits};

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

/// A member whose compressed form fits the budget and whose expansion does not
/// is reported as expanding past it, and is read only up to the budget.
#[test]
fn a_member_that_expands_past_the_budget_is_reported() {
    let blob = fixture("undhr.z");
    let whole = members(&blob);
    let (comp, size) = whole
        .iter()
        .map(|e| (e.comp_size, e.data.len() as u64))
        .find(|&(c, d)| c > 0 && d > c + 2)
        .expect("a member that expands");
    let mut limits = Limits::default();
    limits.max_buffer_bytes = comp + (size - comp) / 2;
    let mut b = Budget::new(limits);
    let mut out = Vec::new();
    let _ = extract_each(
        Format::IshieldZ,
        &blob,
        &mut b,
        &mut |e: Entry, _: &mut Budget| {
            out.push(e);
            None::<()>
        },
    );
    assert!(
        out.iter().any(|x| x
            .unsupported
            .is_some_and(|r| r.contains("decompressed past the per-member"))),
        "got {:?}",
        out.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
}

/// An archive whose table of contents has `dirs` directory records, each
/// declaring `dir_files` members and each a zero-length chunk, so that every
/// record and every member reads the same bytes again. 498 bytes of this took
/// the `unshield` reader 1.5 GB: it builds one entry per declared member before
/// anything is checked.
fn declared_member_bomb(dirs: u16, dir_files: u16) -> Vec<u8> {
    const HEADER: usize = 255;
    const TOC: usize = 64;
    let mut d = vec![0u8; HEADER + TOC];
    d[..4].copy_from_slice(&[0x13, 0x5D, 0x65, 0x8C]);
    d[12..14].copy_from_slice(&1u16.to_le_bytes());
    d[18..22].copy_from_slice(&((HEADER + TOC) as u32).to_le_bytes());
    d[41..45].copy_from_slice(&(HEADER as u32).to_le_bytes());
    d[49..51].copy_from_slice(&dirs.to_le_bytes());
    d[HEADER..HEADER + 2].copy_from_slice(&dir_files.to_le_bytes());
    d
}

#[test]
fn a_table_declaring_more_members_than_the_walk_bound_is_reported_not_built() {
    let blob = declared_member_bomb(1, u16::MAX);
    assert_eq!(detect(&blob), Some(Format::IshieldZ));
    let e = members(&blob);
    assert_eq!(
        e.len(),
        1,
        "got {:?}",
        e.iter().map(|x| &x.name).collect::<Vec<_>>()
    );
    assert!(
        e[0].unsupported.is_some(),
        "members left unexamined must be reported"
    );
}

#[test]
fn a_table_of_many_directories_each_declaring_many_members_stays_small() {
    // 65535 x 65535 declared members: 4 billion entries if built.
    let blob = declared_member_bomb(u16::MAX, u16::MAX);
    let e = members(&blob);
    assert_eq!(e.len(), 1);
    assert!(e[0].unsupported.is_some());
}

/// `undhr.z`'s one member twice, under the same path.
fn same_path_twice() -> Vec<u8> {
    let z = fixture("undhr.z");
    let u32at = |o: usize| u32::from_le_bytes(z[o..o + 4].try_into().unwrap()) as usize;
    let toc = &z[u32at(41)..u32at(18)];
    let dir_chunk = u16::from_le_bytes([toc[2], toc[3]]) as usize;
    let (dir, file) = toc.split_at(dir_chunk);
    let data = &z[255..u32at(41)];

    let mut out = z[..255].to_vec();
    out.extend_from_slice(data);
    out.extend_from_slice(data);
    let toc_at = out.len();
    out.extend_from_slice(&[2, 0]);
    out.extend_from_slice(&dir[2..]);
    out.extend_from_slice(file);
    out.extend_from_slice(file);
    let end = out.len() as u32;
    out[18..22].copy_from_slice(&end.to_le_bytes());
    out[41..45].copy_from_slice(&(toc_at as u32).to_le_bytes());
    out
}

#[test]
fn members_sharing_a_path_are_all_extracted() {
    let e = members(&same_path_twice());
    let want = fixture("undhr.md");
    assert_eq!(
        e.len(),
        2,
        "one member hid the other: {:?}",
        e.iter().map(|x| &x.name).collect::<Vec<_>>()
    );
    assert!(e.iter().all(|x| x.data == want));
}

#[test]
fn a_member_past_the_budget_is_reported_not_skipped() {
    let mut limits = Limits::default();
    limits.max_buffer_bytes = 16;
    let mut b = Budget::new(limits);
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

/// `undhr.z` with its one member's compressed size (in the file record of the
/// table of contents) set to `size`.
fn with_member_size(size: u32) -> Vec<u8> {
    let mut z = fixture("undhr.z");
    let u32at = |z: &[u8], o: usize| u32::from_le_bytes(z[o..o + 4].try_into().unwrap()) as usize;
    let toc = u32at(&z, 41);
    let dir_chunk = u16::from_le_bytes([z[toc + 2], z[toc + 3]]) as usize;
    let at = toc + dir_chunk + 7;
    z[at..at + 4].copy_from_slice(&size.to_le_bytes());
    z
}

#[test]
fn a_member_cut_inside_its_stream_keeps_its_prefix_and_is_reported() {
    let whole = members(&fixture("undhr.z"));
    let want = fixture("undhr.md");
    let half = (whole[0].comp_size / 2) as u32;
    let e = members(&with_member_size(half));
    assert_eq!(e.len(), 1);
    assert!(
        e[0].unsupported.is_some(),
        "a member whose stream stops short was reported as whole"
    );
    assert!(
        e[0].data.len() > 100 && want.starts_with(&e[0].data),
        "the decoded prefix is lost: {} bytes",
        e[0].data.len()
    );
    assert!(e[0].data.len() < want.len());
}

#[test]
fn a_member_damaged_part_way_keeps_its_prefix_and_is_reported() {
    // A byte of the compressed data set to each value in turn until one
    // makes the stream invalid after it has produced output.
    let z = fixture("undhr.z");
    let want = fixture("undhr.md");
    let mut found = false;
    for at in (300..1500).step_by(7) {
        let mut bad = z.clone();
        bad[at] = !bad[at];
        let e = members(&bad);
        if e.len() != 1 || e[0].unsupported.is_none() || e[0].data.is_empty() {
            continue;
        }
        found = true;
        // Output before the damaged byte is the file's own.
        assert!(e[0].data.starts_with(&want[..20]), "byte {at}");
        break;
    }
    assert!(found, "no damaged member kept a decoded prefix");
}

#[test]
fn a_member_whose_range_runs_past_the_file_is_reported() {
    // Past the end of the file, but within the size budget; its stream still
    // ends, so only the range says something is wrong.
    let whole = members(&fixture("undhr.z"));
    let e = members(&with_member_size(whole[0].comp_size as u32 + 100_000));
    assert_eq!(e.len(), 1);
    assert!(e[0].unsupported.is_some());
    assert_eq!(e[0].data, fixture("undhr.md"));
}
