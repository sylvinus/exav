//! Formats stock ClamAV does not open stay shut under `--clamav-compat`, and
//! the ones it opens stay open.
//!
//! clamscan 1.4.3 (`--debug`) types each format below as binary data, or by a
//! type of its own, and extracts nothing from it: a member holding a signature
//! is never found, while the same bytes in a tar or a plain file are. A
//! differential run must not count exav's reach into them as a disagreement.
//!
//! The payload is a signature anchored at offset 0 of its own object: it is
//! nowhere near the start of the container's bytes, so only opening the
//! container can find it, and the raw scan of the container cannot.

use exav_core::loader::Builder;
use exav_core::{ScanOptions, Scanner, Verdict, analyze};
use std::io::{Read, Write};

const PAYLOAD: &[u8] = b"MEMBERPAYLOAD";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A database of one signature: `member` at offset 0 of any file type.
fn scanner(member: &[u8]) -> Scanner {
    let mut b = Builder::new();
    let line = format!("Exav.Test.Member:0:0:{}\n", hex(member));
    b.add_named_bytes("member.ndb", line.as_bytes(), false);
    b.build().unwrap()
}

/// The verdict of a scan of `container` with that database.
fn verdict(container: &[u8], member: &[u8], opts: &ScanOptions) -> Verdict {
    analyze(&scanner(member), container, opts).verdict
}

/// What the scan of `container` finds, by signature name (compat adds
/// `.UNOFFICIAL` to the names of an unofficial database, as clamscan does).
fn found_with(container: &[u8], member: &[u8], opts: &ScanOptions) -> Option<String> {
    match verdict(container, member, opts) {
        Verdict::Infected { signature, .. } => Some(
            signature
                .strip_suffix(".UNOFFICIAL")
                .unwrap_or(&signature)
                .to_string(),
        ),
        _ => None,
    }
}

fn found(container: &[u8], opts: &ScanOptions) -> Option<String> {
    found_with(container, PAYLOAD, opts)
}

/// A default scan opens the container and finds the member; the compat one does
/// not. The first half is what makes the second mean something: a container
/// built wrong would pass the second half for the wrong reason.
fn shut_under_compat(what: &str, container: &[u8], member: &[u8]) {
    assert!(
        !container.starts_with(member),
        "{what}: the container must not itself look like the payload"
    );
    assert_eq!(
        found_with(container, member, &ScanOptions::default()).as_deref(),
        Some("Exav.Test.Member"),
        "{what}: the container must be opened by default"
    );
    assert_eq!(
        found_with(container, member, &ScanOptions::clamav_compat()),
        None,
        "{what}: stock ClamAV opens nothing here, so compat must not"
    );
}

fn opened_by_default_and_shut_under_compat(what: &str, container: &[u8]) {
    shut_under_compat(what, container, PAYLOAD);
}

/// The container is opened by ClamAV too, so compat finds the member as well.
fn open_under_both(what: &str, container: &[u8], member: &[u8]) {
    for (mode, opts) in [
        ("default", ScanOptions::default()),
        ("compat", ScanOptions::clamav_compat()),
    ] {
        assert_eq!(
            found_with(container, member, &opts).as_deref(),
            Some("Exav.Test.Member"),
            "{what}: {mode} must open it, ClamAV does"
        );
    }
}

/// A format exav only recognises: reported not fully examined by default, and
/// clean under compat, as clamscan reports it.
fn reported_by_default_and_clean_under_compat(what: &str, container: &[u8]) {
    assert!(
        matches!(
            verdict(container, PAYLOAD, &ScanOptions::default()),
            Verdict::Unscannable { .. }
        ),
        "{what}: must be reported unscannable by default"
    );
    assert_eq!(
        verdict(container, PAYLOAD, &ScanOptions::clamav_compat()),
        Verdict::Clean,
        "{what}: clamscan reports it clean, so compat must"
    );
}

/// A fixture of exav-unpack, masked fixtures included.
fn fixture(rel: &str) -> Vec<u8> {
    let p = format!(
        "{}/../exav-unpack/tests/fixtures/{rel}",
        env!("CARGO_MANIFEST_DIR")
    );
    exav_core::unpack::read_fixture(&p).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn gunzip(gz: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(gz)
        .read_to_end(&mut out)
        .unwrap();
    out
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(data).unwrap();
    gz.finish().unwrap()
}

/// An AppleSingle (`magic` 0x00051600) or AppleDouble (0x00051607) file: a real
/// name entry, then `fork_id` (1 data fork, 2 resource fork) holding the payload.
fn apple(magic: u32, fork_id: u32) -> Vec<u8> {
    const NAME: &[u8] = b"member.bin";
    let table = 26 + 2 * 12;
    let mut out = Vec::new();
    out.extend_from_slice(&magic.to_be_bytes());
    out.extend_from_slice(&0x0002_0000u32.to_be_bytes());
    out.extend_from_slice(&[0u8; 16]);
    out.extend_from_slice(&2u16.to_be_bytes());
    for (id, off, len) in [
        (3u32, table, NAME.len()),
        (fork_id, table + NAME.len(), PAYLOAD.len()),
    ] {
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&(off as u32).to_be_bytes());
        out.extend_from_slice(&(len as u32).to_be_bytes());
    }
    out.extend_from_slice(NAME);
    out.extend_from_slice(PAYLOAD);
    out
}

#[test]
fn applesingle_and_appledouble_are_opened_by_default_and_not_under_compat() {
    for (what, magic, fork) in [
        ("AppleSingle data fork", 0x0005_1600, 1),
        ("AppleSingle resource fork", 0x0005_1600, 2),
        ("AppleDouble resource fork", 0x0005_1607, 2),
    ] {
        opened_by_default_and_shut_under_compat(what, &apple(magic, fork));
    }
}

/// An InstallShield 6 cabinet holding `PAYLOAD` as one stored file, laid out as
/// the `unshield` library reads one: the common header and volume header, then
/// the descriptor with its directory and file tables, then the data.
fn installshield_cabinet() -> Vec<u8> {
    const DESCRIPTOR: usize = 0x200;
    const TABLE_FROM_DESCRIPTOR: usize = 0x200;
    const TABLE: usize = DESCRIPTOR + TABLE_FROM_DESCRIPTOR;
    const RECORD: usize = 0x57;
    fn put(buf: &mut [u8], at: usize, v: &[u8]) {
        buf[at..at + v.len()].copy_from_slice(v);
    }
    let mut h = vec![0u8; TABLE + 4];
    // One directory, named "", then the file's name.
    let dir_name = (h.len() - TABLE) as u32;
    h.push(0);
    let file_name = (h.len() - TABLE) as u32;
    h.extend_from_slice(b"member.bin\0");
    let records = h.len() - TABLE;
    let record = h.len();
    h.resize(record + RECORD, 0);
    let header_end = h.len();
    put(&mut h, TABLE, &dir_name.to_le_bytes());
    // The file record: expanded and stored sizes, data offset, name, directory
    // and the cabinet it is in.
    put(&mut h, record + 2, &(PAYLOAD.len() as u64).to_le_bytes());
    put(&mut h, record + 10, &(PAYLOAD.len() as u64).to_le_bytes());
    put(&mut h, record + 18, &(header_end as u64).to_le_bytes());
    put(&mut h, record + 58, &file_name.to_le_bytes());
    put(&mut h, record + 85, &1u16.to_le_bytes());
    put(&mut h, 0, b"ISc(");
    put(&mut h, 4, &(0x0100_0000u32 | (6 << 12)).to_le_bytes());
    put(&mut h, 12, &(DESCRIPTOR as u32).to_le_bytes());
    put(
        &mut h,
        16,
        &((header_end - DESCRIPTOR) as u32).to_le_bytes(),
    );
    // The volume header: where the data starts, the first and last file.
    put(&mut h, 20, &(header_end as u32).to_le_bytes());
    put(
        &mut h,
        DESCRIPTOR + 0x0c,
        &(TABLE_FROM_DESCRIPTOR as u32).to_le_bytes(),
    );
    put(&mut h, DESCRIPTOR + 0x1c, &1u32.to_le_bytes());
    put(&mut h, DESCRIPTOR + 0x28, &1u32.to_le_bytes());
    put(&mut h, DESCRIPTOR + 0x2c, &(records as u32).to_le_bytes());
    h.extend_from_slice(PAYLOAD);
    h
}

#[test]
fn an_installshield_cabinet_is_opened_by_default_and_not_under_compat() {
    opened_by_default_and_shut_under_compat("InstallShield cabinet", &installshield_cabinet());
}

/// Real files written by the tools of each format, so what hides the member is
/// the format's own coding: ZOO's LZD and LZH, and InstallShield's implode.
#[test]
fn zoo_and_installshield_z_are_opened_by_default_and_not_under_compat() {
    let license = [&[b' '; 33][..], b"Apache License\n"].concat();
    for rel in ["zoo/default.zoo", "zoo/high_per.zoo"] {
        shut_under_compat(rel, &fixture(rel), &license);
    }
    shut_under_compat(
        "InstallShield .z",
        &fixture("ishieldz/undhr.z"),
        b"# Preamble\n\nWhereas recognition of the i",
    );
}

/// What the format recognises and cannot decode: reported by default, so never
/// clean, and clean under compat as clamscan reports it.
#[test]
fn recognised_only_formats_are_reported_by_default_and_clean_under_compat() {
    reported_by_default_and_clean_under_compat("StuffIt", b"SIT!padding here, more bytes");
    reported_by_default_and_clean_under_compat(
        "ACE",
        &[&[0u8; 7][..], b"**ACE**", &[0u8; 16]].concat(),
    );
    reported_by_default_and_clean_under_compat("lrzip", b"LRZI\x00\x06rest of the stream");
}

/// The member of `tree.py`'s `p1.bin`, which every filesystem fixture holds
/// (`pat(4, 1025)`): its first bytes are what a signature anchors on.
fn tree_member() -> Vec<u8> {
    const TEXT: &[u8] = b"abcdefghij0123456789";
    (0..32usize)
        .map(|i| {
            if (i / 64) % 2 == 0 {
                (((i as u64 * 2_654_435_761 + 4 * 40_503) & 0xFFFF_FFFF) >> 13) as u8
            } else {
                TEXT[(i + 4) % 20]
            }
        })
        .collect()
}

#[test]
fn filesystem_images_are_opened_by_default_and_not_under_compat() {
    let member = tree_member();
    // ext, FAT, exFAT, cramfs, romfs, SquashFS (zstd) and EROFS (lz4).
    for name in [
        "ext2_blockmap",
        "fat12",
        "exfat",
        "cramfs",
        "romfs",
        "squashfs_zstd",
        "erofs_z_lz4",
    ] {
        let img = gunzip(&fixture(&format!("fs/{name}.img.gz")));
        shut_under_compat(name, &img, &member);
    }
}

#[test]
fn an_ntfs_image_is_opened_by_default_and_not_under_compat() {
    let img = gunzip(&fixture("ntfs/attribute_list.img.gz"));
    shut_under_compat("NTFS", &img, b"line 0000000 fragmented across t");
}

#[test]
fn a_wim_image_is_opened_by_default_and_not_under_compat() {
    shut_under_compat(
        "WIM (LZX)",
        &fixture("wim/hard_LZX.wim"),
        b"tnetgrent\0__sysconf\0__nss_passwd",
    );
}

/// A Unix archive (`ar`, `.deb`, `.a`) of one member.
fn ar(member: &[u8]) -> Vec<u8> {
    let mut f = b"!<arch>\n".to_vec();
    let header = format!(
        "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
        "payload.txt/",
        0,
        0,
        0,
        "100644",
        member.len()
    );
    f.extend_from_slice(header.as_bytes());
    f.extend_from_slice(member);
    if member.len() % 2 == 1 {
        f.push(b'\n');
    }
    f
}

#[test]
fn an_ar_archive_and_a_lzip_stream_are_opened_by_default_and_not_under_compat() {
    opened_by_default_and_shut_under_compat("ar", &ar(PAYLOAD));
    shut_under_compat(
        "lzip",
        &fixture("lzip_simple.lz"),
        b"hello exav inside lzip",
    );
}

/// An ARC archive of one stored member (method 2).
fn arc(member: &[u8]) -> Vec<u8> {
    let mut f = vec![0x1A, 2];
    f.extend_from_slice(b"PAYLOAD.TXT\0\0");
    f.extend_from_slice(&(member.len() as u32).to_le_bytes());
    f.extend_from_slice(&[0; 6]);
    f.extend_from_slice(&(member.len() as u32).to_le_bytes());
    f.extend_from_slice(member);
    f.extend_from_slice(&[0x1A, 0]);
    f
}

/// An LZ4 frame of one uncompressed block.
fn lz4(member: &[u8]) -> Vec<u8> {
    let mut f = vec![0x04, 0x22, 0x4D, 0x18, 0x60, 0x40, 0x82];
    f.extend_from_slice(&(0x8000_0000 | member.len() as u32).to_le_bytes());
    f.extend_from_slice(member);
    f.extend_from_slice(&[0; 4]);
    f
}

/// A Zstandard frame of one raw block, sized by a one-byte content size.
fn zstd(member: &[u8]) -> Vec<u8> {
    let mut f = vec![0x28, 0xB5, 0x2F, 0xFD, 0x20, member.len() as u8];
    f.extend_from_slice(&(1 | (member.len() as u32) << 3).to_le_bytes()[..3]);
    f.extend_from_slice(member);
    f
}

#[test]
fn arc_lz4_and_zstd_are_opened_by_default_and_not_under_compat() {
    opened_by_default_and_shut_under_compat("ARC", &arc(PAYLOAD));
    opened_by_default_and_shut_under_compat("LZ4", &lz4(PAYLOAD));
    opened_by_default_and_shut_under_compat("Zstandard", &zstd(PAYLOAD));
}

/// A shortcut whose arguments string is `args`: the member exav reads out of it.
fn lnk(args: &[u8]) -> Vec<u8> {
    let mut f = vec![0u8; 0x4C];
    f[..20].copy_from_slice(&[
        0x4C, 0, 0, 0, 0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46,
    ]);
    f[20..24].copy_from_slice(&(1u32 << 5).to_le_bytes());
    f.extend_from_slice(&(args.len() as u16).to_le_bytes());
    f.extend_from_slice(args);
    f
}

/// A `.pyc` of Python 3.12: a 16-byte header, then the marshalled body.
fn pyc(body: &[u8]) -> Vec<u8> {
    [&[0xCB, 0x0D, 0x0D, 0x0A][..], &[0; 12], body].concat()
}

/// A Java class whose first constant pool entry is a `Utf8` of `utf8`.
fn java_class(utf8: &[u8]) -> Vec<u8> {
    let mut f = vec![0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52, 0, 2, 1];
    f.extend_from_slice(&(utf8.len() as u16).to_be_bytes());
    f.extend_from_slice(utf8);
    f.extend_from_slice(&[0; 16]);
    f
}

/// A Python pickle calling `posix.system` on `arg`.
fn pickle(arg: &[u8]) -> Vec<u8> {
    let mut f = b"\x80\x02cposix\nsystem\nq\x00X".to_vec();
    f.extend_from_slice(&(arg.len() as u32).to_le_bytes());
    f.extend_from_slice(arg);
    f.extend_from_slice(b"q\x01\x85q\x02Rq\x03.");
    f
}

#[test]
fn lnk_pyc_java_class_and_pickle_are_opened_by_default_and_not_under_compat() {
    opened_by_default_and_shut_under_compat("LNK", &lnk(PAYLOAD));
    opened_by_default_and_shut_under_compat("pyc", &pyc(PAYLOAD));
    opened_by_default_and_shut_under_compat("Java class", &java_class(PAYLOAD));
    shut_under_compat(
        "AI model (pickle)",
        &pickle(PAYLOAD),
        b"posix\nsystem\nMEMBERPAYLOAD",
    );
}

/// An SZDD of `member` written as literals, with the compression mode and the
/// byte 9 (the missing character) given.
fn szdd(mode: u8, byte9: u8, member: &[u8]) -> Vec<u8> {
    let mut f = b"SZDD\x88\xF0\x27\x33".to_vec();
    f.extend_from_slice(&[mode, byte9]);
    f.extend_from_slice(&(member.len() as u32).to_le_bytes());
    for chunk in member.chunks(8) {
        f.push(((1u16 << chunk.len()) - 1) as u8);
        f.extend_from_slice(chunk);
    }
    f
}

/// A KWAJ file of `member`, method 0 (stored).
fn kwaj(member: &[u8]) -> Vec<u8> {
    let mut f = b"KWAJ\x88\xF0\x27\xD1".to_vec();
    f.extend_from_slice(&[0, 0, 14, 0, 0, 0]);
    f.extend_from_slice(member);
    f
}

/// ClamAV opens an SZDD in mode `A` whose byte 9 is zero; another mode, a
/// nonzero byte 9 and KWAJ are not opened.
#[test]
fn szdd_is_gated_as_clamav_opens_it() {
    open_under_both(
        "SZDD, mode A, byte 9 zero",
        &szdd(b'A', 0, PAYLOAD),
        PAYLOAD,
    );
    shut_under_compat("SZDD, byte 9 not zero", &szdd(b'A', b'X', PAYLOAD), PAYLOAD);
    shut_under_compat("SZDD, mode B", &szdd(b'B', 0, PAYLOAD), PAYLOAD);
    shut_under_compat("KWAJ", &kwaj(PAYLOAD), PAYLOAD);
}

fn crc32(d: &[u8]) -> u32 {
    let mut c = flate2::Crc::new();
    c.update(d);
    c.sum()
}

/// An ALZ archive of one stored member.
fn alz(member: &[u8]) -> Vec<u8> {
    let name = b"payload.txt";
    let mut f = b"ALZ\x01\x0a\x00\x00\x00BLZ\x01".to_vec();
    f.extend_from_slice(&(name.len() as u16).to_le_bytes());
    f.push(0x20);
    f.extend_from_slice(&[0; 4]);
    f.extend_from_slice(&[0x40, 0, 0, 0]);
    f.extend_from_slice(&crc32(member).to_le_bytes());
    f.extend_from_slice(&(member.len() as u32).to_le_bytes());
    f.extend_from_slice(&(member.len() as u32).to_le_bytes());
    f.extend_from_slice(name);
    f.extend_from_slice(member);
    f.extend_from_slice(b"CLZ\x01");
    f
}

/// An EGG archive of one stored block.
fn egg(member: &[u8]) -> Vec<u8> {
    const END: [u8; 4] = 0x08E2_8222u32.to_le_bytes();
    let name = b"payload.txt";
    let mut f = b"EGGA".to_vec();
    f.extend_from_slice(&0x0100u16.to_le_bytes());
    f.extend_from_slice(&0x1234_5678u32.to_le_bytes());
    f.extend_from_slice(&0u32.to_le_bytes());
    f.extend_from_slice(&END);
    f.extend_from_slice(&0x0A85_90E3u32.to_le_bytes());
    f.extend_from_slice(&0u32.to_le_bytes());
    f.extend_from_slice(&(member.len() as u64).to_le_bytes());
    f.extend_from_slice(&0x0A85_91ACu32.to_le_bytes());
    f.push(0);
    f.extend_from_slice(&(name.len() as u16).to_le_bytes());
    f.extend_from_slice(name);
    f.extend_from_slice(&END);
    f.extend_from_slice(&0x02B5_0C13u32.to_le_bytes());
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(&(member.len() as u32).to_le_bytes());
    f.extend_from_slice(&(member.len() as u32).to_le_bytes());
    f.extend_from_slice(&crc32(member).to_le_bytes());
    f.extend_from_slice(&END);
    f.extend_from_slice(member);
    f.extend_from_slice(&END);
    f
}

/// ClamAV opens ALZ and EGG: compat keeps them.
#[test]
fn alz_and_egg_stay_open_under_compat() {
    open_under_both("ALZ", &alz(PAYLOAD), PAYLOAD);
    open_under_both("EGG", &egg(PAYLOAD), PAYLOAD);
}

/// A CryptFF file: the 8-byte magic, 8 bytes that do not change the decoding,
/// then the content with every byte flipped.
fn cryptff(second: &[u8; 8], content: &[u8]) -> Vec<u8> {
    let mut f = vec![0xB6, 0xB9, 0xAC, 0xAE, 0xFE, 0xFF, 0xFF, 0xFF];
    f.extend_from_slice(second);
    f.extend(content.iter().map(|b| b ^ 0xFF));
    f
}

/// ClamAV decodes a CryptFF file and scans the content (typing it again: a ZIP
/// inside is opened), so both modes do.
#[test]
fn cryptff_is_decoded_by_default_and_under_compat() {
    open_under_both("CryptFF", &cryptff(&[0; 8], PAYLOAD), PAYLOAD);
    open_under_both(
        "CryptFF, other header bytes",
        &cryptff(b"12345678", PAYLOAD),
        PAYLOAD,
    );
    open_under_both(
        "CryptFF around a ZIP",
        &cryptff(&[0; 8], &zip_of(PAYLOAD)),
        PAYLOAD,
    );
    // The content is the flipped bytes: the payload written as it is, is not it.
    let mut unflipped = cryptff(&[0; 8], b"");
    unflipped.extend_from_slice(PAYLOAD);
    for opts in [ScanOptions::default(), ScanOptions::clamav_compat()] {
        assert_eq!(found(&unflipped, &opts), None);
    }
}

/// ClamAV opens a DMG (zlib and bzip2 blocks, an HFS+ volume inside), so the
/// magic-dispatched disk images stay off under compat except this one. EICAR is
/// in the volume, compressed.
#[test]
fn a_dmg_is_opened_under_compat_as_clamav_opens_it() {
    let dmg = gunzip(&fixture("cut_short/udif_zlib.dmg.gz"));
    let eicar = exav_core::unpack::eicar();
    let mut b = Builder::new();
    let line = format!("Exav.Test.Member:0:*:{}\n", hex(&eicar[..40]));
    b.add_named_bytes("member.ndb", line.as_bytes(), false);
    let db = b.build().unwrap();
    for opts in [ScanOptions::default(), ScanOptions::clamav_compat()] {
        assert!(
            matches!(analyze(&db, &dmg, &opts).verdict, Verdict::Infected { .. }),
            "a DMG must be opened"
        );
    }
}

fn tiny_pe() -> &'static [u8] {
    include_bytes!("../testdata/tiny_pe32.exe")
}

fn tiny_elf() -> &'static [u8] {
    include_bytes!("../testdata/tiny_elf64")
}

/// ClamAV scans an executable stapled behind a PE and none stapled behind any
/// other file, and no ELF behind any (a PE and an ELF behind a text file, a PNG,
/// binary data and an ELF were measured).
#[test]
fn an_executable_carved_out_of_a_file_is_scanned_under_compat_as_clamav_scans_it() {
    let pe = tiny_pe();
    // The host differs from the guest in its first bytes: only carving finds it.
    let mut host = pe.to_vec();
    host[0x41] ^= 0xFF;
    open_under_both("PE behind a PE", &[&host[..], pe].concat(), &pe[..0x80]);
    shut_under_compat("PE behind text", &carrier(pe), &pe[..0x80]);
    let elf = tiny_elf();
    shut_under_compat("ELF behind text", &carrier(elf), &elf[..0x40]);
    shut_under_compat("ELF behind a PE", &[&host[..], elf].concat(), &elf[..0x40]);
}

/// A thin 64-bit Mach-O header with a sane file type and command count, then
/// bytes that mark it.
fn tiny_macho() -> Vec<u8> {
    let mut m = vec![0xCF, 0xFA, 0xED, 0xFE];
    m.resize(12, 0);
    m.extend_from_slice(&2u32.to_le_bytes()); // MH_EXECUTE
    m.extend_from_slice(&5u32.to_le_bytes()); // ncmds
    m.resize(28, 0);
    m.extend((0..64u8).map(|b| b.wrapping_mul(7).wrapping_add(3)));
    m
}

/// A universal binary holding `thin` as its one slice.
fn fat_macho(thin: &[u8]) -> Vec<u8> {
    let mut f = vec![0xCA, 0xFE, 0xBA, 0xBE];
    f.extend_from_slice(&1u32.to_be_bytes());
    for field in [0x0100_000Cu32, 0, 64, thin.len() as u32, 6] {
        f.extend_from_slice(&field.to_be_bytes());
    }
    f.resize(64, 0);
    f.extend_from_slice(thin);
    f
}

/// ClamAV scans no Mach-O stapled behind another file (thin and universal ones
/// behind a text file, binary data, a PNG, an ELF and a PE were measured), and
/// does scan one that starts the file.
#[test]
fn a_mach_o_carved_out_of_a_file_is_not_scanned_under_compat() {
    let thin = tiny_macho();
    let fat = fat_macho(&thin);
    open_under_both("thin Mach-O", &thin, &thin[..0x20]);
    shut_under_compat("thin Mach-O behind text", &carrier(&thin), &thin[..0x20]);
    shut_under_compat(
        "thin Mach-O behind an ELF",
        &[tiny_elf(), &thin].concat(),
        &thin[..0x20],
    );
    shut_under_compat(
        "thin Mach-O behind a PE",
        &[tiny_pe(), &[0u8; 64], &thin].concat(),
        &thin[..0x20],
    );
    shut_under_compat(
        "universal Mach-O behind text",
        &carrier(&fat),
        &thin[..0x20],
    );
}

/// A text file with `archive` stapled behind it.
fn carrier(archive: &[u8]) -> Vec<u8> {
    let mut f = b"a carrier with an archive stapled behind it\n".repeat(20);
    f.extend_from_slice(archive);
    f
}

fn zip_of(member: &[u8]) -> Vec<u8> {
    let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    z.start_file("payload.txt", opts).unwrap();
    z.write_all(member).unwrap();
    z.finish().unwrap().into_inner()
}

/// `PAYLOAD` as a bzip2 stream and as an xz stream.
const BZ2: &[u8] = b"\x42\x5a\x68\x39\x31\x41\x59\x26\x53\x59\xce\x31\x1a\xf7\x00\x00\x04\x06\x00\x36\x06\xd0\x20\x20\x00\x31\x00\x30\x20\x68\x7a\x86\x02\x8a\xe0\xde\x47\x8b\xb9\x22\x9c\x28\x48\x67\x18\x8d\x7b\x80";
const XZ: &[u8] = b"\xfd\x37\x7a\x58\x5a\x00\x00\x01\x69\x22\xde\x36\x02\x00\x21\x01\x16\x00\x00\x00\x74\x2f\xe5\xa3\x01\x00\x0c\x4d\x45\x4d\x42\x45\x52\x50\x41\x59\x4c\x4f\x41\x44\x00\x00\x00\x00\x40\x0d\x85\xb9\x00\x01\x21\x0d\x75\xdc\xa8\xd2\x90\x42\x99\x0d\x01\x00\x00\x00\x00\x01\x59\x5a";

/// ClamAV finds a ZIP stapled behind a file, not a gzip, bzip2 or xz stream
/// (appended to a PE, an ELF, a PNG, a text file and binary data alike).
#[test]
fn only_zip_is_carved_out_of_a_file_under_compat() {
    open_under_both("zip", &carrier(&zip_of(PAYLOAD)), PAYLOAD);
    shut_under_compat("gzip", &carrier(&gzip(PAYLOAD)), PAYLOAD);
    shut_under_compat("bzip2", &carrier(BZ2), PAYLOAD);
    shut_under_compat("xz", &carrier(XZ), PAYLOAD);
}

/// `data` uuencoded, one `begin` line, 45 bytes to a line.
fn uuencode(name: &str, data: &[u8]) -> String {
    let char_of = |v: u8| if v == 0 { b'`' } else { v + 32 };
    let mut out = format!("begin 644 {name}\n");
    for line in data.chunks(45) {
        out.push(char_of(line.len() as u8) as char);
        for g in line.chunks(3) {
            let n = u32::from(g[0]) << 16
                | u32::from(*g.get(1).unwrap_or(&0)) << 8
                | u32::from(*g.get(2).unwrap_or(&0));
            for k in (0..4).rev() {
                out.push(char_of((n >> (6 * k) & 63) as u8) as char);
            }
        }
        out.push('\n');
    }
    out.push_str("`\nend\n");
    out
}

/// A message of `first` and what follows it, then a blank line and `PAYLOAD`
/// uuencoded: no MIME header.
fn header_only_mail(first: &str) -> Vec<u8> {
    format!("{first}\n\n{}", uuencode("payload.bin", PAYLOAD)).into_bytes()
}

/// clamscan types a file as mail from its first line alone (measured over 260
/// header names) and decodes the uuencoded file in its body, with no MIME
/// header and no second header. Both modes do.
#[test]
fn a_message_with_headers_only_has_its_uuencoded_body_decoded() {
    for first in [
        "From: a@example.com",
        "From a@example.com Mon Jan  1 00:00:00 2024",
        "Received: from x by y; Mon, 1 Jan 2024 00:00:00 +0000",
        "Return-Path: <a@example.com>\nFrom: a@example.com",
        "To: b@example.com\nFrom: a@example.com",
        "Subject: t\nFrom: a@example.com",
        "Date: Mon, 1 Jan 2024 00:00:00 +0000\nReceived: from x by y",
        "Message-ID: <1@example.com>\nFrom: a@example.com",
        "Delivered-To: b@example.com\nReceived: from x by y",
        "From: a@example.com\r\nTo: b@example.com\r\nSubject: t\r",
    ] {
        open_under_both(first, &header_only_mail(first), PAYLOAD);
    }
}

/// A file clamscan does not type as mail has nothing decoded: the name is in
/// another case, the first line is another header, a blank line or a byte comes
/// first, or the header is not the first line.
#[test]
fn text_that_is_not_typed_as_mail_has_no_uuencoded_body_decoded() {
    for first in [
        "Cc: c@example.com",
        "Reply-To: c@example.com",
        "X-Mailer: m\nFrom: a@example.com",
        "from: a@example.com\nto: b@example.com\nsubject: t",
        "FROM: a@example.com\nTO: b@example.com\nSUBJECT: t",
        " From: a@example.com\nTo: b@example.com",
        "\nFrom: a@example.com\nTo: b@example.com",
        "a note\nFrom: a@example.com\nTo: b@example.com",
    ] {
        let text = header_only_mail(first);
        for (mode, opts) in [
            ("default", ScanOptions::default()),
            ("compat", ScanOptions::clamav_compat()),
        ] {
            assert_eq!(
                found_with(&text, PAYLOAD, &opts),
                None,
                "{first:?}: clamscan types it as text, so {mode} must not decode it"
            );
        }
    }
}

/// bytes with no `60 EA` in them, so that the only ARJ header is the one placed.
fn junk(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 37 % 251) as u8 | 1).collect()
}

/// clamscan finds an ARJ archive wherever it sits in a file, behind binary
/// data, text, an ELF, a PE, or in the bytes of a ZIP member (measured at
/// offsets from 1 byte to 1 MB). Both modes do, and a `60 EA` that is not a
/// main header (its CRC-32 does not hold) costs nothing: it is not one more
/// candidate toward the cap.
#[test]
fn an_arj_stapled_behind_a_file_is_found_by_both_modes() {
    let arj = fixture("sample.arj");
    let member = b"INNER-ARJ-PAYLOAD-12345";
    open_under_both(
        "ARJ behind binary data",
        &[&junk(128)[..], &arj].concat(),
        member,
    );
    open_under_both("ARJ behind text", &carrier(&arj), member);
    open_under_both("ARJ behind an ELF", &[tiny_elf(), &arj].concat(), member);
    open_under_both("ARJ behind a PE", &[tiny_pe(), &arj].concat(), member);
    open_under_both(
        "ARJ in a ZIP member",
        &zip_of(&[&junk(64)[..], &arj].concat()),
        member,
    );
    let mut strays = junk(8000);
    for at in (0..strays.len() - 4).step_by(60) {
        // A size a header could have, and the file type of a main header.
        strays[at..at + 4].copy_from_slice(&[0x60, 0xEA, 0x2A, 0x00]);
        strays[at + 10] = 2;
    }
    for opts in [ScanOptions::default(), ScanOptions::clamav_compat()] {
        assert_eq!(verdict(&strays, member, &opts), Verdict::Clean);
    }
}

/// A multipart message whose second part holds `PAYLOAD` in base64, after the
/// header lines `block`, which must end with a `Content-Type:` that names the
/// boundary `BB`.
fn message(block: &str) -> Vec<u8> {
    use base64::Engine as _;
    format!(
        "{block}\n--BB\nContent-Type: text/plain\n\nhi\n--BB\n\
         Content-Type: application/octet-stream\nContent-Transfer-Encoding: base64\n\n{}\n--BB--\n",
        base64::engine::general_purpose::STANDARD.encode(PAYLOAD)
    )
    .into_bytes()
}

const MULTIPART: &str = "Content-Type: multipart/mixed; boundary=\"BB\"\n";

/// `n` bytes of one line of text, ending with a line feed.
fn text_of(n: usize) -> Vec<u8> {
    [vec![b'y'; n - 1], b"\n".to_vec()].concat()
}

/// Both modes find the attachment, and neither is found by looking at the
/// file as text.
fn opened_as_a_message(what: &str, file: &[u8]) {
    open_under_both(what, file, PAYLOAD);
}

fn clean_under_both(what: &str, file: &[u8]) {
    for (mode, opts) in [
        ("default", ScanOptions::default()),
        ("compat", ScanOptions::clamav_compat()),
    ] {
        assert_eq!(
            verdict(file, PAYLOAD, &opts),
            Verdict::Clean,
            "{what}: clamscan reads no message here, so {mode} must not"
        );
    }
}

/// A message is a message before it is a page: clamscan opens one whose first
/// part is HTML, however its headers begin (the first line is not one of the
/// ones that type a file at once). Both modes do.
#[test]
fn a_message_with_an_html_part_is_opened_whatever_its_first_header() {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(PAYLOAD);
    // A run of headers that puts the MIME ones past the first kilobyte.
    let long = format!(
        "X-Mozilla-Status: 0001\n{}",
        "X-Pad: yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy\n".repeat(60)
    );
    for first in [
        "Cc: a@example.com\n",
        "X-Mozilla-Status: 0001\n",
        "from: a@example.com\n",
        "MIME-Version: 1.0\n",
        "X-Foo: bar\nSubject: x\n",
        &long,
    ] {
        let mime = if first.starts_with("MIME-Version") {
            ""
        } else {
            "MIME-Version: 1.0\n"
        };
        let m = format!(
            "{first}{mime}Content-Type: multipart/related; boundary=\"BB\"\n\n--BB\n\
             Content-Type: text/html\n\n<html><body>hi</body></html>\n--BB\n\
             Content-Type: application/octet-stream\nContent-Transfer-Encoding: base64\n\n\
             {b64}\n--BB--\n"
        );
        opened_as_a_message(first, m.as_bytes());
    }
}

/// clamscan reads a text file, or binary data, as a message from inside it
/// when two header lines of one are close enough (`MIME-Version:` then
/// `Content-Type:`, `From:` then `Content-Type:`, and a few more pairs), wherever
/// they are in it and whatever comes before. Both modes do.
#[test]
fn a_message_inside_a_text_file_is_opened_as_clamscan_opens_it() {
    let mv = message(&format!("MIME-Version: 1.0\n{MULTIPART}"));
    let from = message(&format!(
        "From: a@example.com\nMIME-Version: 1.0\n{MULTIPART}"
    ));
    let note = b"This is a note.\nSome lines.\n\n".to_vec();
    opened_as_a_message("text, then a message", &[&note[..], &from].concat());
    opened_as_a_message(
        "junk, then a message",
        &[&junk(300)[..], b"\n", &from].concat(),
    );
    opened_as_a_message(
        "a page, then a message",
        &[&b"<html><body>hi</body></html>\n"[..], &from].concat(),
    );
    opened_as_a_message(
        "a script, then a message",
        &[&b"#!/bin/sh\necho hi\n"[..], &from].concat(),
    );
    // `MIME-Version:` and `Content-Type:` at any offset.
    for off in [100, 1100, 100_000, 3 << 20] {
        opened_as_a_message(&format!("{off}"), &[&text_of(off)[..], &mv].concat());
    }
    // The headers above the pair belong to the message: a `Content-Type:` ahead of
    // `MIME-Version:`, as Outlook writes it, names the boundary.
    let outlook = message(&format!(
        "To: b@example.com\n{MULTIPART}MIME-Version: 1.0\n"
    ));
    opened_as_a_message("Content-Type first", &[&note[..], &outlook].concat());
    // The other pairs, near the start.
    for pair in [
        format!("Received: from x by y\n{MULTIPART}"),
        format!("From: a@example.com\n{MULTIPART}"),
        format!("Message-Id: <1@example.com>\n{MULTIPART}"),
        format!("message-id: <1@example.com>\n{MULTIPART}"),
    ] {
        opened_as_a_message(&pair, &[&text_of(400)[..], &message(&pair)].concat());
    }
    // A uuencoded file in the body is decoded too.
    let uu = format!(
        "From: a@example.com\nMIME-Version: 1.0\nContent-Type: text/plain\n\n{}",
        uuencode("payload.bin", PAYLOAD)
    );
    opened_as_a_message("uuencoded", &[&note[..], uu.as_bytes()].concat());
    // Inside a ZIP member, and inside the body of a message.
    opened_as_a_message("in a ZIP member", &zip_of(&[&note[..], &from].concat()));
    let outer = format!(
        "From: o@example.com\nMIME-Version: 1.0\nContent-Type: text/plain\n\nsee below\n\n{}",
        String::from_utf8(from).unwrap()
    );
    opened_as_a_message("in the body of a message", outer.as_bytes());
}

/// What clamscan does not read as a message is not read as one: a file of a
/// type of its own, a pair too far from the start of the file or too far
/// apart, a name in another case, a page with the pair past its first 1024
/// bytes. The same bytes would be found were they read.
#[test]
fn what_clamscan_does_not_read_as_a_message_is_not() {
    let mv = message(&format!("MIME-Version: 1.0\n{MULTIPART}"));
    let from_only = message(&format!("From: a@example.com\n{MULTIPART}"));
    // Files of a type of their own.
    for (what, head) in [
        ("a PE", tiny_pe().to_vec()),
        ("an ELF", tiny_elf().to_vec()),
        (
            "a PDF",
            b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n".to_vec(),
        ),
        (
            "a PNG",
            b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\0\x01\0\0\0\x01\x08\x02\0\0\0".to_vec(),
        ),
        (
            "a JPEG",
            b"\xff\xd8\xff\xe0\0\x10JFIF\0\x01\x01\0\0\x01\0\x01\0\0".to_vec(),
        ),
        ("an RTF", b"{\\rtf1\\ansi hello}\n".to_vec()),
    ] {
        clean_under_both(what, &[&head[..], b"\n", &mv].concat());
    }
    // Too far from the start for a pair that is not `MIME-Version:`.
    clean_under_both(
        "From: and Content-Type: at 3000",
        &[&text_of(3000)[..], &from_only].concat(),
    );
    // Too far apart: `Content-Type:` 1200 bytes after `MIME-Version:`, which is
    // far from the start.
    let apart = message(&format!(
        "MIME-Version: 1.0\nX-Pad: {}\n{MULTIPART}",
        "y".repeat(1200)
    ));
    clean_under_both(
        "pair 1200 bytes apart",
        &[&text_of(5000)[..], &apart].concat(),
    );
    // The wrong case, no `MIME-Version:` at all, a name that is not at the start
    // of its line.
    for (what, block) in [
        (
            "capitals",
            format!("MIME-VERSION: 1.0\n{}", MULTIPART.to_uppercase()),
        ),
        ("no MIME-Version", format!("{MULTIPART}X-Pad: y\n")),
        (
            "no space after the colon",
            format!("MIME-Version:1.0\n{MULTIPART}"),
        ),
        ("indented", format!(" MIME-Version: 1.0\n {MULTIPART}")),
    ] {
        clean_under_both(what, &[&text_of(5000)[..], &message(&block)].concat());
    }
    // A page is looked into only where clamscan types it.
    let page = b"<html><body>hi</body></html>\n";
    clean_under_both(
        "a page with the message after 1500 bytes",
        &[&page[..], &text_of(1500), &mv].concat(),
    );
    open_under_both(
        "a page with the message at its start",
        &[&page[..], &mv].concat(),
        PAYLOAD,
    );
}

/// A text holding the headers of a message and none of its parts (a template
/// in a script, an example in a page) is read as a message, and all of it is
/// scanned: the multipart it names and does not hold is not reported. A file
/// that is a message still reports it.
#[test]
fn the_headers_of_a_message_inside_a_text_are_not_reported_as_unread() {
    for (what, file) in [
        (
            "a page",
            "# Sending mail\n\nSet these headers:\n\nMIME-Version: 1.0\n\
             Content-Type: multipart/mixed; boundary=\"frontier\"\n\n\
             Then add the parts in code.\n",
        ),
        (
            "a script",
            "import smtplib\n\nHEAD = \"\"\"\\\nFrom: {sender}\nMIME-Version: 1.0\n\
             Content-Type: multipart/alternative; boundary=\"{b}\"\n\n\"\"\"\n\n\
             def send(s, parts):\n    smtplib.SMTP(\"localhost\").sendmail(s, [s], HEAD)\n",
        ),
    ] {
        for (mode, opts) in [
            ("default", ScanOptions::default()),
            ("compat", ScanOptions::clamav_compat()),
        ] {
            assert_eq!(
                verdict(file.as_bytes(), PAYLOAD, &opts),
                Verdict::Clean,
                "{what}, {mode}: every byte of it was scanned"
            );
        }
    }
    let message = b"From: a@example.com\nMIME-Version: 1.0\n\
                    Content-Type: multipart/mixed; boundary=\"BB\"\n\nno parts here\n";
    let v = verdict(message, PAYLOAD, &ScanOptions::default());
    assert!(matches!(v, Verdict::Unscannable { .. }), "{v:?}");
}

/// clamscan opens an ARJ archive whose main header or file header CRC-32 is
/// stale, going by the shape of the headers. At the start of a file, so do both
/// modes. An archive carved out of another file keeps the CRC of its main
/// header to confirm it, so one with a stale CRC behind other bytes is not
/// opened.
#[test]
fn an_arj_with_a_stale_header_crc_is_opened_at_the_start_of_a_file() {
    let arj = fixture("sample.arj");
    let member = b"INNER-ARJ-PAYLOAD-12345";
    let le16 = |at: usize| usize::from(u16::from_le_bytes([arj[at + 2], arj[at + 3]]));
    // The CRC-32 after the main header, and after the first file header, which
    // follows it and the 2 bytes that say there are no extended headers.
    let main = 4 + le16(0);
    let file = main + 4 + 2;
    open_under_both("intact", &arj, member);
    for (what, at) in [("main", main), ("file", file + 4 + le16(file))] {
        let mut stale = arj.clone();
        stale[at] ^= 0xFF;
        open_under_both(&format!("{what} header CRC"), &stale, member);
        let mut zero = arj.clone();
        zero[at..at + 4].fill(0);
        open_under_both(&format!("{what} header CRC of zero"), &zero, member);
    }
    let mut stale = arj.clone();
    stale[main] ^= 0xFF;
    for (mode, opts) in [
        ("default", ScanOptions::default()),
        ("compat", ScanOptions::clamav_compat()),
    ] {
        assert_eq!(
            found_with(&carrier(&stale), member, &opts),
            None,
            "a stale one behind text is not carved ({mode})"
        );
    }
    open_under_both("carved, intact", &carrier(&arj), member);
}
