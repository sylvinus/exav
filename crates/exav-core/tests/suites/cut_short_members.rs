//! A member whose stream is cut short, or damaged part way, has the bytes
//! decoded before the cut or the damage scanned: EICAR in them is FOUND.
//! A member cut by the end of the file hides nothing (its rest is absent), so
//! a clean prefix is OK; damage with bytes after it leaves those bytes
//! unread, so it is never OK.
//!
//! Fixtures: `exav-unpack/tests/fixtures/cut_short/` (`make.py` and
//! `make_udif.py` there say which tool wrote each). Where a test says what an
//! oracle recovers, that is 7-Zip 25.01 (`7z x`) or Python 3.13's `zlib` /
//! `bz2` / `lzma` decoding the same cut or damaged bytes, fed 16 bytes at a
//! time so the output before an error is kept. The containers built here
//! (ALZ, EGG, HWP3, XAR) are laid out by hand; their deflate streams are
//! flate2's.

use std::io::{Read, Write};

use exav_core::{analyze, ScanOptions, Scanner, Verdict};

#[derive(Clone, Copy, Debug)]
enum Want {
    Found,
    Clean,
    /// Not OK: EICAR found, or the member reported not fully scanned.
    NotClean,
}
use Want::*;

fn fixture(name: &str) -> Vec<u8> {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../exav-unpack/tests/fixtures/cut_short/"
    );
    let gz = exav_core::unpack::read_fixture(&format!("{p}{name}.gz"))
        .unwrap_or_else(|e| panic!("{name}: {e}"));
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(&gz[..])
        .read_to_end(&mut out)
        .unwrap();
    out
}

fn u32_le(d: &[u8], at: usize) -> usize {
    u32::from_le_bytes(d[at..at + 4].try_into().unwrap()) as usize
}

/// `data` cut `pct`% of the way through `region`.
fn cut(data: &[u8], region: (usize, usize), pct: usize) -> Vec<u8> {
    data[..region.0 + (region.1 - region.0) * pct / 100].to_vec()
}

/// `data` with 256 bytes of 0xFF `pct`% of the way through `region`.
fn dmg(data: &[u8], region: (usize, usize), pct: usize) -> Vec<u8> {
    let at = region.0 + (region.1 - region.0) * pct / 100;
    let mut d = data.to_vec();
    d[at..at + 256].fill(0xFF);
    d
}

/// Scan each `(label, input, want)` and fail with every one that is wrong.
fn run(cases: impl IntoIterator<Item = (String, Vec<u8>, Want)>) {
    let db = Scanner::builtin();
    let mut wrong = Vec::new();
    for (label, data, want) in cases {
        let v = analyze(&db, &data, &ScanOptions::default()).verdict;
        let found = matches!(&v, Verdict::Infected { signature, .. }
            if signature.to_ascii_uppercase().contains("EICAR"));
        let ok = match want {
            Found => found,
            Clean => v == Verdict::Clean,
            NotClean => found || matches!(v, Verdict::Unscannable { .. }),
        };
        if !ok {
            wrong.push(format!("{label}: want {want:?}, got {v:?}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// 7z members of LZMA, LZMA2, Deflate and BCJ2 (+ LZMA), EICAR in the
/// middle, the packed streams damaged 40% and 60% in. 7-Zip recovers EICAR
/// from every copy damaged at 60%, and at 40% from the Deflate one only (it
/// decodes on past the damage); every copy is a Data Error. A 7z cut short
/// has lost its header, which sits at the end, so there is no cut case.
#[test]
fn a_7z_member_damaged_part_way_is_scanned_up_to_the_damage() {
    run(["lzma", "lzma2", "deflate", "bcj2"]
        .into_iter()
        .flat_map(|codec| {
            let d = fixture(&format!("7z_{codec}.7z"));
            // The packed streams, from the end of the 32-byte start header to
            // the next header.
            let packed = (32, 32 + u32_le(&d, 12));
            [
                (format!("{codec} 40%"), dmg(&d, packed, 40), NotClean),
                (format!("{codec} 60%"), dmg(&d, packed, 60), Found),
            ]
        }));
}

/// SWF movies (CWS zlib, ZWS LZMA), EICAR 85% into the body. Python's zlib
/// and liblzma recover EICAR from the copies cut 92% in and damaged 92% in,
/// and not from those cut 25% in or damaged 70% in (an error for both).
#[test]
fn an_swf_body_cut_short_or_damaged_is_scanned_as_far_as_it_goes() {
    run([("swf_cws.swf", 8), ("swf_zws.swf", 17)]
        .into_iter()
        .flat_map(|(name, body_at)| {
            let d = fixture(name);
            let body = (body_at, d.len());
            [
                (format!("{name} cut 25%"), cut(&d, body, 25), Clean),
                (format!("{name} cut 92%"), cut(&d, body, 92), Found),
                (format!("{name} damaged 70%"), dmg(&d, body, 70), NotClean),
                (format!("{name} damaged 92%"), dmg(&d, body, 92), Found),
            ]
        }));
}

/// makensis installers, solid LZMA and non-solid zlib, the installed file
/// EICAR 80% in. Cut 25% / 92% through the data after the firstheader:
/// 7-Zip recovers 3129 bytes without EICAR / EICAR from the solid one, and
/// Python's lzma and zlib decoding the file's stream agree for both
/// installers. Damaged 70% / 92% in, the solid stream fails in liblzma before
/// / after EICAR. (0xFF bytes in the zlib one end its stream quietly in zlib
/// too, so it has no damage case here.)
#[test]
fn an_nsis_installer_cut_short_or_damaged_is_scanned_as_far_as_it_goes() {
    let mut cases = Vec::new();
    for name in ["nsis_solid_lzma.exe", "nsis_zlib.exe"] {
        let d = fixture(name);
        let sig = d.windows(12).position(|w| w == b"NullsoftInst").unwrap();
        // The firstheader starts 8 bytes before its "NullsoftInst" and is 28
        // bytes long.
        let data = (sig - 8 + 28, d.len());
        cases.push((format!("{name} cut 25%"), cut(&d, data, 25), Clean));
        cases.push((format!("{name} cut 92%"), cut(&d, data, 92), Found));
        if name == "nsis_solid_lzma.exe" {
            cases.push((format!("{name} damaged 70%"), dmg(&d, data, 70), NotClean));
            cases.push((format!("{name} damaged 92%"), dmg(&d, data, 92), Found));
        }
    }
    run(cases);
}

/// A UPX-packed ELF (LZMA), EICAR in the middle of the block that holds the
/// program's data. Python's liblzma decoding that block recovers EICAR when
/// it is cut 60% in or damaged 60% in (an error), not when cut 25% in or
/// damaged 30% in (an error).
#[test]
fn a_upx_block_cut_short_or_damaged_is_scanned_as_far_as_it_goes() {
    let d = fixture("upx_lzma.elf");
    // l_info is 4 bytes before "UPX!", p_info follows it, then the chain of
    // b_info (sizes at 0 and 4) each followed by its compressed bytes.
    let first = d.windows(4).position(|w| w == b"UPX!").unwrap() - 4 + 24;
    let second = first + 12 + u32_le(&d, first + 4);
    let block = (second + 12, second + 12 + u32_le(&d, second + 4));
    run([
        ("cut 25%".into(), cut(&d, block, 25), Clean),
        ("cut 60%".into(), cut(&d, block, 60), Found),
        ("dmg30%".into(), dmg(&d, block, 30), NotClean),
        ("dmg60%".into(), dmg(&d, block, 60), Found),
    ]);
}

/// A qcow2 image of compressed 4 KiB clusters, EICAR near the end of the
/// fifth. That cluster's deflate stream is bytes 32987..36138 of the file
/// (its L2 entry, and where Python's zlib finds the stream ends). Cut 30% /
/// 97% through it, zlib recovers 1195 bytes without EICAR / 3973 with it;
/// the clusters after it are past the end of the file.
#[test]
fn a_qcow2_cluster_cut_short_is_scanned_as_far_as_it_goes() {
    let d = fixture("disk.qcow2");
    let cluster = (32987, 36138);
    run([
        ("cut 30%".into(), cut(&d, cluster, 30), Clean),
        ("cut 97%".into(), cut(&d, cluster, 97), Found),
    ]);
}

/// A streamOptimized VMDK of one 64 KiB grain, EICAR in the middle. Python's
/// zlib recovers EICAR from the grain cut or damaged 60% in, and not 25% in
/// (the damage is an error for both).
#[test]
fn a_vmdk_grain_cut_short_or_damaged_is_scanned_as_far_as_it_goes() {
    let d = fixture("disk.vmdk");
    // The grain's 12-byte marker is at the header's overhead (sectors, at 64).
    let at = u32_le(&d, 64) * 512;
    let grain = (at + 12, at + 12 + u32_le(&d, at + 8));
    run([
        ("cut 25%".into(), cut(&d, grain, 25), Clean),
        ("cut 60%".into(), cut(&d, grain, 60), Found),
        ("dmg25%".into(), dmg(&d, grain, 25), NotClean),
        ("dmg60%".into(), dmg(&d, grain, 60), Found),
    ]);
}

/// UDIF images (`make_udif.py`) of an HFS+ disk in one zlib, bzip2 or xz
/// run, EICAR 75% into the disk in the volume's one file. Damaged 90% into
/// the run, each codec's Python decoder fails after EICAR; damaged 30% in,
/// before it. zlib decodes on past that damage to near the end of the disk,
/// to bytes that are not the disk's: the file reads whole, and wrong.
#[test]
fn a_dmg_run_damaged_part_way_is_scanned_up_to_the_damage() {
    let mut cases = Vec::new();
    for codec in ["zlib", "bzip2", "xz"] {
        let d = fixture(&format!("udif_{codec}.dmg"));
        // The run is the data fork after 512 unused bytes, up to the plist
        // (koly XMLOffset).
        let koly = d.len() - 512;
        let xml = u64::from_be_bytes(d[koly + 216..koly + 224].try_into().unwrap());
        let run = (512, xml as usize);
        cases.push((format!("{codec} whole"), d.clone(), Found));
        cases.push((format!("{codec} damaged 30%"), dmg(&d, run, 30), NotClean));
        cases.push((format!("{codec} damaged 90%"), dmg(&d, run, 90), Found));
    }
    run(cases);
}

/// UDIF images (`make_udif.py`) whose data fork opens with a bzip2 or an xz
/// run, as hdiutil writes UDBZ and ULMO images, EICAR in a zlib run after it.
/// Read as a bare bzip2 or xz stream from its first bytes, the file never
/// reaches EICAR; walked as the disk image its `koly` trailer says it is, it
/// does. Nothing is damaged here.
#[test]
fn a_dmg_opening_with_a_bzip2_or_xz_run_is_walked_as_a_dmg() {
    run(["bzip2", "xz"].into_iter().map(|codec| {
        let d = fixture(&format!("udif_{codec}_first.dmg"));
        (format!("{codec} first"), d, Found)
    }));
}

/// An .xz stream of text with EICAR in the middle, alone and as a ZIP member
/// (method 95): exav-unpack's `zip/cut_xz.zip`, written by 7-Zip 25.01.
/// Damaged 60% to 76% in, Python's liblzma fed 16 bytes at a time fails
/// 4 to 8 KiB of output after EICAR; damaged 40% in, before it.
#[test]
fn a_damaged_xz_stream_is_scanned_up_to_the_damage() {
    let zip = exav_core::unpack::read_fixture(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../exav-unpack/tests/fixtures/zip/cut_xz.zip"
    ))
    .unwrap();
    let u16_at = |o: usize| usize::from(u16::from_le_bytes([zip[o], zip[o + 1]]));
    let start = 30 + u16_at(26) + u16_at(28);
    let member = (start, start + u32_le(&zip, 18));
    let xz = zip[member.0..member.1].to_vec();
    let mut cases = Vec::new();
    for (pct, want) in [
        (40, NotClean),
        (60, Found),
        (66, Found),
        (70, Found),
        (76, Found),
    ] {
        let alone = dmg(&xz, (0, xz.len()), pct);
        cases.push((format!("xz damaged {pct}%"), alone, want));
        let in_zip = dmg(&zip, member, pct);
        cases.push((format!("zip xz member damaged {pct}%"), in_zip, want));
    }
    run(cases);
}

/// Text of base64-alphabet noise with EICAR `at` bytes in: compressed
/// offsets track plain ones.
fn text(len: usize, at: usize) -> Vec<u8> {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    let mut t: Vec<u8> = (0..len)
        .map(|i| {
            if i % 77 == 76 {
                return b'\n';
            }
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            ALPHA[(x >> 58) as usize]
        })
        .collect();
    let eicar = exav_core::unpack::eicar();
    t[at..at + eicar.len()].copy_from_slice(eicar);
    t
}

/// A stored block whose length check fails: a decoder stops there, with the
/// rest of the stream still after it.
const BAD_STORED_BLOCK: [u8; 5] = [0x00, 0x05, 0x00, 0x00, 0x00];

/// Raw deflate (`zlib` false) or zlib of `text`. With `break_at`, the stream
/// is flushed to a byte boundary at that offset, and [`BAD_STORED_BLOCK`]
/// written there, before the rest.
fn deflate(text: &[u8], zlib: bool, break_at: Option<usize>) -> Vec<u8> {
    let mut w = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    let at = break_at.unwrap_or(text.len());
    w.write_all(&text[..at]).unwrap();
    // A sync flush: everything so far, ending on a byte boundary.
    w.flush().unwrap();
    let head = w.get_ref().len();
    w.write_all(&text[at..]).unwrap();
    let mut raw = w.finish().unwrap();
    if break_at.is_some() {
        raw.splice(head..head, BAD_STORED_BLOCK);
    }
    if !zlib {
        return raw;
    }
    // RFC 1950: header, deflate data, Adler-32 of the text.
    let (mut a, mut b) = (1u32, 0u32);
    for &x in text {
        a = (a + u32::from(x)) % 65521;
        b = (b + a) % 65521;
    }
    let mut z = vec![0x78, 0x9C];
    z.extend_from_slice(&raw);
    z.extend_from_slice(&((b << 16) | a).to_be_bytes());
    z
}

/// What each hand-built container is asked to hold.
struct Built {
    /// The container, with its one member's stream.
    file: Vec<u8>,
    /// Where that stream is in it.
    stream: (usize, usize),
}

fn crc32(d: &[u8]) -> u32 {
    let mut c = flate2::Crc::new();
    c.update(d);
    c.sum()
}

/// An ALZ archive of one deflated member, then the central directory mark.
fn alz(text: &[u8], stream: &[u8]) -> Built {
    let mut f = b"ALZ\x01\x0a\x00\x00\x00".to_vec();
    let name = b"payload.txt";
    f.extend_from_slice(b"BLZ\x01");
    f.extend_from_slice(&(name.len() as u16).to_le_bytes());
    f.push(0x20); // attributes
    f.extend_from_slice(&[0; 4]); // DOS time
    f.push(0x40); // descriptor: 4-byte sizes
    f.push(0);
    f.push(2); // deflate
    f.push(0);
    f.extend_from_slice(&crc32(text).to_le_bytes());
    f.extend_from_slice(&(stream.len() as u32).to_le_bytes());
    f.extend_from_slice(&(text.len() as u32).to_le_bytes());
    f.extend_from_slice(name);
    let at = f.len();
    f.extend_from_slice(stream);
    let end = f.len();
    f.extend_from_slice(b"CLZ\x01");
    Built {
        file: f,
        stream: (at, end),
    }
}

/// An EGG archive (EGG Format Specification 1.0) of one file in one deflate
/// block.
fn egg(text: &[u8], stream: &[u8]) -> Built {
    egg_block(1, text, stream, crc32(text))
}

/// An EGG archive of one file in one block of `method` (0 stored, 1
/// deflate), recording `crc`.
fn egg_block(method: u8, text: &[u8], stream: &[u8], crc: u32) -> Built {
    const END: [u8; 4] = 0x08E2_8222u32.to_le_bytes();
    let mut f = b"EGGA".to_vec();
    f.extend_from_slice(&0x0100u16.to_le_bytes());
    f.extend_from_slice(&0x1234_5678u32.to_le_bytes());
    f.extend_from_slice(&0u32.to_le_bytes());
    f.extend_from_slice(&END);
    f.extend_from_slice(&0x0A85_90E3u32.to_le_bytes()); // file header
    f.extend_from_slice(&0u32.to_le_bytes());
    f.extend_from_slice(&(text.len() as u64).to_le_bytes());
    let name = b"payload.txt";
    f.extend_from_slice(&0x0A85_91ACu32.to_le_bytes()); // file name field
    f.push(0);
    f.extend_from_slice(&(name.len() as u16).to_le_bytes());
    f.extend_from_slice(name);
    f.extend_from_slice(&END);
    f.extend_from_slice(&0x02B5_0C13u32.to_le_bytes()); // block header
    f.push(method);
    f.push(0);
    f.extend_from_slice(&(text.len() as u32).to_le_bytes());
    f.extend_from_slice(&(stream.len() as u32).to_le_bytes());
    f.extend_from_slice(&crc.to_le_bytes());
    f.extend_from_slice(&END);
    let at = f.len();
    f.extend_from_slice(stream);
    let end = f.len();
    f.extend_from_slice(&END);
    Built {
        file: f,
        stream: (at, end),
    }
}

/// An HWP 3.0 document whose compressed body is `stream`, which runs to the
/// end of the file.
fn hwp3(stream: &[u8]) -> Built {
    let mut f = b"HWP Document File V3.00 \x1a\x01\x02\x03\x04\x05".to_vec();
    // Password at 126, compressed flag at 154, info block length at 156,
    // then the 1008-byte summary and the (empty) info block.
    f.resize(126 + 2 + 26, 0);
    f.push(1);
    f.push(0);
    f.extend_from_slice(&0u16.to_le_bytes());
    f.resize(f.len() + 1008, 0);
    let at = f.len();
    f.extend_from_slice(stream);
    Built {
        stream: (at, f.len()),
        file: f,
    }
}

/// A XAR archive of one zlib-encoded file, the heap last.
fn xar(text: &[u8], stream: &[u8]) -> Built {
    let toc = format!(
        "<xar><toc><file><name>payload.txt</name><data><offset>0</offset>\
         <length>{}</length><size>{}</size>\
         <encoding style=\"application/x-gzip\"/></data></file></toc></xar>",
        stream.len(),
        text.len()
    );
    let toc_z = deflate(toc.as_bytes(), true, None);
    let mut f = b"xar!".to_vec();
    f.extend_from_slice(&28u16.to_be_bytes());
    f.extend_from_slice(&1u16.to_be_bytes());
    f.extend_from_slice(&(toc_z.len() as u64).to_be_bytes());
    f.extend_from_slice(&(toc.len() as u64).to_be_bytes());
    f.extend_from_slice(&0u32.to_be_bytes());
    f.extend_from_slice(&toc_z);
    let at = f.len();
    f.extend_from_slice(stream);
    Built {
        stream: (at, f.len()),
        file: f,
    }
}

/// ALZ, EGG, HWP3 and XAR, each holding one deflate or zlib stream of text
/// with EICAR 85% in: cut 25% / 92% through the stream, and broken by an
/// invalid stored block 60% / 90% of the way through the text (before /
/// after EICAR), with the rest of the stream after it.
#[test]
fn a_deflated_member_cut_short_or_damaged_is_scanned_as_far_as_it_goes() {
    let t = text(40_000, 34_000);
    type Make = fn(&[u8], &[u8]) -> Built;
    let formats: [(&str, bool, Make); 4] = [
        ("alz", false, alz),
        ("egg", false, egg),
        ("hwp3", true, |_, s| hwp3(s)),
        ("xar", true, xar),
    ];
    let mut cases = Vec::new();
    for (name, zlib, make) in formats {
        let whole = make(&t, &deflate(&t, zlib, None));
        let s = whole.stream;
        cases.push((format!("{name} cut 25%"), cut(&whole.file, s, 25), Clean));
        cases.push((format!("{name} cut 92%"), cut(&whole.file, s, 92), Found));
        for (pct, want) in [(60, NotClean), (90, Found)] {
            let broken = make(&t, &deflate(&t, zlib, Some(t.len() * pct / 100)));
            cases.push((format!("{name} broken {pct}%"), broken.file, want));
        }
    }
    run(cases);
}

/// An EGG block that decodes in full and then fails its CRC-32 hides
/// nothing: its bytes are scanned, as a ZIP member's are
/// (`salvage::a_bad_checksum_after_a_full_decode_is_clean`). Stored and
/// deflate blocks recording a CRC-32 off by one bit: FOUND with EICAR in the
/// text, OK without.
#[test]
fn an_egg_block_failing_its_crc_after_a_full_decode_is_scanned() {
    let with = text(4000, 2000);
    let mut without = with.clone();
    without[2000..2000 + exav_core::unpack::eicar().len()].fill(b'B');
    let mut cases = Vec::new();
    for (label, t, want) in [("EICAR", &with, Found), ("clean", &without, Clean)] {
        let bad = crc32(t) ^ 1;
        let stored = egg_block(0, t, t, bad).file;
        let deflated = egg_block(1, t, &deflate(t, false, None), bad).file;
        cases.push((format!("stored, {label}"), stored, want));
        cases.push((format!("deflate, {label}"), deflated, want));
    }
    run(cases);
}
