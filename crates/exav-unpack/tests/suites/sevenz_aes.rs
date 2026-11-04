//! Encrypted 7z folders are decrypted and decoded as they are read, from their
//! place in the archive, whatever the coders behind the cipher, and a folder
//! far past the buffer limit is read the same way as a small one. The
//! password is the first that decodes the first member of the folder to the
//! CRC the header gives it.
//!
//! The fixtures were written by 7-Zip 25.01 with the password `hunter2`, and
//! the CRCs below are those of `7z l -slt`:
//!
//! * `aes_big.7z`: `7z a -m0=LZMA2:d=64k -mx=9 -mhe=off -phunter2 a/big.txt`, 8
//!   MiB of one 64-byte line, `-mhe=on` for `aes_big_mhe.7z`.
//! * `aes_bcj2.7z`: `7z a -mf=BCJ2 -md=64k -mx=9 -mhe=off -phunter2 c/code.bin`,
//!   1 MiB of x86-like code (eight calls to one address in every 4 KiB), which
//!   7-Zip folds into a BCJ2 folder with one AES coder on each of its four
//!   packed streams.
//! * `aes_solid_crc.7z`: `7z a -m0=LZMA2:d=64k -mx=9 -ms=on -mhc=off -mhe=off
//!   -phunter2` of three files; the header is not compressed, so a CRC in it
//!   can be changed.
//! * `aes_copy_eicar.7z`: `7z a -m0=Copy -ms=on -mhc=off -mhe=off -phunter2`
//!   of `a.txt`, `eicar.com` (the EICAR string) and `c.txt`; 7-Zip makes a
//!   folder of each, AES and then Copy.

use exav_unpack::source::BlockCache;
use exav_unpack::{Budget, Format, Limits, Member, walk};
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::rc::Rc;

fn fixture(name: &str) -> Vec<u8> {
    let p = format!("{}/tests/fixtures/7z/{name}", env!("CARGO_MANIFEST_DIR"));
    exav_unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

fn crc(data: &[u8]) -> u32 {
    let mut c = flate2::Crc::new();
    c.update(data);
    c.sum()
}

/// What the walk gave for a member.
struct Got {
    name: String,
    data: Vec<u8>,
    /// How the read of a streamed member ended, when it was an error.
    failed: Option<std::io::ErrorKind>,
    /// The error left content undecoded or is a key's (not a checksum that
    /// failed after a full decode).
    hides_content: bool,
    streamed: bool,
    encrypted: bool,
    unsupported: Option<&'static str>,
}

impl std::fmt::Debug for Got {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: {} bytes, failed {:?}, encrypted {}, {:?}",
            self.name,
            self.data.len(),
            self.failed,
            self.encrypted,
            self.unsupported
        )
    }
}

fn limits(max_buffer_bytes: u64) -> Limits {
    let mut l = Limits::default();
    l.max_buffer_bytes = max_buffer_bytes;
    l
}

/// Every member of the archive in `src`, each streamed one read to its end.
fn walked(
    src: &dyn exav_unpack::source::ByteSource,
    words: &[&str],
    max_buffer_bytes: u64,
) -> Vec<Got> {
    try_walk(src, words, limits(max_buffer_bytes)).unwrap()
}

/// [`walked`] under `limits`, and how the walk ended.
fn try_walk(
    src: &dyn exav_unpack::source::ByteSource,
    words: &[&str],
    limits: Limits,
) -> Result<Vec<Got>, exav_unpack::LimitHit> {
    let words = words.iter().map(|w| w.to_string()).collect();
    let mut budget = Budget::with_passwords(limits, words);
    let mut out = Vec::new();
    walk(
        Format::SevenZip,
        src,
        &mut budget,
        &mut |meta, content, _| {
            let (data, error, streamed) = match content {
                None => (Vec::new(), None, false),
                Some(Member::Bytes(b)) => (b, None, false),
                Some(Member::Stream(r)) => {
                    let mut b = Vec::new();
                    let error = r.read_to_end(&mut b).err();
                    (b, error, true)
                }
                #[allow(unreachable_patterns)]
                Some(_) => (Vec::new(), None, false),
            };
            out.push(Got {
                name: meta.name.clone(),
                data,
                failed: error.as_ref().map(|e| e.kind()),
                hides_content: error
                    .as_ref()
                    .is_some_and(exav_unpack::decode_error_hides_content),
                streamed,
                encrypted: meta.encrypted,
                unsupported: meta.unsupported,
            });
            None::<()>
        },
    )?;
    Ok(out)
}

const BIG_CRC: u32 = 0xF61B_5D4B;
const BIG_SIZE: usize = 8 * 1024 * 1024;
const CODE_CRC: u32 = 0xD86F_4D8A;
const CODE_SIZE: usize = 1024 * 1024;

/// A member of 8 MiB (and 1 MiB) is far past a buffer limit of 64 KiB: it is
/// decrypted and decoded as it is read, the header encrypted or not, and the
/// bytes are the ones 7-Zip packed.
#[test]
fn an_encrypted_member_far_past_the_buffer_limit_is_read_as_it_is_decrypted() {
    let line = b"line of text repeated to make a member far past a small limit..\n";
    for name in ["aes_big.7z", "aes_big_mhe.7z"] {
        let blob = fixture(name);
        let got = walked(&blob.as_slice(), &["hunter2"], 64 * 1024);
        assert_eq!(got.len(), 1, "{name}: {got:?}");
        let m = &got[0];
        assert!(m.name.ends_with("big.txt"), "{name}: {m:?}");
        assert!(m.streamed && m.encrypted, "{name}: {m:?}");
        assert!(
            m.unsupported.is_none() && m.failed.is_none(),
            "{name}: {m:?}"
        );
        assert_eq!(m.data.len(), BIG_SIZE, "{name}");
        assert_eq!(crc(&m.data), BIG_CRC, "{name}");
        assert!(m.data.chunks(64).all(|c| c == line), "{name}");
    }
}

/// 7-Zip puts an AES coder on each of the four packed streams of a BCJ2
/// folder; the graph is read as it is for a plain one.
#[test]
fn an_encrypted_bcj2_folder_is_read_as_it_is_decrypted() {
    let blob = fixture("aes_bcj2.7z");
    let got = walked(&blob.as_slice(), &["hunter2"], 64 * 1024);
    assert_eq!(got.len(), 1, "{got:?}");
    let m = &got[0];
    assert!(m.name.ends_with("code.bin"), "{m:?}");
    assert!(m.streamed && m.encrypted, "{m:?}");
    assert!(m.unsupported.is_none() && m.failed.is_none(), "{m:?}");
    assert_eq!(m.data.len(), CODE_SIZE);
    assert_eq!(crc(&m.data), CODE_CRC);
}

/// A password that does not open the folder, or none, is reported for every
/// member, with no bytes of it.
#[test]
fn a_wrong_or_missing_password_is_reported_for_every_member() {
    for name in [
        "aes_big.7z",
        "aes_big_mhe.7z",
        "aes_bcj2.7z",
        "aes_solid_crc.7z",
    ] {
        let blob = fixture(name);
        let got = walked(&blob.as_slice(), &["nope", "nor this"], 64 * 1024);
        assert!(!got.is_empty(), "{name}");
        for m in &got {
            assert!(m.encrypted && m.data.is_empty(), "{name}: {m:?}");
            // With an encrypted header the members are not listed: the whole
            // archive is the one that is reported.
            assert!(m.unsupported.is_some(), "{name}: {m:?}");
        }
        let none = walked(&blob.as_slice(), &[], 64 * 1024);
        assert!(
            none.iter().all(|m| m.encrypted && m.unsupported.is_some()),
            "{name}: {none:?}"
        );
    }
    let blob = fixture("aes_solid_crc.7z");
    let got = walked(&blob.as_slice(), &["nope"], 64 * 1024);
    assert_eq!(got.len(), 3);
    assert!(
        got.iter()
            .all(|m| m.unsupported == Some("7z: wrong or missing password"))
    );
}

const FIRST: &[u8] = b"first member, a line of text that repeats....................\n";
const SECOND: &[u8] = b"second member, another line of text which is a bit longer...\n";
const FIRST_CRC: u32 = 0x8A44_23E8;
const SECOND_CRC: u32 = 0x77E9_9A77;

/// The folder of three members is opened by the second password, and every
/// member comes out whole, past the first.
#[test]
fn the_password_that_opens_a_folder_is_found_among_others() {
    let blob = fixture("aes_solid_crc.7z");
    let got = walked(
        &blob.as_slice(),
        &["nope", "hunter2", "nor this"],
        64 * 1024,
    );
    assert_eq!(got.len(), 3, "{got:?}");
    assert!(got.iter().all(|m| m.encrypted && m.failed.is_none()));
    assert!(got[0].data == FIRST.repeat(64), "{:?}", got[0]);
    assert!(got[1].data == SECOND.repeat(10_000), "{:?}", got[1]);
    assert_eq!(got[2].data, b"the third member\n");
}

/// `blob` with a bit of a CRC changed: the last place its four bytes are
/// (the header is after the packed streams) in an archive of which the header
/// is not compressed.
fn with_crc_changed(blob: &[u8], crc: u32) -> Vec<u8> {
    let at = blob
        .windows(4)
        .rposition(|w| w == crc.to_le_bytes())
        .expect("the CRC is in the header");
    let mut d = blob.to_vec();
    d[at] ^= 1;
    d
}

/// The CRC of the first member is what tells the password: with it changed,
/// no password opens the folder, and none of its members is given.
#[test]
fn a_folder_whose_first_member_does_not_match_its_crc_is_not_opened() {
    let blob = with_crc_changed(&fixture("aes_solid_crc.7z"), FIRST_CRC);
    let got = walked(&blob.as_slice(), &["hunter2"], 64 * 1024);
    assert_eq!(got.len(), 3, "{got:?}");
    for m in &got {
        assert!(m.encrypted && m.data.is_empty(), "{m:?}");
        assert_eq!(
            m.unsupported,
            Some("7z: wrong or missing password"),
            "{m:?}"
        );
    }
}

/// `blob` with the CRCs of its members taken out of the header (which is not
/// compressed), the sizes and checksums of the headers made right again.
fn without_crcs(blob: &[u8]) -> Vec<u8> {
    without_digests(blob, &[FIRST_CRC, SECOND_CRC, crc(b"the third member\n")])
}

/// [`without_crcs`] for an archive whose digests of the substreams are
/// `crcs`, in the order of its members.
fn without_digests(blob: &[u8], crcs: &[u32]) -> Vec<u8> {
    let u64_at = |at: usize| u64::from_le_bytes(blob[at..at + 8].try_into().unwrap()) as usize;
    let (next, size) = (u64_at(12), u64_at(20));
    let header_at = 32 + next;
    let header = &blob[header_at..header_at + size];
    // The digests of the substreams: property 0x0A, all defined, the CRCs.
    let digests: Vec<u8> = [0x0A, 0x01]
        .into_iter()
        .chain(crcs.iter().flat_map(|c| c.to_le_bytes()))
        .collect();
    let at = header
        .windows(digests.len())
        .rposition(|w| w == digests)
        .expect("the digests are in the header");
    // The same property with none defined: a bit vector, and no CRC.
    let mut new = header[..at].to_vec();
    new.extend_from_slice(&[0x0A, 0x00]);
    new.resize(new.len() + crcs.len().div_ceil(8), 0);
    new.extend_from_slice(&header[at + digests.len()..]);
    let mut out = blob[..header_at].to_vec();
    out[20..28].copy_from_slice(&(new.len() as u64).to_le_bytes());
    out[28..32].copy_from_slice(&crc(&new).to_le_bytes());
    let start = crc(&out[12..32]);
    out[8..12].copy_from_slice(&start.to_le_bytes());
    out.extend_from_slice(&new);
    out
}

/// A folder none of whose members has a CRC has nothing to tell a password
/// by but that it decodes: the right one opens it, and every member comes
/// out whole, as it does with the CRCs, but is reported, as the password is
/// not confirmed.
#[test]
fn a_folder_without_crcs_is_decoded_and_its_members_are_reported() {
    let blob = without_crcs(&fixture("aes_solid_crc.7z"));
    let got = walked(&blob.as_slice(), &["hunter2"], 64 * 1024);
    assert_eq!(got.len(), 3, "{got:?}");
    for m in &got {
        assert!(m.encrypted && m.failed.is_none(), "{m:?}");
        let why = m.unsupported.unwrap_or_default();
        assert!(why.contains("no CRC"), "{m:?}");
    }
    assert!(got[0].data == FIRST.repeat(64), "{:?}", got[0]);
    assert!(got[1].data == SECOND.repeat(10_000), "{:?}", got[1]);
    assert_eq!(got[2].data, b"the third member\n");
}

/// The members of `aes_copy_eicar.7z` (three folders of one file each, AES and
/// then Copy), in the order 7-Zip wrote them, with their CRCs.
const COPY_MEMBERS: [(&str, &[u8]); 3] = [
    ("a.txt", b"the first member, plain text\n"),
    ("c.txt", b"the third member, plain text\n"),
    (
        "eicar.com",
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    ),
];

fn copy_crcs() -> Vec<u32> {
    COPY_MEMBERS.iter().map(|(_, d)| crc(d)).collect()
}

/// With a stored coder under the cipher a wrong password decodes as well as
/// the right one, to garbage. With the CRCs in the header it is refused; with
/// none, the folders are read with the first password and every member is
/// reported, so that the garbage is not taken for scanned.
#[test]
fn a_stored_folder_without_crcs_is_read_with_a_wrong_password_and_reported() {
    let blob = fixture("aes_copy_eicar.7z");
    // The fixture as 7-Zip wrote it: a wrong password is refused.
    let got = walked(&blob.as_slice(), &["nope"], 64 * 1024);
    assert_eq!(got.len(), 3, "{got:?}");
    for m in &got {
        assert_eq!(
            m.unsupported,
            Some("7z: wrong or missing password"),
            "{m:?}"
        );
        assert!(m.data.is_empty(), "{m:?}");
    }
    let got = walked(&blob.as_slice(), &["nope", "hunter2"], 64 * 1024);
    for (m, (name, plain)) in got.iter().zip(COPY_MEMBERS) {
        assert!(m.name.ends_with(name) && m.unsupported.is_none(), "{m:?}");
        assert_eq!(m.data, plain, "{m:?}");
    }

    let blob = without_digests(&blob, &copy_crcs());
    for words in [&["nope"][..], &["nope", "hunter2"][..]] {
        let got = walked(&blob.as_slice(), words, 64 * 1024);
        assert_eq!(got.len(), 3, "{words:?}: {got:?}");
        for (m, (name, plain)) in got.iter().zip(COPY_MEMBERS) {
            assert!(m.name.ends_with(name) && m.encrypted, "{m:?}");
            assert!(m.failed.is_none() && m.data.len() == plain.len(), "{m:?}");
            let why = m.unsupported.unwrap_or_default();
            assert!(why.contains("no CRC"), "{words:?}: {m:?}");
            // The first password decodes, so it is the one used: it is wrong.
            assert_ne!(m.data, plain, "{words:?}: {m:?}");
        }
    }
    // The right password gives the bytes, and the members are still reported.
    let got = walked(&blob.as_slice(), &["hunter2"], 64 * 1024);
    for (m, (_, plain)) in got.iter().zip(COPY_MEMBERS) {
        assert_eq!(m.data, plain, "{m:?}");
        assert!(
            m.unsupported.unwrap_or_default().contains("no CRC"),
            "{m:?}"
        );
    }
}

/// With the folder opened, a later member that does not match its CRC is read
/// to its end and then fails, and the member after it is not lost.
#[test]
fn a_member_that_does_not_match_its_crc_fails_at_its_end() {
    let blob = with_crc_changed(&fixture("aes_solid_crc.7z"), SECOND_CRC);
    let got = walked(&blob.as_slice(), &["hunter2"], 64 * 1024);
    assert_eq!(got.len(), 3, "{got:?}");
    assert!(got[0].failed.is_none() && got[0].data == FIRST.repeat(64));
    assert_eq!(
        got[1].failed,
        Some(std::io::ErrorKind::InvalidData),
        "{:?}",
        got[1]
    );
    // Not a checksum failing after a full decode: the key may be wrong.
    assert!(got[1].hides_content, "{:?}", got[1]);
    assert!(
        got[1].data == SECOND.repeat(10_000),
        "the bytes are given, the CRC is told at the end: {:?}",
        got[1]
    );
    assert!(got[2].failed.is_none() && got[2].data == b"the third member\n");
}

/// Damage in the packed bytes after the first member: the first comes out
/// whole, the second is given as far as it decodes and then fails, and the
/// third, in the block that ended, is reported with no bytes.
#[test]
fn damage_in_the_packed_bytes_after_the_first_member_is_an_error() {
    let mut blob = fixture("aes_solid_crc.7z");
    // The folder's packed stream starts after the 32-byte start header and is
    // 256 bytes; the first member is in the first of them.
    for at in [32 + 200, 32 + 240] {
        blob[at] ^= 0x55;
    }
    let got = walked(&blob.as_slice(), &["hunter2"], 64 * 1024);
    assert_eq!(got.len(), 3, "{got:?}");
    assert!(
        got[0].failed.is_none() && got[0].data == FIRST.repeat(64),
        "{got:?}"
    );
    let second = SECOND.repeat(10_000);
    assert!(got[1].failed.is_some(), "{got:?}");
    assert!(
        !got[1].data.is_empty() && got[1].data.len() < second.len(),
        "{got:?}"
    );
    assert!(
        second.starts_with(&got[1].data),
        "the bytes before the damage are the member's"
    );
    assert!(
        got[2].data.is_empty() && got[2].unsupported.is_some(),
        "{got:?}"
    );
}

/// A source that counts what is read from it.
struct Counting {
    inner: Cursor<Vec<u8>>,
    read: Rc<Cell<u64>>,
}

impl Read for Counting {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.read.set(self.read.get() + n as u64);
        Ok(n)
    }
}

impl Seek for Counting {
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(to)
    }
}

/// A 7z number: the leading ones of its first byte count the bytes after it.
fn num(n: u64) -> Vec<u8> {
    let mut extra = 0;
    while extra < 8 && n >= 1u64 << (7 * (extra + 1)) {
        extra += 1;
    }
    if extra == 8 {
        return [&[0xFF][..], &n.to_le_bytes()].concat();
    }
    let mut out = vec![(0xFF00u16 >> extra) as u8 | (n >> (8 * extra)) as u8];
    out.extend(&n.to_le_bytes()[..extra]);
    out
}

/// An archive of one folder, AES-256 and then Copy, of `members` (name and
/// content) one after the other, with the header 7-Zip writes for it, the
/// password `pw` and a key of 2^8 rounds.
fn aes_copy_archive(pw: &str, members: &[(&str, Vec<u8>)]) -> Vec<u8> {
    use cbc::cipher::{BlockModeEncrypt, KeyIvInit, block_padding::NoPadding};
    const CYCLES: u8 = 8;
    let salt: Vec<u8> = (1..=8).collect();
    let iv: [u8; 16] = std::array::from_fn(|i| 0x30 + i as u8);
    let word: Vec<u8> = pw.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut sha = Sha256::new();
    for counter in 0..(1u64 << CYCLES) {
        sha.update(&salt);
        sha.update(&word);
        sha.update(counter.to_le_bytes());
    }
    let key: [u8; 32] = sha.finalize().into();

    let plain: Vec<u8> = members
        .iter()
        .flat_map(|(_, d)| d.iter().copied())
        .collect();
    let mut packed = plain.clone();
    packed.resize(plain.len().next_multiple_of(16), 0);
    let n = packed.len();
    cbc::Encryptor::<aes::Aes256>::new(&key.into(), &iv.into())
        .encrypt_padded::<NoPadding>(&mut packed, n)
        .unwrap();

    // Both carry bits of the first byte, then the salt's and the IV's sizes
    // less one, as 7-Zip writes them.
    let mut props = vec![
        CYCLES | 0xC0,
        ((salt.len() as u8 - 1) << 4) | (iv.len() as u8 - 1),
    ];
    props.extend(&salt);
    props.extend(iv);

    let mut h = vec![0x01, 0x04, 0x06, 0x00, 0x01, 0x09];
    h.extend(num(packed.len() as u64));
    h.extend([0x00, 0x07, 0x0B, 0x01, 0x00, 0x02]);
    // The coders: AES with its properties, then Copy, whose input is the
    // output of the first.
    h.extend([0x24, 0x06, 0xF1, 0x07, 0x01, props.len() as u8]);
    h.extend(&props);
    h.extend([0x01, 0x00, 0x01, 0x00]);
    h.push(0x0C);
    h.extend(num(plain.len() as u64));
    h.extend(num(plain.len() as u64));
    h.extend([0x00, 0x08, 0x0D]);
    h.extend(num(members.len() as u64));
    h.push(0x09);
    for (_, d) in &members[..members.len() - 1] {
        h.extend(num(d.len() as u64));
    }
    h.extend([0x0A, 0x01]);
    for (_, d) in members {
        h.extend(crc(d).to_le_bytes());
    }
    h.extend([0x00, 0x00, 0x05]);
    h.extend(num(members.len() as u64));
    let names: Vec<u8> = members
        .iter()
        .flat_map(|(n, _)| n.encode_utf16().chain([0]).flat_map(u16::to_le_bytes))
        .collect();
    h.push(0x11);
    h.extend(num(names.len() as u64 + 1));
    h.push(0x00);
    h.extend(names);
    h.extend([0x00, 0x00]);

    let mut start = Vec::new();
    start.extend((packed.len() as u64).to_le_bytes());
    start.extend((h.len() as u64).to_le_bytes());
    start.extend(crc(&h).to_le_bytes());
    let mut out = b"7z\xBC\xAF\x27\x1C\x00\x04".to_vec();
    out.extend(crc(&start).to_le_bytes());
    out.extend(start);
    out.extend(packed);
    out.extend(h);
    out
}

/// The folder is read from where it is as its members are: when the second
/// member of 6 MiB starts, the source has been read as far as the first member
/// (the one that opened the folder), and one chunk more, not as far as its
/// end. Everything comes out as it went in.
#[test]
fn a_folder_is_read_from_the_source_as_its_members_are() {
    let first: Vec<u8> = (0..4096u32).map(|i| (i * 7 % 251) as u8).collect();
    let second: Vec<u8> = (0..6u32 << 20).map(|i| (i * 13 % 241) as u8).collect();
    let blob = aes_copy_archive(
        "pw",
        &[("first", first.clone()), ("second", second.clone())],
    );
    let read = Rc::new(Cell::new(0));
    let src = Counting {
        inner: Cursor::new(blob.clone()),
        read: Rc::clone(&read),
    };
    let cache = BlockCache::with_sizes(src, 4096, 64 * 1024).unwrap();
    let mut budget = Budget::with_passwords(limits(64 * 1024), vec!["wrong".into(), "pw".into()]);
    let mut at_second = None;
    let mut got = Vec::new();
    walk(
        Format::SevenZip,
        &cache,
        &mut budget,
        &mut |meta, content, _| {
            let Some(Member::Stream(r)) = content else {
                panic!("{}: not streamed", meta.name);
            };
            let mut data = vec![0u8; 1024];
            r.read_exact(&mut data).unwrap();
            if meta.name == "second" {
                at_second = Some(read.get());
            }
            r.read_to_end(&mut data).unwrap();
            got.push((meta.name.clone(), data));
            None::<()>
        },
    )
    .unwrap();
    assert_eq!(got.len(), 2);
    assert!(got[0].1 == first && got[1].1 == second);
    let at_second = at_second.expect("the second member was reached");
    assert!(
        at_second < 1 << 20,
        "{at_second} of {} bytes read when the second member started",
        blob.len()
    );
    assert!(
        read.get() >= blob.len() as u64 - 4096,
        "the whole is read in the end"
    );
}

/// Trying a password decodes the first member to check it. That costs the scan
/// nothing for the password that opens the folder, which is read again to be
/// scanned and charged then, and what it decoded for each that does not,
/// which is what bounds a long list of them.
#[test]
fn trying_passwords_is_charged_to_the_scan_for_the_wrong_ones_only() {
    let member: Vec<u8> = (0..6u32 << 20).map(|i| (i * 13 % 241) as u8).collect();
    let blob = aes_copy_archive("pw", &[("m", member.clone())]);
    // The member and a little more: one pass over it, not two.
    let mut limits = Limits::default();
    limits.max_scanned_bytes = member.len() as u64 + 4096;
    let got = try_walk(&blob.as_slice(), &["pw"], limits.clone()).unwrap();
    assert!(got.len() == 1 && got[0].data == member && got[0].failed.is_none());
    // Copy gives garbage for a wrong password, all of the member: the first
    // is charged what it decoded, and the second finds no room for it.
    let hit = try_walk(&blob.as_slice(), &["w1", "w2", "pw"], limits).unwrap_err();
    assert!(!hit.is_corrupt(), "{}", hit.reason);
}

/// A first member the scan has not budget left to read is not decoded to open
/// the folder: the walk ends on the limit, and the source is hardly read.
#[test]
fn a_member_past_what_the_scan_has_left_is_not_decoded_to_open_the_folder() {
    let member: Vec<u8> = (0..6u32 << 20).map(|i| (i * 13 % 241) as u8).collect();
    let blob = aes_copy_archive("pw", &[("m", member)]);
    let read = Rc::new(Cell::new(0));
    let src = Counting {
        inner: Cursor::new(blob),
        read: Rc::clone(&read),
    };
    let cache = BlockCache::with_sizes(src, 4096, 64 * 1024).unwrap();
    let mut limits = Limits::default();
    limits.max_scanned_bytes = 1 << 20;
    let hit = try_walk(&cache, &["pw"], limits).unwrap_err();
    assert!(!hit.is_corrupt(), "{}", hit.reason);
    assert!(read.get() < 1 << 20, "{} bytes read", read.get());
}
