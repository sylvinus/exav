//! RAR 2.9/4 archives made by official RAR 6.12 (`-ma4`), each from the case
//! a decoder got wrong. The inputs are generated text, random bytes and
//! synthetic x86 calls; the digests are of those inputs.
//!
//! ```sh
//! rar a -ma4 -s -m5 -mct+ solid_ppmd.rar a_text.txt b_rand.bin c_text.txt
//! rar a -ma4 -s -m3 solid_empty.rar a_text.txt d_empty.txt e_text.txt
//! rar a -ma4 -s- -m3 -mce+ x86_second.rar a_text.txt f_code.zzz
//! rar a -ma4 -s- -m3 -md64k two_windows.rar e_text.txt
//! rar a -ma4 -s- -m3 -md1m two_windows.rar g_far.bin
//! rar a -ma4 -m3 -pinfected enc_data.rar a_text.txt e_text.txt
//! rar a -ma4 -m3 -hpinfected enc_headers.rar a_text.txt e_text.txt
//! rar a -ma4 -m3 -hpsecret enc_headers_unknown.rar e_text.txt
//! ```

use super::extract_each;
use exav_unpack::{Budget, Entry, Format, Limits};

const A_TEXT: &str = "626d0b9812f0357bbf21fa9bf5b44f2bcf5d384bc8f8f7d244cebb00871f6a50";
const B_RAND: &str = "c6c2d39c7f99a42669286fc1de93492c4ff5a56647857229039bbd1c11c89123";
const C_TEXT: &str = "dc7d5790fb353fc6d2090c43f576b5792aadecb36ed356cc9fa683c3cce2fc67";
const D_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const E_TEXT: &str = "78f776229395b3ff192fdf4a903215ee8415f2c11793cb3600ad43bfca3b2317";
const F_CODE: &str = "82ef44488a09b8bb96d10558615d7a94090539943963154218bfb09be782c240";
const G_FAR: &str = "592e2e0c2a52d101b1ac8bd5935cab37422715989f93d0254e157735789d7890";

fn members(name: &str, passwords: &[&str]) -> Vec<Entry> {
    let p = format!("{}/tests/fixtures/rar4/{name}", env!("CARGO_MANIFEST_DIR"));
    let blob = std::fs::read(&p).unwrap_or_else(|e| panic!("read {p}: {e}"));
    let mut b = Budget::with_passwords(
        Limits::default(),
        passwords.iter().map(|s| s.to_string()).collect(),
    );
    let mut out = Vec::new();
    let _ = extract_each(
        Format::Rar,
        &blob,
        &mut b,
        &mut |e: Entry, _: &mut Budget| {
            out.push(e);
            None::<()>
        },
    );
    out
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Every member read, as (name, digest), sorted.
fn read(name: &str, passwords: &[&str]) -> Vec<(String, String)> {
    let mut got: Vec<_> = members(name, passwords)
        .into_iter()
        .map(|e| {
            assert!(
                e.unsupported.is_none(),
                "{name} {}: {:?}",
                e.name,
                e.unsupported
            );
            (e.name, sha256_hex(&e.data))
        })
        .collect();
    got.sort();
    got
}

fn want(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(n, d)| (n.to_string(), d.to_string()))
        .collect()
}

/// A PPMd block header that sets no escape symbol keeps the one before it;
/// it was reset to the default. And a member ending on PPMd's end-of-data
/// code is followed by a block header.
#[test]
fn a_solid_ppmd_group_decodes_every_member() {
    assert_eq!(
        read("solid_ppmd.rar", &[]),
        want(&[
            ("a_text.txt", A_TEXT),
            ("b_rand.bin", B_RAND),
            ("c_text.txt", C_TEXT)
        ])
    );
}

/// An empty member of a solid group still ends on its end-of-file code, which
/// the next member starts after.
#[test]
fn an_empty_member_of_a_solid_group_is_read_through() {
    assert_eq!(
        read("solid_empty.rar", &[]),
        want(&[
            ("a_text.txt", A_TEXT),
            ("d_empty.txt", D_EMPTY),
            ("e_text.txt", E_TEXT)
        ])
    );
}

/// The x86 filter converts addresses relative to its own member; they were
/// counted from the start of the first member decoded.
#[test]
fn the_x86_filter_counts_from_its_own_member() {
    assert_eq!(
        read("x86_second.rar", &[]),
        want(&[("a_text.txt", A_TEXT), ("f_code.zzz", F_CODE)])
    );
}

/// A member that is not solid is decoded on its own window: `g_far.bin`
/// repeats 64 KiB of random bytes after 200 KiB of zeros, under a 512 KiB
/// window, after a first member's 64 KiB (which the decoder rounds up to its
/// 256 KiB floor).
#[test]
fn each_member_is_decoded_on_its_own_window() {
    assert_eq!(
        read("two_windows.rar", &[]),
        want(&[("e_text.txt", E_TEXT), ("g_far.bin", G_FAR)])
    );
}

#[cfg(feature = "decrypt")]
#[test]
fn encrypted_members_open_with_a_default_password() {
    let e = members("enc_data.rar", &[]);
    assert!(e.iter().all(|e| e.encrypted));
    assert_eq!(
        read("enc_data.rar", &[]),
        want(&[("a_text.txt", A_TEXT), ("e_text.txt", E_TEXT)])
    );
}

#[cfg(feature = "decrypt")]
#[test]
fn encrypted_headers_open_with_a_default_password() {
    assert_eq!(
        read("enc_headers.rar", &[]),
        want(&[("a_text.txt", A_TEXT), ("e_text.txt", E_TEXT)])
    );
}

#[test]
fn encrypted_headers_without_the_password_are_reported() {
    let e = members("enc_headers_unknown.rar", &[]);
    assert_eq!(e.len(), 1, "{e:?}");
    assert!(e[0].encrypted && e[0].unsupported.is_some());
    #[cfg(feature = "decrypt")]
    assert_eq!(
        read("enc_headers_unknown.rar", &["secret"]),
        want(&[("e_text.txt", E_TEXT)])
    );
}
