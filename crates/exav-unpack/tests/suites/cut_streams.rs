//! A stream cut short gives up what the reference decoder gives up.
//!
//! `bzip2 -dc`, `xz -dc` and Python's `bz2` and `lzma` write every byte they can
//! decode from a stream whose end is missing, then report the cut. An extractor
//! that holds back more than they do shows a scan less than the file has: the
//! payload at the end of a stream is the one a truncation puts at the cut.

use exav_unpack::{Budget, Entry, Format, Limits, extract};
use std::io::Write;

/// A text that compresses, so the string is not in the compressed bytes.
fn payload() -> Vec<u8> {
    let mut v = b"filler to put the payload at the end ".repeat(30);
    v.extend([exav_unpack::eicar(), b"\n"].concat().repeat(8));
    v
}

fn decoded(format: Format, blob: &[u8]) -> Vec<u8> {
    let mut budget = Budget::new(Limits::default());
    match extract(format, &blob, &mut budget) {
        Ok(entries) => entries.into_iter().flat_map(|e: Entry| e.data).collect(),
        Err(_) => Vec::new(),
    }
}

fn finds_the_payload(out: &[u8]) -> bool {
    let eicar = exav_unpack::eicar();
    out.windows(eicar.len()).any(|w| w == eicar)
}

fn bzip2(data: &[u8]) -> Vec<u8> {
    let mut enc = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::new(9));
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

#[test]
fn a_bzip2_stream_cut_inside_its_trailer_still_gives_its_last_block() {
    let data = payload();
    let bz = bzip2(&data);
    assert!(!bz.windows(68).any(|w| w == exav_unpack::eicar()));
    assert!(
        finds_the_payload(&decoded(Format::Bzip2, &bz)),
        "the whole stream"
    );
    // The trailer is ten bytes: the end magic and the combined checksum.
    for cut in 1..=9 {
        let out = decoded(Format::Bzip2, &bz[..bz.len() - cut]);
        assert!(
            finds_the_payload(&out),
            "cut {cut} bytes short: {} bytes out",
            out.len()
        );
    }
}

#[test]
fn a_later_bzip2_stream_that_is_cut_short_is_scanned_as_far_as_it_goes() {
    let benign = bzip2(&b"nothing to see here ".repeat(50));
    let mut cut = bzip2(&payload());
    cut.truncate(cut.len() - 5);
    let both = [benign.as_slice(), &cut].concat();
    assert!(
        finds_the_payload(&decoded(Format::Bzip2, &both)),
        "the second stream was read as far as the first"
    );
    // Whole, the two streams give both.
    let whole = [benign.as_slice(), &bzip2(&payload())].concat();
    assert!(finds_the_payload(&decoded(Format::Bzip2, &whole)));
}

fn xz(data: &[u8]) -> Vec<u8> {
    let mut w =
        lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(6)).unwrap();
    w.write_all(data).unwrap();
    w.finish().unwrap()
}

/// Words, so that the stream is compressed and its end carries real symbols,
/// and the string at the very end.
fn words_then_payload() -> Vec<u8> {
    let mut x: u32 = 0x1234_5678;
    let mut v = Vec::new();
    while v.len() < 30_000 {
        for _ in 0..(3 + x % 7) {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            v.push(b'a' + (x % 16) as u8);
        }
        v.push(b' ');
    }
    v.extend_from_slice(exav_unpack::eicar());
    v
}

/// The decoder reads ahead of what it writes, so the last bytes it could decode
/// from what it was given wait in it for input that is not there; `xz -dc` and
/// Python's `lzma` write them. This stream is cut at the shortest length at
/// which they have written the whole of the string at its end (generated with
/// Python: 30,000 bytes of words, then the string, `lzma.compress`, then a
/// binary search for the cut).
#[test]
fn an_xz_stream_cut_gives_what_xz_writes() {
    // Masked: a scanner that reads a cut stream as `xz -dc` does finds the
    // string in it.
    let blob = exav_unpack::read_fixture(&format!(
        "{}/tests/fixtures/xz/cut_where_xz_has_written_the_payload.xz",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let out = decoded(Format::Xz, &blob);
    assert!(finds_the_payload(&out), "{} bytes out", out.len());
}

/// A cut anywhere gives a prefix of the whole, and at least what a
/// straightforward decoder gives.
#[test]
fn an_xz_stream_cut_anywhere_gives_a_prefix_of_the_whole() {
    let data = words_then_payload();
    let blob = xz(&data);
    assert!(
        finds_the_payload(&decoded(Format::Xz, &blob)),
        "the whole stream"
    );
    for cut in 1..=400 {
        let got = decoded(Format::Xz, &blob[..blob.len() - cut]);
        assert!(
            data.starts_with(&got),
            "cut {cut}: {} bytes that are not the stream's",
            got.len()
        );
    }
}
