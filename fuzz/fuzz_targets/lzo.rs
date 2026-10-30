#![no_main]
//! The LZO1X decoder on hostile bytes, as SquashFS feeds it. The first two bytes
//! are the most it may write; the rest is the stream.
//!
//! Checked: it never panics, never writes more than it may, and what it
//! writes is a function of the stream alone. A stream of literals, which the
//! decoder must give back as they are, is built from the same bytes and checked
//! too: the encoding of a run of literals is the one instruction whose length
//! has three forms.
use libfuzzer_sys::fuzz_target;

/// The LZO1X stream of `data` as literals only, ended as a stream is.
fn literals(data: &[u8]) -> Vec<u8> {
    let mut s = Vec::new();
    match data.len() {
        0 => {}
        // A first byte of 17 and more says how many follow it, 1 to 238.
        n @ 1..=238 => {
            s.push(17 + n as u8);
            s.extend_from_slice(data);
        }
        n => {
            // 0, then the run less 18 in bytes of 255 and one more, then the
            // run: a run of 3 + t bytes, t being 15 and what is written.
            s.push(0);
            let mut t = n - 18;
            while t > 255 {
                s.push(0);
                t -= 255;
            }
            s.push(t as u8);
            s.extend_from_slice(data);
        }
    }
    s.extend_from_slice(&[0x11, 0, 0]);
    s
}

fuzz_target!(|data: &[u8]| {
    let Some((head, stream)) = data.split_at_checked(2) else {
        return;
    };
    let max = usize::from(u16::from_le_bytes([head[0], head[1]]));
    if let Ok(out) = exav_unpack::lzo_decompress(stream, max) {
        assert!(out.len() <= max, "wrote {} of at most {max}", out.len());
        assert_eq!(exav_unpack::lzo_decompress(stream, max).unwrap(), out);
    }
    // The first 1500 bytes of the stream as literals.
    let lits = &stream[..stream.len().min(1500)];
    let encoded = literals(lits);
    let decoded = exav_unpack::lzo_decompress(&encoded, usize::MAX >> 1).unwrap();
    assert_eq!(decoded, lits);
});
