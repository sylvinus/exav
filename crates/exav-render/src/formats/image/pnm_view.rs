//! PNM files to look at that `image` refuses for their comments: a `#` line
//! between the size and the maximum value, or in the samples of a plain
//! (P1 to P3) file. The comments are cut out and the file decoded again. A
//! fallback of `decode_any` only.

use super::{decode, Error, Format, Pixels};

pub(super) fn decode_uncommented(data: &[u8], max_alloc: u64) -> Result<Pixels, Error> {
    let fixed = uncomment(data).ok_or(Error::Undecodable)?;
    decode(&fixed, Format::Pnm, max_alloc)
}

/// The file with a header of numbers on lines of their own, and no comments in
/// a plain file's samples. `None` for P7 and for a header that is not numbers.
fn uncomment(data: &[u8]) -> Option<Vec<u8>> {
    let kind = *data.get(1)?;
    if data[0] != b'P' || !(b'1'..=b'6').contains(&kind) {
        return None;
    }
    // Width and height; a bitmap has no maximum value.
    let fields = if matches!(kind, b'1' | b'4') { 2 } else { 3 };
    let mut out = vec![b'P', kind, b'\n'];
    let mut at = 2;
    for _ in 0..fields {
        loop {
            match *data.get(at)? {
                b'#' => {
                    while *data.get(at)? != b'\n' {
                        at += 1;
                    }
                }
                c if c.is_ascii_whitespace() => at += 1,
                _ => break,
            }
        }
        let start = at;
        while data.get(at).is_some_and(u8::is_ascii_digit) {
            at += 1;
        }
        if at == start {
            return None;
        }
        out.extend_from_slice(&data[start..at]);
        out.push(b'\n');
    }
    if matches!(kind, b'1'..=b'3') {
        let mut samples = data.get(at..)?.iter();
        while let Some(&b) = samples.next() {
            if b == b'#' {
                samples.by_ref().find(|&&c| c == b'\n');
                out.push(b'\n');
            } else {
                out.push(b);
            }
        }
    } else {
        // One whitespace byte ends the header of a raw file.
        out.extend_from_slice(data.get(at + 1..)?);
    }
    Some(out)
}
