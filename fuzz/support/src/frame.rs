//! How the targets that take more than one thing cut their input up.
//!
//! The framing is plain bytes, not `arbitrary`'s: a seed is a real file with a
//! three-byte header put in front of it (or a byte after it, for `trailer`),
//! and the mutator can still change what the header says without breaking it.

/// The most files a framed input carries.
pub const MAX_FILES: usize = 8;

/// The last two bytes of `data` as a little-endian number, and what is before
/// them. An input of fewer than two bytes selects nothing (0).
pub fn trailer(data: &[u8]) -> (&[u8], u16) {
    match data {
        [body @ .., a, b] => (body, u16::from_le_bytes([*a, *b])),
        _ => (data, 0),
    }
}

/// An input cut into the pieces `parse` finds.
#[derive(Debug, PartialEq, Eq)]
pub struct Framed<'a> {
    /// Switches for the target to read as it likes.
    pub bits: u16,
    /// Up to [`MAX_FILES`] pieces, each a kind byte and its bytes.
    pub files: Vec<(u8, &'a [u8])>,
    /// Everything after the pieces.
    pub rest: &'a [u8],
}

/// `[bits: u16 LE] [count: u8] ([kind: u8] [len: u16 LE] [bytes])* [rest]`.
///
/// Lenient: a count above [`MAX_FILES`] counts as `count % (MAX_FILES + 1)`,
/// and a length past the end is cut to what is left, so a mutation of the
/// header changes the cut and does not throw the input away. Only an input
/// shorter than the three header bytes has none.
pub fn parse(data: &[u8]) -> Option<Framed<'_>> {
    let (&lo, data) = data.split_first()?;
    let (&hi, data) = data.split_first()?;
    let (&count, mut data) = data.split_first()?;
    let mut files = Vec::new();
    for _ in 0..count as usize % (MAX_FILES + 1) {
        let [kind, l0, l1, tail @ ..] = data else {
            break;
        };
        let len = (u16::from_le_bytes([*l0, *l1]) as usize).min(tail.len());
        files.push((*kind, &tail[..len]));
        data = &tail[len..];
    }
    Some(Framed {
        bits: u16::from_le_bytes([lo, hi]),
        files,
        rest: data,
    })
}

/// The input `parse` cuts into `bits`, `files` and `rest`. For writing seeds
/// and tests; a file over 64 KiB - 1 is cut, as `parse` could not read it.
pub fn encode(bits: u16, files: &[(u8, &[u8])], rest: &[u8]) -> Vec<u8> {
    let mut out = bits.to_le_bytes().to_vec();
    let files = &files[..files.len().min(MAX_FILES)];
    out.push(files.len() as u8);
    for (kind, bytes) in files {
        let bytes = &bytes[..bytes.len().min(u16::MAX as usize)];
        out.push(*kind);
        out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(bytes);
    }
    out.extend_from_slice(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_framed_input_is_cut_where_it_was_joined() {
        let files: &[(u8, &[u8])] = &[(3, b"abc"), (0, b""), (9, &[0u8; 300])];
        let bytes = encode(0xBEEF, files, b"the rest");
        let got = parse(&bytes).unwrap();
        assert_eq!(got.bits, 0xBEEF);
        assert_eq!(got.files, files);
        assert_eq!(got.rest, b"the rest");
    }

    #[test]
    fn a_length_past_the_end_is_cut_to_what_is_left() {
        // One file declaring 1000 bytes, with 4 after its header.
        let got = parse(&[0, 0, 1, 7, 0xE8, 0x03, 1, 2, 3, 4]).unwrap();
        assert_eq!(got.files, [(7, &[1u8, 2, 3, 4][..])]);
        assert_eq!(got.rest, b"");
    }

    #[test]
    fn a_count_over_the_most_wraps_instead_of_failing() {
        let got = parse(&[0, 0, 200, 1]).unwrap();
        assert!(got.files.len() <= MAX_FILES);
    }

    #[test]
    fn a_header_alone_has_no_files_and_nothing_after() {
        let got = parse(&[1, 0, 0]).unwrap();
        assert_eq!((got.bits, got.files.len(), got.rest.len()), (1, 0, 0));
        assert!(parse(&[1, 0]).is_none());
        assert!(parse(&[]).is_none());
    }

    #[test]
    fn a_raw_file_behind_a_zero_header_is_all_rest() {
        let mut seed = vec![0, 0, 0];
        seed.extend_from_slice(b"MZ\x90\x00file");
        let got = parse(&seed).unwrap();
        assert_eq!((got.bits, got.files.len()), (0, 0));
        assert_eq!(got.rest, b"MZ\x90\x00file");
    }

    #[test]
    fn the_trailer_is_the_last_two_bytes_and_a_short_input_selects_nothing() {
        assert_eq!(trailer(b"abc\x34\x12"), (&b"abc"[..], 0x1234));
        assert_eq!(trailer(b"\x34\x12"), (&b""[..], 0x1234));
        assert_eq!(trailer(b"\x34"), (&b"\x34"[..], 0));
        assert_eq!(trailer(b""), (&b""[..], 0));
    }
}
