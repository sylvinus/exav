//! Reading at offsets and lengths a file's own header supplies.
//!
//! `data.get(off..off + len)` panics (checks on) or wraps (WebAssembly) when a
//! header field puts `off` near the top of `usize`, and a wrapped range can pass
//! the bounds check it was written for. [`at`] answers `None` instead.

/// `data[off..off + len]`, or `None` if it ends past the data or the sum overflows.
pub(crate) fn at(data: &[u8], off: usize, len: usize) -> Option<&[u8]> {
    data.get(off..off.checked_add(len)?)
}

#[cfg(test)]
mod tests {
    use super::at;

    #[test]
    fn a_range_whose_end_wraps_is_none() {
        let d = [1u8, 2, 3, 4];
        assert_eq!(at(&d, 1, 2), Some(&d[1..3]));
        assert_eq!(at(&d, 3, 2), None);
        assert_eq!(at(&d, usize::MAX, 2), None);
        assert_eq!(at(&d, 2, usize::MAX), None);
    }
}
