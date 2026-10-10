//! Reading at offsets and lengths a container's own header supplies.
//!
//! `data.get(off..off + len)` panics (checks on) or wraps (WebAssembly) when a
//! header field puts `off` near the top of `usize`, and a wrapped range can pass
//! the bounds check it was written for. [`at`] answers `None` instead.

/// `data[off..off + len]`, or `None` if it ends past the data or the sum overflows.
#[allow(dead_code)]
pub(crate) fn at(data: &[u8], off: usize, len: usize) -> Option<&[u8]> {
    data.get(off..off.checked_add(len)?)
}

/// A header's `u64` as a `usize`, saturating: `as usize` keeps only the low 32
/// bits on wasm32, which can turn a far offset into a near one that passes a
/// bounds check.
#[allow(dead_code)]
pub(crate) fn to_usize(v: u64) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::{at, to_usize};

    #[test]
    fn a_wide_offset_saturates_instead_of_truncating() {
        assert_eq!(to_usize(5), 5);
        assert_eq!(to_usize(u64::MAX), usize::MAX);
        // Past 32 bits: kept where `usize` is 64 bits, the top where it is not.
        let want = if usize::BITS >= 64 {
            (1u64 << 32) as usize
        } else {
            usize::MAX
        };
        assert_eq!(to_usize(1 << 32), want);
    }

    #[test]
    fn a_range_is_inside_the_data_or_absent() {
        let d = [1u8, 2, 3, 4];
        assert_eq!(at(&d, 1, 2), Some(&d[1..3]));
        assert_eq!(at(&d, 0, 4), Some(&d[..]));
        assert_eq!(at(&d, 4, 0), Some(&d[4..]));
        assert_eq!(at(&d, 1, 4), None);
        assert_eq!(at(&d, 5, 0), None);
    }

    #[test]
    fn a_sum_that_overflows_is_absent_not_a_panic() {
        let d = [0u8; 8];
        assert_eq!(at(&d, usize::MAX, 4), None);
        assert_eq!(at(&d, usize::MAX - 1, 2), None);
        assert_eq!(at(&d, 4, usize::MAX), None);
    }
}
