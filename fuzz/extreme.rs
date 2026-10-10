//! A custom mutator for the targets that read container formats.
//!
//! A container's own numbers (offsets, counts, sizes) are what an unchecked sum
//! overflows on, and libFuzzer's stock mutations reach a value like
//! `0xFFFF_FFFF_FFFF_FFF0` in one chosen field very rarely. This one sets a
//! 2-, 4- or 8-byte field, at any position, to a value near the top of its
//! range, a quarter of the time, and leaves the rest to the stock mutator.
//!
//! Used with `#[path = "../extreme.rs"] mod extreme;` and
//! `libfuzzer_sys::fuzz_mutator!` (see `fuzz_targets/unpack.rs`).

/// Values written as 2, 4 or 8 bytes (truncated to the width), little- or
/// big-endian: the top of the range, just under it, the sign bit, and the
/// largest value that is still a positive signed one.
const EXTREMES: [u64; 8] = [
    u64::MAX,
    u64::MAX - 15,
    1 << 63,
    (1 << 63) - 1,
    1 << 62,
    1 << 55,
    (1 << 44) - 1,
    0x8000,
];

/// One step of a xorshift, so that a mutation is a function of `seed` alone.
fn next(state: &mut u32) -> u32 {
    let mut x = *state | 1;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    x
}

/// Sets one field of `data[..size]` to an extreme, or returns `false` (leaving
/// `data` as it was) when `seed` does not choose to, or `size` is too small.
pub fn set_extreme_field(data: &mut [u8], size: usize, seed: u32) -> bool {
    let mut state = seed;
    if next(&mut state) % 4 != 0 {
        return false;
    }
    let width = [2usize, 4, 8][next(&mut state) as usize % 3];
    if size < width || size > data.len() {
        return false;
    }
    let at = next(&mut state) as usize % (size - width + 1);
    let value = EXTREMES[next(&mut state) as usize % EXTREMES.len()];
    let big = next(&mut state) & 1 == 1;
    let bytes = if big {
        value.to_be_bytes()
    } else {
        value.to_le_bytes()
    };
    // Little-endian keeps the low bytes, big-endian the low bytes too (they are
    // at the end of `to_be_bytes`): the field gets the value truncated.
    let field = if big { &bytes[8 - width..] } else { &bytes[..width] };
    data[at..at + width].copy_from_slice(field);
    true
}

#[cfg(test)]
mod tests {
    use super::set_extreme_field;

    /// Over many seeds, about a quarter change something, only inside `size`,
    /// and what they write is a value of the list at the chosen width.
    #[test]
    fn a_quarter_of_the_seeds_set_a_field_inside_the_input() {
        let base = vec![0x11u8; 64];
        let mut changed = 0;
        for seed in 0..4000u32 {
            let mut d = base.clone();
            d.extend_from_slice(&[0x22; 16]);
            let hit = set_extreme_field(&mut d, 64, seed.wrapping_mul(2654435761));
            assert_eq!(&d[64..], &[0x22; 16], "wrote past size");
            if hit {
                changed += 1;
                assert_ne!(&d[..64], &base[..], "reported a change, made none");
            } else {
                assert_eq!(&d[..64], &base[..], "changed the input and said it did not");
            }
        }
        assert!((600..1400).contains(&changed), "{changed} of 4000");
    }

    #[test]
    fn a_field_can_land_on_the_first_and_the_last_byte() {
        let (mut first, mut last) = (false, false);
        for seed in 0..20000u32 {
            let mut d = vec![0x11u8; 16];
            if set_extreme_field(&mut d, 16, seed.wrapping_mul(2654435761)) {
                first |= d[0] != 0x11;
                last |= d[15] != 0x11;
            }
        }
        assert!(first && last, "first {first}, last {last}");
    }

    #[test]
    fn an_input_shorter_than_the_field_is_left_alone() {
        for seed in 0..1000u32 {
            let mut d = vec![0x11u8; 1];
            assert!(!set_extreme_field(&mut d, 1, seed));
            assert_eq!(d, [0x11]);
        }
    }
}
