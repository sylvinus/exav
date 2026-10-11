//! Structured-data (DLP) heuristics: count payment-card numbers and US Social
//! Security numbers in a text buffer, as a data-exfiltration signal driven by
//! the `--structured-cc-count` / `--structured-ssn-count` thresholds.
//!
//! Written independently from public sources:
//! - **Luhn checksum** — the ISO/IEC 7812-1 check-digit algorithm.
//! - **Payment-card prefixes / lengths** — the public Issuer Identification
//!   Number (IIN/BIN) ranges and lengths for the major networks (see e.g. the
//!   "Payment card number" reference on Wikipedia): Visa, Mastercard (incl. the
//!   2-series `2221–2720`), American Express, Discover, Diners Club, JCB, and
//!   UnionPay.
//! - **SSN validity** — the US Social Security Administration's public rules: a
//!   `AAA-GG-SSSS` number where the area is `001–899` but never `666`, the group
//!   is `01–99`, and the serial is `0001–9999`. Areas `900–999` were never
//!   issued, so the publicly reserved advertising block `987-65-43xx` is
//!   rejected by the area rule.
//!
//! Single forward byte-wise passes, no allocation, no panics on binary input.

use crate::byte_source::{Bytes, Indexed};

/// Which SSN textual format(s) to count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsnMode {
    /// Hyphenated `AAA-GG-SSSS`.
    Normal,
    /// Bare 9-digit `AAAGGSSSS`.
    Stripped,
    /// Count both formats.
    Both,
}

/// A public IIN/BIN prefix range and the card lengths valid for it. `credit`
/// marks genuine credit-card networks; ranges kept `false` (e.g. UATP, Maestro)
/// are recognised but not counted as credit cards.
struct Bin {
    lo: u32,
    hi: u32,
    len_lo: usize,
    len_hi: usize,
    credit: bool,
}

/// Major-network IIN/BIN prefix ranges (6-digit prefixes), public information.
/// Sorted ascending by `lo` so the lookup can stop early.
const BINS: &[Bin] = &[
    Bin {
        lo: 100_000,
        hi: 199_999,
        len_lo: 15,
        len_hi: 15,
        credit: false,
    }, // UATP (not credit)
    Bin {
        lo: 222_100,
        hi: 272_099,
        len_lo: 16,
        len_hi: 16,
        credit: true,
    }, // Mastercard 2-series
    Bin {
        lo: 300_000,
        hi: 305_999,
        len_lo: 14,
        len_hi: 16,
        credit: true,
    }, // Diners Club
    Bin {
        lo: 309_500,
        hi: 309_599,
        len_lo: 14,
        len_hi: 16,
        credit: true,
    }, // Diners Club Intl
    Bin {
        lo: 340_000,
        hi: 349_999,
        len_lo: 15,
        len_hi: 15,
        credit: true,
    }, // American Express
    Bin {
        lo: 352_800,
        hi: 358_999,
        len_lo: 16,
        len_hi: 16,
        credit: true,
    }, // JCB
    Bin {
        lo: 360_000,
        hi: 369_999,
        len_lo: 14,
        len_hi: 16,
        credit: true,
    }, // Diners Club Intl
    Bin {
        lo: 370_000,
        hi: 379_999,
        len_lo: 15,
        len_hi: 15,
        credit: true,
    }, // American Express
    Bin {
        lo: 380_000,
        hi: 399_999,
        len_lo: 16,
        len_hi: 16,
        credit: true,
    }, // Diners Club Intl
    Bin {
        lo: 400_000,
        hi: 499_999,
        len_lo: 16,
        len_hi: 16,
        credit: true,
    }, // Visa
    Bin {
        lo: 500_000,
        hi: 509_999,
        len_lo: 16,
        len_hi: 16,
        credit: false,
    }, // Maestro (not credit)
    Bin {
        lo: 510_000,
        hi: 559_999,
        len_lo: 16,
        len_hi: 16,
        credit: true,
    }, // Mastercard
    Bin {
        lo: 601_100,
        hi: 601_199,
        len_lo: 16,
        len_hi: 16,
        credit: true,
    }, // Discover
    Bin {
        lo: 620_000,
        hi: 629_999,
        len_lo: 16,
        len_hi: 16,
        credit: true,
    }, // UnionPay
    Bin {
        lo: 644_000,
        hi: 659_999,
        len_lo: 16,
        len_hi: 16,
        credit: true,
    }, // Discover
];

/// Maximum separator characters tolerated inside one card number.
const MAX_SEPARATORS: i32 = 8;

/// Find the BIN range containing a 6-digit prefix. `credit_only` skips non-credit
/// networks (UATP/Maestro).
fn bin_for(prefix: u32, credit_only: bool) -> Option<&'static Bin> {
    for b in BINS {
        if prefix < b.lo {
            break;
        }
        if prefix <= b.hi && (!credit_only || b.credit) {
            return Some(b);
        }
    }
    None
}

/// The Luhn (mod-10) checksum over ASCII digits.
fn luhn_valid(digits: &[u8]) -> bool {
    let mut sum = 0i32;
    let mut double = false;
    for &d in digits.iter().rev() {
        let mut v = (d - b'0') as i32;
        if double {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        double = !double;
        sum += v;
    }
    sum % 10 == 0
}

fn digits_to_u32(d: &[u8]) -> u32 {
    d.iter().fold(0u32, |a, &c| {
        a.wrapping_mul(10).wrapping_add((c - b'0') as u32)
    })
}

/// Try to read a payment-card number at the front of `buf`: a recognised 6-digit
/// prefix, a valid length for that network, up to [`MAX_SEPARATORS`] single space
/// or hyphen separators, and a passing Luhn check.
fn card_at(buf: &[u8], credit_only: bool) -> bool {
    let mut digits = [0u8; 19];
    let mut n = 0usize;
    let mut seps = 0i32;
    let mut i = 0usize;

    // Collect the 6-digit prefix.
    while i < buf.len() && n < 6 {
        let c = buf[i];
        if c.is_ascii_digit() {
            digits[n] = c;
            n += 1;
            i += 1;
        } else if (c == b' ' || c == b'-') && seps < MAX_SEPARATORS {
            seps += 1;
            i += 1;
        } else {
            break;
        }
    }
    if n < 6 {
        return false;
    }
    let Some(bin) = bin_for(digits_to_u32(&digits[..6]), credit_only) else {
        return false;
    };

    // Collect up to the network's maximum length.
    while i < buf.len() && n < bin.len_hi {
        let c = buf[i];
        if c.is_ascii_digit() {
            digits[n] = c;
            n += 1;
            i += 1;
        } else if (c == b' ' || c == b'-') && seps < MAX_SEPARATORS {
            seps += 1;
            i += 1;
        } else {
            break;
        }
    }
    // Reject if too short, or an extra digit runs past the allowed length.
    if n < bin.len_lo || (i < buf.len() && buf[i].is_ascii_digit()) {
        return false;
    }
    luhn_valid(&digits[..n])
}

/// Count payment-card numbers in `data` (credit networks only).
pub fn count_credit_cards(data: &[u8]) -> usize {
    count_credit_cards_in(&mut Indexed(data))
}

/// Bytes [`card_at`] reads: every digit and separator it may take, and the
/// byte after them.
const CARD_REACH: usize = 19 + MAX_SEPARATORS as usize + 1;

/// [`count_credit_cards`] over any object.
pub(crate) fn count_credit_cards_in<B: Bytes>(data: &mut B) -> usize {
    let mut count = 0usize;
    let mut i = 0usize;
    while i < data.len() {
        if data.at(i).is_ascii_digit()
            && (i == 0 || !data.at(i - 1).is_ascii_digit())
            && card_at(&data.range(i, i + CARD_REACH), true)
        {
            count += 1;
            // Skip ahead past a plausible card so one number isn't recounted.
            i += 13;
        }
        i += 1;
    }
    count
}

/// Read three digit fields at fixed positions, `None` if any byte isn't a digit.
fn field(bytes: &[u8]) -> Option<i32> {
    let mut v = 0i32;
    for &c in bytes {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + (c - b'0') as i32;
    }
    Some(v)
}

/// True if an SSN (hyphenated or bare) sits at the front of `buf` and satisfies
/// the public SSA validity rules.
fn ssn_at(buf: &[u8], hyphens: bool) -> bool {
    let width = if hyphens { 11 } else { 9 };
    if buf.len() < width {
        return false;
    }
    // A digit immediately after means it's part of a longer number.
    if buf.len() > width && buf[width].is_ascii_digit() {
        return false;
    }
    let (area, group, serial) = if hyphens {
        if buf[3] != b'-' || buf[6] != b'-' {
            return false;
        }
        match (field(&buf[0..3]), field(&buf[4..6]), field(&buf[7..11])) {
            (Some(a), Some(g), Some(s)) => (a, g, s),
            _ => return false,
        }
    } else {
        match (field(&buf[0..3]), field(&buf[3..5]), field(&buf[5..9])) {
            (Some(a), Some(g), Some(s)) => (a, g, s),
            _ => return false,
        }
    };
    // Public SSA rules: area 001-899 except 666; group 01-99; serial 0001-9999.
    // Areas 900-999 (which include the reserved advertising block 987-65-43xx)
    // were never issued and so fall outside the area range.
    (1..=899).contains(&area)
        && area != 666
        && (1..=99).contains(&group)
        && (1..=9999).contains(&serial)
}

fn count_ssn_fmt<B: Bytes>(data: &mut B, hyphens: bool) -> usize {
    let width = if hyphens { 11 } else { 9 };
    let mut count = 0usize;
    let mut i = 0usize;
    while i < data.len() {
        if data.at(i).is_ascii_digit()
            && (i == 0 || !data.at(i - 1).is_ascii_digit())
            // `ssn_at` reads the number and the byte after it.
            && ssn_at(&data.range(i, i + width + 1), hyphens)
        {
            count += 1;
            i += width;
        }
        i += 1;
    }
    count
}

/// Count US Social Security numbers in `data` in the requested format(s).
pub fn count_ssns(data: &[u8], mode: SsnMode) -> usize {
    count_ssns_in(&mut Indexed(data), mode)
}

/// [`count_ssns`] over any object.
pub(crate) fn count_ssns_in<B: Bytes>(data: &mut B, mode: SsnMode) -> usize {
    match mode {
        SsnMode::Normal => count_ssn_fmt(data, true),
        SsnMode::Stripped => count_ssn_fmt(data, false),
        SsnMode::Both => count_ssn_fmt(data, true) + count_ssn_fmt(data, false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Public standard test card numbers (widely published sandbox values).
    const VISA: &[u8] = b"4111111111111111";
    const MC: &[u8] = b"5555555555554444";
    const AMEX: &[u8] = b"371449635398431";
    const DISCOVER: &[u8] = b"6011111111111117";

    #[test]
    fn luhn_algorithm() {
        assert!(luhn_valid(b"4111111111111111"));
        assert!(!luhn_valid(b"4111111111111112"));
    }

    #[test]
    fn valid_cards_of_each_network() {
        assert_eq!(count_credit_cards(VISA), 1);
        assert_eq!(count_credit_cards(MC), 1);
        assert_eq!(count_credit_cards(AMEX), 1);
        assert_eq!(count_credit_cards(DISCOVER), 1);
    }

    #[test]
    fn luhn_failure_not_counted() {
        assert_eq!(count_credit_cards(b"4111111111111112"), 0);
    }

    #[test]
    fn non_credit_prefix_not_counted() {
        // A Maestro-range number (500000…) is recognised but not a credit card.
        // 5000000000000009 passes Luhn but sits in the non-credit range.
        assert_eq!(count_credit_cards(b"5000000000000009"), 0);
    }

    #[test]
    fn separators_tolerated() {
        assert_eq!(count_credit_cards(b"4111-1111-1111-1111"), 1);
        assert_eq!(count_credit_cards(b"4111 1111 1111 1111"), 1);
    }

    #[test]
    fn counts_multiple() {
        let mut buf = Vec::new();
        for _ in 0..5 {
            buf.extend_from_slice(VISA);
            buf.push(b'\n');
        }
        assert_eq!(count_credit_cards(&buf), 5);
    }

    #[test]
    fn ssn_normal_and_stripped() {
        assert_eq!(count_ssns(b"123-45-6789", SsnMode::Normal), 1);
        assert_eq!(count_ssns(b"123456789", SsnMode::Stripped), 1);
        // Wrong format for the requested mode isn't counted.
        assert_eq!(count_ssns(b"123-45-6789", SsnMode::Stripped), 0);
    }

    #[test]
    fn ssn_invalid_areas() {
        assert_eq!(count_ssns(b"000-12-3456", SsnMode::Normal), 0);
        assert_eq!(count_ssns(b"666-12-3456", SsnMode::Normal), 0);
        assert_eq!(count_ssns(b"900-12-3456", SsnMode::Normal), 0);
    }

    #[test]
    fn ssn_reserved_and_high_areas_rejected() {
        // The reserved advertising block sits in the never-issued 900-999 area
        // range, so it (and the rest of that range) is rejected.
        assert_eq!(count_ssns(b"987-65-4320", SsnMode::Normal), 0);
        assert_eq!(count_ssns(b"987-65-4329", SsnMode::Normal), 0);
        assert_eq!(count_ssns(b"987-65-4319", SsnMode::Normal), 0);
        // The highest valid area is 899.
        assert_eq!(count_ssns(b"899-65-4319", SsnMode::Normal), 1);
    }

    #[test]
    fn ssn_both_counts_each() {
        assert_eq!(count_ssns(b"123-45-6789 445566778", SsnMode::Both), 2);
    }

    #[test]
    fn no_panic_on_binary() {
        let data: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let _ = count_credit_cards(&data);
        let _ = count_ssns(&data, SsnMode::Both);
    }

    #[test]
    fn integration_structured_cc_verdict() {
        use crate::{analyze, Method, ScanOptions, Scanner, Verdict};
        let db = Scanner::builtin();
        let mut buf = Vec::new();
        for card in [VISA, MC, AMEX, DISCOVER] {
            buf.extend_from_slice(card);
            buf.push(b'\n');
        }
        let opts = ScanOptions {
            structured_cc_count: Some(3),
            ..ScanOptions::default()
        };
        match analyze(&db, &buf, &opts).verdict {
            Verdict::Infected {
                signature, method, ..
            } => {
                assert_eq!(signature, "Heuristics.Structured.CreditCardNumber");
                assert_eq!(method, Method::Heuristic);
            }
            other => panic!("expected CC detection, got {other:?}"),
        }
        let high = ScanOptions {
            structured_cc_count: Some(50),
            ..ScanOptions::default()
        };
        assert!(matches!(analyze(&db, &buf, &high).verdict, Verdict::Clean));
    }

    #[test]
    fn counts_read_in_blocks_are_the_counts_from_memory() {
        use crate::byte_source::{BlockCache, Stepper, CHUNK};
        let plants: &[&[u8]] = &[
            VISA,
            MC,
            AMEX,
            DISCOVER,
            b"4111 1111 1111 1111",
            b"078-05-1120",
            b"123-45-6789",
            b"123456789",
        ];
        let mut state = 0x243F_6A88_85A3_08D3u64;
        let mut data = Vec::new();
        while data.len() < 4 * CHUNK {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            if state.is_multiple_of(7) {
                data.extend_from_slice(plants[(state / 7 % plants.len() as u64) as usize]);
            } else {
                data.push(b"0123456789 -x\n"[(state % 14) as usize]);
            }
        }
        let cache = BlockCache::with_sizes(std::io::Cursor::new(data.clone()), 61, 4 * 61).unwrap();
        let cards = count_credit_cards(&data);
        assert!(cards > 10);
        assert_eq!(count_credit_cards_in(&mut Stepper::new(&cache)), cards);
        for mode in [SsnMode::Normal, SsnMode::Stripped, SsnMode::Both] {
            assert_eq!(
                count_ssns_in(&mut Stepper::new(&cache), mode),
                count_ssns(&data, mode)
            );
        }
    }
}
