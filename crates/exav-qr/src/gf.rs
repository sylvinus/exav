// Written for exav, in place of the g2p crate rqrr uses for these two fields.

//! The Galois fields of QR codes: GF(2^4) for the format information, GF(2^8)
//! for the codewords. An element is a polynomial over GF(2) held as the bits
//! of a byte, reduced by the field's modulus; `GENERATOR` is `x`.

use std::ops::{Add, AddAssign, Div, Mul, MulAssign};

pub trait GaloisField:
    Copy + PartialEq + AddAssign + Mul<Output = Self> + MulAssign + Div<Output = Self>
{
    const ZERO: Self;
    const ONE: Self;
    const GENERATOR: Self;

    /// `self` to the power `n`; `ONE` for `n` = 0, even for `ZERO`.
    fn pow(self, n: usize) -> Self;
}

/// The powers of the generator and the logarithms of the elements.
struct Tables {
    /// `exp[i]` is `GENERATOR^i`, for two periods of the field, so that the sum
    /// of two logarithms indexes it without a reduction.
    exp: [u8; 2 * 255],
    /// `log[e]` is the `i` below the period with `exp[i] == e`; `log[0]` is unused.
    log: [u8; 256],
}

impl Tables {
    const fn new(bits: u32, modulus: u16) -> Tables {
        let period = (1usize << bits) - 1;
        let mut exp = [0u8; 2 * 255];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        let mut i = 0;
        while i < 2 * period {
            exp[i] = x as u8;
            if i < period {
                log[x as usize] = i as u8;
            }
            x <<= 1;
            if x >> bits != 0 {
                x ^= modulus;
            }
            i += 1;
        }
        Tables { exp, log }
    }
}

macro_rules! field {
    ($name:ident, $bits:expr, $modulus:expr) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub struct $name(pub u8);

        impl $name {
            /// The number of nonzero elements.
            const PERIOD: usize = (1 << $bits) - 1;

            fn tables() -> &'static Tables {
                static TABLES: Tables = Tables::new($bits, $modulus);
                &TABLES
            }
        }

        impl Add for $name {
            type Output = Self;

            // Addition in GF(2^n) is the exclusive or.
            #[allow(clippy::suspicious_arithmetic_impl)]
            fn add(self, rhs: Self) -> Self {
                Self(self.0 ^ rhs.0)
            }
        }

        impl AddAssign for $name {
            fn add_assign(&mut self, rhs: Self) {
                *self = *self + rhs;
            }
        }

        impl Mul for $name {
            type Output = Self;

            fn mul(self, rhs: Self) -> Self {
                if self.0 == 0 || rhs.0 == 0 {
                    return Self(0);
                }
                let t = Self::tables();
                let sum = usize::from(t.log[usize::from(self.0)])
                    + usize::from(t.log[usize::from(rhs.0)]);
                Self(t.exp[sum])
            }
        }

        impl MulAssign for $name {
            fn mul_assign(&mut self, rhs: Self) {
                *self = *self * rhs;
            }
        }

        impl Div for $name {
            type Output = Self;

            /// Panics when `rhs` is zero.
            fn div(self, rhs: Self) -> Self {
                assert!(rhs.0 != 0, "division by zero in {}", stringify!($name));
                if self.0 == 0 {
                    return Self(0);
                }
                let t = Self::tables();
                let sum = usize::from(t.log[usize::from(self.0)]) + Self::PERIOD
                    - usize::from(t.log[usize::from(rhs.0)]);
                Self(t.exp[sum])
            }
        }

        impl GaloisField for $name {
            const ZERO: Self = Self(0);
            const ONE: Self = Self(1);
            const GENERATOR: Self = Self(2);

            fn pow(self, n: usize) -> Self {
                if n == 0 {
                    return Self::ONE;
                }
                if self.0 == 0 {
                    return Self::ZERO;
                }
                let t = Self::tables();
                let log = usize::from(t.log[usize::from(self.0)]);
                Self(t.exp[log * (n % Self::PERIOD) % Self::PERIOD])
            }
        }
    };
}

// x^4 + x + 1
field!(GF16, 4, 0b1_0011);
// x^8 + x^4 + x^3 + x^2 + 1
field!(GF256, 8, 0b1_0001_1101);

#[cfg(test)]
mod tests {
    use super::*;

    /// `a * b` as polynomials over GF(2), reduced by `modulus` as it goes.
    fn schoolbook(mut a: u16, mut b: u16, bits: u32, modulus: u16) -> u8 {
        let mut product = 0;
        while b != 0 {
            if b & 1 != 0 {
                product ^= a;
            }
            b >>= 1;
            a <<= 1;
            if a >> bits != 0 {
                a ^= modulus;
            }
        }
        product as u8
    }

    macro_rules! check_field {
        ($name:ident, $bits:expr, $modulus:expr) => {
            let size = 1u16 << $bits;
            for a in 0..size {
                for b in 0..size {
                    let want = schoolbook(a, b, $bits, $modulus);
                    assert_eq!(($name(a as u8) * $name(b as u8)).0, want);
                    if b != 0 {
                        assert_eq!(($name(want) / $name(b as u8)).0, a as u8);
                    }
                }
            }
            // The generator reaches every nonzero element, once per period.
            let mut seen = vec![false; size as usize];
            for i in 0..usize::from(size - 1) {
                let p = $name::GENERATOR.pow(i);
                assert!(!seen[usize::from(p.0)]);
                seen[usize::from(p.0)] = true;
            }
            assert_eq!($name::GENERATOR.pow(usize::from(size - 1)), $name::ONE);
            assert_eq!($name::ZERO.pow(0), $name::ONE);
            assert_eq!($name::ZERO.pow(5), $name::ZERO);
        };
    }

    #[test]
    fn field_arithmetic() {
        check_field!(GF16, 4, 0b1_0011);
        check_field!(GF256, 8, 0b1_0001_1101);
        // x^4 = x + 1 and x^8 = x^4 + x^3 + x^2 + 1, the moduli.
        assert_eq!(GF16::GENERATOR.pow(4), GF16(0b0011));
        assert_eq!(GF256::GENERATOR.pow(8), GF256(0x1d));
    }
}
