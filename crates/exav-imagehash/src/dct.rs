//! The unnormalised DCT-II, `X[k] = Σ x[m]·cos(π(2m+1)k / 2n)`, in safe Rust.
//!
//! For a power of two and for 3, this is rustdct 0.7.1's algorithm: its
//! split radix (`algorithm/type2and3_splitradix.rs`) over its kernels for 2,
//! 3, 4, 8 and 16 (`algorithm/type2and3_butterflies.rs`), with the same
//! twiddles and the same operations in the same order, so the coefficients
//! are rustdct's to the bit. Upstream skips bounds checks with `unsafe`; here
//! they stay. rustdct is MIT OR Apache-2.0, used under the MIT License
//! (`LICENSE-rustdct`).
//!
//! Any other length, which rustdct hands to rustfft, goes through Makhoul's
//! reordering and a Bluestein FFT instead: the same transform, rounded
//! differently.

use std::f64::consts::PI;
use std::ops::{Add, Mul, Neg, Sub};

/// The float types the DCT runs in.
pub(crate) trait Real:
    Copy + Add<Output = Self> + Sub<Output = Self> + Mul<Output = Self> + Neg<Output = Self>
{
    const ZERO: Self;
    const FRAC_1_SQRT_2: Self;
    fn from_f64(v: f64) -> Self;
}

impl Real for f32 {
    const ZERO: f32 = 0.0;
    const FRAC_1_SQRT_2: f32 = std::f32::consts::FRAC_1_SQRT_2;
    fn from_f64(v: f64) -> f32 {
        v as f32
    }
}

impl Real for f64 {
    const ZERO: f64 = 0.0;
    const FRAC_1_SQRT_2: f64 = std::f64::consts::FRAC_1_SQRT_2;
    fn from_f64(v: f64) -> f64 {
        v
    }
}

#[derive(Clone, Copy)]
struct Complex<T> {
    re: T,
    im: T,
}

impl<T: Real> Add for Complex<T> {
    type Output = Self;
    fn add(self, o: Self) -> Self {
        Complex {
            re: self.re + o.re,
            im: self.im + o.im,
        }
    }
}

impl<T: Real> Sub for Complex<T> {
    type Output = Self;
    fn sub(self, o: Self) -> Self {
        Complex {
            re: self.re - o.re,
            im: self.im - o.im,
        }
    }
}

impl<T: Real> Mul for Complex<T> {
    type Output = Self;
    fn mul(self, o: Self) -> Self {
        Complex {
            re: self.re * o.re - self.im * o.im,
            im: self.re * o.im + self.im * o.re,
        }
    }
}

impl<T: Real> Complex<T> {
    const ZERO: Self = Complex {
        re: T::ZERO,
        im: T::ZERO,
    };

    fn conj(self) -> Self {
        Complex {
            re: self.re,
            im: -self.im,
        }
    }
}

/// `e^(-2πi·i/len)`, computed as rustdct's `single_twiddle` computes it.
fn twiddle_angle(i: usize, len: usize) -> f64 {
    PI * -2f64 / len as f64 * i as f64
}

/// rustdct's `single_twiddle(i, len).conj()`.
fn twiddle_conj<T: Real>(i: usize, len: usize) -> Complex<T> {
    let a = twiddle_angle(i, len);
    Complex {
        re: T::from_f64(a.cos()),
        im: -T::from_f64(a.sin()),
    }
}

/// A DCT-II of one length, planned as rustdct's `DctPlanner::plan_dct2` plans it.
pub(crate) struct Dct2<T> {
    len: usize,
    kind: Kind<T>,
}

enum Kind<T> {
    B2,
    B3(T),
    B4(Butterfly4<T>),
    B8(Butterfly8<T>),
    B16(Butterfly16<T>),
    SplitRadix {
        half: Box<Dct2<T>>,
        quarter: Box<Dct2<T>>,
        twiddles: Vec<Complex<T>>,
    },
    Fft(Makhoul<T>),
}

impl<T: Real> Dct2<T> {
    pub(crate) fn new(len: usize) -> Self {
        let kind = match len {
            2 => Kind::B2,
            3 => Kind::B3(T::from_f64(twiddle_angle(1, 12).cos())),
            4 => Kind::B4(Butterfly4::new()),
            8 => Kind::B8(Butterfly8::new()),
            16 => Kind::B16(Butterfly16::new()),
            _ if len.is_power_of_two() && len > 2 => Kind::SplitRadix {
                half: Box::new(Dct2::new(len / 2)),
                quarter: Box::new(Dct2::new(len / 4)),
                twiddles: (0..len / 4)
                    .map(|i| twiddle_conj(2 * i + 1, len * 4))
                    .collect(),
            },
            _ => Kind::Fft(Makhoul::new(len)),
        };
        Dct2 { len, kind }
    }

    /// Transforms `buf` in place; `scratch` is at least as long.
    pub(crate) fn process(&self, buf: &mut [T], scratch: &mut [T]) {
        assert_eq!(buf.len(), self.len);
        match &self.kind {
            Kind::B2 => butterfly2_dct2(buf, 0, 1),
            Kind::B3(twiddle) => {
                let (b0, b1, b2) = (buf[0], buf[1], buf[2]);
                buf[0] = b0 + b1 + b2;
                buf[1] = (b0 - b2) * *twiddle;
                buf[2] = (b0 + b2) * T::from_f64(0.5) - b1;
            }
            Kind::B4(b) => b.dct2(buf),
            Kind::B8(b) => b.dct2(buf),
            Kind::B16(b) => b.dct2(buf),
            Kind::SplitRadix {
                half,
                quarter,
                twiddles,
            } => split_radix(buf, &mut scratch[..self.len], half, quarter, twiddles),
            Kind::Fft(m) => m.dct2(buf),
        }
    }
}

fn butterfly2_dct2<T: Real>(b: &mut [T], zero: usize, one: usize) {
    let sum = b[zero] + b[one];
    b[one] = (b[zero] - b[one]) * T::FRAC_1_SQRT_2;
    b[zero] = sum;
}

fn butterfly2_dst2<T: Real>(b: &mut [T]) {
    let sum = b[0] - b[1];
    b[0] = (b[0] + b[1]) * T::FRAC_1_SQRT_2;
    b[1] = sum;
}

struct Butterfly4<T> {
    twiddle: Complex<T>,
}

impl<T: Real> Butterfly4<T> {
    fn new() -> Self {
        Butterfly4 {
            twiddle: twiddle_conj(1, 16),
        }
    }

    fn dct2(&self, b: &mut [T]) {
        let lower_dct4 = b[0] - b[3];
        let upper_dct4 = b[2] - b[1];
        b[0] = b[0] + b[3];
        b[2] = b[2] + b[1];
        butterfly2_dct2(b, 0, 2);
        b[1] = lower_dct4 * self.twiddle.re - upper_dct4 * self.twiddle.im;
        b[3] = upper_dct4 * self.twiddle.re + lower_dct4 * self.twiddle.im;
    }

    fn dst2(&self, b: &mut [T]) {
        let lower_dct4 = b[0] + b[3];
        let upper_dct4 = b[2] + b[1];
        b[3] = b[0] - b[3];
        b[1] = b[2] - b[1];
        butterfly2_dct2(b, 3, 1);
        b[2] = lower_dct4 * self.twiddle.re - upper_dct4 * self.twiddle.im;
        b[0] = upper_dct4 * self.twiddle.re + lower_dct4 * self.twiddle.im;
    }
}

struct Butterfly8<T> {
    butterfly4: Butterfly4<T>,
    twiddles: [Complex<T>; 2],
}

impl<T: Real> Butterfly8<T> {
    fn new() -> Self {
        Butterfly8 {
            butterfly4: Butterfly4::new(),
            twiddles: [twiddle_conj(1, 32), twiddle_conj(3, 32)],
        }
    }

    fn dct2(&self, b: &mut [T]) {
        let mut dct2_buffer = [b[0] + b[7], b[1] + b[6], b[2] + b[5], b[3] + b[4]];
        self.butterfly4.dct2(&mut dct2_buffer);

        let d = [b[0] - b[7], b[3] - b[4], b[1] - b[6], b[2] - b[5]];
        let t = &self.twiddles;
        let mut dct4_even = [
            d[0] * t[0].re + d[1] * t[0].im,
            d[2] * t[1].re + d[3] * t[1].im,
        ];
        let mut dct4_odd = [
            d[3] * t[1].re - d[2] * t[1].im,
            d[1] * t[0].re - d[0] * t[0].im,
        ];
        butterfly2_dct2(&mut dct4_even, 0, 1);
        butterfly2_dst2(&mut dct4_odd);

        b[0] = dct2_buffer[0];
        b[1] = dct4_even[0];
        b[2] = dct2_buffer[1];
        b[3] = dct4_even[1] - dct4_odd[0];
        b[4] = dct2_buffer[2];
        b[5] = dct4_even[1] + dct4_odd[0];
        b[6] = dct2_buffer[3];
        b[7] = dct4_odd[1];
    }
}

struct Butterfly16<T> {
    butterfly8: Butterfly8<T>,
    butterfly4: Butterfly4<T>,
    twiddles: [Complex<T>; 4],
}

impl<T: Real> Butterfly16<T> {
    fn new() -> Self {
        Butterfly16 {
            butterfly8: Butterfly8::new(),
            butterfly4: Butterfly4::new(),
            twiddles: [
                twiddle_conj(1, 64),
                twiddle_conj(3, 64),
                twiddle_conj(5, 64),
                twiddle_conj(7, 64),
            ],
        }
    }

    fn dct2(&self, b: &mut [T]) {
        let mut dct2_buffer = [
            b[0] + b[15],
            b[1] + b[14],
            b[2] + b[13],
            b[3] + b[12],
            b[4] + b[11],
            b[5] + b[10],
            b[6] + b[9],
            b[7] + b[8],
        ];
        self.butterfly8.dct2(&mut dct2_buffer);

        let d = [
            b[0] - b[15],
            b[7] - b[8],
            b[1] - b[14],
            b[6] - b[9],
            b[2] - b[13],
            b[5] - b[10],
            b[3] - b[12],
            b[4] - b[11],
        ];
        let t = &self.twiddles;
        let mut dct4_even = [
            d[0] * t[0].re + d[1] * t[0].im,
            d[2] * t[1].re + d[3] * t[1].im,
            d[4] * t[2].re + d[5] * t[2].im,
            d[6] * t[3].re + d[7] * t[3].im,
        ];
        let mut dct4_odd = [
            d[7] * t[3].re - d[6] * t[3].im,
            d[5] * t[2].re - d[4] * t[2].im,
            d[3] * t[1].re - d[2] * t[1].im,
            d[1] * t[0].re - d[0] * t[0].im,
        ];
        self.butterfly4.dct2(&mut dct4_even);
        self.butterfly4.dst2(&mut dct4_odd);

        b[0] = dct2_buffer[0];
        b[1] = dct4_even[0];
        b[2] = dct2_buffer[1];
        b[3] = dct4_even[1] - dct4_odd[0];
        b[4] = dct2_buffer[2];
        b[5] = dct4_even[1] + dct4_odd[0];
        b[6] = dct2_buffer[3];
        b[7] = dct4_even[2] + dct4_odd[1];
        b[8] = dct2_buffer[4];
        b[9] = dct4_even[2] - dct4_odd[1];
        b[10] = dct2_buffer[5];
        b[11] = dct4_even[3] - dct4_odd[2];
        b[12] = dct2_buffer[6];
        b[13] = dct4_even[3] + dct4_odd[2];
        b[14] = dct2_buffer[7];
        b[15] = dct4_odd[3];
    }
}

/// One split-radix step: a DCT-II of half the length on the sums, two of a
/// quarter on the twiddled differences, recombined.
fn split_radix<T: Real>(
    buf: &mut [T],
    scratch: &mut [T],
    half: &Dct2<T>,
    quarter: &Dct2<T>,
    twiddles: &[Complex<T>],
) {
    let len = buf.len();
    let half_len = len / 2;
    let quarter_len = len / 4;

    let (input_dct2, input_dct4) = scratch.split_at_mut(half_len);
    let (input_dct4_even, input_dct4_odd) = input_dct4.split_at_mut(quarter_len);

    for i in 0..quarter_len {
        let input_bottom = buf[i];
        let input_top = buf[len - i - 1];
        let input_half_bottom = buf[half_len - i - 1];
        let input_half_top = buf[half_len + i];

        input_dct2[i] = input_top + input_bottom;
        input_dct2[half_len - i - 1] = input_half_bottom + input_half_top;

        let lower_dct4 = input_bottom - input_top;
        let upper_dct4 = input_half_bottom - input_half_top;
        let twiddle = twiddles[i];
        let cos_input = lower_dct4 * twiddle.re + upper_dct4 * twiddle.im;
        let sin_input = upper_dct4 * twiddle.re - lower_dct4 * twiddle.im;

        input_dct4_even[i] = cos_input;
        input_dct4_odd[quarter_len - i - 1] = if i.is_multiple_of(2) {
            sin_input
        } else {
            -sin_input
        };
    }

    // The original buffer is the inner transforms' scratch.
    half.process(input_dct2, buf);
    quarter.process(input_dct4_even, buf);
    quarter.process(input_dct4_odd, buf);

    buf[0] = input_dct2[0];
    buf[1] = input_dct4_even[0];
    buf[2] = input_dct2[1];
    for i in 1..quarter_len {
        let dct4_cos_output = input_dct4_even[i];
        let dct4_sin_output = if (i + quarter_len).is_multiple_of(2) {
            -input_dct4_odd[quarter_len - i]
        } else {
            input_dct4_odd[quarter_len - i]
        };
        buf[i * 4 - 1] = dct4_cos_output + dct4_sin_output;
        buf[i * 4] = input_dct2[i * 2];
        buf[i * 4 + 1] = dct4_cos_output - dct4_sin_output;
        buf[i * 4 + 2] = input_dct2[i * 2 + 1];
    }
    buf[len - 1] = -input_dct4_odd[0];
}

/// The DCT-II of any length as one complex DFT of that length (Makhoul): the
/// even samples in order, then the odd ones reversed, transformed, and each
/// output turned by `e^(-iπk/2n)`.
///
/// The first sample is taken off every sample beforehand: a constant's AC
/// terms are exactly zero, so this changes none of them, and a flat row
/// then gives exact zeros rather than the FFT's rounding noise. The DC term
/// is the plain sum.
struct Makhoul<T> {
    dft: Bluestein<T>,
    post: Vec<Complex<T>>,
}

impl<T: Real> Makhoul<T> {
    fn new(n: usize) -> Self {
        let post = (0..n)
            .map(|k| {
                let a = PI * k as f64 / (2 * n) as f64;
                Complex {
                    re: T::from_f64(a.cos()),
                    im: T::from_f64(a.sin()),
                }
            })
            .collect();
        Makhoul {
            dft: Bluestein::new(n),
            post,
        }
    }

    fn dct2(&self, buf: &mut [T]) {
        let n = buf.len();
        let first = buf[0];
        let sum = buf.iter().fold(T::ZERO, |s, &x| s + x);
        let mut v = vec![Complex::ZERO; n];
        for (m, &x) in buf.iter().enumerate() {
            let at = if m.is_multiple_of(2) {
                m / 2
            } else {
                n - 1 - m / 2
            };
            v[at].re = x - first;
        }
        let v = self.dft.dft(&v);
        for ((out, v), p) in buf.iter_mut().zip(v).zip(&self.post) {
            *out = v.re * p.re + v.im * p.im;
        }
        buf[0] = sum;
    }
}

/// A DFT of any length `n` as a circular convolution with a chirp, done by
/// power-of-two FFTs of at least `2n - 1` points.
struct Bluestein<T> {
    chirp: Vec<Complex<T>>,
    /// The FFT of the conjugate chirp, laid out for the convolution.
    kernel: Vec<Complex<T>>,
    fft: Radix2<T>,
}

impl<T: Real> Bluestein<T> {
    fn new(n: usize) -> Self {
        // `e^(-iπj²/n)`, with `j²` reduced mod `2n` so the angle stays small.
        let chirp: Vec<Complex<T>> = (0..n as u64)
            .map(|j| {
                let a = -PI * ((j * j) % (2 * n as u64)) as f64 / n as f64;
                Complex {
                    re: T::from_f64(a.cos()),
                    im: T::from_f64(a.sin()),
                }
            })
            .collect();
        let m = (2 * n - 1).next_power_of_two();
        let fft = Radix2::new(m);
        let mut kernel = vec![Complex::ZERO; m];
        for (j, c) in chirp.iter().enumerate() {
            kernel[j] = c.conj();
            if j > 0 {
                kernel[m - j] = c.conj();
            }
        }
        fft.run(&mut kernel, false);
        Bluestein { chirp, kernel, fft }
    }

    fn dft(&self, x: &[Complex<T>]) -> Vec<Complex<T>> {
        let m = self.kernel.len();
        let mut a = vec![Complex::ZERO; m];
        for ((a, &x), &c) in a.iter_mut().zip(x).zip(&self.chirp) {
            *a = x * c;
        }
        self.fft.run(&mut a, false);
        for (a, &k) in a.iter_mut().zip(&self.kernel) {
            *a = *a * k;
        }
        self.fft.run(&mut a, true);
        let scale = T::from_f64(1.0 / m as f64);
        a.iter()
            .zip(&self.chirp)
            .map(|(&a, &c)| {
                let a = a * c;
                Complex {
                    re: a.re * scale,
                    im: a.im * scale,
                }
            })
            .collect()
    }
}

/// An in-place iterative radix-2 FFT of a power-of-two length.
struct Radix2<T> {
    /// `e^(-2πik/m)` for `k < m/2`.
    twiddles: Vec<Complex<T>>,
}

impl<T: Real> Radix2<T> {
    fn new(m: usize) -> Self {
        let twiddles = (0..m / 2)
            .map(|k| {
                let a = -2.0 * PI * k as f64 / m as f64;
                Complex {
                    re: T::from_f64(a.cos()),
                    im: T::from_f64(a.sin()),
                }
            })
            .collect();
        Radix2 { twiddles }
    }

    /// Forward, or unscaled inverse.
    fn run(&self, a: &mut [Complex<T>], inverse: bool) {
        let m = a.len();
        let mut j = 0;
        for i in 1..m {
            let mut bit = m >> 1;
            while j & bit != 0 {
                j ^= bit;
                bit >>= 1;
            }
            j |= bit;
            if i < j {
                a.swap(i, j);
            }
        }
        let mut len = 2;
        while len <= m {
            let step = m / len;
            for start in (0..m).step_by(len) {
                for k in 0..len / 2 {
                    let w = self.twiddles[k * step];
                    let w = if inverse { w.conj() } else { w };
                    let u = a[start + k];
                    let v = a[start + k + len / 2] * w;
                    a[start + k] = u + v;
                    a[start + k + len / 2] = u - v;
                }
            }
            len <<= 1;
        }
    }
}

/// In-place 2-D DCT-II of an `n × n` row-major buffer: the columns, then the
/// rows, each pass scaled by 2 (`scipy.fftpack.dct`'s unnormalised scale).
pub(crate) fn dct2d<T: Real>(buf: &mut [T], n: usize) {
    let dct = Dct2::new(n);
    let two = T::from_f64(2.0);
    let mut t = vec![T::ZERO; n * n];
    let mut scratch = vec![T::ZERO; n];
    transpose(buf, &mut t, n);
    for row in t.chunks_mut(n) {
        dct.process(row, &mut scratch);
        for v in row {
            *v = *v * two;
        }
    }
    transpose(&t, buf, n);
    for row in buf.chunks_mut(n) {
        dct.process(row, &mut scratch);
        for v in row {
            *v = *v * two;
        }
    }
}

/// `n × n`, in tiles so that a large side stays in cache.
fn transpose<T: Copy>(from: &[T], to: &mut [T], n: usize) {
    const TILE: usize = 16;
    for r0 in (0..n).step_by(TILE) {
        for c0 in (0..n).step_by(TILE) {
            for r in r0..(r0 + TILE).min(n) {
                for c in c0..(c0 + TILE).min(n) {
                    to[c * n + r] = from[r * n + c];
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic values in `-1..1`.
    fn input(n: usize, seed: u64) -> Vec<f64> {
        let mut s = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        (0..n)
            .map(|_| {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                (s >> 11) as f64 / (1u64 << 52) as f64 - 1.0
            })
            .collect()
    }

    fn ours<T: Real>(x: &[T]) -> Vec<T> {
        let mut v = x.to_vec();
        let mut scratch = v.clone();
        Dct2::new(v.len()).process(&mut v, &mut scratch);
        v
    }

    fn theirs<T: rustdct::DctNum>(x: &[T]) -> Vec<T> {
        let mut v = x.to_vec();
        rustdct::DctPlanner::new()
            .plan_dct2(v.len())
            .process_dct2(&mut v);
        v
    }

    /// Where rustdct does not go to rustfft, the coefficients are its own.
    #[test]
    fn rustdcts_lengths_are_rustdct_to_the_bit() {
        let lens = [2, 3, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096];
        for (seed, &n) in lens.iter().enumerate() {
            let x = input(n, seed as u64);
            let x32: Vec<f32> = x.iter().map(|&v| v as f32).collect();
            let bits = |v: Vec<f64>| v.into_iter().map(f64::to_bits).collect::<Vec<_>>();
            let bits32 = |v: Vec<f32>| v.into_iter().map(f32::to_bits).collect::<Vec<_>>();
            assert_eq!(bits(ours(&x)), bits(theirs(&x)), "f64, {n}");
            assert_eq!(bits32(ours(&x32)), bits32(theirs(&x32)), "f32, {n}");
        }
    }

    /// A flat row has no AC term at all, not rounding noise, which the
    /// median threshold would turn into bits.
    #[test]
    fn a_flat_row_has_no_ac_at_any_length() {
        for n in (1..=70).chain([100, 255, 1000, 4095, 4096]) {
            let x = vec![0.3137f64; n];
            assert!(ours(&x)[1..].iter().all(|&v| v == 0.0), "f64, {n}");
            let x = vec![0.3137f32; n];
            assert!(ours(&x)[1..].iter().all(|&v| v == 0.0), "f32, {n}");
        }
    }

    /// Elsewhere they are the same transform, within rounding.
    #[test]
    fn other_lengths_are_rustdct_within_rounding() {
        let lens = (1..=70).filter(|n: &usize| !n.is_power_of_two() && *n != 3);
        for (seed, n) in lens.chain([100, 255, 1000, 4095]).enumerate() {
            let x = input(n, seed as u64 + 100);
            let x32: Vec<f32> = x.iter().map(|&v| v as f32).collect();
            let scale: f64 = x.iter().map(|v| v.abs()).sum();
            let worst = |a: &[f64], b: &[f64]| {
                a.iter()
                    .zip(b)
                    .map(|(a, b)| (a - b).abs())
                    .fold(0.0, f64::max)
                    / scale
            };
            assert!(worst(&ours(&x), &theirs(&x)) < 1e-13, "f64, {n}");
            let (a, b): (Vec<f64>, Vec<f64>) = (
                ours(&x32).into_iter().map(f64::from).collect(),
                theirs(&x32).into_iter().map(f64::from).collect(),
            );
            assert!(worst(&a, &b) < 1e-5, "f32, {n}");
        }
    }
}
