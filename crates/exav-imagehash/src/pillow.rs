//! Pillow 12.3.0's resize of an 8-bit grey (`L`) image and its conversions to
//! `L`, ported so that a hash computed the way Python's `imagehash` computes
//! it comes out equal. From `src/PIL/Image.py` (`Image.resize`) and
//! `src/libImaging/Resample.c` and `Convert.c`; Pillow is under the MIT-CMU
//! license, whose text is in `LICENSE-pillow`.

/// A Pillow resampling filter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PillowFilter {
    Box,
    Bilinear,
    Hamming,
    Bicubic,
    Lanczos,
}

impl PillowFilter {
    fn support(self) -> f64 {
        match self {
            PillowFilter::Box => 0.5,
            PillowFilter::Bilinear | PillowFilter::Hamming => 1.0,
            PillowFilter::Bicubic => 2.0,
            PillowFilter::Lanczos => 3.0,
        }
    }

    fn weight(self, x: f64) -> f64 {
        match self {
            PillowFilter::Box => {
                if x > -0.5 && x <= 0.5 {
                    1.0
                } else {
                    0.0
                }
            }
            PillowFilter::Bilinear => {
                let x = x.abs();
                if x < 1.0 {
                    1.0 - x
                } else {
                    0.0
                }
            }
            PillowFilter::Hamming => {
                let x = x.abs();
                if x == 0.0 {
                    1.0
                } else if x >= 1.0 {
                    0.0
                } else {
                    let x = x * std::f64::consts::PI;
                    // `0.54f + 0.46f * cos(x)`: float constants, double cosine.
                    x.sin() / x * (f64::from(0.54f32) + f64::from(0.46f32) * x.cos())
                }
            }
            PillowFilter::Bicubic => {
                const A: f64 = -0.5;
                let x = x.abs();
                if x < 1.0 {
                    ((A + 2.0) * x - (A + 3.0)) * x * x + 1.0
                } else if x < 2.0 {
                    (((x - 5.0) * x + 8.0) * x - 4.0) * A
                } else {
                    0.0
                }
            }
            PillowFilter::Lanczos => {
                if (-3.0..3.0).contains(&x) {
                    sinc(x) * sinc(x / 3.0)
                } else {
                    0.0
                }
            }
        }
    }
}

fn sinc(x: f64) -> f64 {
    if x == 0.0 {
        return 1.0;
    }
    let x = x * std::f64::consts::PI;
    x.sin() / x
}

/// 8 bits for the result, two for overflow and the sign.
const PRECISION_BITS: u32 = 32 - 8 - 2;

fn clip8(v: i32) -> u8 {
    (v >> PRECISION_BITS).clamp(0, 255) as u8
}

/// The weights of one dimension: per output pixel, the first input pixel and
/// how many follow, and `ksize` fixed-point coefficients. They are made one
/// output pixel at a time: all of them together are `ksize` per output pixel,
/// which for a very wide, very short image is many times the image.
struct Axis {
    in_size: i32,
    in0: f32,
    out_size: i32,
    scale: f64,
    support: f64,
    inv_filterscale: f64,
    ksize: usize,
    f: PillowFilter,
}

impl Axis {
    fn new(in_size: i32, in0: f32, in1: f32, out_size: i32, f: PillowFilter) -> Axis {
        let scale = f64::from(in1 - in0) / f64::from(out_size);
        let filterscale = scale.max(1.0);
        let support = f.support() * filterscale;
        Axis {
            in_size,
            in0,
            out_size,
            scale,
            support,
            inv_filterscale: 1.0 / filterscale,
            ksize: (support.ceil() as usize)
                .saturating_mul(2)
                .saturating_add(1),
            f,
        }
    }

    /// Output pixel `xx`: the centre of its window, the first input pixel and
    /// how many follow.
    fn span(&self, xx: i32) -> (f64, i32, i32) {
        let center = f64::from(self.in0) + (f64::from(xx) + 0.5) * self.scale;
        let xmin = ((center - self.support + 0.5) as i32).max(0);
        let xmax = ((center + self.support + 0.5) as i32).min(self.in_size) - xmin;
        (center, xmin, xmax)
    }

    fn bounds(&self, xx: i32) -> (i32, i32) {
        let (_, xmin, xmax) = self.span(xx);
        (xmin, xmax)
    }

    /// The `ksize` fixed-point coefficients of output pixel `xx`, in `k`;
    /// `kk` is scratch.
    fn weights(&self, xx: i32, kk: &mut Vec<f64>, k: &mut Vec<i32>) {
        let (center, xmin, xmax) = self.span(xx);
        kk.clear();
        kk.resize(self.ksize, 0.0);
        let mut ww = 0.0;
        for x in 0..xmax.max(0) {
            let w = self
                .f
                .weight((f64::from(x + xmin) - center + 0.5) * self.inv_filterscale);
            kk[x as usize] = w;
            ww += w;
        }
        if ww != 0.0 {
            for v in kk.iter_mut().take(xmax.max(0) as usize) {
                *v /= ww;
            }
        }
        k.clear();
        k.extend(kk.iter().map(|&v| {
            let s = v * f64::from(1u32 << PRECISION_BITS);
            if v < 0.0 {
                (-0.5 + s) as i32
            } else {
                (0.5 + s) as i32
            }
        }));
    }
}

/// A grey image, row-major.
#[derive(Clone)]
pub(crate) struct Gray {
    pub(crate) width: usize,
    pub(crate) height: usize,
    pub(crate) pixels: Vec<u8>,
}

fn horizontal(input: &Gray, offset: usize, rows: usize, axis: &Axis) -> Gray {
    let width = axis.out_size as usize;
    let mut pixels = vec![0u8; width * rows];
    let (mut kk, mut k) = (Vec::new(), Vec::new());
    for xx in 0..axis.out_size {
        let (xmin, xmax) = axis.bounds(xx);
        axis.weights(xx, &mut kk, &mut k);
        for yy in 0..rows {
            let line = &input.pixels[(yy + offset) * input.width..][..input.width];
            let mut ss: i32 = 1 << (PRECISION_BITS - 1);
            for x in 0..xmax.max(0) as usize {
                ss = ss.wrapping_add(i32::from(line[x + xmin as usize]).wrapping_mul(k[x]));
            }
            pixels[yy * width + xx as usize] = clip8(ss);
        }
    }
    Gray {
        width,
        height: rows,
        pixels,
    }
}

fn vertical(input: &Gray, axis: &Axis, shift: i32) -> Gray {
    let height = axis.out_size as usize;
    let width = input.width;
    let mut pixels = vec![0u8; width * height];
    let (mut kk, mut k) = (Vec::new(), Vec::new());
    for yy in 0..axis.out_size {
        let (ymin, ymax) = axis.bounds(yy);
        let ymin = (ymin - shift) as usize;
        axis.weights(yy, &mut kk, &mut k);
        let yy = yy as usize;
        for xx in 0..width {
            let mut ss: i32 = 1 << (PRECISION_BITS - 1);
            for (y, &ky) in k.iter().enumerate().take(ymax.max(0) as usize) {
                let p = input.pixels[(y + ymin) * width + xx];
                ss = ss.wrapping_add(i32::from(p).wrapping_mul(ky));
            }
            pixels[yy * width + xx] = clip8(ss);
        }
    }
    Gray {
        width,
        height,
        pixels,
    }
}

/// `ImagingResample` (`ImagingResampleInner`) for an 8-bit, one-band image.
fn resample(input: &Gray, xsize: usize, ysize: usize, f: PillowFilter, b: [f32; 4]) -> Gray {
    let need_horizontal = xsize != input.width || b[0] != 0.0 || b[2] != xsize as f32;
    let need_vertical = ysize != input.height || b[1] != 0.0 || b[3] != ysize as f32;
    let vert = Axis::new(input.height as i32, b[1], b[3], ysize as i32, f);
    let ybox_first = vert.bounds(0).0;
    let (last_min, last_len) = vert.bounds(ysize as i32 - 1);
    let ybox_last = last_min + last_len;
    let mut shift = 0;
    let mut current = None;
    if need_horizontal {
        let horiz = Axis::new(input.width as i32, b[0], b[2], xsize as i32, f);
        shift = ybox_first;
        current = Some(horizontal(
            input,
            ybox_first as usize,
            (ybox_last - ybox_first) as usize,
            &horiz,
        ));
    }
    let src = current.as_ref().unwrap_or(input);
    if need_vertical {
        vertical(src, &vert, shift)
    } else {
        src.clone()
    }
}

/// `Image.resize(size, resample)` of an `L` image, with no box and no
/// `reducing_gap`, as `imagehash` calls it.
pub(crate) fn resize(input: &Gray, xsize: usize, ysize: usize, f: PillowFilter) -> Gray {
    let (w, h) = (input.width, input.height);
    if (w, h) == (xsize, ysize) {
        return input.clone();
    }
    let b = [0.0, 0.0, w as f32, h as f32];
    if h > w.saturating_mul(100) && ysize < h {
        let im = resample(input, w, ysize, f, [0.0, b[1], w as f32, b[3]]);
        return resample(&im, xsize, ysize, f, [b[0], 0.0, b[2], ysize as f32]);
    }
    resample(input, xsize, ysize, f, b)
}

/// `rgb2l`: ITU-R 601-2 luma in 16-bit fixed point.
pub(crate) fn l24(r: u8, g: u8, b: u8) -> u8 {
    ((u32::from(r) * 19595 + u32::from(g) * 38470 + u32::from(b) * 7471 + 0x8000) >> 16) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gray(width: usize, height: usize, f: impl Fn(usize, usize) -> u8) -> Gray {
        let pixels = (0..height)
            .flat_map(|y| (0..width).map(move |x| (x, y)))
            .map(|(x, y)| f(x, y))
            .collect();
        Gray {
            width,
            height,
            pixels,
        }
    }

    /// A flat field stays flat at every size, through every filter: the
    /// weights of each output pixel sum to one.
    #[test]
    fn a_flat_field_stays_flat() {
        for f in [
            PillowFilter::Box,
            PillowFilter::Bilinear,
            PillowFilter::Hamming,
            PillowFilter::Bicubic,
            PillowFilter::Lanczos,
        ] {
            for (w, h) in [(97, 61), (32, 32), (5, 700), (3000, 7)] {
                let out = resize(&gray(w, h, |_, _| 137), 32, 32, f);
                assert!(out.pixels.iter().all(|&p| p == 137), "{f:?} {w}x{h}");
            }
        }
    }

    #[test]
    fn rgb2l_rounds_as_pillow() {
        assert_eq!(l24(255, 255, 255), 255);
        assert_eq!(l24(0, 0, 0), 0);
        assert_eq!(l24(255, 0, 0), 76);
        assert_eq!(l24(0, 255, 0), 150);
        assert_eq!(l24(0, 0, 255), 29);
    }
}
