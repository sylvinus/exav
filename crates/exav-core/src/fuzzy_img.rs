//! Image perceptual hashing for the `fuzzy_img#<hash>` logical subsignature
//! format.
//!
//! A `fuzzy_img#<16-hex>` subsig matches a 64-bit DCT-based perceptual image
//! hash — the Python `imagehash` `phash()` *median* variant — computed over
//! decoded image pixels, by exact 64-bit equality (the signature format
//! supports only Hamming distance 0). To reproduce the hash byte-exactly we run
//! the canonical pure-Rust pipeline: the `image` crate for decode + Lanczos3
//! resize and `rustdct`/`transpose` for the 2-D DCT-II. The algorithm
//! (grayscale coefficients, ×2 per-DCT-pass scale, low-frequency block, median
//! threshold, MSB-first bit packing) is implemented from a behavioural
//! specification of the imagehash phash, not from any reference implementation's
//! source.
//!
//! Pipeline (see the spec for exact arithmetic):
//!   decode → RGB8 (drop alpha) → BT.601 grayscale (round) → resize_exact 32×32
//!   Lanczos3 (stretch) → luma/255 f32 → 2-D DCT-II (×2 per pass) → top-left 8×8
//!   (DC included) → median threshold (strict `>`) → MSB-first pack → 8 bytes.

use image::{imageops::FilterType, DynamicImage, GrayImage};

/// Cheap magic-byte gate: does this buffer plausibly start an image the `image`
/// crate can decode? Avoids invoking the full decoder on non-image content on
/// every scanned object. Covers the formats the fuzzy-hash signatures target
/// (PNG/GIF/JPEG/TIFF) plus the common "graphics" bucket (BMP/WebP).
pub fn looks_like_image(d: &[u8]) -> bool {
    d.len() >= 12
        && (d.starts_with(b"\x89PNG\r\n\x1a\n")          // PNG
            || d.starts_with(b"GIF87a")
            || d.starts_with(b"GIF89a")
            || d.starts_with(&[0xFF, 0xD8, 0xFF])         // JPEG
            || d.starts_with(b"II*\x00")                  // TIFF little-endian
            || d.starts_with(b"MM\x00*")                  // TIFF big-endian
            || d.starts_with(b"BM")                       // BMP
            || (d.starts_with(b"RIFF") && &d[8..12] == b"WEBP"))
}

/// Compute the 64-bit `fuzzy_img` perceptual hash of an encoded image.
/// Returns `None` if the bytes don't decode as an image (non-fatal — the hash
/// is simply skipped and the scan continues).
pub fn phash(data: &[u8]) -> Option<[u8; 8]> {
    let img = image::load_from_memory(data).ok()?;
    let rgb = img.to_rgb8();
    let (w, h) = rgb.dimensions();
    if w == 0 || h == 0 {
        return None;
    }

    // BT.601 luma, round half away from zero — NOT the image crate's grayscale
    // (which uses different coefficients).
    let mut gray = GrayImage::new(w, h);
    for (src, dst) in rgb.pixels().zip(gray.pixels_mut()) {
        let [r, g, b] = src.0;
        let luma = 0.299_f32 * r as f32 + 0.587_f32 * g as f32 + 0.114_f32 * b as f32;
        dst.0[0] = luma.round() as u8;
    }

    // Stretch to exactly 32×32 with Lanczos3 (no aspect preservation), then to
    // f32 in [0,1] via luma/255 (what `to_luma32f` does).
    let small = DynamicImage::ImageLuma8(gray).resize_exact(32, 32, FilterType::Lanczos3);
    let lf = small.to_luma32f();
    let mut buf: Vec<f32> = lf.pixels().map(|p| p.0[0]).collect();
    debug_assert_eq!(buf.len(), 32 * 32);

    dct2d_32(&mut buf);

    // Top-left 8×8 low-frequency block (DC term included), row-major.
    let mut low = [0f32; 64];
    for v in 0..8 {
        for u in 0..8 {
            low[v * 8 + u] = buf[v * 32 + u];
        }
    }

    // Median = mean of the two central elements of the 64 sorted values.
    let mut sorted = low;
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let median = (sorted[31] + sorted[32]) / 2.0;

    // Bit set iff value strictly greater than the median; packed MSB-first
    // within each byte (low-freq index 0 = MSB of byte 0).
    let mut out = [0u8; 8];
    for (idx, &val) in low.iter().enumerate() {
        if val > median {
            out[idx / 8] |= 1 << (7 - (idx % 8));
        }
    }
    Some(out)
}

/// In-place separable 2-D DCT-II over a 32×32 row-major f32 buffer, with the ×2
/// post-scaling after each 1-D pass (total ×4) the imagehash phash applies
/// (the `scipy.fftpack.dct` normalisation). Magnitudes don't affect the median
/// threshold, but we replicate it for fidelity.
fn dct2d_32(buf: &mut [f32]) {
    use rustdct::DctPlanner;
    let dct = DctPlanner::new().plan_dct2(32);
    let mut scratch = vec![0f32; 32 * 32];

    // DCT the columns: transpose so columns become contiguous rows, transform.
    transpose::transpose(buf, &mut scratch, 32, 32);
    for row in scratch.chunks_mut(32) {
        dct.process_dct2(row);
        for v in row {
            *v *= 2.0;
        }
    }
    // DCT the rows: transpose back, transform.
    transpose::transpose(&scratch, buf, 32, 32);
    for row in buf.chunks_mut(32) {
        dct.process_dct2(row);
        for v in row {
            *v *= 2.0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn solid_png(w: u32, h: u32, rgb: [u8; 3]) -> Vec<u8> {
        let img = image::RgbImage::from_pixel(w, h, image::Rgb(rgb));
        let mut out = std::io::Cursor::new(Vec::new());
        image::DynamicImage::ImageRgb8(img)
            .write_to(&mut out, image::ImageFormat::Png)
            .unwrap();
        out.into_inner()
    }

    fn hex(h: [u8; 8]) -> String {
        h.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn solid_nonblack_is_dc_only() {
        // A flat non-black field: only the DC coefficient is positive, the median
        // is 0, so only bit 0 (MSB of byte 0) is set ⇒ 0x80,0,0,... (decoder-
        // independent anchor from the spec).
        for color in [
            [255, 255, 255],
            [128, 128, 128],
            [200, 30, 30],
            [10, 10, 200],
        ] {
            let png = solid_png(64, 64, color);
            assert_eq!(
                hex(phash(&png).unwrap()),
                "8000000000000000",
                "color {color:?}"
            );
        }
    }

    #[test]
    fn solid_black_is_all_zero() {
        let png = solid_png(64, 64, [0, 0, 0]);
        assert_eq!(hex(phash(&png).unwrap()), "0000000000000000");
    }

    #[test]
    fn non_image_returns_none() {
        assert!(phash(b"not an image at all, just text bytes").is_none());
        assert!(!looks_like_image(b"MZ\x90\x00 a PE not an image"));
        assert!(looks_like_image(&solid_png(8, 8, [1, 2, 3])));
    }
}
