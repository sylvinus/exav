// Copyright (c) the JPEG XL Project Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use crate::render::RenderPipelineInPlaceStage;
use jxl_simd::{F32SimdVec, SimdMask, simd_function};

/// Unpremultiply color channels by alpha.
/// This divides RGB values by the alpha channel value.
/// When alpha is 0, the color output is 0 (to avoid division by zero).
#[allow(dead_code)] // Render pipeline stage for unpremultiplied alpha output
pub struct UnpremultiplyAlphaStage {
    /// First color channel index (typically 0 for R)
    first_color_channel: usize,
    /// Number of color channels (typically 3 for RGB)
    num_color_channels: usize,
    /// Alpha channel index
    alpha_channel: usize,
}

impl std::fmt::Display for UnpremultiplyAlphaStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unpremultiply alpha stage for color channels {}-{} with alpha channel {}",
            self.first_color_channel,
            self.first_color_channel + self.num_color_channels - 1,
            self.alpha_channel
        )
    }
}

#[allow(dead_code)]
impl UnpremultiplyAlphaStage {
    pub fn new(
        first_color_channel: usize,
        num_color_channels: usize,
        alpha_channel: usize,
    ) -> Self {
        Self {
            first_color_channel,
            num_color_channels,
            alpha_channel,
        }
    }
}

// SIMD unpremultiply: color = color / alpha (with alpha=0 -> color=0)
simd_function!(
    unpremultiply_rows_simd_dispatch,
    d: D,
    fn unpremultiply_rows_simd(color_rows: &mut [&mut [f32]], alpha_row: &[f32], xsize: usize) {
        let zero = D::F32Vec::splat(d, 0.0);
        let epsilon = D::F32Vec::splat(d, 1e-10); // Small value to detect near-zero alpha

        for color_row in color_rows.iter_mut() {
            let iter_color = color_row.chunks_exact_mut(D::F32Vec::LEN);
            let iter_alpha = alpha_row.chunks_exact(D::F32Vec::LEN);
            for (color_chunk, alpha_chunk) in iter_color.zip(iter_alpha).take(xsize.div_ceil(D::F32Vec::LEN)) {
                let color_vec = D::F32Vec::load(d, color_chunk);
                let alpha_vec = D::F32Vec::load(d, alpha_chunk);

                // Compute color / alpha, but use 0 where alpha is very small
                // This avoids division by zero and matches expected behavior
                let alpha_safe = alpha_vec.max(epsilon);
                let unpremul = color_vec / alpha_safe;

                // Zero out result where alpha was near-zero
                // if_then_else_f32(if_true, if_false): returns if_true where mask is true
                let result = alpha_vec.gt(epsilon).if_then_else_f32(unpremul, zero);

                result.store(color_chunk);
            }
        }
    }
);

impl RenderPipelineInPlaceStage for UnpremultiplyAlphaStage {
    type Type = f32;

    fn uses_channel(&self, c: usize) -> bool {
        (self.first_color_channel..self.first_color_channel + self.num_color_channels).contains(&c)
            || c == self.alpha_channel
    }

    fn process_row_chunk(
        &self,
        _position: (usize, usize),
        xsize: usize,
        row: &mut [&mut [f32]],
        _state: Option<&mut (dyn std::any::Any + Send)>,
    ) {
        // The row slice contains only the channels we said we use.
        // The last channel is alpha (since alpha_channel > color channels).
        let num_channels = row.len();
        if num_channels < 2 {
            return;
        }

        // Alpha is the last channel in the row slice
        let (color_rows, alpha_row) = row.split_at_mut(num_channels - 1);
        let alpha_row = &alpha_row[0][..];

        unpremultiply_rows_simd_dispatch(color_rows, alpha_row, xsize);
    }
}

#[cfg(test)]
mod test {
    use test_log::test;

    use super::*;
    use crate::error::Result;
    use crate::image::Image;
    use crate::render::test::make_and_run_simple_pipeline;
    use crate::util::test::assert_all_almost_abs_eq;

    #[test]
    fn consistency() -> Result<()> {
        crate::render::test::test_stage_consistency(
            || UnpremultiplyAlphaStage::new(0, 3, 3),
            (500, 500),
            4,
        )
    }

    #[test]
    fn unpremultiply_basic() -> Result<()> {
        let mut input_r = Image::new((4, 1))?;
        let mut input_g = Image::new((4, 1))?;
        let mut input_b = Image::new((4, 1))?;
        let mut input_a = Image::new((4, 1))?;

        // Test values: premultiplied colors with varying alpha
        // These are the OUTPUT values from premultiply_basic test
        input_r.row_mut(0).copy_from_slice(&[1.0, 0.5, 0.0, 0.0]);
        input_g.row_mut(0).copy_from_slice(&[0.5, 0.25, 0.0, 0.5]);
        input_b.row_mut(0).copy_from_slice(&[0.0, 0.125, 0.0, 0.25]);
        input_a.row_mut(0).copy_from_slice(&[1.0, 0.5, 0.0, 0.5]);

        let stage = UnpremultiplyAlphaStage::new(0, 3, 3);
        let output = make_and_run_simple_pipeline(
            stage,
            &[input_r, input_g, input_b, input_a],
            (4, 1),
            0,
            256,
        )?;

        // Expected: color / alpha (with alpha=0 -> color=0)
        // Pixel 0: alpha=1.0, so unchanged
        // Pixel 1: alpha=0.5, so double the values
        // Pixel 2: alpha=0.0, so output 0
        // Pixel 3: alpha=0.5, so double the values
        assert_all_almost_abs_eq(output[0].row(0), &[1.0, 1.0, 0.0, 0.0], 1e-6);
        assert_all_almost_abs_eq(output[1].row(0), &[0.5, 0.5, 0.0, 1.0], 1e-6);
        assert_all_almost_abs_eq(output[2].row(0), &[0.0, 0.25, 0.0, 0.5], 1e-6);
        // Alpha unchanged
        assert_all_almost_abs_eq(output[3].row(0), &[1.0, 0.5, 0.0, 0.5], 1e-6);

        Ok(())
    }

    #[test]
    fn unpremultiply_roundtrip() -> Result<()> {
        // Test that premultiply followed by unpremultiply returns original values
        // (except where alpha=0)
        let mut input_r = Image::new((4, 1))?;
        let mut input_g = Image::new((4, 1))?;
        let mut input_b = Image::new((4, 1))?;
        let mut input_a = Image::new((4, 1))?;

        // Original straight alpha values
        input_r.row_mut(0).copy_from_slice(&[1.0, 0.8, 0.5, 0.2]);
        input_g.row_mut(0).copy_from_slice(&[0.5, 0.6, 0.7, 0.3]);
        input_b.row_mut(0).copy_from_slice(&[0.0, 0.4, 0.9, 0.1]);
        input_a.row_mut(0).copy_from_slice(&[1.0, 0.5, 0.25, 0.75]);

        // First premultiply
        let premul_stage = crate::render::stages::PremultiplyAlphaStage::new(0, 3, 3);
        let premul_output = make_and_run_simple_pipeline(
            premul_stage,
            &[input_r, input_g, input_b, input_a],
            (4, 1),
            0,
            256,
        )?;

        // Then unpremultiply
        let unpremul_stage = UnpremultiplyAlphaStage::new(0, 3, 3);
        let final_output =
            make_and_run_simple_pipeline(unpremul_stage, &premul_output, (4, 1), 0, 256)?;

        // Should get back original values
        assert_all_almost_abs_eq(final_output[0].row(0), &[1.0, 0.8, 0.5, 0.2], 1e-5);
        assert_all_almost_abs_eq(final_output[1].row(0), &[0.5, 0.6, 0.7, 0.3], 1e-5);
        assert_all_almost_abs_eq(final_output[2].row(0), &[0.0, 0.4, 0.9, 0.1], 1e-5);
        // Alpha unchanged
        assert_all_almost_abs_eq(final_output[3].row(0), &[1.0, 0.5, 0.25, 0.75], 1e-5);

        Ok(())
    }
}
