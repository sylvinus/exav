// Copyright (c) the JPEG XL Project Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Black (K) channel stage for CMYK to RGB conversion.
//!
//! In JPEG XL CMYK images, the CMY channels are stored as the first 3 color channels
//! (like RGB), and the K (black) channel is stored as an extra channel of type Black.
//!
//! The values follow the convention: 0 = max ink, 1 = no ink (for normalized values).
//! To convert CMYK to RGB: R = C * K, G = M * K, B = Y * K (all normalized to [0, 1]).

use crate::render::RenderPipelineInPlaceStage;

/// Applies the Black (K) channel to CMY channels to produce RGB output.
///
/// This stage multiplies each CMY channel by the K channel value, which converts
/// CMYK to RGB. The K channel is consumed (set to 1.0) after application.
pub struct BlackChannelStage {
    /// Black channel index (offset from 3)
    black_c: usize,
}

impl std::fmt::Display for BlackChannelStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "black channel stage for channel {}", self.black_c)
    }
}

impl BlackChannelStage {
    pub fn new(black_c_offset: usize) -> Self {
        Self {
            black_c: 3 + black_c_offset,
        }
    }
}

impl RenderPipelineInPlaceStage for BlackChannelStage {
    type Type = f32;

    fn uses_channel(&self, c: usize) -> bool {
        c < 3 || c == self.black_c
    }

    fn process_row_chunk(
        &self,
        _position: (usize, usize),
        xsize: usize,
        row: &mut [&mut [f32]],
        _state: Option<&mut (dyn std::any::Any + Send)>,
    ) {
        let [row_c, row_m, row_y, row_k] = row else {
            panic!(
                "incorrect number of channels; expected 4, found {}",
                row.len()
            );
        };

        assert!(
            xsize <= row_c.len()
                && xsize <= row_m.len()
                && xsize <= row_y.len()
                && xsize <= row_k.len()
        );

        // CMYK to RGB: R = C * K, G = M * K, B = Y * K
        // Where C, M, Y, K are all in [0, 1] with 1 = no ink
        for idx in 0..xsize {
            let k = row_k[idx];
            row_c[idx] *= k;
            row_m[idx] *= k;
            row_y[idx] *= k;
        }
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
        crate::render::test::test_stage_consistency(|| BlackChannelStage::new(0), (500, 500), 4)
    }

    #[test]
    fn cmyk_to_rgb_white() -> Result<()> {
        // Pure white: CMY = 1 (no ink), K = 1 (no black)
        let mut input_c = Image::new((3, 1))?;
        let mut input_m = Image::new((3, 1))?;
        let mut input_y = Image::new((3, 1))?;
        let mut input_k = Image::new((3, 1))?;
        input_c.row_mut(0).copy_from_slice(&[1.0, 1.0, 1.0]);
        input_m.row_mut(0).copy_from_slice(&[1.0, 1.0, 1.0]);
        input_y.row_mut(0).copy_from_slice(&[1.0, 1.0, 1.0]);
        input_k.row_mut(0).copy_from_slice(&[1.0, 1.0, 1.0]);

        let stage = BlackChannelStage::new(0);
        let output = make_and_run_simple_pipeline(
            stage,
            &[input_c, input_m, input_y, input_k],
            (3, 1),
            0,
            256,
        )?;

        // White stays white
        assert_all_almost_abs_eq(output[0].row(0), &[1.0, 1.0, 1.0], 1e-6);
        assert_all_almost_abs_eq(output[1].row(0), &[1.0, 1.0, 1.0], 1e-6);
        assert_all_almost_abs_eq(output[2].row(0), &[1.0, 1.0, 1.0], 1e-6);

        Ok(())
    }

    #[test]
    fn cmyk_to_rgb_black() -> Result<()> {
        // Pure black: CMY = 1 (no ink), K = 0 (full black)
        let mut input_c = Image::new((3, 1))?;
        let mut input_m = Image::new((3, 1))?;
        let mut input_y = Image::new((3, 1))?;
        let mut input_k = Image::new((3, 1))?;
        input_c.row_mut(0).copy_from_slice(&[1.0, 1.0, 1.0]);
        input_m.row_mut(0).copy_from_slice(&[1.0, 1.0, 1.0]);
        input_y.row_mut(0).copy_from_slice(&[1.0, 1.0, 1.0]);
        input_k.row_mut(0).copy_from_slice(&[0.0, 0.0, 0.0]);

        let stage = BlackChannelStage::new(0);
        let output = make_and_run_simple_pipeline(
            stage,
            &[input_c, input_m, input_y, input_k],
            (3, 1),
            0,
            256,
        )?;

        // White + full black = black
        assert_all_almost_abs_eq(output[0].row(0), &[0.0, 0.0, 0.0], 1e-6);
        assert_all_almost_abs_eq(output[1].row(0), &[0.0, 0.0, 0.0], 1e-6);
        assert_all_almost_abs_eq(output[2].row(0), &[0.0, 0.0, 0.0], 1e-6);

        Ok(())
    }

    #[test]
    fn cmyk_to_rgb_gray() -> Result<()> {
        // 50% gray: CMY = 1 (no ink), K = 0.5 (half black)
        let mut input_c = Image::new((3, 1))?;
        let mut input_m = Image::new((3, 1))?;
        let mut input_y = Image::new((3, 1))?;
        let mut input_k = Image::new((3, 1))?;
        input_c.row_mut(0).copy_from_slice(&[1.0, 1.0, 1.0]);
        input_m.row_mut(0).copy_from_slice(&[1.0, 1.0, 1.0]);
        input_y.row_mut(0).copy_from_slice(&[1.0, 1.0, 1.0]);
        input_k.row_mut(0).copy_from_slice(&[0.5, 0.5, 0.5]);

        let stage = BlackChannelStage::new(0);
        let output = make_and_run_simple_pipeline(
            stage,
            &[input_c, input_m, input_y, input_k],
            (3, 1),
            0,
            256,
        )?;

        // White + 50% black = 50% gray
        assert_all_almost_abs_eq(output[0].row(0), &[0.5, 0.5, 0.5], 1e-6);
        assert_all_almost_abs_eq(output[1].row(0), &[0.5, 0.5, 0.5], 1e-6);
        assert_all_almost_abs_eq(output[2].row(0), &[0.5, 0.5, 0.5], 1e-6);

        Ok(())
    }

    #[test]
    fn cmyk_to_rgb_cyan() -> Result<()> {
        // Cyan: C = 0 (full cyan), M = Y = 1 (no ink), K = 1 (no black)
        let mut input_c = Image::new((3, 1))?;
        let mut input_m = Image::new((3, 1))?;
        let mut input_y = Image::new((3, 1))?;
        let mut input_k = Image::new((3, 1))?;
        input_c.row_mut(0).copy_from_slice(&[0.0, 0.0, 0.0]); // Full cyan
        input_m.row_mut(0).copy_from_slice(&[1.0, 1.0, 1.0]);
        input_y.row_mut(0).copy_from_slice(&[1.0, 1.0, 1.0]);
        input_k.row_mut(0).copy_from_slice(&[1.0, 1.0, 1.0]);

        let stage = BlackChannelStage::new(0);
        let output = make_and_run_simple_pipeline(
            stage,
            &[input_c, input_m, input_y, input_k],
            (3, 1),
            0,
            256,
        )?;

        // Pure cyan in RGB: R=0, G=1, B=1
        assert_all_almost_abs_eq(output[0].row(0), &[0.0, 0.0, 0.0], 1e-6);
        assert_all_almost_abs_eq(output[1].row(0), &[1.0, 1.0, 1.0], 1e-6);
        assert_all_almost_abs_eq(output[2].row(0), &[1.0, 1.0, 1.0], 1e-6);

        Ok(())
    }
}
