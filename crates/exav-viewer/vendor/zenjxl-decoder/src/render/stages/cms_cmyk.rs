// Copyright (c) the JPEG XL Project Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! CMS-based CMYK to RGB conversion stage.
//!
//! This stage uses a Color Management System (moxcms) to convert CMYK data
//! to RGB using an embedded ICC profile. This is needed for proper CMYK
//! color reproduction, as simple mathematical conversion (R=C*K) does not
//! account for ink characteristics, dot gain, and color gamut mapping that
//! ICC profiles encode.

use std::sync::Mutex;

use crate::api::JxlCmsTransformer;
use crate::render::RenderPipelineInPlaceStage;

/// CMS-based CMYK to RGB conversion stage.
///
/// This stage:
/// 1. Reads CMY from channels 0, 1, 2 and K from the specified extra channel
/// 2. Packs them into CMYK format (4 channels)
/// 3. Transforms through the ICC profile using moxcms
/// 4. Outputs RGB to channels 0, 1, 2
pub struct CmsCmykToRgbStage {
    /// Black channel index (offset from 3)
    black_c: usize,
    /// The CMS transformer for CMYK → sRGB conversion (uses Mutex for interior mutability)
    transformer: Mutex<Box<dyn JxlCmsTransformer + Send + Sync>>,
}

impl std::fmt::Display for CmsCmykToRgbStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CMS CMYK to RGB stage for channel {}", self.black_c)
    }
}

impl CmsCmykToRgbStage {
    pub fn new(
        black_c_offset: usize,
        transformer: Box<dyn JxlCmsTransformer + Send + Sync>,
    ) -> Self {
        Self {
            black_c: 3 + black_c_offset,
            transformer: Mutex::new(transformer),
        }
    }
}

impl RenderPipelineInPlaceStage for CmsCmykToRgbStage {
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

        // Allocate buffers for CMYK input and RGB output
        // In moxcms, CMYK uses Layout::Rgba (4 channels)
        let mut cmyk_input = vec![0.0f32; xsize * 4];
        let mut rgb_output = vec![0.0f32; xsize * 3];

        // Pack CMYK data with inversion
        // JXL uses reflectance convention: 1.0 = no ink (white), 0.0 = full ink
        // ICC/moxcms uses: 0.0 = no ink, 1.0 = max ink
        // skcms (used by libjxl) auto-inverts for CMYK profiles.
        // We must invert to match ICC convention before passing to moxcms.
        for idx in 0..xsize {
            cmyk_input[idx * 4] = 1.0 - row_c[idx];
            cmyk_input[idx * 4 + 1] = 1.0 - row_m[idx];
            cmyk_input[idx * 4 + 2] = 1.0 - row_y[idx];
            cmyk_input[idx * 4 + 3] = 1.0 - row_k[idx];
        }

        // Transform CMYK → RGB through ICC profile
        let mut transformer = self.transformer.lock().unwrap();

        match transformer.do_transform(&cmyk_input, &mut rgb_output) {
            Ok(()) => {
                // Unpack RGB output
                for idx in 0..xsize {
                    row_c[idx] = rgb_output[idx * 3];
                    row_m[idx] = rgb_output[idx * 3 + 1];
                    row_y[idx] = rgb_output[idx * 3 + 2];
                }
            }
            Err(_e) => {
                // Fall back to simple CMYK math if transform fails
                for idx in 0..xsize {
                    let k = row_k[idx];
                    row_c[idx] *= k;
                    row_m[idx] *= k;
                    row_y[idx] *= k;
                }
            }
        }
    }
}
