// Copyright (c) the JPEG XL Project Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use crate::api::{
    JxlColorEncoding, JxlPrimaries, JxlTransferFunction, JxlWhitePoint, adapt_to_xyz_d50,
    primaries_to_xyz, primaries_to_xyz_d50,
};
use crate::error::Result;
use crate::headers::{FileHeader, OpsinInverseMatrix};
use crate::render::stages::from_linear;
use crate::render::{Channels, ChannelsMut, RenderPipelineInOutStage, RenderPipelineInPlaceStage};
use crate::util::{Matrix3x3, eval_rational_poly_simd, inv_3x3_matrix, mul_3x3_matrix};
use jxl_simd::{F32SimdVec, SimdMask, simd_function};

const SRGB_LUMINANCES: [f32; 3] = [0.2126, 0.7152, 0.0722];

#[derive(Clone)]
pub struct OutputColorInfo {
    // Luminance of each primary.
    pub luminances: [f32; 3],
    pub intensity_target: f32,
    pub opsin: OpsinInverseMatrix,
    pub tf: from_linear::TransferFunction,
}

#[cfg(test)]
impl Default for OutputColorInfo {
    fn default() -> Self {
        use crate::headers::encodings::Empty;
        Self {
            luminances: SRGB_LUMINANCES,
            intensity_target: 255.0,
            opsin: OpsinInverseMatrix::default(&Empty {}),
            tf: from_linear::TransferFunction::Srgb,
        }
    }
}

impl OutputColorInfo {
    fn opsin_matrix_to_matrix3x3(matrix: [f32; 9]) -> Matrix3x3<f64> {
        [
            [matrix[0] as f64, matrix[1] as f64, matrix[2] as f64],
            [matrix[3] as f64, matrix[4] as f64, matrix[5] as f64],
            [matrix[6] as f64, matrix[7] as f64, matrix[8] as f64],
        ]
    }

    fn matrix3x3_to_opsin_matrix(matrix: Matrix3x3<f64>) -> [f32; 9] {
        [
            matrix[0][0] as f32,
            matrix[0][1] as f32,
            matrix[0][2] as f32,
            matrix[1][0] as f32,
            matrix[1][1] as f32,
            matrix[1][2] as f32,
            matrix[2][0] as f32,
            matrix[2][1] as f32,
            matrix[2][2] as f32,
        ]
    }

    pub fn from_header(header: &FileHeader) -> Result<Self> {
        let srgb_output = OutputColorInfo {
            luminances: SRGB_LUMINANCES,
            intensity_target: header.image_metadata.tone_mapping.intensity_target,
            opsin: header.transform_data.opsin_inverse_matrix.clone(),
            tf: from_linear::TransferFunction::Srgb,
        };
        if header.image_metadata.color_encoding.want_icc {
            return Ok(srgb_output);
        }

        let tf;
        let mut inverse_matrix = Self::opsin_matrix_to_matrix3x3(
            header.transform_data.opsin_inverse_matrix.inverse_matrix,
        );
        let mut luminances = SRGB_LUMINANCES;
        let desired_colorspace =
            JxlColorEncoding::from_internal(&header.image_metadata.color_encoding)?;
        match &desired_colorspace {
            JxlColorEncoding::XYB { .. } => {
                return Ok(srgb_output);
            }
            JxlColorEncoding::RgbColorSpace {
                white_point,
                primaries,
                transfer_function,
                ..
            } => {
                tf = transfer_function;
                if *primaries != JxlPrimaries::SRGB || *white_point != JxlWhitePoint::D65 {
                    let [r, g, b] = JxlPrimaries::SRGB.to_xy_coords();
                    let w = JxlWhitePoint::D65.to_xy_coords();
                    let srgb_to_xyzd50 =
                        primaries_to_xyz_d50(r.0, r.1, g.0, g.1, b.0, b.1, w.0, w.1)?;
                    let [r, g, b] = primaries.to_xy_coords();
                    let w = white_point.to_xy_coords();
                    let original_to_xyz = primaries_to_xyz(r.0, r.1, g.0, g.1, b.0, b.1, w.0, w.1)?;
                    luminances = original_to_xyz[1].map(|lum| lum as f32);
                    let adapt_to_d50 = adapt_to_xyz_d50(w.0, w.1)?;
                    let original_to_xyzd50 = mul_3x3_matrix(&adapt_to_d50, &original_to_xyz);
                    let xyzd50_to_original = inv_3x3_matrix(&original_to_xyzd50)?;
                    let srgb_to_original = mul_3x3_matrix(&xyzd50_to_original, &srgb_to_xyzd50);
                    inverse_matrix = mul_3x3_matrix(&srgb_to_original, &inverse_matrix);
                }
            }

            JxlColorEncoding::GrayscaleColorSpace {
                transfer_function, ..
            } => {
                tf = transfer_function;
                let f64_luminances = luminances.map(|lum| lum as f64);
                let srgb_to_luminance: Matrix3x3<f64> =
                    [f64_luminances, f64_luminances, f64_luminances];
                inverse_matrix = mul_3x3_matrix(&srgb_to_luminance, &inverse_matrix);
            }
        }

        let mut opsin = header.transform_data.opsin_inverse_matrix.clone();
        opsin.inverse_matrix = Self::matrix3x3_to_opsin_matrix(inverse_matrix);
        let intensity_target = header.image_metadata.tone_mapping.intensity_target;
        let from_linear_tf = match tf {
            JxlTransferFunction::PQ => from_linear::TransferFunction::Pq { intensity_target },
            JxlTransferFunction::HLG => from_linear::TransferFunction::Hlg {
                intensity_target,
                luminance_rgb: luminances,
            },
            JxlTransferFunction::BT709 => from_linear::TransferFunction::Bt709,
            JxlTransferFunction::Linear => from_linear::TransferFunction::Gamma(1.0),
            JxlTransferFunction::SRGB => from_linear::TransferFunction::Srgb,
            JxlTransferFunction::DCI => from_linear::TransferFunction::Gamma(2.6_f32.recip()),
            JxlTransferFunction::Gamma(g) => from_linear::TransferFunction::Gamma(*g),
        };
        Ok(OutputColorInfo {
            luminances,
            intensity_target,
            opsin,
            tf: from_linear_tf,
        })
    }
}

/// Convert XYB to linear RGB with appropriate primaries, where 1.0 corresponds to `intensity_target` nits.
pub struct XybStage {
    first_channel: usize,
    output_color_info: OutputColorInfo,
}

impl XybStage {
    pub fn new(first_channel: usize, output_color_info: OutputColorInfo) -> Self {
        Self {
            first_channel,
            output_color_info,
        }
    }
}

impl std::fmt::Display for XybStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let channel = self.first_channel;
        write!(
            f,
            "XYB to linear for channel [{},{},{}]",
            channel,
            channel + 1,
            channel + 2
        )
    }
}

simd_function!(
    xyb_process_dispatch,
    d: D,
    fn xyb_process(
        opsin: &OpsinInverseMatrix,
        intensity_target: f32,
        xsize: usize,
        row_x: &mut [f32],
        row_y: &mut [f32],
        row_b: &mut [f32],
    ) {
        let OpsinInverseMatrix {
            inverse_matrix: mat,
            opsin_biases: bias,
            ..
        } = opsin;
        // TODO(veluca): consider computing the cbrt in advance.
        let bias_cbrt = bias.map(|x| D::F32Vec::splat(d, x.cbrt()));
        let intensity_scale = 255.0 / intensity_target;
        let scaled_bias = bias.map(|x| D::F32Vec::splat(d, x * intensity_scale));
        let mat = mat.map(|x| D::F32Vec::splat(d, x));
        let intensity_scale = D::F32Vec::splat(d, intensity_scale);

        // Pre-loop assertions: prove row lengths so LLVM can eliminate bounds checks.
        assert!(row_x.len() >= xsize);
        assert!(row_y.len() >= xsize);
        assert!(row_b.len() >= xsize);

        for idx in (0..xsize).step_by(D::F32Vec::LEN) {
            let x = D::F32Vec::load_from(d, row_x, idx);
            let y = D::F32Vec::load_from(d, row_y, idx);
            let b = D::F32Vec::load_from(d, row_b, idx);

            // Mix and apply bias
            let l = y + x - bias_cbrt[0];
            let m = y - x - bias_cbrt[1];
            let s = b - bias_cbrt[2];

            // Apply biased inverse gamma and scale (1.0 corresponds to `intensity_target` nits)
            let l2 = l * l;
            let m2 = m * m;
            let s2 = s * s;
            let scaled_l = l * intensity_scale;
            let scaled_m = m * intensity_scale;
            let scaled_s = s * intensity_scale;
            let l = l2.mul_add(scaled_l, scaled_bias[0]);
            let m = m2.mul_add(scaled_m, scaled_bias[1]);
            let s = s2.mul_add(scaled_s, scaled_bias[2]);

            // Apply opsin inverse matrix (linear LMS to linear sRGB)
            let r = mat[0].mul_add(l, mat[1].mul_add(m, mat[2] * s));
            let g = mat[3].mul_add(l, mat[4].mul_add(m, mat[5] * s));
            let b = mat[6].mul_add(l, mat[7].mul_add(m, mat[8] * s));
            r.store_at(row_x, idx);
            g.store_at(row_y, idx);
            b.store_at(row_b, idx);
        }
    }
);

impl RenderPipelineInPlaceStage for XybStage {
    type Type = f32;

    fn uses_channel(&self, c: usize) -> bool {
        (self.first_channel..self.first_channel + 3).contains(&c)
    }

    fn process_row_chunk(
        &self,
        _position: (usize, usize),
        xsize: usize,
        row: &mut [&mut [f32]],
        _state: Option<&mut (dyn std::any::Any + Send)>,
    ) {
        let [row_x, row_y, row_b] = row else {
            panic!(
                "incorrect number of channels; expected 3, found {}",
                row.len()
            );
        };

        xyb_process_dispatch(
            &self.output_color_info.opsin,
            self.output_color_info.intensity_target,
            xsize,
            row_x,
            row_y,
            row_b,
        );
    }
}

/// Fused XYB inverse + transfer function + u8 conversion in a single SIMD pass.
/// Supports sRGB and gamma transfer functions. Eliminates intermediate f32 buffer
/// writes between the three separate stages (XYB, TF, u8 conversion).
pub struct XybToU8Stage {
    first_channel: usize,
    output_color_info: OutputColorInfo,
    bit_depth: u8,
    tf: super::from_linear::TransferFunction,
}

impl XybToU8Stage {
    pub fn new(
        first_channel: usize,
        output_color_info: OutputColorInfo,
        bit_depth: u8,
        tf: super::from_linear::TransferFunction,
    ) -> Self {
        Self {
            first_channel,
            output_color_info,
            bit_depth,
            tf,
        }
    }
}

impl std::fmt::Display for XybToU8Stage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let c = self.first_channel;
        write!(
            f,
            "Fused XYB→{:?}→U{} for channels [{},{},{}]",
            self.tf,
            self.bit_depth,
            c,
            c + 1,
            c + 2,
        )
    }
}

/// Common XYB inverse that produces linear RGB values for three channels.
/// Returns (r_lin, g_lin, b_lin) SIMD vectors.
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn xyb_inverse<D: jxl_simd::SimdDescriptor>(
    _d: D,
    x: D::F32Vec,
    y: D::F32Vec,
    b: D::F32Vec,
    bias_cbrt: &[D::F32Vec; 3],
    intensity_scale: D::F32Vec,
    scaled_bias: &[D::F32Vec; 3],
    mat: &[D::F32Vec; 9],
) -> (D::F32Vec, D::F32Vec, D::F32Vec) {
    let l = y + x - bias_cbrt[0];
    let m = y - x - bias_cbrt[1];
    let s = b - bias_cbrt[2];

    let l2 = l * l;
    let m2 = m * m;
    let s2 = s * s;
    let scaled_l = l * intensity_scale;
    let scaled_m = m * intensity_scale;
    let scaled_s = s * intensity_scale;
    let l = l2.mul_add(scaled_l, scaled_bias[0]);
    let m = m2.mul_add(scaled_m, scaled_bias[1]);
    let s = s2.mul_add(scaled_s, scaled_bias[2]);

    let r_lin = mat[0].mul_add(l, mat[1].mul_add(m, mat[2] * s));
    let g_lin = mat[3].mul_add(l, mat[4].mul_add(m, mat[5] * s));
    let b_lin = mat[6].mul_add(l, mat[7].mul_add(m, mat[8] * s));
    (r_lin, g_lin, b_lin)
}

simd_function!(
    xyb_to_srgb_u8_dispatch,
    d: D,
    fn xyb_to_srgb_u8_process(
        opsin: &OpsinInverseMatrix,
        intensity_target: f32,
        max_val: f32,
        xsize: usize,
        input_rows: &Channels<f32>,
        output_rows: &mut ChannelsMut<u8>,
    ) {
        let OpsinInverseMatrix {
            inverse_matrix: mat,
            opsin_biases: bias,
            ..
        } = opsin;

        let bias_cbrt = bias.map(|x| D::F32Vec::splat(d, x.cbrt()));
        let intensity_scale_f = 255.0 / intensity_target;
        let scaled_bias = bias.map(|x| D::F32Vec::splat(d, x * intensity_scale_f));
        let mat = mat.map(|x| D::F32Vec::splat(d, x));
        let intensity_scale = D::F32Vec::splat(d, intensity_scale_f);

        #[allow(clippy::excessive_precision)]
        const P: [f32; 5] = [
            -5.135152395e-4,
            5.287254571e-3,
            3.903842876e-1,
            1.474205315,
            7.352629620e-1,
        ];
        #[allow(clippy::excessive_precision)]
        const Q: [f32; 5] = [
            1.004519624e-2,
            3.036675394e-1,
            1.340816930,
            9.258482155e-1,
            2.424867759e-2,
        ];
        let zero = D::F32Vec::splat(d, 0.0);
        let one = D::F32Vec::splat(d, 1.0);
        let scale = D::F32Vec::splat(d, max_val);
        let threshold = D::F32Vec::splat(d, 0.0031308);
        let linear_scale = D::F32Vec::splat(d, 12.92);

        let in_x = input_rows[0][0];
        let in_y = input_rows[1][0];
        let in_b = input_rows[2][0];
        let (out_r, out_g, out_b) = output_rows.split_first_3_mut();

        let end = xsize.next_multiple_of(D::F32Vec::LEN);
        // Pre-loop assertions: prove row lengths so LLVM can eliminate bounds checks.
        assert!(in_x.len() >= end);
        assert!(in_y.len() >= end);
        assert!(in_b.len() >= end);
        assert!(out_r[0].len() >= end);
        assert!(out_g[0].len() >= end);
        assert!(out_b[0].len() >= end);

        for idx in (0..end).step_by(D::F32Vec::LEN) {
            let x = D::F32Vec::load_from(d, in_x, idx);
            let y = D::F32Vec::load_from(d, in_y, idx);
            let b = D::F32Vec::load_from(d, in_b, idx);

            let (r_lin, g_lin, b_lin) = xyb_inverse(
                d, x, y, b, &bias_cbrt, intensity_scale, &scaled_bias, &mat,
            );

            // sRGB TF + u8 quantize
            let r_c = r_lin.max(zero).min(one);
            let r_srgb = threshold.gt(r_c).if_then_else_f32(
                r_c * linear_scale,
                eval_rational_poly_simd(d, r_c.sqrt(), P, Q),
            );
            (r_srgb * scale).round_store_u8(&mut out_r[0][idx..]);

            let g_c = g_lin.max(zero).min(one);
            let g_srgb = threshold.gt(g_c).if_then_else_f32(
                g_c * linear_scale,
                eval_rational_poly_simd(d, g_c.sqrt(), P, Q),
            );
            (g_srgb * scale).round_store_u8(&mut out_g[0][idx..]);

            let b_c = b_lin.max(zero).min(one);
            let b_srgb = threshold.gt(b_c).if_then_else_f32(
                b_c * linear_scale,
                eval_rational_poly_simd(d, b_c.sqrt(), P, Q),
            );
            (b_srgb * scale).round_store_u8(&mut out_b[0][idx..]);
        }
    }
);

simd_function!(
    xyb_to_gamma_u8_dispatch,
    d: D,
    fn xyb_to_gamma_u8_process(
        opsin: &OpsinInverseMatrix,
        gamma_params: &[f32; 3],
        xsize: usize,
        input_rows: &Channels<f32>,
        output_rows: &mut ChannelsMut<u8>,
    ) {
        let [intensity_target, gamma, max_val] = *gamma_params;
        let OpsinInverseMatrix {
            inverse_matrix: mat,
            opsin_biases: bias,
            ..
        } = opsin;

        let bias_cbrt = bias.map(|x| D::F32Vec::splat(d, x.cbrt()));
        let intensity_scale_f = 255.0 / intensity_target;
        let scaled_bias = bias.map(|x| D::F32Vec::splat(d, x * intensity_scale_f));
        let mat = mat.map(|x| D::F32Vec::splat(d, x));
        let intensity_scale = D::F32Vec::splat(d, intensity_scale_f);

        let zero = D::F32Vec::splat(d, 0.0);
        let scale = D::F32Vec::splat(d, max_val);
        let gamma_vec = D::F32Vec::splat(d, gamma);

        let in_x = input_rows[0][0];
        let in_y = input_rows[1][0];
        let in_b = input_rows[2][0];
        let (out_r, out_g, out_b) = output_rows.split_first_3_mut();

        let end = xsize.next_multiple_of(D::F32Vec::LEN);
        // Pre-loop assertions: prove row lengths so LLVM can eliminate bounds checks.
        assert!(in_x.len() >= end);
        assert!(in_y.len() >= end);
        assert!(in_b.len() >= end);
        assert!(out_r[0].len() >= end);
        assert!(out_g[0].len() >= end);
        assert!(out_b[0].len() >= end);

        for idx in (0..end).step_by(D::F32Vec::LEN) {
            let x = D::F32Vec::load_from(d, in_x, idx);
            let y = D::F32Vec::load_from(d, in_y, idx);
            let b = D::F32Vec::load_from(d, in_b, idx);

            let (r_lin, g_lin, b_lin) = xyb_inverse(
                d, x, y, b, &bias_cbrt, intensity_scale, &scaled_bias, &mat,
            );

            // Gamma TF + u8 quantize: powf(abs(x), gamma) * copysign(1, x)
            let r_abs = r_lin.abs().max(zero);
            let r_tf = crate::util::fast_powf_simd(d, r_abs, gamma_vec).copysign(r_lin);
            (r_tf * scale).round_store_u8(&mut out_r[0][idx..]);

            let g_abs = g_lin.abs().max(zero);
            let g_tf = crate::util::fast_powf_simd(d, g_abs, gamma_vec).copysign(g_lin);
            (g_tf * scale).round_store_u8(&mut out_g[0][idx..]);

            let b_abs = b_lin.abs().max(zero);
            let b_tf = crate::util::fast_powf_simd(d, b_abs, gamma_vec).copysign(b_lin);
            (b_tf * scale).round_store_u8(&mut out_b[0][idx..]);
        }
    }
);

impl RenderPipelineInOutStage for XybToU8Stage {
    type InputT = f32;
    type OutputT = u8;
    const SHIFT: (u8, u8) = (0, 0);
    const BORDER: (u8, u8) = (0, 0);

    fn uses_channel(&self, c: usize) -> bool {
        (self.first_channel..self.first_channel + 3).contains(&c)
    }

    fn process_row_chunk(
        &self,
        _position: (usize, usize),
        xsize: usize,
        input_rows: &Channels<f32>,
        output_rows: &mut ChannelsMut<u8>,
        _state: Option<&mut (dyn std::any::Any + Send)>,
    ) {
        let max_val = ((1u32 << self.bit_depth) - 1) as f32;
        match self.tf {
            super::from_linear::TransferFunction::Srgb => {
                xyb_to_srgb_u8_dispatch(
                    &self.output_color_info.opsin,
                    self.output_color_info.intensity_target,
                    max_val,
                    xsize,
                    input_rows,
                    output_rows,
                );
            }
            super::from_linear::TransferFunction::Gamma(gamma) => {
                xyb_to_gamma_u8_dispatch(
                    &self.output_color_info.opsin,
                    &[self.output_color_info.intensity_target, gamma, max_val],
                    xsize,
                    input_rows,
                    output_rows,
                );
            }
            _ => unreachable!("XybToU8Stage only supports Srgb and Gamma TFs"),
        }
    }
}

#[cfg(test)]
mod test {
    use test_log::test;

    use super::*;
    use crate::error::Result;
    use crate::headers::encodings::Empty;
    use crate::image::Image;
    use crate::render::test::make_and_run_simple_pipeline;
    use crate::util::round_up_size_to_cache_line;
    use crate::util::test::assert_all_almost_abs_eq;
    use jxl_simd::{ScalarDescriptor, SimdDescriptor, test_all_instruction_sets};

    #[test]
    fn consistency() -> Result<()> {
        crate::render::test::test_stage_consistency(
            || XybStage::new(0, OutputColorInfo::default()),
            (500, 500),
            3,
        )
    }

    #[test]
    fn srgb_primaries() -> Result<()> {
        let mut input_x = Image::new((3, 1))?;
        let mut input_y = Image::new((3, 1))?;
        let mut input_b = Image::new((3, 1))?;
        input_x
            .row_mut(0)
            .copy_from_slice(&[0.028100073, -0.015386105, 0.0]);
        input_y
            .row_mut(0)
            .copy_from_slice(&[0.4881882, 0.71478134, 0.2781282]);
        input_b
            .row_mut(0)
            .copy_from_slice(&[0.471659, 0.43707693, 0.66613984]);

        let stage = XybStage::new(0, OutputColorInfo::default());
        let output =
            make_and_run_simple_pipeline(stage, &[input_x, input_y, input_b], (3, 1), 0, 256)?;

        assert_all_almost_abs_eq(output[0].row(0), &[1.0, 0.0, 0.0], 1e-6);
        assert_all_almost_abs_eq(output[1].row(0), &[0.0, 1.0, 0.0], 1e-6);
        assert_all_almost_abs_eq(output[2].row(0), &[0.0, 0.0, 1.0], 1e-6);

        Ok(())
    }

    fn xyb_process_scalar_equivalent<D: SimdDescriptor>(d: D) {
        let opsin = OpsinInverseMatrix::default(&Empty {});
        arbtest::arbtest(|u| {
            let xsize = u.arbitrary_len::<usize>()?;
            let intensity_target = u.arbitrary::<u8>()? as f32 * 2.0 + 1.0;
            let mut row_x = vec![0.0; round_up_size_to_cache_line::<f32>(xsize)];
            let mut row_y = vec![0.0; round_up_size_to_cache_line::<f32>(xsize)];
            let mut row_b = vec![0.0; round_up_size_to_cache_line::<f32>(xsize)];

            for i in 0..xsize {
                row_x[i] = u.arbitrary::<i16>()? as f32 * (0.07 / i16::MAX as f32);
                row_y[i] = u.arbitrary::<u16>()? as f32 * (1.0 / u16::MAX as f32);
                row_b[i] = u.arbitrary::<u16>()? as f32 * (1.0 / u16::MAX as f32);
            }

            let mut scalar_x = row_x.clone();
            let mut scalar_y = row_y.clone();
            let mut scalar_b = row_b.clone();

            xyb_process(
                d,
                &opsin,
                intensity_target,
                xsize,
                &mut row_x,
                &mut row_y,
                &mut row_b,
            );

            xyb_process(
                ScalarDescriptor::new().unwrap(),
                &opsin,
                intensity_target,
                xsize,
                &mut scalar_x,
                &mut scalar_y,
                &mut scalar_b,
            );

            for i in 0..xsize {
                for (simd, scalar) in [
                    (row_x[i], scalar_x[i]),
                    (row_y[i], scalar_y[i]),
                    (row_b[i], scalar_b[i]),
                ] {
                    let abs = (simd - scalar).abs();
                    let max = simd.abs().max(scalar.abs());
                    let rel = abs / max;
                    assert!(
                        abs < 1e-3 || rel < 1e-3,
                        "simd {simd}, scalar {scalar}, abs {abs:?} rel {rel:?}",
                    );
                }
            }

            Ok(())
        });
    }

    test_all_instruction_sets!(xyb_process_scalar_equivalent);

    #[test]
    fn fused_xyb_srgb_u8_consistency() -> Result<()> {
        crate::render::test::test_stage_consistency(
            || {
                XybToU8Stage::new(
                    0,
                    OutputColorInfo::default(),
                    8,
                    super::super::from_linear::TransferFunction::Srgb,
                )
            },
            (500, 500),
            3,
        )
    }

    #[test]
    fn fused_xyb_gamma_u8_consistency() -> Result<()> {
        crate::render::test::test_stage_consistency(
            || {
                XybToU8Stage::new(
                    0,
                    OutputColorInfo::default(),
                    8,
                    super::super::from_linear::TransferFunction::Gamma(0.454545),
                )
            },
            (500, 500),
            3,
        )
    }
}
