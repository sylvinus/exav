// Copyright (c) the JPEG XL Project Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use crate::{
    BLOCK_DIM, MIN_SIGMA,
    features::epf::SigmaSource,
    render::{
        Channels, ChannelsMut, RenderPipelineInOutStage,
        stages::epf::common::{get_sigma, prepare_sad_mul_storage},
    },
};

use jxl_simd::{F32SimdVec, SimdMask, simd_function};

/// 3x3 plus-shaped kernel with 5 SADs per pixel (3x3 plus-shaped). So this makes this filter a 5x5 filter.
pub struct Epf1Stage {
    /// Multiplier for sigma in pass 1
    sigma_scale: f32,
    /// (inverse) multiplier for sigma on borders
    border_sad_mul: f32,
    channel_scale: [f32; 3],
    sigma: SigmaSource,
}

impl std::fmt::Display for Epf1Stage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EPF stage 1 with sigma scale: {}, border_sad_mul: {}",
            self.sigma_scale, self.border_sad_mul
        )
    }
}

impl Epf1Stage {
    pub fn new(
        sigma_scale: f32,
        border_sad_mul: f32,
        channel_scale: [f32; 3],
        sigma: SigmaSource,
    ) -> Self {
        Self {
            sigma,
            sigma_scale,
            channel_scale,
            border_sad_mul,
        }
    }
}

simd_function!(
epf1_process_row_chunk_dispatch,
d: D,
fn epf1_process_row_chunk(
    stage: &Epf1Stage,
    pos: (usize, usize),
    xsize: usize,
    input_rows: &Channels<f32>,
    output_rows: &mut ChannelsMut<f32>,
) {
    let (xpos, ypos) = pos;
    assert_eq!(input_rows.len(), 3);
    assert_eq!(output_rows.len(), 3);

    // Extract all row references upfront and assert lengths once.
    // This lets LLVM prove bounds checks are unnecessary in the hot loop.
    // EPF1 has BORDER=2, so 5 input rows per channel (indices 0-4).
    // Max column access: row[4 + x] where x goes up to xsize - VEC_LEN,
    // and load reads VEC_LEN elements. So min row len = 4 + xsize.
    let min_in_len = 4 + xsize;
    let min_out_len = xsize;

    let rows = &input_rows.row_data;
    let rpc = input_rows.rows_per_channel;
    assert!(rpc >= 5);
    assert!(rows.len() >= 3 * rpc);

    // Extract channel row slices (5 rows each) with length assertions.
    // Indexing with constants after the assertion lets LLVM eliminate
    // bounds checks on row selection in the hot loop.
    let ch0 = &rows[..rpc];
    let ch1 = &rows[rpc..2 * rpc];
    let ch2 = &rows[2 * rpc..3 * rpc];
    let channels: [&[&[f32]]; 3] = [ch0, ch1, ch2];
    for ch in &channels {
        for r in 0..5 {
            assert!(ch[r].len() >= min_in_len);
        }
    }

    let out_rows = &mut output_rows.row_data;
    let out_rpc = output_rows.rows_per_channel;
    assert!(out_rpc >= 1);
    assert!(out_rows.len() >= 3 * out_rpc);
    for c in 0..3 {
        assert!(out_rows[c * out_rpc].len() >= min_out_len);
    }

    let row_sigma = stage.sigma.row(ypos / BLOCK_DIM);

    let sm = stage.sigma_scale * 1.65;
    let bsm = sm * stage.border_sad_mul;
    let sad_mul_storage = prepare_sad_mul_storage(xpos, ypos, sm, bsm);

    let scale_vec: [D::F32Vec; 3] = stage.channel_scale.map(|s| D::F32Vec::splat(d, s));

    for x in (0..xsize).step_by(D::F32Vec::LEN) {
        let sigma = get_sigma(d, x + xpos, row_sigma);
        let sad_mul = D::F32Vec::load_from(d, &sad_mul_storage, x % 8);

        let sigma_mask = D::F32Vec::splat(d, MIN_SIGMA).gt(sigma);
        if sigma_mask.all() {
            for c in 0..3 {
                D::F32Vec::load_from(d, channels[c][2], 2 + x)
                    .store_at(out_rows[c * out_rpc], x);
            }
            continue;
        }

        // Compute SADs across all 3 channels
        let mut sads = [D::F32Vec::splat(d, 0.0); 4];
        for c in 0..3 {
            let ch = channels[c];
            let scale = scale_vec[c];
            let p20 = D::F32Vec::load_from(d, ch[0], 2 + x);
            let p11 = D::F32Vec::load_from(d, ch[1], 1 + x);
            let p21 = D::F32Vec::load_from(d, ch[1], 2 + x);
            let p31 = D::F32Vec::load_from(d, ch[1], 3 + x);
            let p02 = D::F32Vec::load_from(d, ch[2], x);
            let p12 = D::F32Vec::load_from(d, ch[2], 1 + x);
            let p22 = D::F32Vec::load_from(d, ch[2], 2 + x);
            let p32 = D::F32Vec::load_from(d, ch[2], 3 + x);
            let p42 = D::F32Vec::load_from(d, ch[2], 4 + x);
            let p13 = D::F32Vec::load_from(d, ch[3], 1 + x);
            let p23 = D::F32Vec::load_from(d, ch[3], 2 + x);
            let p33 = D::F32Vec::load_from(d, ch[3], 3 + x);
            let p24 = D::F32Vec::load_from(d, ch[4], 2 + x);
            let d20_21 = (p20 - p21).abs();
            let d11_21 = (p11 - p21).abs();
            let d22_21 = (p22 - p21).abs();
            let d31_21 = (p31 - p21).abs();
            let d02_12 = (p02 - p12).abs();
            let d11_12 = (p11 - p12).abs();
            let d12_22 = (p22 - p12).abs();
            let d31_32 = (p31 - p32).abs();
            let d22_32 = (p22 - p32).abs();
            let d42_32 = (p42 - p32).abs();
            let d13_12 = (p13 - p12).abs();
            let d22_23 = (p22 - p23).abs();
            let d13_23 = (p13 - p23).abs();
            let d33_23 = (p33 - p23).abs();
            let d33_32 = (p33 - p32).abs();
            let d24_23 = (p24 - p23).abs();
            sads[0] = (d20_21 + d11_12 + d22_21 + d31_32 + d22_23).mul_add(scale, sads[0]);
            sads[1] = (d11_21 + d02_12 + d12_22 + d22_32 + d13_23).mul_add(scale, sads[1]);
            sads[2] = (d31_21 + d12_22 + d22_32 + d42_32 + d33_23).mul_add(scale, sads[2]);
            sads[3] = (d22_21 + d13_12 + d22_23 + d33_32 + d24_23).mul_add(scale, sads[3]);
        }

        // Compute output based on SADs
        let inv_sigma = sigma * sad_mul;
        let mut w = D::F32Vec::splat(d, 1.0);
        for sad in sads.iter_mut() {
            *sad = sad
                .mul_add(inv_sigma, D::F32Vec::splat(d, 1.0))
                .max(D::F32Vec::splat(d, 0.0));
            w += *sad;
        }
        let inv_w = D::F32Vec::splat(d, 1.0) / w;
        for c in 0..3 {
            let ch = channels[c];
            let mut out = D::F32Vec::load_from(d, ch[2], 2 + x);
            out = D::F32Vec::load_from(d, ch[3], 2 + x).mul_add(sads[3], out);
            out = D::F32Vec::load_from(d, ch[2], 3 + x).mul_add(sads[2], out);
            out = D::F32Vec::load_from(d, ch[2], 1 + x).mul_add(sads[1], out);
            out = D::F32Vec::load_from(d, ch[1], 2 + x).mul_add(sads[0], out);
            out *= inv_w;
            let p22 = D::F32Vec::load_from(d, ch[2], 2 + x);
            let out = sigma_mask.if_then_else_f32(p22, out);
            out.store_at(out_rows[c * out_rpc], x);
        }
    }
});

impl RenderPipelineInOutStage for Epf1Stage {
    type InputT = f32;
    type OutputT = f32;
    const SHIFT: (u8, u8) = (0, 0);
    const BORDER: (u8, u8) = (2, 2);

    fn uses_channel(&self, c: usize) -> bool {
        c < 3
    }

    fn process_row_chunk(
        &self,
        (xpos, ypos): (usize, usize),
        xsize: usize,
        input_rows: &Channels<f32>,
        output_rows: &mut ChannelsMut<f32>,
        _state: Option<&mut (dyn std::any::Any + Send)>,
    ) {
        epf1_process_row_chunk_dispatch(self, (xpos, ypos), xsize, input_rows, output_rows);
    }
}
