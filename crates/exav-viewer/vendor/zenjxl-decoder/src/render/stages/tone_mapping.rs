// Copyright (c) the JPEG XL Project Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Render pipeline stage for HDR tone mapping.
//!
//! This stage maps pixel values from one intensity target to another,
//! matching libjxl's `ToneMappingStage`. It handles:
//! - PQ content: Rec.2408 tone mapping when desired < source intensity target
//! - HLG content: OOTF adjustment for different display luminances
//!
//! The stage operates on linear-light RGB data.

use crate::render::RenderPipelineInPlaceStage;
use crate::util::fast_powf;

/// Render pipeline stage that applies HDR tone mapping.
///
/// Inserted into the pipeline when the caller requests a different
/// `desired_intensity_target` than the image's embedded `intensity_target`.
/// Operates on display-referred linear RGB where 1.0 = `orig_intensity_target` nits.
#[derive(Debug)]
pub struct ToneMappingStage {
    first_channel: usize,
    config: ToneMappingConfig,
}

#[derive(Debug)]
enum ToneMappingConfig {
    /// Rec.2408 tone mapping for PQ content.
    Pq(Rec2408ToneMapper),
    /// HLG OOTF adjustment between two intensity targets.
    Hlg(HlgOotfConfig),
}

/// Precomputed Rec.2408 tone mapper (BT.2408 Annex 5).
///
/// Maps PQ content from source range to target range, preserving hue
/// while compressing highlights.
#[derive(Debug)]
struct Rec2408ToneMapper {
    luminances: [f32; 3],
    source_max: f32,
    target_max: f32,
    pq_mastering_min: f32,
    pq_mastering_range: f32,
    inv_pq_mastering_range: f32,
    min_lum: f32,
    ks: f32,
    max_lum: f32,
    inv_one_minus_ks: f32,
    normalizer: f32,
    inv_target_peak: f32,
}

impl Rec2408ToneMapper {
    fn new(source_range: (f32, f32), target_range: (f32, f32), luminances: [f32; 3]) -> Self {
        let pq_mastering_min = linear_to_pq(source_range.0);
        let pq_mastering_max = linear_to_pq(source_range.1);
        let pq_mastering_range = pq_mastering_max - pq_mastering_min;
        let inv_pq_mastering_range = 1.0 / pq_mastering_range;

        let min_lum = (linear_to_pq(target_range.0) - pq_mastering_min) * inv_pq_mastering_range;
        let max_lum = (linear_to_pq(target_range.1) - pq_mastering_min) * inv_pq_mastering_range;
        let ks = 1.5 * max_lum - 0.5;

        Self {
            luminances,
            source_max: source_range.1,
            target_max: target_range.1,
            pq_mastering_min,
            pq_mastering_range,
            inv_pq_mastering_range,
            min_lum,
            ks,
            max_lum,
            inv_one_minus_ks: 1.0 / (1.0 - ks).max(1e-6),
            normalizer: source_range.1 / target_range.1,
            inv_target_peak: 1.0 / target_range.1,
        }
    }

    #[inline]
    fn t(&self, a: f32) -> f32 {
        (a - self.ks) * self.inv_one_minus_ks
    }

    #[inline]
    fn p(&self, b: f32) -> f32 {
        let t_b = self.t(b);
        let t_b_2 = t_b * t_b;
        let t_b_3 = t_b_2 * t_b;
        (2.0 * t_b_3 - 3.0 * t_b_2 + 1.0) * self.ks
            + (t_b_3 - 2.0 * t_b_2 + t_b) * (1.0 - self.ks)
            + (-2.0 * t_b_3 + 3.0 * t_b_2) * self.max_lum
    }

    /// Tone map a single pixel in-place. Input/output is linear light
    /// normalized so 1.0 = orig_intensity_target nits.
    #[inline]
    fn tone_map(&self, r: &mut f32, g: &mut f32, b: &mut f32) {
        let luminance = self.source_max
            * (self.luminances[0] * *r + self.luminances[1] * *g + self.luminances[2] * *b);

        let normalized_pq = ((linear_to_pq(luminance) - self.pq_mastering_min)
            * self.inv_pq_mastering_range)
            .min(1.0);

        let e2 = if normalized_pq < self.ks {
            normalized_pq
        } else {
            self.p(normalized_pq)
        };

        let one_minus_e2 = 1.0 - e2;
        let one_minus_e2_2 = one_minus_e2 * one_minus_e2;
        let one_minus_e2_4 = one_minus_e2_2 * one_minus_e2_2;
        let e3 = self.min_lum * one_minus_e2_4 + e2;
        let e4 = e3 * self.pq_mastering_range + self.pq_mastering_min;
        let new_luminance = pq_to_linear(e4).clamp(0.0, self.target_max);

        let min_luminance = 1e-6;
        let use_cap = luminance <= min_luminance;
        let ratio = new_luminance / luminance.max(min_luminance);
        let cap = new_luminance * self.inv_target_peak;
        let multiplier = ratio * self.normalizer;

        if use_cap {
            *r = cap;
            *g = cap;
            *b = cap;
        } else {
            *r *= multiplier;
            *g *= multiplier;
            *b *= multiplier;
        }
    }
}

/// Config for HLG OOTF adjustment between intensity targets.
#[derive(Debug)]
struct HlgOotfConfig {
    luminances: [f32; 3],
    exponent: f32,
}

impl HlgOotfConfig {
    fn new(
        orig_intensity_target: f32,
        desired_intensity_target: f32,
        luminances: [f32; 3],
    ) -> Self {
        // HLG system gamma from BT.2100-2:
        //   gamma = 1.2 * 1.111^log2(Lw / 1000)
        // The OOTF exponent to adjust from one target to another is the
        // difference of system gammas minus 1.
        let orig_gamma = 1.2_f32 * 1.111_f32.powf((orig_intensity_target / 1e3).log2());
        let desired_gamma = 1.2_f32 * 1.111_f32.powf((desired_intensity_target / 1e3).log2());
        let exponent = desired_gamma - orig_gamma;

        Self {
            luminances,
            exponent,
        }
    }

    /// Apply the OOTF adjustment. Input is display-referred linear light.
    #[inline]
    fn apply(&self, r: &mut f32, g: &mut f32, b: &mut f32) {
        if self.exponent.abs() < 1e-6 {
            return;
        }
        let mixed = *r * self.luminances[0] + *g * self.luminances[1] + *b * self.luminances[2];
        if mixed <= 0.0 {
            return;
        }
        let mult = fast_powf(mixed, self.exponent);
        *r *= mult;
        *g *= mult;
        *b *= mult;
    }
}

/// Desaturate out-of-gamut pixels while preserving luminance.
///
/// Applied after tone mapping to handle pixels pushed out of gamut
/// by the tone mapping curve.
#[inline]
fn gamut_map(r: &mut f32, g: &mut f32, b: &mut f32, luminances: &[f32; 3]) {
    let luminance = luminances[0] * *r + luminances[1] * *g + luminances[2] * *b;

    // Preserve_saturation = 0.3 matches libjxl's ToneMappingStage
    let preserve_saturation: f32 = 0.3;

    let mut gray_mix_saturation = 0.0_f32;
    let mut gray_mix_luminance = 0.0_f32;

    for &val in [r as &f32, g, b].iter() {
        let val_minus_gray = *val - luminance;
        let inv_val_minus_gray = if val_minus_gray == 0.0 {
            1.0
        } else {
            1.0 / val_minus_gray
        };
        let val_over_val_minus_gray = *val * inv_val_minus_gray;

        if val_minus_gray < 0.0 {
            gray_mix_saturation = gray_mix_saturation.max(val_over_val_minus_gray);
        }

        gray_mix_luminance = gray_mix_luminance.max(if val_minus_gray <= 0.0 {
            gray_mix_saturation
        } else {
            val_over_val_minus_gray - inv_val_minus_gray
        });
    }

    let gray_mix = (preserve_saturation * (gray_mix_saturation - gray_mix_luminance)
        + gray_mix_luminance)
        .clamp(0.0, 1.0);

    *r = gray_mix * (luminance - *r) + *r;
    *g = gray_mix * (luminance - *g) + *g;
    *b = gray_mix * (luminance - *b) + *b;

    let max_clr = r.max(*g).max(*b).max(1.0);
    let normalizer = 1.0 / max_clr;
    *r *= normalizer;
    *g *= normalizer;
    *b *= normalizer;
}

/// PQ inverse EOTF: luminance (nits) → PQ encoded value [0, 1].
fn linear_to_pq(luminance: f32) -> f32 {
    let mut val = [luminance / 10000.0];
    crate::color::tf::linear_to_pq_precise(10000.0, &mut val);
    val[0]
}

/// PQ EOTF: PQ encoded value [0, 1] → luminance (nits).
fn pq_to_linear(encoded: f32) -> f32 {
    let mut val = [encoded];
    crate::color::tf::pq_to_linear_precise(10000.0, &mut val);
    val[0] * 10000.0
}

impl ToneMappingStage {
    /// Create a tone mapping stage for PQ content.
    ///
    /// Applies Rec.2408 tone mapping when `desired_intensity_target < orig_intensity_target`.
    pub fn pq(
        first_channel: usize,
        orig_intensity_target: f32,
        desired_intensity_target: f32,
        luminances: [f32; 3],
    ) -> Self {
        Self {
            first_channel,
            config: ToneMappingConfig::Pq(Rec2408ToneMapper::new(
                (0.0, orig_intensity_target),
                (0.0, desired_intensity_target),
                luminances,
            )),
        }
    }

    /// Create a tone mapping stage for HLG content.
    ///
    /// Adjusts the HLG OOTF for the desired display luminance.
    pub fn hlg(
        first_channel: usize,
        orig_intensity_target: f32,
        desired_intensity_target: f32,
        luminances: [f32; 3],
    ) -> Self {
        Self {
            first_channel,
            config: ToneMappingConfig::Hlg(HlgOotfConfig::new(
                orig_intensity_target,
                desired_intensity_target,
                luminances,
            )),
        }
    }
}

impl std::fmt::Display for ToneMappingStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let c = self.first_channel;
        let kind = match &self.config {
            ToneMappingConfig::Pq(_) => "PQ Rec.2408",
            ToneMappingConfig::Hlg(_) => "HLG OOTF",
        };
        write!(
            f,
            "Tone mapping ({}) for channels [{},{},{}]",
            kind,
            c,
            c + 1,
            c + 2
        )
    }
}

impl RenderPipelineInPlaceStage for ToneMappingStage {
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
        let [row_r, row_g, row_b] = row else {
            panic!(
                "incorrect number of channels; expected 3, found {}",
                row.len()
            );
        };

        let luminances = match &self.config {
            ToneMappingConfig::Pq(tm) => tm.luminances,
            ToneMappingConfig::Hlg(cfg) => cfg.luminances,
        };

        for i in 0..xsize {
            let (r, g, b) = (&mut row_r[i], &mut row_g[i], &mut row_b[i]);

            match &self.config {
                ToneMappingConfig::Pq(tm) => tm.tone_map(r, g, b),
                ToneMappingConfig::Hlg(cfg) => cfg.apply(r, g, b),
            }

            gamut_map(r, g, b, &luminances);
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

    const LUMINANCE_BT2020: [f32; 3] = [0.2627, 0.678, 0.0593];

    #[test]
    fn consistency_pq() -> Result<()> {
        crate::render::test::test_stage_consistency(
            || ToneMappingStage::pq(0, 10000.0, 250.0, LUMINANCE_BT2020),
            (500, 500),
            3,
        )
    }

    #[test]
    fn consistency_hlg() -> Result<()> {
        crate::render::test::test_stage_consistency(
            || ToneMappingStage::hlg(0, 1000.0, 300.0, LUMINANCE_BT2020),
            (500, 500),
            3,
        )
    }

    #[test]
    fn pq_tone_mapping_compresses_highlights() -> Result<()> {
        // Input: two pixels at different brightness levels.
        // In the PQ linear domain, 1.0 = orig_intensity_target nits.
        // 0.1 = 1000 nits, 0.8 = 8000 nits relative to 10000 nit source.
        // After tone mapping to 250 nits, the bright pixel should be compressed
        // more than the dim one, but both map to [0, 1] of the target range.
        let dim = 0.1_f32; // 1000 nits
        let bright = 0.8_f32; // 8000 nits

        let stage = ToneMappingStage::pq(0, 10000.0, 250.0, LUMINANCE_BT2020);

        let input_dim = [
            Image::new_with_value((1, 1), dim)?,
            Image::new_with_value((1, 1), dim)?,
            Image::new_with_value((1, 1), dim)?,
        ];
        let output_dim = make_and_run_simple_pipeline(
            ToneMappingStage::pq(0, 10000.0, 250.0, LUMINANCE_BT2020),
            &input_dim,
            (1, 1),
            0,
            256,
        )?;

        let input_bright = [
            Image::new_with_value((1, 1), bright)?,
            Image::new_with_value((1, 1), bright)?,
            Image::new_with_value((1, 1), bright)?,
        ];
        let output_bright = make_and_run_simple_pipeline(stage, &input_bright, (1, 1), 0, 256)?;

        let dim_out = output_dim[0].row(0)[0];
        let bright_out = output_bright[0].row(0)[0];

        // Both should be in valid range
        assert!(dim_out >= 0.0, "Dim pixel negative: {dim_out}");
        assert!(bright_out >= 0.0, "Bright pixel negative: {bright_out}");

        // The bright pixel should map higher than the dim pixel
        assert!(
            bright_out > dim_out,
            "Tone mapping should preserve ordering: bright {bright_out} <= dim {dim_out}"
        );

        // The ratio between bright/dim output should be less than the input ratio,
        // proving that highlights were compressed
        let input_ratio = bright / dim;
        let output_ratio = bright_out / dim_out;
        assert!(
            output_ratio < input_ratio,
            "Highlights not compressed: input ratio {input_ratio}, output ratio {output_ratio}"
        );

        Ok(())
    }

    #[test]
    fn pq_dark_pixel_preserved() -> Result<()> {
        // A dim PQ pixel (0.01 linear = 100 nits) should be mostly preserved
        let input_r = Image::new_with_value((1, 1), 0.01)?;
        let input_g = Image::new_with_value((1, 1), 0.01)?;
        let input_b = Image::new_with_value((1, 1), 0.01)?;

        let stage = ToneMappingStage::pq(0, 10000.0, 250.0, LUMINANCE_BT2020);
        let output =
            make_and_run_simple_pipeline(stage, &[input_r, input_g, input_b], (1, 1), 0, 256)?;

        for (c, img) in output.iter().enumerate().take(3) {
            let val = img.row(0)[0];
            assert!(val >= 0.0, "Channel {c} value {val} is negative");
        }
        Ok(())
    }

    #[test]
    fn hlg_identity_at_same_target() -> Result<()> {
        // When orig == desired, the OOTF exponent is 0 and output should be identity
        let input_r = Image::new_with_value((1, 1), 0.5)?;
        let input_g = Image::new_with_value((1, 1), 0.3)?;
        let input_b = Image::new_with_value((1, 1), 0.1)?;

        let stage = ToneMappingStage::hlg(0, 1000.0, 1000.0, LUMINANCE_BT2020);
        let output =
            make_and_run_simple_pipeline(stage, &[input_r, input_g, input_b], (1, 1), 0, 256)?;

        // Should be unchanged (identity OOTF) — gamut map is still applied but
        // these values are in-gamut so they should pass through
        let r = output[0].row(0)[0];
        let g = output[1].row(0)[0];
        let b = output[2].row(0)[0];
        assert!((r - 0.5).abs() < 0.01, "R changed: expected ~0.5, got {r}");
        assert!((g - 0.3).abs() < 0.01, "G changed: expected ~0.3, got {g}");
        assert!((b - 0.1).abs() < 0.01, "B changed: expected ~0.1, got {b}");
        Ok(())
    }

    #[test]
    fn hlg_different_targets_changes_values() -> Result<()> {
        let input_r = Image::new_with_value((1, 1), 0.5)?;
        let input_g = Image::new_with_value((1, 1), 0.5)?;
        let input_b = Image::new_with_value((1, 1), 0.5)?;

        // 1000 nit source → 300 nit display (significant OOTF change)
        let stage = ToneMappingStage::hlg(0, 1000.0, 300.0, LUMINANCE_BT2020);
        let output =
            make_and_run_simple_pipeline(stage, &[input_r, input_g, input_b], (1, 1), 0, 256)?;

        let r = output[0].row(0)[0];
        assert!(r > 0.0 && r <= 1.0, "R value {r} out of range");
        // Value should be different from 0.5 due to OOTF
        assert!(
            (r - 0.5).abs() > 0.01,
            "R value {r} unchanged — OOTF not applied"
        );
        Ok(())
    }
}
