// Copyright (c) the JPEG XL Project Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use std::{collections::BTreeSet, sync::Arc};

#[cfg(feature = "jpeg")]
use crate::util::TryVecExt;
use crate::{
    api::JxlColorProfile,
    entropy_coding::decode::Histograms,
    error::Result,
    features::{noise::Noise, patches::PatchesDictionary, spline::Splines},
    headers::{
        FileHeader,
        extra_channels::ExtraChannelInfo,
        frame_header::{Encoding, FrameHeader},
        permutation::Permutation,
        toc::Toc,
    },
    image::Image,
    util::{MemoryTracker, tracing_wrappers::*},
};
use adaptive_lf_smoothing::adaptive_lf_smoothing;
use block_context_map::BlockContextMap;
use color_correlation_map::ColorCorrelationParams;
use modular::{FullModularImage, Tree};
use quant_weights::DequantMatrices;
use quantizer::{LfQuantFactors, QuantizerParams};

mod adaptive_lf_smoothing;
mod block_context_map;
mod coeff_order;
pub mod color_correlation_map;
pub mod decode;
mod group;
pub mod lf_preview;
pub mod modular;
mod quant_weights;
pub mod quantizer;
pub mod render;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Section {
    LfGlobal,
    Lf { group: usize },
    HfGlobal,
    Hf { group: usize, pass: usize },
}

pub struct LfGlobalState {
    patches: Option<Arc<PatchesDictionary>>,
    splines: Option<Splines>,
    noise: Option<Noise>,
    lf_quant: LfQuantFactors,
    pub quant_params: Option<QuantizerParams>,
    block_context_map: Option<BlockContextMap>,
    color_correlation_params: Option<ColorCorrelationParams>,
    tree: Option<Tree>,
    modular_global: FullModularImage,
}

pub struct PassState {
    coeff_orders: Vec<Permutation>,
    histograms: Histograms,
}

pub struct HfGlobalState {
    num_histograms: u32,
    passes: Vec<PassState>,
    dequant_matrices: DequantMatrices,
}

#[derive(Debug)]
pub struct ReferenceFrame {
    pub frame: Vec<Image<f32>>,
    pub saved_before_color_transform: bool,
}

impl ReferenceFrame {
    #[cfg(test)]
    pub fn blank(
        width: usize,
        height: usize,
        num_channels: usize,
        saved_before_color_transform: bool,
    ) -> Result<Self> {
        let frame = (0..num_channels)
            .map(|_| Image::new((width, height)))
            .collect::<Result<_>>()?;
        Ok(Self {
            frame,
            saved_before_color_transform,
        })
    }
    #[cfg(test)]
    pub fn random<R: rand::Rng>(
        mut rng: &mut R,
        width: usize,
        height: usize,
        num_channels: usize,
        saved_before_color_transform: bool,
    ) -> Result<Self> {
        let frame = (0..num_channels)
            .map(|_| Image::new_random((width, height), &mut rng))
            .collect::<Result<_>>()?;
        Ok(Self {
            frame,
            saved_before_color_transform,
        })
    }
}

pub struct DecoderState {
    pub(super) file_header: FileHeader,
    pub(super) reference_frames: Arc<[Option<ReferenceFrame>; Self::MAX_STORED_FRAMES]>,
    pub(super) lf_frames: [Option<[Image<f32>; 3]>; 4],
    pub render_spotcolors: bool,
    #[cfg(test)]
    pub use_simple_pipeline: bool,
    pub visible_frame_index: usize,
    pub nonvisible_frame_index: usize,
    pub high_precision: bool,
    pub premultiply_output: bool,
    /// Whether to bake the image's stored EXIF/container orientation into the
    /// output pixels (the save stage applies the orientation transform so the
    /// emitted image is upright). When `false`, the orientation transform is
    /// skipped: pixels are emitted in their stored (coded) orientation and the
    /// caller is expected to read the intrinsic orientation from the basic info
    /// and bake it later if desired. Mirrors
    /// [`crate::api::JxlDecoderOptions::adjust_orientation`].
    pub adjust_orientation: bool,
    /// The embedded color profile from the JXL file (ICC or simple color encoding).
    /// This is needed for CMS-based color space conversion (e.g., CMYK → RGB).
    pub embedded_color_profile: Option<JxlColorProfile>,
    /// Security limits for decoding. Stored here to propagate through frame decoding.
    pub limits: crate::api::JxlDecoderLimits,
    /// Cooperative cancellation / timeout handle.
    pub stop: std::sync::Arc<dyn enough::Stop>,
    /// Memory tracker for enforcing max_memory_bytes limits.
    pub memory_tracker: MemoryTracker,
    /// Desired display intensity target in nits. When set, the decoder applies
    /// tone mapping (Rec.2408 for PQ, OOTF for HLG) to map from the image's
    /// embedded intensity target to this value.
    pub desired_intensity_target: Option<f32>,
    /// Whether parallel decoding/rendering is enabled.
    pub(super) parallel: bool,
    // Whether the latest level 1 LF frame was fully rendered.
    // If this is set to `true`, early flushing in the main frame
    // (before HF is available) will do nothing.
    pub lf_frame_was_rendered: bool,
}

impl DecoderState {
    pub const MAX_STORED_FRAMES: usize = 4;

    pub fn new(file_header: FileHeader) -> Self {
        Self {
            file_header,
            reference_frames: Arc::new([None, None, None, None]),
            lf_frames: [None, None, None, None],
            render_spotcolors: true,
            #[cfg(test)]
            use_simple_pipeline: false,
            visible_frame_index: 0,
            nonvisible_frame_index: 0,
            high_precision: false,
            premultiply_output: false,
            adjust_orientation: true,
            desired_intensity_target: None,
            embedded_color_profile: None,
            limits: crate::api::JxlDecoderLimits::default(),
            stop: std::sync::Arc::new(enough::Unstoppable),
            memory_tracker: MemoryTracker::unlimited(),
            parallel: false,
            lf_frame_was_rendered: false,
        }
    }

    /// Check cancellation status and return error if cancelled.
    pub fn check_cancelled(&self) -> crate::error::Result<()> {
        Ok(self.stop.check()?)
    }

    pub fn extra_channel_info(&self) -> &Vec<ExtraChannelInfo> {
        &self.file_header.image_metadata.extra_channel_info
    }

    #[allow(dead_code)] // Part of DecoderState public API
    pub fn reference_frame(&self, i: usize) -> Option<&ReferenceFrame> {
        assert!(i < Self::MAX_STORED_FRAMES);
        self.reference_frames[i].as_ref()
    }

    #[cfg(test)]
    pub fn set_use_simple_pipeline(&mut self, u: bool) {
        self.use_simple_pipeline = u;
    }
}

impl std::fmt::Debug for DecoderState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecoderState")
            .field("visible_frame_index", &self.visible_frame_index)
            .field("nonvisible_frame_index", &self.nonvisible_frame_index)
            .field("high_precision", &self.high_precision)
            .field("parallel", &self.parallel)
            .finish_non_exhaustive()
    }
}

pub struct HfMetadata {
    ytox_map: Image<i8>,
    ytob_map: Image<i8>,
    pub raw_quant_map: Image<i32>,
    pub transform_map: Image<u8>,
    pub epf_map: Image<u8>,
    used_hf_types: u32,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RenderUnit {
    /// VarDCT data
    VarDCT,
    /// Modular channel with the given index
    Modular(usize),
}

pub struct Frame {
    header: FrameHeader,
    toc: Toc,
    color_channels: usize,
    lf_global: Option<LfGlobalState>,
    hf_global: Option<HfGlobalState>,
    /// Multi-pass HF coefficient accumulation buffer. Separate from HfGlobalState
    /// so that `&HfGlobalState` and `&mut hf_coefficients` can be borrowed independently,
    /// enabling parallel VarDCT group decode for single-pass frames.
    /// Each element is a Vec of per-group coefficient buffers (one Vec<i32> per group per channel).
    hf_coefficients: Option<[Vec<Vec<i32>>; 3]>,
    lf_image: Option<[Image<f32>; 3]>,
    quant_lf: Image<u8>,
    hf_meta: Option<HfMetadata>,
    pub(crate) decoder_state: DecoderState,
    #[cfg(test)]
    use_simple_pipeline: bool,
    #[cfg(test)]
    render_pipeline: Option<Box<dyn std::any::Any>>,
    #[cfg(not(test))]
    render_pipeline: Option<Box<crate::render::LowMemoryRenderPipeline>>,
    reference_frame_data: Option<Vec<Image<f32>>>,
    lf_frame_data: Option<[Image<f32>; 3]>,
    was_flushed_once: bool,
    /// Reusable buffers for VarDCT group decoding.
    vardct_buffers: Option<group::VarDctBuffers>,
    /// JPEG coefficient storage for JPEG reconstruction.
    /// Per-channel arrays of i16 coefficients at image-wide block positions.
    #[cfg(feature = "jpeg")]
    jpeg_coeffs: Option<[Vec<i16>; 3]>,
    // Last pass rendered so far for each HF group.
    last_rendered_pass: Vec<Option<usize>>,
    // Groups that should be rendered on the next call to flush().
    groups_to_flush: BTreeSet<usize>,
    changed_since_last_flush: BTreeSet<(usize, RenderUnit)>,
    incomplete_groups: usize,
}

impl Frame {
    pub fn toc(&self) -> &Toc {
        &self.toc
    }

    pub fn header(&self) -> &FrameHeader {
        &self.header
    }

    /// Returns true if the render pipeline has not been prepared yet.
    pub fn render_pipeline_not_ready(&self) -> bool {
        self.render_pipeline.is_none()
    }

    #[allow(dead_code)] // Part of Frame public API
    pub fn total_bytes_in_toc(&self) -> usize {
        self.toc.entries.iter().map(|x| *x as usize).sum()
    }

    #[instrument(level = "debug", skip(self), ret)]
    pub fn get_section_idx(&self, section: Section) -> usize {
        if self.header.num_toc_entries() == 1 {
            0
        } else {
            match section {
                Section::LfGlobal => 0,
                Section::Lf { group } => 1 + group,
                Section::HfGlobal => self.header.num_lf_groups() + 1,
                Section::Hf { group, pass } => {
                    2 + self.header.num_lf_groups() + self.header.num_groups() * pass + group
                }
            }
        }
    }

    pub fn finalize_lf(&mut self) -> Result<()> {
        if self.header.should_do_adaptive_lf_smoothing() {
            let lf_global = self.lf_global.as_ref().unwrap();
            let lf_quant = &lf_global.lf_quant;
            let inv_quant_lf = lf_global.quant_params.as_ref().unwrap().inv_quant_lf();
            adaptive_lf_smoothing(
                [
                    inv_quant_lf * lf_quant.quant_factors[0],
                    inv_quant_lf * lf_quant.quant_factors[1],
                    inv_quant_lf * lf_quant.quant_factors[2],
                ],
                self.lf_image.as_mut().unwrap(),
                #[cfg(feature = "threads")]
                self.decoder_state.parallel,
            )
        } else {
            Ok(())
        }
    }

    pub fn finalize(mut self) -> Result<Option<DecoderState>> {
        // First, drop the render pipeline to ensure that no other references to the reference
        // frames are around.
        self.render_pipeline = None;
        // Save reference frame if this frame can be referenced and was actually decoded.
        // If reference_frame_data is None (frame was skipped), we don't save it.
        // Subsequent frames referencing this slot may fail.
        if self.header.can_be_referenced
            && let Some(frame_data) = self.reference_frame_data
        {
            let slot = self.header.save_as_reference as usize;
            // Check reference frame limit
            if let Some(limit) = self.decoder_state.limits.max_reference_frames
                && slot >= limit
            {
                return Err(crate::error::Error::LimitExceeded {
                    resource: "reference_frames",
                    actual: (slot + 1) as u64,
                    limit: limit as u64,
                });
            }
            info!("Saving frame in slot {}", self.header.save_as_reference);
            let rf = Arc::get_mut(&mut self.decoder_state.reference_frames)
                .expect("remaining references to reference_frames");
            rf[slot] = Some(ReferenceFrame {
                frame: frame_data,
                saved_before_color_transform: self.header.save_before_ct,
            });
        }

        if self.header.lf_level != 0 {
            self.decoder_state.lf_frames[(self.header.lf_level - 1) as usize] = self.lf_frame_data;
        }
        let decoder_state = if self.header.is_last {
            None
        } else {
            Some(self.decoder_state)
        };
        Ok(decoder_state)
    }

    fn modular_color_channels(&self) -> usize {
        if self.header.encoding == Encoding::VarDCT {
            0
        } else {
            self.color_channels
        }
    }

    /// Enable JPEG coefficient capture for JPEG reconstruction.
    /// Must be called before any HF group decode.
    #[cfg(feature = "jpeg")]
    pub fn enable_jpeg_reconstruction(&mut self) {
        // Use padded block dimensions (accounts for chroma subsampling)
        let (xsize_blocks, ysize_blocks) = self.header.size_blocks();
        let block_count = xsize_blocks * ysize_blocks;
        self.jpeg_coeffs = Some([
            vec![0i16; block_count * 64],
            vec![0i16; block_count * 64],
            vec![0i16; block_count * 64],
        ]);
    }

    /// Reconstruct the original JPEG from captured coefficients and JBRD metadata.
    ///
    /// Must be called after all LF and HF groups have been decoded.
    /// Returns the byte-exact original JPEG file.
    #[cfg(feature = "jpeg")]
    /// Build the reconstruction [`JpegData`] (coefficients + structure). The
    /// EXIF/XMP APPn payloads are left as empty placeholders here and filled
    /// later in `take_jpeg_reconstruction`, from container boxes that are parsed
    /// *after* the codestream. Run `write_jpeg` on the result for the bytes.
    ///
    /// [`JpegData`]: crate::jpeg::data::JpegData
    pub fn jpeg_reconstruct(
        &self,
        jbrd_data: &[u8],
    ) -> crate::error::Result<crate::jpeg::data::JpegData> {
        use crate::jpeg::data::JpegComponentType;
        use crate::jpeg::decode_jbrd;

        // kCFLFixedPointPrecision from libjxl — fixed-point precision for CfL
        const CFL_FP: i32 = 11;
        // kDefaultColorFactor
        const COLOR_FACTOR: i32 = 84;

        let mut jpeg = decode_jbrd(jbrd_data, self.header.width, self.header.height)?;
        let num_components = jpeg.components.len();

        // Get raw quant table from HF global (stored during Raw quant decode)
        let hf_global = self
            .hf_global
            .as_ref()
            .ok_or_else(|| crate::error::Error::InvalidJbrd("no HF global state".into()))?;
        let (raw_qt, _qtable_den) = hf_global
            .dequant_matrices
            .raw_qtable
            .as_ref()
            .ok_or_else(|| crate::error::Error::InvalidJbrd("no raw quant table".into()))?;

        // Channel mapping: JPEG component index → JXL channel index
        // JXL c0←JPEG Cb, c1←JPEG Y, c2←JPEG Cr
        let jpeg_to_jxl: Vec<usize> = if num_components == 1 {
            // Grayscale: the encoder routes the single (luma) component into the
            // JXL Y channel (index 1) and zero-fills channels 0/2 (jxl-encoder
            // encode.rs grayscale zero-fill). Reading channel 0 would yield an
            // all-zero plane → an all-zero (truncated) reconstruction.
            vec![1]
        } else {
            match jpeg.component_type {
                JpegComponentType::YCbCr => vec![1, 0, 2],
                _ => (0..num_components).collect(),
            }
        };

        // Fill quant table values from raw_qtable (transpose JXL→JPEG natural order)
        for (jpeg_c, &jxl_c) in jpeg_to_jxl.iter().enumerate() {
            if jpeg_c >= jpeg.components.len() {
                break;
            }
            let quant_idx = jpeg.components[jpeg_c].quant_idx as usize;
            if quant_idx < jpeg.quant.len() {
                for y in 0..8 {
                    for x in 0..8 {
                        // JXL stores transposed: raw_qt[c*64 + x*8+y] = JPEG qt[y*8+x]
                        jpeg.quant[quant_idx].values[y * 8 + x] = raw_qt[jxl_c * 64 + x * 8 + y];
                    }
                }
            }
        }

        // Set sampling factors from frame header's jpeg_upsampling
        for (jpeg_c, &jxl_c) in jpeg_to_jxl.iter().enumerate() {
            if jpeg_c >= jpeg.components.len() {
                break;
            }
            let comp = &mut jpeg.components[jpeg_c];
            comp.h_samp_factor = 1 << self.header.raw_hshift(jxl_c);
            comp.v_samp_factor = 1 << self.header.raw_vshift(jxl_c);
        }

        // DC recovery parameters
        let lf_global = self
            .lf_global
            .as_ref()
            .ok_or_else(|| crate::error::Error::InvalidJbrd("no LF global state".into()))?;
        let quant_params = lf_global
            .quant_params
            .as_ref()
            .ok_or_else(|| crate::error::Error::InvalidJbrd("no quant params".into()))?;
        let inv_quant_lf = (quantizer::GLOBAL_SCALE_DENOM as f32)
            / (quant_params.global_scale as f32 * quant_params.quant_lf as f32);
        let lf_factors = lf_global.lf_quant.quant_factors.map(|f| f * inv_quant_lf);

        // DC offset: only applied when color_transform is kNone (not YCbCr).
        // For JPEG YCbCr mode (do_ycbcr=true), dcoff is 0.
        let use_dcoff = !self.header.do_ycbcr;

        let lf_image = self
            .lf_image
            .as_ref()
            .ok_or_else(|| crate::error::Error::InvalidJbrd("no lf_image".into()))?;
        let jpeg_coeffs = self.jpeg_coeffs.as_ref().ok_or_else(|| {
            crate::error::Error::InvalidJbrd("JPEG coefficient capture not enabled".into())
        })?;

        // Frame-level padded block dimensions (accounts for chroma subsampling)
        let (frame_xblocks, _frame_yblocks) = self.header.size_blocks();

        // Check if all channels are 4:4:4 (no subsampling)
        let is_444 =
            (0..3).all(|c| self.header.raw_hshift(c) == 0 && self.header.raw_vshift(c) == 0);

        // CfL maps for undoing chroma-from-luma decorrelation
        let hf_meta = self.hf_meta.as_ref();

        // Pre-compute scaled quant table ratios for CfL undo.
        // scaled_qtable[c][j] = (Y_qt[freq] << CFL_FP) / Chroma_qt[freq]
        // indexed in JPEG natural order (j = row*8+col).
        let scaled_qtable: [[i32; 64]; 3] = {
            let mut sq = [[0i32; 64]; 3];
            for c in [0usize, 2] {
                for (j, sq_val) in sq[c].iter_mut().enumerate() {
                    let jxl_pos = (j % 8) * 8 + (j / 8);
                    let num = raw_qt[64 + jxl_pos]; // Y channel (JXL c1)
                    let den = raw_qt[c * 64 + jxl_pos]; // Chroma channel
                    if num > 0 && den > 0 {
                        *sq_val = (num << CFL_FP) / den;
                    }
                }
            }
            sq
        };

        // Set per-component block dimensions from frame header
        let maxhs = self.header.maxhs as usize;
        let maxvs = self.header.maxvs as usize;
        for (jpeg_c, &jxl_c) in jpeg_to_jxl.iter().enumerate() {
            if jpeg_c >= jpeg.components.len() {
                break;
            }
            let hshift_c = maxhs - self.header.raw_hshift(jxl_c);
            let vshift_c = maxvs - self.header.raw_vshift(jxl_c);
            let comp = &mut jpeg.components[jpeg_c];
            comp.width_in_blocks = (frame_xblocks >> hshift_c) as u32;
            comp.height_in_blocks = (_frame_yblocks >> vshift_c) as u32;
        }

        // Build per-component coefficient arrays
        for (jpeg_c, &jxl_c) in jpeg_to_jxl.iter().enumerate() {
            if jpeg_c >= jpeg.components.len() {
                break;
            }
            let comp = &mut jpeg.components[jpeg_c];
            let wb = comp.width_in_blocks as usize;
            let hb = comp.height_in_blocks as usize;
            let num_blocks = wb * hb;
            comp.coeffs = Vec::try_from_elem(0i16, num_blocks * 64)?;

            // HShift/VShift for mapping component blocks to frame-level block grid
            let hshift_c = maxhs - self.header.raw_hshift(jxl_c);
            let vshift_c = maxvs - self.header.raw_vshift(jxl_c);

            let q_dc = raw_qt[jxl_c * 64];
            let dcoff = if use_dcoff && q_dc != 0 {
                1024 / q_dc
            } else {
                0
            };
            let fac = lf_factors[jxl_c];

            for by in 0..hb {
                for bx in 0..wb {
                    let block_idx = by * wb + bx;

                    // Map component block to frame-level block position
                    // For subsampled channels: frame_bx = comp_bx << hshift
                    let frame_bx = bx << hshift_c;
                    let frame_by = by << vshift_c;

                    // DC recovery from lf_image
                    let dc_float = lf_image[jxl_c].row(by)[bx];
                    let quant_dc_int = (dc_float / fac).round() as i32;
                    let jpeg_dc = quant_dc_int - dcoff;
                    comp.coeffs[block_idx * 64] = jpeg_dc.clamp(-2047, 2047) as i16;

                    // AC coefficients from captured data (already transposed to JPEG order)
                    // Captured at frame-level block position
                    let src_offset = (frame_by * frame_xblocks + frame_bx) * 64;
                    if src_offset + 64 <= jpeg_coeffs[jxl_c].len() {
                        for k in 1..64 {
                            comp.coeffs[block_idx * 64 + k] = jpeg_coeffs[jxl_c][src_offset + k];
                        }
                    }

                    // CfL undo for chroma channels (JXL c0=Cb, c2=Cr)
                    // libjxl's encoder applies integer CfL decorrelation for 4:4:4 JPEGs:
                    //   stored_chroma = original_chroma - cfl_factor
                    // We undo it:
                    //   original_chroma = stored_chroma + cfl_factor
                    if is_444
                        && (jxl_c == 0 || jxl_c == 2)
                        && let Some(meta) = hf_meta
                    {
                        let tile_x = frame_bx / color_correlation_map::COLOR_TILE_DIM_IN_BLOCKS;
                        let tile_y = frame_by / color_correlation_map::COLOR_TILE_DIM_IN_BLOCKS;
                        let map_val = if jxl_c == 0 {
                            meta.ytox_map.row(tile_y)[tile_x] as i32
                        } else {
                            meta.ytob_map.row(tile_y)[tile_x] as i32
                        };

                        if map_val != 0 {
                            // RatioJPEG: factor * (1 << CFL_FP) / kDefaultColorFactor
                            let scale = map_val * (1 << CFL_FP) / COLOR_FACTOR;
                            let round = 1i32 << (CFL_FP - 1);

                            // Y coefficients at the same frame block position (JXL c1)
                            let y_offset = src_offset;

                            for k in 1..64 {
                                let y_coeff = jpeg_coeffs[1][y_offset + k] as i32;
                                let qt = scaled_qtable[jxl_c][k];
                                let coeff_scale = (qt * scale + round) >> CFL_FP;
                                let cfl_factor = (y_coeff * coeff_scale + round) >> CFL_FP;
                                comp.coeffs[block_idx * 64 + k] += cfl_factor as i16;
                            }
                        }
                    }
                }
            }
        }

        Ok(jpeg)
    }
}

#[cfg(test)]
mod test {
    use std::panic;

    use crate::{
        error::{Error, Result},
        features::spline::Point,
        util::test::assert_almost_abs_eq,
    };
    use test_log::test;

    use super::Frame;

    fn decode(
        bytes: &[u8],
        verify: impl Fn(&Frame, usize) -> Result<()> + 'static,
    ) -> Result<usize> {
        crate::api::tests::decode(bytes, usize::MAX, false, false, Some(Box::new(verify)))
            .map(|x| x.0)
    }

    #[test]
    fn splines() -> Result<(), Error> {
        let verify_frame = move |frame: &Frame, _| {
            let lf_global = frame.lf_global.as_ref().unwrap();
            let splines = lf_global.splines.as_ref().unwrap();
            assert_eq!(splines.quantization_adjustment, 0);
            let expected_starting_points = [Point { x: 9.0, y: 54.0 }].to_vec();
            assert_eq!(splines.starting_points, expected_starting_points);
            assert_eq!(splines.splines.len(), 1);
            let spline = splines.splines[0].clone();
            let expected_control_points = [
                (109, 105),
                (-130, -261),
                (-66, 193),
                (227, -52),
                (-170, 290),
            ]
            .to_vec();
            assert_eq!(spline.control_points.clone(), expected_control_points);

            const EXPECTED_COLOR_DCT: [[i32; 32]; 3] = [
                {
                    let mut row = [0; 32];
                    row[0] = 168;
                    row[1] = 119;
                    row
                },
                {
                    let mut row = [0; 32];
                    row[0] = 9;
                    row[2] = 7;
                    row
                },
                {
                    let mut row = [0; 32];
                    row[0] = -10;
                    row[1] = 7;
                    row
                },
            ];
            assert_eq!(spline.color_dct, EXPECTED_COLOR_DCT);
            const EXPECTED_SIGMA_DCT: [i32; 32] = {
                let mut dct = [0; 32];
                dct[0] = 4;
                dct[7] = 2;
                dct
            };
            assert_eq!(spline.sigma_dct, EXPECTED_SIGMA_DCT);
            Ok(())
        };
        assert_eq!(
            decode(
                include_bytes!("../../resources/test/splines.jxl"),
                verify_frame
            )?,
            1
        );
        Ok(())
    }

    #[test]
    fn noise() -> Result<(), Error> {
        let verify_frame = |frame: &Frame, _| {
            let lf_global = frame.lf_global.as_ref().unwrap();
            let noise = lf_global.noise.as_ref().unwrap();
            let want_noise = [
                0.000000, 0.000977, 0.002930, 0.003906, 0.005859, 0.006836, 0.008789, 0.010742,
            ];
            for (index, noise_param) in want_noise.iter().enumerate() {
                assert_almost_abs_eq(noise.lut[index], *noise_param, 1e-6);
            }
            Ok(())
        };
        assert_eq!(
            decode(
                include_bytes!("../../resources/test/8x8_noise.jxl"),
                verify_frame,
            )?,
            1
        );
        Ok(())
    }

    #[test]
    fn patches() -> Result<(), Error> {
        let verify_frame = |frame: &Frame, frame_index| {
            if frame_index == 0 {
                assert!(!frame.header().has_patches());
                assert!(frame.header().can_be_referenced);
            } else if frame_index == 1 {
                assert!(frame.header().has_patches());
                assert!(!frame.header().can_be_referenced);
            }
            Ok(())
        };
        assert_eq!(
            decode(
                include_bytes!("../../resources/test/grayscale_patches_modular.jxl"),
                verify_frame,
            )?,
            2
        );
        Ok(())
    }

    #[test]
    fn multiple_lf_420() -> Result<(), Error> {
        let verify_frame = |frame: &Frame, _| {
            assert!(frame.header().is420());
            let Some(lf_image) = &frame.lf_image else {
                panic!("no lf_image");
            };
            for y in 0..146 {
                let sample_cb_row = lf_image[0].row(y);
                let sample_cr_row = lf_image[2].row(y);
                for x in 0..146 {
                    let sample_cb = sample_cb_row[x];
                    let sample_cr = sample_cr_row[x];
                    let no_chroma = sample_cb == 0.0 && sample_cr == 0.0;
                    if y < 128 || x < 128 {
                        assert!(!no_chroma);
                    } else {
                        assert!(no_chroma);
                    }
                }
            }
            Ok(())
        };
        decode(
            include_bytes!("../../resources/test/multiple_lf_420.jxl"),
            verify_frame,
        )?;
        Ok(())
    }

    #[test]
    fn xyb_grayscale_patches() -> Result<(), Error> {
        let verify_frame = |frame: &Frame, frame_index| {
            if frame_index == 0 {
                assert_eq!(
                    frame.header.frame_type,
                    crate::headers::frame_header::FrameType::ReferenceOnly,
                );
                assert_eq!(
                    frame.header.encoding,
                    crate::headers::frame_header::Encoding::Modular,
                );
                assert_eq!(frame.modular_color_channels(), 3);
            } else {
                assert!(frame.header.has_patches());
                assert_eq!(frame.modular_color_channels(), 0);
            }
            Ok(())
        };
        assert_eq!(
            decode(
                include_bytes!("../../resources/test/grayscale_patches_var_dct.jxl"),
                verify_frame,
            )?,
            2
        );
        Ok(())
    }
}
