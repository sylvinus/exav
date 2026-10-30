// Copyright (c) the JPEG XL Project Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use std::collections::BTreeSet;
use std::sync::Arc;

use super::render::pipeline;
use super::{
    block_context_map::BlockContextMap,
    coeff_order::decode_coeff_orders,
    color_correlation_map::ColorCorrelationParams,
    group::{VarDctBuffers, decode_vardct_group},
    modular::{FullModularImage, ModularStreamId, Tree, decode_hf_metadata, decode_vardct_lf},
    quant_weights::DequantMatrices,
    quantizer::{LfQuantFactors, QuantizerParams},
};
use crate::error::Error;
use crate::frame::block_context_map::{ZERO_DENSITY_CONTEXT_COUNT, ZERO_DENSITY_CONTEXT_LIMIT};
use crate::headers::frame_header::FrameType;
#[cfg(test)]
use crate::render::SimpleRenderPipeline;
use crate::render::buffer_splitter::BufferSplitter;
use crate::transforms::transform_map::*;
use crate::util::{ShiftRightCeil, mirror};
use crate::{
    GROUP_DIM,
    bit_reader::BitReader,
    entropy_coding::decode::Histograms,
    error::Result,
    features::{noise::Noise, patches::PatchesDictionary, spline::Splines},
    frame::{
        DecoderState, Frame, HfGlobalState, HfMetadata, LfGlobalState, PassState, coeff_order,
    },
    headers::{
        color_encoding::ColorSpace,
        frame_header::{Encoding, FrameHeader},
        toc::Toc,
    },
    image::Image,
    render::RenderPipeline,
    util::{CeilLog2, Xorshift128Plus, tracing_wrappers::*},
};

#[cfg(feature = "threads")]
use super::modular::decode_hf_metadata_into_rects;
use crate::headers::CustomTransformData;
#[cfg(feature = "threads")]
use crate::image::Rect;
use crate::render::RenderPipelineInOutStage;
use crate::render::stages::Upsample8x;
use crate::render::{Channels, ChannelsMut};

pub(super) fn upsample_lf_group(
    group: usize,
    pixels: &mut [Image<f32>; 3],
    lf_image: &[Image<f32>; 3],
    header: &FrameHeader,
    factors: &CustomTransformData,
) -> Result<()> {
    let group_dim = header.group_dim();
    let lf_group_dim = group_dim / 8;
    let (width_groups, _) = header.size_groups();
    let gx = group % width_groups;
    let gy = group / width_groups;

    let upsample = Upsample8x::new(factors, 0);
    let mut state = upsample.init_local_state(0)?.unwrap();

    let max_width = pixels.iter().map(|x| x.size().0).max().unwrap();

    // Temporary buffer for 8 output rows
    // We reuse this buffer for each iteration to minimize allocation
    let mut temp_out_buf: [_; 8] = std::array::from_fn(|_| vec![0.0f32; max_width + 128]);

    let mut input_rows_storage: [_; 5] = std::array::from_fn(|_| vec![0.0; max_width / 8 + 32]);

    for c in 0..3 {
        let lf_img = &lf_image[c];
        let out_img = &mut pixels[c];
        let (out_width, out_height) = out_img.size();

        let vs = header.vshift(c);
        let hs = header.hshift(c);

        let lf_group_dim_x = lf_group_dim >> hs;
        let lf_group_dim_y = lf_group_dim >> vs;
        let lf_x0 = gx * lf_group_dim_x;
        let lf_y0 = gy * lf_group_dim_y;

        let lf_width = lf_img.size().0.shrc(hs);
        let lf_height = lf_img.size().1.shrc(hs);

        let start_x = lf_x0.saturating_sub(2);
        let lf_x1 = (lf_x0 + lf_group_dim_x).min(lf_width);
        let end_x = (lf_x1 + 2).min(lf_width);
        let copy_width = end_x - start_x;

        for y in 0..lf_group_dim_y {
            let cy = lf_y0 + y;

            for dy in -2..=2 {
                let iy = cy as isize + dy;
                let iy = mirror(iy, lf_height);

                let storage = &mut input_rows_storage[(dy + 2) as usize];

                let save_start = if start_x == lf_x0 { 2 } else { 0 };
                let save_end = save_start + copy_width;

                storage[save_start..save_end].copy_from_slice(&lf_img.row(iy)[start_x..end_x]);

                if start_x == lf_x0 {
                    storage[0] = storage[2 + mirror(-2, copy_width)];
                    storage[1] = storage[2 + mirror(-1, copy_width)];
                }
                if end_x == lf_x1 {
                    storage[save_end] = storage[save_start + mirror(save_end as isize, save_end)];
                    storage[save_end + 1] =
                        storage[save_start + mirror(save_end as isize + 1, save_end)];
                }
            }

            let input_rows_refs = input_rows_storage.iter().map(|x| &x[..]).collect();
            let input_channels = Channels::new(input_rows_refs, 1, 5);

            {
                // Prepare output refs
                let output_rows_refs = temp_out_buf.iter_mut().map(|x| &mut x[..]).collect();
                let mut output_channels = ChannelsMut::new(output_rows_refs, 1, 8);

                upsample.process_row_chunk(
                    (0, 0),
                    lf_x1 - lf_x0,
                    &input_channels,
                    &mut output_channels,
                    Some(state.as_mut()),
                );
            }

            // Copy back to out_img
            let base_y = y * 8;
            for (i, buf) in temp_out_buf.iter().enumerate() {
                let out_y = base_y + i;
                if out_y < out_height {
                    out_img.row_mut(out_y)[..out_width].copy_from_slice(&buf[..out_width]);
                }
            }
        }
    }
    Ok(())
}

impl Frame {
    pub fn from_header_and_toc(
        frame_header: FrameHeader,
        toc: Toc,
        mut decoder_state: DecoderState,
    ) -> Result<Self> {
        if frame_header.is_visible() {
            decoder_state.visible_frame_index += 1;
            decoder_state.nonvisible_frame_index = 0;
        } else {
            decoder_state.nonvisible_frame_index += 1;
        }
        if frame_header.frame_type == FrameType::LFFrame && frame_header.lf_level == 1 {
            decoder_state.lf_frame_was_rendered = false;
        }
        let image_metadata = &decoder_state.file_header.image_metadata;
        let is_gray = !frame_header.do_ycbcr
            && !image_metadata.xyb_encoded
            && image_metadata.color_encoding.color_space == ColorSpace::Gray;
        let color_channels = if is_gray { 1 } else { 3 };
        let size_blocks = frame_header.size_blocks();
        let tracker = &decoder_state.memory_tracker;
        let lf_image = if frame_header.encoding == Encoding::VarDCT {
            if frame_header.has_lf_frame() {
                if let Some([a, b, c]) = &decoder_state.lf_frames[frame_header.lf_level as usize] {
                    Some([a.try_clone()?, b.try_clone()?, c.try_clone()?])
                } else {
                    return Err(Error::NoLfFrame(frame_header.lf_level));
                }
            } else {
                Some([
                    Image::new_tracked(size_blocks, tracker)?,
                    Image::new_tracked(size_blocks, tracker)?,
                    Image::new_tracked(size_blocks, tracker)?,
                ])
            }
        } else {
            None
        };
        let quant_lf = Image::new_tracked(size_blocks, tracker)?;
        let size_color_tiles = (size_blocks.0.div_ceil(8), size_blocks.1.div_ceil(8));
        let hf_meta = if frame_header.encoding == Encoding::VarDCT {
            Some(HfMetadata {
                ytox_map: Image::new_tracked(size_color_tiles, tracker)?,
                ytob_map: Image::new_tracked(size_color_tiles, tracker)?,
                raw_quant_map: Image::new_tracked(size_blocks, tracker)?,
                transform_map: Image::new_with_value(
                    size_blocks,
                    HfTransformType::INVALID_TRANSFORM,
                )?,
                epf_map: Image::new_tracked(size_blocks, tracker)?,
                used_hf_types: 0,
            })
        } else {
            None
        };

        let reference_frame_data = if frame_header.can_be_referenced {
            let image_size = &decoder_state.file_header.size;
            let image_size = (image_size.xsize() as usize, image_size.ysize() as usize);
            let sz = if frame_header.save_before_ct {
                frame_header.size_upsampled()
            } else {
                image_size
            };

            let num_ref_channels = 3 + image_metadata.extra_channel_info.len();
            Some(
                (0..num_ref_channels)
                    .map(|_| Image::new_tracked(sz, tracker))
                    .collect::<Result<Vec<_>>>()?,
            )
        } else {
            None
        };

        let lf_frame_data = if frame_header.lf_level != 0 {
            let upsampled = frame_header.size_upsampled();
            Some(
                (0..3)
                    .map(|_| Image::new_tracked(upsampled, tracker))
                    .collect::<Result<Vec<_>, _>>()?
                    .try_into()
                    .unwrap(),
            )
        } else {
            None
        };

        Ok(Self {
            #[cfg(test)]
            use_simple_pipeline: decoder_state.use_simple_pipeline,
            last_rendered_pass: vec![None; frame_header.num_groups()],
            incomplete_groups: frame_header.num_groups(),
            header: frame_header,
            color_channels,
            toc,
            lf_global: None,
            hf_global: None,
            hf_coefficients: None,
            lf_image,
            quant_lf,
            hf_meta,
            decoder_state,
            render_pipeline: None,
            reference_frame_data,
            lf_frame_data,
            was_flushed_once: false,
            vardct_buffers: None,
            #[cfg(feature = "jpeg")]
            jpeg_coeffs: None,
            groups_to_flush: BTreeSet::new(),
            changed_since_last_flush: BTreeSet::new(),
        })
    }

    pub fn allow_rendering_before_last_pass(&self) -> bool {
        if self
            .lf_global
            .as_ref()
            .is_none_or(|x| !x.modular_global.can_do_partial_render())
        {
            return false;
        }

        self.header.frame_type == FrameType::RegularFrame
            || (self.header.frame_type == FrameType::LFFrame
                && self.header.lf_level == 1
                // TODO(veluca): this should probably be "there is no alpha".
                && self.header.num_extra_channels == 0)
    }

    /// Given a bit reader pointing at the end of the TOC, returns a vector of `BitReader`s, each
    /// of which reads a specific section.
    #[allow(dead_code)] // TOC-based section splitting for future incremental decode
    pub fn sections<'a>(&self, br: &'a mut BitReader) -> Result<Vec<BitReader<'a>>> {
        debug!(toc = ?self.toc);
        let ret = self
            .toc
            .entries
            .iter()
            .scan(br, |br, count| Some(br.split_at(*count as usize)))
            .collect::<Result<Vec<_>>>()?;
        if !self.toc.permuted {
            return Ok(ret);
        }
        let mut inv_perm = vec![0; ret.len()];
        for (i, pos) in self.toc.permutation.iter().enumerate() {
            inv_perm[*pos as usize] = i;
        }
        let mut shuffled_ret = ret.clone();
        for (br, pos) in ret.into_iter().zip(inv_perm) {
            shuffled_ret[pos] = br;
        }
        Ok(shuffled_ret)
    }

    #[instrument(level = "debug", skip_all)]
    pub fn decode_lf_global(&mut self, br: &mut BitReader) -> Result<()> {
        // Check for cancellation at start of major decode step
        self.decoder_state.check_cancelled()?;
        debug!(section_size = br.total_bits_available());
        assert!(self.lf_global.is_none());
        trace!(pos = br.total_bits_read());

        let patches = if self.header.has_patches() {
            info!("decoding patches");
            Some(PatchesDictionary::read(
                br,
                self.header.size_padded().0,
                self.header.size_padded().1,
                self.decoder_state.extra_channel_info().len(),
                &self.decoder_state.reference_frames[..],
                self.decoder_state.limits.max_patches,
                &self.decoder_state.memory_tracker,
            )?)
        } else {
            None
        };

        let splines = if self.header.has_splines() {
            info!("decoding splines");
            Some(Splines::read(
                br,
                self.header.width * self.header.height,
                self.decoder_state.limits.max_spline_points,
                &self.decoder_state.memory_tracker,
            )?)
        } else {
            None
        };

        let noise = if self.header.has_noise() {
            info!("decoding noise");
            Some(Noise::read(br)?)
        } else {
            None
        };

        let lf_quant = LfQuantFactors::new(br)?;
        debug!(?lf_quant);

        let quant_params = if self.header.encoding == Encoding::VarDCT {
            info!("decoding VarDCT quantizer params");
            Some(QuantizerParams::read(br)?)
        } else {
            None
        };
        debug!(?quant_params);

        let block_context_map = if self.header.encoding == Encoding::VarDCT {
            info!("decoding block context map");
            Some(BlockContextMap::read(br)?)
        } else {
            None
        };
        debug!(?block_context_map);

        let color_correlation_params = if self.header.encoding == Encoding::VarDCT {
            info!("decoding color correlation params");
            Some(ColorCorrelationParams::read(br)?)
        } else {
            None
        };
        debug!(?color_correlation_params);

        let tree = if br.read(1)? == 1 {
            // Calculate dynamic size limit based on image dimensions
            let dynamic_limit = 1024
                + self.header.width as usize
                    * self.header.height as usize
                    * (self.color_channels + self.decoder_state.extra_channel_info().len())
                    / 16;
            // Use configured limit if set, otherwise use 2^22 default
            let configured_limit = self.decoder_state.limits.max_tree_size.unwrap_or(1 << 22);
            let size_limit = dynamic_limit.min(configured_limit);
            Some(Tree::read(
                br,
                size_limit,
                &self.decoder_state.memory_tracker,
            )?)
        } else {
            None
        };

        let modular_global = FullModularImage::read(
            &self.header,
            &self.decoder_state.file_header.image_metadata,
            self.modular_color_channels(),
            &tree,
            br,
            &self.decoder_state.memory_tracker,
        )?;

        self.lf_global = Some(LfGlobalState {
            patches: patches.map(Arc::new),
            splines,
            noise,
            lf_quant,
            quant_params,
            block_context_map,
            color_correlation_params,
            tree,
            modular_global,
        });

        Ok(())
    }

    /// The VarDCT quantizer `(global_scale, quant_lf)` for this frame, if it is
    /// a VarDCT frame whose `LfGlobal` section has been decoded. The codestream
    /// parser persists the first regular frame's value so a probe can recover
    /// the main image's encode quality without rendering pixels.
    pub(crate) fn vardct_quantizer(&self) -> Option<(u32, u32)> {
        let qp = self.lf_global.as_ref()?.quant_params.as_ref()?;
        Some((qp.global_scale, qp.quant_lf))
    }

    #[instrument(level = "debug", skip(self, br))]
    pub fn decode_lf_group(&mut self, group: usize, br: &mut BitReader) -> Result<()> {
        debug!(section_size = br.total_bits_available());
        let lf_global = self.lf_global.as_mut().unwrap();
        if self.header.encoding == Encoding::VarDCT && !self.header.has_lf_frame() {
            info!("decoding VarDCT LF with group id {}", group);
            decode_vardct_lf(
                group,
                &self.header,
                &self.decoder_state.file_header.image_metadata,
                &lf_global.tree,
                lf_global.color_correlation_params.as_ref().unwrap(),
                lf_global.quant_params.as_ref().unwrap(),
                &lf_global.lf_quant,
                lf_global.block_context_map.as_ref().unwrap(),
                self.lf_image.as_mut().unwrap(),
                &mut self.quant_lf,
                br,
                &self.decoder_state.memory_tracker,
            )?;
        }
        lf_global.modular_global.read_stream(
            ModularStreamId::ModularLF(group),
            &self.header,
            &lf_global.tree,
            br,
            &self.decoder_state.memory_tracker,
        )?;
        if self.header.encoding == Encoding::VarDCT {
            info!("decoding HF metadata with group id {}", group);
            let hf_meta = self.hf_meta.as_mut().unwrap();
            decode_hf_metadata(
                group,
                &self.header,
                &self.decoder_state.file_header.image_metadata,
                &lf_global.tree,
                hf_meta,
                br,
                &self.decoder_state.memory_tracker,
            )?;
        }
        Ok(())
    }

    /// Parallel LF group decode for modular frames.
    /// Each LF group's modular data is decoded in parallel using rayon.
    /// Only valid for Encoding::Modular (VarDCT LF groups have shared mutable state).
    #[cfg(feature = "threads")]
    pub fn decode_lf_groups_modular_parallel(
        &self,
        sections: Vec<(usize, Vec<u8>, usize)>,
    ) -> Result<()> {
        use rayon::prelude::*;

        assert_eq!(self.header.encoding, Encoding::Modular);
        let lf_global = self.lf_global.as_ref().unwrap();
        // Extract shared references to avoid capturing &Frame (which may not be Sync).
        let modular = &lf_global.modular_global;
        let tree = &lf_global.tree;
        let header = &self.header;
        let stop: &dyn enough::Stop = &*self.decoder_state.stop;
        let tracker = &self.decoder_state.memory_tracker;
        sections.into_par_iter().try_for_each(|(group, data, len)| {
            stop.check()?;
            let mut br = BitReader::new_padded(&data, len)?;
            modular.read_stream(
                ModularStreamId::ModularLF(group),
                header,
                tree,
                &mut br,
                tracker,
            )
        })
    }

    /// Parallel LF group decode for VarDCT frames.
    ///
    /// Each LF group decodes into locally-owned `Image` buffers (no shared
    /// mutable state). Results are copied back into the parent images
    /// sequentially after the parallel section.
    #[cfg(feature = "threads")]
    pub fn decode_lf_groups_vardct_parallel(
        &mut self,
        sections: Vec<(usize, Vec<u8>, usize)>,
    ) -> Result<()> {
        use rayon::prelude::*;
        use std::sync::atomic::{AtomicU32, Ordering};

        assert_eq!(self.header.encoding, Encoding::VarDCT);

        let lf_global = self.lf_global.as_ref().unwrap();
        // Shared (read-only) state for all groups.
        let header = &self.header;
        let image_metadata = &self.decoder_state.file_header.image_metadata;
        let tree = &lf_global.tree;
        let color_correlation = lf_global.color_correlation_params.as_ref().unwrap();
        let quant_params = lf_global.quant_params.as_ref().unwrap();
        let lf_quant = &lf_global.lf_quant;
        let bctx = lf_global.block_context_map.as_ref().unwrap();
        let modular = &lf_global.modular_global;
        let stop: &dyn enough::Stop = &*self.decoder_state.stop;
        let memory_tracker = &self.decoder_state.memory_tracker;
        let has_lf_frame = header.has_lf_frame();
        let used_hf_types = AtomicU32::new(0);

        /// Per-group decode output, owned by the parallel task.
        struct LfGroupOutput {
            group: usize,
            /// LF coefficients (3 channels, only if !has_lf_frame).
            lf_local: Option<[Image<f32>; 3]>,
            /// Quantized LF (only if !has_lf_frame).
            quant_lf_local: Option<Image<u8>>,
            /// HF metadata maps.
            ytox_local: Image<i8>,
            ytob_local: Image<i8>,
            transform_local: Image<u8>,
            raw_quant_local: Image<i32>,
            epf_local: Image<u8>,
        }

        let results: Vec<LfGroupOutput> = sections
            .into_par_iter()
            .map(|(group, data, len)| -> Result<LfGroupOutput> {
                stop.check()?;
                let mut br = BitReader::new_padded(&data, len)?;
                let r = header.lf_group_rect(group);

                // Phase 1: Decode VarDCT LF coefficients into local images.
                let (lf_local, quant_lf_local) = if !has_lf_frame {
                    let extra_precision = br.read(2)?;
                    let mul = 1.0 / (1 << extra_precision) as f32;
                    let stream_id = ModularStreamId::VarDCTLF(group).get_id(header);
                    let shrink_rect = |size: (usize, usize), c| {
                        (size.0 >> header.hshift(c), size.1 >> header.vshift(c))
                    };
                    let mut buffers = [
                        super::modular::ModularChannel::new(
                            shrink_rect(r.size, 1),
                            image_metadata.bit_depth,
                        )?,
                        super::modular::ModularChannel::new(
                            shrink_rect(r.size, 0),
                            image_metadata.bit_depth,
                        )?,
                        super::modular::ModularChannel::new(
                            shrink_rect(r.size, 2),
                            image_metadata.bit_depth,
                        )?,
                    ];
                    super::modular::decode::decode_modular_subbitstream(
                        buffers.iter_mut().collect(),
                        stream_id,
                        None,
                        tree,
                        &mut br,
                        memory_tracker,
                    )?;

                    // Allocate local images for this group's rect.
                    let lf_sizes: [(usize, usize); 3] = if header.is444() {
                        [r.size; 3]
                    } else {
                        core::array::from_fn(|c| shrink_rect(r.size, c))
                    };
                    let mut lf_images: [Image<f32>; 3] = [
                        Image::new(lf_sizes[0])?,
                        Image::new(lf_sizes[1])?,
                        Image::new(lf_sizes[2])?,
                    ];
                    let mut quant_lf_img = Image::<u8>::new(r.size)?;

                    // dequant_lf writes into these local images.
                    // Destructure to avoid multiple mutable borrows of the array.
                    let full_rect = |sz: (usize, usize)| Rect {
                        origin: (0, 0),
                        size: sz,
                    };
                    let [ref mut lf0, ref mut lf1, ref mut lf2] = lf_images;
                    let lf_rects = [
                        lf0.get_rect_mut(full_rect(lf_sizes[0])),
                        lf1.get_rect_mut(full_rect(lf_sizes[1])),
                        lf2.get_rect_mut(full_rect(lf_sizes[2])),
                    ];
                    let quant_lf_rect = quant_lf_img.get_rect_mut(full_rect(r.size));
                    super::modular::dequant_lf(
                        r,
                        lf_rects,
                        quant_lf_rect,
                        [&buffers[0].data, &buffers[1].data, &buffers[2].data],
                        color_correlation,
                        quant_params,
                        lf_quant,
                        mul,
                        header,
                        bctx,
                    )?;
                    (Some(lf_images), Some(quant_lf_img))
                } else {
                    (None, None)
                };

                // Phase 2: Modular LF stream (uses RefCell internally, already thread-safe).
                modular.read_stream(
                    ModularStreamId::ModularLF(group),
                    header,
                    tree,
                    &mut br,
                    memory_tracker,
                )?;

                // Phase 3: Decode HF metadata into local images.
                let cr = Rect {
                    origin: (r.origin.0 >> 3, r.origin.1 >> 3),
                    size: (r.size.0.div_ceil(8), r.size.1.div_ceil(8)),
                };
                let mut ytox_local = Image::<i8>::new(cr.size)?;
                let mut ytob_local = Image::<i8>::new(cr.size)?;
                let mut transform_local =
                    Image::<u8>::new_with_value(r.size, HfTransformType::INVALID_TRANSFORM)?;
                let mut raw_quant_local = Image::<i32>::new(r.size)?;
                let mut epf_local = Image::<u8>::new(r.size)?;
                let full_cr = Rect {
                    origin: (0, 0),
                    size: cr.size,
                };
                let full_r = Rect {
                    origin: (0, 0),
                    size: r.size,
                };
                let used = decode_hf_metadata_into_rects(
                    group,
                    header,
                    image_metadata,
                    tree,
                    r,
                    cr,
                    ytox_local.get_rect_mut(full_cr),
                    ytob_local.get_rect_mut(full_cr),
                    transform_local.get_rect_mut(full_r),
                    raw_quant_local.get_rect_mut(full_r),
                    epf_local.get_rect_mut(full_r),
                    &mut br,
                    memory_tracker,
                )?;
                used_hf_types.fetch_or(used, Ordering::Relaxed);

                Ok(LfGroupOutput {
                    group,
                    lf_local,
                    quant_lf_local,
                    ytox_local,
                    ytob_local,
                    transform_local,
                    raw_quant_local,
                    epf_local,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        // Sequential copy-back: write each group's local images into the parent images.
        let lf_image = self.lf_image.as_mut().unwrap();
        let hf_meta = self.hf_meta.as_mut().unwrap();

        /// Copy rows from a local image into a rect of the parent image.
        fn copy_image_to_rect<T: crate::image::ImageDataType + Copy>(
            src: &Image<T>,
            dst: &mut Image<T>,
            dst_rect: Rect,
        ) {
            let src_size = src.size();
            debug_assert_eq!(src_size, dst_rect.size);
            for y in 0..src_size.1 {
                let src_row = src.row(y);
                let dst_row = dst.row_mut(dst_rect.origin.1 + y);
                dst_row[dst_rect.origin.0..dst_rect.origin.0 + src_size.0]
                    .copy_from_slice(&src_row[..src_size.0]);
            }
        }

        for output in results {
            let r = header.lf_group_rect(output.group);
            let cr = Rect {
                origin: (r.origin.0 >> 3, r.origin.1 >> 3),
                size: (r.size.0.div_ceil(8), r.size.1.div_ceil(8)),
            };

            // Copy LF coefficients + quant_lf.
            if let Some(lf_local) = &output.lf_local {
                if header.is444() {
                    for c in 0..3 {
                        copy_image_to_rect(&lf_local[c], &mut lf_image[c], r);
                    }
                } else {
                    for c in 0..3 {
                        let shifted_rect = Rect {
                            origin: (
                                r.origin.0 >> header.hshift(c),
                                r.origin.1 >> header.vshift(c),
                            ),
                            size: (r.size.0 >> header.hshift(c), r.size.1 >> header.vshift(c)),
                        };
                        copy_image_to_rect(&lf_local[c], &mut lf_image[c], shifted_rect);
                    }
                }
            }
            if let Some(ref quant_lf_local) = output.quant_lf_local {
                copy_image_to_rect(quant_lf_local, &mut self.quant_lf, r);
            }

            // Copy HF metadata maps.
            copy_image_to_rect(&output.ytox_local, &mut hf_meta.ytox_map, cr);
            copy_image_to_rect(&output.ytob_local, &mut hf_meta.ytob_map, cr);
            copy_image_to_rect(&output.transform_local, &mut hf_meta.transform_map, r);
            copy_image_to_rect(&output.raw_quant_local, &mut hf_meta.raw_quant_map, r);
            copy_image_to_rect(&output.epf_local, &mut hf_meta.epf_map, r);
        }

        // Merge the atomic used_hf_types back.
        self.hf_meta.as_mut().unwrap().used_hf_types |= used_hf_types.load(Ordering::Relaxed);
        Ok(())
    }

    #[instrument(level = "debug", skip_all)]
    pub fn decode_hf_global(&mut self, br: &mut BitReader) -> Result<()> {
        // Check for cancellation at start of major decode step
        self.decoder_state.check_cancelled()?;
        debug!(section_size = br.total_bits_available());
        if self.header.encoding == Encoding::Modular {
            return Ok(());
        }
        let lf_global = self.lf_global.as_mut().unwrap();
        let dequant_matrices = DequantMatrices::decode(
            &self.header,
            lf_global,
            br,
            &self.decoder_state.memory_tracker,
        )?;
        let block_context_map = lf_global.block_context_map.as_mut().unwrap();
        let num_histo_bits = self.header.num_groups().ceil_log2();
        let num_histograms: u32 = br.read(num_histo_bits)? as u32 + 1;
        info!(
            "Processing HFGlobal section with {} passes and {} histograms",
            self.header.passes.num_passes, num_histograms
        );
        let mut passes: Vec<PassState> = vec![];
        #[allow(unused_variables)]
        for i in 0..self.header.passes.num_passes as usize {
            let used_orders = match br.read(2)? {
                0 => 0x5f,
                1 => 0x13,
                2 => 0,
                _ => br.read(coeff_order::NUM_ORDERS)?,
            } as u32;
            debug!(used_orders);
            let coeff_orders = decode_coeff_orders(used_orders, br)?;
            assert_eq!(coeff_orders.len(), 3 * coeff_order::NUM_ORDERS);
            let num_contexts = num_histograms as usize * block_context_map.num_ac_contexts();
            info!(
                "Decoding histograms for pass {} with {} contexts",
                i, num_contexts
            );
            let mut histograms = Histograms::decode(num_contexts, br, true)?;
            // Pad the context map to avoid index out of bounds in decode_vardct_group (group.rs#L514@752e6a4).
            let padding = ZERO_DENSITY_CONTEXT_LIMIT - ZERO_DENSITY_CONTEXT_COUNT;
            histograms.resize(num_contexts + padding);
            debug!("Found {} histograms", histograms.num_histograms());
            passes.push(PassState {
                coeff_orders,
                histograms,
            });
        }
        // Note that, if we have extra channels that can be rendered progressively,
        // we might end up re-drawing some VarDCT groups. In that case, we need to
        // keep around the coefficients, so allocate coefficients under those conditions
        // too.
        // TODO(veluca): evaluate whether we can make this check more precise.
        self.hf_coefficients = if passes.len() <= 1
            && !(self
                .lf_global
                .as_mut()
                .unwrap()
                .modular_global
                .can_do_partial_render()
                && self.header.num_extra_channels > 0)
        {
            None
        } else {
            let coeffs_per_group = GROUP_DIM * GROUP_DIM;
            let num_groups = self.header.num_groups();
            let tracker = &self.decoder_state.memory_tracker;
            // Compute byte budget in u64 to avoid usize overflow on 32-bit
            // targets (i686, wasm32). Without this, an attacker-supplied
            // header with very large `num_groups` could overflow usize and
            // bypass the memory tracker, then OOM during the actual Vec
            // allocations below.
            let alloc_bytes = (coeffs_per_group as u64)
                .checked_mul(num_groups as u64)
                .and_then(|v| v.checked_mul(3))
                .and_then(|v| v.checked_mul(std::mem::size_of::<i32>() as u64))
                .ok_or(Error::ArithmeticOverflow)?;
            tracker.try_allocate(alloc_bytes)?;
            let mut channels: [Vec<Vec<i32>>; 3] = [Vec::new(), Vec::new(), Vec::new()];
            for ch in &mut channels {
                ch.try_reserve_exact(num_groups)?;
                for _ in 0..num_groups {
                    let mut v: Vec<i32> = Vec::new();
                    v.try_reserve_exact(coeffs_per_group)?;
                    v.resize(coeffs_per_group, 0);
                    ch.push(v);
                }
            }
            Some(channels)
        };
        self.hf_global = Some(HfGlobalState {
            num_histograms,
            passes,
            dequant_matrices,
        });
        Ok(())
    }

    /// Overlap LF group decode with HF global parsing using rayon::join.
    ///
    /// decode_hf_global depends only on lf_global (the LF Global section), NOT on
    /// LF group data. So it can run concurrently with LF group decoding, saving
    /// ~6ms at 16T by hiding HF global parse latency behind the LF group barrier.
    #[cfg(feature = "threads")]
    pub fn decode_lf_and_hf_global_parallel(
        &mut self,
        lf_sections: Vec<(usize, Vec<u8>, usize)>,
        hf_data: Vec<u8>,
        hf_len: usize,
    ) -> Result<()> {
        use rayon::prelude::*;
        use std::sync::atomic::{AtomicU32, Ordering};

        assert_eq!(self.header.encoding, Encoding::VarDCT);

        // Destructure self to get disjoint borrows of individual fields.
        let Self {
            header,
            lf_global,
            hf_global,
            hf_coefficients,
            lf_image,
            quant_lf,
            hf_meta,
            decoder_state,
            ..
        } = self;

        let lf_global_ref = lf_global.as_ref().unwrap();
        let image_metadata = &decoder_state.file_header.image_metadata;
        let tree = &lf_global_ref.tree;
        let color_correlation = lf_global_ref.color_correlation_params.as_ref().unwrap();
        let quant_params = lf_global_ref.quant_params.as_ref().unwrap();
        let lf_quant = &lf_global_ref.lf_quant;
        let bctx = lf_global_ref.block_context_map.as_ref().unwrap();
        let modular = &lf_global_ref.modular_global;
        let stop: &dyn enough::Stop = &*decoder_state.stop;
        let memory_tracker_ref = &decoder_state.memory_tracker;
        let has_lf_frame = header.has_lf_frame();
        let used_hf_types = AtomicU32::new(0);

        struct LfGroupOutput {
            group: usize,
            lf_local: Option<[Image<f32>; 3]>,
            quant_lf_local: Option<Image<u8>>,
            ytox_local: Image<i8>,
            ytob_local: Image<i8>,
            transform_local: Image<u8>,
            raw_quant_local: Image<i32>,
            epf_local: Image<u8>,
        }

        struct HfGlobalOutput {
            hf_state: HfGlobalState,
            coefficients: Option<[Vec<Vec<i32>>; 3]>,
        }

        let phase_timing = std::env::var("JXL_PHASE_TIMING").is_ok();
        let join_start = crate::util::Instant::now();

        // Run LF group decode and HF global parse in parallel.
        let (lf_result, hf_result) = rayon::join(
            || -> Result<(Vec<LfGroupOutput>, std::time::Duration)> {
                let par_start = crate::util::Instant::now();
                let results: Vec<LfGroupOutput> = lf_sections
                    .into_par_iter()
                    .map(|(group, data, len)| -> Result<LfGroupOutput> {
                        stop.check()?;
                        let mut br = BitReader::new_padded(&data, len)?;
                        let r = header.lf_group_rect(group);

                        let (lf_local, quant_lf_local) = if !has_lf_frame {
                            let extra_precision = br.read(2)?;
                            let mul = 1.0 / (1 << extra_precision) as f32;
                            let stream_id = ModularStreamId::VarDCTLF(group).get_id(header);
                            let shrink_rect = |size: (usize, usize), c| {
                                (size.0 >> header.hshift(c), size.1 >> header.vshift(c))
                            };
                            let mut buffers = [
                                super::modular::ModularChannel::new(
                                    shrink_rect(r.size, 1),
                                    image_metadata.bit_depth,
                                )?,
                                super::modular::ModularChannel::new(
                                    shrink_rect(r.size, 0),
                                    image_metadata.bit_depth,
                                )?,
                                super::modular::ModularChannel::new(
                                    shrink_rect(r.size, 2),
                                    image_metadata.bit_depth,
                                )?,
                            ];
                            super::modular::decode::decode_modular_subbitstream(
                                buffers.iter_mut().collect(),
                                stream_id,
                                None,
                                tree,
                                &mut br,
                                memory_tracker_ref,
                            )?;

                            let lf_sizes: [(usize, usize); 3] = if header.is444() {
                                [r.size; 3]
                            } else {
                                core::array::from_fn(|c| shrink_rect(r.size, c))
                            };
                            let mut lf_images: [Image<f32>; 3] = [
                                Image::new(lf_sizes[0])?,
                                Image::new(lf_sizes[1])?,
                                Image::new(lf_sizes[2])?,
                            ];
                            let mut quant_lf_img = Image::<u8>::new(r.size)?;

                            let full_rect = |sz: (usize, usize)| Rect {
                                origin: (0, 0),
                                size: sz,
                            };
                            let [ref mut lf0, ref mut lf1, ref mut lf2] = lf_images;
                            let lf_rects = [
                                lf0.get_rect_mut(full_rect(lf_sizes[0])),
                                lf1.get_rect_mut(full_rect(lf_sizes[1])),
                                lf2.get_rect_mut(full_rect(lf_sizes[2])),
                            ];
                            let quant_lf_rect = quant_lf_img.get_rect_mut(full_rect(r.size));
                            super::modular::dequant_lf(
                                r,
                                lf_rects,
                                quant_lf_rect,
                                [&buffers[0].data, &buffers[1].data, &buffers[2].data],
                                color_correlation,
                                quant_params,
                                lf_quant,
                                mul,
                                header,
                                bctx,
                            )?;
                            (Some(lf_images), Some(quant_lf_img))
                        } else {
                            (None, None)
                        };

                        modular.read_stream(
                            ModularStreamId::ModularLF(group),
                            header,
                            tree,
                            &mut br,
                            memory_tracker_ref,
                        )?;

                        let cr = Rect {
                            origin: (r.origin.0 >> 3, r.origin.1 >> 3),
                            size: (r.size.0.div_ceil(8), r.size.1.div_ceil(8)),
                        };
                        let mut ytox_local = Image::<i8>::new(cr.size)?;
                        let mut ytob_local = Image::<i8>::new(cr.size)?;
                        let mut transform_local = Image::<u8>::new_with_value(
                            r.size,
                            HfTransformType::INVALID_TRANSFORM,
                        )?;
                        let mut raw_quant_local = Image::<i32>::new(r.size)?;
                        let mut epf_local = Image::<u8>::new(r.size)?;
                        let full_cr = Rect {
                            origin: (0, 0),
                            size: cr.size,
                        };
                        let full_r = Rect {
                            origin: (0, 0),
                            size: r.size,
                        };
                        let used = decode_hf_metadata_into_rects(
                            group,
                            header,
                            image_metadata,
                            tree,
                            r,
                            cr,
                            ytox_local.get_rect_mut(full_cr),
                            ytob_local.get_rect_mut(full_cr),
                            transform_local.get_rect_mut(full_r),
                            raw_quant_local.get_rect_mut(full_r),
                            epf_local.get_rect_mut(full_r),
                            &mut br,
                            memory_tracker_ref,
                        )?;
                        used_hf_types.fetch_or(used, Ordering::Relaxed);

                        Ok(LfGroupOutput {
                            group,
                            lf_local,
                            quant_lf_local,
                            ytox_local,
                            ytob_local,
                            transform_local,
                            raw_quant_local,
                            epf_local,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok((results, par_start.elapsed()))
            },
            || -> Result<(HfGlobalOutput, std::time::Duration)> {
                let hf_start = crate::util::Instant::now();
                decoder_state.check_cancelled()?;
                let mut br = BitReader::new_padded(&hf_data, hf_len)?;
                let dequant_matrices =
                    DequantMatrices::decode(header, lf_global_ref, &mut br, memory_tracker_ref)?;
                let num_histo_bits = header.num_groups().ceil_log2();
                let num_histograms: u32 = br.read(num_histo_bits)? as u32 + 1;
                let num_ac = bctx.num_ac_contexts();
                let mut passes: Vec<PassState> = vec![];
                for _ in 0..header.passes.num_passes as usize {
                    let used_orders = match br.read(2)? {
                        0 => 0x5f,
                        1 => 0x13,
                        2 => 0,
                        _ => br.read(coeff_order::NUM_ORDERS)?,
                    } as u32;
                    let coeff_orders = decode_coeff_orders(used_orders, &mut br)?;
                    assert_eq!(coeff_orders.len(), 3 * coeff_order::NUM_ORDERS);
                    let num_contexts = num_histograms as usize * num_ac;
                    let mut histograms = Histograms::decode(num_contexts, &mut br, true)?;
                    let padding = ZERO_DENSITY_CONTEXT_LIMIT - ZERO_DENSITY_CONTEXT_COUNT;
                    histograms.resize(num_contexts + padding);
                    passes.push(PassState {
                        coeff_orders,
                        histograms,
                    });
                }
                let coefficients = if passes.len() <= 1
                    && !(modular.can_do_partial_render() && header.num_extra_channels > 0)
                {
                    None
                } else {
                    let coeffs_per_group = GROUP_DIM * GROUP_DIM;
                    let num_groups = header.num_groups();
                    let tracker = &decoder_state.memory_tracker;
                    // u64-checked path mirrors the sequential decoder above:
                    // prevents usize overflow on 32-bit targets (i686, wasm32)
                    // for attacker-controlled `num_groups`.
                    let alloc_bytes = (coeffs_per_group as u64)
                        .checked_mul(num_groups as u64)
                        .and_then(|v| v.checked_mul(3))
                        .and_then(|v| v.checked_mul(std::mem::size_of::<i32>() as u64))
                        .ok_or(Error::ArithmeticOverflow)?;
                    tracker.try_allocate(alloc_bytes)?;
                    let mut channels: [Vec<Vec<i32>>; 3] = [Vec::new(), Vec::new(), Vec::new()];
                    for ch in &mut channels {
                        ch.try_reserve_exact(num_groups)?;
                        for _ in 0..num_groups {
                            let mut v: Vec<i32> = Vec::new();
                            v.try_reserve_exact(coeffs_per_group)?;
                            v.resize(coeffs_per_group, 0);
                            ch.push(v);
                        }
                    }
                    Some(channels)
                };
                Ok((
                    HfGlobalOutput {
                        hf_state: HfGlobalState {
                            num_histograms,
                            passes,
                            dequant_matrices,
                        },
                        coefficients,
                    },
                    hf_start.elapsed(),
                ))
            },
        );

        let (lf_outputs, lf_par_dur) = lf_result?;
        let (hf_output, hf_dur) = hf_result?;
        let join_dur = join_start.elapsed();

        // Sequential copy-back for LF group results.
        let copyback_start = crate::util::Instant::now();
        let lf_image = lf_image.as_mut().unwrap();
        let hf_meta = hf_meta.as_mut().unwrap();

        fn copy_image_to_rect<T: crate::image::ImageDataType + Copy>(
            src: &Image<T>,
            dst: &mut Image<T>,
            dst_rect: Rect,
        ) {
            let src_size = src.size();
            debug_assert_eq!(src_size, dst_rect.size);
            for y in 0..src_size.1 {
                let src_row = src.row(y);
                let dst_row = dst.row_mut(dst_rect.origin.1 + y);
                dst_row[dst_rect.origin.0..dst_rect.origin.0 + src_size.0]
                    .copy_from_slice(&src_row[..src_size.0]);
            }
        }

        for output in lf_outputs {
            let r = header.lf_group_rect(output.group);
            let cr = Rect {
                origin: (r.origin.0 >> 3, r.origin.1 >> 3),
                size: (r.size.0.div_ceil(8), r.size.1.div_ceil(8)),
            };
            if let Some(lf_local) = &output.lf_local {
                if header.is444() {
                    for c in 0..3 {
                        copy_image_to_rect(&lf_local[c], &mut lf_image[c], r);
                    }
                } else {
                    for c in 0..3 {
                        let shifted_rect = Rect {
                            origin: (
                                r.origin.0 >> header.hshift(c),
                                r.origin.1 >> header.vshift(c),
                            ),
                            size: (r.size.0 >> header.hshift(c), r.size.1 >> header.vshift(c)),
                        };
                        copy_image_to_rect(&lf_local[c], &mut lf_image[c], shifted_rect);
                    }
                }
            }
            if let Some(ref quant_lf_local) = output.quant_lf_local {
                copy_image_to_rect(quant_lf_local, quant_lf, r);
            }
            copy_image_to_rect(&output.ytox_local, &mut hf_meta.ytox_map, cr);
            copy_image_to_rect(&output.ytob_local, &mut hf_meta.ytob_map, cr);
            copy_image_to_rect(&output.transform_local, &mut hf_meta.transform_map, r);
            copy_image_to_rect(&output.raw_quant_local, &mut hf_meta.raw_quant_map, r);
            copy_image_to_rect(&output.epf_local, &mut hf_meta.epf_map, r);
        }
        hf_meta.used_hf_types |= used_hf_types.load(Ordering::Relaxed);
        let copyback_dur = copyback_start.elapsed();

        // Apply HF global results.
        *hf_global = Some(hf_output.hf_state);
        *hf_coefficients = hf_output.coefficients;

        if phase_timing {
            eprintln!(
                "[JXL_LF_HF_OVERLAP] lf_par: {:.2}ms | hf_parse: {:.2}ms | \
                 join_wall: {:.2}ms | copyback: {:.2}ms | \
                 saved: {:.2}ms",
                lf_par_dur.as_secs_f64() * 1000.0,
                hf_dur.as_secs_f64() * 1000.0,
                join_dur.as_secs_f64() * 1000.0,
                copyback_dur.as_secs_f64() * 1000.0,
                (lf_par_dur + hf_dur).saturating_sub(join_dur).as_secs_f64() * 1000.0,
            );
        }

        Ok(())
    }

    pub fn render_noise_for_group(
        &mut self,
        group: usize,
        complete: bool,
        buffer_splitter: &mut BufferSplitter,
    ) -> Result<()> {
        // TODO(sboukortt): consider making this a dedicated stage
        // TODO(veluca): SIMD.
        let num_channels = self.header.num_extra_channels as usize + 3;

        let group_dim = self.header.group_dim() as u32;
        let xsize_groups = self.header.size_groups().0;
        let gx = (group % xsize_groups) as u32;
        let gy = (group / xsize_groups) as u32;
        let upsampling = self.header.upsampling;
        let upsampled_size = self.header.size_upsampled();

        // Total buffer covers the upsampled region for this group
        let buf_x1 = ((gx + 1) * upsampling * group_dim) as usize;
        let buf_y1 = ((gy + 1) * upsampling * group_dim) as usize;
        let buf_xsize = buf_x1.min(upsampled_size.0) - (gx * upsampling * group_dim) as usize;
        let buf_ysize = buf_y1.min(upsampled_size.1) - (gy * upsampling * group_dim) as usize;

        let bits_to_float = |bits: u32| f32::from_bits((bits >> 9) | 0x3F800000);

        // Get all 3 noise channel buffers upfront
        let mut bufs = [
            pipeline!(self, p, p.get_buffer(num_channels)?),
            pipeline!(self, p, p.get_buffer(num_channels + 1)?),
            pipeline!(self, p, p.get_buffer(num_channels + 2)?),
        ];

        const FLOATS_PER_BATCH: usize =
            Xorshift128Plus::N * std::mem::size_of::<u64>() / std::mem::size_of::<f32>();
        let mut batch = [0u64; Xorshift128Plus::N];

        // libjxl iterates through upsampling subdivisions with separate RNG seeds.
        // For each subregion, a single RNG is shared across all 3 channels.
        for iy in 0..upsampling {
            for ix in 0..upsampling {
                // Seed coordinates for this subregion (matches libjxl)
                let x0 = (gx * upsampling + ix) * group_dim;
                let y0 = (gy * upsampling + iy) * group_dim;

                // Create RNG with this subregion's seed - shared across all 3 channels
                let mut rng = Xorshift128Plus::new_with_seeds(
                    self.decoder_state.visible_frame_index as u32,
                    self.decoder_state.nonvisible_frame_index as u32,
                    x0,
                    y0,
                );

                // Subregion boundaries within the buffer
                let sub_x0 = (ix * group_dim) as usize;
                let sub_y0 = (iy * group_dim) as usize;
                let sub_x1 = ((ix + 1) * group_dim) as usize;
                let sub_y1 = ((iy + 1) * group_dim) as usize;

                // Clamp to actual buffer size
                let sub_xsize = sub_x1.min(buf_xsize).saturating_sub(sub_x0);
                let sub_ysize = sub_y1.min(buf_ysize).saturating_sub(sub_y0);

                // Skip if this subregion is entirely outside the buffer
                if sub_xsize == 0 || sub_ysize == 0 {
                    continue;
                }

                // Fill all 3 channels with this subregion's noise, sharing the RNG
                for buf in &mut bufs {
                    for y in 0..sub_ysize {
                        let row = buf.row_mut(sub_y0 + y);
                        for batch_index in 0..sub_xsize.div_ceil(FLOATS_PER_BATCH) {
                            rng.fill(&mut batch);
                            let batch_size =
                                (sub_xsize - batch_index * FLOATS_PER_BATCH).min(FLOATS_PER_BATCH);
                            for i in 0..batch_size {
                                let x = sub_x0 + FLOATS_PER_BATCH * batch_index + i;
                                let k = i / 2;
                                let high_bytes = i % 2 != 0;
                                let bits = if high_bytes {
                                    ((batch[k] & 0xFFFFFFFF00000000) >> 32) as u32
                                } else {
                                    (batch[k] & 0xFFFFFFFF) as u32
                                };
                                row[x] = bits_to_float(bits);
                            }
                        }
                    }
                }
            }
        }

        // Set all buffers after filling
        let [buf0, buf1, buf2] = bufs;
        pipeline!(
            self,
            p,
            p.set_buffer_for_group(num_channels, group, complete, buf0, buffer_splitter)?
        );
        pipeline!(
            self,
            p,
            p.set_buffer_for_group(num_channels + 1, group, complete, buf1, buffer_splitter)?
        );
        pipeline!(
            self,
            p,
            p.set_buffer_for_group(num_channels + 2, group, complete, buf2, buffer_splitter)?
        );
        Ok(())
    }

    // Returns `true` if VarDCT and noise data were effectively rendered.
    #[instrument(level = "debug", skip(self, passes, buffer_splitter))]
    pub fn decode_hf_group(
        &mut self,
        group: usize,
        passes: &mut [(usize, BitReader)],
        buffer_splitter: &mut BufferSplitter,
        force_render: bool,
    ) -> Result<bool> {
        if passes.is_empty() {
            assert!(force_render);
        }

        let last_pass_in_file = self.header.passes.num_passes as usize - 1;
        let was_complete = self.last_rendered_pass[group].is_some_and(|p| p >= last_pass_in_file);

        if let Some((p, _)) = passes.last() {
            self.last_rendered_pass[group] = Some(*p);
        };
        let pass_to_render = self.last_rendered_pass[group];
        let complete = pass_to_render.is_some_and(|p| p >= last_pass_in_file);

        if complete && !was_complete {
            self.incomplete_groups = self.incomplete_groups.checked_sub(1).unwrap();
        }

        // Render if we are decoding the last pass, or if we are requesting an eager render and
        // we can handle this case of eager renders.
        let do_render = if complete {
            true
        } else if force_render {
            self.allow_rendering_before_last_pass()
        } else {
            false
        };

        if !do_render && passes.is_empty() {
            return Ok(false);
        }

        if self.header.has_noise() && do_render {
            self.render_noise_for_group(group, complete, buffer_splitter)?;
        }

        let lf_global = self.lf_global.as_ref().unwrap();
        if self.header.encoding == Encoding::VarDCT {
            info!("Decoding VarDCT group {group}");
            let hf_global = self.hf_global.as_ref().unwrap();
            let hf_meta = self.hf_meta.as_ref().unwrap();
            let hf_coeffs = self.hf_coefficients.as_mut().map(|[a, b, c]| {
                [
                    a[group].as_mut_slice(),
                    b[group].as_mut_slice(),
                    c[group].as_mut_slice(),
                ]
            });
            let mut pixels = if do_render {
                Some([
                    pipeline!(self, p, p.get_buffer(0))?,
                    pipeline!(self, p, p.get_buffer(1))?,
                    pipeline!(self, p, p.get_buffer(2))?,
                ])
            } else {
                None
            };
            let buffers = match &mut self.vardct_buffers {
                Some(b) => b,
                None => self.vardct_buffers.insert(VarDctBuffers::new()?),
            };
            if pass_to_render.is_none() && do_render {
                upsample_lf_group(
                    group,
                    pixels.as_mut().unwrap(),
                    self.lf_image.as_ref().unwrap(),
                    &self.header,
                    &self.decoder_state.file_header.transform_data,
                )?;
            } else {
                decode_vardct_group(
                    group,
                    passes,
                    &self.header,
                    lf_global,
                    hf_global,
                    hf_meta,
                    &self.lf_image,
                    &self.quant_lf,
                    &self
                        .decoder_state
                        .file_header
                        .transform_data
                        .opsin_inverse_matrix
                        .quant_biases,
                    hf_coeffs,
                    &mut pixels,
                    buffers,
                    &self.decoder_state.memory_tracker,
                    #[cfg(feature = "jpeg")]
                    self.jpeg_coeffs.as_mut(),
                )?;
            }
            if let Some(pixels) = pixels {
                for (c, img) in pixels.into_iter().enumerate() {
                    pipeline!(
                        self,
                        p,
                        p.set_buffer_for_group(c, group, complete, img, buffer_splitter)?
                    );
                }
            }
        }

        {
            let lf_global = self.lf_global.as_ref().unwrap();
            for (pass, br) in passes.iter_mut() {
                lf_global.modular_global.read_stream(
                    ModularStreamId::ModularHF { group, pass: *pass },
                    &self.header,
                    &lf_global.tree,
                    br,
                    &self.decoder_state.memory_tracker,
                )?;
            }
        }
        Ok(do_render)
    }
}

#[cfg(test)]
mod overflow_tests {
    /// Regression for: `(coeffs_per_group * num_groups * 3 * size_of::<i32>())
    /// as u64` used to compute in `usize` first, which overflows on 32-bit
    /// targets (i686, wasm32) for attacker-controlled `num_groups`. This
    /// pinned the sequence we now use for overflow-safe sizing.
    #[test]
    fn coeff_alloc_size_overflows_in_u64_when_bogus() {
        // Mimic the saturation logic inline. `coeffs_per_group` is GROUP_DIM*GROUP_DIM
        // (256*256 = 65536 in production). Pick `num_groups` such that
        // `coeffs_per_group * num_groups` overflows u32 but not u64, so that
        // a buggy 32-bit lower would have wrapped silently.
        let coeffs_per_group: u64 = 256 * 256;
        let num_groups: u64 = (u32::MAX as u64) / coeffs_per_group + 1;
        let total = coeffs_per_group
            .checked_mul(num_groups)
            .and_then(|v| v.checked_mul(3))
            .and_then(|v| v.checked_mul(core::mem::size_of::<i32>() as u64));
        // Stays within u64 — we want this to be Some(...) so the tracker can
        // reject it with LimitExceeded.
        assert!(total.is_some());
        // ...but above any sane usize on 32-bit (>4 GiB).
        assert!(total.unwrap() > u32::MAX as u64);

        // Now demonstrate that pathological inputs *also* saturate cleanly:
        let huge: u64 = u64::MAX / 4;
        let tot2 = huge
            .checked_mul(huge)
            .and_then(|v| v.checked_mul(3))
            .and_then(|v| v.checked_mul(core::mem::size_of::<i32>() as u64));
        assert!(
            tot2.is_none(),
            "extreme inputs must saturate to None (Error::ArithmeticOverflow path)"
        );
    }
}
