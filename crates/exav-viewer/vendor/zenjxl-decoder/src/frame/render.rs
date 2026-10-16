// Copyright (c) the JPEG XL Project Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use crate::api::JxlCms;
use crate::api::JxlColorEncoding;
use crate::api::JxlColorProfile;
use crate::api::JxlColorType;
use crate::api::JxlDataFormat;
use crate::api::JxlOutputBuffer;
use crate::bit_reader::BitReader;
use crate::error::{Error, Result};
use crate::features::epf::SigmaSource;
use crate::frame::RenderUnit;
#[cfg(feature = "threads")]
use crate::frame::decode::upsample_lf_group;
use crate::headers::frame_header::Encoding;
use crate::headers::frame_header::FrameType;
use crate::headers::{Orientation, color_encoding::ColorSpace, extra_channels::ExtraChannel};
use crate::image::Image;
use crate::image::Rect;
#[cfg(test)]
use crate::render::SimpleRenderPipeline;
use crate::render::buffer_splitter::BufferSplitter;
use crate::render::{LowMemoryRenderPipeline, RenderPipeline, RenderPipelineBuilder, stages::*};
use crate::{
    api::JxlPixelFormat,
    frame::{DecoderState, Frame, LfGlobalState},
    headers::frame_header::FrameHeader,
};

#[cfg(test)]
macro_rules! pipeline {
    ($frame: expr, $pipeline: ident, $op: expr) => {
        if $frame.use_simple_pipeline {
            let $pipeline = $frame
                .render_pipeline
                .as_mut()
                .unwrap()
                .downcast_mut::<SimpleRenderPipeline>()
                .unwrap();
            $op
        } else {
            use crate::render::LowMemoryRenderPipeline;
            let $pipeline = $frame
                .render_pipeline
                .as_mut()
                .unwrap()
                .downcast_mut::<LowMemoryRenderPipeline>()
                .unwrap();
            $op
        }
    };
}

#[cfg(not(test))]
macro_rules! pipeline {
    ($frame: expr, $pipeline: ident, $op: expr) => {{
        let $pipeline = $frame.render_pipeline.as_mut().unwrap();
        $op
    }};
}

pub(crate) use pipeline;

impl Frame {
    /// Add conversion stages for non-float output formats.
    /// This is needed before saving to U8/U16/F16 formats to convert from the pipeline's f32.
    fn add_conversion_stages<P: RenderPipeline>(
        mut pipeline: RenderPipelineBuilder<P>,
        channels: &[usize],
        data_format: JxlDataFormat,
        clamp_range_for_f16: Option<(f32, f32)>,
    ) -> RenderPipelineBuilder<P> {
        use crate::render::stages::{
            ConvertF32ToF16Stage, ConvertF32ToU8Stage, ConvertF32ToU16Stage,
        };

        match data_format {
            JxlDataFormat::U8 { bit_depth } => {
                for &channel in channels {
                    pipeline =
                        pipeline.add_inout_stage(ConvertF32ToU8Stage::new(channel, bit_depth));
                }
            }
            JxlDataFormat::U16 { bit_depth, .. } => {
                for &channel in channels {
                    pipeline =
                        pipeline.add_inout_stage(ConvertF32ToU16Stage::new(channel, bit_depth));
                }
            }
            JxlDataFormat::F16 { .. } => {
                for &channel in channels {
                    pipeline = pipeline.add_inout_stage(
                        ConvertF32ToF16Stage::new_with_clamp_range(channel, clamp_range_for_f16),
                    );
                }
            }
            // F32 doesn't need conversion - the pipeline already uses f32
            JxlDataFormat::F32 { .. } => {}
        }
        pipeline
    }

    /// Check if CMS will consume a black channel that the user requested in the output.
    fn check_cms_consumed_black_channel(
        black_channel: Option<usize>,
        in_channels: usize,
        out_channels: usize,
        pixel_format: &JxlPixelFormat,
    ) -> Result<()> {
        if let Some(k_pipeline_idx) = black_channel
            && out_channels < in_channels
        {
            // K channel is consumed (4->3 conversion)
            let k_ec_idx = k_pipeline_idx - 3;
            if pixel_format
                .extra_channel_format
                .get(k_ec_idx)
                .is_some_and(|f| f.is_some())
            {
                return Err(Error::CmsConsumedChannelRequested {
                    channel_index: k_ec_idx,
                    channel_type: "Black".to_string(),
                });
            }
        }
        Ok(())
    }

    pub fn decode_and_render_hf_groups(
        &mut self,
        api_buffers: &mut Option<&mut [JxlOutputBuffer<'_>]>,
        pixel_format: &JxlPixelFormat,
        groups: Vec<(usize, Vec<(usize, BitReader)>)>,
        do_flush: bool,
        output_profile: &JxlColorProfile,
    ) -> Result<()> {
        if self.render_pipeline.is_none() {
            assert_eq!(groups.iter().map(|x| x.1.len()).sum::<usize>(), 0);
            // We don't yet have any output ready (as the pipeline would be initialized otherwise),
            // so exit without doing anything.
            return Ok(());
        }

        let mut buffers: Vec<Option<JxlOutputBuffer>> = Vec::new();

        macro_rules! buffers_from_api {
            ($get_next: expr) => {
                if pixel_format.color_data_format.is_some() {
                    buffers.push($get_next);
                }

                for fmt in &pixel_format.extra_channel_format {
                    if fmt.is_some() {
                        buffers.push($get_next);
                    }
                }
            };
        }

        if let Some(api_buffers) = api_buffers {
            let mut api_buffers_iter = api_buffers.iter_mut();
            buffers_from_api!(Some(JxlOutputBuffer::reborrow(
                api_buffers_iter.next().unwrap(),
            )));
        } else {
            buffers_from_api!(None);
        }

        // Temporarily remove the reference/lf frames to be saved; we will move them back once
        // rendering is done.
        let mut reference_frame_data = std::mem::take(&mut self.reference_frame_data);
        let mut lf_frame_data = std::mem::take(&mut self.lf_frame_data);

        if let Some(ref_images) = &mut reference_frame_data {
            buffers.extend(ref_images.iter_mut().map(|img| {
                let rect = Rect {
                    size: img.size(),
                    origin: (0, 0),
                };
                Some(JxlOutputBuffer::from_image_rect_mut(
                    img.get_rect_mut(rect).into_raw(),
                ))
            }));
        };

        if let Some(lf_images) = &mut lf_frame_data {
            buffers.extend(lf_images.iter_mut().map(|img| {
                let rect = Rect {
                    size: img.size(),
                    origin: (0, 0),
                };
                Some(JxlOutputBuffer::from_image_rect_mut(
                    img.get_rect_mut(rect).into_raw(),
                ))
            }));
        };

        let frame_timing = std::env::var("JXL_PHASE_TIMING").is_ok();
        let frame_start = crate::util::Instant::now();

        pipeline!(self, p, p.check_buffer_sizes(&mut buffers[..])?);

        let mut buffer_splitter = BufferSplitter::new(&mut buffers[..]);

        pipeline!(self, p, p.render_outside_frame(&mut buffer_splitter)?);

        let frame_setup_dur = frame_start.elapsed();

        let modular_global = &mut self.lf_global.as_mut().unwrap().modular_global;

        modular_global.set_pipeline_used_channels(pipeline!(self, p, p.used_channel_mask()));

        // Determine parallel vs sequential early — affects flush strategy.
        #[cfg(all(feature = "threads", not(test)))]
        let use_parallel = self.decoder_state.parallel && groups.len() > 1;
        #[cfg(all(feature = "threads", test))]
        let use_parallel =
            self.decoder_state.parallel && groups.len() > 1 && !self.use_simple_pipeline;
        #[cfg(not(feature = "threads"))]
        let use_parallel = false;

        // STEP 1: if we are requesting a flush, and did not flush before, mark modular channels
        // as having been decoded as 0.
        // Skip for parallel path — no intermediate flush rendering, so zero-fill is unnecessary.
        // The final render (incomplete_groups==0) gets correct data from actual decoding.
        if !self.was_flushed_once && do_flush && !use_parallel {
            self.was_flushed_once = true;
            self.groups_to_flush.extend(0..self.header.num_groups());
            modular_global.zero_fill_empty_channels(
                self.header.passes.num_passes as usize,
                self.header.num_groups(),
            )?;
        }

        // Preserve modular buffers when a final re-render may be needed.
        // Sequential always re-renders; parallel re-renders only for incremental
        // (cross-batch boundaries have partial readiness). One-shot parallel
        // gets full readiness from the first pass, but we can't predict
        // one-shot vs incremental here, so preserve speculatively.
        if self.header.num_groups() > 1 && pipeline!(self, p, p.needs_border_rendering()) {
            modular_global.set_preserve_buffers(true);
        }

        // STEP 2: ensure that groups that will be re-rendered are marked as such.
        // VarDCT data to be rendered.
        for (g, _) in groups.iter() {
            self.groups_to_flush.insert(*g);
            pipeline!(self, p, p.mark_group_to_rerender(*g));
        }
        // Modular data to be re-rendered.
        // In parallel mode, modular marking is deferred to per-group processing
        // inside decode_groups_parallel: mark_group_to_be_read sets buffer
        // statuses to FINAL_RENDER, which would break per-group dependency
        // checks if done for all groups up-front.
        if !use_parallel {
            let modular_global = &mut self.lf_global.as_mut().unwrap().modular_global;
            for (group, passes) in groups.iter() {
                for (pass, _) in passes.iter() {
                    modular_global.mark_group_to_be_read(2 + *pass, *group);
                }
            }
            let mut pass_to_pipeline = |_, group, _, _| {
                self.groups_to_flush.insert(group);
                pipeline!(self, p, p.mark_group_to_rerender(group));
                Ok(())
            };
            modular_global.process_output(&self.header, true, &mut pass_to_pipeline)?;
        }

        // STEP 3: decode the groups, eagerly rendering VarDCT channels and noise.

        let hf_start = crate::util::Instant::now();
        if use_parallel {
            #[cfg(feature = "threads")]
            {
                self.decode_groups_parallel(groups, &mut buffer_splitter, do_flush)?;
                // Track incremental parallel decode: if groups remain incomplete
                // after this batch, a final re-render will be needed to correct
                // cross-batch border readiness.
                if self.incomplete_groups > 0 {
                    self.was_flushed_once = true;
                }
            }
        } else {
            for (group, mut passes) in groups {
                // Check for cancellation between groups
                self.decoder_state.check_cancelled()?;
                if self.decode_hf_group(group, &mut passes, &mut buffer_splitter, do_flush)? {
                    self.changed_since_last_flush
                        .insert((group, RenderUnit::VarDCT));
                }
            }
        }
        let hf_dur = hf_start.elapsed();

        // STEP 4: process all modular transforms that can now be processed,
        // flushing buffers that will not be used again, if either we are forcing a render now
        // or we are done with the file.
        let flush_start = crate::util::Instant::now();
        // Skip intermediate flush for parallel path — the parallel decode already renders
        // each batch correctly. Intermediate STEP 4+5 re-rendering causes partial-readiness
        // bugs with border-dependent stages (EPF, Gaborish). Only process when all groups
        // are complete (one-shot final render) or in sequential mode.
        if self.incomplete_groups == 0 || (do_flush && !use_parallel) {
            // Final re-render with full readiness masks. Needed when groups were
            // rendered with partial readiness:
            // - Sequential: always (groups processed one at a time)
            // - Parallel incremental: yes (cross-batch boundaries have partial readiness)
            // - Parallel one-shot: NO (all groups in one batch, full readiness from
            //   prepare_groups_parallel marking all groups ready before emission)
            // was_flushed_once distinguishes: set in STEP 1 (sequential) or after
            // decode_groups_parallel with incomplete groups (parallel incremental).
            let is_final_rerender = self.incomplete_groups == 0
                && self.was_flushed_once
                && self.header.num_groups() > 1
                && pipeline!(self, p, p.needs_border_rendering())
                && (self.header.encoding != Encoding::VarDCT || self.hf_coefficients.is_some());
            if is_final_rerender {
                self.groups_to_flush.extend(0..self.header.num_groups());
                self.changed_since_last_flush.clear();
                pipeline!(self, p, p.prepare_final_rerender());
            }

            let modular_global = &mut self.lf_global.as_mut().unwrap().modular_global;
            let mut pass_to_pipeline = |chan, group, complete, image: Option<Image<i32>>| {
                self.changed_since_last_flush
                    .insert((group, RenderUnit::Modular(chan)));
                pipeline!(
                    self,
                    p,
                    p.set_buffer_for_group(
                        chan,
                        group,
                        complete,
                        image.unwrap(),
                        &mut buffer_splitter
                    )?
                );
                Ok(())
            };
            modular_global.process_output(&self.header, false, &mut pass_to_pipeline)?;

            // STEP 5: re-render VarDCT/noise data in rendered groups for which it was
            // not rendered, or re-send to pipeline modular channels that were not
            // updated in those groups.
            let step5_groups: std::collections::BTreeSet<usize> =
                std::mem::take(&mut self.groups_to_flush);
            for g in step5_groups {
                if self
                    .changed_since_last_flush
                    .take(&(g, RenderUnit::VarDCT))
                    .is_none()
                {
                    self.decode_hf_group(g, &mut [], &mut buffer_splitter, true)?;
                }
                let modular_global = &mut self.lf_global.as_mut().unwrap().modular_global;
                let mut pass_to_pipeline = |chan, group, complete, image| {
                    pipeline!(
                        self,
                        p,
                        p.set_buffer_for_group(chan, group, complete, image, &mut buffer_splitter)?
                    );
                    Ok(())
                };
                for c in modular_global.channel_range() {
                    if self
                        .changed_since_last_flush
                        .take(&(g, RenderUnit::Modular(c)))
                        .is_none()
                    {
                        modular_global.flush_output(g, c, &mut pass_to_pipeline)?;
                    }
                }
            }

            if is_final_rerender {
                pipeline!(
                    self,
                    p,
                    p.render_all_groups_full_readiness(&mut buffer_splitter)?
                );
                pipeline!(self, p, p.finish_final_rerender());
            }
        }
        let flush_dur = flush_start.elapsed();

        let regions = buffer_splitter.into_changed_regions();

        self.reference_frame_data = reference_frame_data;
        self.lf_frame_data = lf_frame_data;

        if frame_timing {
            let total = frame_start.elapsed();
            let teardown = total.saturating_sub(frame_setup_dur + hf_dur + flush_dur);
            eprintln!(
                "[JXL_FRAME_TIMING] setup: {:.2}ms | \
                 hf_groups: {:.2}ms | flush: {:.2}ms | teardown: {:.2}ms | \
                 total: {:.2}ms",
                frame_setup_dur.as_secs_f64() * 1000.0,
                hf_dur.as_secs_f64() * 1000.0,
                flush_dur.as_secs_f64() * 1000.0,
                teardown.as_secs_f64() * 1000.0,
                total.as_secs_f64() * 1000.0,
            );
        }

        if self.header.frame_type == FrameType::LFFrame && self.header.lf_level == 1 {
            if do_flush && let Some(buffers) = api_buffers {
                self.maybe_preview_lf_frame(
                    pixel_format,
                    buffers,
                    Some(&regions[..]),
                    output_profile,
                )?;
            } else if self.incomplete_groups == 0 {
                // If we are not requesting another flush at the end of the LF frame, we
                // probably have a partial render. Ensure we re-render the LF frame when
                // decoding the actual frame.
                self.decoder_state.lf_frame_was_rendered = false;
            }
        }

        Ok(())
    }

    /// Parallel decode + render path for both VarDCT and Modular frames.
    ///
    /// Processes ALL groups through a four-phase pipeline (no batching),
    /// reducing rayon barriers from ~5×(num_groups/num_threads) to 5 total
    /// and enabling better work-stealing across all groups.
    ///
    /// The four phases:
    /// 1. Sequential: compute render decisions and allocate pixel buffers
    /// 2. Parallel: entropy decode + dequant + IDCT (VarDCT) / read_stream (Modular)
    /// 3. Store, render, recycle:
    ///    - 3a. Sequential: store decoded buffers + extract borders + compute renderable work items
    ///    - 3b. Parallel: render all work items through the pipeline (EPF, color, save)
    ///    - 3c. Sequential: recycle buffers + update flush state
    ///
    /// Requirements:
    /// - More than 1 group
    #[cfg(feature = "threads")]
    fn decode_groups_parallel(
        &mut self,
        groups: Vec<(usize, Vec<(usize, BitReader)>)>,
        buffer_splitter: &mut BufferSplitter,
        do_flush: bool,
    ) -> Result<()> {
        use super::group::{VarDctBuffers, decode_vardct_group};
        use super::modular::ModularStreamId;
        use crate::image::{Image, OwnedRawImage};
        use crate::render::buffer_splitter;
        use crate::render::low_memory_pipeline::render_group;

        use crate::util::Xorshift128Plus;
        use rayon::prelude::*;

        // Helper macros to get &mut / & LowMemoryRenderPipeline from the pipeline field.
        // In non-test builds the field is Box<LMP>; in test builds it's Box<dyn Any>.
        macro_rules! lmp_mut {
            () => {{
                #[cfg(not(test))]
                {
                    self.render_pipeline.as_mut().unwrap()
                }
                #[cfg(test)]
                {
                    self.render_pipeline
                        .as_mut()
                        .unwrap()
                        .downcast_mut::<LowMemoryRenderPipeline>()
                        .unwrap()
                }
            }};
        }
        macro_rules! lmp_ref {
            () => {{
                #[cfg(not(test))]
                {
                    self.render_pipeline.as_ref().unwrap()
                }
                #[cfg(test)]
                {
                    self.render_pipeline
                        .as_ref()
                        .unwrap()
                        .downcast_ref::<LowMemoryRenderPipeline>()
                        .unwrap()
                }
            }};
        }

        let phase_timing = std::env::var("JXL_PHASE_TIMING").is_ok();

        let last_pass_in_file = self.header.passes.num_passes as usize - 1;
        let is_vardct = self.header.encoding == Encoding::VarDCT;

        let stop: &dyn enough::Stop = &*self.decoder_state.stop;

        struct GroupWork<'a> {
            group: usize,
            passes: Vec<(usize, BitReader<'a>)>,
            complete: bool,
            do_render: bool,
            pixels: Option<[Image<f32>; 3]>,
            /// Owned per-group HF coefficient buffers (multi-pass only).
            hf_coeffs: Option<[Vec<i32>; 3]>,
        }

        struct GroupRenderInfo {
            group: usize,
            do_render: bool,
            has_items: bool,
        }

        // Take ownership of per-group HF coefficient buffers before Phase 1.
        // Each group owns its own Vec<i32> — no shared mutable state.
        let mut hf_coefficients = self.hf_coefficients.take();

        // Phase 1: Sequential — compute render decisions (NO pixel allocation).
        // Pixel buffers are allocated on-demand in Phase 2 (parallel) to avoid
        // the sequential allocation bottleneck that caused the 0.59x regression.
        let phase1_start = crate::util::Instant::now();
        let mut work: Vec<GroupWork> = Vec::with_capacity(groups.len());
        let mut num_needs_pixels = 0usize;
        for (group, passes) in groups {
            let was_complete =
                self.last_rendered_pass[group].is_some_and(|p| p >= last_pass_in_file);
            if let Some((p, _)) = passes.last() {
                self.last_rendered_pass[group] = Some(*p);
            }
            let pass_to_render = self.last_rendered_pass[group];
            let complete = pass_to_render.is_some_and(|p| p >= last_pass_in_file);
            if complete && !was_complete {
                self.incomplete_groups = self.incomplete_groups.checked_sub(1).unwrap();
            }
            let do_render = if complete {
                true
            } else if do_flush {
                self.allow_rendering_before_last_pass()
            } else {
                false
            };

            if is_vardct && do_render {
                num_needs_pixels += 1;
            }

            // Take this group's owned coefficient buffers (multi-pass only).
            let hf_coeffs = hf_coefficients.as_mut().map(|[a, b, c]| {
                [
                    std::mem::take(&mut a[group]),
                    std::mem::take(&mut b[group]),
                    std::mem::take(&mut c[group]),
                ]
            });

            work.push(GroupWork {
                group,
                passes,
                complete,
                do_render,
                pixels: None, // Deferred to Phase 2
                hf_coeffs,
            });
        }

        let num_groups = work.len();
        let phase1_dur = phase1_start.elapsed();

        // Pre-seed a shared pixel buffer pool from the scratch pool.
        // Allocate min(num_threads, groups_needing_pixels) triples — recycled
        // buffers from previous calls are free (no page faults). Remaining
        // groups allocate fresh in Phase 2, but in PARALLEL across threads
        // instead of sequentially here.
        let num_threads = rayon::current_num_threads();
        let pool_size = num_threads.min(num_needs_pixels);
        let mut pixel_pool_vec: Vec<[Image<f32>; 3]> = Vec::with_capacity(pool_size);
        for _ in 0..pool_size {
            pixel_pool_vec.push([
                pipeline!(self, p, p.get_buffer(0))?,
                pipeline!(self, p, p.get_buffer(1))?,
                pipeline!(self, p, p.get_buffer(2))?,
            ]);
        }
        let pixel_pool = std::sync::Mutex::new(pixel_pool_vec);
        // Buffer sizes for fresh allocation in Phase 2.
        let pixel_sizes: [(usize, usize); 3] = if is_vardct && num_needs_pixels > pool_size {
            [
                lmp_ref!().pixel_buffer_size(0),
                lmp_ref!().pixel_buffer_size(1),
                lmp_ref!().pixel_buffer_size(2),
            ]
        } else {
            [(0, 0); 3] // unused — all groups served from pool
        };

        // Adaptive batching: for large group counts, process in mini-batches
        // running the full Phase 2→3a→3b→3c pipeline per batch. This allows
        // pixel buffer recycling between batches but each batch incurs a
        // barrier cycle. Each barrier costs ~1ms+ from thread synchronization,
        // so we avoid batching unless group count is very high (8K+ images).
        // At 4T/384 groups, 6 batches caused 40% overhead vs unbatched.
        let decode_batch_size = if num_needs_pixels > num_threads * 256 {
            num_threads * 64
        } else {
            num_groups // fully unbatched
        };
        let is_batched = decode_batch_size < num_groups;

        // VarDCT scratch buffer pool — persists across all batches.
        let mut vb_pool: Vec<VarDctBuffers> = Vec::new();
        if let Some(buf) = self.vardct_buffers.take() {
            vb_pool.push(buf);
        }
        let buffer_pool = std::sync::Mutex::new(vb_pool);

        let mut setup_dur = std::time::Duration::ZERO;
        let mut phase2_dur = std::time::Duration::ZERO;
        let mut collect_dur = std::time::Duration::ZERO;
        let mut phase3a_store_dur = std::time::Duration::ZERO;
        let mut phase3a_prepare_dur = std::time::Duration::ZERO;
        let mut phase3b_dur = std::time::Duration::ZERO;
        let mut phase3c_dur = std::time::Duration::ZERO;

        for batch_start in (0..num_groups).step_by(decode_batch_size) {
            let batch_end = (batch_start + decode_batch_size).min(num_groups);

            // Re-seed pixel pool from scratch between batches.
            let setup_start = crate::util::Instant::now();
            if batch_start > 0 {
                let batch_needs = work[batch_start..batch_end]
                    .iter()
                    .filter(|gw| is_vardct && gw.do_render)
                    .count();
                let reseed = num_threads.min(batch_needs);
                let mut pool = pixel_pool.lock().unwrap();
                for _ in 0..reseed {
                    match (|| -> Result<[Image<f32>; 3]> {
                        Ok([
                            pipeline!(self, p, p.get_buffer(0))?,
                            pipeline!(self, p, p.get_buffer(1))?,
                            pipeline!(self, p, p.get_buffer(2))?,
                        ])
                    })() {
                        Ok(triple) => pool.push(triple),
                        Err(_) => break,
                    }
                }
            }

            setup_dur += setup_start.elapsed();

            // Phase 2: Parallel decode this batch.
            let phase2_start = crate::util::Instant::now();
            {
                let lf_global = self.lf_global.as_ref().unwrap();
                let header = &self.header;
                let hf_global = self.hf_global.as_ref();
                let hf_meta = self.hf_meta.as_ref();
                let lf_image = &self.lf_image;
                let quant_lf = &self.quant_lf;
                let quant_biases = &self
                    .decoder_state
                    .file_header
                    .transform_data
                    .opsin_inverse_matrix
                    .quant_biases;
                let tracker = &self.decoder_state.memory_tracker;

                work[batch_start..batch_end]
                    .par_iter_mut()
                    .try_for_each(|gw| -> Result<()> {
                        stop.check()?;
                        // Allocate pixel buffers on-demand from the shared pool.
                        // This runs in PARALLEL instead of the old sequential Phase 1
                        // allocation, distributing page fault cost across threads.
                        if is_vardct && gw.do_render {
                            gw.pixels = Some(match pixel_pool.lock().unwrap().pop() {
                                Some(bufs) => bufs,
                                None => [
                                    Image::<f32>::new_uninit(pixel_sizes[0])?,
                                    Image::<f32>::new_uninit(pixel_sizes[1])?,
                                    Image::<f32>::new_uninit(pixel_sizes[2])?,
                                ],
                            });
                        }
                        if is_vardct && !gw.passes.is_empty() {
                            let hf_global = hf_global.unwrap();
                            let hf_meta = hf_meta.unwrap();
                            let mut buffers = match buffer_pool.lock().unwrap().pop() {
                                Some(b) => b,
                                None => VarDctBuffers::new()?,
                            };

                            if !(gw.pixels.is_none() && gw.do_render) {
                                // Each parallel task uses a distinct gw.group —
                                // each group owns its own Vec<i32>, no shared state.
                                let hf_coeffs = gw.hf_coeffs.as_mut().map(|[a, b, c]| {
                                    [a.as_mut_slice(), b.as_mut_slice(), c.as_mut_slice()]
                                });
                                decode_vardct_group(
                                    gw.group,
                                    &mut gw.passes,
                                    header,
                                    lf_global,
                                    hf_global,
                                    hf_meta,
                                    lf_image,
                                    quant_lf,
                                    quant_biases,
                                    hf_coeffs,
                                    &mut gw.pixels,
                                    &mut buffers,
                                    tracker,
                                    #[cfg(feature = "jpeg")]
                                    None,
                                )?;
                            }
                            buffer_pool.lock().unwrap().push(buffers);
                        }

                        for (pass, br) in gw.passes.iter_mut() {
                            lf_global.modular_global.read_stream(
                                ModularStreamId::ModularHF {
                                    group: gw.group,
                                    pass: *pass,
                                },
                                header,
                                &lf_global.tree,
                                br,
                                tracker,
                            )?;
                        }
                        Ok(())
                    })?;
            }
            phase2_dur += phase2_start.elapsed();

            // Collect VarDCT pixels for parallel storage.
            let collect_start = crate::util::Instant::now();
            let mut pending_stores: Vec<Option<([OwnedRawImage; 3], bool)>> = if is_vardct {
                let num_groups = lmp_ref!().num_groups();
                let mut stores: Vec<Option<([OwnedRawImage; 3], bool)>> =
                    (0..num_groups).map(|_| None).collect();
                for gw in &mut work[batch_start..batch_end] {
                    if let Some(pixels) = gw.pixels.take() {
                        stores[gw.group] = Some((pixels.map(|p| p.into_raw()), gw.complete));
                    }
                }
                stores
            } else {
                Vec::new()
            };

            collect_dur += collect_start.elapsed();

            // Phase 3a-store: Sequential — store decoded buffers and run process_output.
            let phase3a_start = crate::util::Instant::now();
            let mut groups_stored: Vec<(usize, bool, bool)> =
                Vec::with_capacity(batch_end - batch_start);
            let mut modular_channels_output: Vec<(usize, usize)> = Vec::new();
            for gw in &mut work[batch_start..batch_end] {
                self.decoder_state.check_cancelled()?;

                if is_vardct {
                    if gw.pixels.is_none() && gw.do_render && gw.passes.is_empty() {
                        let mut pixels = [
                            pipeline!(self, p, p.get_buffer(0))?,
                            pipeline!(self, p, p.get_buffer(1))?,
                            pipeline!(self, p, p.get_buffer(2))?,
                        ];
                        upsample_lf_group(
                            gw.group,
                            &mut pixels,
                            self.lf_image.as_ref().unwrap(),
                            &self.header,
                            &self.decoder_state.file_header.transform_data,
                        )?;
                        for (c, img) in pixels.into_iter().enumerate() {
                            lmp_mut!().store_buffer_only(c, gw.group, gw.complete, img);
                        }
                    } else if let Some(pixels) = gw.pixels.take() {
                        for (c, img) in pixels.into_iter().enumerate() {
                            lmp_mut!().store_buffer_only(c, gw.group, gw.complete, img);
                        }
                    }
                }

                // Generate noise buffers for this group if needed.
                if self.header.has_noise() && gw.do_render {
                    let num_channels = self.header.num_extra_channels as usize + 3;
                    let group_dim = self.header.group_dim() as u32;
                    let xsize_groups = self.header.size_groups().0;
                    let gx = (gw.group % xsize_groups) as u32;
                    let gy = (gw.group / xsize_groups) as u32;
                    let upsampling = self.header.upsampling;
                    let upsampled_size = self.header.size_upsampled();

                    let buf_x1 = ((gx + 1) * upsampling * group_dim) as usize;
                    let buf_y1 = ((gy + 1) * upsampling * group_dim) as usize;
                    let buf_xsize =
                        buf_x1.min(upsampled_size.0) - (gx * upsampling * group_dim) as usize;
                    let buf_ysize =
                        buf_y1.min(upsampled_size.1) - (gy * upsampling * group_dim) as usize;

                    let bits_to_float = |bits: u32| f32::from_bits((bits >> 9) | 0x3F800000);

                    let mut bufs = [
                        pipeline!(self, p, p.get_buffer(num_channels)?),
                        pipeline!(self, p, p.get_buffer(num_channels + 1)?),
                        pipeline!(self, p, p.get_buffer(num_channels + 2)?),
                    ];

                    const FLOATS_PER_BATCH: usize = Xorshift128Plus::N * std::mem::size_of::<u64>()
                        / std::mem::size_of::<f32>();
                    let mut batch = [0u64; Xorshift128Plus::N];

                    for iy in 0..upsampling {
                        for ix in 0..upsampling {
                            let x0 = (gx * upsampling + ix) * group_dim;
                            let y0 = (gy * upsampling + iy) * group_dim;
                            let mut rng = Xorshift128Plus::new_with_seeds(
                                self.decoder_state.visible_frame_index as u32,
                                self.decoder_state.nonvisible_frame_index as u32,
                                x0,
                                y0,
                            );
                            let sub_x0 = (ix * group_dim) as usize;
                            let sub_y0 = (iy * group_dim) as usize;
                            let sub_x1 = ((ix + 1) * group_dim) as usize;
                            let sub_y1 = ((iy + 1) * group_dim) as usize;
                            let sub_xsize = sub_x1.min(buf_xsize).saturating_sub(sub_x0);
                            let sub_ysize = sub_y1.min(buf_ysize).saturating_sub(sub_y0);
                            if sub_xsize == 0 || sub_ysize == 0 {
                                continue;
                            }
                            for buf in &mut bufs {
                                for y in 0..sub_ysize {
                                    let row = buf.row_mut(sub_y0 + y);
                                    for batch_index in 0..sub_xsize.div_ceil(FLOATS_PER_BATCH) {
                                        rng.fill(&mut batch);
                                        let batch_size = (sub_xsize
                                            - batch_index * FLOATS_PER_BATCH)
                                            .min(FLOATS_PER_BATCH);
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

                    let [buf0, buf1, buf2] = bufs;
                    lmp_mut!().store_buffer_only(num_channels, gw.group, gw.complete, buf0);
                    lmp_mut!().store_buffer_only(num_channels + 1, gw.group, gw.complete, buf1);
                    lmp_mut!().store_buffer_only(num_channels + 2, gw.group, gw.complete, buf2);
                }

                // Mark modular groups for reading (but don't process yet).
                {
                    let lf_global = self.lf_global.as_mut().unwrap();
                    for (pass, _) in gw.passes.iter() {
                        lf_global
                            .modular_global
                            .mark_group_to_be_read(2 + *pass, gw.group);
                    }
                }

                groups_stored.push((gw.group, gw.do_render, true));
            }

            // Process modular transforms globally after marking ALL groups.
            // This matches the sequential path's STEP 2 + STEP 4 pattern:
            // cascading transforms (squeeze, palette) have neighbor
            // dependencies that require all groups to be marked before
            // process_output can resolve them correctly.
            {
                let lf_global = self.lf_global.as_mut().unwrap();
                lf_global.modular_global.drain_dry_run_to_ready();
                lf_global.modular_global.process_output(
                    &self.header,
                    false,
                    &mut |chan, group, _complete, image: Option<Image<i32>>| {
                        if !lmp_mut!().has_buffer(chan, group) {
                            lmp_mut!().store_buffer_only(chan, group, true, image.unwrap());
                        }
                        modular_channels_output.push((group, chan));
                        // Track cross-group output from cascading transforms.
                        if !groups_stored.iter().any(|(g, _, _)| *g == group) {
                            groups_stored.push((group, true, false));
                        }
                        Ok(())
                    },
                )?;
            }

            phase3a_store_dur += phase3a_start.elapsed();
            let phase3a_prep_start = crate::util::Instant::now();

            // Phase 3a-prepare: Parallel — extract borders and emit work items.
            // When batching, groups from previous batches have is_ready=true,
            // so the readiness mask correctly reflects partial-batch boundaries.
            // Border regions at batch edges are covered by neighboring batches'
            // emit_work_items (the pipeline was designed for incremental arrival).
            //
            // For VarDCT images, store_and_prepare_groups_parallel combines
            // pending pixel storage with border extraction in a single parallel
            // pass, eliminating the sequential pixel store bottleneck.
            // In one-shot unbatched mode, all groups' center data stays alive
            // through Phase 3b, so rendering can read border pixels directly
            // from neighbors' center buffers. Skip the topbottom/leftright copy.
            // In batched or incremental mode, center data is recycled between
            // batches/calls, so borders must be extracted into separate buffers.
            let is_one_shot = num_groups == self.header.num_groups();
            // Only skip border copy in true one-shot decode (not incremental).
            // In incremental decode, was_flushed_once is true from a prior call,
            // and the final re-render needs border buffers to correct cross-batch
            // boundary pixels.
            let skip_border_copy = !is_batched && is_one_shot && !self.was_flushed_once;
            let (all_items, group_has_items) = if is_vardct && !pending_stores.is_empty() {
                lmp_mut!()
                    .store_and_prepare_groups_parallel(&mut pending_stores, skip_border_copy)?
            } else {
                lmp_mut!().prepare_groups_parallel(skip_border_copy)?
            };
            let mut has_items_vec = vec![false; lmp_ref!().num_groups()];
            for &(g, has) in &group_has_items {
                if has {
                    has_items_vec[g] = true;
                }
            }

            // Build render_infos from store tracking + prepare results.
            let mut render_infos: Vec<GroupRenderInfo> = Vec::with_capacity(groups_stored.len());
            for &(group, do_render, is_main) in &groups_stored {
                let has_items = has_items_vec[group];
                if is_main || has_items {
                    render_infos.push(GroupRenderInfo {
                        group,
                        do_render,
                        has_items,
                    });
                }
            }

            phase3a_prepare_dur += phase3a_prep_start.elapsed();

            // Phase 3b: Fragment-based parallel render.
            //
            // Split output buffers into per-tile disjoint fragments (row bands ×
            // column ranges), then process ALL tiles in parallel with direct
            // writes. No copy-back needed since each tile writes exclusively to
            // its own fragment.
            //
            // Falls back to two-phase (owned buffers + copy-back) when band
            // splitting isn't possible (single gy band with overlapping rows).
            let phase3b_start = crate::util::Instant::now();
            if !all_items.is_empty() {
                let p = lmp_ref!();
                let view = p.read_view();
                let (frame_origin, full_image_size) = p.extend_origin_size();
                let sbi = p.save_buffer_info();
                let input_size = p.input_size();
                let factory = p.context_factory();
                let num_buffer_slots = buffer_splitter.get_full_buffers().len();

                // Pre-compute channel_rects for all items.
                let all_layouts: Vec<Vec<(usize, usize, usize, Rect)>> = all_items
                    .iter()
                    .map(|item| {
                        buffer_splitter::compute_local_buffer_layouts(
                            sbi,
                            num_buffer_slots,
                            item.image_area,
                            input_size,
                            full_image_size,
                            frame_origin,
                        )
                    })
                    .collect();

                // Group items by gy (sorted ascending).
                let mut gy_map: std::collections::BTreeMap<usize, Vec<usize>> =
                    std::collections::BTreeMap::new();
                for (i, item) in all_items.iter().enumerate() {
                    gy_map.entry(item.gy).or_default().push(i);
                }
                let gy_items: Vec<Vec<usize>> = gy_map.into_values().collect();
                let num_bands = gy_items.len();

                // Sort items within each band by gx for consistent column ordering.
                let gy_items: Vec<Vec<usize>> = gy_items
                    .into_iter()
                    .map(|mut indices| {
                        indices.sort_by_key(|&idx| all_items[idx].gx);
                        indices
                    })
                    .collect();

                // Compute per-slot, per-band row ranges from channel_rects.
                let mut slot_band_ranges: Vec<Vec<(usize, usize)>> =
                    vec![vec![(usize::MAX, 0); num_bands]; num_buffer_slots];
                for (band_idx, item_indices) in gy_items.iter().enumerate() {
                    for &item_idx in item_indices {
                        for &(slot, _, _, channel_rect) in &all_layouts[item_idx] {
                            let start_row = channel_rect.origin.1;
                            let end_row = start_row + channel_rect.size.1;
                            let range = &mut slot_band_ranges[slot][band_idx];
                            range.0 = range.0.min(start_row);
                            range.1 = range.1.max(end_row);
                        }
                    }
                }

                // Verify non-overlapping bands for each active slot.
                let can_band_split = num_bands > 1
                    && slot_band_ranges.iter().all(|ranges| {
                        ranges.windows(2).all(|w| {
                            let (_, end_a) = w[0];
                            let (start_b, _) = w[1];
                            // Empty bands (usize::MAX, 0) never overlap.
                            end_a == 0 || start_b == usize::MAX || end_a <= start_b
                        })
                    });

                // Fragment path: split each slot's buffer into a tile grid,
                // then process all tiles in parallel with direct writes.
                if can_band_split {
                    // Compute per-slot row split points.
                    let slot_split_rows: Vec<Vec<usize>> = (0..num_buffer_slots)
                        .map(|slot| {
                            let ranges = &slot_band_ranges[slot];
                            (0..num_bands - 1)
                                .map(|band_idx| {
                                    let end_row = ranges[band_idx].1;
                                    if end_row == 0 { 0 } else { end_row }
                                })
                                .collect()
                        })
                        .collect();

                    // Compute per-slot, per-band column split points.
                    // Within each band, items are sorted by gx. For each slot,
                    // use the column start of each item (except the first) as
                    // the split point.
                    let slot_split_cols_per_band: Vec<Vec<Vec<usize>>> = (0..num_buffer_slots)
                        .map(|slot| {
                            gy_items
                                .iter()
                                .map(|item_indices| {
                                    // Collect column starts for items in this band+slot.
                                    let col_starts: Vec<usize> = item_indices
                                        .iter()
                                        .filter_map(|&item_idx| {
                                            all_layouts[item_idx]
                                                .iter()
                                                .find(|&&(s, _, _, _)| s == slot)
                                                .map(|&(_, _, _, cr)| cr.origin.0)
                                        })
                                        .collect();
                                    // Split points = starts of 2nd, 3rd, ... items.
                                    col_starts.into_iter().skip(1).collect()
                                })
                                .collect()
                        })
                        .collect();

                    // Split each slot's buffer into a tile grid.
                    let output = buffer_splitter.get_full_buffers();
                    let mut slot_grids: Vec<Option<Vec<Vec<Option<JxlOutputBuffer<'_>>>>>> = output
                        .iter_mut()
                        .enumerate()
                        .map(|(slot_idx, buf_opt)| {
                            buf_opt.as_mut().map(|buf| {
                                let split_cols_refs: Vec<&[usize]> = slot_split_cols_per_band
                                    [slot_idx]
                                    .iter()
                                    .map(|v| v.as_slice())
                                    .collect();
                                buf.split_into_tile_grid(
                                    &slot_split_rows[slot_idx],
                                    &split_cols_refs,
                                )
                                .into_iter()
                                .map(|band| band.into_iter().map(Some).collect())
                                .collect()
                            })
                        })
                        .collect();

                    // Build per-item fragment sets by taking from the grid.
                    // Each item gets one fragment per slot, plus the fragment's
                    // absolute column offset so rect() can adjust correctly.
                    let mut item_fragments: Vec<Vec<Option<JxlOutputBuffer<'_>>>> = (0..all_items
                        .len())
                        .map(|_| (0..num_buffer_slots).map(|_| None).collect())
                        .collect();
                    let mut item_col_offsets: Vec<Vec<usize>> =
                        vec![vec![0; num_buffer_slots]; all_items.len()];

                    for (band_idx, item_indices) in gy_items.iter().enumerate() {
                        // Track fragment index per slot (items without a rect for
                        // a given slot don't consume a fragment in that slot).
                        let mut slot_frag_idx: Vec<usize> = vec![0; num_buffer_slots];
                        for &item_idx in item_indices {
                            for slot_idx in 0..num_buffer_slots {
                                let has_rect = all_layouts[item_idx]
                                    .iter()
                                    .any(|&(s, _, _, _)| s == slot_idx);
                                if !has_rect {
                                    continue;
                                }
                                let frag_idx = slot_frag_idx[slot_idx];
                                slot_frag_idx[slot_idx] += 1;
                                if let Some(grid) = slot_grids[slot_idx].as_mut()
                                    && let Some(frag) =
                                        grid[band_idx].get_mut(frag_idx).and_then(|o| o.take())
                                {
                                    item_fragments[item_idx][slot_idx] = Some(frag);
                                    // Fragment col offset: 0 for first fragment,
                                    // split_cols[frag_idx-1] for subsequent ones.
                                    let col_offset = if frag_idx == 0 {
                                        0
                                    } else {
                                        slot_split_cols_per_band[slot_idx][band_idx]
                                            .get(frag_idx - 1)
                                            .copied()
                                            .unwrap_or(0)
                                    };
                                    item_col_offsets[item_idx][slot_idx] = col_offset;
                                }
                            }
                        }
                    }
                    drop(slot_grids);

                    // Process all tiles in parallel with direct fragment writes.
                    item_fragments
                        .par_iter_mut()
                        .enumerate()
                        .try_for_each_init(
                            || factory.create(1).ok(),
                            |ctx_opt, (item_idx, slot_bufs)| -> Result<()> {
                                stop.check()?;
                                let ctx = ctx_opt.as_mut().ok_or(Error::ImageOutOfMemory(0, 0))?;
                                let item = &all_items[item_idx];
                                // Create rect sub-views from fragments.
                                // Fragments cover the full band; rect() narrows
                                // to the tile's exact row range and resets to 0-based.
                                let mut local_bufs: Vec<Option<JxlOutputBuffer<'_>>> = slot_bufs
                                    .iter_mut()
                                    .enumerate()
                                    .map(|(slot_idx, frag_opt)| {
                                        let frag = frag_opt.as_mut()?;
                                        let cr = all_layouts[item_idx]
                                            .iter()
                                            .find(|&&(s, _, _, _)| s == slot_idx)
                                            .map(|&(_, _, _, cr)| cr)?;
                                        // Adjust column origin: fragment starts at
                                        // col_offset, tile starts at cr.origin.0.
                                        let col_offset = item_col_offsets[item_idx][slot_idx];
                                        Some(frag.rect(Rect {
                                            origin: (cr.origin.0 - col_offset, cr.origin.1),
                                            size: cr.size,
                                        }))
                                    })
                                    .collect();
                                render_group::render(
                                    ctx,
                                    &view,
                                    (item.gx, item.gy),
                                    item.image_area,
                                    &mut local_bufs,
                                )?;
                                Ok(())
                            },
                        )?;

                    drop(item_fragments);
                } else {
                    // Fallback: two-phase render (owned buffers + copy-back).
                    // Used when band splitting isn't possible (single gy band
                    // or overlapping row ranges).
                    let render_outputs: Vec<Vec<buffer_splitter::OwnedLocalBuffer>> =
                        all_items
                            .par_iter()
                            .enumerate()
                            .map_init(
                                || factory.create(1).ok(),
                                |ctx_opt, (idx, item)| -> Result<Vec<buffer_splitter::OwnedLocalBuffer>> {
                                    stop.check()?;
                                    let ctx = ctx_opt
                                        .as_mut()
                                        .ok_or(Error::ImageOutOfMemory(0, 0))?;
                                    let layouts = &all_layouts[idx];
                                    let mut owned: Vec<buffer_splitter::OwnedLocalBuffer> =
                                        layouts
                                            .iter()
                                            .map(|&(slot, bpr, nr, cr)| {
                                                buffer_splitter::OwnedLocalBuffer {
                                                    data: vec![0u8; bpr * nr],
                                                    bytes_per_row: bpr,
                                                    num_rows: nr,
                                                    channel_rect: cr,
                                                    buffer_index: slot,
                                                }
                                            })
                                            .collect();
                                    let mut local_bufs: Vec<Option<JxlOutputBuffer<'_>>> =
                                        (0..num_buffer_slots).map(|_| None).collect();
                                    for olb in owned.iter_mut() {
                                        local_bufs[olb.buffer_index] =
                                            Some(JxlOutputBuffer::new(
                                                &mut olb.data,
                                                olb.num_rows,
                                                olb.bytes_per_row,
                                            ));
                                    }
                                    render_group::render(
                                        ctx,
                                        &view,
                                        (item.gx, item.gy),
                                        item.image_area,
                                        &mut local_bufs,
                                    )?;
                                    drop(local_bufs);
                                    Ok(owned)
                                },
                            )
                            .collect::<Result<Vec<_>>>()?;

                    // Sequential copy-back (no band split available).
                    let output = buffer_splitter.get_full_buffers();
                    for owned in &render_outputs {
                        buffer_splitter::copy_back_local_buffers(owned, output);
                    }
                }
            }
            phase3b_dur += phase3b_start.elapsed();

            // Phase 3c: Sequential — recycle buffers and update flush state.
            // When batching, skip border recycling: cross-batch process_output
            // can store data to groups from previous batches, re-readying them
            // for rendering. Their neighbors' border buffers must stay alive.
            // Center data IS recycled to refill the pixel pool for next batch.
            let phase3c_start = crate::util::Instant::now();
            for ri in &render_infos {
                if ri.has_items {
                    lmp_mut!().recycle_group_buffers(ri.group, !is_batched);
                }
                if ri.do_render {
                    self.groups_to_flush.remove(&ri.group);
                    // Track what was rendered so STEP 5 doesn't redundantly re-render.
                    if is_vardct {
                        self.changed_since_last_flush
                            .insert((ri.group, RenderUnit::VarDCT));
                    }
                } else {
                    self.groups_to_flush.insert(ri.group);
                }
            }
            for &(group, chan) in &modular_channels_output {
                self.changed_since_last_flush
                    .insert((group, RenderUnit::Modular(chan)));
            }
            phase3c_dur += phase3c_start.elapsed();
        } // end batch loop

        // After all batches complete, run the deferred border recycling pass.
        // This is a no-op when unbatched (borders were already recycled above).
        if is_batched {
            lmp_mut!().recycle_all_borders();
        }

        // Save one VarDCT buffer for reuse in next call.
        self.vardct_buffers = buffer_pool.into_inner().unwrap().pop();

        // Restore HF coefficient buffers after all batches complete.
        if let Some(ref mut channels) = hf_coefficients {
            for gw in &mut work {
                if let Some(coeffs) = gw.hf_coeffs.take() {
                    let [a, b, c] = coeffs;
                    channels[0][gw.group] = a;
                    channels[1][gw.group] = b;
                    channels[2][gw.group] = c;
                }
            }
        }
        self.hf_coefficients = hf_coefficients;

        if phase_timing {
            let batches = num_groups.div_ceil(decode_batch_size);
            let total = phase1_dur
                + setup_dur
                + phase2_dur
                + collect_dur
                + phase3a_store_dur
                + phase3a_prepare_dur
                + phase3b_dur
                + phase3c_dur;
            eprintln!(
                "[JXL_PHASE_TIMING] {num_groups} groups ({batches} batches of {decode_batch_size}) | \
                 P1: {:.2}ms | setup: {:.2}ms | P2: {:.2}ms | collect: {:.2}ms | \
                 P3a-store: {:.2}ms | P3a-prep: {:.2}ms | \
                 P3b: {:.2}ms | P3c: {:.2}ms | sum: {:.2}ms",
                phase1_dur.as_secs_f64() * 1000.0,
                setup_dur.as_secs_f64() * 1000.0,
                phase2_dur.as_secs_f64() * 1000.0,
                collect_dur.as_secs_f64() * 1000.0,
                phase3a_store_dur.as_secs_f64() * 1000.0,
                phase3a_prepare_dur.as_secs_f64() * 1000.0,
                phase3b_dur.as_secs_f64() * 1000.0,
                phase3c_dur.as_secs_f64() * 1000.0,
                total.as_secs_f64() * 1000.0,
            );
        }

        Ok(())
    }

    /// Helper function to detect CMYK ICC profile from bytes.
    /// Returns true if the ICC profile has CMYK color space signature.
    #[cfg(feature = "cms")]
    fn is_cmyk_icc_profile(icc_data: &[u8]) -> bool {
        if icc_data.len() < 20 {
            return false;
        }
        // ICC color space signature is at bytes 16-19
        &icc_data[16..20] == b"CMYK"
    }

    /// Try to create a CMS-based CMYK->RGB conversion stage.
    /// Returns Some(stage) if successful, None if we should fall back to simple K multiplication.
    #[cfg(feature = "cms")]
    fn try_create_cms_cmyk_stage(
        decoder_state: &DecoderState,
        cms: Option<&dyn JxlCms>,
        black_channel_offset: usize,
    ) -> Result<Option<CmsCmykToRgbStage>> {
        // Check if we have a CMS and a CMYK ICC profile
        let (cms, icc_data) = match (cms, &decoder_state.embedded_color_profile) {
            (Some(cms), Some(JxlColorProfile::Icc(icc_data))) => (cms, icc_data),
            _ => return Ok(None),
        };

        // Check if the ICC profile is CMYK
        if !Self::is_cmyk_icc_profile(icc_data) {
            return Ok(None);
        }

        // Create CMYK -> sRGB transform
        let cmyk_profile = JxlColorProfile::Icc(icc_data.clone());
        let srgb_profile = JxlColorProfile::Simple(JxlColorEncoding::srgb(false));

        // Initialize a single transformer for CMYK -> sRGB
        let (output_channels, mut transformers) = cms.initialize_transforms(
            1,   // We only need 1 transformer
            256, // pixels per transform (row chunk size is typically small)
            cmyk_profile,
            srgb_profile,
            decoder_state
                .file_header
                .image_metadata
                .tone_mapping
                .intensity_target,
        )?;

        // Verify we got an RGB output (3 channels)
        if output_channels != 3 || transformers.is_empty() {
            return Ok(None);
        }

        // Take the transformer and create the CMS stage
        let transformer = transformers.remove(0);
        Ok(Some(CmsCmykToRgbStage::new(
            black_channel_offset,
            transformer,
        )))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn build_render_pipeline<T: RenderPipeline>(
        decoder_state: &DecoderState,
        frame_header: &FrameHeader,
        lf_global: &LfGlobalState,
        epf_sigma: &Option<SigmaSource>,
        pixel_format: &JxlPixelFormat,
        cms: Option<&dyn JxlCms>,
        input_profile: &JxlColorProfile,
        output_profile: &JxlColorProfile,
    ) -> Result<Box<T>> {
        let num_channels = frame_header.num_extra_channels as usize + 3;
        let num_temp_channels = if frame_header.has_noise() { 3 } else { 0 };
        let metadata = &decoder_state.file_header.image_metadata;
        // Orientation handed to the save stage. When `adjust_orientation` is set
        // (the default), the save stage bakes the stored orientation into the
        // output so the emitted image is upright. When it is cleared (Preserve
        // mode), we pass `Identity` so the save stage performs no spatial
        // transform: pixels are emitted in their stored (coded) orientation and
        // dimensions, and the intrinsic orientation is reported on the basic
        // info for a later baking stage to apply.
        let save_orientation = if decoder_state.adjust_orientation {
            metadata.orientation
        } else {
            Orientation::Identity
        };
        let mut pipeline = RenderPipelineBuilder::<T>::new(
            num_channels + num_temp_channels,
            frame_header.size_upsampled(),
            frame_header.upsampling.ilog2() as usize,
            frame_header.log_group_dim(),
        )
        .with_memory_tracker(decoder_state.memory_tracker.clone());

        if frame_header.encoding == Encoding::Modular {
            if decoder_state.file_header.image_metadata.xyb_encoded {
                pipeline = pipeline
                    .add_inout_stage(ConvertModularXYBToF32Stage::new(0, &lf_global.lf_quant))
            } else {
                for i in 0..3 {
                    pipeline = pipeline
                        .add_inout_stage(ConvertModularToF32Stage::new(i, metadata.bit_depth));
                }
            }
        }
        for i in 3..num_channels {
            // Use each extra channel's own bit depth, not the image's metadata bit depth
            let ec_bit_depth = metadata.extra_channel_info[i - 3].bit_depth();
            pipeline = pipeline.add_inout_stage(ConvertModularToF32Stage::new(i, ec_bit_depth));
        }

        for c in 0..3 {
            if frame_header.hshift(c) != 0 {
                pipeline = pipeline.add_inout_stage(HorizontalChromaUpsample::new(c));
            }
            if frame_header.vshift(c) != 0 {
                pipeline = pipeline.add_inout_stage(VerticalChromaUpsample::new(c));
            }
        }

        let filters = &frame_header.restoration_filter;
        if filters.gab {
            pipeline = pipeline
                .add_inout_stage(GaborishStage::new(
                    0,
                    filters.gab_x_weight1,
                    filters.gab_x_weight2,
                ))
                .add_inout_stage(GaborishStage::new(
                    1,
                    filters.gab_y_weight1,
                    filters.gab_y_weight2,
                ))
                .add_inout_stage(GaborishStage::new(
                    2,
                    filters.gab_b_weight1,
                    filters.gab_b_weight2,
                ));
        }

        let rf = &frame_header.restoration_filter;
        if rf.epf_iters >= 3 {
            pipeline = pipeline.add_inout_stage(Epf0Stage::new(
                rf.epf_pass0_sigma_scale,
                rf.epf_border_sad_mul,
                rf.epf_channel_scale,
                epf_sigma.clone().unwrap(),
            ))
        }
        if rf.epf_iters >= 1 {
            pipeline = pipeline.add_inout_stage(Epf1Stage::new(
                1.0,
                rf.epf_border_sad_mul,
                rf.epf_channel_scale,
                epf_sigma.clone().unwrap(),
            ))
        }
        if rf.epf_iters >= 2 {
            pipeline = pipeline.add_inout_stage(Epf2Stage::new(
                rf.epf_pass2_sigma_scale,
                rf.epf_border_sad_mul,
                rf.epf_channel_scale,
                epf_sigma.clone().unwrap(),
            ))
        }

        let late_ec_upsample = frame_header.upsampling > 1
            && frame_header
                .ec_upsampling
                .iter()
                .all(|x| *x == frame_header.upsampling);

        if !late_ec_upsample {
            let transform_data = &decoder_state.file_header.transform_data;
            for (ec, ec_up) in frame_header.ec_upsampling.iter().enumerate() {
                if *ec_up > 1 {
                    pipeline = match *ec_up {
                        2 => pipeline.add_inout_stage(Upsample2x::new(transform_data, 3 + ec)),
                        4 => pipeline.add_inout_stage(Upsample4x::new(transform_data, 3 + ec)),
                        8 => pipeline.add_inout_stage(Upsample8x::new(transform_data, 3 + ec)),
                        _ => unreachable!(),
                    };
                }
            }
        }

        if frame_header.has_patches() {
            pipeline = pipeline.add_inplace_stage(PatchesStage {
                patches: lf_global.patches.clone().unwrap(),
                extra_channels: metadata.extra_channel_info.clone(),
                decoder_state: decoder_state.reference_frames.clone(),
            })
        }

        if frame_header.has_splines() {
            pipeline = pipeline.add_inplace_stage(SplinesStage::new(
                lf_global.splines.clone().unwrap(),
                frame_header.size(),
                &lf_global.color_correlation_params.unwrap_or_default(),
                decoder_state.high_precision,
            )?)
        }

        if frame_header.upsampling > 1 {
            let transform_data = &decoder_state.file_header.transform_data;
            let nb_channels = if late_ec_upsample {
                3 + frame_header.ec_upsampling.len()
            } else {
                3
            };
            for c in 0..nb_channels {
                pipeline = match frame_header.upsampling {
                    2 => pipeline.add_inout_stage(Upsample2x::new(transform_data, c)),
                    4 => pipeline.add_inout_stage(Upsample4x::new(transform_data, c)),
                    8 => pipeline.add_inout_stage(Upsample8x::new(transform_data, c)),
                    _ => unreachable!(),
                };
            }
        }

        if frame_header.has_noise() {
            pipeline = pipeline
                .add_inout_stage(ConvolveNoiseStage::new(num_channels))
                .add_inout_stage(ConvolveNoiseStage::new(num_channels + 1))
                .add_inout_stage(ConvolveNoiseStage::new(num_channels + 2))
                .add_inplace_stage(AddNoiseStage::new(
                    *lf_global.noise.as_ref().unwrap(),
                    lf_global.color_correlation_params.unwrap_or_default(),
                    num_channels,
                ));
        }

        // Calculate the actual number of API-provided buffers based on pixel_format.
        // This is the number of buffers the caller provides, NOT the theoretical max.
        // When extra_channel_format[i] is None, that channel doesn't get a buffer.
        let num_api_buffers = std::iter::once(&pixel_format.color_data_format)
            .chain(pixel_format.extra_channel_format.iter())
            .filter(|x| x.is_some())
            .count();
        assert_eq!(
            pixel_format.extra_channel_format.len(),
            frame_header.num_extra_channels as usize
        );

        assert!(frame_header.lf_level == 0 || !frame_header.can_be_referenced);

        if frame_header.lf_level != 0 {
            for i in 0..3 {
                pipeline = pipeline.add_save_stage(
                    &[i],
                    Orientation::Identity,
                    num_api_buffers + i,
                    JxlColorType::Grayscale,
                    JxlDataFormat::f32(),
                    false,
                );
            }
        }
        if frame_header.can_be_referenced && frame_header.save_before_ct {
            for i in 0..num_channels {
                pipeline = pipeline.add_save_stage(
                    &[i],
                    Orientation::Identity,
                    num_api_buffers + i,
                    JxlColorType::Grayscale,
                    JxlDataFormat::f32(),
                    false,
                );
            }
        }

        let output_color_info = OutputColorInfo::from_header(&decoder_state.file_header)?;

        // Determine output TF: use output profile's TF if available, else fall back to embedded profile's TF.
        // Note: output_color_info (luminances, opsin matrix) always comes from the embedded profile;
        // CMS handles any primaries conversion if the output profile differs.
        let output_tf = output_profile
            .transfer_function()
            .map(|tf| {
                TransferFunction::from_api_tf(
                    tf,
                    output_color_info.intensity_target,
                    output_color_info.luminances,
                )
            })
            .unwrap_or_else(|| output_color_info.tf.clone());

        // Clamp transfer-domain values while converting to f16 so we don't
        // emit wild out-of-range values to downstream consumers.
        //
        // PQ has a bounded signal domain [0,1].
        // HLG may carry modest overshoot/undershoot (e.g. from narrow-range
        // workflows), so preserve headroom with a looser clamp.
        let clamp_range_for_f16 = match &output_tf {
            TransferFunction::Pq { .. } => Some((0.0, 1.0)),
            TransferFunction::Hlg { .. } => Some((-0.074, 1.1)),
            _ => None,
        };

        // Find the Black (K) extra channel if present.
        // In JXL, CMYK is stored as 3 color channels (CMY) + K as extra channel.
        // Pipeline index of K = extra_channel_index + 3
        let black_channel: Option<usize> = decoder_state
            .file_header
            .image_metadata
            .extra_channel_info
            .iter()
            .enumerate()
            .find(|x| x.1.ec_type == ExtraChannel::Black)
            .map(|(k_idx, _)| k_idx + 3);

        let xyb_encoded = decoder_state.file_header.image_metadata.xyb_encoded;
        let has_black_channel = black_channel.is_some();

        // Pre-check: can we fuse XYB inverse + sRGB TF + u8 conversion into one stage?
        // All conditions checked here are available before CMS; the CMS check comes later.
        let has_spot_colors = decoder_state.render_spotcolors
            && decoder_state
                .file_header
                .image_metadata
                .extra_channel_info
                .iter()
                .any(|info| info.ec_type == ExtraChannel::SpotColor);
        let mut fuse_xyb_u8: Option<(u8, TransferFunction)> = None;
        if xyb_encoded
            && !frame_header.do_ycbcr
            && !output_tf.is_linear()
            && matches!(
                &output_tf,
                TransferFunction::Srgb | TransferFunction::Gamma(_)
            )
            && let Some(JxlDataFormat::U8 { bit_depth }) = pixel_format.color_data_format
            && !has_black_channel
            && !frame_header.needs_blending()
            && !has_spot_colors
            && !decoder_state.premultiply_output
        {
            // Defer XybStage — will be fused with TF + u8.
            fuse_xyb_u8 = Some((bit_depth, output_tf.clone()));
        }

        if frame_header.do_ycbcr {
            pipeline = pipeline.add_inplace_stage(YcbcrToRgbStage::new(0));
        } else if xyb_encoded && fuse_xyb_u8.is_none() {
            pipeline = pipeline.add_inplace_stage(XybStage::new(0, output_color_info.clone()));
        }

        // Insert tone mapping stage if desired_intensity_target differs from
        // the image's embedded intensity target. This matches libjxl's
        // ToneMappingStage (stage_tone_mapping.cc). The stage operates on
        // display-referred linear RGB, so it must come after XYB decode and
        // before FromLinearStage / CMS.
        let orig_intensity_target = output_color_info.intensity_target;
        if let Some(desired) = decoder_state.desired_intensity_target
            && (desired - orig_intensity_target).abs() > f32::EPSILON
            && xyb_encoded
        {
            match &output_color_info.tf {
                TransferFunction::Pq { .. } => {
                    pipeline = pipeline.add_inplace_stage(ToneMappingStage::pq(
                        0,
                        orig_intensity_target,
                        desired,
                        output_color_info.luminances,
                    ));
                }
                TransferFunction::Hlg { .. } => {
                    pipeline = pipeline.add_inplace_stage(ToneMappingStage::hlg(
                        0,
                        orig_intensity_target,
                        desired,
                        output_color_info.luminances,
                    ));
                }
                _ => {
                    // Tone mapping only applies to HDR transfer functions
                }
            }
        }

        // Insert CMS stage if profiles differ.
        // Following libjxl: use EITHER CMS OR FromLinearStage, never both.
        // - If output matches original encoding: only FromLinearStage is needed
        // - If output differs: CMS handles everything including TF conversion
        //
        // For XYB images, XybStage outputs LINEAR data in the embedded profile's primaries,
        // so the CMS input should be the LINEAR version of the embedded profile.
        // For ICC embedded profiles with XYB, XybStage outputs linear sRGB (see xyb.rs).
        let cms_input_profile = if xyb_encoded {
            // XYB outputs linear, so use linear version of input profile for CMS
            input_profile.with_linear_tf().or_else(|| {
                // For ICC profiles with XYB, XybStage outputs linear sRGB
                Some(JxlColorProfile::Simple(JxlColorEncoding::linear_srgb(
                    false,
                )))
            })
        } else {
            // Non-XYB: data is in the embedded profile's space including TF
            Some(input_profile.clone())
        };

        // Compare ORIGINAL input profile (not linearized cms_input_profile) with output.
        // This matches libjxl (53042ec5) dec_xyb.cc:184:
        //   color_encoding_is_original = orig_color_encoding.SameColorEncoding(c_desired);
        let color_encoding_is_original = input_profile.same_color_encoding(output_profile);

        // Also check if the CMS would be a no-op: for XYB images, the CMS input is the
        // linearized version of the embedded profile. If this matches the output profile,
        // the CMS transform would be identity but may introduce clamping artifacts
        // (e.g., moxcms clamps TRC LUT to [0,1], losing out-of-gamut values).
        let cms_would_be_identity = cms_input_profile
            .as_ref()
            .is_some_and(|cms_in| cms_in.same_color_encoding(output_profile));

        let mut cms_used = false;

        // Skip CMS if channel counts differ (grayscale↔RGB) - like libjxl's not_mixing_color_and_grey.
        // Exception: CMYK (4) → RGB (3) is allowed via CMS.
        let src_channels = cms_input_profile
            .as_ref()
            .map(|p| p.channels())
            .unwrap_or(3);
        let dst_channels = output_profile.channels();
        let channel_counts_compatible =
            src_channels == dst_channels || (src_channels == 4 && dst_channels == 3);

        if !color_encoding_is_original
            && !cms_would_be_identity
            && channel_counts_compatible
            && let Some(cms) = cms
            && let Some(cms_input) = cms_input_profile
        {
            // Use frame width as max_pixels since rows can be that wide
            let max_pixels = frame_header.size_upsampled().0;
            // Use CMS input profile's channel count, matching libjxl's c_src_.Channels()
            // For CMYK, channels() returns 4; for RGB, 3; for grayscale, 1.
            let in_channels = cms_input.channels();
            // Create enough transformers for parallel rendering threads.
            #[cfg(feature = "threads")]
            let num_transforms = if decoder_state.parallel {
                rayon::current_num_threads() + 2
            } else {
                1
            };
            #[cfg(not(feature = "threads"))]
            let num_transforms = 1;
            let (out_channels, transformers) = cms.initialize_transforms(
                num_transforms,
                max_pixels,
                cms_input,
                output_profile.clone(),
                output_color_info.intensity_target,
            )?;
            // CMS cannot add channels - reject transforms that would
            if out_channels > in_channels {
                return Err(Error::CmsChannelCountIncrease {
                    in_channels,
                    out_channels,
                });
            }
            // Only pass black_channel to CmsStage if CMS is actually processing CMYK input.
            // For XYB images, even if original was CMYK, CMS input is linear RGB.
            let cms_black_channel = if in_channels == 4 {
                black_channel
            } else {
                None
            };
            Self::check_cms_consumed_black_channel(
                cms_black_channel,
                in_channels,
                out_channels,
                pixel_format,
            )?;
            if !transformers.is_empty() {
                pipeline = pipeline.add_inplace_stage(CmsStage::new(
                    transformers,
                    in_channels,
                    out_channels,
                    cms_black_channel,
                    max_pixels,
                ));
                cms_used = true;
            }
        }

        // For CMYK images, we need to handle blending in CMYK color space.
        // If ANY frame in the image needs blending, ALL frames must save their
        // reference in CMYK space so that subsequent frames can blend correctly.
        let cmyk_needs_deferred_cms = has_black_channel
            && (frame_header.needs_blending()
                || (frame_header.can_be_referenced && !frame_header.save_before_ct));

        // If CMS was used, the full XYB+TF+u8 fusion is not possible — fall back.
        // We deferred XybStage earlier, so we need to add it now plus the separate TF stage.
        if fuse_xyb_u8.is_some() && cms_used {
            fuse_xyb_u8 = None;
            pipeline = pipeline.add_inplace_stage(XybStage::new(0, output_color_info.clone()));
        }

        // XYB output is linear, so apply transfer function:
        // - Only if output is non-linear AND
        // - CMS was not used (CMS already handles the full conversion including TF)
        //
        // When full XYB+TF+U8 fusion is active, skip both FromLinearStage and XybStage —
        // XybToU8Stage handles all three in one SIMD pass.
        // When only sRGB+U8 fusion is active (non-XYB or CMS fallback), FromLinearSrgbToU8Stage
        // handles the TF+u8 conversion.
        let mut fuse_srgb_to_u8_bit_depth: Option<u8> = None;
        if fuse_xyb_u8.is_some() {
            // Full fusion path: XYB+TF+U8 all handled at conversion stage
        } else if xyb_encoded && !output_tf.is_linear() && !cms_used {
            if let TransferFunction::Srgb = &output_tf
                && let Some(JxlDataFormat::U8 { bit_depth }) = pixel_format.color_data_format
                && !has_black_channel
                && !frame_header.needs_blending()
                && !has_spot_colors
                && !decoder_state.premultiply_output
            {
                fuse_srgb_to_u8_bit_depth = Some(bit_depth);
            }
            if fuse_srgb_to_u8_bit_depth.is_none() {
                pipeline = pipeline.add_inplace_stage(FromLinearStage::new(0, output_tf.clone()));
            }
        }

        // For CMYK images that don't need deferred CMS, apply Black channel conversion here
        if has_black_channel && !cmyk_needs_deferred_cms {
            for (i, info) in decoder_state
                .file_header
                .image_metadata
                .extra_channel_info
                .iter()
                .enumerate()
            {
                if info.ec_type == ExtraChannel::Black {
                    // Try to use CMS-based CMYK conversion if we have:
                    // 1. A CMS implementation available
                    // 2. An embedded CMYK ICC profile
                    #[cfg(feature = "cms")]
                    if let Some(cms_stage) = Self::try_create_cms_cmyk_stage(decoder_state, cms, i)?
                    {
                        pipeline = pipeline.add_inplace_stage(cms_stage);
                    } else {
                        // Fall back to simple K multiplication: R = C * K, G = M * K, B = Y * K
                        pipeline = pipeline.add_inplace_stage(BlackChannelStage::new(i));
                    }
                    #[cfg(not(feature = "cms"))]
                    {
                        let _ = cms; // suppress unused warning when cms feature is off
                        pipeline = pipeline.add_inplace_stage(BlackChannelStage::new(i));
                    }
                }
            }
        }

        if frame_header.needs_blending() {
            pipeline = pipeline.add_inplace_stage(BlendingStage::new(
                frame_header,
                &decoder_state.file_header,
                decoder_state.reference_frames.clone(),
            )?);
            // TODO(veluca): we might not need to add an extend stage if the image size is
            // compatible with the frame size.
            pipeline = pipeline.add_extend_stage(ExtendToImageDimensionsStage::new(
                frame_header,
                &decoder_state.file_header,
                decoder_state.reference_frames.clone(),
            )?);
        }

        // For CMYK images that need deferred CMS, save reference in CMYK space (before CMS)
        // and apply CMS conversion after. This is critical: blending must happen in CMYK space.
        if cmyk_needs_deferred_cms {
            // Save reference in CMYK space (before CMS conversion)
            if frame_header.can_be_referenced && !frame_header.save_before_ct {
                for i in 0..num_channels {
                    pipeline = pipeline.add_save_stage(
                        &[i],
                        Orientation::Identity,
                        num_api_buffers + i,
                        JxlColorType::Grayscale,
                        JxlDataFormat::f32(),
                        false,
                    );
                }
            }

            // Apply CMS conversion (CMYK -> RGB) after blending/saving
            for (i, info) in decoder_state
                .file_header
                .image_metadata
                .extra_channel_info
                .iter()
                .enumerate()
            {
                if info.ec_type == ExtraChannel::Black {
                    #[cfg(feature = "cms")]
                    if let Some(cms_stage) = Self::try_create_cms_cmyk_stage(decoder_state, cms, i)?
                    {
                        pipeline = pipeline.add_inplace_stage(cms_stage);
                    } else {
                        pipeline = pipeline.add_inplace_stage(BlackChannelStage::new(i));
                    }
                    #[cfg(not(feature = "cms"))]
                    {
                        let _ = cms;
                        pipeline = pipeline.add_inplace_stage(BlackChannelStage::new(i));
                    }
                }
            }
        }

        // For non-CMYK images (or CMYK that doesn't need deferred CMS), save reference after CT
        if frame_header.can_be_referenced
            && !frame_header.save_before_ct
            && !cmyk_needs_deferred_cms
        {
            for i in 0..num_channels {
                pipeline = pipeline.add_save_stage(
                    &[i],
                    Orientation::Identity,
                    num_api_buffers + i,
                    JxlColorType::Grayscale,
                    JxlDataFormat::f32(),
                    false,
                );
            }
        }

        if decoder_state.render_spotcolors {
            for (i, info) in decoder_state
                .file_header
                .image_metadata
                .extra_channel_info
                .iter()
                .enumerate()
            {
                if info.ec_type == ExtraChannel::SpotColor {
                    pipeline = pipeline
                        .add_inplace_stage(SpotColorStage::new(i, info.spot_color.unwrap()));
                }
            }
        }

        if frame_header.is_visible() {
            let color_space = decoder_state
                .file_header
                .image_metadata
                .color_encoding
                .color_space;
            let num_color_channels = if color_space == ColorSpace::Gray {
                1
            } else {
                3
            };
            // Find the alpha channel info (index and metadata) if the color type requires alpha
            let alpha_channel_info = if pixel_format.color_type.has_alpha() {
                decoder_state
                    .file_header
                    .image_metadata
                    .extra_channel_info
                    .iter()
                    .enumerate()
                    .find(|x| x.1.ec_type == ExtraChannel::Alpha)
            } else {
                None
            };
            let alpha_in_color = alpha_channel_info.map(|x| x.0 + 3);
            // Check if the source alpha is already premultiplied (alpha_associated)
            let source_alpha_associated =
                alpha_channel_info.is_some_and(|(_, info)| info.alpha_associated());
            if pixel_format.color_type.is_grayscale() && num_color_channels == 3 {
                return Err(Error::NotGrayscale);
            }
            // Determine if we need to fill opaque alpha:
            // - color_type requests alpha (has_alpha() is true)
            // - but no actual alpha channel exists in the image (alpha_in_color is None)
            let fill_opaque_alpha = pixel_format.color_type.has_alpha() && alpha_in_color.is_none();

            // Determine if we should premultiply:
            // - premultiply_output is requested
            // - there is an alpha channel in the output
            // - source is not already premultiplied (to avoid double-premultiplication)
            let should_premultiply = decoder_state.premultiply_output
                && alpha_in_color.is_some()
                && !source_alpha_associated;

            // Note: We don't unpremultiply by default because djxl also doesn't by default.
            // When source has alpha_associated=true (premultiplied), we output premultiplied
            // unless explicitly requested otherwise via premultiply_output=false + cms option.
            // This matches libjxl's JxlDecoderSetUnpremultiplyAlpha default of false.

            let color_source_channels: &[usize] =
                match (pixel_format.color_type.is_grayscale(), alpha_in_color) {
                    (true, None) => &[0],
                    (true, Some(c)) => &[0, c],
                    (false, None) => &[0, 1, 2],
                    (false, Some(c)) => &[0, 1, 2, c],
                };
            // `output_buffer_index` walks the PACKED position in the caller's
            // api buffer list — color first (if requested), then each
            // *requested* (`Some`) extra channel in order. This must match
            // `num_api_buffers` above and the packed buffer Vec built at decode
            // time. The previous absolute extra-channel index (`1 + i`) desynced
            // from the packed buffers whenever an extra channel was unrequested
            // (`None`, e.g. alpha folded into color) or color itself was absent,
            // indexing past the end of `buffers` — the spot-colour decode panic.
            let mut output_buffer_index = 0usize;
            if let Some(df) = &pixel_format.color_data_format {
                // Add premultiply stage if needed (before conversion to output format)
                if should_premultiply && let Some(alpha_channel) = alpha_in_color {
                    pipeline = pipeline.add_inplace_stage(PremultiplyAlphaStage::new(
                        0,
                        num_color_channels,
                        alpha_channel,
                    ));
                }
                // Add conversion stages for non-float output formats.
                // Full fusion: XYB+TF+U8 in one stage (XybToU8Stage)
                // Partial fusion: sRGB+U8 in one stage (FromLinearSrgbToU8Stage)
                // No fusion: separate stages
                if let Some((bit_depth, ref tf)) = fuse_xyb_u8 {
                    use crate::render::stages::ConvertF32ToU8Stage;
                    pipeline = pipeline.add_inout_stage(XybToU8Stage::new(
                        0,
                        output_color_info.clone(),
                        bit_depth,
                        tf.clone(),
                    ));
                    // Alpha channel still needs plain f32→u8 conversion (no TF/XYB)
                    for &channel in color_source_channels.iter().filter(|&&c| c >= 3) {
                        pipeline =
                            pipeline.add_inout_stage(ConvertF32ToU8Stage::new(channel, bit_depth));
                    }
                } else if let Some(bit_depth) = fuse_srgb_to_u8_bit_depth {
                    use crate::render::stages::{ConvertF32ToU8Stage, FromLinearSrgbToU8Stage};
                    pipeline = pipeline.add_inout_stage(FromLinearSrgbToU8Stage::new(0, bit_depth));
                    // Alpha channel still needs plain f32→u8 conversion (no TF)
                    for &channel in color_source_channels.iter().filter(|&&c| c >= 3) {
                        pipeline =
                            pipeline.add_inout_stage(ConvertF32ToU8Stage::new(channel, bit_depth));
                    }
                } else {
                    pipeline = Self::add_conversion_stages(
                        pipeline,
                        color_source_channels,
                        *df,
                        clamp_range_for_f16,
                    );
                }
                pipeline = pipeline.add_save_stage(
                    color_source_channels,
                    save_orientation,
                    output_buffer_index,
                    pixel_format.color_type,
                    *df,
                    fill_opaque_alpha,
                );
                output_buffer_index += 1;
            }
            for i in 0..frame_header.num_extra_channels as usize {
                if let Some(df) = &pixel_format.extra_channel_format[i] {
                    // Add conversion stages for non-float output formats
                    pipeline = Self::add_conversion_stages(pipeline, &[3 + i], *df, None);
                    pipeline = pipeline.add_save_stage(
                        &[3 + i],
                        save_orientation,
                        output_buffer_index,
                        JxlColorType::Grayscale,
                        *df,
                        false,
                    );
                    output_buffer_index += 1;
                }
            }
        }
        pipeline.build()
    }

    pub fn prepare_render_pipeline(
        &mut self,
        pixel_format: &JxlPixelFormat,
        cms: Option<&dyn JxlCms>,
        input_profile: &JxlColorProfile,
        output_profile: &JxlColorProfile,
    ) -> Result<()> {
        let lf_global = self.lf_global.as_ref().unwrap();
        let epf_sigma = if self.header.restoration_filter.epf_iters > 0 {
            Some(SigmaSource::new(&self.header, lf_global, &self.hf_meta)?)
        } else {
            None
        };

        #[cfg(test)]
        let render_pipeline = if self.use_simple_pipeline {
            Self::build_render_pipeline::<SimpleRenderPipeline>(
                &self.decoder_state,
                &self.header,
                lf_global,
                &epf_sigma,
                pixel_format,
                cms,
                input_profile,
                output_profile,
            )? as Box<dyn std::any::Any>
        } else {
            Self::build_render_pipeline::<LowMemoryRenderPipeline>(
                &self.decoder_state,
                &self.header,
                lf_global,
                &epf_sigma,
                pixel_format,
                cms,
                input_profile,
                output_profile,
            )? as Box<dyn std::any::Any>
        };
        #[cfg(not(test))]
        let render_pipeline = Self::build_render_pipeline::<LowMemoryRenderPipeline>(
            &self.decoder_state,
            &self.header,
            lf_global,
            &epf_sigma,
            pixel_format,
            cms,
            input_profile,
            output_profile,
        )?;
        self.render_pipeline = Some(render_pipeline);
        self.was_flushed_once = false;
        Ok(())
    }

    /// Run `prepare_render_pipeline` and `finalize_lf` together, overlapping
    /// the pipeline build with adaptive LF smoothing via `std::thread::scope`.
    ///
    /// Both operations access disjoint fields of `Frame`:
    /// - Pipeline: reads header/lf_global/hf_meta/decoder_state, writes render_pipeline
    /// - finalize_lf: reads header/lf_global, writes lf_image
    ///
    /// The pipeline build captures `cms: &dyn JxlCms` which is not `Sync`,
    /// so it must stay on the main thread. `finalize_lf` (which doesn't need
    /// `cms`) runs on a scoped OS thread.
    #[cfg(feature = "threads")]
    #[allow(dead_code)] // Parallel pipeline+LF preparation for threaded decode
    pub fn prepare_pipeline_and_finalize_lf(
        &mut self,
        pixel_format: &JxlPixelFormat,
        cms: Option<&dyn JxlCms>,
        input_profile: &JxlColorProfile,
        output_profile: &JxlColorProfile,
    ) -> Result<()> {
        self.prepare_render_pipeline(pixel_format, cms, input_profile, output_profile)?;
        self.finalize_lf()
    }
}
