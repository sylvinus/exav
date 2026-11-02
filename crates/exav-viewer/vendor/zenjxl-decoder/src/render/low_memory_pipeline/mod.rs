// Copyright (c) the JPEG XL Project Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#![allow(clippy::needless_range_loop)]

use std::any::Any;

use row_buffers::RowBuffer;

use crate::api::JxlOutputBuffer;
use crate::error::Result;
use crate::image::{DataTypeTag, Image, ImageDataType, OwnedRawImage, Rect};
use crate::render::MAX_BORDER;
use crate::render::buffer_splitter::{BufferSplitter, SaveStageBufferInfo};
use crate::render::internal::Stage;
use crate::render::low_memory_pipeline::group_scheduler::InputBuffer;
use crate::util::{ShiftRightCeil, tracing_wrappers::*};

use super::RenderPipeline;
use super::internal::{RenderPipelineShared, RunInOutStage, RunInPlaceStage};

pub(crate) mod group_scheduler;
mod helpers;
pub(crate) mod render_group;
pub(crate) mod row_buffers;
mod run_stage;
mod save;

/// Per-thread mutable state used during group rendering.
/// Extracting this from LowMemoryRenderPipeline enables parallel rendering
/// with multiple GroupRenderContexts sharing the same immutable pipeline data.
pub(crate) struct GroupRenderContext {
    pub(super) row_buffers: Vec<Vec<RowBuffer>>,
    pub(super) local_states: Vec<Option<Box<dyn Any + Send>>>,
}

/// Factory for creating `GroupRenderContext` from any thread.
/// Captures only `Sync` data (row buffer dimensions + stage definitions).
#[cfg(feature = "threads")]
pub(crate) struct ContextFactory<'a> {
    row_buffer_template: &'a [Vec<RowBuffer>],
    shared: &'a RenderPipelineShared<RowBuffer>,
}

#[cfg(feature = "threads")]
impl ContextFactory<'_> {
    pub(crate) fn create(&self, thread_index: usize) -> Result<GroupRenderContext> {
        let row_buffers = self
            .row_buffer_template
            .iter()
            .map(|stage_bufs| {
                stage_bufs
                    .iter()
                    .map(|buf| buf.new_like())
                    .collect::<Result<Vec<_>>>()
            })
            .collect::<Result<Vec<_>>>()?;

        let local_states = self
            .shared
            .stages
            .iter()
            .map(|x| x.init_local_state(thread_index))
            .collect::<Result<Vec<_>>>()?;

        Ok(GroupRenderContext {
            row_buffers,
            local_states,
        })
    }
}

/// Immutable view of pipeline data needed during rendering.
/// Bundles all read-only references so render functions can operate
/// without borrowing the entire pipeline.
pub(crate) struct PipelineReadView<'a> {
    pub(super) shared: &'a RenderPipelineShared<RowBuffer>,
    pub(in crate::render::low_memory_pipeline) input_buffers: &'a [InputBuffer],
    pub(super) stage_input_buffer_index: &'a [Vec<(usize, usize)>],
    pub(super) downsampling_for_stage: &'a [(usize, usize)],
    pub(super) stage_output_border_pixels: &'a [(usize, usize)],
    pub(super) input_border_pixels: &'a [(usize, usize)],
    pub(super) border_size: (usize, usize),
    pub(super) opaque_alpha_buffers: &'a [Option<RowBuffer>],
    pub(super) sorted_buffer_indices: &'a [Vec<(usize, usize, usize)>],
}

pub struct LowMemoryRenderPipeline {
    shared: RenderPipelineShared<RowBuffer>,
    input_buffers: Vec<InputBuffer>,
    render_ctx: GroupRenderContext,
    save_buffer_info: Vec<Option<SaveStageBufferInfo>>,
    // The input buffer that each channel of each stage should use.
    // This is indexed both by stage index (0 corresponds to input data, 1 to stage[0], etc) and by
    // index *of those channels that are used*.
    stage_input_buffer_index: Vec<Vec<(usize, usize)>>,
    // Tracks whether we already rendered the padding around the core frame (if any).
    padding_was_rendered: bool,
    // The amount of pixels that each stage needs to *output* around the current group to
    // run future stages correctly.
    stage_output_border_pixels: Vec<(usize, usize)>,
    // The amount of pixels that we need to read (for every channel) in non-edge groups to run all
    // stages correctly.
    input_border_pixels: Vec<(usize, usize)>,
    // Size of the border, in image (i.e. non-downsampled) pixels.
    border_size: (usize, usize),
    // For every stage, the downsampling level of *any* channel that the stage uses at that point.
    // Note that this must be equal across all the used channels.
    downsampling_for_stage: Vec<(usize, usize)>,
    // Pre-filled opaque alpha buffers for stages that need fill_opaque_alpha.
    // Indexed by stage index; None if stage doesn't need alpha fill.
    opaque_alpha_buffers: Vec<Option<RowBuffer>>,
    // Sorted indices to call get_distinct_indices.
    sorted_buffer_indices: Vec<Vec<(usize, usize, usize)>>,
    // For each channel and the 3 kinds of buffers (center / topbottom / leftright), buffers that
    // could be reused to store group data for that channel.
    // Indexed by [3*channel] = center, [3*channel+1] = topbottom, [3*channel+2] = leftright.
    scratch_channel_buffers: Vec<Vec<OwnedRawImage>>,
    // When true, render_with_new_group skips border recycling (only recycles center data).
    // Used during the final re-render pass to keep all groups' is_ready=true so that
    // sequential processing produces the same readiness masks as the parallel path.
    skip_border_recycling: bool,
    // When true, set_buffer_for_group stores data but skips rendering.
    // Used during the final re-render to fill all groups before the two-pass render.
    store_only: bool,
}

impl RenderPipeline for LowMemoryRenderPipeline {
    type Buffer = RowBuffer;

    fn new_from_shared(shared: RenderPipelineShared<Self::Buffer>) -> Result<Self> {
        let mut input_buffers = vec![];
        let nc = shared.num_channels();
        for _ in 0..shared.group_chan_complete.len() {
            input_buffers.push(InputBuffer::new(nc));
        }
        let mut previous_inout: Vec<_> = (0..nc).map(|x| (0usize, x)).collect();
        let mut stage_input_buffer_index = vec![];
        let mut next_border_and_cur_downsample = vec![vec![]];

        for ci in shared.channel_info[0].iter() {
            next_border_and_cur_downsample[0].push((0, ci.downsample));
        }

        // For each stage, compute in which stage its input was buffered (the previous InOut
        // stage). Also, compute for each InOut stage and channel the border with which the stage
        // output is used; this will used to allocate buffers of the correct size.
        for (i, stage) in shared.stages.iter().enumerate() {
            stage_input_buffer_index.push(previous_inout.clone());
            next_border_and_cur_downsample.push(vec![]);
            if let Stage::InOut(p) = stage {
                for (chan, (ps, pc)) in previous_inout.iter_mut().enumerate() {
                    if !p.uses_channel(chan) {
                        continue;
                    }
                    next_border_and_cur_downsample[*ps][*pc].0 = p.border().1;
                    *ps = i + 1;
                    *pc = next_border_and_cur_downsample[i + 1].len();
                    next_border_and_cur_downsample[i + 1]
                        .push((0, shared.channel_info[i + 1][chan].downsample));
                }
            }
        }

        let mut initial_buffers = vec![];
        for chan in 0..nc {
            initial_buffers.push(RowBuffer::new(
                shared.channel_info[0][chan].ty.unwrap_or(DataTypeTag::U8),
                next_border_and_cur_downsample[0][chan].0 as usize,
                0,
                0,
                shared.chunk_size >> shared.channel_info[0][chan].downsample.0,
            )?);
        }
        let mut row_buffers = vec![initial_buffers];

        // Allocate buffers.
        for (i, stage) in shared.stages.iter().enumerate() {
            let mut stage_buffers = vec![];
            for (next_y_border, (dsx, _)) in next_border_and_cur_downsample[i + 1].iter() {
                stage_buffers.push(RowBuffer::new(
                    stage.output_type().unwrap(),
                    *next_y_border as usize,
                    stage.shift().1 as usize,
                    stage.shift().0 as usize,
                    shared.chunk_size >> *dsx,
                )?);
            }
            row_buffers.push(stage_buffers);
        }
        // Compute information to be used to compute sub-rects for "save" stages to operate on
        // rects.
        let mut save_buffer_info = vec![];
        'stage: for (i, (s, ci)) in shared
            .stages
            .iter()
            .zip(shared.channel_info.iter())
            .enumerate()
        {
            let Stage::Save(s) = s else {
                continue;
            };
            for (c, ci) in ci.iter().enumerate() {
                if s.uses_channel(c) {
                    let info = SaveStageBufferInfo {
                        downsample: ci.downsample,
                        orientation: s.orientation,
                        byte_size: s.data_format.bytes_per_sample() * s.output_channels(),
                        after_extend: shared.extend_stage_index.is_some_and(|e| i > e),
                    };
                    while save_buffer_info.len() <= s.output_buffer_index {
                        save_buffer_info.push(None);
                    }
                    save_buffer_info[s.output_buffer_index] = Some(info);
                    continue 'stage;
                }
            }
        }

        // Compute the amount of border pixels needed per channel, per stage.
        let mut border_pixels = vec![(0usize, 0usize); nc];
        let mut border_pixels_per_stage = vec![];
        for s in shared.stages.iter().rev() {
            let mut stage_max = (0, 0);
            for (c, bp) in border_pixels.iter_mut().enumerate() {
                if !s.uses_channel(c) {
                    continue;
                }
                stage_max.0 = stage_max.0.max(bp.0);
                stage_max.1 = stage_max.1.max(bp.1);

                bp.0 = bp.0.shrc(s.shift().0) + s.border().0 as usize;
                bp.1 = bp.1.shrc(s.shift().1) + s.border().1 as usize;
            }
            border_pixels_per_stage.push(stage_max);
        }
        border_pixels_per_stage.reverse();

        assert!(border_pixels_per_stage[0].0 <= MAX_BORDER);

        let downsampling_for_stage: Vec<_> = shared
            .stages
            .iter()
            .zip(shared.channel_info.iter())
            .map(|(s, ci)| {
                let dowsamplings: Vec<_> = (0..nc)
                    .filter_map(|c| {
                        if s.uses_channel(c) {
                            Some(ci[c].downsample)
                        } else {
                            None
                        }
                    })
                    .collect();
                for &d in dowsamplings.iter() {
                    assert_eq!(d, dowsamplings[0]);
                }
                (dowsamplings[0].0 as usize, dowsamplings[0].1 as usize)
            })
            .collect();

        // Create opaque alpha buffers for save stages that need fill_opaque_alpha
        let mut opaque_alpha_buffers = vec![];
        for (i, stage) in shared.stages.iter().enumerate() {
            if let Stage::Save(s) = stage {
                if s.fill_opaque_alpha {
                    let (dx, _dy) = downsampling_for_stage[i];
                    let row_len = shared.chunk_size >> dx;
                    let fill_pattern = s.data_format.opaque_alpha_bytes();
                    let buf =
                        RowBuffer::new_filled(s.data_format.data_type(), row_len, &fill_pattern)?;
                    opaque_alpha_buffers.push(Some(buf));
                } else {
                    opaque_alpha_buffers.push(None);
                }
            } else {
                opaque_alpha_buffers.push(None);
            }
        }

        let default_channels: Vec<usize> = (0..nc).collect();
        for (s, ibi) in stage_input_buffer_index.iter_mut().enumerate() {
            let mut filtered = vec![];
            // For SaveStage, use s.channels to get correct output ordering (e.g., BGRA).
            let channels = if let Stage::Save(save_stage) = &shared.stages[s] {
                save_stage.channels.as_slice()
            } else {
                default_channels.as_slice()
            };
            for &c in channels {
                if shared.stages[s].uses_channel(c) {
                    filtered.push(ibi[c]);
                }
            }
            *ibi = filtered;
        }

        let sorted_buffer_indices = (0..shared.stages.len())
            .map(|s| {
                let mut v: Vec<_> = stage_input_buffer_index[s]
                    .iter()
                    .enumerate()
                    .map(|(i, (outer, inner))| (*outer, *inner, i))
                    .collect();
                v.sort();
                v
            })
            .collect();

        let mut border_size = (0, 0);
        for c in 0..nc {
            border_size.0 = border_size
                .0
                .max(border_pixels[c].0 << shared.channel_info[0][c].downsample.0);
            border_size.1 = border_size
                .1
                .max(border_pixels[c].1 << shared.channel_info[0][c].downsample.1);
        }
        for s in 0..shared.stages.len() {
            border_size.0 = border_size
                .0
                .max(border_pixels_per_stage[s].0 << downsampling_for_stage[s].0);
            border_size.1 = border_size
                .1
                .max(border_pixels_per_stage[s].1 << downsampling_for_stage[s].1);
        }

        let local_states: Vec<_> = shared
            .stages
            .iter()
            .map(|x| x.init_local_state(0)) // Thread index 0 for single-threaded execution
            .collect::<Result<_>>()?;

        Ok(Self {
            input_buffers,
            stage_input_buffer_index,
            render_ctx: GroupRenderContext {
                row_buffers,
                local_states,
            },
            padding_was_rendered: false,
            save_buffer_info,
            stage_output_border_pixels: border_pixels_per_stage,
            border_size,
            input_border_pixels: border_pixels,
            shared,
            downsampling_for_stage,
            opaque_alpha_buffers,
            sorted_buffer_indices,
            scratch_channel_buffers: (0..nc * 3).map(|_| vec![]).collect(),
            skip_border_recycling: false,
            store_only: false,
        })
    }

    #[instrument(skip_all, err)]
    fn get_buffer<T: ImageDataType>(&mut self, channel: usize) -> Result<Image<T>> {
        if let Some(b) = self.maybe_get_scratch_buffer(channel, 0) {
            return Ok(Image::from_raw(b));
        }
        let sz = self.shared.group_size_for_channel(channel, T::DATA_TYPE_ID);
        Image::<T>::new_uninit(sz)
    }

    fn set_buffer_for_group<T: ImageDataType>(
        &mut self,
        channel: usize,
        group_id: usize,
        complete: bool,
        buf: Image<T>,
        buffer_splitter: &mut BufferSplitter,
    ) -> Result<()> {
        if self.shared.channel_is_used[channel] {
            // Cascading transforms (squeeze, palette) may re-produce output
            // for a channel/group already stored but not yet rendered (waiting
            // for other channels). Skip the duplicate — the first buffer is
            // valid and ready_channels is already incremented.
            if self.input_buffers[group_id].has_buffer(channel) {
                return Ok(());
            }
            debug!(
                "filling data for group {}, channel {}, using type {:?}",
                group_id,
                channel,
                T::DATA_TYPE_ID,
            );
            self.input_buffers[group_id].set_buffer(channel, buf.into_raw());
            self.shared.group_chan_complete[group_id][channel] = complete;

            if !self.store_only {
                self.render_with_new_group(group_id, buffer_splitter)?;
            }
        }
        Ok(())
    }

    fn check_buffer_sizes(&self, buffers: &mut [Option<JxlOutputBuffer>]) -> Result<()> {
        // Check that buffer sizes are correct.
        let mut size = self.shared.input_size;
        for (i, s) in self.shared.stages.iter().enumerate() {
            match s {
                Stage::Extend(e) => size = e.image_size,
                Stage::Save(s) => {
                    let (dx, dy) = self.downsampling_for_stage[i];
                    s.check_buffer_size(
                        (size.0 >> dx, size.1 >> dy),
                        buffers[s.output_buffer_index].as_ref(),
                    )?
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn render_outside_frame(&mut self, buffer_splitter: &mut BufferSplitter) -> Result<()> {
        if self.shared.extend_stage_index.is_none() || self.padding_was_rendered {
            return Ok(());
        }
        self.padding_was_rendered = true;
        // TODO(veluca): consider pre-computing those strips at pipeline construction and making
        // smaller strips.
        let e = self.shared.extend_stage_index.unwrap();
        let Stage::Extend(e) = &self.shared.stages[e] else {
            unreachable!("extend stage is not an extend stage");
        };
        let frame_end = (
            e.frame_origin.0 + self.shared.input_size.0 as isize,
            e.frame_origin.1 + self.shared.input_size.1 as isize,
        );
        // Split the full image area in 4 strips: left and right of the frame, and above and below.
        // We divide each part further in strips of width self.shared.chunk_size.
        let mut strips = vec![];
        // Above (including left and right)
        if e.frame_origin.1 > 0 {
            let xend = e.image_size.0;
            let yend = (e.frame_origin.1 as usize).min(e.image_size.1);
            for x in (0..xend).step_by(self.shared.chunk_size) {
                let xe = (x + self.shared.chunk_size).min(xend);
                strips.push((x..xe, 0..yend));
            }
        }
        // Below
        if frame_end.1 < e.image_size.1 as isize {
            let ystart = frame_end.1.max(0) as usize;
            let yend = e.image_size.1;
            let xend = e.image_size.0;
            for x in (0..xend).step_by(self.shared.chunk_size) {
                let xe = (x + self.shared.chunk_size).min(xend);
                strips.push((x..xe, ystart..yend));
            }
        }
        // Left
        if e.frame_origin.0 > 0 {
            let ystart = e.frame_origin.1.max(0) as usize;
            let yend = (frame_end.1 as usize).min(e.image_size.1);
            let xend = (e.frame_origin.0 as usize).min(e.image_size.0);
            for x in (0..xend).step_by(self.shared.chunk_size) {
                let xe = (x + self.shared.chunk_size).min(xend);
                strips.push((x..xe, ystart..yend));
            }
        }
        // Right
        if frame_end.0 < e.image_size.0 as isize {
            let xstart = frame_end.0.max(0) as usize;
            let xend = e.image_size.0;
            let ystart = e.frame_origin.1.max(0) as usize;
            let yend = (frame_end.1 as usize).min(e.image_size.1);
            for x in (xstart..xend).step_by(self.shared.chunk_size) {
                let xe = (x + self.shared.chunk_size).min(xend);
                strips.push((x..xe, ystart..yend));
            }
        }
        let full_image_size = e.image_size;
        for (xrange, yrange) in strips {
            let rect_to_render = Rect {
                origin: (xrange.start, yrange.start),
                size: (xrange.clone().count(), yrange.clone().count()),
            };
            if rect_to_render.size.0 == 0 || rect_to_render.size.1 == 0 {
                continue;
            }
            let mut local_buffers = buffer_splitter.get_local_buffers(
                &self.save_buffer_info,
                rect_to_render,
                true,
                full_image_size,
                full_image_size,
                (0, 0),
            );
            let view = PipelineReadView {
                shared: &self.shared,
                input_buffers: &self.input_buffers,
                stage_input_buffer_index: &self.stage_input_buffer_index,
                downsampling_for_stage: &self.downsampling_for_stage,
                stage_output_border_pixels: &self.stage_output_border_pixels,
                input_border_pixels: &self.input_border_pixels,
                border_size: self.border_size,
                opaque_alpha_buffers: &self.opaque_alpha_buffers,
                sorted_buffer_indices: &self.sorted_buffer_indices,
            };
            render_group::render_outside(
                &mut self.render_ctx,
                &view,
                xrange,
                yrange,
                &mut local_buffers,
            )?;
        }
        Ok(())
    }

    fn mark_group_to_rerender(&mut self, g: usize) {
        self.input_buffers[g].is_ready = false;
    }

    fn box_inout_stage<S: super::RenderPipelineInOutStage + Send + Sync>(
        stage: S,
    ) -> Box<dyn RunInOutStage<Self::Buffer> + Send + Sync> {
        Box::new(stage)
    }

    fn box_inplace_stage<S: super::RenderPipelineInPlaceStage + Send + Sync>(
        stage: S,
    ) -> Box<dyn RunInPlaceStage<Self::Buffer> + Send + Sync> {
        Box::new(stage)
    }

    fn used_channel_mask(&self) -> &[bool] {
        &self.shared.channel_is_used
    }

    fn needs_border_rendering(&self) -> bool {
        self.border_size != (0, 0)
    }

    fn prepare_final_rerender(&mut self) {
        let num_groups = self.input_buffers.len();
        for g in 0..num_groups {
            self.input_buffers[g].is_ready = false;
            self.input_buffers[g].num_completed_groups_3x3 = 0;
            self.input_buffers[g].ready_channels = 0;
            // Recycle all existing buffers so fresh data is stored.
            for c in 0..self.input_buffers[g].data.len() {
                if let Some(b) = std::mem::take(&mut self.input_buffers[g].data[c]) {
                    self.store_scratch_buffer(c, 0, b);
                }
                if let Some(b) = std::mem::take(&mut self.input_buffers[g].topbottom[c]) {
                    self.store_scratch_buffer(c, 1, b);
                }
                if let Some(b) = std::mem::take(&mut self.input_buffers[g].leftright[c]) {
                    self.store_scratch_buffer(c, 2, b);
                }
            }
        }
        // Store-only mode: set_buffer_for_group stores data without rendering.
        self.store_only = true;
        self.skip_border_recycling = true;
    }

    fn render_all_groups_full_readiness(
        &mut self,
        buffer_splitter: &mut BufferSplitter,
    ) -> Result<()> {
        let num_groups = self.shared.group_count.0 * self.shared.group_count.1;

        // Pass 1: Extract borders for ALL groups, setting is_ready=true.
        // This mirrors the parallel path's extract_borders phase — all groups
        // become ready before any readiness masks are computed.
        for g in 0..num_groups {
            let _ = self.prepare_group(g)?;
            // Work items are discarded — they reflect partial readiness since
            // later groups aren't ready yet. We recompute with full readiness
            // in Pass 2.
        }

        // Pass 2: All groups now have is_ready=true and borders extracted.
        // Compute work items with full readiness masks and render.
        let is_ready: Vec<bool> = self.input_buffers.iter().map(|b| b.is_ready).collect();
        for g in 0..num_groups {
            let items = group_scheduler::compute_work_items(
                g,
                &is_ready,
                &self.shared,
                self.border_size,
                true,
            )?;
            if items.is_empty() {
                continue;
            }

            let (origin, size) = if let Some(e) = self.shared.extend_stage_index {
                let Stage::Extend(e) = &self.shared.stages[e] else {
                    unreachable!("extend stage is not an extend stage");
                };
                (e.frame_origin, e.image_size)
            } else {
                ((0, 0), self.shared.input_size)
            };

            {
                let view = PipelineReadView {
                    shared: &self.shared,
                    input_buffers: &self.input_buffers,
                    stage_input_buffer_index: &self.stage_input_buffer_index,
                    downsampling_for_stage: &self.downsampling_for_stage,
                    stage_output_border_pixels: &self.stage_output_border_pixels,
                    input_border_pixels: &self.input_border_pixels,
                    border_size: self.border_size,
                    opaque_alpha_buffers: &self.opaque_alpha_buffers,
                    sorted_buffer_indices: &self.sorted_buffer_indices,
                };
                let ctx = &mut self.render_ctx;
                let save_buffer_info = &self.save_buffer_info;

                for item in &items {
                    let mut local_buffers = buffer_splitter.get_local_buffers(
                        save_buffer_info,
                        item.image_area,
                        false,
                        view.shared.input_size,
                        size,
                        origin,
                    );
                    render_group::render(
                        ctx,
                        &view,
                        (item.gx, item.gy),
                        item.image_area,
                        &mut local_buffers,
                    )?;
                }
            }

            self.recycle_group_buffers(g, false);
        }

        Ok(())
    }

    fn finish_final_rerender(&mut self) {
        self.store_only = false;
        self.skip_border_recycling = false;
        self.recycle_all_borders();
    }
}

/// Methods for the parallel rendering path.
#[cfg(feature = "threads")]
impl LowMemoryRenderPipeline {
    /// Returns the pixel buffer size for a channel (used for parallel allocation).
    pub(crate) fn pixel_buffer_size(&self, channel: usize) -> (usize, usize) {
        self.shared
            .group_size_for_channel(channel, crate::image::DataTypeTag::F32)
    }

    /// Returns true if a buffer has already been stored for this channel/group.
    pub(crate) fn has_buffer(&self, channel: usize, group_id: usize) -> bool {
        self.input_buffers[group_id].has_buffer(channel)
    }

    /// Stores a buffer for a group/channel without triggering rendering.
    pub(crate) fn store_buffer_only<T: ImageDataType>(
        &mut self,
        channel: usize,
        group_id: usize,
        complete: bool,
        buf: Image<T>,
    ) {
        self.input_buffers[group_id].set_buffer(channel, buf.into_raw());
        self.shared.group_chan_complete[group_id][channel] = complete;
    }

    /// Creates a PipelineReadView borrowing the immutable state.
    pub(crate) fn read_view(&self) -> PipelineReadView<'_> {
        PipelineReadView {
            shared: &self.shared,
            input_buffers: &self.input_buffers,
            stage_input_buffer_index: &self.stage_input_buffer_index,
            downsampling_for_stage: &self.downsampling_for_stage,
            stage_output_border_pixels: &self.stage_output_border_pixels,
            input_border_pixels: &self.input_border_pixels,
            border_size: self.border_size,
            opaque_alpha_buffers: &self.opaque_alpha_buffers,
            sorted_buffer_indices: &self.sorted_buffer_indices,
        }
    }

    /// Returns the frame origin and full image size from the extend stage,
    /// or defaults for non-extend pipelines.
    pub(crate) fn extend_origin_size(&self) -> ((isize, isize), (usize, usize)) {
        if let Some(e) = self.shared.extend_stage_index {
            let Stage::Extend(e) = &self.shared.stages[e] else {
                unreachable!("extend stage is not an extend stage");
            };
            (e.frame_origin, e.image_size)
        } else {
            ((0, 0), self.shared.input_size)
        }
    }

    /// Returns a factory that can create GroupRenderContexts from any thread.
    /// The returned factory is Send + Sync (captures only Sync data).
    pub(crate) fn context_factory(&self) -> ContextFactory<'_> {
        ContextFactory {
            row_buffer_template: &self.render_ctx.row_buffers,
            shared: &self.shared,
        }
    }

    /// Returns the save buffer info for computing output sub-views.
    pub(crate) fn save_buffer_info(&self) -> &[Option<SaveStageBufferInfo>] {
        &self.save_buffer_info
    }

    /// Returns the input (frame) size.
    pub(crate) fn input_size(&self) -> (usize, usize) {
        self.shared.input_size
    }

    /// Prepares all groups that have all channels ready, in parallel.
    ///
    /// Phase 1 (parallel): Extracts border data for each ready group.
    ///   Border extraction is per-group with no cross-group reads, so it
    ///   can safely run in parallel. Skips the scratch buffer pool (allocates
    ///   fresh if needed) for thread safety. Does NOT set is_ready.
    ///
    /// Phase 2 (serial): Sets is_ready and emits work items, in group index order.
    ///   The is_ready flag is set here so that the 3×3 readiness mask reflects
    ///   serial ordering, preserving the non-overlapping work-item guarantee.
    ///
    /// Returns the collected work items and a list of `(group_id, has_items)` pairs
    /// for the caller to build render-info.
    #[allow(clippy::type_complexity)]
    pub(crate) fn prepare_groups_parallel(
        &mut self,
        skip_border_copy: bool,
    ) -> Result<(Vec<group_scheduler::RenderWorkItem>, Vec<(usize, bool)>)> {
        use group_scheduler::extract_borders;

        let shared = &self.shared;
        let border_size = self.border_size;

        if skip_border_copy {
            // Fast path: no border data to copy. Just check ready_channels
            // and mark is_ready sequentially — each check is ~10ns, so rayon
            // dispatch overhead would dominate for hundreds of groups.
            let num_used = shared.num_used_channels();
            let mut extracted_groups = Vec::with_capacity(self.input_buffers.len());
            for (g, buf) in self.input_buffers.iter_mut().enumerate() {
                if buf.ready_channels == num_used {
                    buf.ready_channels = 0;
                    buf.is_ready = true;
                    extracted_groups.push(g);
                }
            }
            let bs = self.border_size;
            let mut items = Vec::with_capacity(extracted_groups.len());
            let mut group_has_items = Vec::with_capacity(extracted_groups.len());
            // Full readiness is common in one-shot mode.
            let full_readiness = self.input_buffers.iter().all(|b| b.is_ready);
            if full_readiness {
                for &g in &extracted_groups {
                    let empty_ready = []; // unused with full_readiness=true
                    let group_items =
                        group_scheduler::compute_work_items(g, &empty_ready, shared, bs, true)?;
                    let has = !group_items.is_empty();
                    items.extend(group_items);
                    group_has_items.push((g, has));
                }
            } else {
                let is_ready: Vec<bool> = self.input_buffers.iter().map(|b| b.is_ready).collect();
                for &g in &extracted_groups {
                    let group_items =
                        group_scheduler::compute_work_items(g, &is_ready, shared, bs, false)?;
                    let has = !group_items.is_empty();
                    items.extend(group_items);
                    group_has_items.push((g, has));
                }
            }
            return Ok((items, group_has_items));
        }

        // Slow path: actual border extraction requires per-group mutable access
        // to copy pixel data into topbottom/leftright buffers. Parallelize with rayon.
        use rayon::prelude::*;

        let extracted: Vec<bool> = self
            .input_buffers
            .par_iter_mut()
            .map(|buf| extract_borders(buf, shared, border_size, false))
            .collect::<Result<Vec<_>>>()?;

        for (g, did_extract) in extracted.iter().enumerate() {
            if *did_extract {
                self.input_buffers[g].is_ready = true;
            }
        }
        let is_ready: Vec<bool> = self.input_buffers.iter().map(|b| b.is_ready).collect();
        let full_readiness = is_ready.iter().all(|&r| r);
        let extracted_groups: Vec<usize> = extracted
            .iter()
            .enumerate()
            .filter_map(|(g, &did)| if did { Some(g) } else { None })
            .collect();
        let shared = &self.shared;
        let bs = self.border_size;
        let mut items = Vec::with_capacity(extracted_groups.len());
        let mut group_has_items = Vec::with_capacity(extracted_groups.len());
        if full_readiness {
            for &g in &extracted_groups {
                let group_items =
                    group_scheduler::compute_work_items(g, &is_ready, shared, bs, true)?;
                let has = !group_items.is_empty();
                items.extend(group_items);
                group_has_items.push((g, has));
            }
        } else {
            let results: Vec<(usize, Vec<group_scheduler::RenderWorkItem>)> = extracted_groups
                .par_iter()
                .map(|&g| {
                    let items =
                        group_scheduler::compute_work_items(g, &is_ready, shared, bs, false)?;
                    Ok((g, items))
                })
                .collect::<Result<Vec<_>>>()?;
            for (g, group_items) in results {
                let has = !group_items.is_empty();
                items.extend(group_items);
                group_has_items.push((g, has));
            }
        }
        Ok((items, group_has_items))
    }

    /// Returns the total number of groups in the pipeline.
    pub(crate) fn num_groups(&self) -> usize {
        self.input_buffers.len()
    }

    /// Stores pending pixel data and prepares groups in a single pass.
    ///
    /// `pending_stores` is indexed by group_id. Each entry is `Some((pixels, complete))`
    /// for groups that have VarDCT pixel data to store from Phase 2, or `None` for groups
    /// that were stored in the sequential Phase 3a-store (LF upsample, noise, modular).
    ///
    /// When `skip_border_copy` is true, runs sequentially (pixel store is just pointer
    /// moves, no data copy). Otherwise parallelizes pixel store + border extraction.
    #[allow(clippy::type_complexity)]
    pub(crate) fn store_and_prepare_groups_parallel(
        &mut self,
        pending_stores: &mut [Option<([OwnedRawImage; 3], bool)>],
        skip_border_copy: bool,
    ) -> Result<(Vec<group_scheduler::RenderWorkItem>, Vec<(usize, bool)>)> {
        // Set group_chan_complete for pending stores.
        for (g, store) in pending_stores.iter().enumerate() {
            if let Some((_, complete)) = store {
                for c in 0..self.shared.group_chan_complete[g].len() {
                    self.shared.group_chan_complete[g][c] = *complete;
                }
            }
        }

        let shared = &self.shared;
        let border_size = self.border_size;

        if skip_border_copy {
            // Fast path: store pixels + check readiness sequentially.
            // Pixel store is just moving OwnedRawImage pointers (~100 bytes each).
            // Border check is comparing ready_channels to num_used_channels().
            let num_used = shared.num_used_channels();
            let mut extracted_groups = Vec::with_capacity(self.input_buffers.len());
            for (g, (buf, store)) in self
                .input_buffers
                .iter_mut()
                .zip(pending_stores.iter_mut())
                .enumerate()
            {
                if let Some((pixels, _complete)) = store.take() {
                    for (c, img) in pixels.into_iter().enumerate() {
                        buf.set_buffer(c, img);
                    }
                }
                if buf.ready_channels == num_used {
                    buf.ready_channels = 0;
                    buf.is_ready = true;
                    extracted_groups.push(g);
                }
            }
            let bs = self.border_size;
            let mut items = Vec::with_capacity(extracted_groups.len());
            let mut group_has_items = Vec::with_capacity(extracted_groups.len());
            let full_readiness = self.input_buffers.iter().all(|b| b.is_ready);
            if full_readiness {
                for &g in &extracted_groups {
                    let empty_ready = [];
                    let group_items =
                        group_scheduler::compute_work_items(g, &empty_ready, shared, bs, true)?;
                    let has = !group_items.is_empty();
                    items.extend(group_items);
                    group_has_items.push((g, has));
                }
            } else {
                let is_ready: Vec<bool> = self.input_buffers.iter().map(|b| b.is_ready).collect();
                for &g in &extracted_groups {
                    let group_items =
                        group_scheduler::compute_work_items(g, &is_ready, shared, bs, false)?;
                    let has = !group_items.is_empty();
                    items.extend(group_items);
                    group_has_items.push((g, has));
                }
            }
            return Ok((items, group_has_items));
        }

        // Slow path: actual border extraction needs parallel mutable access.
        use group_scheduler::extract_borders;
        use rayon::prelude::*;

        let extracted: Vec<bool> = self
            .input_buffers
            .par_iter_mut()
            .zip(pending_stores.par_iter_mut())
            .map(|(buf, store)| {
                if let Some((pixels, _complete)) = store.take() {
                    for (c, img) in pixels.into_iter().enumerate() {
                        buf.set_buffer(c, img);
                    }
                }
                extract_borders(buf, shared, border_size, false)
            })
            .collect::<Result<Vec<_>>>()?;

        for (g, did_extract) in extracted.iter().enumerate() {
            if *did_extract {
                self.input_buffers[g].is_ready = true;
            }
        }
        let is_ready: Vec<bool> = self.input_buffers.iter().map(|b| b.is_ready).collect();
        let full_readiness = is_ready.iter().all(|&r| r);
        let extracted_groups: Vec<usize> = extracted
            .iter()
            .enumerate()
            .filter_map(|(g, &did)| if did { Some(g) } else { None })
            .collect();
        let shared = &self.shared;
        let bs = self.border_size;
        let mut items = Vec::with_capacity(extracted_groups.len());
        let mut group_has_items = Vec::with_capacity(extracted_groups.len());
        if full_readiness {
            for &g in &extracted_groups {
                let group_items =
                    group_scheduler::compute_work_items(g, &is_ready, shared, bs, true)?;
                let has = !group_items.is_empty();
                items.extend(group_items);
                group_has_items.push((g, has));
            }
        } else {
            let results: Vec<(usize, Vec<group_scheduler::RenderWorkItem>)> = extracted_groups
                .par_iter()
                .map(|&g| {
                    let items =
                        group_scheduler::compute_work_items(g, &is_ready, shared, bs, false)?;
                    Ok((g, items))
                })
                .collect::<Result<Vec<_>>>()?;
            for (g, group_items) in results {
                let has = !group_items.is_empty();
                items.extend(group_items);
                group_has_items.push((g, has));
            }
        }
        Ok((items, group_has_items))
    }
}
