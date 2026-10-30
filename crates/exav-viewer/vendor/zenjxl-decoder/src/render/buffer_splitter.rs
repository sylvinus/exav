// Copyright (c) the JPEG XL Project Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use crate::{api::JxlOutputBuffer, headers::Orientation, image::Rect, util::ShiftRightCeil};

// Information for splitting the output buffers.
#[derive(Debug)]
pub struct SaveStageBufferInfo {
    pub downsample: (u8, u8),
    pub orientation: Orientation,
    pub byte_size: usize,
    pub after_extend: bool,
}

/// Data structure responsible for handing out access to portions of the output buffers.
pub struct BufferSplitter<'a, 'b> {
    buffers: &'a mut [Option<JxlOutputBuffer<'b>>],
    requested_rects: Vec<Rect>,
}

impl<'a, 'b> BufferSplitter<'a, 'b> {
    pub fn new(bufs: &'a mut [Option<JxlOutputBuffer<'b>>]) -> Self {
        Self {
            buffers: bufs,
            requested_rects: vec![],
        }
    }

    pub(crate) fn get_local_buffers(
        &mut self,
        save_buffer_info: &[Option<SaveStageBufferInfo>],
        rect: Rect,
        outside_current_frame: bool,
        frame_size: (usize, usize),
        full_image_size: (usize, usize),
        frame_origin: (isize, isize),
    ) -> Vec<Option<JxlOutputBuffer<'_>>> {
        self.requested_rects.push(rect);
        let mut local_buffers = vec![];
        let buffers = &mut *self.buffers;
        local_buffers.reserve(buffers.len());
        for _ in 0..buffers.len() {
            local_buffers.push(None::<JxlOutputBuffer>);
        }
        let rect = if !outside_current_frame {
            rect.clip(frame_size)
        } else {
            rect
        };
        for (i, (info, buf)) in save_buffer_info.iter().zip(buffers.iter_mut()).enumerate() {
            let Some(bi) = info else {
                // We never write to this buffer.
                continue;
            };
            let Some(buf) = buf.as_mut() else {
                // The buffer to write into was not provided.
                continue;
            };
            if outside_current_frame && !bi.after_extend {
                // Before-extend stages do not write to rects outside the current frame.
                continue;
            }
            let mut channel_rect = rect.downsample(bi.downsample);
            if !outside_current_frame {
                let frame_size = (
                    frame_size.0.shrc(bi.downsample.0),
                    frame_size.1.shrc(bi.downsample.1),
                );
                channel_rect = channel_rect.clip(frame_size);
                if bi.after_extend {
                    // clip this rect to its visible area in the full image (in full image coordinates).
                    let origin = (
                        rect.origin.0 as isize + frame_origin.0,
                        rect.origin.1 as isize + frame_origin.1,
                    );
                    let end = (
                        origin.0 + rect.size.0 as isize,
                        origin.1 + rect.size.1 as isize,
                    );
                    let origin = (origin.0.max(0) as usize, origin.1.max(0) as usize);
                    let end = (
                        end.0.min(full_image_size.0 as isize).max(0) as usize,
                        end.1.min(full_image_size.1 as isize).max(0) as usize,
                    );
                    channel_rect = Rect {
                        origin,
                        size: (
                            end.0.saturating_sub(origin.0),
                            end.1.saturating_sub(origin.1),
                        ),
                    };
                }
            }
            if channel_rect.size.0 == 0 || channel_rect.size.1 == 0 {
                // Buffer would be empty anyway.
                continue;
            }
            let channel_rect = bi.orientation.display_rect(channel_rect, full_image_size);
            let channel_rect = channel_rect.to_byte_rect_sz(bi.byte_size);
            local_buffers[i] = Some(buf.rect(channel_rect));
        }
        local_buffers
    }

    pub fn into_changed_regions(self) -> Vec<Rect> {
        self.requested_rects
    }

    #[cfg(any(test, feature = "threads"))]
    pub fn get_full_buffers(&mut self) -> &mut [Option<JxlOutputBuffer<'b>>] {
        &mut *self.buffers
    }
}

/// Computes the channel rect for a given save buffer info and image rect.
#[cfg(feature = "threads")]
pub(crate) fn compute_channel_rect(
    bi: &SaveStageBufferInfo,
    rect: Rect,
    frame_size: (usize, usize),
    full_image_size: (usize, usize),
    frame_origin: (isize, isize),
) -> Option<Rect> {
    let mut channel_rect = rect.downsample(bi.downsample);
    let ds_frame_size = (
        frame_size.0.shrc(bi.downsample.0),
        frame_size.1.shrc(bi.downsample.1),
    );
    channel_rect = channel_rect.clip(ds_frame_size);
    if bi.after_extend {
        let origin = (
            rect.origin.0 as isize + frame_origin.0,
            rect.origin.1 as isize + frame_origin.1,
        );
        let end = (
            origin.0 + rect.size.0 as isize,
            origin.1 + rect.size.1 as isize,
        );
        let origin = (origin.0.max(0) as usize, origin.1.max(0) as usize);
        let end = (
            end.0.min(full_image_size.0 as isize).max(0) as usize,
            end.1.min(full_image_size.1 as isize).max(0) as usize,
        );
        channel_rect = Rect {
            origin,
            size: (
                end.0.saturating_sub(origin.0),
                end.1.saturating_sub(origin.1),
            ),
        };
    }
    if channel_rect.size.0 == 0 || channel_rect.size.1 == 0 {
        return None;
    }
    let channel_rect = bi.orientation.display_rect(channel_rect, full_image_size);
    Some(channel_rect.to_byte_rect_sz(bi.byte_size))
}

/// One locally-owned output buffer for a single channel of a single work item.
/// The render pipeline writes into `data` (tightly packed rows), and the
/// `channel_rect` records where this data should be copied in the real output.
#[cfg(feature = "threads")]
pub(crate) struct OwnedLocalBuffer {
    pub(crate) data: Vec<u8>,
    pub(crate) bytes_per_row: usize,
    pub(crate) num_rows: usize,
    pub(crate) channel_rect: Rect,
    pub(crate) buffer_index: usize,
}

/// Render output from one parallel work item. Contains owned buffers
/// that need to be copied back into the real output.
#[cfg(feature = "threads")]
#[allow(dead_code)] // Threaded render output container
pub(crate) struct WorkItemOutput {
    pub(crate) buffers: Vec<OwnedLocalBuffer>,
}

/// Computes which output buffer slots are needed for a work item and their sizes.
/// Returns (buffer_index, bytes_per_row, num_rows, channel_rect) for each active slot.
#[cfg(feature = "threads")]
pub(crate) fn compute_local_buffer_layouts(
    save_buffer_info: &[Option<SaveStageBufferInfo>],
    num_buffer_slots: usize,
    rect: Rect,
    frame_size: (usize, usize),
    full_image_size: (usize, usize),
    frame_origin: (isize, isize),
) -> Vec<(usize, usize, usize, Rect)> {
    let rect = rect.clip(frame_size);
    let mut layouts = Vec::new();

    for (i, info) in save_buffer_info.iter().enumerate() {
        let Some(bi) = info else {
            continue;
        };
        if i >= num_buffer_slots {
            continue;
        }
        let Some(channel_rect) =
            compute_channel_rect(bi, rect, frame_size, full_image_size, frame_origin)
        else {
            continue;
        };
        let bytes_per_row = channel_rect.size.0;
        let num_rows = channel_rect.size.1;
        if bytes_per_row == 0 || num_rows == 0 {
            continue;
        }
        layouts.push((i, bytes_per_row, num_rows, channel_rect));
    }
    layouts
}

/// Copies locally-owned render output back into the real output buffers.
///
/// Called sequentially after the parallel render completes.
#[cfg(feature = "threads")]
pub(crate) fn copy_back_local_buffers(
    owned_buffers: &[OwnedLocalBuffer],
    output: &mut [Option<JxlOutputBuffer<'_>>],
) {
    for olb in owned_buffers {
        let Some(buf) = output[olb.buffer_index].as_mut() else {
            continue;
        };
        let channel_rect = olb.channel_rect;
        let mut target = buf.rect(channel_rect);
        for row in 0..olb.num_rows {
            let src_start = row * olb.bytes_per_row;
            let src_end = src_start + olb.bytes_per_row;
            let dst_row = target.row_mut(row);
            dst_row[..olb.bytes_per_row].copy_from_slice(&olb.data[src_start..src_end]);
        }
    }
}
