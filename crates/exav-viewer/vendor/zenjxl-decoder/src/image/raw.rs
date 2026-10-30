// Copyright (c) the JPEG XL Project Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use std::fmt::Debug;

use crate::{
    error::Result,
    util::{CACHE_LINE_BYTE_SIZE, MemoryGuard, MemoryTracker},
};

use super::{Rect, internal::RawImageBuffer};

pub struct OwnedRawImage {
    // All the accessible bytes of `self.data` are initialized (Vec<u8> guarantees this).
    // `data.is_aligned(CACHE_LINE_BYTE_SIZE)` is true.
    pub(super) data: RawImageBuffer,
    pub(super) offset: (usize, usize),
    padding: (usize, usize),
    /// If set, this image's allocation is tracked against a memory budget.
    /// On drop, `tracked_bytes` will be released back to the tracker.
    tracker: Option<MemoryTracker>,
    tracked_bytes: u64,
}

impl OwnedRawImage {
    pub fn new(byte_size: (usize, usize)) -> Result<Self> {
        Self::new_zeroed_with_padding(byte_size, (0, 0), (0, 0))
    }

    /// Allocate an output buffer without zeroing.
    ///
    /// # Safety contract
    /// The caller must ensure every byte is written before being read.
    /// This is appropriate for output buffers that the decoder will fully populate.
    pub fn new_uninit(byte_size: (usize, usize)) -> Result<Self> {
        let mut padding = (0usize, 0usize);
        if !(padding.0 + byte_size.0).is_multiple_of(CACHE_LINE_BYTE_SIZE) {
            padding.0 += CACHE_LINE_BYTE_SIZE - (padding.0 + byte_size.0) % CACHE_LINE_BYTE_SIZE;
        }
        Ok(Self {
            data: RawImageBuffer::try_allocate(
                (byte_size.0 + padding.0, byte_size.1 + padding.1),
                true,
            )?,
            offset: (0, 0),
            padding,
            tracker: None,
            tracked_bytes: 0,
        })
    }

    pub fn new_zeroed_with_padding(
        byte_size: (usize, usize),
        offset: (usize, usize),
        mut padding: (usize, usize),
    ) -> Result<Self> {
        // Since RawImageBuffer::try_allocate will round up the length of a row to a cache line,
        // might as well declare that as available padding space.
        if !(padding.0 + byte_size.0).is_multiple_of(CACHE_LINE_BYTE_SIZE) {
            padding.0 += CACHE_LINE_BYTE_SIZE - (padding.0 + byte_size.0) % CACHE_LINE_BYTE_SIZE;
        }
        Ok(Self {
            data: RawImageBuffer::try_allocate(
                (byte_size.0 + padding.0, byte_size.1 + padding.1),
                false,
            )?,
            offset,
            padding,
            tracker: None,
            tracked_bytes: 0,
        })
    }

    #[inline]
    pub fn get_rect_including_padding_mut(&mut self, rect: Rect) -> RawImageRectMut<'_> {
        let (bpr, nr, bbr) = self.data.dimensions();
        let storage = self.data.data_slice_mut();
        sub_rect_mut(storage, bpr, nr, bbr, rect)
    }

    #[inline]
    pub fn get_rect_including_padding(&self, rect: Rect) -> RawImageRect<'_> {
        let (bpr, nr, bbr) = self.data.dimensions();
        let storage = self.data.data_slice();
        sub_rect(storage, bpr, nr, bbr, rect)
    }

    #[inline]
    fn shift_rect(&self, rect: Rect) -> Rect {
        if cfg!(debug_assertions) {
            // Check the original rect is within the content size (without padding)
            rect.check_within(self.byte_size());
        }
        Rect {
            origin: (rect.origin.0 + self.offset.0, rect.origin.1 + self.offset.1),
            size: rect.size,
        }
    }

    #[inline]
    pub fn get_rect_mut(&mut self, rect: Rect) -> RawImageRectMut<'_> {
        self.get_rect_including_padding_mut(self.shift_rect(rect))
    }

    #[inline]
    pub fn get_rect(&self, rect: Rect) -> RawImageRect<'_> {
        self.get_rect_including_padding(self.shift_rect(rect))
    }

    #[inline(always)]
    pub fn row_mut(&mut self, row: usize) -> &mut [u8] {
        let offset = self.offset;
        let end = offset.0 + self.byte_size().0;
        let row = self.data.row_mut(row + offset.1);
        &mut row[offset.0..end]
    }

    #[inline(always)]
    pub fn row(&self, row: usize) -> &[u8] {
        let offset = self.offset;
        let end = offset.0 + self.byte_size().0;
        let row = self.data.row(row + offset.1);
        &row[offset.0..end]
    }

    #[inline]
    pub fn byte_size(&self) -> (usize, usize) {
        let size = self.data.byte_size();
        (size.0 - self.padding.0, size.1 - self.padding.1)
    }

    #[inline]
    pub fn byte_offset(&self) -> (usize, usize) {
        self.offset
    }

    #[inline]
    pub fn byte_padding(&self) -> (usize, usize) {
        self.padding
    }

    /// Pre-fault all virtual memory pages by touching one byte per page in parallel.
    /// This avoids page fault contention during rendering by spreading fault handling
    /// across rayon worker threads before the hot rendering loop begins.
    #[cfg(feature = "threads")]
    pub fn prefault_parallel(&mut self) {
        use rayon::prelude::*;
        const PAGE_SIZE: usize = 4096;
        let data = self.data.data_slice_mut();
        if data.is_empty() {
            return;
        }
        data.par_chunks_mut(PAGE_SIZE).for_each(|chunk| {
            chunk[0] = 0;
        });
    }

    /// Sets memory tracking on this image so that `tracked_bytes` are released
    /// back to `tracker` when this image is dropped.
    pub(super) fn set_tracker(&mut self, tracker: MemoryTracker, bytes: u64) {
        self.tracker = Some(tracker);
        self.tracked_bytes = bytes;
    }

    pub fn try_clone(&self) -> Result<OwnedRawImage> {
        // If tracked, reserve budget for the clone before allocating.
        if let Some(tracker) = &self.tracker {
            tracker.try_allocate(self.tracked_bytes)?;
        }
        // Guard ensures rollback if the raw data clone fails.
        let guard: Option<MemoryGuard> = self
            .tracker
            .as_ref()
            .map(|t| MemoryGuard::new(t.clone(), self.tracked_bytes));

        let clone = Self {
            data: self.data.try_clone()?,
            offset: self.offset,
            padding: self.padding,
            tracker: self.tracker.clone(),
            tracked_bytes: self.tracked_bytes,
        };

        // Transfer budget ownership from guard to the clone's Drop.
        if let Some(g) = guard {
            g.disarm();
        }

        Ok(clone)
    }
}

impl Drop for OwnedRawImage {
    fn drop(&mut self) {
        if let Some(tracker) = &self.tracker {
            tracker.release(self.tracked_bytes);
        }
        // Vec<u8> drops automatically — no manual dealloc needed.
        self.data.deallocate();
    }
}

/// Helper: create an immutable sub-view from a storage slice and its dimensions.
#[inline]
fn sub_rect<'a>(
    storage: &'a [u8],
    bpr: usize,
    nr: usize,
    bbr: usize,
    rect: Rect,
) -> RawImageRect<'a> {
    if rect.size.0 == 0 || rect.size.1 == 0 {
        return RawImageRect {
            storage: &[],
            bytes_per_row: 0,
            num_rows: 0,
            bytes_between_rows: 0,
        };
    }
    assert!(rect.origin.1 + rect.size.1 <= nr);
    assert!(rect.origin.0 + rect.size.0 <= bpr);
    let new_start = rect.origin.1 * bbr + rect.origin.0;
    let data_span = (rect.size.1 - 1) * bbr + rect.size.0;
    assert!(new_start + data_span <= storage.len());
    RawImageRect {
        storage: &storage[new_start..new_start + data_span],
        bytes_per_row: rect.size.0,
        num_rows: rect.size.1,
        bytes_between_rows: bbr,
    }
}

/// Helper: create a mutable sub-view from a storage slice and its dimensions.
#[inline]
fn sub_rect_mut<'a>(
    storage: &'a mut [u8],
    bpr: usize,
    nr: usize,
    bbr: usize,
    rect: Rect,
) -> RawImageRectMut<'a> {
    if rect.size.0 == 0 || rect.size.1 == 0 {
        return RawImageRectMut {
            storage: &mut [],
            bytes_per_row: 0,
            num_rows: 0,
            bytes_between_rows: 0,
        };
    }
    assert!(rect.origin.1 + rect.size.1 <= nr);
    assert!(rect.origin.0 + rect.size.0 <= bpr);
    let new_start = rect.origin.1 * bbr + rect.origin.0;
    let data_span = (rect.size.1 - 1) * bbr + rect.size.0;
    assert!(new_start + data_span <= storage.len());
    RawImageRectMut {
        storage: &mut storage[new_start..new_start + data_span],
        bytes_per_row: rect.size.0,
        num_rows: rect.size.1,
        bytes_between_rows: bbr,
    }
}

/// Immutable view into image data. Holds a borrowed slice + row layout info.
/// `Copy` because it's just a `&[u8]` + dimensions.
#[derive(Clone, Copy)]
pub struct RawImageRect<'a> {
    pub(super) storage: &'a [u8],
    pub(super) bytes_per_row: usize,
    pub(super) num_rows: usize,
    pub(super) bytes_between_rows: usize,
}

impl<'a> RawImageRect<'a> {
    #[inline(always)]
    pub fn row(&self, row: usize) -> &'a [u8] {
        assert!(row < self.num_rows);
        let start = row * self.bytes_between_rows;
        &self.storage[start..start + self.bytes_per_row]
    }

    #[inline]
    pub fn rect(&self, rect: Rect) -> RawImageRect<'a> {
        sub_rect(
            self.storage,
            self.bytes_per_row,
            self.num_rows,
            self.bytes_between_rows,
            rect,
        )
    }

    #[inline]
    pub fn byte_size(&self) -> (usize, usize) {
        (self.bytes_per_row, self.num_rows)
    }

    #[inline]
    pub(super) fn is_aligned(&self, align: usize) -> bool {
        if self.num_rows == 0 {
            return true;
        }
        self.bytes_per_row.is_multiple_of(align)
            && self.bytes_between_rows.is_multiple_of(align)
            && (self.storage.as_ptr() as usize).is_multiple_of(align)
    }
}

/// Mutable view into image data. Holds a borrowed mutable slice + row layout info.
pub struct RawImageRectMut<'a> {
    pub(super) storage: &'a mut [u8],
    pub(super) bytes_per_row: usize,
    pub(super) num_rows: usize,
    pub(super) bytes_between_rows: usize,
}

impl<'a> RawImageRectMut<'a> {
    #[inline(always)]
    pub fn row(&mut self, row: usize) -> &mut [u8] {
        assert!(row < self.num_rows);
        let start = row * self.bytes_between_rows;
        &mut self.storage[start..start + self.bytes_per_row]
    }

    #[inline]
    pub fn rect_mut(&mut self, rect: Rect) -> RawImageRectMut<'_> {
        sub_rect_mut(
            self.storage,
            self.bytes_per_row,
            self.num_rows,
            self.bytes_between_rows,
            rect,
        )
    }

    pub fn as_rect(&self) -> RawImageRect<'_> {
        RawImageRect {
            storage: self.storage,
            bytes_per_row: self.bytes_per_row,
            num_rows: self.num_rows,
            bytes_between_rows: self.bytes_between_rows,
        }
    }

    #[inline]
    pub fn byte_size(&self) -> (usize, usize) {
        (self.bytes_per_row, self.num_rows)
    }

    #[inline]
    pub(super) fn is_aligned(&self, align: usize) -> bool {
        if self.num_rows == 0 {
            return true;
        }
        self.bytes_per_row.is_multiple_of(align)
            && self.bytes_between_rows.is_multiple_of(align)
            && (self.storage.as_ptr() as usize).is_multiple_of(align)
    }

    /// Creates a mutable view from an external slice and dimensions.
    #[allow(dead_code)] // Part of RawImageRectMut construction API
    pub(super) fn from_slice(
        buf: &'a mut [u8],
        num_rows: usize,
        bytes_per_row: usize,
        bytes_between_rows: usize,
    ) -> Self {
        RawImageBuffer::check_vals(num_rows, bytes_per_row, bytes_between_rows);
        let expected_len = if num_rows == 0 {
            0
        } else {
            (num_rows - 1) * bytes_between_rows + bytes_per_row
        };
        assert!(
            buf.len() >= expected_len,
            "buffer too small: {} < {}",
            buf.len(),
            expected_len
        );
        RawImageRectMut {
            storage: if expected_len == 0 {
                &mut []
            } else {
                &mut buf[..expected_len]
            },
            bytes_per_row,
            num_rows,
            bytes_between_rows,
        }
    }
}

impl Debug for OwnedRawImage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "raw {}x{}", self.byte_size().0, self.byte_size().1)
    }
}

impl Debug for RawImageRect<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "raw rect {}x{}", self.byte_size().0, self.byte_size().1)
    }
}

impl Debug for RawImageRectMut<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "raw mutrect {}x{}",
            self.byte_size().0,
            self.byte_size().1
        )
    }
}
