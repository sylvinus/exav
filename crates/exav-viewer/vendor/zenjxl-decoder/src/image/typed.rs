// Copyright (c) the JPEG XL Project Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use std::{fmt::Debug, marker::PhantomData};

use crate::{
    error::Result,
    image::internal::DistinctRowsIndexes,
    util::{CACHE_LINE_BYTE_SIZE, MemoryGuard, MemoryTracker, tracing_wrappers::*},
};

use super::{ImageDataType, OwnedRawImage, RawImageRect, RawImageRectMut, Rect};

/// Cast a `&[u8]` row to `&[T]`.
///
/// With `allow-unsafe`, uses a direct pointer cast (zero overhead). The caller
/// must uphold the alignment/size invariants established at construction time.
/// Without `allow-unsafe`, delegates to `bytemuck::cast_slice` which validates
/// alignment and size on every call.
#[cfg(feature = "allow-unsafe")]
#[inline(always)]
pub(super) fn cast_row<T: ImageDataType>(row: &[u8]) -> &[T] {
    let new_len = row.len() / std::mem::size_of::<T>();
    debug_assert!(row.len().is_multiple_of(std::mem::size_of::<T>()));
    debug_assert!((row.as_ptr() as usize).is_multiple_of(std::mem::align_of::<T>()));
    #[allow(unsafe_code)]
    // SAFETY: Alignment and size invariants verified at Image/ImageRect construction
    // (from_raw asserts both data.is_aligned(T::DATA_TYPE_ID.size()) and that the byte
    // offset is a multiple of the element size, so every row pointer is aligned to
    // align_of::<T>()).
    // The underlying buffer is cache-line aligned (64 bytes ≥ align_of::<T>()),
    // bytes_per_row = width * sizeof(T), bytes_between_rows is a multiple of
    // CACHE_LINE_BYTE_SIZE.
    unsafe {
        std::slice::from_raw_parts(row.as_ptr().cast::<T>(), new_len)
    }
}

#[cfg(not(feature = "allow-unsafe"))]
#[inline(always)]
pub(super) fn cast_row<T: ImageDataType>(row: &[u8]) -> &[T] {
    bytemuck::cast_slice(row)
}

/// Cast a `&mut [u8]` row to `&mut [T]`. See [`cast_row`] for safety rationale.
#[cfg(feature = "allow-unsafe")]
#[inline(always)]
pub(super) fn cast_row_mut<T: ImageDataType>(row: &mut [u8]) -> &mut [T] {
    let new_len = row.len() / std::mem::size_of::<T>();
    debug_assert!(row.len().is_multiple_of(std::mem::size_of::<T>()));
    debug_assert!((row.as_ptr() as usize).is_multiple_of(std::mem::align_of::<T>()));
    #[allow(unsafe_code)]
    // SAFETY: Same invariants as cast_row, plus exclusive (&mut) access.
    unsafe {
        std::slice::from_raw_parts_mut(row.as_mut_ptr().cast::<T>(), new_len)
    }
}

#[cfg(not(feature = "allow-unsafe"))]
#[inline(always)]
pub(super) fn cast_row_mut<T: ImageDataType>(row: &mut [u8]) -> &mut [T] {
    bytemuck::cast_slice_mut(row)
}

#[repr(transparent)]
pub struct Image<T: ImageDataType> {
    // Safety invariant: self.raw.data and self.raw.byte_offset().0 are aligned to
    // T::DATA_TYPE_ID.size().
    raw: OwnedRawImage,
    _ph: PhantomData<T>,
}

impl<T: ImageDataType> Image<T> {
    #[instrument(ret, err)]
    pub fn new_with_padding(
        size: (usize, usize),
        offset: (usize, usize),
        padding: (usize, usize),
    ) -> Result<Image<T>> {
        let s = T::DATA_TYPE_ID.size();
        let img = OwnedRawImage::new_zeroed_with_padding(
            (size.0 * s, size.1),
            (offset.0 * s, offset.1),
            (padding.0 * s, padding.1),
        )?;
        Ok(Self::from_raw(img))
    }

    #[instrument(ret, err)]
    pub fn new(size: (usize, usize)) -> Result<Image<T>> {
        Self::new_with_padding(size, (0, 0), (0, 0))
    }

    /// Allocates an uninitialized image buffer.
    ///
    /// With the `allow-unsafe` feature, the memory is left truly uninitialized
    /// (saving page-fault and zeroing costs). Without it, the buffer is zeroed.
    ///
    /// # Safety contract
    /// The caller MUST write every pixel before reading it.
    pub fn new_uninit(size: (usize, usize)) -> Result<Image<T>> {
        let s = T::DATA_TYPE_ID.size();
        let img = OwnedRawImage::new_uninit((size.0 * s, size.1))?;
        Ok(Self::from_raw(img))
    }

    pub fn new_with_value(size: (usize, usize), value: T) -> Result<Image<T>> {
        // TODO(veluca): skip zero-initializing the allocation if this becomes
        // performance-sensitive.
        let mut ret = Self::new(size)?;
        ret.fill(value);
        Ok(ret)
    }

    /// Computes the allocation size in bytes for an image of the given dimensions.
    /// This accounts for cache-line alignment of rows.
    pub fn allocation_size(size: (usize, usize)) -> u64 {
        let (width, height) = size;
        if width == 0 || height == 0 {
            return 0;
        }
        let bytes_per_row = width.saturating_mul(T::DATA_TYPE_ID.size());
        let bytes_between_rows =
            bytes_per_row.div_ceil(CACHE_LINE_BYTE_SIZE) * CACHE_LINE_BYTE_SIZE;
        let total = (height - 1)
            .saturating_mul(bytes_between_rows)
            .saturating_add(bytes_per_row);
        total as u64
    }

    /// Creates a new image after checking the memory tracker budget.
    /// The image tracks its allocation and releases the budget on drop.
    #[instrument(ret, err)]
    pub fn new_tracked(size: (usize, usize), tracker: &MemoryTracker) -> Result<Image<T>> {
        let alloc_size = Self::allocation_size(size);
        tracker.try_allocate(alloc_size)?;
        // Guard ensures budget is rolled back if the allocation below fails.
        let guard = MemoryGuard::new(tracker.clone(), alloc_size);
        let mut img = Self::new(size)?;
        img.raw.set_tracker(tracker.clone(), alloc_size);
        guard.disarm(); // Ownership transferred to OwnedRawImage's Drop.
        Ok(img)
    }

    /// Creates a new image with padding after checking the memory tracker budget.
    /// The image tracks its allocation and releases the budget on drop.
    #[instrument(ret, err)]
    pub fn new_with_padding_tracked(
        size: (usize, usize),
        offset: (usize, usize),
        padding: (usize, usize),
        tracker: &MemoryTracker,
    ) -> Result<Image<T>> {
        let total_width = size.0.saturating_add(offset.0).saturating_add(padding.0);
        let total_height = size.1.saturating_add(offset.1).saturating_add(padding.1);
        let alloc_size = Self::allocation_size((total_width, total_height));
        tracker.try_allocate(alloc_size)?;
        let guard = MemoryGuard::new(tracker.clone(), alloc_size);
        let mut img = Self::new_with_padding(size, offset, padding)?;
        img.raw.set_tracker(tracker.clone(), alloc_size);
        guard.disarm();
        Ok(img)
    }

    #[inline]
    pub fn size(&self) -> (usize, usize) {
        (
            self.raw.byte_size().0 / T::DATA_TYPE_ID.size(),
            self.raw.byte_size().1,
        )
    }

    pub fn offset(&self) -> (usize, usize) {
        (
            self.raw.byte_offset().0 / T::DATA_TYPE_ID.size(),
            self.raw.byte_offset().1,
        )
    }

    pub fn padding(&self) -> (usize, usize) {
        (
            self.raw.byte_padding().0 / T::DATA_TYPE_ID.size(),
            self.raw.byte_padding().1,
        )
    }

    pub fn fill(&mut self, v: T) {
        if self.size().0 == 0 {
            return;
        }
        for y in 0..self.size().1 {
            self.row_mut(y).fill(v);
        }
    }

    #[inline]
    pub fn get_rect_including_padding_mut(&mut self, rect: Rect) -> ImageRectMut<'_, T> {
        ImageRectMut::from_raw(
            self.raw
                .get_rect_including_padding_mut(rect.to_byte_rect(T::DATA_TYPE_ID)),
        )
    }

    #[inline]
    pub fn get_rect_including_padding(&mut self, rect: Rect) -> ImageRect<'_, T> {
        ImageRect::from_raw(
            self.raw
                .get_rect_including_padding(rect.to_byte_rect(T::DATA_TYPE_ID)),
        )
    }

    #[inline]
    pub fn get_rect_mut(&mut self, rect: Rect) -> ImageRectMut<'_, T> {
        ImageRectMut::from_raw(self.raw.get_rect_mut(rect.to_byte_rect(T::DATA_TYPE_ID)))
    }

    #[inline]
    pub fn get_rect(&self, rect: Rect) -> ImageRect<'_, T> {
        ImageRect::from_raw(self.raw.get_rect(rect.to_byte_rect(T::DATA_TYPE_ID)))
    }

    pub fn try_clone(&self) -> Result<Self> {
        Ok(Self::from_raw(self.raw.try_clone()?))
    }

    pub fn into_raw(self) -> OwnedRawImage {
        self.raw
    }

    pub fn from_raw(raw: OwnedRawImage) -> Self {
        const { assert!(CACHE_LINE_BYTE_SIZE.is_multiple_of(T::DATA_TYPE_ID.size())) };
        assert!(raw.data.is_aligned(T::DATA_TYPE_ID.size()));
        assert!(
            raw.byte_offset().0.is_multiple_of(T::DATA_TYPE_ID.size()),
            "image byte offset must be aligned to element size"
        );
        Image {
            raw,
            _ph: PhantomData,
        }
    }

    #[inline(always)]
    pub fn row(&self, row: usize) -> &[T] {
        cast_row(self.raw.row(row))
    }

    #[inline(always)]
    pub fn row_mut(&mut self, row: usize) -> &mut [T] {
        cast_row_mut(self.raw.row_mut(row))
    }

    /// Note: this is quadratic in the number of rows. Indexing *ignores any padding rows*, i.e.
    /// the row at index 0 will be the first row of the *padding*, unlike with all the other row
    /// accessors.
    #[inline(always)]
    pub fn distinct_full_rows_mut<I: DistinctRowsIndexes>(
        &mut self,
        rows: I,
    ) -> I::CastOutput<'_, T> {
        let rows = self.raw.data.distinct_rows_mut(rows);
        I::cast_rows(rows)
    }

    /// Returns mutable slices for all rows. Each slice has exactly `width`
    /// elements where width = self.size().0. Rows are disjoint within the
    /// underlying buffer (separated by cache-line-aligned stride).
    pub fn all_rows_mut(&mut self) -> Vec<&mut [T]> {
        let (bytes_per_row, num_rows, bytes_between_rows) = self.raw.data.dimensions();
        if num_rows == 0 {
            return Vec::new();
        }
        let data = self.raw.data.data_slice_mut();
        // Use a recursive split pattern that the borrow checker can track.
        // split_rows_recursive handles the "remaining slice" ownership chain.
        let mut result = Vec::with_capacity(num_rows);
        split_rows_into(
            data,
            bytes_per_row,
            bytes_between_rows,
            num_rows,
            &mut result,
        );
        result
    }
}

/// Splits a byte slice into per-row mutable `&mut [T]` slices.
/// Each row is `bytes_per_row` bytes wide, rows are `bytes_between_rows` apart,
/// and the total spans `num_rows` rows.
///
/// Uses a `while let` loop with `Option<&mut [u8]>` to satisfy the borrow
/// checker: `take()` moves ownership out, `split_at_mut` produces two disjoint
/// halves, and we re-insert the remainder for the next iteration.
fn split_rows_into<'a, T: ImageDataType>(
    data: &'a mut [u8],
    bytes_per_row: usize,
    bytes_between_rows: usize,
    num_rows: usize,
    out: &mut Vec<&'a mut [T]>,
) {
    let mut remaining: Option<&'a mut [u8]> = Some(data);
    for i in 0..num_rows {
        let data = remaining.take().unwrap();
        if i < num_rows - 1 {
            let (head, tail) = data.split_at_mut(bytes_between_rows);
            out.push(cast_row_mut(&mut head[..bytes_per_row]));
            remaining = Some(tail);
        } else {
            out.push(cast_row_mut(&mut data[..bytes_per_row]));
        }
    }
}

#[derive(Clone, Copy)]
pub struct ImageRect<'a, T: ImageDataType> {
    // Invariant: self.raw.is_aligned(T::DATA_TYPE_ID.size()) is true.
    raw: RawImageRect<'a>,
    _ph: PhantomData<T>,
}

impl<'a, T: ImageDataType> ImageRect<'a, T> {
    #[inline(always)]
    pub fn rect(&self, rect: Rect) -> ImageRect<'a, T> {
        Self::from_raw(self.raw.rect(rect.to_byte_rect(T::DATA_TYPE_ID)))
    }

    #[inline]
    pub fn size(&self) -> (usize, usize) {
        (
            self.raw.byte_size().0 / T::DATA_TYPE_ID.size(),
            self.raw.byte_size().1,
        )
    }

    #[inline(always)]
    pub fn row(&self, row: usize) -> &'a [T] {
        // RawImageRect::row() returns &'a [u8] (the lifetime of the underlying storage),
        // and cast_row preserves that lifetime.
        cast_row(self.raw.row(row))
    }

    pub fn iter(&self) -> impl Iterator<Item = T> + '_ {
        (0..self.size().1).flat_map(|x| self.row(x).iter().cloned())
    }

    pub fn into_raw(self) -> RawImageRect<'a> {
        self.raw
    }

    #[inline]
    pub fn from_raw(raw: RawImageRect<'a>) -> Self {
        const { assert!(CACHE_LINE_BYTE_SIZE.is_multiple_of(T::DATA_TYPE_ID.size())) };
        assert!(raw.is_aligned(T::DATA_TYPE_ID.size()));
        ImageRect {
            raw,
            _ph: PhantomData,
        }
    }
}

pub struct ImageRectMut<'a, T: ImageDataType> {
    // Invariant: self.raw.is_aligned(T::DATA_TYPE_ID.size()) is true.
    raw: RawImageRectMut<'a>,
    _ph: PhantomData<T>,
}

impl<'a, T: ImageDataType> ImageRectMut<'a, T> {
    #[inline]
    pub fn rect(&'a mut self, rect: Rect) -> ImageRectMut<'a, T> {
        Self::from_raw(self.raw.rect_mut(rect.to_byte_rect(T::DATA_TYPE_ID)))
    }

    #[inline]
    pub fn size(&self) -> (usize, usize) {
        (
            self.raw.byte_size().0 / T::DATA_TYPE_ID.size(),
            self.raw.byte_size().1,
        )
    }

    #[inline(always)]
    pub fn row(&mut self, row: usize) -> &mut [T] {
        cast_row_mut(self.raw.row(row))
    }

    pub fn as_rect(&'a self) -> ImageRect<'a, T> {
        ImageRect::from_raw(self.raw.as_rect())
    }

    pub fn into_raw(self) -> RawImageRectMut<'a> {
        self.raw
    }

    #[inline]
    pub fn from_raw(raw: RawImageRectMut<'a>) -> Self {
        const { assert!(CACHE_LINE_BYTE_SIZE.is_multiple_of(T::DATA_TYPE_ID.size())) };
        assert!(raw.is_aligned(T::DATA_TYPE_ID.size()));
        ImageRectMut {
            raw,
            _ph: PhantomData,
        }
    }
}

impl<T: ImageDataType> Debug for Image<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?} {}x{}",
            T::DATA_TYPE_ID,
            self.size().0,
            self.size().1
        )
    }
}

impl<T: ImageDataType> Debug for ImageRect<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?} rect {}x{}",
            T::DATA_TYPE_ID,
            self.size().0,
            self.size().1
        )
    }
}

impl<T: ImageDataType> Debug for ImageRectMut<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?} mutrect {}x{}",
            T::DATA_TYPE_ID,
            self.size().0,
            self.size().1
        )
    }
}
