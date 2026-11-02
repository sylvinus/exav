// Copyright (c) the JPEG XL Project Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use std::fmt::Debug;

use crate::{
    error::{Error, Result},
    util::{CACHE_LINE_BYTE_SIZE, tracing_wrappers::*},
};

/// Allocates zeroed memory, returning an error instead of aborting on OOM.
///
/// Always uses `try_reserve` to ensure proper error handling for all allocation
/// sizes. The `vec!` macro calls the global allocator which aborts on failure,
/// so we avoid it for any size that could plausibly fail. After `try_reserve`
/// succeeds, `resize` is guaranteed not to re-allocate.
fn alloc_zeroed_fallible(
    total_len: usize,
    bytes_per_row: usize,
    num_rows: usize,
) -> Result<Vec<u8>> {
    let mut storage = Vec::new();
    storage
        .try_reserve(total_len)
        .map_err(|_| Error::ImageOutOfMemory(bytes_per_row, num_rows))?;
    storage.resize(total_len, 0);
    Ok(storage)
}

/// Safe image buffer backed by `Vec<u8>` with cache-line alignment via offset.
///
/// For owned buffers, `storage` holds the allocation and `offset` points to the first
/// cache-line-aligned byte.
///
/// Invariants:
///  - If `num_rows > 0`, then `bytes_per_row > 0` and `bytes_per_row <= bytes_between_rows`.
///  - All accessible byte ranges `[offset + i*bytes_between_rows .. offset + i*bytes_between_rows + bytes_per_row]`
///    for i in 0..num_rows are within `storage.len()`.
///  - The computation `bytes_between_rows * (num_rows-1) + bytes_per_row` does not overflow
///    and has a result that is at most `isize::MAX`, or `num_rows` is 0.
#[derive(Debug, Clone)]
pub(super) struct RawImageBuffer {
    storage: Vec<u8>,
    offset: usize,
    bytes_per_row: usize,
    num_rows: usize,
    bytes_between_rows: usize,
}

impl RawImageBuffer {
    pub(super) fn check_vals(num_rows: usize, bytes_per_row: usize, bytes_between_rows: usize) {
        if num_rows > 0 {
            assert!(bytes_per_row > 0);
            assert!(bytes_between_rows >= bytes_per_row);
            assert!(
                bytes_between_rows
                    .checked_mul(num_rows - 1)
                    .unwrap()
                    .checked_add(bytes_per_row)
                    .unwrap()
                    <= isize::MAX as usize
            );
        }
    }

    /// Checks that the data pointer, bytes_per_row, and bytes_between_rows are all multiples of `align`.
    #[inline(always)]
    pub(super) fn is_aligned(&self, align: usize) -> bool {
        if self.num_rows == 0 {
            return true;
        }
        self.bytes_per_row.is_multiple_of(align)
            && self.bytes_between_rows.is_multiple_of(align)
            && self.data_ptr_addr().is_multiple_of(align)
    }

    /// Returns the address of the first data byte (for alignment checking).
    #[inline(always)]
    fn data_ptr_addr(&self) -> usize {
        if self.storage.is_empty() {
            0
        } else {
            (self.storage.as_ptr() as usize) + self.offset
        }
    }

    /// Returns the minimum size that the accessible data spans, or 0 if empty.
    pub(super) fn minimum_allocation_size(&self) -> usize {
        if self.num_rows == 0 {
            0
        } else {
            (self.num_rows - 1) * self.bytes_between_rows + self.bytes_per_row
        }
    }

    #[inline]
    pub(super) fn byte_size(&self) -> (usize, usize) {
        (self.bytes_per_row, self.num_rows)
    }

    /// Returns (bytes_per_row, num_rows, bytes_between_rows).
    #[inline]
    pub(super) fn dimensions(&self) -> (usize, usize, usize) {
        (self.bytes_per_row, self.num_rows, self.bytes_between_rows)
    }

    /// Returns the accessible data as an immutable slice, starting at the first row.
    #[inline]
    pub(super) fn data_slice(&self) -> &[u8] {
        let size = self.minimum_allocation_size();
        if size == 0 {
            &[]
        } else {
            &self.storage[self.offset..self.offset + size]
        }
    }

    /// Returns the accessible data as a mutable slice, starting at the first row.
    #[inline]
    pub(super) fn data_slice_mut(&mut self) -> &mut [u8] {
        let size = self.minimum_allocation_size();
        if size == 0 {
            &mut []
        } else {
            let start = self.offset;
            &mut self.storage[start..start + size]
        }
    }

    #[inline(always)]
    pub(super) fn row(&self, row: usize) -> &[u8] {
        assert!(row < self.num_rows);
        let start = self.offset + row * self.bytes_between_rows;
        &self.storage[start..start + self.bytes_per_row]
    }

    #[inline(always)]
    pub(super) fn row_mut(&mut self, row: usize) -> &mut [u8] {
        assert!(row < self.num_rows);
        let start = self.offset + row * self.bytes_between_rows;
        &mut self.storage[start..start + self.bytes_per_row]
    }

    /// Returns mutable slices for distinct rows. Panics if any rows are equal.
    /// Note: this is quadratic in the number of rows.
    #[inline(always)]
    pub(super) fn distinct_rows_mut<I: DistinctRowsIndexes>(&mut self, rows: I) -> I::Output<'_> {
        rows.get_rows_mut(self)
    }

    /// Returns zeroed memory. The returned buffer is aligned to
    /// CACHE_LINE_BYTE_SIZE bytes via offset.
    pub(super) fn try_allocate(byte_size: (usize, usize), uninit: bool) -> Result<RawImageBuffer> {
        let (bytes_per_row, num_rows) = byte_size;
        if bytes_per_row == 0 || num_rows == 0 {
            return Ok(RawImageBuffer {
                storage: Vec::new(),
                offset: 0,
                bytes_per_row: 0,
                num_rows: 0,
                bytes_between_rows: 0,
            });
        }
        if bytes_per_row as u64 >= i64::MAX as u64 / 4 || num_rows as u64 >= i64::MAX as u64 / 4 {
            return Err(Error::ImageSizeTooLarge(bytes_per_row, num_rows));
        }
        debug!("trying to allocate image");
        let bytes_between_rows =
            bytes_per_row.div_ceil(CACHE_LINE_BYTE_SIZE) * CACHE_LINE_BYTE_SIZE;
        let data_len = (num_rows - 1)
            .checked_mul(bytes_between_rows)
            .and_then(|v| v.checked_add(bytes_per_row))
            .ok_or(Error::ImageSizeTooLarge(bytes_per_row, num_rows))?;
        assert_ne!(data_len, 0);

        // Allocate with extra space for alignment padding
        let total_len = data_len
            .checked_add(CACHE_LINE_BYTE_SIZE - 1)
            .ok_or(Error::ImageSizeTooLarge(bytes_per_row, num_rows))?;
        let storage = if uninit {
            #[cfg(feature = "allow-unsafe")]
            {
                // Skip zeroing entirely: pages fault on first write.
                let mut v = Vec::new();
                v.try_reserve(total_len)
                    .map_err(|_| Error::ImageOutOfMemory(bytes_per_row, num_rows))?;
                #[allow(unsafe_code)]
                // SAFETY: try_reserve succeeded so capacity >= total_len.
                // Caller guarantees all bytes will be written before being read.
                unsafe {
                    v.set_len(total_len);
                }
                v
            }
            #[cfg(not(feature = "allow-unsafe"))]
            {
                alloc_zeroed_fallible(total_len, bytes_per_row, num_rows)?
            }
        } else {
            alloc_zeroed_fallible(total_len, bytes_per_row, num_rows)?
        };

        // Compute offset to first cache-line-aligned byte
        let base_ptr = storage.as_ptr() as usize;
        let aligned_ptr = base_ptr.div_ceil(CACHE_LINE_BYTE_SIZE) * CACHE_LINE_BYTE_SIZE;
        let offset = aligned_ptr - base_ptr;

        Ok(RawImageBuffer {
            storage,
            offset,
            bytes_per_row,
            num_rows,
            bytes_between_rows,
        })
    }

    /// Returns a copy of the current buffer contents in a new buffer.
    pub(super) fn try_clone(&self) -> Result<Self> {
        let out = RawImageBuffer::try_allocate(self.byte_size(), true)?;
        assert_eq!(self.bytes_per_row, out.bytes_per_row);
        assert_eq!(self.bytes_between_rows, out.bytes_between_rows);
        assert_eq!(self.num_rows, out.num_rows);
        let data_len = self.minimum_allocation_size();
        if data_len != 0 {
            let mut result = out;
            let src = &self.storage[self.offset..self.offset + data_len];
            let dst = &mut result.storage[result.offset..result.offset + data_len];
            dst.copy_from_slice(src);
            Ok(result)
        } else {
            Ok(out)
        }
    }

    /// Clears the buffer, releasing the backing Vec.
    pub(super) fn deallocate(&mut self) {
        self.storage = Vec::new();
        self.offset = 0;
        self.num_rows = 0;
        self.bytes_per_row = 0;
        self.bytes_between_rows = 0;
    }
}

// RawImageBuffer is Send + Sync automatically because Vec<u8> is Send + Sync.

#[allow(private_interfaces)]
pub trait DistinctRowsIndexes {
    type Output<'a>;
    type CastOutput<'a, T: 'static>;

    fn get_rows_mut<'a>(&self, image: &'a mut RawImageBuffer) -> Self::Output<'a>;

    fn cast_rows<'a, T: crate::image::ImageDataType>(
        rows: Self::Output<'a>,
    ) -> Self::CastOutput<'a, T>;
}

#[allow(private_interfaces)]
impl<const S: usize> DistinctRowsIndexes for [usize; S] {
    type Output<'a> = [&'a mut [u8]; S];
    type CastOutput<'a, T: 'static> = [&'a mut [T]; S];

    #[inline(always)]
    fn get_rows_mut<'a>(&self, image: &'a mut RawImageBuffer) -> Self::Output<'a> {
        for i in 0..S {
            assert!(self[i] < image.num_rows);
            for j in i + 1..S {
                assert_ne!(self[i], self[j]);
            }
        }

        // Compute byte ranges for each row
        let ranges: [std::ops::Range<usize>; S] = std::array::from_fn(|i| {
            let start = image.offset + self[i] * image.bytes_between_rows;
            start..start + image.bytes_per_row
        });

        // Use split_at_mut to safely create non-overlapping mutable slices.
        let storage = &mut image.storage[..];
        get_distinct_slices(storage, ranges)
    }

    #[inline(always)]
    fn cast_rows<'a, T: crate::image::ImageDataType>(
        rows: Self::Output<'a>,
    ) -> Self::CastOutput<'a, T> {
        rows.map(|row| crate::image::typed::cast_row_mut(row))
    }
}

/// Safely extract multiple non-overlapping mutable slices from a single slice.
fn get_distinct_slices<const S: usize>(
    data: &mut [u8],
    ranges: [std::ops::Range<usize>; S],
) -> [&mut [u8]; S] {
    // Create index-range pairs sorted by start position
    let mut indexed: [(usize, std::ops::Range<usize>); S] =
        std::array::from_fn(|i| (i, ranges[i].clone()));
    // Sort by range start (simple insertion sort for small S)
    for i in 1..S {
        let mut j = i;
        while j > 0 && indexed[j].1.start < indexed[j - 1].1.start {
            indexed.swap(j, j - 1);
            j -= 1;
        }
    }

    // Verify non-overlapping
    for i in 1..S {
        assert!(
            indexed[i].1.start >= indexed[i - 1].1.end,
            "overlapping row ranges"
        );
    }

    // Collect the slices using split_at_mut, then restore original order
    let mut slices: Vec<(usize, &mut [u8])> = Vec::with_capacity(S);
    let mut remaining = data;
    let mut consumed = 0usize;
    for item in indexed.iter().take(S) {
        let (orig_idx, ref range) = *item;
        let skip = range.start - consumed;
        let len = range.len();
        let (_, rest) = remaining.split_at_mut(skip);
        let (chunk, rest2) = rest.split_at_mut(len);
        slices.push((orig_idx, chunk));
        remaining = rest2;
        consumed = range.end;
    }

    // Sort back to original order
    slices.sort_by_key(|(idx, _)| *idx);

    // Convert to fixed-size array
    let mut iter = slices.into_iter().map(|(_, s)| s);
    std::array::from_fn(|_| iter.next().unwrap())
}
