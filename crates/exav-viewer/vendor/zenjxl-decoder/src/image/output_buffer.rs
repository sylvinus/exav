// Copyright (c) the JPEG XL Project Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use std::fmt::Debug;

use super::{RawImageRectMut, Rect, internal::RawImageBuffer};

/// Internal storage for a `JxlOutputBuffer`.
///
/// `Contiguous`: a single mutable byte slice with a row stride.
/// `Fragmented`: a collection of per-row mutable byte slices, used for
/// column-split tile fragments where rows are non-contiguous in memory.
pub(crate) enum BufferStorage<'a> {
    Contiguous {
        data: &'a mut [u8],
        bytes_between_rows: usize,
    },
    #[allow(dead_code)] // Constructed by split methods used in threads feature
    Fragmented { rows: Vec<&'a mut [u8]> },
}

pub struct JxlOutputBuffer<'a> {
    storage: BufferStorage<'a>,
    bytes_per_row: usize,
    num_rows: usize,
    /// Row offset for band buffers: row_mut(r) accesses storage row (r - row_offset).
    /// Always 0 for normal buffers. Set by split_into_row_bands for band sub-buffers.
    row_offset: usize,
}

impl<'a> JxlOutputBuffer<'a> {
    pub fn from_image_rect_mut(raw: RawImageRectMut<'a>) -> Self {
        Self {
            storage: BufferStorage::Contiguous {
                data: raw.storage,
                bytes_between_rows: raw.bytes_between_rows,
            },
            bytes_per_row: raw.bytes_per_row,
            num_rows: raw.num_rows,
            row_offset: 0,
        }
    }

    /// Creates a new JxlOutputBuffer from a mutable byte slice.
    pub fn new(buf: &'a mut [u8], num_rows: usize, bytes_per_row: usize) -> Self {
        RawImageBuffer::check_vals(num_rows, bytes_per_row, bytes_per_row);
        let expected_len = if num_rows == 0 {
            0
        } else {
            (num_rows - 1) * bytes_per_row + bytes_per_row
        };
        assert!(buf.len() >= expected_len);
        Self {
            storage: BufferStorage::Contiguous {
                data: if expected_len == 0 {
                    &mut []
                } else {
                    &mut buf[..expected_len]
                },
                bytes_between_rows: bytes_per_row,
            },
            bytes_per_row,
            num_rows,
            row_offset: 0,
        }
    }

    /// Creates a new JxlOutputBuffer from raw pointers.
    /// It is guaranteed that `buf` will never be used to write uninitialized data.
    ///
    /// # Safety
    /// - `buf` must be valid for writes for all bytes in the range
    ///   `buf[i*bytes_between_rows..i*bytes_between_rows+bytes_per_row]` for all values of `i`
    ///   from `0` to `num_rows-1`.
    /// - The bytes in these ranges must not be accessed as long as the returned `Self` is in scope.
    /// - All the bytes in those ranges (and in between) must be part of the same allocated object.
    #[cfg(feature = "allow-unsafe")]
    #[allow(unsafe_code)]
    pub unsafe fn new_from_ptr(
        buf: *mut std::mem::MaybeUninit<u8>,
        num_rows: usize,
        bytes_per_row: usize,
        bytes_between_rows: usize,
    ) -> Self {
        RawImageBuffer::check_vals(num_rows, bytes_per_row, bytes_between_rows);
        let total_len = if num_rows == 0 {
            0
        } else {
            (num_rows - 1) * bytes_between_rows + bytes_per_row
        };
        let data = if total_len == 0 {
            &mut []
        } else {
            // SAFETY: Caller guarantees `buf` is valid for `total_len` bytes.
            // MaybeUninit<u8> and u8 have identical layout.
            unsafe { std::slice::from_raw_parts_mut(buf as *mut u8, total_len) }
        };
        Self {
            storage: BufferStorage::Contiguous {
                data,
                bytes_between_rows,
            },
            bytes_per_row,
            num_rows,
            row_offset: 0,
        }
    }

    pub(crate) fn reborrow(lender: &'a mut JxlOutputBuffer<'_>) -> JxlOutputBuffer<'a> {
        JxlOutputBuffer {
            storage: match &mut lender.storage {
                BufferStorage::Contiguous {
                    data,
                    bytes_between_rows,
                } => BufferStorage::Contiguous {
                    data,
                    bytes_between_rows: *bytes_between_rows,
                },
                BufferStorage::Fragmented { rows } => BufferStorage::Fragmented {
                    rows: rows.iter_mut().map(|r| &mut **r).collect(),
                },
            },
            bytes_per_row: lender.bytes_per_row,
            num_rows: lender.num_rows,
            row_offset: lender.row_offset,
        }
    }

    /// Returns a mutable row as a byte slice.
    ///
    /// For band buffers (row_offset > 0), `row` is in the parent buffer's
    /// coordinate system and is translated internally.
    #[inline]
    pub(crate) fn row_mut(&mut self, row: usize) -> &mut [u8] {
        let local_row = row.wrapping_sub(self.row_offset);
        assert!(
            local_row < self.num_rows,
            "row {row} out of range [{}, {})",
            self.row_offset,
            self.row_offset + self.num_rows,
        );
        match &mut self.storage {
            BufferStorage::Contiguous {
                data,
                bytes_between_rows,
            } => {
                let start = local_row * *bytes_between_rows;
                &mut data[start..start + self.bytes_per_row]
            }
            BufferStorage::Fragmented { rows } => &mut rows[local_row][..self.bytes_per_row],
        }
    }

    #[inline]
    pub fn write_bytes(&mut self, row: usize, col: usize, bytes: &[u8]) {
        let slice = self.row_mut(row);
        slice[col..col + bytes.len()].copy_from_slice(bytes);
    }

    pub fn byte_size(&self) -> (usize, usize) {
        (self.bytes_per_row, self.num_rows)
    }

    /// Split this buffer into non-overlapping row bands.
    ///
    /// `split_rows` contains sorted row indices where splits occur, in the
    /// buffer's own coordinate system (i.e., relative to `self.row_offset`).
    /// Returns one sub-buffer per band: [0, split_rows[0]),
    /// [split_rows[0], split_rows[1]), ..., [split_rows[last], num_rows).
    ///
    /// Each returned sub-buffer has its `row_offset` set so that callers can
    /// use the parent buffer's coordinate system for row access.
    ///
    /// While the returned sub-buffers are alive, `self` cannot be used.
    /// When they are dropped, `self` becomes available again.
    #[cfg(feature = "threads")]
    #[allow(dead_code)] // Parallel row-band splitting for threaded output
    pub(crate) fn split_into_row_bands(
        &mut self,
        split_rows: &[usize],
    ) -> Vec<JxlOutputBuffer<'_>> {
        let bpr = self.bytes_per_row;
        let nrows = self.num_rows;
        let base_offset = self.row_offset;

        match &mut self.storage {
            BufferStorage::Contiguous {
                data,
                bytes_between_rows,
            } => {
                let btr = *bytes_between_rows;
                let mut result = Vec::with_capacity(split_rows.len() + 1);
                let mut remaining: &mut [u8] = data;
                let mut current_row = 0;

                for &split_row in split_rows.iter().chain(std::iter::once(&nrows)) {
                    assert!(
                        split_row >= current_row && split_row <= nrows,
                        "split_rows must be sorted and <= num_rows"
                    );
                    let band_rows = split_row - current_row;

                    if band_rows == 0 {
                        result.push(JxlOutputBuffer {
                            storage: BufferStorage::Contiguous {
                                data: &mut [],
                                bytes_between_rows: btr,
                            },
                            bytes_per_row: bpr,
                            num_rows: 0,
                            row_offset: base_offset + current_row,
                        });
                    } else {
                        let span = (band_rows - 1) * btr + bpr;
                        if split_row < nrows {
                            let total_bytes = band_rows * btr;
                            let tmp = remaining;
                            let (band_full, rest) = tmp.split_at_mut(total_bytes);
                            result.push(JxlOutputBuffer {
                                storage: BufferStorage::Contiguous {
                                    data: &mut band_full[..span],
                                    bytes_between_rows: btr,
                                },
                                bytes_per_row: bpr,
                                num_rows: band_rows,
                                row_offset: base_offset + current_row,
                            });
                            remaining = rest;
                        } else {
                            let tmp = remaining;
                            let (band, _) = tmp.split_at_mut(span);
                            result.push(JxlOutputBuffer {
                                storage: BufferStorage::Contiguous {
                                    data: band,
                                    bytes_between_rows: btr,
                                },
                                bytes_per_row: bpr,
                                num_rows: band_rows,
                                row_offset: base_offset + current_row,
                            });
                            remaining = &mut [];
                        }
                    }
                    current_row = split_row;
                }
                result
            }
            BufferStorage::Fragmented { rows } => {
                let mut result = Vec::with_capacity(split_rows.len() + 1);
                let mut remaining: &mut [&'_ mut [u8]] = rows;
                let mut current_row = 0;

                for &split_row in split_rows.iter().chain(std::iter::once(&nrows)) {
                    assert!(
                        split_row >= current_row && split_row <= nrows,
                        "split_rows must be sorted and <= num_rows"
                    );
                    let band_rows = split_row - current_row;

                    let tmp = remaining;
                    let (band_slice, rest) = tmp.split_at_mut(band_rows);
                    result.push(JxlOutputBuffer {
                        storage: BufferStorage::Fragmented {
                            rows: band_slice.iter_mut().map(|r| &mut **r).collect(),
                        },
                        bytes_per_row: bpr,
                        num_rows: band_rows,
                        row_offset: base_offset + current_row,
                    });
                    remaining = rest;
                    current_row = split_row;
                }
                result
            }
        }
    }

    /// Split this buffer into non-overlapping column fragments.
    ///
    /// `split_cols` contains sorted byte-column positions where splits occur.
    /// Returns one sub-buffer per fragment: [0, split_cols[0]),
    /// [split_cols[0], split_cols[1]), ..., [split_cols[last], bytes_per_row).
    ///
    /// Each returned sub-buffer uses `Fragmented` storage (per-row slices)
    /// since column sub-ranges are not contiguous across rows.
    ///
    /// Preserves `row_offset` so callers can use the parent buffer's coordinate
    /// system for row access.
    #[cfg(feature = "threads")]
    #[allow(dead_code)] // Parallel column-fragment splitting for threaded output
    pub(crate) fn split_into_col_fragments(
        &mut self,
        split_cols: &[usize],
    ) -> Vec<JxlOutputBuffer<'_>> {
        let bpr = self.bytes_per_row;
        let nrows = self.num_rows;
        let base_offset = self.row_offset;
        let num_frags = split_cols.len() + 1;

        // Validate split_cols.
        for (i, &col) in split_cols.iter().enumerate() {
            assert!(col <= bpr, "split_col {col} exceeds bytes_per_row {bpr}");
            if i > 0 {
                assert!(col >= split_cols[i - 1], "split_cols must be sorted");
            }
        }

        // Pre-allocate fragment row collectors.
        let mut fragment_rows: Vec<Vec<&mut [u8]>> =
            (0..num_frags).map(|_| Vec::with_capacity(nrows)).collect();

        match &mut self.storage {
            BufferStorage::Contiguous {
                data,
                bytes_between_rows,
            } => {
                let btr = *bytes_between_rows;
                let mut remaining: &mut [u8] = data;

                for row_idx in 0..nrows {
                    // Always consume via split_at_mut so the borrow checker
                    // sees `remaining` is moved, not aliased.
                    let tmp = remaining;
                    let split_point = if row_idx < nrows - 1 { btr } else { tmp.len() };
                    let (chunk, rest) = tmp.split_at_mut(split_point);
                    remaining = rest;
                    let row_useful = &mut chunk[..bpr];

                    // Split this row into column fragments.
                    let mut col_remaining = row_useful;
                    let mut prev_col = 0;
                    for (frag_idx, &split_col) in split_cols.iter().enumerate() {
                        let width = split_col - prev_col;
                        let (frag, rest) = col_remaining.split_at_mut(width);
                        fragment_rows[frag_idx].push(frag);
                        col_remaining = rest;
                        prev_col = split_col;
                    }
                    fragment_rows[num_frags - 1].push(col_remaining);
                }
            }
            BufferStorage::Fragmented { rows } => {
                for row in rows.iter_mut() {
                    let mut col_remaining: &mut [u8] = row;
                    let mut prev_col = 0;
                    for (frag_idx, &split_col) in split_cols.iter().enumerate() {
                        let width = split_col - prev_col;
                        let (frag, rest) = col_remaining.split_at_mut(width);
                        fragment_rows[frag_idx].push(frag);
                        col_remaining = rest;
                        prev_col = split_col;
                    }
                    fragment_rows[num_frags - 1].push(col_remaining);
                }
            }
        }

        // Build result buffers.
        let mut result = Vec::with_capacity(num_frags);
        let mut prev_col = 0;
        for (frag_idx, rows) in fragment_rows.into_iter().enumerate() {
            let col_end = if frag_idx < split_cols.len() {
                split_cols[frag_idx]
            } else {
                bpr
            };
            let width = col_end - prev_col;
            result.push(JxlOutputBuffer {
                storage: BufferStorage::Fragmented { rows },
                bytes_per_row: width,
                num_rows: nrows,
                row_offset: base_offset,
            });
            prev_col = col_end;
        }
        result
    }

    /// Split this buffer into a 2D grid of fragments (by rows then columns).
    ///
    /// Combines row-band splitting and column-fragment splitting in a single
    /// method to avoid multi-level borrowing. All returned fragments borrow
    /// directly from `self.storage`.
    ///
    /// `split_rows`: sorted row indices where gy bands split.
    /// `split_cols_per_band`: for each band, sorted column indices where gx tiles split.
    ///
    /// Returns `result[band_idx][frag_idx]` where each fragment uses `Fragmented`
    /// storage with `row_offset` set to the band's starting row.
    #[cfg(feature = "threads")]
    pub(crate) fn split_into_tile_grid(
        &mut self,
        split_rows: &[usize],
        split_cols_per_band: &[&[usize]],
    ) -> Vec<Vec<JxlOutputBuffer<'_>>> {
        let bpr = self.bytes_per_row;
        let nrows = self.num_rows;
        let base_offset = self.row_offset;
        let num_bands = split_rows.len() + 1;

        assert_eq!(
            split_cols_per_band.len(),
            num_bands,
            "need one set of split_cols per band"
        );

        let BufferStorage::Contiguous {
            data,
            bytes_between_rows,
        } = &mut self.storage
        else {
            panic!("split_into_tile_grid requires Contiguous storage")
        };
        let btr = *bytes_between_rows;
        let mut remaining: &mut [u8] = data;

        let mut result: Vec<Vec<JxlOutputBuffer<'_>>> = Vec::with_capacity(num_bands);
        let mut current_row = 0;

        for band_idx in 0..num_bands {
            let band_end = if band_idx < split_rows.len() {
                split_rows[band_idx]
            } else {
                nrows
            };
            assert!(
                band_end >= current_row && band_end <= nrows,
                "split_rows must be sorted and <= num_rows"
            );
            let band_rows = band_end - current_row;
            let split_cols = split_cols_per_band[band_idx];
            let num_frags = split_cols.len() + 1;

            // Pre-allocate per-fragment row collectors for this band.
            let mut fragment_rows: Vec<Vec<&mut [u8]>> = (0..num_frags)
                .map(|_| Vec::with_capacity(band_rows))
                .collect();

            for row_offset_in_band in 0..band_rows {
                let is_last_overall_row = current_row + row_offset_in_band == nrows - 1;
                let tmp = remaining;
                let split_point = if is_last_overall_row { tmp.len() } else { btr };
                let (chunk, rest) = tmp.split_at_mut(split_point);
                remaining = rest;
                let row_useful = &mut chunk[..bpr];

                // Split row into column fragments.
                let mut col_remaining = row_useful;
                let mut prev_col = 0;
                for (frag_idx, &split_col) in split_cols.iter().enumerate() {
                    let width = split_col - prev_col;
                    let (frag, rest) = col_remaining.split_at_mut(width);
                    fragment_rows[frag_idx].push(frag);
                    col_remaining = rest;
                    prev_col = split_col;
                }
                fragment_rows[num_frags - 1].push(col_remaining);
            }

            // Build fragment buffers for this band.
            let mut band_frags = Vec::with_capacity(num_frags);
            let mut prev_col = 0;
            for (frag_idx, rows) in fragment_rows.into_iter().enumerate() {
                let col_end = if frag_idx < split_cols.len() {
                    split_cols[frag_idx]
                } else {
                    bpr
                };
                let width = col_end - prev_col;
                band_frags.push(JxlOutputBuffer {
                    storage: BufferStorage::Fragmented { rows },
                    bytes_per_row: width,
                    num_rows: band_rows,
                    row_offset: base_offset + current_row,
                });
                prev_col = col_end;
            }
            result.push(band_frags);
            current_row = band_end;
        }
        result
    }

    pub fn rect(&mut self, rect: Rect) -> JxlOutputBuffer<'_> {
        if rect.size.0 == 0 || rect.size.1 == 0 {
            return JxlOutputBuffer {
                storage: BufferStorage::Contiguous {
                    data: &mut [],
                    bytes_between_rows: 0,
                },
                bytes_per_row: 0,
                num_rows: 0,
                row_offset: 0,
            };
        }
        assert!(
            rect.origin.1 >= self.row_offset,
            "rect origin row {} < row_offset {}",
            rect.origin.1,
            self.row_offset,
        );
        let local_y = rect.origin.1 - self.row_offset;
        assert!(local_y + rect.size.1 <= self.num_rows);
        assert!(rect.origin.0 + rect.size.0 <= self.bytes_per_row);

        match &mut self.storage {
            BufferStorage::Contiguous {
                data,
                bytes_between_rows,
            } => {
                let btr = *bytes_between_rows;
                let new_start = local_y * btr + rect.origin.0;
                let data_span = (rect.size.1 - 1) * btr + rect.size.0;
                assert!(new_start + data_span <= data.len());
                JxlOutputBuffer {
                    storage: BufferStorage::Contiguous {
                        data: &mut data[new_start..new_start + data_span],
                        bytes_between_rows: btr,
                    },
                    bytes_per_row: rect.size.0,
                    num_rows: rect.size.1,
                    // Child views from rect() are always 0-based.
                    row_offset: 0,
                }
            }
            BufferStorage::Fragmented { rows } => {
                let col_start = rect.origin.0;
                let col_end = col_start + rect.size.0;
                let sub_rows: Vec<&mut [u8]> = rows[local_y..local_y + rect.size.1]
                    .iter_mut()
                    .map(|row| &mut row[col_start..col_end])
                    .collect();
                JxlOutputBuffer {
                    storage: BufferStorage::Fragmented { rows: sub_rows },
                    bytes_per_row: rect.size.0,
                    num_rows: rect.size.1,
                    // Child views from rect() are always 0-based.
                    row_offset: 0,
                }
            }
        }
    }
}

impl Debug for JxlOutputBuffer<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "JxlOutputBuffer {}x{}",
            self.bytes_per_row, self.num_rows
        )
    }
}
