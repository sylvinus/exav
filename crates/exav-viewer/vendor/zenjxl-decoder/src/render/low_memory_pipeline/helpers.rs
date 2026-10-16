// Copyright (c) the JPEG XL Project Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use crate::render::low_memory_pipeline::render_group::ChannelVec;

/// Returns a vector of &mut vals[idx[i].0][idx[i].1], in order of idx[i].2.
/// Panics if any of the indices are out of bounds or
/// (idx[i].0, idx[i].1) == (idx[j].0, idx[j].1) for i != j or indices are not
/// sorted lexicographically.
#[cfg(feature = "allow-unsafe")]
#[inline]
#[allow(unsafe_code)]
pub(super) fn get_distinct_indices<'a, T>(
    vals: &'a mut [impl AsMut<[T]>],
    idx: &[(usize, usize, usize)],
) -> ChannelVec<&'a mut T> {
    let mut answer_buffer: ChannelVec<Option<&'a mut T>> = ChannelVec::new();
    for _ in 0..idx.len() {
        answer_buffer.push(None);
    }

    let mut prev_outer = usize::MAX;
    let mut prev_inner = usize::MAX;
    for &(outer, inner, pos) in idx {
        assert!(
            prev_outer == usize::MAX
                || outer > prev_outer
                || (outer == prev_outer && inner > prev_inner),
            "indices must be sorted and distinct"
        );
        prev_outer = outer;
        prev_inner = inner;

        let buf = vals[outer].as_mut();
        assert!(inner < buf.len(), "inner index out of bounds");
        // SAFETY: indices are guaranteed distinct (no two (outer, inner) pairs are equal),
        // so each &mut T points to a different element. We use raw pointers to avoid
        // the borrow checker's inability to prove non-aliasing across loop iterations.
        // Both pointer operations share this single safety justification.
        let ptr = unsafe { buf.as_mut_ptr().add(inner) };
        // SAFETY: `ptr` is in-bounds (asserted above) and unique (indices are distinct).
        answer_buffer[pos] = Some(unsafe { &mut *ptr });
    }

    answer_buffer
        .into_iter()
        .map(|x| x.expect("Not all elements were found"))
        .collect()
}

/// Safe fallback using split_at_mut to avoid aliasing mutable references.
#[cfg(not(feature = "allow-unsafe"))]
#[inline]
pub(super) fn get_distinct_indices<'a, T>(
    vals: &'a mut [impl AsMut<[T]>],
    idx: &[(usize, usize, usize)],
) -> ChannelVec<&'a mut T> {
    let mut answer: ChannelVec<Option<&'a mut T>> = ChannelVec::new();
    for _ in 0..idx.len() {
        answer.push(None);
    }

    // Process each outer slice using split_at_mut to safely extract elements.
    for (outer_idx, outer_val) in vals.iter_mut().enumerate() {
        let mut remaining = outer_val.as_mut();
        let mut base = 0usize;
        for &(outer, inner, pos) in idx {
            if outer != outer_idx {
                continue;
            }
            debug_assert!(inner >= base, "indices must be sorted within each outer");
            let (_, rest) = remaining.split_at_mut(inner - base);
            let (element, after) = rest.split_first_mut().unwrap();
            answer[pos] = Some(element);
            remaining = after;
            base = inner + 1;
        }
    }

    answer
        .into_iter()
        .map(|x| x.expect("Not all elements were found"))
        .collect()
}
