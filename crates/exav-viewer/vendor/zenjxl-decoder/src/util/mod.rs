// Copyright (c) the JPEG XL Project Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#[cfg(test)]
pub mod test;

// Re-export AtomicRefCell from the atomic_refcell crate (replaces custom implementation)
mod bits;
mod cacheline;
mod clock;
mod concat_slice;
mod fast_math;
mod float16;
mod linalg;
mod log2;
mod memory_tracker;
mod mirror;
pub mod ndarray;
pub mod profiling;
mod rational_poly;
mod shift_right_ceil;
// Re-export SmallVec from the smallvec crate (replaces custom implementation)
pub mod tracing_wrappers;
mod vec_helpers;
mod xorshift128plus;

pub use atomic_refcell::{AtomicRef, AtomicRefCell, AtomicRefMut};
pub use bits::*;
pub use cacheline::*;
pub use clock::Instant;
pub use fast_math::*;
pub use float16::f16;
pub use linalg::*;
pub use log2::*;
pub use memory_tracker::*;
pub use mirror::*;
pub(crate) use ndarray::*;
#[allow(unused_imports)]
pub use profiling::*;
pub use rational_poly::*;
pub use shift_right_ceil::*;
pub use smallvec::SmallVec;
pub use vec_helpers::*;
pub use xorshift128plus::*;
