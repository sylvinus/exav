// Copyright (c) the JPEG XL Project Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Fallible and aligned allocation utilities for safe, OOM-resistant decoding.
//!
//! This module provides:
//! - `NewWithCapacity` trait for fallible `Vec` and `String` allocation
//! - `AlignedVec` type alias for SIMD-aligned allocations (64-byte alignment for AVX-512)
//! - Helper functions for creating aligned vectors with fallible allocation

use aligned_vec::{AVec, ConstAlign};
use std::collections::TryReserveError;

/// Alignment for SIMD operations (64 bytes for AVX-512 compatibility).
#[allow(dead_code)] // SIMD alignment infrastructure
pub const SIMD_ALIGN: usize = 64;

/// Type alias for AVX-512-aligned vectors.
/// Uses 64-byte alignment which is compatible with all x86 SIMD (SSE, AVX, AVX-512)
/// and ARM NEON (which only requires 16-byte alignment).
#[allow(dead_code)] // SIMD alignment infrastructure
pub type AlignedVec<T> = AVec<T, ConstAlign<SIMD_ALIGN>>;

/// Creates a new aligned vector with the given capacity, returning an error on allocation failure.
#[allow(dead_code)] // SIMD alignment infrastructure
pub fn aligned_vec_with_capacity<T>(capacity: usize) -> Result<AlignedVec<T>, TryReserveError> {
    // AVec doesn't have try_with_capacity, so we create empty and try_reserve
    let mut vec = AVec::new(SIMD_ALIGN);
    // Note: AVec's try_reserve returns a different error type, so we allocate
    // conservatively by checking if the allocation would be too large
    let size_bytes = capacity.checked_mul(std::mem::size_of::<T>());
    if size_bytes.is_none() || size_bytes.unwrap() > isize::MAX as usize {
        // This would fail allocation - return a synthetic TryReserveError
        // by trying to allocate on a regular Vec which will fail the same way
        let mut dummy: Vec<T> = Vec::new();
        dummy.try_reserve(capacity)?;
    }
    vec.reserve(capacity);
    Ok(vec)
}

/// Creates a new aligned vector filled with zeros.
#[allow(dead_code)] // SIMD alignment infrastructure
pub fn aligned_vec_zeroed<T: Default + Clone>(
    len: usize,
) -> Result<AlignedVec<T>, TryReserveError> {
    let mut vec = aligned_vec_with_capacity(len)?;
    vec.resize(len, T::default());
    Ok(vec)
}

// TODO(firsching): as soon as "Vec::try_with_capacity" is available from the
// standard library use this instead of the functions here.
pub trait NewWithCapacity {
    type Output;
    type Error;
    fn new_with_capacity(capacity: usize) -> Result<Self::Output, Self::Error>;
}

impl<T> NewWithCapacity for Vec<T> {
    type Output = Vec<T>;
    type Error = TryReserveError;

    fn new_with_capacity(capacity: usize) -> Result<Self::Output, Self::Error> {
        let mut vec = Vec::new();
        vec.try_reserve(capacity)?;
        Ok(vec)
    }
}

impl NewWithCapacity for String {
    type Output = String;
    type Error = TryReserveError;
    fn new_with_capacity(capacity: usize) -> Result<Self::Output, Self::Error> {
        let mut s = String::new();
        s.try_reserve(capacity)?;
        Ok(s)
    }
}

/// Extension trait for fallible vector operations.
pub trait TryVecExt<T> {
    /// Try to create a vector filled with copies of `value`.
    fn try_from_elem(value: T, count: usize) -> Result<Vec<T>, TryReserveError>
    where
        T: Clone;

    /// Try to extend the vector from an iterator, reserving capacity first.
    #[allow(dead_code)]
    fn try_extend_from_slice(&mut self, slice: &[T]) -> Result<(), TryReserveError>
    where
        T: Clone;
}

impl<T> TryVecExt<T> for Vec<T> {
    fn try_from_elem(value: T, count: usize) -> Result<Vec<T>, TryReserveError>
    where
        T: Clone,
    {
        let mut vec = Vec::new();
        vec.try_reserve(count)?;
        vec.resize(count, value);
        Ok(vec)
    }

    fn try_extend_from_slice(&mut self, slice: &[T]) -> Result<(), TryReserveError>
    where
        T: Clone,
    {
        self.try_reserve(slice.len())?;
        self.extend_from_slice(slice);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aligned_vec_with_capacity() {
        let vec: AlignedVec<f32> = aligned_vec_with_capacity(1024).unwrap();
        assert!((vec.as_ptr() as usize).is_multiple_of(SIMD_ALIGN));
    }

    #[test]
    fn test_aligned_vec_zeroed() {
        let vec: AlignedVec<f32> = aligned_vec_zeroed(1024).unwrap();
        assert_eq!(vec.len(), 1024);
        assert!(vec.iter().all(|&x| x == 0.0));
        assert!((vec.as_ptr() as usize).is_multiple_of(SIMD_ALIGN));
    }

    #[test]
    fn test_try_from_elem() {
        let vec = Vec::<u8>::try_from_elem(42, 100).unwrap();
        assert_eq!(vec.len(), 100);
        assert!(vec.iter().all(|&x| x == 42));
    }
}
