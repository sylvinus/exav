// Copyright (c) the JPEG XL Project Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use crate::image::ImageDataType;

pub const CACHE_LINE_BYTE_SIZE: usize = 64;

pub const fn num_per_cache_line<T>() -> usize {
    // Post-mono check that T is smaller than a cache line and has size a power of 2.
    // This prevents some of the silliest mistakes.
    const {
        assert!(std::mem::size_of::<T>() <= CACHE_LINE_BYTE_SIZE);
        assert!(std::mem::size_of::<T>().is_power_of_two());
    }
    CACHE_LINE_BYTE_SIZE / std::mem::size_of::<T>()
}

#[allow(dead_code)] // Used by SimpleRenderPipeline (test infrastructure)
pub fn round_up_size_to_cache_line<T>(size: usize) -> usize {
    let n = const { num_per_cache_line::<T>() };
    size.div_ceil(n) * n
}

#[derive(Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C, align(64))]
pub struct CacheLine([u8; CACHE_LINE_BYTE_SIZE]);

impl Default for CacheLine {
    fn default() -> Self {
        CacheLine([0; CACHE_LINE_BYTE_SIZE])
    }
}

#[inline(always)]
pub fn slice_from_cachelines<T: ImageDataType>(slice: &[CacheLine]) -> &[T] {
    const { assert!(64usize.is_multiple_of(std::mem::align_of::<T>())) };
    const { assert!(CACHE_LINE_BYTE_SIZE.is_multiple_of(std::mem::size_of::<T>())) };
    const { assert!(CACHE_LINE_BYTE_SIZE == 64) };
    // CacheLine: Pod, T: Pod (via ImageDataType) — safe transmutation via bytemuck.
    // CacheLine is 64-byte aligned which satisfies T's alignment requirements.
    bytemuck::cast_slice(bytemuck::cast_slice::<CacheLine, u8>(slice))
}

#[inline(always)]
pub fn slice_from_cachelines_mut<T: ImageDataType>(slice: &mut [CacheLine]) -> &mut [T] {
    const { assert!(64usize.is_multiple_of(std::mem::align_of::<T>())) };
    const { assert!(CACHE_LINE_BYTE_SIZE.is_multiple_of(std::mem::size_of::<T>())) };
    const { assert!(CACHE_LINE_BYTE_SIZE == 64) };
    bytemuck::cast_slice_mut(bytemuck::cast_slice_mut::<CacheLine, u8>(slice))
}
