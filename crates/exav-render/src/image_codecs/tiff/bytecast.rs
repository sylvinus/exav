//! Trivial, internal byte transmutation.
//!
//! exav: through `bytemuck` instead of upstream's `unsafe` slice casts, which
//! exav-core forbids. The same casts, of fixed-size numbers to their bytes;
//! `f16` goes through its bits, as `half` gives them.
// Until we implement predictors for f16, we don't need f16_as_ne_bytes. (Due to the macro we do
// not apply this directly to the functions). And rust-version is not new enough for `expect`.
#![allow(dead_code)]
use half::f16;
use half::slice::HalfFloatSliceExt;

macro_rules! integral_slice_as_bytes{($int:ty, $const:ident $(,$mut:ident)*) => {
    pub(crate) fn $const(slice: &[$int]) -> &[u8] {
        bytemuck::cast_slice(slice)
    }
    $(pub(crate) fn $mut(slice: &mut [$int]) -> &mut [u8] {
        bytemuck::cast_slice_mut(slice)
    })*
}}

integral_slice_as_bytes!(i8, i8_as_ne_bytes, i8_as_ne_mut_bytes);
integral_slice_as_bytes!(u16, u16_as_ne_bytes, u16_as_ne_mut_bytes);
integral_slice_as_bytes!(i16, i16_as_ne_bytes, i16_as_ne_mut_bytes);
integral_slice_as_bytes!(u32, u32_as_ne_bytes, u32_as_ne_mut_bytes);
integral_slice_as_bytes!(i32, i32_as_ne_bytes, i32_as_ne_mut_bytes);
integral_slice_as_bytes!(u64, u64_as_ne_bytes, u64_as_ne_mut_bytes);
integral_slice_as_bytes!(i64, i64_as_ne_bytes, i64_as_ne_mut_bytes);
integral_slice_as_bytes!(f32, f32_as_ne_bytes, f32_as_ne_mut_bytes);
pub(crate) fn f16_as_ne_bytes(slice: &[f16]) -> &[u8] {
    bytemuck::cast_slice(slice.reinterpret_cast())
}
pub(crate) fn f16_as_ne_mut_bytes(slice: &mut [f16]) -> &mut [u8] {
    bytemuck::cast_slice_mut(slice.reinterpret_cast_mut())
}
integral_slice_as_bytes!(f64, f64_as_ne_bytes, f64_as_ne_mut_bytes);
