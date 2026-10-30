// Copyright (c) the JPEG XL Project Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! A JPEG XL decoder in safe Rust.
//!
//! `zenjxl-decoder` is a pure-Rust decoder for the JPEG XL bitstream format
//! (ISO/IEC 18181). It is a fork of the upstream
//! [`libjxl/jxl-rs`](https://github.com/libjxl/jxl-rs) reference decoder,
//! which in turn tracks the C++ [`libjxl`](https://github.com/libjxl/libjxl)
//! implementation. Upstream remains the source of truth for codec behaviour;
//! this fork adds resource limits, cooperative cancellation, parallel decode,
//! and a handful of bug fixes and hardening changes on top.
//!
//! # Crate layout
//!
//! Most users only need the [`api`] module:
//!
//! ```no_run
//! use zenjxl_decoder::api::decode;
//!
//! let bytes = std::fs::read("image.jxl").unwrap();
//! let image = decode(&bytes).unwrap();
//! ```
//!
//! Pass [`api::JxlDecoderOptions`] to [`api::decode_with`] to configure
//! resource limits, cancellation, or colour conversion.
//!
//! # SIMD
//!
//! Multi-architecture SIMD (SSE4.2, AVX2, AVX-512, NEON, WASM128) lives in
//! the companion [`zenjxl-decoder-simd`](https://crates.io/crates/zenjxl-decoder-simd)
//! crate and is enabled via the `all-simd` feature (or per-ISA features such
//! as `avx`, `neon`, `wasm128`). Dispatch is runtime, via
//! [`archmage`](https://crates.io/crates/archmage).
//!
//! # Safety
//!
//! The main `jxl` crate is `#![forbid(unsafe_code)]` by default. Enabling the
//! `allow-unsafe` feature opts into a small set of `unsafe` fast paths guarded
//! by safe fallbacks.
//!
//! # Features
//!
//! - `threads` -- rayon-based parallel group decode and render.
//! - `cms` -- [`moxcms`](https://crates.io/crates/moxcms) ICC profile transforms
//!   (required for CMYK input).
//! - `jpeg` -- lossless JPEG reconstruction from JXL containers.
//! - `all-simd` / `sse42` / `avx` / `avx512` / `neon` / `wasm128` -- SIMD backends.
//! - `allow-unsafe` -- opt in to `unsafe` fast paths.
//!
//! # License
//!
//! BSD-3-Clause, matching upstream [`libjxl/jxl-rs`](https://github.com/libjxl/jxl-rs).

#![cfg_attr(not(feature = "allow-unsafe"), forbid(unsafe_code))]
#![cfg_attr(feature = "allow-unsafe", deny(unsafe_code))]

pub mod api;
pub use api::{decode, decode_with, read_header, read_header_with};
#[cfg(feature = "jpeg")]
pub use api::{reconstruct_jpeg, reconstruct_jpeg_with};
pub(crate) mod bit_reader;
pub(crate) mod color;
pub(crate) mod container;
pub(crate) mod entropy_coding;
pub(crate) mod error;
pub(crate) mod features;
pub(crate) mod frame;
pub(crate) mod headers;
pub(crate) mod icc;
pub(crate) mod image;
pub(crate) mod render;
pub(crate) mod transforms;
pub(crate) mod util;

#[cfg(feature = "jpeg")]
pub(crate) mod jpeg;

#[cfg(test)]
mod tests;

// TODO: Move these to a more appropriate location.
const GROUP_DIM: usize = 256;
const BLOCK_DIM: usize = 8;
const BLOCK_SIZE: usize = BLOCK_DIM * BLOCK_DIM;
#[allow(clippy::excessive_precision)]
const MIN_SIGMA: f32 = -3.90524291751269967465540850526868;
