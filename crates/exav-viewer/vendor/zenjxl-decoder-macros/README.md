# zenjxl-decoder [![CI](https://img.shields.io/github/actions/workflow/status/imazen/zenjxl-decoder/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/imazen/zenjxl-decoder/actions/workflows/ci.yml) [![crates.io](https://img.shields.io/crates/v/zenjxl-decoder?style=flat-square)](https://crates.io/crates/zenjxl-decoder) [![docs.rs](https://img.shields.io/docsrs/zenjxl-decoder?style=flat-square)](https://docs.rs/zenjxl-decoder) [![MSRV](https://img.shields.io/badge/MSRV-1.89-blue?style=flat-square)](https://doc.rust-lang.org/cargo/reference/manifest.html#the-rust-version-field) [![license](https://img.shields.io/crates/l/zenjxl-decoder?style=flat-square)](https://github.com/imazen/zenjxl-decoder#license)

A JPEG XL decoder in safe Rust. Fork of [libjxl/jxl-rs](https://github.com/libjxl/jxl-rs) with security hardening, bug fixes, and parallel decoding.

Maintained by [Lilith River](https://github.com/lilith) at [Imazen](https://github.com/imazen).

```toml
[dependencies]
zenjxl-decoder = "0.3"
```

The Rust lib name is `jxl`, so you `use jxl::...` in code.

If you find a conformant JXL file that decodes incorrectly (or not at all), [open an issue](https://github.com/imazen/zenjxl-decoder/issues/new).

## What's different from upstream

This fork fixes several decoding bugs, adds resource limits and cooperative cancellation, and wires up parallel decoding via rayon. All changes are BSD-3-Clause licensed under the Google CLA, intended for upstream contribution.

### Bug Fixes

| Bug | Description |
|-----|-------------|
| sRGB Transfer Function | Apply sRGB TF by default for XYB-encoded images (was outputting linear) |
| RCT Overflow Panic | Wrapping arithmetic to prevent panic on edge-case pixel values |
| Extra Channel Format Slots | Allocate format slots for all extra channels, not just first |
| Progressive AC Validation | Fix inverted `last_pass` validation (must be strictly increasing) |
| Extra Channel Bit Depth | Use extra channel's own `bit_depth` for modular-to-f32 conversion |
| Noise Seeding (upsampling > 1) | Separate RNG seeds per subregion for upsampled frames |
| CMYK Blending Order | Blend in CMYK space, then CMS-convert to RGB |

### New Features

| Feature | Description |
|---------|-------------|
| CMS-based CMYK to RGB | ICC profile-based CMYK conversion via optional `moxcms` backend |
| Cooperative cancellation | `enough::Stop` trait — cancel or timeout decoding from any thread |
| Resource limits | `JxlDecoderLimits` API — cap pixels, memory, ICC size, tree size, etc. |
| Memory tracking | `max_memory_bytes` budget with atomic, lock-free tracking |
| Fallible allocation | All significant allocations return `TryReserveError` instead of panicking |
| Parallel decoding | Rayon-based parallel group decode and render (opt-in via `threads` feature) |

## Usage

### Basic decode

```rust
use jxl::api::{JxlDecoder, JxlDecoderOptions};

let data = std::fs::read("image.jxl")?;
let mut decoder = JxlDecoder::new(&data, JxlDecoderOptions::default());
// ... process frames
```

### Resource limits

```rust
use jxl::api::{JxlDecoderLimits, JxlDecoderOptions};

// For untrusted input
let options = JxlDecoderOptions {
    limits: JxlDecoderLimits::restrictive(),
    ..Default::default()
};
```

| Limit | Default | Restrictive |
|-------|---------|-------------|
| `max_pixels` | 2^30 (~1B) | 100M |
| `max_extra_channels` | 256 | 16 |
| `max_icc_size` | 256 MB | 1 MB |
| `max_tree_size` | 4M nodes | 1M nodes |
| `max_patches` | (derived) | 64K |
| `max_spline_points` | 1M | 64K |
| `max_reference_frames` | 4 | 2 |
| `max_memory_bytes` | None | 1 GB |

All limits return `Error::LimitExceeded { resource, actual, limit }` when exceeded.

### Cancellation

The decoder accepts any [`enough::Stop`](https://docs.rs/enough) implementation:

```rust
use almost_enough::Stopper;
use std::sync::Arc;

let stop = Arc::new(Stopper::new());
let stop_clone = Arc::clone(&stop);

// Cancel from another thread
std::thread::spawn(move || {
    std::thread::sleep(std::time::Duration::from_secs(5));
    stop_clone.cancel();
});

let options = JxlDecoderOptions {
    stop,
    ..Default::default()
};
```

Cancellation checks run inside parallel closures too, so a cancel request is noticed mid-batch.

### Parallel decoding

Enable the `threads` feature (on by default in `jxl_cli`):

```toml
[dependencies]
zenjxl-decoder = { version = "0.3", features = ["threads"] }
```

Set `parallel: false` on `JxlDecoderOptions` to force single-threaded mode at runtime.

## Features

| Feature | Description |
|---------|-------------|
| `threads` | Rayon-based parallel group decode and render |
| `cms` | moxcms CMS backend for ICC profile transforms |
| `jpeg` | JPEG reconstruction from JXL containers |
| `all-simd` | All SIMD backends (SSE4.2, AVX2, AVX-512, NEON, WASM128) |
| `sse42` / `avx` / `avx512` / `neon` / `wasm128` | Individual SIMD targets |
| `allow-unsafe` | Enable `unsafe` fast paths in the main crate (safe fallbacks used otherwise) |

## Conformance

Against [libjxl/conformance](https://github.com/libjxl/conformance) test suite (Level 5): **17/23 passing** (74%, as of December 2025).

```bash
cargo test --features cms conformance -- --ignored --nocapture
```

| Status | Tests |
|--------|-------|
| Pass | alpha_nonpremultiplied, alpha_triangles, bench_oriented_brg_5, bicycles, blendmodes_5, cafe_5, delta_palette, grayscale_5, grayscale_jpeg_5, grayscale_public_university, lz77_flower, noise_5, opsin_inverse_5, patches_5, patches_lossless, sunset_logo, upsampling_5 |
| Skip | animation_icos4d_5, animation_newtons_cradle, animation_spline_5 (animation rendering not yet supported; animation metadata parsing is available via `JxlImageInfo::animation`) |
| Fail | bike_5, progressive_5 (out-of-gamut/HDR values), spot (6-channel output not yet supported) |

Against codec-corpus (184 JXL files with djxl reference output): **184/184 passing** (100%, as of December 2025).

## Upstream Contributions

Bug fixes reported to [libjxl/jxl-rs](https://github.com/libjxl/jxl-rs):

| # | Type | Status | Description |
|---|------|--------|-------------|
| [#607](https://github.com/libjxl/jxl-rs/pull/607) | PR | Merged | ICC tag parsing overflow fix |
| [#637](https://github.com/libjxl/jxl-rs/pull/637) | PR | Merged | Extra channel bit_depth fix (from our [#604](https://github.com/libjxl/jxl-rs/pull/604)) |
| [#632](https://github.com/libjxl/jxl-rs/pull/632) | PR | Merged | RCT wrapping arithmetic (from our [#603](https://github.com/libjxl/jxl-rs/pull/603)) |
| [#609](https://github.com/libjxl/jxl-rs/issues/609) | Issue | Fixed | Progressive AC last_pass validation bug |
| [#610](https://github.com/libjxl/jxl-rs/issues/610) | Issue | Fixed | Noise seeding wrong when upsampling > 1 |
| [#660](https://github.com/libjxl/jxl-rs/pull/660) | PR | Open | Conformance test infrastructure |
| [#602](https://github.com/libjxl/jxl-rs/pull/602) | PR | Closed | Integer overflow handling (ICC part merged as #607; rest declined) |

## Sister project

[jxl-encoder](https://github.com/imazen/jxl-encoder) — a multithreaded JPEG XL encoder in Rust, also by Imazen.

## Image tech I maintain

| | |
|:--|:--|
| State of the art codecs* | [zenjpeg] · [zenpng] · [zenwebp] · [zengif] · [zenavif] ([rav1d-safe] · [zenrav1e] · [zenavif-parse] · [zenavif-serialize]) · [zenjxl] ([jxl-encoder] · **zenjxl-decoder**) · [zentiff] · [zenbitmaps] · [heic] · [zenraw] · [zenpdf] · [ultrahdr] · [mozjpeg-rs] · [webpx] |
| Compression | [zenflate] · [zenzop] |
| Processing | [zenresize] · [zenfilters] · [zenquant] · [zenblend] |
| Metrics | [zensim] · [fast-ssim2] · [butteraugli] · [resamplescope-rs] · [codec-eval] · [codec-corpus] |
| Pixel types & color | [zenpixels] · [zenpixels-convert] · [linear-srgb] · [garb] |
| Pipeline | [zenpipe] · [zencodec] · [zencodecs] · [zenlayout] · [zennode] |
| ImageResizer | [ImageResizer] (C#) — 24M+ NuGet downloads across all packages |
| [Imageflow][] | Image optimization engine (Rust) — [.NET][imageflow-dotnet] · [node][imageflow-node] · [go][imageflow-go] — 9M+ NuGet downloads across all packages |
| [Imageflow Server][] | [The fast, safe image server](https://www.imazen.io/) (Rust+C#) — 552K+ NuGet downloads, deployed by Fortune 500s and major brands |

<sub>* as of 2026</sub>

### General Rust awesomeness

[archmage] · [magetypes] · [enough] · [whereat] · [zenbench] · [cargo-copter]

[And other projects](https://www.imazen.io/open-source) · [GitHub @imazen](https://github.com/imazen) · [GitHub @lilith](https://github.com/lilith) · [lib.rs/~lilith](https://lib.rs/~lilith) · [NuGet](https://www.nuget.org/profiles/imazen) (over 30 million downloads / 87 packages)

## License

BSD-3-Clause. See [LICENSE](LICENSE).



### Upstream Contribution

This is a fork of [libjxl/jxl-rs](https://github.com/libjxl/jxl-rs) (BSD-3-Clause).
We are willing to release our improvements under the original BSD-3-Clause
license if upstream takes over maintenance of those improvements. We'd rather
contribute back than maintain a parallel codebase. Open an issue or reach out.

[zenjpeg]: https://github.com/imazen/zenjpeg
[zenpng]: https://github.com/imazen/zenpng
[zenwebp]: https://github.com/imazen/zenwebp
[zengif]: https://github.com/imazen/zengif
[zenavif]: https://github.com/imazen/zenavif
[zenjxl]: https://github.com/imazen/zenjxl
[zentiff]: https://github.com/imazen/zentiff
[zenbitmaps]: https://github.com/imazen/zenbitmaps
[heic]: https://github.com/imazen/heic-decoder-rs
[zenraw]: https://github.com/imazen/zenraw
[zenpdf]: https://github.com/imazen/zenpdf
[ultrahdr]: https://github.com/imazen/ultrahdr
[jxl-encoder]: https://github.com/imazen/jxl-encoder
[rav1d-safe]: https://github.com/imazen/rav1d-safe
[zenrav1e]: https://github.com/imazen/zenrav1e
[mozjpeg-rs]: https://github.com/imazen/mozjpeg-rs
[zenavif-parse]: https://github.com/imazen/zenavif-parse
[zenavif-serialize]: https://github.com/imazen/zenavif-serialize
[webpx]: https://github.com/imazen/webpx
[zenflate]: https://github.com/imazen/zenflate
[zenzop]: https://github.com/imazen/zenzop
[zenresize]: https://github.com/imazen/zenresize
[zenfilters]: https://github.com/imazen/zenfilters
[zenquant]: https://github.com/imazen/zenquant
[zenblend]: https://github.com/imazen/zenblend
[zensim]: https://github.com/imazen/zensim
[fast-ssim2]: https://github.com/imazen/fast-ssim2
[butteraugli]: https://github.com/imazen/butteraugli
[zenpixels]: https://github.com/imazen/zenpixels
[zenpixels-convert]: https://github.com/imazen/zenpixels
[linear-srgb]: https://github.com/imazen/linear-srgb
[garb]: https://github.com/imazen/garb
[zenpipe]: https://github.com/imazen/zenpipe
[zencodec]: https://github.com/imazen/zencodec
[zencodecs]: https://github.com/imazen/zencodecs
[zenlayout]: https://github.com/imazen/zenlayout
[zennode]: https://github.com/imazen/zennode
[Imageflow]: https://github.com/imazen/imageflow
[Imageflow Server]: https://github.com/imazen/imageflow-server
[imageflow-dotnet]: https://github.com/imazen/imageflow-dotnet
[imageflow-node]: https://github.com/imazen/imageflow-node
[imageflow-go]: https://github.com/imazen/imageflow-go
[ImageResizer]: https://github.com/imazen/resizer
[archmage]: https://github.com/imazen/archmage
[magetypes]: https://github.com/imazen/archmage
[enough]: https://github.com/imazen/enough
[whereat]: https://github.com/lilith/whereat
[zenbench]: https://github.com/imazen/zenbench
[cargo-copter]: https://github.com/imazen/cargo-copter
[resamplescope-rs]: https://github.com/imazen/resamplescope-rs
[codec-eval]: https://github.com/imazen/codec-eval
[codec-corpus]: https://github.com/imazen/codec-corpus
