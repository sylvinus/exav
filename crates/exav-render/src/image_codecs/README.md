# JPEG and TIFF decoders, vendored

The ClamAV preset hashes the pixels `image` 0.25.9 decodes, the version ClamAV
1.4.6 and 1.5.4 ship, so that a hash equals `sigtool --fuzzy-img`'s. For JPEG and
for JPEG-compressed TIFF, `image` and `tiff` decode with zune-jpeg 0.5.8 and
0.4.21, depending on them with their default features, which include its SIMD
code (IDCT, upsampling and colour conversion for AVX2 and NEON), all of its
`unsafe`, chosen at run time. Nothing downstream can turn those features off.

So `image` is built without its `jpeg` and `tiff` features, and this module
holds what it would have run, over zune-jpeg built with `std` only, where it
applies `forbid(unsafe_code)`:

- `jpeg.rs` is `image`'s JPEG decoder (`src/codecs/jpeg/decoder.rs`).
- `tiff_image.rs` is `image`'s TIFF decoder (`src/codecs/tiff.rs`, with the
  `expand_bits` it calls from `src/utils/mod.rs`).
- `tiff/` is the decoder of `tiff` 0.10.3, the version `image` 0.25.9
  resolves to.
- `mod.rs`'s `decode` is what `ImageReader::decode` does with a decoder.

`image` is MIT OR Apache-2.0 (`LICENSE-image` is its MIT text) and `tiff` MIT
(`tiff/LICENSE`).

## What differs from upstream

`jpeg.rs` and `tiff_image.rs` keep only what decoding uses (no ICC, EXIF, XMP
or orientation accessors, which `ImageReader::decode` does not call), turn
`image`'s private helpers (`ImageError::from_jpeg`, `ImageError::from_tiff_decode`,
`ColorType::from_jpeg`, `utils::expand_bits`) into functions of their own, and
`JpegDecoder` borrows its input where upstream copies it.

`tiff/` is upstream's `src/` without the encoder, and otherwise:

- `lib.rs` is `mod.rs`, and `crate::` is `crate::image_codecs::tiff::`.
- The features are fixed at what `image` enables: `deflate`, `fax`, `jpeg` and
  `lzw` are `true`, `zstd` is `false`.
- zune-jpeg 0.4 is the dependency `zune-jpeg-04`, so `zune_jpeg::` is
  `zune_jpeg_04::`.
- `bytecast.rs` casts through `bytemuck` instead of two `unsafe` slice casts,
  which this crate forbids, and `f16` through `half`'s view of its bits.
- `decoder/image.rs`: `samples.into()` is `usize::from(samples)`, which type
  inference cannot find ambiguous whatever else the dependency graph holds.

`tiff/` skips rustfmt and the lints.

Checked: over 9,751 JPEGs and 372 TIFFs in 31 encodings (none, LZW, Deflate
and PackBits, with and without predictors, strips and tiles, JPEG as RGB, grey
and CMYK, fax, 1, 8, 16 and 32-bit, alpha, CMYK, big-endian), every hash
equals `sigtool --fuzzy-img`'s from ClamAV 1.5.4, and the images it cannot
hash have none here either.

## Going back to `image`'s own decoders

If `image` and `tiff` come to depend on zune-jpeg without its default
features, or zune-jpeg makes its SIMD code opt-in: delete this directory and
`mod image_codecs` in `lib.rs`, put `jpeg` and `tiff` back in `image`'s
features in `Cargo.toml` and drop the dependencies listed under it, and decode
JPEG and TIFF through `image::ImageReader` in `lib.rs`'s `decode`.
