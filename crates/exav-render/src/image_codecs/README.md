# JPEG and TIFF decoders, vendored

The ClamAV preset hashes the pixels `image` 0.25.9 decodes, the version ClamAV
1.4.6 and 1.5.4 ship, so that a hash equals `sigtool --fuzzy-img`'s. For JPEG and
for JPEG-compressed TIFF, `image` and `tiff` decode with zune-jpeg 0.5.8 and
0.4.21, depending on them with their default features, which include its SIMD
code (IDCT, upsampling and colour conversion for AVX2 and NEON), all of its
`unsafe`, chosen at run time. Nothing downstream can turn those features off.

The JPEG path here runs zune-jpeg **0.5.15**, not 0.5.8: ClamAV is not a
reference to track version by version, and 0.5.8 panics on damaged files
(sampling factors that do not nest, in its upsampler) that 0.5.15 decodes. On
532 JPEGs (every chroma subsampling, quality 10 to 100, progressive, restart
markers, odd sizes, grey, and the fixtures and wild files) the two give the same
hash for all but the files below. Where they differ, 0.5.8 gives
`8000000000000000`, the hash of a flat image: a baseline JPEG with a scan for
each component instead of one for all (libjxl's `*_non_interleaved` and
`*_partially_interleaved` samples; `tests/fixtures/images/make.py` writes
one), which 0.5.15 decodes, so the hash is its pixels' and no longer what
`sigtool --fuzzy-img` gives. The 0.4.21 of JPEG-compressed TIFF is unchanged.

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
  `lzw` are `true`, `zstd` is `false`: Zstandard strips are read through
  ruzstd only inside `decoder::with_viewer_codecs`, which `tiff_view.rs`
  (`decode_any`) sets, so that `decode`, and what is hashed, refuses them as
  ClamAV's decoder does.
- zune-jpeg 0.4 is the dependency `zune-jpeg-04`, so `zune_jpeg::` is
  `zune_jpeg_04::`.
- `bytecast.rs` casts through `bytemuck` instead of two `unsafe` slice casts,
  which this crate forbids.
- `half::f16` is `u16`, its bits (`decoder/mod.rs`), which drops `half` and
  the `zerocopy` it pulls. `tiff_image.rs` only accepts 32-bit floats, so no
  f16 sample is ever converted.
- `decoder/image.rs`: `samples.into()` is `usize::from(samples)`, which type
  inference cannot find ambiguous whatever else the dependency graph holds.

- `decoder/image.rs`: a one-sample `RGBPalette` is `ColorType::Palette`, not an
  error, as in later versions of `tiff`. `tiff_image.rs` refuses a palette
  either way, so what `image` decodes, and what is hashed, is unchanged.
  `formats/image/tiff_view.rs` reads such files, and signed, wide and
  floating-point grey ones, for `decode_any` (the viewer) only.
- `decoder/image.rs`, each for `with_viewer_codecs` only so that what is
  hashed is unchanged: a palette with an alpha sample, CMYK with 6 to 8
  samples and 8-bit CIELab are `Multiband`; a file with TileWidth,
  TileLength and no TileOffsets is read as tiles named by StripOffsets and
  StripByteCounts (libtiff keeps both in one field); strips with no
  StripByteCounts run to the end of the file; YCbCr that is not JPEG and has
  its chroma sampled less than its luma (`Image::ycbcr_subsampling`, read from
  tag 530) is expanded to one Y, Cb, Cr to a pixel (`stream::YcbcrUnits`);
  Deflate strips are not checked
  against their Adler-32; a link back to a directory
  already read ends the chain; a three-sample JPEG
  chunk is decoded to RGB when zune-jpeg 0.4 takes it for CMYK; LZMA strips
  (34925: an xz stream of one LZMA2 block, behind a delta filter when
  predicted; `stream::xz_lzma2`, through `lzma-rust2`) and ThunderScan
  (32809, `stream::thunder_scan`) are read; old-style JPEG (compression 6) is
  read by making a JPEG of each strip or tile from the tags 512 to 521 or the
  stream `JPEGInterchangeFormat` points to (`decoder/ojpeg.rs`); a missing
  PhotometricInterpretation is BlackIsZero (RGB for three samples) and
  BitsPerSample entries past SamplesPerPixel are ignored, as libtiff does;
  grey of 9 to 15 bits is left packed in the buffer, with no byte order and no
  inversion, for `tiff_view.rs` to unpack.
- `decoder/stream.rs`: the LZW reader does not assert when `weezl` 0.1.12 says
  `NoProgress`. It returns the output of that call when there is some (the
  last bytes of a tile whose end code is still to be read: the padding of a
  tile that overhangs the image reads past them) and asks again when only
  input was taken; upstream panics in both cases, and in a build that aborts
  on panic, such as WebAssembly, that ends the decoder. Inside
  `with_viewer_codecs` it also decodes a block of 64 KiB at a time and hands
  that out: asked for a row's data and then its padding, a few bytes each,
  `weezl` (0.1.10 as well as 0.1.12) can end a valid stream short, and the
  hash must keep ClamAV's reading of such a tile, which is none. In the same
  reader, a stream that starts 0x00 and an odd byte is old-style LZW (least
  significant bit first, a code late) and is read as such.

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
