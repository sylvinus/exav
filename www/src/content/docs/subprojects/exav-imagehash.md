---
title: exav-imagehash
description: Perceptual image hashes, with every step a parameter, reproducing ClamAV's fuzzy_img hash (sigtool --fuzzy-img) and Python imagehash's phash bit for bit.
---

**Perceptual image hashes, with the steps that tell one tool's hash from
another's as parameters.** Two settings of those steps reproduce existing
tools:

- **ClamAV**: the hash ClamAV matches `fuzzy_img#` signatures against, equal
  to `sigtool --fuzzy-img` from ClamAV 1.4.6 and 1.5.4. exav's scanner uses it.
- **imagehash**: Python `imagehash.phash(Image.open(f))` with its defaults.

It is in each [release](/scanner/getting-started/installation/#prebuilt-binaries), as
`exav-imagehash-<tag>-<target>`, or:

```bash
cargo install exav-imagehash
```

```bash
exav-imagehash logo.png                           # ClamAV's hash
exav-imagehash --preset imagehash logo.png        # imagehash's
exav-imagehash --preset imagehash --hash-size 16 --threshold mean logo.png
exav-imagehash --distance a.png b.png             # bits that differ
```

Each file prints as `FILE: HASH`, the hash in hex, as both tools print it. An
image that cannot be hashed is reported on stderr, and the exit code is then 1.

## What a hash is

A DCT hash of the image's luminance, the kind called "pHash": the image is
decoded, turned grey, resized to a square, transformed with a 2-D DCT-II, and
the low-frequency corner of the result is compared with its median. Each bit
says whether a coefficient is above it. Two images that look alike have hashes
a few bits apart.

There is no standard behind the name. Implementations differ at every step,
and a `fuzzy_img#` signature only matches at distance 0, so to match ClamAV's
signatures the hash has to be ClamAV's to the bit, decoder included.

## The parameters

| Flag | `Params` field | ClamAV | imagehash |
|---|---|---|---|
| `--hash-size N` | `hash_size` | 8 (64 bits) | 8 |
| `--highfreq-factor N` | `highfreq_factor`: the DCT is `hash_size × N` square | 4 | 4 |
| `--grey bt601-float\|pillow` | `grey` | BT.601 in `f32`, rounded | Pillow's `convert("L")` |
| `--resize ...` | `resize` | the `image` crate's Lanczos3 | Pillow's Lanczos, ported |
| `--precision f32\|f64` | `precision` | pixels as `v/255` in `f32` | `0..=255` in `f64`, as scipy |
| `--threshold median\|mean` | `threshold` | median | median |
| `--drop-dc` | `keep_dc: false` | kept | kept |
| `--formats all\|clamav-graphics\|LIST` | `formats` | all | all |
| `--max-decode-bytes N` | `max_decode_bytes` | 512 MiB | 512 MiB |

`--resize` also takes `catmull-rom`, `gaussian`, `triangle` and `nearest` (the
`image` crate's), and `pillow-bicubic`, `pillow-bilinear`, `pillow-hamming` and
`pillow-box`. `--print-params` shows what a command line amounts to.

## How exact

Checked against the tools themselves:

- **ClamAV preset**: equal to `sigtool --fuzzy-img` on 9,751 JPEGs, 372 TIFFs
  in 31 encodings, and 780 images in every mode of PNG, GIF, BMP, WebP, ICO,
  PNM and QOI. An image sigtool cannot hash has no hash here either.
- **imagehash preset**: equal on those 780 (8 and 16-bit, grey, palette,
  alpha, 1-bit). On JPEG, 98% equal and the rest a bit or two apart: Pillow
  decodes with libjpeg-turbo, whose pixels are not zune-jpeg's. On TIFF, equal
  wherever both read the file; Pillow's libtiff also reads fax G3, palette,
  planar, grey with alpha and YCbCr JPEG TIFFs, which ClamAV's decoder, and so
  this one, refuses. A PPM with a maxval other than 255 or 65535 is scaled
  differently.

## Formats

PNG, GIF, JPEG, TIFF and BMP, and WebP, ICO, PNM, QOI, DDS, farbfeld,
Radiance HDR, JPEG 2000 and JBIG2, each a Cargo feature on by default,
recognised from their first bytes. `sigtool --fuzzy-img` hashes all of them
but JPEG 2000 and JBIG2, and OpenEXR, which this crate leaves out: its decoder
brings `rayon-core` and `smallvec`, crates with `unsafe`. The hash is one of
pixels, so a JPEG 2000 or JBIG2 image hashes as the same pixels do in a PNG,
and a signature `sigtool --fuzzy-img` made from that PNG matches it.

clamscan, scanning, takes only the first five for graphics (`Target:5`), and
hashes nothing else. exav does the same under `--clamav-compat`; otherwise
every format here is graphics, and a `fuzzy_img#` signature is matched
against all of them.

## Safety

The crate is `#![forbid(unsafe_code)]`, and its decoders have no `unsafe`:
png, gif, image-webp, qoi, hayro-jpeg2000 and hayro-jbig2 (built without
their `simd` feature) forbid it, `image`'s own (BMP, ICO, PNM, DDS,
farbfeld, HDR) use none, and zune-jpeg's only `unsafe` is its SIMD code, which
`image` and `tiff` turn on with no way to turn it off from outside, so the
crate vendors `image`'s JPEG and TIFF decoders and `tiff`'s, over zune-jpeg
built without it.

The DCT is vendored too: rustdct 0.7.1's algorithm for a power of two, with
bounds checks where rustdct skips them with `unsafe`, so its coefficients,
and the presets' hashes, are rustdct's to the bit. rustdct hands other
lengths to rustfft and its SIMD code; here they go through a Bluestein FFT
of the crate's own, which rounds differently, so a hash with such a `hash_size
× highfreq_factor` can differ from rustdct's in a bit whose coefficient sits
at the median.

The rest of the dependency tree is not free of `unsafe`. On the way to a hash:
the checksums and inflate under PNG and TIFF (`crc32fast`, `simd-adler32`,
`flate2`), and pixel and byte casts (`image`, `bytemuck`, `half`,
`zerocopy`). `moxcms`, `image`'s colour management, is compiled in but not
reached.

Decoding is bounded by
`max_decode_bytes` (`Error::TooLarge` past it), and a decoder panicking on a
crafted file is caught and reported as `Error::Undecodable`. The decoders are
pinned to the versions libclamav links, for the hashes as much as for
`cargo install`, which resolves without a lockfile.

## As a library

```bash
cargo add exav-imagehash
```

```rust
use exav_imagehash::{Hasher, Params, Preset, Threshold};

let bytes = std::fs::read("logo.png")?;
let h = Hasher::new(Preset::ClamAv).hash(&bytes)?;
println!("{h}");                                     // 16 hex digits

let p = Params { hash_size: 16, threshold: Threshold::Mean, ..Params::IMAGEHASH_PHASH };
let h = Hasher::with_params(p)?.hash(&bytes)?;      // 256 bits

let d = h.distance(&other);                          // None between sizes
```

`hash_rgb8`, `hash_rgba8` and `hash_gray` take decoded pixels, for a caller
with a decoder of its own; only the grey conversion, the resize and the DCT
then apply.

The command is the `cli` feature, on by default with every format past the
first five (`webp`, `ico`, `pnm`, `qoi`, `dds`, `ff`, `hdr`, `jp2`, `jbig2`);
a library consumer can turn default features off and pick the formats it
needs.

Building exav without its `image-hash` feature leaves this crate out, and
loads `fuzzy_img#` signatures as unsupported.
