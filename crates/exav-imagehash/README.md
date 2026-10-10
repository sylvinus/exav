# exav-imagehash

**Perceptual image hashes**, with every step of the hash a
parameter and two settings that reproduce existing tools bit for bit:

- **ClamAV**: the hash ClamAV matches `fuzzy_img#` signatures against, equal
  to `sigtool --fuzzy-img` (ClamAV 1.4.6 and 1.5.4);
- **imagehash**: Python `imagehash.phash(Image.open(f))` with its defaults.

The crate is `#![forbid(unsafe_code)]`, and its image decoders have no
`unsafe`: zune-jpeg is built without its SIMD code, the only `unsafe` it has,
with `image`'s JPEG and TIFF decoders vendored to make that possible. The DCT
is rustdct's, vendored with bounds checks where it skips them with `unsafe`.
Other dependencies do use `unsafe`: the PNG and TIFF checksums and inflate,
and pixel casts. Decoding is bounded by a byte
budget, and a decoder panicking on a crafted file is caught and reported as an
undecodable image.

```rust
use exav_imagehash::{Hasher, Params, Preset, Threshold};

let bytes = std::fs::read("logo.png")?;

let h = Hasher::new(Preset::ClamAv).hash(&bytes)?;           // sigtool --fuzzy-img
let h = Hasher::new(Preset::ImagehashPhash).hash(&bytes)?;   // imagehash.phash

// Any step changed, from either preset:
let p = Params { hash_size: 16, threshold: Threshold::Mean, ..Params::IMAGEHASH_PHASH };
let h = Hasher::with_params(p)?.hash(&bytes)?;

println!("{h}");                          // hex, as both tools print it
let d = h.distance(&"95d3f8748359f805".parse()?);
let h = Hasher::new(Preset::ClamAv).hash_rgb8(width, height, &pixels)?;
```

The steps: the grey conversion (`Grey`: ClamAV's BT.601 in `f32`, or Pillow's
`convert("L")`), the resize (`Resize`: the `image` crate's filters, or Pillow's
resampler, ported), the DCT's size (`hash_size × highfreq_factor`) and
arithmetic (`Precision`: `f32` or `f64`), the threshold (median or mean), and
whether the DC term is kept.

**Formats:** PNG, GIF, JPEG, TIFF and BMP, and, each a Cargo feature on by
default, WebP, ICO, PNM, QOI, DDS, farbfeld, Radiance HDR, JPEG 2000 and
JBIG2, recognised from their first bytes. `Formats::CLAMAV_GRAPHICS` is the
five clamscan hashes while scanning; `sigtool --fuzzy-img` hashes all but JPEG
2000 and JBIG2 (and OpenEXR, which this crate does not read). A JPEG 2000 or
JBIG2 image hashes as the same pixels do in a PNG.

**How exact.** Checked against the tools themselves:

- ClamAV preset: equal to `sigtool --fuzzy-img` on 9,751 JPEGs, 372 TIFFs in 31
  encodings, and 780 images in every mode of PNG, GIF, BMP, WebP, ICO, PNM and
  QOI; the images it cannot hash, it does not hash either.
- imagehash preset: equal on those 780 (8-bit and 16-bit, grey, palette,
  alpha, 1-bit). On JPEG, 98% equal and the rest a bit or two apart: Pillow
  decodes with libjpeg-turbo, whose pixels are not zune-jpeg's. On TIFF, equal
  wherever both read the file; Pillow's libtiff also reads fax G3, palette,
  planar, grey with alpha and YCbCr JPEG TIFFs, which ClamAV's decoder, and so
  this one, refuses. A PPM with a maxval other than 255 or 65535 is scaled
  differently.

`tests/fixtures/` holds reference images with both tools' hashes.

The crate also ships the `exav-imagehash` command (the `cli` feature, on by
default):

```sh
cargo install exav-imagehash
exav-imagehash logo.png                           # ClamAV's hash
exav-imagehash --preset imagehash logo.png        # imagehash's
exav-imagehash --preset imagehash --hash-size 16 --threshold mean logo.png
exav-imagehash --distance a.png b.png
```

Licensed under MIT. Full documentation:
[exav.org](https://exav.org/subprojects/exav-imagehash/). See [`NOTICE`](NOTICE)
for the vendored code and its licenses.
