//! The JPEG and TIFF decoders `fuzzy_img` hashes with: `image`'s own, over
//! decoders built without their SIMD code. See `README.md`.

pub(crate) mod jpeg;
#[allow(dead_code, unused_imports, clippy::all)]
#[rustfmt::skip]
mod tiff;
// As upstream wrote it.
#[allow(clippy::chunks_exact_to_as_chunks, clippy::manual_is_multiple_of)]
pub(crate) mod tiff_image;

use image::{DynamicImage, ImageDecoder, ImageResult, Limits};

/// What `image::ImageReader::decode` does once it has a decoder.
pub(crate) fn decode(
    mut decoder: impl ImageDecoder,
    mut limits: Limits,
) -> ImageResult<DynamicImage> {
    limits.reserve(decoder.total_bytes())?;
    decoder.set_limits(limits)?;
    DynamicImage::from_decoder(decoder)
}
