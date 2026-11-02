// Copyright (c) the JPEG XL Project Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! High-level convenience API for decoding JXL images.
//!
//! For most use cases, [`decode`] is all you need:
//!
//! ```no_run
//! let data = std::fs::read("image.jxl").unwrap();
//! let image = zenjxl_decoder::decode(&data).unwrap();
//! let (w, h) = (image.width, image.height);
//! let rgba: &[u8] = &image.data;
//! ```
//!
//! Use [`read_header`] to inspect metadata without decoding pixels.
//!
//! For streaming input, incremental decoding, or fine-grained control over
//! pixel format and color management, use the lower-level [`JxlDecoder`]
//! typestate API instead.
//!
//! [`JxlDecoder`]: super::JxlDecoder

use super::{
    GainMapBundle, JxlBasicInfo, JxlColorProfile, JxlColorType, JxlDataFormat, JxlDecoder,
    JxlDecoderLimits, JxlDecoderOptions, JxlOutputBuffer, JxlPixelFormat, ProcessingResult, states,
};
use crate::error::{Error, Result};
use crate::headers::extra_channels::ExtraChannel;
use crate::image::{OwnedRawImage, Rect};

/// A decoded JXL image with interleaved RGBA (or GrayAlpha) u8 pixel data.
#[non_exhaustive]
pub struct JxlImage {
    /// Image width in pixels.
    pub width: usize,
    /// Image height in pixels.
    pub height: usize,
    /// Interleaved pixel data: RGBA or GrayAlpha, row-major, tightly packed.
    /// Length = `width * height * channels` where channels is 4 (RGBA) or 2 (GrayAlpha).
    pub data: Vec<u8>,
    /// Number of channels per pixel (4 for RGBA, 2 for GrayAlpha).
    pub channels: usize,
    /// True if the source image is grayscale (output is GrayAlpha).
    pub is_grayscale: bool,
    /// Image metadata from the file header.
    pub info: JxlBasicInfo,
    /// The color profile of the output pixels.
    pub output_profile: JxlColorProfile,
    /// The color profile embedded in the file.
    pub embedded_profile: JxlColorProfile,
    /// HDR gain map bundle from a `jhgm` container box, if present.
    ///
    /// Captured whether the box precedes or follows the codestream. For
    /// animations, boxes that follow the codestream are not read (decoding
    /// stops after the first frame).
    pub gain_map: Option<GainMapBundle>,
    /// Raw EXIF data from the `Exif` container box (TIFF header offset stripped).
    /// `None` for bare codestreams or files without an `Exif` box.
    ///
    /// Captured whether the box precedes or follows the codestream. For
    /// animations, boxes that follow the codestream are not read (decoding
    /// stops after the first frame).
    pub exif: Option<Vec<u8>>,
    /// Raw XMP data from the `xml ` container box.
    /// `None` for bare codestreams or files without an `xml ` box.
    ///
    /// Captured whether the box precedes or follows the codestream. For
    /// animations, boxes that follow the codestream are not read (decoding
    /// stops after the first frame).
    pub xmp: Option<Vec<u8>>,
}

/// Image metadata extracted from the file header, without decoding pixels.
#[non_exhaustive]
pub struct JxlImageInfo {
    /// Image metadata (dimensions, bit depth, orientation, extra channels, animation).
    pub info: JxlBasicInfo,
    /// The color profile embedded in the file.
    pub embedded_profile: JxlColorProfile,
}

/// Decode a JXL image from a byte slice to RGBA u8 pixels.
///
/// For grayscale images, returns GrayAlpha u8 (2 channels).
/// For color images, returns RGBA u8 (4 channels).
/// Alpha is always included; images without alpha get opaque (255) alpha.
///
/// Decodes only the first frame. For animation support, use the
/// [`JxlDecoder`](super::JxlDecoder) streaming API.
///
/// Uses default security limits and parallel decoding (if the `threads`
/// feature is enabled). For custom limits or cancellation, use
/// [`decode_with`].
///
/// # Example
///
/// ```no_run
/// let data = std::fs::read("photo.jxl").unwrap();
/// let image = zenjxl_decoder::decode(&data).unwrap();
/// assert_eq!(image.data.len(), image.width * image.height * image.channels);
/// ```
pub fn decode(data: &[u8]) -> Result<JxlImage> {
    decode_with(data, JxlDecoderOptions::default())
}

/// Decode a JXL image with custom decoder options.
///
/// Same output format as [`decode`] (RGBA u8 or GrayAlpha u8), but allows
/// configuring security limits, cancellation, parallel mode, and CMS.
pub fn decode_with(data: &[u8], options: JxlDecoderOptions) -> Result<JxlImage> {
    let mut input: &[u8] = data;

    // Phase 1: Initialized → WithImageInfo (parse header + ICC)
    let decoder = JxlDecoder::<states::Initialized>::new(options);
    let mut decoder = match decoder.process(&mut input)? {
        ProcessingResult::Complete { result } => result,
        ProcessingResult::NeedsMoreInput { .. } => {
            return Err(Error::OutOfBounds(0));
        }
    };

    let info = decoder.basic_info().clone();
    let embedded_profile = decoder.embedded_color_profile().clone();
    let (width, height) = info.size;

    // Determine color type: add alpha to whatever the image naturally is
    let is_grayscale = decoder.current_pixel_format().color_type.is_grayscale();
    let color_type = if is_grayscale {
        JxlColorType::GrayscaleAlpha
    } else {
        JxlColorType::Rgba
    };
    let channels = color_type.samples_per_pixel();

    // Find main alpha channel for interleaving
    let main_alpha = info
        .extra_channels
        .iter()
        .position(|ec| ec.ec_type == ExtraChannel::Alpha);

    let u8_format = JxlDataFormat::U8 { bit_depth: 8 };

    // Set pixel format: interleave alpha into color channels, keep other extras as u8
    let pixel_format = JxlPixelFormat {
        color_type,
        color_data_format: Some(u8_format),
        extra_channel_format: info
            .extra_channels
            .iter()
            .enumerate()
            .map(|(i, _)| {
                if Some(i) == main_alpha {
                    None // interleaved into RGBA/GrayAlpha
                } else {
                    Some(u8_format)
                }
            })
            .collect(),
    };
    decoder.set_pixel_format(pixel_format);

    let output_profile = decoder.output_color_profile().clone();

    // Count non-interleaved extra channels (everything except the main alpha)
    let extra_count = info.extra_channels.len() - usize::from(main_alpha.is_some());

    // Phase 2: WithImageInfo → WithFrameInfo (parse frame header)
    let decoder = match decoder.process(&mut input)? {
        ProcessingResult::Complete { result } => result,
        ProcessingResult::NeedsMoreInput { .. } => {
            return Err(Error::OutOfBounds(0));
        }
    };

    // Allocate output buffers
    let row_bytes = width * channels; // 1 byte per sample for u8
    let mut output = OwnedRawImage::new_uninit((row_bytes, height))?;
    #[cfg(feature = "threads")]
    output.prefault_parallel();

    let mut extra_outputs: Vec<OwnedRawImage> = (0..extra_count)
        .map(|_| OwnedRawImage::new_uninit((width, height)))
        .collect::<Result<_>>()?;

    // Phase 3: WithFrameInfo → decode pixels
    let mut bufs: Vec<JxlOutputBuffer<'_>> = std::iter::once(&mut output)
        .chain(extra_outputs.iter_mut())
        .map(|img| {
            let rect = Rect {
                size: img.byte_size(),
                origin: (0, 0),
            };
            JxlOutputBuffer::from_image_rect_mut(img.get_rect_mut(rect))
        })
        .collect();

    let mut decoder = match decoder.process(&mut input, &mut bufs)? {
        ProcessingResult::Complete { result } => result,
        ProcessingResult::NeedsMoreInput { .. } => {
            return Err(Error::OutOfBounds(0));
        }
    };

    // Phase 4: drain trailing container boxes, then extract box metadata.
    // The jhgm (gain map), Exif, and xml boxes may follow the codestream —
    // jxl-encoder's `append_gain_map_bundle` writes `signature + ftyp + jxlc
    // + jhgm` — and the box parser only reaches them by processing past the
    // final frame (#20). Animations stop after the first frame, so boxes
    // trailing a multi-frame codestream stay unread; use the low-level
    // [`JxlDecoder`] API to collect those.
    let (gain_map, exif, xmp) = if !decoder.has_more_frames() && !input.is_empty() {
        match decoder.process(&mut input)? {
            ProcessingResult::Complete { mut result } => take_box_metadata(&mut result),
            ProcessingResult::NeedsMoreInput { mut fallback, .. } => {
                take_box_metadata(&mut fallback)
            }
        }
    } else {
        take_box_metadata(&mut decoder)
    };

    // Copy to tightly packed Vec<u8>
    let total_bytes = row_bytes * height;
    let mut pixels = Vec::with_capacity(total_bytes);
    for y in 0..height {
        pixels.extend_from_slice(output.row(y));
    }

    Ok(JxlImage {
        width,
        height,
        data: pixels,
        channels,
        is_grayscale,
        info,
        output_profile,
        embedded_profile,
        gain_map,
        exif,
        xmp,
    })
}

/// Takes the gain map, EXIF, and XMP captured by the box parser, in one call
/// usable from any decoder state.
fn take_box_metadata<S: states::JxlState>(
    decoder: &mut JxlDecoder<S>,
) -> (Option<GainMapBundle>, Option<Vec<u8>>, Option<Vec<u8>>) {
    (
        decoder.take_gain_map(),
        decoder.take_exif(),
        decoder.take_xmp(),
    )
}

/// Reconstruct the original JPEG bytes from a JXL file that carries a JBRD
/// (JPEG Bitstream Reconstruction Data) box — i.e. a JXL produced by lossless
/// JPEG transcoding (`jxl_encoder::LosslessConfig::encode_jpeg_transcode`).
///
/// Returns `Ok(Some(bytes))` with the **byte-exact** original JPEG when the
/// file carries reconstruction data, or `Ok(None)` when it does not (a JXL that
/// was not produced from a JPEG). This is the pure-Rust counterpart to
/// `djxl <in.jxl> <out.jpg> --reconstruct_jpeg`.
///
/// Requires the `jpeg` cargo feature.
///
/// # Example
///
/// ```no_run
/// let jxl = std::fs::read("photo.jxl").unwrap();
/// if let Some(jpeg) = zenjxl_decoder::reconstruct_jpeg(&jxl).unwrap() {
///     std::fs::write("photo_reconstructed.jpg", &jpeg).unwrap();
/// }
/// ```
#[cfg(feature = "jpeg")]
pub fn reconstruct_jpeg(data: &[u8]) -> Result<Option<Vec<u8>>> {
    reconstruct_jpeg_with(data, JxlDecoderOptions::default())
}

/// Reconstruct the original JPEG bytes with custom decoder options.
///
/// See [`reconstruct_jpeg`]. Drives a full frame decode (reconstruction needs
/// the captured quantized coefficients) and then returns the JBRD-reconstructed
/// JPEG. The decoded pixels themselves are discarded.
#[cfg(feature = "jpeg")]
pub fn reconstruct_jpeg_with(data: &[u8], options: JxlDecoderOptions) -> Result<Option<Vec<u8>>> {
    let mut input: &[u8] = data;

    // Phase 1: parse header.
    let decoder = JxlDecoder::<states::Initialized>::new(options);
    let mut decoder = match decoder.process(&mut input)? {
        ProcessingResult::Complete { result } => result,
        ProcessingResult::NeedsMoreInput { .. } => return Err(Error::OutOfBounds(0)),
    };

    let info = decoder.basic_info().clone();
    let (width, height) = info.size;

    // Output format mirrors `decode_with`: natural color type + interleaved
    // alpha. The pixels are discarded — we only need a complete frame decode so
    // the JBRD coefficient capture runs.
    let is_grayscale = decoder.current_pixel_format().color_type.is_grayscale();
    let color_type = if is_grayscale {
        JxlColorType::GrayscaleAlpha
    } else {
        JxlColorType::Rgba
    };
    let channels = color_type.samples_per_pixel();
    let main_alpha = info
        .extra_channels
        .iter()
        .position(|ec| ec.ec_type == ExtraChannel::Alpha);
    let u8_format = JxlDataFormat::U8 { bit_depth: 8 };
    let pixel_format = JxlPixelFormat {
        color_type,
        color_data_format: Some(u8_format),
        extra_channel_format: info
            .extra_channels
            .iter()
            .enumerate()
            .map(|(i, _)| {
                if Some(i) == main_alpha {
                    None
                } else {
                    Some(u8_format)
                }
            })
            .collect(),
    };
    decoder.set_pixel_format(pixel_format);
    let extra_count = info.extra_channels.len() - usize::from(main_alpha.is_some());

    // Phase 2: parse frame header.
    let decoder = match decoder.process(&mut input)? {
        ProcessingResult::Complete { result } => result,
        ProcessingResult::NeedsMoreInput { .. } => return Err(Error::OutOfBounds(0)),
    };

    // Phase 3: decode the frame into throwaway buffers.
    let row_bytes = width * channels;
    let mut output = OwnedRawImage::new_uninit((row_bytes, height))?;
    let mut extra_outputs: Vec<OwnedRawImage> = (0..extra_count)
        .map(|_| OwnedRawImage::new_uninit((width, height)))
        .collect::<Result<_>>()?;
    let mut bufs: Vec<JxlOutputBuffer<'_>> = core::iter::once(&mut output)
        .chain(extra_outputs.iter_mut())
        .map(|img| {
            let rect = Rect {
                size: img.byte_size(),
                origin: (0, 0),
            };
            JxlOutputBuffer::from_image_rect_mut(img.get_rect_mut(rect))
        })
        .collect();

    let mut decoder = match decoder.process(&mut input, &mut bufs)? {
        ProcessingResult::Complete { result } => result,
        ProcessingResult::NeedsMoreInput { .. } => return Err(Error::OutOfBounds(0)),
    };

    // Phase 4: drain the remaining input so the box parser consumes the trailing
    // Exif / xml metadata boxes (which follow the codestream in a JPEG-transcode
    // container). Only then can `take_jpeg_reconstruction` stitch EXIF/XMP back
    // into the reconstructed APPn markers. A JBRD transcode has a single frame,
    // so this drains to `NeedsMoreInput` once the boxes are parsed.
    loop {
        if input.is_empty() {
            break;
        }
        let before = input.len();
        match decoder.process(&mut input)? {
            ProcessingResult::NeedsMoreInput { fallback, .. } => {
                decoder = fallback;
                if input.len() == before {
                    break; // no progress — avoid spinning
                }
            }
            // Unexpected second frame; the trailing boxes before it are parsed.
            ProcessingResult::Complete { mut result } => {
                return Ok(result.take_jpeg_reconstruction());
            }
        }
    }

    Ok(decoder.take_jpeg_reconstruction())
}

/// Read image metadata without decoding pixels.
///
/// Parses the file header and ICC profile. Returns dimensions, bit depth,
/// orientation, extra channel info, animation info, and color profile.
///
/// This is fast (~1μs for sRGB images, ~7μs for images with ICC profiles).
///
/// # Example
///
/// ```no_run
/// let data = std::fs::read("photo.jxl").unwrap();
/// let header = zenjxl_decoder::read_header(&data).unwrap();
/// let (w, h) = header.info.size;
/// println!("{w}x{h}");
/// ```
pub fn read_header(data: &[u8]) -> Result<JxlImageInfo> {
    read_header_with(data, JxlDecoderLimits::default())
}

/// Read image metadata with custom security limits.
pub fn read_header_with(data: &[u8], limits: JxlDecoderLimits) -> Result<JxlImageInfo> {
    let mut input: &[u8] = data;
    let options = JxlDecoderOptions {
        limits,
        ..JxlDecoderOptions::default()
    };
    let decoder = JxlDecoder::<states::Initialized>::new(options);
    let decoder = match decoder.process(&mut input)? {
        ProcessingResult::Complete { result } => result,
        ProcessingResult::NeedsMoreInput { .. } => {
            return Err(Error::OutOfBounds(0));
        }
    };

    Ok(JxlImageInfo {
        info: decoder.basic_info().clone(),
        embedded_profile: decoder.embedded_color_profile().clone(),
    })
}
