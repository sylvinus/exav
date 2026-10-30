// Copyright (c) the JPEG XL Project Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// #![warn(missing_docs)]

mod color;
mod convenience;
mod data_types;
mod decoder;
mod inner;
mod input;
#[cfg(feature = "cms")]
mod moxcms_wrapper;
mod options;
mod signature;
mod xyb_constants;

pub use crate::image::JxlOutputBuffer;
pub use color::*;
pub use convenience::{JxlImage, JxlImageInfo, decode, decode_with, read_header, read_header_with};
#[cfg(feature = "jpeg")]
pub use convenience::{reconstruct_jpeg, reconstruct_jpeg_with};
pub use data_types::*;
pub use decoder::*;
pub use enough::{Stop, Unstoppable};
pub use inner::*;
pub use input::*;
#[cfg(feature = "cms")]
pub use moxcms_wrapper::*;
pub use options::*;
pub use signature::*;

// Error types
pub use crate::error::{Error, Result};

// Image types used by CLI/fuzz for output buffer construction
pub use crate::image::{
    DataTypeTag, Image, ImageDataType, ImageRect, ImageRectMut, OwnedRawImage, RawImageRect,
    RawImageRectMut, Rect,
};

// Header types that appear in public API structs
pub use crate::headers::color_encoding::RenderingIntent;
pub use crate::headers::extra_channels::ExtraChannel;
pub use crate::headers::image_metadata::Orientation;

// Container box types
pub use crate::container::gain_map::GainMapBundle;

// Point type used in Error variants
pub use crate::features::spline::Point;

// Profiling (feature-gated, used by CLI)
#[cfg(feature = "profiling")]
pub use crate::util::profiling::print_profile_report;

/// This type represents the return value of a function that reads input from a bitstream. The
/// variant `Complete` indicates that the operation was completed successfully, and its return
/// value is available. The variant `NeedsMoreInput` indicates that more input is needed, and the
/// function should be called again. This variant comes with a `size_hint`, representing an
/// estimate of the number of additional bytes needed, and a `fallback`, representing additional
/// information that might be needed to call the function again (i.e. because it takes a decoder
/// object by value).
#[derive(Debug, PartialEq)]
pub enum ProcessingResult<T, U> {
    Complete { result: T },
    NeedsMoreInput { size_hint: usize, fallback: U },
}

impl<T> ProcessingResult<T, ()> {
    fn new(
        result: Result<T, crate::error::Error>,
    ) -> Result<ProcessingResult<T, ()>, crate::error::Error> {
        match result {
            Ok(v) => Ok(ProcessingResult::Complete { result: v }),
            Err(crate::error::Error::OutOfBounds(v)) => Ok(ProcessingResult::NeedsMoreInput {
                size_hint: v,
                fallback: (),
            }),
            Err(e) => Err(e),
        }
    }
}

#[derive(Clone)]
#[non_exhaustive]
pub struct ToneMapping {
    pub intensity_target: f32,
    pub min_nits: f32,
    pub relative_to_max_display: bool,
    pub linear_below: f32,
}

#[derive(Clone)]
#[non_exhaustive]
pub struct JxlBasicInfo {
    /// Dimensions of the pixel data the decoder will emit, in the order the
    /// output buffer must be laid out (`(width, height)`).
    ///
    /// This depends on [`JxlDecoderOptions::adjust_orientation`]:
    /// - When orientation is adjusted (the default, "Correct"), the stored
    ///   orientation is baked into the output, so this is the *display* size
    ///   (width/height are swapped relative to [`Self::coded_size`] for
    ///   transposing orientations).
    /// - When orientation adjustment is disabled ("Preserve"), pixels are
    ///   emitted in their stored orientation, so this equals
    ///   [`Self::coded_size`].
    ///
    /// Allocate output buffers against this size.
    pub size: (usize, usize),
    /// The stored (coded) dimensions of the image as written in the codestream,
    /// `(width, height)`, *before* any orientation is applied. Unaffected by
    /// [`JxlDecoderOptions::adjust_orientation`]. For transposing orientations
    /// this differs from the display size; see [`Self::size`].
    pub coded_size: (usize, usize),
    pub bit_depth: JxlBitDepth,
    /// Orientation of the pixels the decoder emits, i.e. the residual transform
    /// a caller must still apply to obtain an upright image.
    ///
    /// This depends on [`JxlDecoderOptions::adjust_orientation`]:
    /// - When orientation is adjusted (the default, "Correct"), the stored
    ///   orientation has already been baked into the output pixels, so this is
    ///   [`Orientation::Identity`].
    /// - When orientation adjustment is disabled ("Preserve"), this is the
    ///   image's stored orientation (equal to [`Self::intrinsic_orientation`]),
    ///   which the caller should bake into the [`Self::coded_size`] pixels to
    ///   display them upright.
    pub orientation: Orientation,
    /// The image's intrinsic (stored) EXIF/container orientation as written in
    /// the codestream, regardless of [`JxlDecoderOptions::adjust_orientation`].
    ///
    /// Use this to re-tag re-encoded output or to decide how to bake the stored
    /// orientation. In "Correct" mode the emitted pixels are already upright
    /// even though this reports a non-Identity value; in "Preserve" mode this
    /// equals [`Self::orientation`].
    pub intrinsic_orientation: Orientation,
    pub extra_channels: Vec<JxlExtraChannel>,
    pub animation: Option<JxlAnimation>,
    pub uses_original_profile: bool,
    pub tone_mapping: ToneMapping,
    pub preview_size: Option<(usize, usize)>,
    /// Intrinsic display size, if different from coded size.
    ///
    /// When present, the image should be rendered at this `(width, height)`
    /// rather than the coded `size`. Used for resolution-independence
    /// (e.g. a 4000×3000 image meant to display at 2000×1500).
    pub intrinsic_size: Option<(usize, usize)>,
}
