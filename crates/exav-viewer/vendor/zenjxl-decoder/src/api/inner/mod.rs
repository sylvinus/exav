// Copyright (c) the JPEG XL Project Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#[cfg(test)]
use crate::api::FrameCallback;
use crate::{
    api::JxlFrameHeader,
    error::{Error, Result},
};

use super::{JxlBasicInfo, JxlColorProfile, JxlDecoderOptions, JxlPixelFormat, VardctQuantizer};
use crate::container::frame_index::FrameIndexBox;
use crate::container::gain_map::GainMapBundle;
use box_parser::BoxParser;
use codestream_parser::CodestreamParser;

mod box_parser;
mod codestream_parser;
mod process;

/// Low-level, less-type-safe API.
pub struct JxlDecoderInner {
    options: JxlDecoderOptions,
    box_parser: BoxParser,
    codestream_parser: CodestreamParser,
}

impl JxlDecoderInner {
    /// Creates a new decoder with the given options and, optionally, CMS.
    pub fn new(options: JxlDecoderOptions) -> Self {
        JxlDecoderInner {
            options,
            box_parser: BoxParser::new(),
            codestream_parser: CodestreamParser::new(),
        }
    }

    #[cfg(test)]
    pub fn set_frame_callback(&mut self, callback: Box<FrameCallback>) {
        self.codestream_parser.frame_callback = Some(callback);
    }

    #[cfg(test)]
    pub fn decoded_frames(&self) -> usize {
        self.codestream_parser.decoded_frames
    }

    /// Test-only accessor for the active [`crate::frame::DecoderState`].
    ///
    /// Used by regression tests that need to verify that per-run options
    /// (limits, memory_tracker, parallel, high_precision, premultiply_output,
    /// embedded_color_profile) survive the preview-frame recovery path in
    /// `codestream_parser::sections::handle_frame_finalized`.
    ///
    /// Returns the parser-owned decoder state if it has not yet been moved
    /// into a Frame, otherwise the in-progress frame's decoder state.
    #[cfg(test)]
    pub(crate) fn decoder_state_for_test(&self) -> Option<&crate::frame::DecoderState> {
        if let Some(state) = self.codestream_parser.decoder_state.as_ref() {
            Some(state)
        } else {
            self.codestream_parser
                .frame
                .as_ref()
                .map(|f| &f.decoder_state)
        }
    }

    /// Obtains the image's basic information, if available.
    ///
    /// Keep this aligned with typed `WithImageInfo` transitions: image info is
    /// not observable until the embedded color profile has been parsed. This
    /// mirrors the fix from upstream jxl-rs 28ddaeb (PR #745) so that callers
    /// driving `set_pixel_format` off the partial info cannot race the profile
    /// parse and observe an early-format-selection state that differs from
    /// what the typed `WithImageInfo` transition would produce.
    pub fn basic_info(&self) -> Option<&JxlBasicInfo> {
        self.codestream_parser.embedded_color_profile.as_ref()?;
        self.codestream_parser.basic_info.as_ref()
    }

    /// Retrieves the file's color profile, if available.
    pub fn embedded_color_profile(&self) -> Option<&JxlColorProfile> {
        self.codestream_parser.embedded_color_profile.as_ref()
    }

    /// Returns the first regular VarDCT frame's quantizer, if this is a lossy
    /// VarDCT image whose first frame's `LfGlobal` section has been decoded.
    ///
    /// `None` for Modular (lossless) images, or before the first regular frame
    /// has been parsed (e.g. right after image-info, which `read_header` stops
    /// at). Advance one frame (e.g. `skip_frame`) to populate it from a probe.
    pub fn vardct_quantizer(&self) -> Option<VardctQuantizer> {
        let (global_scale, quant_lf) = self.codestream_parser.first_vardct_quantizer?;
        Some(VardctQuantizer {
            global_scale,
            quant_lf,
        })
    }

    /// Retrieves the current output color profile, if available.
    pub fn output_color_profile(&self) -> Option<&JxlColorProfile> {
        self.codestream_parser.output_color_profile.as_ref()
    }

    /// Specifies the preferred color profile to be used for outputting data.
    /// Same semantics as JxlDecoderSetOutputColorProfile.
    pub fn set_output_color_profile(&mut self, profile: JxlColorProfile) -> Result<()> {
        if let (JxlColorProfile::Icc(_), None) = (&profile, &self.options.cms) {
            return Err(Error::ICCOutputNoCMS);
        }
        self.codestream_parser.output_color_profile = Some(profile);
        self.codestream_parser.output_color_profile_set_by_user = true;
        Ok(())
    }

    pub fn current_pixel_format(&self) -> Option<&JxlPixelFormat> {
        self.codestream_parser.pixel_format.as_ref()
    }

    pub fn set_pixel_format(&mut self, pixel_format: JxlPixelFormat) {
        // TODO(veluca): return an error if we are asking for both planar and
        // interleaved-in-color alpha.
        self.codestream_parser.pixel_format = Some(pixel_format);
        self.codestream_parser.update_default_output_color_profile();
    }

    pub fn frame_header(&self) -> Option<JxlFrameHeader> {
        let frame_header = self.codestream_parser.frame.as_ref()?.header();
        // The render pipeline always adds ExtendToImageDimensionsStage which extends
        // frames to the full image size. So the output size is always the image size,
        // not the frame's upsampled size.
        let size = self.codestream_parser.basic_info.as_ref()?.size;
        Some(JxlFrameHeader {
            name: frame_header.name.clone(),
            duration: self
                .codestream_parser
                .animation
                .as_ref()
                .map(|anim| frame_header.duration(anim)),
            size,
        })
    }

    /// Number of passes we have full data for.
    /// Returns the minimum number of passes completed across all groups.
    pub fn num_completed_passes(&self) -> Option<usize> {
        Some(self.codestream_parser.num_completed_passes())
    }

    /// Fully resets the decoder to its initial state.
    ///
    /// This clears all state including pixel_format. For animation loop playback,
    /// consider using [`rewind`](Self::rewind) instead which preserves pixel_format.
    ///
    /// After calling this, the caller should provide input from the beginning of the file.
    pub fn reset(&mut self) {
        // TODO(veluca): keep track of frame offsets for skipping.
        self.box_parser = BoxParser::new();
        self.codestream_parser = CodestreamParser::new();
    }

    /// Rewinds for animation loop replay, keeping pixel_format setting.
    ///
    /// This resets the decoder but preserves the pixel_format configuration,
    /// so the caller doesn't need to re-set it after rewinding.
    ///
    /// After calling this, the caller should provide input from the beginning of the file.
    /// Headers will be re-parsed, then frames can be decoded again.
    ///
    /// Returns `true` if pixel_format was preserved, `false` if none was set.
    pub fn rewind(&mut self) -> bool {
        self.box_parser = BoxParser::new();
        self.codestream_parser.rewind().is_some()
    }

    pub fn has_more_frames(&self) -> bool {
        self.codestream_parser.has_more_frames
    }

    /// Returns the reconstructed JPEG bytes if the file contained a JBRD box.
    ///
    /// The reconstruction `JpegData` is built when the frame decodes, but the
    /// EXIF/XMP APPn payloads (lifted into container boxes that follow the
    /// codestream) and the final byte serialization are produced here, once the
    /// whole container has been parsed.
    #[cfg(feature = "jpeg")]
    pub fn take_jpeg_reconstruction(&mut self) -> Option<Vec<u8>> {
        let mut jpeg = self.codestream_parser.jpeg_recon.take()?;
        // The original ICC profile (if any) was lifted into the codestream color
        // encoding; recover it to re-chunk the ICC_PROFILE APP2 markers.
        let icc = match self.codestream_parser.embedded_color_profile.as_ref() {
            Some(JxlColorProfile::Icc(bytes)) => Some(bytes.clone()),
            _ => None,
        };
        crate::jpeg::fill_metadata(
            &mut jpeg,
            self.box_parser.exif.clone(),
            self.box_parser.xmp.clone(),
            icc.as_deref(),
        );
        crate::jpeg::write_jpeg(&jpeg).ok()
    }

    /// Returns the parsed frame index box, if the file contained one.
    pub fn frame_index(&self) -> Option<&FrameIndexBox> {
        self.box_parser.frame_index.as_ref()
    }

    /// Returns a reference to the parsed gain map bundle, if the file contained one.
    pub fn gain_map(&self) -> Option<&GainMapBundle> {
        self.box_parser.gain_map.as_ref()
    }

    /// Takes the parsed gain map bundle, if the file contained one.
    /// After calling this, `gain_map()` will return `None`.
    pub fn take_gain_map(&mut self) -> Option<GainMapBundle> {
        self.box_parser.gain_map.take()
    }

    /// Returns the raw EXIF data from the `Exif` container box, if present.
    ///
    /// The 4-byte TIFF header offset prefix has been stripped; this returns
    /// the raw EXIF/TIFF bytes starting with the byte-order marker (`II` or `MM`).
    /// Returns `None` for bare codestreams or files without an `Exif` box.
    pub fn exif(&self) -> Option<&[u8]> {
        self.box_parser.exif.as_deref()
    }

    /// Takes the EXIF data, leaving `None` in its place.
    pub fn take_exif(&mut self) -> Option<Vec<u8>> {
        self.box_parser.exif.take()
    }

    /// Returns the raw XMP data from the `xml ` container box, if present.
    ///
    /// Returns `None` for bare codestreams or files without an `xml ` box.
    pub fn xmp(&self) -> Option<&[u8]> {
        self.box_parser.xmp.as_deref()
    }

    /// Takes the XMP data, leaving `None` in its place.
    pub fn take_xmp(&mut self) -> Option<Vec<u8>> {
        self.box_parser.xmp.take()
    }

    #[cfg(test)]
    pub(crate) fn set_use_simple_pipeline(&mut self, u: bool) {
        self.codestream_parser.set_use_simple_pipeline(u);
    }
}
