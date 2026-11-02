// Copyright (c) the JPEG XL Project Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use std::{
    collections::{HashSet, VecDeque},
    io::IoSliceMut,
};

use sections::SectionState;

#[cfg(test)]
use crate::api::FrameCallback;
use crate::{
    api::{
        JxlBasicInfo, JxlBitstreamInput, JxlColorEncoding, JxlColorProfile, JxlDataFormat,
        JxlDecoderOptions, JxlOutputBuffer, JxlPixelFormat,
        inner::{box_parser::BoxParser, process::SmallBuffer},
    },
    error::{Error, Result},
    frame::{DecoderState, Frame, Section},
    headers::{Animation, FileHeader, frame_header::FrameHeader, toc::IncrementalTocReader},
    icc::IncrementalIccReader,
};

mod non_section;
mod sections;

struct SectionBuffer {
    len: usize,
    data: Vec<u8>,
    section: Section,
}

/// Padding bytes appended to each section buffer so BitReader::refill()
/// can always take the fast 8-byte read path.
const SECTION_PADDING: usize = 8;

pub(super) struct CodestreamParser {
    // TODO(veluca): this would probably be cleaner with some kind of state enum.
    pub(super) file_header: Option<FileHeader>,
    icc_parser: Option<IncrementalIccReader>,
    // These fields are populated once image information is available.
    pub(super) decoder_state: Option<DecoderState>,
    pub(super) basic_info: Option<JxlBasicInfo>,
    pub(super) animation: Option<Animation>,
    pub(super) embedded_color_profile: Option<JxlColorProfile>,
    pub(super) output_color_profile: Option<JxlColorProfile>,
    pub(super) pixel_format: Option<JxlPixelFormat>,
    xyb_encoded: bool,
    is_gray: bool,
    pub(super) output_color_profile_set_by_user: bool,

    // These fields are populated when starting to decode a frame, and cleared once
    // the frame is done.
    frame_header: Option<FrameHeader>,
    toc_parser: Option<IncrementalTocReader>,
    pub(super) frame: Option<Frame>,

    // Buffers.
    non_section_buf: SmallBuffer,
    non_section_bit_offset: u8,
    sections: VecDeque<SectionBuffer>,
    ready_section_data: usize,
    skip_sections: bool,
    // True when we need to process frames without copying them to output buffers, e.g. reference frames
    process_without_output: bool,
    // True once the preview frame has been processed (if there is one)
    preview_done: bool,
    // Saved file header for recreating decoder state after preview frame
    saved_file_header: Option<crate::headers::FileHeader>,

    section_state: SectionState,

    // Or only section if in single section special case.
    lf_global_section: Option<SectionBuffer>,
    lf_sections: Vec<SectionBuffer>,
    hf_global_section: Option<SectionBuffer>,
    // indexed by group, then by pass.
    hf_sections: Vec<Vec<Option<SectionBuffer>>>,
    // group indices that *might* have new renderable data.
    candidate_hf_sections: HashSet<usize>,

    pub(super) has_more_frames: bool,

    /// `(global_scale, quant_lf)` of the first regular VarDCT frame, captured
    /// when its `LfGlobal` is decoded and kept for the decoder's lifetime so a
    /// probe can recover the main image's encode quality. `None` for Modular
    /// (lossless) files or before the first regular frame is decoded.
    pub(super) first_vardct_quantizer: Option<(u32, u32)>,

    header_needed_bytes: Option<u64>,

    #[cfg(test)]
    pub frame_callback: Option<Box<FrameCallback>>,
    #[cfg(test)]
    pub decoded_frames: usize,

    /// JBRD box data for JPEG reconstruction.
    #[cfg(feature = "jpeg")]
    pub(super) jbrd_data: Option<Vec<u8>>,
    /// Reconstruction JpegData (built after the frame decodes if jbrd present).
    /// EXIF/XMP APPn placeholders are filled, and the bytes written, lazily in
    /// `take_jpeg_reconstruction` — after the trailing container boxes parse.
    #[cfg(feature = "jpeg")]
    pub(super) jpeg_recon: Option<crate::jpeg::data::JpegData>,
}

impl CodestreamParser {
    pub(super) fn new() -> Self {
        Self {
            file_header: None,
            icc_parser: None,
            decoder_state: None,
            basic_info: None,
            animation: None,
            embedded_color_profile: None,
            output_color_profile: None,
            pixel_format: None,
            xyb_encoded: false,
            is_gray: false,
            output_color_profile_set_by_user: false,
            frame_header: None,
            toc_parser: None,
            frame: None,
            first_vardct_quantizer: None,
            non_section_buf: SmallBuffer::new(4096),
            non_section_bit_offset: 0,
            sections: VecDeque::new(),
            ready_section_data: 0,
            skip_sections: false,
            process_without_output: false,
            preview_done: false,
            saved_file_header: None,
            section_state: SectionState::new(0, 0),
            lf_global_section: None,
            lf_sections: vec![],
            hf_global_section: None,
            hf_sections: vec![],
            candidate_hf_sections: HashSet::new(),
            has_more_frames: true,
            header_needed_bytes: None,
            #[cfg(test)]
            frame_callback: None,
            #[cfg(test)]
            decoded_frames: 0,
            #[cfg(feature = "jpeg")]
            jbrd_data: None,
            #[cfg(feature = "jpeg")]
            jpeg_recon: None,
        }
    }

    fn has_visible_frame(&self) -> bool {
        if let Some(frame) = &self.frame {
            frame.header().is_visible()
        } else {
            false
        }
    }

    /// Returns the number of passes that are fully completed across all groups.
    pub(super) fn num_completed_passes(&self) -> usize {
        self.section_state.num_completed_passes()
    }

    #[cfg(test)]
    pub(crate) fn set_use_simple_pipeline(&mut self, u: bool) {
        self.decoder_state
            .as_mut()
            .unwrap()
            .set_use_simple_pipeline(u);
    }

    /// Rewinds for animation loop replay, keeping pixel_format setting.
    pub(super) fn rewind(&mut self) -> Option<JxlPixelFormat> {
        let pixel_format = self.pixel_format.take();
        *self = Self::new();
        self.pixel_format = pixel_format.clone();
        pixel_format
    }

    pub(super) fn process(
        &mut self,
        box_parser: &mut BoxParser,
        input: &mut dyn JxlBitstreamInput,
        decode_options: &JxlDecoderOptions,
        mut output_buffers: Option<&mut [JxlOutputBuffer]>,
        do_flush: bool,
    ) -> Result<()> {
        if let Some(output_buffers) = &output_buffers {
            let px = self.pixel_format.as_ref().unwrap();
            let expected_len = std::iter::once(&px.color_data_format)
                .chain(px.extra_channel_format.iter())
                .filter(|x| x.is_some())
                .count();
            if output_buffers.len() != expected_len {
                return Err(Error::WrongBufferCount(output_buffers.len(), expected_len));
            }
        }
        // If we have sections to read, read into sections; otherwise, read into the local buffer.
        loop {
            if !self.sections.is_empty() {
                // Try to pick up JBRD data that may have arrived during box parsing
                #[cfg(feature = "jpeg")]
                if self.jbrd_data.is_none()
                    && let Some(data) = box_parser.take_jbrd_data()
                {
                    self.jbrd_data = Some(data);
                    if let Some(frame) = &mut self.frame {
                        frame.enable_jpeg_reconstruction();
                    }
                }

                let regular_frame = self.has_visible_frame();
                // Only skip sections if we don't need the frame data. Frames that can be
                // referenced must be decoded because they serve as sources for patches,
                // blending, or frame extension in subsequent frames.
                let can_be_referenced = self
                    .frame
                    .as_ref()
                    .is_some_and(|f| f.header().can_be_referenced);
                if !self.process_without_output && output_buffers.is_none() && !can_be_referenced {
                    self.skip_sections = true;
                }

                if !self.skip_sections {
                    // This is just an estimate as there could be box bytes in the middle.
                    let mut readable_section_data = (self.non_section_buf.len()
                        + input.available_bytes()?
                        + self.ready_section_data)
                        .max(1);
                    // Ensure enough section buffers are available for reading available data.
                    for buf in self.sections.iter_mut() {
                        if buf.data.is_empty() {
                            // Allocate with SECTION_PADDING extra zero bytes so
                            // BitReader::refill() always takes the fast 8-byte path.
                            buf.data.resize(buf.len + SECTION_PADDING, 0);
                        }
                        readable_section_data = readable_section_data.saturating_sub(buf.len);
                        if readable_section_data == 0 {
                            break;
                        }
                    }
                    // Read sections up to the end of the current box.
                    let mut available_codestream = match box_parser.get_more_codestream(input) {
                        Err(Error::OutOfBounds(_)) => 0,
                        Ok(c) => c as usize,
                        Err(e) => return Err(e),
                    };
                    let mut section_buffers = vec![];
                    let mut ready = self.ready_section_data;
                    for buf in self.sections.iter_mut() {
                        if buf.data.is_empty() {
                            break;
                        }
                        let len = buf.len;
                        if len > ready {
                            let readable = (available_codestream + ready).min(len);
                            section_buffers.push(IoSliceMut::new(&mut buf.data[ready..readable]));
                            available_codestream =
                                available_codestream.saturating_sub(readable - ready);
                            if available_codestream == 0 {
                                break;
                            }
                        }
                        ready = ready.saturating_sub(len);
                    }
                    let ready_before = self.ready_section_data;
                    let mut buffers = &mut section_buffers[..];
                    loop {
                        let num = if !box_parser.box_buffer.is_empty() {
                            box_parser.box_buffer.take(buffers)
                        } else {
                            input.read(buffers)?
                        };
                        self.ready_section_data += num;
                        box_parser.consume_codestream(num as u64);
                        IoSliceMut::advance_slices(&mut buffers, num);
                        if num == 0 || buffers.is_empty() {
                            break;
                        }
                    }
                    match self.process_sections(decode_options, &mut output_buffers, do_flush) {
                        Ok(None) => Ok(()),
                        Ok(Some(missing)) => Err(Error::OutOfBounds(missing)),
                        Err(Error::OutOfBounds(_)) => Err(Error::SectionTooShort),
                        Err(err) => Err(err),
                    }?;
                    // If no section data was read and sections are still pending,
                    // the input is truncated — return an error instead of looping
                    // forever waiting for data that will never arrive.
                    if !self.sections.is_empty()
                        && self.ready_section_data == ready_before
                        && input.available_bytes().unwrap_or(0) == 0
                        && box_parser.box_buffer.is_empty()
                    {
                        let total_needed: usize = self.sections.iter().map(|s| s.len).sum();
                        return Err(Error::OutOfBounds(
                            total_needed.saturating_sub(self.ready_section_data),
                        ));
                    }
                } else {
                    let total_size = self.sections.iter().map(|x| x.len).sum::<usize>();
                    loop {
                        let to_skip = total_size - self.ready_section_data;
                        if to_skip == 0 {
                            break;
                        }
                        let available_codestream = box_parser.get_more_codestream(input)? as usize;
                        let to_skip = to_skip.min(available_codestream);
                        let skipped = if !box_parser.box_buffer.is_empty() {
                            box_parser.box_buffer.consume(to_skip)
                        } else {
                            input.skip(to_skip)?
                        };
                        box_parser.consume_codestream(skipped as u64);
                        self.ready_section_data += skipped;
                        if skipped == 0 {
                            break;
                        }
                    }
                    if self.ready_section_data < total_size {
                        return Err(Error::OutOfBounds(total_size - self.ready_section_data));
                    } else {
                        self.sections.clear();
                        // Finalize the skipped frame, mirroring what process_sections does
                        let frame = self
                            .frame
                            .take()
                            .expect("frame must be set when skip_sections is true");
                        if let Some(decoder_state) = frame.finalize()? {
                            self.decoder_state = Some(decoder_state);
                        } else {
                            self.has_more_frames = false;
                        }
                        self.skip_sections = false;
                    }
                }
                if self.sections.is_empty() {
                    // Go back to parsing a new frame header, if any.
                    // Only return if this was a regular visible frame that was actually decoded
                    // (not a frame we were skipping like a preview frame)
                    let was_skipping = self.process_without_output;
                    self.process_without_output = false;
                    if regular_frame && !was_skipping {
                        // JBRD reconstruction: the trailing Exif / XMP / brob
                        // metadata boxes follow the frame's codestream. When the
                        // codestream is large the section reads stop exactly at
                        // the frame end without over-reading the trailing boxes,
                        // so drive the box parser through them now — otherwise
                        // EXIF/XMP/ICC are silently dropped from the reconstructed
                        // APPn markers. `OutOfBounds` is the clean EOF after the
                        // last box; only fires when a reconstruction is pending,
                        // so non-JPEG decodes are unaffected.
                        #[cfg(feature = "jpeg")]
                        if self.jpeg_recon.is_some() {
                            match box_parser.get_more_codestream(input) {
                                Ok(_) | Err(Error::OutOfBounds(_)) => {}
                                Err(e) => return Err(e),
                            }
                        }
                        return Ok(());
                    }
                    continue;
                }
            } else {
                // Trying to read a frame or a file header.
                assert!(self.frame.is_none());
                // Defensive (mirrors libjxl/jxl-rs#749): on normal input `has_more_frames`
                // is still set when we reach this header-reading branch, but a
                // malformed/edge input (e.g. skipping a final preview frame, or an empty
                // follow-up `process()` call) can re-enter here with it cleared. There is
                // no more image data to read, so return gracefully instead of panicking
                // on untrusted input.
                if !self.has_more_frames {
                    // The codestream is complete, but metadata boxes (`jhgm`
                    // gain map, `Exif`, `xml `, `brob`) may trail it in the
                    // container — jxl-encoder's `append_gain_map_bundle`
                    // writes `signature + ftyp + jxlc + jhgm` (#20). Drive
                    // the box parser through whatever input is available so
                    // they are captured. `OutOfBounds` is the clean EOF after
                    // the last box — or an incomplete trailing box, whose
                    // parsing resumes if `process` is called again with more
                    // input.
                    match box_parser.get_more_codestream(input) {
                        Ok(_) | Err(Error::OutOfBounds(_)) => {}
                        Err(e) => return Err(e),
                    }
                    return Ok(());
                }

                // Loop to handle incremental parsing (e.g. large ICC profiles) that may need
                // multiple buffer refills to complete.
                loop {
                    let available_codestream = match box_parser.get_more_codestream(input) {
                        Err(Error::OutOfBounds(_)) => 0,
                        Ok(c) => c as usize,
                        Err(e) => return Err(e),
                    };
                    let c = self.non_section_buf.refill(
                        |buf| {
                            if !box_parser.box_buffer.is_empty() {
                                Ok(box_parser.box_buffer.take(buf))
                            } else {
                                input.read(buf)
                            }
                        },
                        Some(available_codestream),
                    )? as u64;
                    box_parser.consume_codestream(c);

                    // If we know that non-section parsing will require more bytes than what
                    // we added to the codestream, don't even try to parse non-section data.
                    if let Some(needed) = self.header_needed_bytes.as_mut() {
                        *needed = needed.saturating_sub(c);
                        if *needed > 0 {
                            if !self.non_section_buf.can_read_more() {
                                self.non_section_buf.enlarge();
                            }
                            // Check if input still has data - if so, refill and retry
                            if input.available_bytes().unwrap_or(0) > 0 {
                                continue;
                            } else {
                                return Err(Error::OutOfBounds(*needed as usize));
                            }
                        }
                    }

                    let range = self.non_section_buf.range();
                    match self.process_non_section(decode_options) {
                        Ok(()) => {
                            self.header_needed_bytes = None;
                            break;
                        }
                        Err(Error::OutOfBounds(n)) => {
                            let new_range = self.non_section_buf.range();
                            // If non-section parsing consumed no bytes, and the non-section buffer
                            // cannot accept more bytes, enlarge the buffer to allow to make progress.
                            if new_range == range && !self.non_section_buf.can_read_more() {
                                self.non_section_buf.enlarge();
                            }
                            self.header_needed_bytes = Some(n as u64);
                            // Check if input still has data - if so, refill and retry
                            if input.available_bytes().unwrap_or(0) > 0 {
                                continue;
                            } else {
                                return Err(Error::OutOfBounds(n));
                            }
                        }
                        Err(e) => return Err(e),
                    }
                }

                if self.decoder_state.is_some() && self.frame_header.is_none() {
                    // Return to caller if we found image info.
                    return Ok(());
                }
                if self.frame.is_some() {
                    // Transfer JBRD data from box parser and enable JPEG reconstruction
                    #[cfg(feature = "jpeg")]
                    if self.jbrd_data.is_none()
                        && let Some(data) = box_parser.take_jbrd_data()
                    {
                        self.jbrd_data = Some(data);
                    }
                    #[cfg(feature = "jpeg")]
                    if self.jbrd_data.is_some()
                        && let Some(frame) = &mut self.frame
                    {
                        frame.enable_jpeg_reconstruction();
                    }

                    // Check if this is a preview frame that should be skipped
                    let is_preview_frame = !self.preview_done
                        && self
                            .basic_info
                            .as_ref()
                            .is_some_and(|info| info.preview_size.is_some());
                    if is_preview_frame {
                        self.preview_done = true;
                        if decode_options.skip_preview {
                            self.process_without_output = true;
                            continue;
                        }
                    }

                    if self.has_visible_frame() {
                        // Return to caller if we found visible frame info.
                        return Ok(());
                    } else {
                        self.process_without_output = true;
                        continue;
                    }
                }
            }
        }
    }

    pub(super) fn update_default_output_color_profile(&mut self) {
        // Only set default output_color_profile if not already configured by user
        if self.output_color_profile_set_by_user {
            return;
        }

        let embedded_color_profile = self.embedded_color_profile.as_ref().unwrap();
        let pixel_format = self.pixel_format.as_ref().unwrap();

        // Determine default output color profile following libjxl logic:
        // - For XYB: use embedded if can_output_to(), else:
        //   - if float samples are requested: linear sRGB,
        //   - else: sRGB
        // - For non-XYB: use embedded color profile
        let output_color_profile = if self.xyb_encoded {
            // Use embedded if we can output to it, otherwise fall back to sRGB
            let base_encoding = if embedded_color_profile.can_output_to() {
                match &embedded_color_profile {
                    JxlColorProfile::Simple(enc) => enc.clone(),
                    JxlColorProfile::Icc(_) => {
                        unreachable!("can_output_to returns false for ICC")
                    }
                }
            } else {
                let data_format = pixel_format
                    .color_data_format
                    .unwrap_or(JxlDataFormat::U8 { bit_depth: 8 });
                let is_float = matches!(
                    data_format,
                    JxlDataFormat::F32 { .. } | JxlDataFormat::F16 { .. }
                );
                if is_float {
                    JxlColorEncoding::linear_srgb(self.is_gray)
                } else {
                    JxlColorEncoding::srgb(self.is_gray)
                }
            };

            JxlColorProfile::Simple(base_encoding)
        } else {
            embedded_color_profile.clone()
        };
        self.output_color_profile = Some(output_color_profile);
    }
}
