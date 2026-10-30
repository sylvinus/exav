// Copyright (c) the JPEG XL Project Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use std::io::IoSliceMut;
use std::sync::Arc;

use super::SECTION_PADDING;

use crate::{
    api::{
        Endianness, JxlBasicInfo, JxlBitDepth, JxlColorEncoding, JxlColorProfile, JxlColorType,
        JxlDataFormat, JxlDecoderOptions, JxlExtraChannel, JxlPixelFormat,
        inner::codestream_parser::SectionState,
    },
    bit_reader::BitReader,
    error::{Error, Result},
    frame::{DecoderState, Frame, Section},
    headers::{
        FileHeader, JxlHeader, Orientation, color_encoding::ColorSpace,
        encodings::UnconditionalCoder, frame_header::FrameHeader, toc::IncrementalTocReader,
    },
    icc::IncrementalIccReader,
    util::{MemoryTracker, NewWithCapacity},
};

use super::{CodestreamParser, SectionBuffer};
use crate::api::ToneMapping;

/// Populate a freshly constructed [`DecoderState`] with per-run settings pulled
/// from [`JxlDecoderOptions`] and the previously parsed embedded color profile.
///
/// Ported from libjxl/jxl-rs #743 (f1514f1): upstream centralized this plumbing
/// in `DecoderState::new(file_header, &options)` to guarantee both the primary
/// creation path and the preview-frame recovery path populate identical fields.
/// In our tree we keep the old two-argument constructor (because our
/// `DecoderState` has several imazen-only fields) and centralize the plumbing
/// via this helper instead. Both call sites in `non_section.rs` and
/// `sections.rs` MUST go through this function so that options set on the
/// initial state are preserved after a preview-frame-triggered recreate.
pub(super) fn apply_decoder_options(
    state: &mut DecoderState,
    decode_options: &JxlDecoderOptions,
    embedded_color_profile: &Option<JxlColorProfile>,
) {
    state.render_spotcolors = decode_options.render_spot_colors;
    state.high_precision = decode_options.high_precision;
    state.premultiply_output = decode_options.premultiply_output;
    state.adjust_orientation = decode_options.adjust_orientation;
    state.desired_intensity_target = decode_options.desired_intensity_target;
    state.embedded_color_profile = embedded_color_profile.clone();
    state.limits = decode_options.limits.clone();
    state.stop = Arc::clone(&decode_options.stop);
    state.memory_tracker = MemoryTracker::from_limit(decode_options.limits.max_memory_bytes);
    state.parallel = decode_options.parallel;
}

fn check_size_limit(
    limits: &crate::api::JxlDecoderLimits,
    (xs, ys): (usize, usize),
    num_ec: usize,
) -> Result<()> {
    // Check max_pixels from new limits API
    let total_pixels = xs.saturating_mul(ys);
    if let Some(limit) = limits.max_pixels
        && total_pixels > limit
    {
        return Err(Error::LimitExceeded {
            resource: "pixels",
            actual: total_pixels as u64,
            limit: limit as u64,
        });
    }
    // Check extra channels limit
    if let Some(limit) = limits.max_extra_channels
        && num_ec > limit
    {
        return Err(Error::LimitExceeded {
            resource: "extra_channels",
            actual: num_ec as u64,
            limit: limit as u64,
        });
    }
    Ok(())
}

impl CodestreamParser {
    #[cold]
    pub(super) fn process_non_section(&mut self, decode_options: &JxlDecoderOptions) -> Result<()> {
        if self.decoder_state.is_none() && self.file_header.is_none() {
            // We don't have a file header yet. Try parsing that.
            let mut br = BitReader::new(&self.non_section_buf);
            br.skip_bits(self.non_section_bit_offset as usize)?;
            let file_header = FileHeader::read(&mut br)?;
            let xsize = file_header.size.xsize() as usize;
            let ysize = file_header.size.ysize() as usize;
            check_size_limit(
                &decode_options.limits,
                (xsize, ysize),
                file_header.image_metadata.extra_channel_info.len(),
            )?;
            if let Some(preview) = &file_header.image_metadata.preview {
                check_size_limit(
                    &decode_options.limits,
                    (preview.xsize() as usize, preview.ysize() as usize),
                    file_header.image_metadata.extra_channel_info.len(),
                )?;
            }
            let data = &file_header.image_metadata;
            self.animation = data.animation.clone();
            // The stored (coded) dimensions, before orientation is applied.
            let coded_size = (xsize, ysize);
            // The display dimensions, after the stored orientation is applied.
            let display_size = if data.orientation.is_transposing() {
                (ysize, xsize)
            } else {
                (xsize, ysize)
            };
            // When `adjust_orientation` is set (the default), the save stage
            // bakes the stored orientation into the output: emitted pixels are
            // upright (display dims, residual orientation Identity). When it is
            // cleared (Preserve mode), pixels are emitted in their stored
            // orientation (coded dims, residual orientation = stored), and the
            // caller bakes it later. `intrinsic_orientation` always reports the
            // stored value so re-encoders can re-tag correctly. The render
            // pipeline's save-stage gating in `build_render_pipeline` mirrors
            // this exactly via `DecoderState::adjust_orientation`.
            let (output_size, residual_orientation) = if decode_options.adjust_orientation {
                (display_size, Orientation::Identity)
            } else {
                (coded_size, data.orientation)
            };
            self.basic_info = Some(JxlBasicInfo {
                size: output_size,
                coded_size,
                bit_depth: if data.bit_depth.floating_point_sample() {
                    JxlBitDepth::Float {
                        bits_per_sample: data.bit_depth.bits_per_sample(),
                        exponent_bits_per_sample: data.bit_depth.exponent_bits_per_sample(),
                    }
                } else {
                    JxlBitDepth::Int {
                        bits_per_sample: data.bit_depth.bits_per_sample(),
                    }
                },
                orientation: residual_orientation,
                intrinsic_orientation: data.orientation,
                extra_channels: data
                    .extra_channel_info
                    .iter()
                    .map(|info| JxlExtraChannel {
                        ec_type: info.ec_type,
                        alpha_associated: info.alpha_associated(),
                        bits_per_sample: info.bit_depth().bits_per_sample(),
                        name: info.name().to_owned(),
                        dim_shift: info.dim_shift(),
                    })
                    .collect(),
                animation: data
                    .animation
                    .as_ref()
                    .map(|anim| crate::api::JxlAnimation {
                        tps_numerator: anim.tps_numerator,
                        tps_denominator: anim.tps_denominator,
                        num_loops: anim.num_loops,
                        have_timecodes: anim.have_timecodes,
                    }),
                uses_original_profile: !data.xyb_encoded,
                tone_mapping: ToneMapping {
                    intensity_target: data.tone_mapping.intensity_target,
                    min_nits: data.tone_mapping.min_nits,
                    relative_to_max_display: data.tone_mapping.relative_to_max_display,
                    linear_below: data.tone_mapping.linear_below,
                },
                preview_size: data
                    .preview
                    .as_ref()
                    .map(|p| (p.xsize() as usize, p.ysize() as usize)),
                intrinsic_size: data
                    .intrinsic_size
                    .as_ref()
                    .map(|s| (s.xsize() as usize, s.ysize() as usize)),
            });
            self.file_header = Some(file_header);
            let bits = br.total_bits_read();
            self.non_section_buf.consume(bits / 8);
            self.non_section_bit_offset = (bits % 8) as u8;
        }

        if self.decoder_state.is_none() && self.embedded_color_profile.is_none() {
            let file_header = self.file_header.as_ref().unwrap();

            // Parse (or extract from file header) the ICC profile.
            let mut br = BitReader::new(&self.non_section_buf);
            br.skip_bits(self.non_section_bit_offset as usize)?;
            let embedded_color_profile = if file_header.image_metadata.color_encoding.want_icc {
                if self.icc_parser.is_none() {
                    self.icc_parser = Some(IncrementalIccReader::new(
                        &mut br,
                        decode_options.limits.max_icc_size,
                    )?);
                }
                let icc_parser = self.icc_parser.as_mut().unwrap();
                let mut bits = br.total_bits_read();
                for _ in 0..icc_parser.remaining() {
                    match icc_parser.read_one(&mut br) {
                        Ok(()) => bits = br.total_bits_read(),
                        Err(Error::OutOfBounds(c)) => {
                            self.non_section_buf.consume(bits / 8);
                            self.non_section_bit_offset = (bits % 8) as u8;
                            // Estimate >= one bit per remaining character to read.
                            return Err(Error::OutOfBounds(c + icc_parser.remaining() / 8));
                        }
                        Err(e) => return Err(e),
                    }
                }
                let icc_result = self.icc_parser.take().unwrap().finalize(&mut br);
                self.non_section_buf.consume(bits / 8);
                self.non_section_bit_offset = (bits % 8) as u8;
                JxlColorProfile::Icc(icc_result?)
            } else {
                JxlColorProfile::Simple(JxlColorEncoding::from_internal(
                    &file_header.image_metadata.color_encoding,
                )?)
            };
            self.embedded_color_profile = Some(embedded_color_profile.clone());

            let xyb_encoded = file_header.image_metadata.xyb_encoded;
            let is_gray = file_header.image_metadata.color_encoding.color_space == ColorSpace::Gray;
            self.xyb_encoded = xyb_encoded;
            self.is_gray = is_gray;

            // Only set default pixel_format if not already configured (e.g. via rewind)
            if self.pixel_format.is_none() {
                self.pixel_format = Some(JxlPixelFormat {
                    color_type: if is_gray {
                        JxlColorType::Grayscale
                    } else {
                        JxlColorType::Rgb
                    },
                    color_data_format: Some(JxlDataFormat::F32 {
                        endianness: Endianness::native(),
                    }),
                    extra_channel_format: vec![
                        Some(JxlDataFormat::F32 {
                            endianness: Endianness::native()
                        });
                        file_header.image_metadata.extra_channel_info.len()
                    ],
                });
            }

            if let Some(user_profile) = &self.output_color_profile {
                // Validate user's output color profile choice (libjxl compatibility)
                // For non-XYB without CMS: only same encoding as embedded is allowed
                if !xyb_encoded
                    && decode_options.cms.is_none()
                    && *user_profile != embedded_color_profile
                {
                    return Err(Error::NonXybOutputNoCMS);
                }
            } else {
                self.update_default_output_color_profile();
            }

            let mut br = BitReader::new(&self.non_section_buf);
            br.skip_bits(self.non_section_bit_offset as usize)?;
            br.jump_to_byte_boundary()?;
            self.non_section_buf.consume(br.total_bits_read() / 8);

            // We now have image information.
            let mut decoder_state = DecoderState::new(self.file_header.take().unwrap());
            apply_decoder_options(
                &mut decoder_state,
                decode_options,
                &self.embedded_color_profile,
            );
            self.decoder_state = Some(decoder_state);
            // Reset bit offset to 0 since we've consumed everything up to a byte boundary
            self.non_section_bit_offset = 0;
            return Ok(());
        }

        let decoder_state = self.decoder_state.as_mut().unwrap();

        if self.frame_header.is_none() {
            // We don't have a frame header yet. Try parsing that.
            let mut br = BitReader::new(&self.non_section_buf);
            br.skip_bits(self.non_section_bit_offset as usize)?;

            // For preview frames, use the preview dimensions instead of main image dimensions
            let nonserialized = if !self.preview_done {
                decoder_state
                    .file_header
                    .preview_frame_header_nonserialized()
                    .unwrap_or_else(|| decoder_state.file_header.frame_header_nonserialized())
            } else {
                decoder_state.file_header.frame_header_nonserialized()
            };

            let mut frame_header = FrameHeader::read_unconditional(&(), &mut br, &nonserialized)?;
            frame_header.postprocess(&nonserialized);
            check_size_limit(
                &decode_options.limits,
                frame_header.size(),
                frame_header.num_extra_channels as usize,
            )?;

            // Initialize storage buffers for available sections.
            self.lf_global_section = None;
            self.lf_sections.clear();
            self.hf_global_section = None;
            // Use fallible allocation: `num_groups()` is derived from the
            // (untrusted) frame header dimensions and can be astronomically
            // large for malformed inputs. Avoid aborting the process on OOM and
            // return a recoverable error instead. (port libjxl/jxl-rs#774,
            // fixes #770.)
            let num_groups = frame_header.num_groups();
            let num_passes = frame_header.passes.num_passes as usize;
            let mut hf_sections = Vec::new_with_capacity(num_groups)?;
            for _ in 0..num_groups {
                let mut row = Vec::new_with_capacity(num_passes)?;
                for _ in 0..num_passes {
                    row.push(None);
                }
                hf_sections.push(row);
            }
            self.hf_sections = hf_sections;
            self.candidate_hf_sections.clear();

            self.frame_header = Some(frame_header);
            let bits = br.total_bits_read();
            self.non_section_buf.consume(bits / 8);
            self.non_section_bit_offset = (bits % 8) as u8;
        }

        let toc = {
            let mut br = BitReader::new(&self.non_section_buf);
            br.skip_bits(self.non_section_bit_offset as usize)?;
            if self.toc_parser.is_none() {
                let num_toc_entries = self.frame_header.as_ref().unwrap().num_toc_entries();
                self.toc_parser = Some(IncrementalTocReader::new(num_toc_entries as u32, &mut br)?);
            }

            let toc_parser = self.toc_parser.as_mut().unwrap();
            let mut bits = br.total_bits_read();
            while !toc_parser.is_complete() {
                match toc_parser.read_step(&mut br) {
                    Ok(()) => bits = br.total_bits_read(),
                    Err(Error::OutOfBounds(c)) => {
                        self.non_section_buf.consume(bits / 8);
                        self.non_section_bit_offset = (bits % 8) as u8;
                        // Estimate >= 16 bits per remaining entry to read.
                        return Err(Error::OutOfBounds(
                            c + toc_parser.remaining_entries() as usize * 2,
                        ));
                    }
                    Err(e) => return Err(e),
                }
            }
            br.jump_to_byte_boundary()?;

            bits = br.total_bits_read();
            self.non_section_buf.consume(bits / 8);
            self.non_section_bit_offset = (bits % 8) as u8;
            self.toc_parser.take().unwrap().finalize()
        };

        // Save file_header before creating frame (for preview frame recovery)
        self.saved_file_header = self.decoder_state.as_ref().map(|ds| ds.file_header.clone());

        let frame = Frame::from_header_and_toc(
            self.frame_header.take().unwrap(),
            toc,
            self.decoder_state.take().unwrap(),
        )?;

        let mut sections: Vec<_> = frame
            .toc()
            .entries
            .iter()
            .map(|x| SectionBuffer {
                len: *x as usize,
                data: vec![],
                section: Section::LfGlobal, // will be fixed later
            })
            .collect();

        let order = if frame.toc().permuted {
            frame.toc().permutation.0.clone()
        } else {
            (0..sections.len() as u32).collect()
        };

        if sections.len() > 1 {
            let base_sections = [Section::LfGlobal, Section::HfGlobal];
            let lf_sections = (0..frame.header().num_lf_groups()).map(|x| Section::Lf { group: x });
            let hf_sections = (0..frame.header().passes.num_passes).flat_map(|p| {
                (0..frame.header().num_groups()).map(move |g| Section::Hf {
                    group: g,
                    pass: p as usize,
                })
            });

            for section in base_sections
                .into_iter()
                .chain(lf_sections)
                .chain(hf_sections)
            {
                sections[order[frame.get_section_idx(section)] as usize].section = section;
            }
        }

        self.sections = sections.into_iter().collect();
        self.ready_section_data = 0;

        // Move data from the pre-section buffer into the sections.
        // Allocate with SECTION_PADDING extra zero bytes so BitReader::refill()
        // always takes the fast 8-byte read path.
        for buf in self.sections.iter_mut() {
            if self.non_section_buf.is_empty() {
                break;
            }
            let mut data = Vec::new();
            data.try_reserve_exact(buf.len + SECTION_PADDING)?;
            data.resize(buf.len + SECTION_PADDING, 0);
            buf.data = data;
            self.ready_section_data += self
                .non_section_buf
                .take(&mut [IoSliceMut::new(&mut buf.data[..buf.len])]);
        }

        self.section_state =
            SectionState::new(frame.header().num_lf_groups(), frame.header().num_groups());

        self.frame = Some(frame);

        Ok(())
    }
}
