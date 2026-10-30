// Copyright (c) the JPEG XL Project Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use std::io::IoSliceMut;

use crate::container::frame_index::FrameIndexBox;
use crate::container::gain_map::GainMapBundle;
use crate::error::{Error, Result};
use crate::util::NewWithCapacity;

use crate::api::{
    JxlBitstreamInput, JxlSignatureType, check_signature_internal, inner::process::SmallBuffer,
};

#[derive(Clone)]
enum ParseState {
    SignatureNeeded,
    BoxNeeded,
    CodestreamBox(u64),
    SkippableBox(u64),
    #[cfg(feature = "jpeg")]
    JbrdBox(u64),
    /// Buffering a jxli box: (remaining bytes, accumulated content).
    BufferingFrameIndex(u64, Vec<u8>),
    /// Buffering a jhgm box: (remaining bytes, accumulated content).
    BufferingGainMap(u64, Vec<u8>),
    /// Buffering an Exif box: (remaining bytes, accumulated content).
    BufferingExif(u64, Vec<u8>),
    /// Buffering an xml (XMP) box: (remaining bytes, accumulated content).
    BufferingXmp(u64, Vec<u8>),
    /// Buffering a brob (brotli-compressed) box: (remaining bytes, accumulated
    /// content). The content is `[4-byte inner box type][brotli payload]`; once
    /// complete it is decompressed and routed to exif/xmp by the inner type.
    #[cfg(feature = "jpeg")]
    BufferingBrob(u64, Vec<u8>),
}

enum CodestreamBoxType {
    None,
    Jxlc,
    Jxlp(u32),
    LastJxlp,
}

pub(super) struct BoxParser {
    pub(super) box_buffer: SmallBuffer,
    state: ParseState,
    box_type: CodestreamBoxType,
    #[cfg(feature = "jpeg")]
    jbrd_data: Option<Vec<u8>>,
    /// Parsed frame index box, if present in the file.
    pub(super) frame_index: Option<FrameIndexBox>,
    /// Parsed gain map bundle, if present in the file.
    pub(super) gain_map: Option<GainMapBundle>,
    /// Raw EXIF data from the `Exif` container box (without the 4-byte TIFF offset prefix).
    pub(super) exif: Option<Vec<u8>>,
    /// Raw XMP data from the `xml ` container box.
    pub(super) xmp: Option<Vec<u8>>,
}

impl BoxParser {
    pub(super) fn new() -> Self {
        BoxParser {
            box_buffer: SmallBuffer::new(128),
            state: ParseState::SignatureNeeded,
            box_type: CodestreamBoxType::None,
            #[cfg(feature = "jpeg")]
            jbrd_data: None,
            frame_index: None,
            gain_map: None,
            exif: None,
            xmp: None,
        }
    }

    /// Take the accumulated JBRD box data, if any was found.
    #[cfg(feature = "jpeg")]
    pub(super) fn take_jbrd_data(&mut self) -> Option<Vec<u8>> {
        self.jbrd_data.take()
    }

    // Reads input until the next byte of codestream is available.
    // This function might over-read bytes. Thus, the contents of self.box_buffer should always be
    // read after this function call.
    // Returns the number of codestream bytes that will be available to be read after this call,
    // including any bytes in self.box_buffer.
    // Might return `u64::MAX`, indicating that the rest of the file is codestream.
    pub(super) fn get_more_codestream(&mut self, input: &mut dyn JxlBitstreamInput) -> Result<u64> {
        loop {
            match self.state.clone() {
                ParseState::SignatureNeeded => {
                    self.box_buffer.refill(|b| input.read(b), None)?;
                    match check_signature_internal(&self.box_buffer)? {
                        None => return Err(Error::InvalidSignature),
                        Some(JxlSignatureType::Codestream) => {
                            self.state = ParseState::CodestreamBox(u64::MAX);
                            return Ok(u64::MAX);
                        }
                        Some(JxlSignatureType::Container) => {
                            self.box_buffer
                                .consume(JxlSignatureType::Container.signature().len());
                            self.state = ParseState::BoxNeeded;
                        }
                    }
                }
                ParseState::CodestreamBox(b) => {
                    return Ok(b);
                }
                ParseState::SkippableBox(mut s) => {
                    let num = s.min(usize::MAX as u64) as usize;
                    let skipped = if !self.box_buffer.is_empty() {
                        self.box_buffer.consume(num)
                    } else {
                        input.skip(num)?
                    };
                    if skipped == 0 {
                        return Err(Error::OutOfBounds(num));
                    }
                    s -= skipped as u64;
                    if s == 0 {
                        self.state = ParseState::BoxNeeded;
                    } else {
                        self.state = ParseState::SkippableBox(s);
                    }
                }
                #[cfg(feature = "jpeg")]
                ParseState::JbrdBox(mut remaining) => {
                    // Read jbrd box content into buffer
                    let num = remaining.min(usize::MAX as u64) as usize;
                    let jbrd = self.jbrd_data.get_or_insert_with(Vec::new);
                    if !self.box_buffer.is_empty() {
                        let avail = self.box_buffer.len().min(num);
                        jbrd.extend_from_slice(&self.box_buffer[..avail]);
                        self.box_buffer.consume(avail);
                        remaining -= avail as u64;
                    } else {
                        // Read from input using IoSliceMut
                        let chunk_size = num.min(65536);
                        let start = jbrd.len();
                        jbrd.resize(start + chunk_size, 0);
                        let read =
                            input.read(&mut [std::io::IoSliceMut::new(&mut jbrd[start..])])?;
                        if read == 0 {
                            jbrd.truncate(start);
                            return Err(Error::OutOfBounds(num));
                        }
                        jbrd.truncate(start + read);
                        remaining -= read as u64;
                    }
                    if remaining == 0 {
                        self.state = ParseState::BoxNeeded;
                    } else {
                        self.state = ParseState::JbrdBox(remaining);
                    }
                }
                ParseState::BufferingFrameIndex(mut remaining, mut buf) => {
                    let num = remaining.min(usize::MAX as u64) as usize;
                    if !self.box_buffer.is_empty() {
                        let take = num.min(self.box_buffer.len());
                        buf.extend_from_slice(&self.box_buffer[..take]);
                        self.box_buffer.consume(take);
                        remaining -= take as u64;
                    } else {
                        let old_len = buf.len();
                        buf.resize(old_len + num, 0);
                        let read = input.read(&mut [IoSliceMut::new(&mut buf[old_len..])])?;
                        if read == 0 {
                            return Err(Error::OutOfBounds(num));
                        }
                        buf.truncate(old_len + read);
                        remaining -= read as u64;
                    }
                    if remaining == 0 {
                        // Parse the buffered frame index box.
                        self.frame_index = Some(FrameIndexBox::parse(&buf)?);
                        self.state = ParseState::BoxNeeded;
                    } else {
                        self.state = ParseState::BufferingFrameIndex(remaining, buf);
                    }
                }
                ParseState::BufferingGainMap(mut remaining, mut buf) => {
                    let num = remaining.min(usize::MAX as u64) as usize;
                    if !self.box_buffer.is_empty() {
                        let take = num.min(self.box_buffer.len());
                        buf.extend_from_slice(&self.box_buffer[..take]);
                        self.box_buffer.consume(take);
                        remaining -= take as u64;
                    } else {
                        let old_len = buf.len();
                        buf.resize(old_len + num, 0);
                        let read = input.read(&mut [IoSliceMut::new(&mut buf[old_len..])])?;
                        if read == 0 {
                            return Err(Error::OutOfBounds(num));
                        }
                        buf.truncate(old_len + read);
                        remaining -= read as u64;
                    }
                    if remaining == 0 {
                        // Parse the buffered gain map bundle.
                        self.gain_map = Some(GainMapBundle::parse(&buf)?);
                        self.state = ParseState::BoxNeeded;
                    } else {
                        self.state = ParseState::BufferingGainMap(remaining, buf);
                    }
                }
                ParseState::BufferingExif(mut remaining, mut buf) => {
                    let num = remaining.min(usize::MAX as u64) as usize;
                    if !self.box_buffer.is_empty() {
                        let take = num.min(self.box_buffer.len());
                        buf.extend_from_slice(&self.box_buffer[..take]);
                        self.box_buffer.consume(take);
                        remaining -= take as u64;
                    } else {
                        let old_len = buf.len();
                        buf.resize(old_len + num, 0);
                        let read = input.read(&mut [IoSliceMut::new(&mut buf[old_len..])])?;
                        if read == 0 {
                            return Err(Error::OutOfBounds(num));
                        }
                        buf.truncate(old_len + read);
                        remaining -= read as u64;
                    }
                    if remaining == 0 {
                        // Exif box payload starts with a 4-byte TIFF header offset
                        // (big-endian u32). Strip it to return raw EXIF/TIFF data.
                        if buf.len() >= 4 {
                            self.exif = Some(buf[4..].to_vec());
                        }
                        self.state = ParseState::BoxNeeded;
                    } else {
                        self.state = ParseState::BufferingExif(remaining, buf);
                    }
                }
                ParseState::BufferingXmp(mut remaining, mut buf) => {
                    let num = remaining.min(usize::MAX as u64) as usize;
                    if !self.box_buffer.is_empty() {
                        let take = num.min(self.box_buffer.len());
                        buf.extend_from_slice(&self.box_buffer[..take]);
                        self.box_buffer.consume(take);
                        remaining -= take as u64;
                    } else {
                        let old_len = buf.len();
                        buf.resize(old_len + num, 0);
                        let read = input.read(&mut [IoSliceMut::new(&mut buf[old_len..])])?;
                        if read == 0 {
                            return Err(Error::OutOfBounds(num));
                        }
                        buf.truncate(old_len + read);
                        remaining -= read as u64;
                    }
                    if remaining == 0 {
                        self.xmp = Some(buf);
                        self.state = ParseState::BoxNeeded;
                    } else {
                        self.state = ParseState::BufferingXmp(remaining, buf);
                    }
                }
                #[cfg(feature = "jpeg")]
                ParseState::BufferingBrob(mut remaining, mut buf) => {
                    let num = remaining.min(usize::MAX as u64) as usize;
                    if !self.box_buffer.is_empty() {
                        let take = num.min(self.box_buffer.len());
                        buf.extend_from_slice(&self.box_buffer[..take]);
                        self.box_buffer.consume(take);
                        remaining -= take as u64;
                    } else {
                        let old_len = buf.len();
                        buf.resize(old_len + num, 0);
                        let read = input.read(&mut [IoSliceMut::new(&mut buf[old_len..])])?;
                        if read == 0 {
                            return Err(Error::OutOfBounds(num));
                        }
                        buf.truncate(old_len + read);
                        remaining -= read as u64;
                    }
                    if remaining == 0 {
                        // brob payload = [4-byte inner box type][brotli stream].
                        if buf.len() >= 4
                            && let Some(out) = brotli_decompress_box(&buf[4..])
                        {
                            match &buf[0..4] {
                                // Same handling as a raw Exif box: strip the
                                // 4-byte TIFF-header offset.
                                b"Exif" if out.len() >= 4 => self.exif = Some(out[4..].to_vec()),
                                b"xml " => self.xmp = Some(out),
                                _ => {}
                            }
                        }
                        self.state = ParseState::BoxNeeded;
                    } else {
                        self.state = ParseState::BufferingBrob(remaining, buf);
                    }
                }
                ParseState::BoxNeeded => {
                    self.box_buffer.refill(|b| input.read(b), None)?;
                    let min_len = match &self.box_buffer[..] {
                        [0, 0, 0, 1, ..] => 16,
                        _ => 8,
                    };
                    if self.box_buffer.len() <= min_len {
                        return Err(Error::OutOfBounds(min_len - self.box_buffer.len()));
                    }
                    let ty: [_; 4] = self.box_buffer[4..8].try_into().unwrap();
                    let extra_len = if &ty == b"jxlp" { 4 } else { 0 };
                    if self.box_buffer.len() <= min_len + extra_len {
                        return Err(Error::OutOfBounds(
                            min_len + extra_len - self.box_buffer.len(),
                        ));
                    }
                    let box_len = match &self.box_buffer[..] {
                        [0, 0, 0, 1, ..] => {
                            u64::from_be_bytes(self.box_buffer[8..16].try_into().unwrap())
                        }
                        _ => u32::from_be_bytes(self.box_buffer[0..4].try_into().unwrap()) as u64,
                    };
                    // Per JXL spec: jxlc box with length 0 has special meaning "extends to EOF"
                    let content_len = if box_len == 0 && (&ty == b"jxlp" || &ty == b"jxlc") {
                        u64::MAX
                    } else {
                        if box_len <= (min_len + extra_len) as u64 {
                            return Err(Error::InvalidBox);
                        }
                        box_len - min_len as u64 - extra_len as u64
                    };
                    match &ty {
                        b"jxlc" => {
                            if matches!(
                                self.box_type,
                                CodestreamBoxType::Jxlp(..) | CodestreamBoxType::LastJxlp
                            ) {
                                return Err(Error::InvalidBox);
                            }
                            self.box_type = CodestreamBoxType::Jxlc;
                            self.state = ParseState::CodestreamBox(content_len);
                        }
                        b"jxlp" => {
                            let index = u32::from_be_bytes(
                                self.box_buffer[min_len..min_len + 4].try_into().unwrap(),
                            );
                            let wanted_idx = match self.box_type {
                                CodestreamBoxType::Jxlc | CodestreamBoxType::LastJxlp => {
                                    return Err(Error::InvalidBox);
                                }
                                CodestreamBoxType::None => 0,
                                CodestreamBoxType::Jxlp(i) => i + 1,
                            };
                            let last = index & 0x80000000 != 0;
                            let idx = index & 0x7fffffff;
                            if idx != wanted_idx {
                                return Err(Error::InvalidBox);
                            }
                            self.box_type = if last {
                                CodestreamBoxType::LastJxlp
                            } else {
                                CodestreamBoxType::Jxlp(idx)
                            };
                            self.state = ParseState::CodestreamBox(content_len);
                        }
                        #[cfg(feature = "jpeg")]
                        b"jbrd" => {
                            self.state = ParseState::JbrdBox(content_len);
                        }
                        b"jhgm" => {
                            if content_len == u64::MAX {
                                return Err(Error::InvalidBox);
                            }
                            // Reasonable size limit for a gain map bundle (256 MB).
                            // Gain maps contain a full JXL codestream so they can be large.
                            if content_len > 256 * 1024 * 1024 {
                                self.state = ParseState::SkippableBox(content_len);
                            } else {
                                // Use fallible alloc — capacity reserves up to
                                // 256 MB and a global allocator that can't
                                // satisfy the request must surface as a graceful
                                // error, never an `abort()` on the parser thread.
                                self.state = ParseState::BufferingGainMap(
                                    content_len,
                                    Vec::<u8>::new_with_capacity(content_len as usize)?,
                                );
                            }
                        }
                        b"jxli" => {
                            if content_len == u64::MAX {
                                return Err(Error::InvalidBox);
                            }
                            // Reasonable size limit for a frame index box (16 MB).
                            if content_len > 16 * 1024 * 1024 {
                                self.state = ParseState::SkippableBox(content_len);
                            } else {
                                self.state = ParseState::BufferingFrameIndex(
                                    content_len,
                                    Vec::<u8>::new_with_capacity(content_len as usize)?,
                                );
                            }
                        }
                        b"Exif" => {
                            if content_len == u64::MAX {
                                return Err(Error::InvalidBox);
                            }
                            // Reasonable size limit for EXIF data (16 MB).
                            if content_len > 16 * 1024 * 1024 {
                                self.state = ParseState::SkippableBox(content_len);
                            } else {
                                self.state = ParseState::BufferingExif(
                                    content_len,
                                    Vec::<u8>::new_with_capacity(content_len as usize)?,
                                );
                            }
                        }
                        b"xml " => {
                            if content_len == u64::MAX {
                                return Err(Error::InvalidBox);
                            }
                            // Reasonable size limit for XMP data (16 MB).
                            if content_len > 16 * 1024 * 1024 {
                                self.state = ParseState::SkippableBox(content_len);
                            } else {
                                self.state = ParseState::BufferingXmp(
                                    content_len,
                                    Vec::<u8>::new_with_capacity(content_len as usize)?,
                                );
                            }
                        }
                        // Brotli-compressed metadata box. The encoder wraps EXIF
                        // / XMP in `brob` when brotli shrinks them; decompress
                        // and route by inner box type. Needs brotli (jpeg feat).
                        #[cfg(feature = "jpeg")]
                        b"brob" => {
                            if content_len == u64::MAX || content_len > 16 * 1024 * 1024 {
                                self.state = ParseState::SkippableBox(content_len);
                            } else {
                                self.state = ParseState::BufferingBrob(
                                    content_len,
                                    Vec::<u8>::new_with_capacity(content_len as usize)?,
                                );
                            }
                        }
                        _ => {
                            self.state = ParseState::SkippableBox(content_len);
                        }
                    }
                    self.box_buffer.consume(min_len + extra_len);
                }
            }
        }
    }

    pub(super) fn consume_codestream(&mut self, amount: u64) {
        if let ParseState::CodestreamBox(cb) = &mut self.state {
            *cb = cb.checked_sub(amount).unwrap();
            if *cb == 0 {
                self.state = ParseState::BoxNeeded;
            }
        } else if amount != 0 {
            unreachable!()
        }
    }
}

/// Brotli-decompress a `brob` box payload (the bytes after the 4-byte inner box
/// type). Returns `None` on malformed input. Only built with the `jpeg` feature
/// (which provides `brotli`); without it `brob` boxes are skipped.
#[cfg(feature = "jpeg")]
fn brotli_decompress_box(compressed: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut out = Vec::new();
    brotli::Decompressor::new(compressed, 4096)
        .read_to_end(&mut out)
        .ok()?;
    Some(out)
}
