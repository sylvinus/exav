// Copyright (c) the JPEG XL Project Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! JPEG reconstruction from JXL containers with JBRD boxes.
//!
//! When a JPEG file is losslessly transcoded to JXL, the JXL container
//! includes a `jbrd` (JPEG Bitstream Reconstruction Data) box alongside
//! the codestream. This module decodes that box and reconstructs the
//! original JPEG byte-exactly.

pub(crate) mod data;
mod jbrd;
mod writer;

pub use jbrd::decode_jbrd;
pub use writer::write_jpeg;

/// Fill the EXIF / XMP APPn placeholders in a reconstruction [`data::JpegData`]
/// with the payloads from the JXL container's `Exif` / `xml ` boxes.
///
/// When jxl-encoder transcodes a JPEG, it lifts the (first) EXIF and XMP APPn
/// markers into JXL container boxes, leaving an empty placeholder in the JBRD
/// `app_data`. Those boxes are parsed *after* the codestream, so the
/// reconstruction `JpegData` is built with empty placeholders and filled here
/// (at `take_jpeg_reconstruction` time) once the boxes are available.
///
/// `exif` is the raw TIFF payload (the box parser already stripped the JXL
/// 4-byte offset); `xmp` is the raw XML. Each is re-wrapped with the APP1
/// marker prefix (`Exif\0\0` / `http://ns.adobe.com/xap/1.0/\0`) the original
/// JPEG used, so the reconstructed marker is byte-exact.
/// ICC profile re-chunking: the standard `ICC_PROFILE` APP2 payload size used
/// by libjpeg / ImageMagick / libjxl (65535 marker - 2 len - 12 tag - 2 seq).
const ICC_CHUNK_PAYLOAD: usize = 65519;

pub(crate) fn fill_metadata(
    jpeg: &mut data::JpegData,
    exif: Option<Vec<u8>>,
    xmp: Option<Vec<u8>>,
    icc: Option<&[u8]>,
) {
    use data::AppMarkerType;
    // total_chunks for ICC = the number of empty Icc placeholders.
    let icc_total = jpeg
        .app_marker_type
        .iter()
        .zip(jpeg.app_data.iter())
        .filter(|(t, d)| **t == AppMarkerType::Icc && d.is_empty())
        .count();
    let mut exif = exif;
    let mut xmp = xmp;
    let mut icc_chunk = 0usize;
    for i in 0..jpeg.app_data.len() {
        // A non-empty entry is an inline (Unknown-type) marker — leave it.
        if !jpeg.app_data[i].is_empty() {
            continue;
        }
        match jpeg.app_marker_type[i] {
            AppMarkerType::Exif => {
                if let Some(tiff) = exif.take() {
                    let mut v = b"Exif\0\0".to_vec();
                    v.extend_from_slice(&tiff);
                    jpeg.app_data[i] = v;
                }
            }
            AppMarkerType::Xmp => {
                if let Some(xml) = xmp.take() {
                    let mut v = b"http://ns.adobe.com/xap/1.0/\0".to_vec();
                    v.extend_from_slice(&xml);
                    jpeg.app_data[i] = v;
                }
            }
            AppMarkerType::Icc => {
                // ICC APP2 markers are re-chunked from the codestream's embedded
                // ICC profile (the encoder lifts the profile into the JXL color
                // encoding and tags each original chunk as an empty placeholder).
                // Each chunk: "ICC_PROFILE\0" + seq(1-based) + total + payload.
                if let Some(icc) = icc {
                    let start = icc_chunk * ICC_CHUNK_PAYLOAD;
                    if start < icc.len() && icc_total <= u8::MAX as usize {
                        let end = (start + ICC_CHUNK_PAYLOAD).min(icc.len());
                        let mut v = b"ICC_PROFILE\0".to_vec();
                        v.push((icc_chunk + 1) as u8);
                        v.push(icc_total as u8);
                        v.extend_from_slice(&icc[start..end]);
                        jpeg.app_data[i] = v;
                    }
                }
                icc_chunk += 1;
            }
            _ => {}
        }
    }
}
