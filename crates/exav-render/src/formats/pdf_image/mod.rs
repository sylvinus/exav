//! The images of PDF streams that pdf.js 6 decodes with C and C++ compiled
//! to WebAssembly (OpenJPEG for JPXDecode, PDFium's decoders for
//! JBIG2Decode and CCITTFaxDecode), decoded into the buffers those
//! decoders give pdf.js, so that @exav/viewer can stand in for them.
//!
//! The layouts were taken from pdf.js's own decoders, run as black boxes.

use std::fmt;

#[cfg(feature = "ccitt")]
mod ccitt;
#[cfg(feature = "jbig2")]
mod jbig2;
#[cfg(feature = "jp2")]
mod jpx;

#[cfg(feature = "ccitt")]
pub use ccitt::{decode_ccitt, CcittParams};
#[cfg(feature = "jbig2")]
pub use jbig2::decode_jbig2;
#[cfg(all(feature = "jbig2", feature = "image"))]
pub(crate) use jbig2::region_pixels;
#[cfg(feature = "jp2")]
pub use jpx::{decode_jpx, JpxImage, JpxParams};

/// Why a stream has no pixels. The message is what pdf.js reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error(&'static str);

impl Error {
    #[allow(dead_code)]
    pub(crate) const fn new(message: &'static str) -> Error {
        Error(message)
    }

    pub fn message(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for Error {}

/// Rows of `width` bits, each padded to a byte: a 1-bit image as pdf.js
/// reads one.
#[cfg(any(feature = "jbig2", feature = "ccitt"))]
pub(crate) fn row_bytes(width: u32) -> usize {
    width.div_ceil(8) as usize
}
