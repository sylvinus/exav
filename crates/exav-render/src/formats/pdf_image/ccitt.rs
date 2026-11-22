//! CCITTFaxDecode (T.4 and T.6), through hayro-ccitt.

use hayro_ccitt::{DecodeSettings, Decoder, DecoderContext, EncodingMode, decode};

use super::{Error, row_bytes};

/// The stream's `/DecodeParms`, and the image dictionary's size.
#[derive(Clone, Copy, Debug)]
pub struct CcittParams {
    pub width: u32,
    pub height: u32,
    /// Negative: Group 4; 0: Group 3 one-dimensional; positive: Group 3
    /// two-dimensional.
    pub k: i32,
    pub end_of_line: bool,
    pub encoded_byte_align: bool,
    pub black_is_1: bool,
    pub columns: u32,
    pub rows: u32,
}

/// `height` rows of `width` bits, each a whole number of bytes (cut from the
/// decoded row at a byte); a pixel is 1 when it is white, or black with
/// `black_is_1`. Rows the data does not reach
/// are left 0, as pdf.js's decoder leaves them, so a stream that decodes to
/// nothing is not an error. Only an image past `max_alloc` is.
pub fn decode_ccitt(data: &[u8], p: CcittParams, max_alloc: u64) -> Result<Vec<u8>, Error> {
    let stride = row_bytes(p.width);
    let out_len = stride as u64 * u64::from(p.height);
    // The output, and the decoder's two lines of colour changes.
    if out_len + u64::from(p.columns) * 16 > max_alloc {
        return Err(Error::new("Image too large"));
    }
    let mut out = vec![0; out_len as usize];
    let settings = DecodeSettings {
        columns: p.columns,
        rows: if p.rows > 0 { p.rows } else { p.height },
        end_of_block: true,
        end_of_line: p.end_of_line,
        rows_are_byte_aligned: p.encoded_byte_align,
        encoding: match p.k {
            k if k < 0 => EncodingMode::Group4,
            0 => EncodingMode::Group3_1D,
            _ => EncodingMode::Group3_2D,
        },
        strict: false,
    };
    let mut rows = Rows {
        out: &mut out,
        stride,
        // Whole bytes: pdf.js's decoder copies each row's first bytes.
        width: stride.saturating_mul(8),
        columns: p.columns as usize,
        height: p.height as usize,
        black_is_1: p.black_is_1,
        y: 0,
    };
    // An error leaves the rows decoded before it; the row it broke off in is
    // not given.
    let _ = decode(data, &mut rows, &mut DecoderContext::new(settings));
    Ok(out)
}

/// Writes each row the decoder gives: background, then its black runs.
struct Rows<'a> {
    out: &'a mut [u8],
    stride: usize,
    /// Pixels in a row of the output (whole bytes).
    width: usize,
    /// Pixels in a row the decoder gives.
    columns: usize,
    height: usize,
    black_is_1: bool,
    y: usize,
}

impl Decoder for Rows<'_> {
    fn push_row(&mut self, changes: &[u32]) {
        if self.y < self.height {
            let row = &mut self.out[self.y * self.stride..][..self.stride];
            row.fill(if self.black_is_1 { 0x00 } else { 0xFF });
            // Black from each even change to the next, or to the end of the row.
            for run in changes.chunks(2) {
                let from = run[0] as usize;
                let to = run.get(1).map_or(self.columns, |&c| c as usize);
                for x in from..to.min(self.width) {
                    let bit = 0x80 >> (x % 8);
                    if self.black_is_1 {
                        row[x / 8] |= bit;
                    } else {
                        row[x / 8] &= !bit;
                    }
                }
            }
        }
        self.y += 1;
    }
}
