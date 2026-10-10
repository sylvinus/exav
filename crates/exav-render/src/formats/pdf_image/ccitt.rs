//! CCITTFaxDecode (T.4 and T.6), through hayro-ccitt.

use hayro_ccitt::{decode, DecodeSettings, Decoder, DecoderContext, EncodingMode};

use super::{row_bytes, Error};

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
    // Group 3 lines delimited by EOLs are byte-aligned by fill bits before
    // each EOL, so that it ends on the boundary. hayro-ccitt would align
    // right after the line, inside the fill or the EOL; unaligned, it reads
    // any fill as part of the EOL.
    let eol_aligned = p.k >= 0 && (has_eol(data, 4) || (p.end_of_line && has_eol(data, 64)));
    let settings = DecodeSettings {
        columns: p.columns,
        rows: if p.rows > 0 { p.rows } else { p.height },
        end_of_block: true,
        end_of_line: p.end_of_line,
        rows_are_byte_aligned: p.encoded_byte_align && !eol_aligned,
        encoding: match p.k {
            k if k < 0 => EncodingMode::Group4,
            0 => EncodingMode::Group3_1D,
            k => EncodingMode::Group3_2D { k: k as u32 },
        },
        invert_black: false,
    };
    let mut rows = Rows {
        out: &mut out,
        stride,
        // Whole bytes: pdf.js's decoder copies each row's first bytes.
        width: stride.saturating_mul(8),
        height: p.height as usize,
        black_is_1: p.black_is_1,
        x: 0,
        y: 0,
        started: false,
    };
    let result = decode(data, &mut rows, &mut DecoderContext::new(settings));
    // The row the data broke off in is given, white past its last pixel.
    if result.is_err() && (rows.y > 0 || rows.started) {
        rows.start();
    }
    Ok(out)
}

/// Whether the first `bytes` of `data` hold an EOL: 11 or more 0 bits, then
/// a 1. No code word holds 11 zeros. With 4 bytes, only an EOL the data
/// opens with fits.
fn has_eol(data: &[u8], bytes: usize) -> bool {
    let mut zeros = 0;
    for &b in data.iter().take(bytes) {
        for i in (0..8).rev() {
            if b >> i & 1 == 0 {
                zeros += 1;
            } else if zeros >= 11 {
                return true;
            } else if bytes <= 4 {
                return false;
            } else {
                zeros = 0;
            }
        }
    }
    false
}

/// Writes each row the decoder starts as background, then its pixels.
struct Rows<'a> {
    out: &'a mut [u8],
    stride: usize,
    width: usize,
    height: usize,
    black_is_1: bool,
    x: usize,
    y: usize,
    started: bool,
}

impl Rows<'_> {
    fn start(&mut self) {
        if !self.started && self.y < self.height {
            let white = if self.black_is_1 { 0x00 } else { 0xFF };
            let at = self.y * self.stride;
            self.out[at..at + self.stride].fill(white);
        }
        self.started = true;
    }
}

impl Decoder for Rows<'_> {
    fn push_pixels(&mut self, white: bool, count: u32) {
        // hayro-ccitt also reports empty runs, which start no row.
        if count == 0 {
            return;
        }
        self.start();
        let end = self.x.saturating_add(count as usize);
        if !white && self.y < self.height {
            let row = &mut self.out[self.y * self.stride..][..self.stride];
            for x in self.x..end.min(self.width) {
                let bit = 0x80 >> (x % 8);
                if self.black_is_1 {
                    row[x / 8] |= bit;
                } else {
                    row[x / 8] &= !bit;
                }
            }
        }
        self.x = end;
    }

    fn next_line(&mut self) {
        self.start();
        self.started = false;
        self.x = 0;
        self.y += 1;
    }
}
