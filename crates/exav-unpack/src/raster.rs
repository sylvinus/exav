//! What a reader says of the samples of a member that is raw pixels with no
//! file header, so that a consumer can build them. The one piece of pixel
//! code here is [`Predictor::undo`], which the PDF reader also runs on the
//! streams that are not images.

/// The samples of a PDF image XObject, as its dictionary describes them. The
/// member's bytes are the stream with its filters undone, except a predictor
/// (`predictor`: its rows still carry the tag byte) or a codec (`codec`: the
/// bytes are still its coded stream).
///
/// New fields may appear in any release: build one with `..Raster::default()`
/// for the fields you do not set.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Raster {
    /// `/Width`.
    pub width: u32,
    /// `/Height`.
    pub height: u32,
    /// `/BitsPerComponent`: 1, 2, 4, 8 or 16. 1 for an image mask.
    pub bits: u8,
    pub space: RasterSpace,
    /// `/Decode`, as written (at most eight numbers), when the dictionary has
    /// one.
    pub decode: Option<Vec<f32>>,
    /// The predictor of the stream's last filter, when it has one.
    pub predictor: Option<Predictor>,
    /// Set when the bytes are an image codec's stream that this crate does not
    /// decode, not samples.
    pub codec: Option<RasterCodec>,
}

/// A color space, as far as a pixel builder needs it.
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub enum RasterSpace {
    /// `DeviceGray`, `CalGray`, or an ICC profile of one component.
    #[default]
    Gray,
    /// `DeviceRGB`, `CalRGB`, or an ICC profile of three components.
    Rgb,
    /// `DeviceCMYK`, or an ICC profile of four components.
    Cmyk,
    /// `Indexed`: a sample is an index into `palette`, `base` components to
    /// an entry, entries `0..=hival`. A palette shorter than that is as the
    /// file has it.
    Indexed {
        base: Box<RasterSpace>,
        hival: u8,
        palette: Vec<u8>,
    },
    /// An image mask (`/ImageMask true`): one bit per pixel.
    Mask,
    /// Any other space (`Lab`, `Separation`, `DeviceN`...), by name, or why
    /// the dictionary's could not be read.
    Other(String),
    /// An image whose dictionary does not say how big it is or how its
    /// samples are stored (`/Width`, `/Height`, `/BitsPerComponent` or
    /// `/ColorSpace` missing or out of reach): `width`, `height` and `bits`
    /// are then 0, and there are no samples to build.
    Undescribed,
}

/// A PNG or TIFF predictor (`/Predictor` and the rest of `/DecodeParms`) that
/// is still to be undone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Predictor {
    /// `/Predictor`: 2 for TIFF, 10 to 15 for PNG.
    pub kind: u8,
    /// `/Colors`.
    pub colors: u32,
    /// `/BitsPerComponent` of the parameters.
    pub bits: u8,
    /// `/Columns`.
    pub columns: u32,
}

impl Predictor {
    /// The bytes of a row of samples, and whether a byte that says how the
    /// row was written leads it (PNG). `None` for parameters no predictor has.
    pub fn row(&self) -> Option<(u64, bool)> {
        let png = (10..=15).contains(&self.kind);
        if !(png || self.kind == 2)
            || !(1..=255).contains(&self.colors)
            || !matches!(self.bits, 1 | 2 | 4 | 8 | 16)
            || self.columns == 0
        {
            return None;
        }
        let pixel = u64::from(self.colors) * u64::from(self.bits);
        Some(((pixel * u64::from(self.columns)).div_ceil(8), png))
    }

    /// Undoes the predictor in `data`, every row, the last one as far as it
    /// goes: the output is never longer than the input. `false`, with `data`
    /// as it was, for parameters no predictor has.
    pub fn undo(&self, data: &mut Vec<u8>) -> bool {
        let Some((rowlen, png)) = self.row() else {
            return false;
        };
        // A row longer than the data is the data.
        let rowlen = usize::try_from(rowlen)
            .map_or(data.len(), |n| n.min(data.len()))
            .max(1);
        let colors = self.colors as usize;
        if png {
            undo_png(data, rowlen, (colors * usize::from(self.bits)).div_ceil(8));
        } else {
            let samples = usize::try_from(u64::from(self.colors) * u64::from(self.columns))
                .unwrap_or(usize::MAX);
            undo_tiff(data, rowlen, colors, self.bits, samples);
        }
        true
    }
}

/// PNG predictors: every row is a byte that says how it was written, then
/// `rowlen` bytes. A byte past 4 is no prediction. `bpp` is the bytes in a
/// pixel.
fn undo_png(data: &mut Vec<u8>, rowlen: usize, bpp: usize) {
    let stride = rowlen + 1;
    let mut written = 0;
    let mut y = 0;
    while y * stride < data.len() {
        let src = y * stride;
        let dst = y * rowlen;
        let tag = data[src];
        let have = rowlen.min(data.len() - src - 1);
        // The row moves down over the bytes of the rows before it, which are
        // done with: its place is never past where it was.
        data.copy_within(src + 1..src + 1 + have, dst);
        for i in 0..have {
            let left = if i >= bpp { data[dst + i - bpp] } else { 0 };
            let (up, up_left) = if y > 0 {
                let above = dst - rowlen + i;
                (data[above], if i >= bpp { data[above - bpp] } else { 0 })
            } else {
                (0, 0)
            };
            let predicted = match tag {
                1 => left,
                2 => up,
                3 => ((u16::from(left) + u16::from(up)) / 2) as u8,
                4 => paeth(left, up, up_left),
                _ => 0,
            };
            data[dst + i] = data[dst + i].wrapping_add(predicted);
        }
        written = dst + have;
        y += 1;
    }
    data.truncate(written);
}

fn paeth(a: u8, b: u8, c: u8) -> u8 {
    let (a, b, c) = (i32::from(a), i32::from(b), i32::from(c));
    let p = a + b - c;
    let (pa, pb, pc) = ((p - a).abs(), (p - b).abs(), (p - c).abs());
    if pa <= pb && pa <= pc {
        a as u8
    } else if pb <= pc {
        b as u8
    } else {
        c as u8
    }
}

/// The TIFF predictor: every sample is the difference to the one `colors`
/// before it in its row. `samples` is the most a row holds.
fn undo_tiff(data: &mut [u8], rowlen: usize, colors: usize, bits: u8, samples: usize) {
    for row in data.chunks_mut(rowlen) {
        match bits {
            8 => {
                for i in colors..row.len().min(samples) {
                    row[i] = row[i].wrapping_add(row[i - colors]);
                }
            }
            16 => {
                for i in colors..(row.len() / 2).min(samples) {
                    let at = |k: usize| u16::from_be_bytes([row[2 * k], row[2 * k + 1]]);
                    let sum = at(i).wrapping_add(at(i - colors)).to_be_bytes();
                    row[2 * i..2 * i + 2].copy_from_slice(&sum);
                }
            }
            _ => {
                let bits = usize::from(bits);
                let mask = (1u8 << bits) - 1;
                // The sample `k`: the byte it is in, and its shift.
                let place = |k: usize| (k * bits / 8, 8 - bits - k * bits % 8);
                for i in colors..(row.len() * 8 / bits).min(samples) {
                    let (byte, shift) = place(i);
                    let (before, before_shift) = place(i - colors);
                    let sum = ((row[byte] >> shift) & mask)
                        .wrapping_add((row[before] >> before_shift) & mask)
                        & mask;
                    row[byte] = (row[byte] & !(mask << shift)) | (sum << shift);
                }
            }
        }
    }
}

/// An image codec that is not decoded here.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RasterCodec {
    /// `CCITTFaxDecode`, with its parameters.
    Ccitt {
        /// `/K`.
        k: i32,
        /// `/EndOfLine`.
        end_of_line: bool,
        /// `/EncodedByteAlign`.
        encoded_byte_align: bool,
        /// `/BlackIs1`.
        black_is_1: bool,
        /// `/Columns`.
        columns: u32,
        /// `/Rows`.
        rows: u32,
    },
    /// `JBIG2Decode`.
    Jbig2 {
        /// The stream `/JBIG2Globals` names, with its filters undone: the
        /// segments shared by the images of a document. The images that name
        /// the same stream share these bytes.
        globals: Option<std::sync::Arc<[u8]>>,
        /// The dictionary names globals and they could not be read (not a
        /// stream, a filter that fails, or more than the budget leaves).
        globals_unread: bool,
    },
}
