//! What a reader says of the samples of a member that is raw pixels with no
//! file header, so that a consumer can build them. Data only: no pixel code
//! lives in this crate.

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
