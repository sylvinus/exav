//! The payloads of the QR codes in an image, for a scanner or a search: a
//! link in a QR code is a link a reader follows with a phone. The codes are
//! found and read by exav-qr in the image's pixels, in grey, a transparent pixel
//! taken as white (a code drawn on a transparent background).
//!
//! The search in one image is bounded by its pixels, by its time, by the memory
//! it holds, by the finder patterns and candidate grids it works on and by the
//! codes read; a limit that stopped it says so in [`Found::cut`]. [`search`]
//! is the entry for a caller that holds these as options: it is the one place
//! that turns them into limits and an outcome into a reason. The time, the
//! memory and the two counts are checked by exav-qr inside its own loops, which
//! can take far longer than the size of the image suggests (the grouping of
//! finder patterns copies the image once per candidate group).

use std::time::{Duration, Instant};

use exav_qr::{PreparedImage, SearchLimits, Stop};
use exav_unpack::{Raster, RasterCodec};

/// What the search in one image may spend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Pixels an image may have to be searched; `None`: any the decoder
    /// gives within its own limit.
    pub max_pixels: Option<u64>,
    /// Time the search may take; `None`: any.
    pub max_time: Option<Duration>,
    /// Codes read in one image; `None`: all.
    pub max_codes: Option<usize>,
    /// Finder patterns (the square a code has in three corners) the search
    /// may find in one image; `None`: any.
    pub max_finders: Option<usize>,
    /// Groups of three finder patterns the search may try as a grid in one
    /// image; `None`: any.
    pub max_grids: Option<usize>,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_pixels: Some(DEFAULT_MAX_PIXELS),
            max_time: Some(DEFAULT_MAX_TIME),
            max_codes: Some(DEFAULT_MAX_CODES),
            max_finders: Some(DEFAULT_MAX_FINDERS),
            max_grids: Some(DEFAULT_MAX_GRIDS),
        }
    }
}

/// Pixels searched in an image by default: a phone's photograph.
pub const DEFAULT_MAX_PIXELS: u64 = 50_000_000;
/// Time the search in an image may take by default.
pub const DEFAULT_MAX_TIME: Duration = Duration::from_secs(5);
/// Codes read in one image by default.
pub const DEFAULT_MAX_CODES: usize = 64;
/// Finder patterns found in one image by default.
pub const DEFAULT_MAX_FINDERS: usize = 1_000;
/// Groups of finder patterns tried as a grid in one image by default.
pub const DEFAULT_MAX_GRIDS: usize = 256;

/// What the search found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Found {
    /// The payload of each code read, as text (invalid UTF-8 replaced).
    pub payloads: Vec<String>,
    /// Why the search stopped before the end, when a limit stopped it: the
    /// image may hold more codes than were read.
    pub cut: Option<String>,
    /// Why the image was not read at all, when no setting makes it readable: it
    /// is recognised but does not decode, or is a PDF image that is not read
    /// (its dictionary, color space, predictor or JBIG2 globals).
    pub unread: Option<String>,
}

/// The codes in an image of `width` by `height` pixels whose grey level at
/// `(x, y)` is `grey(x, y)`. The search holds at most `max_alloc` bytes: the
/// grey image and its working buffers.
pub fn find_in_grey(
    width: usize,
    height: usize,
    grey: impl FnMut(usize, usize) -> u8,
    max_alloc: u64,
    limits: &Limits,
) -> Found {
    let deadline = deadline(limits);
    find_in_grey_by(width, height, grey, max_alloc, limits, deadline)
}

/// The reason an image of `pixels` pixels is not searched, when it has more
/// than `limits` allow.
fn over_pixel_limit(pixels: u64, limits: &Limits) -> Option<String> {
    let max = limits.max_pixels.filter(|&max| pixels > max)?;
    Some(format!(
        "QR codes: an image of {pixels} pixels, over the {max}-pixel limit"
    ))
}

/// When a search started now must be over; the clock is read only when there is
/// a time limit.
fn deadline(limits: &Limits) -> Option<Instant> {
    let time = limits.max_time?;
    Instant::now().checked_add(time)
}

/// Runs `f`, containing a panic of the reader on a crafted image where panics
/// unwind (`None`). Where they abort there is nothing to contain.
#[cfg(panic = "unwind")]
fn guarded<T>(f: impl FnOnce() -> T) -> Option<T> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).ok()
}

#[cfg(not(panic = "unwind"))]
fn guarded<T>(f: impl FnOnce() -> T) -> Option<T> {
    Some(f())
}

fn find_in_grey_by(
    width: usize,
    height: usize,
    grey: impl FnMut(usize, usize) -> u8,
    max_alloc: u64,
    limits: &Limits,
    deadline: Option<Instant>,
) -> Found {
    let mut found = Found::default();
    let pixels = (width as u64).saturating_mul(height as u64);
    if let Some(cut) = over_pixel_limit(pixels, limits) {
        found.cut = Some(cut);
        return found;
    }
    if width == 0 || height == 0 {
        return found;
    }
    let search = SearchLimits {
        deadline,
        max_finder_patterns: limits.max_finders,
        max_candidate_grids: limits.max_grids,
        max_bytes: Some(max_alloc),
    };
    let cut = |stop: Stop| match stop {
        Stop::Deadline => {
            let ms = limits.max_time.map_or(0, |t| t.as_millis());
            format!("QR codes: the search took over {ms} ms")
        }
        Stop::Memory => {
            format!("QR codes: the search needs more than {max_alloc} bytes of memory")
        }
        Stop::FinderPatterns => format!(
            "QR codes: more than {} finder patterns in an image",
            limits.max_finders.unwrap_or(0)
        ),
        Stop::CandidateGrids => format!(
            "QR codes: more than {} candidate grids in an image",
            limits.max_grids.unwrap_or(0)
        ),
    };
    let read = guarded(|| {
        let mut prepared =
            match PreparedImage::prepare_from_greyscale_within(width, height, grey, search) {
                Ok(prepared) => prepared,
                Err(stop) => {
                    found.cut = Some(cut(stop));
                    return;
                }
            };
        let detection = prepared.detect();
        if let Some(stop) = detection.stop {
            found.cut = Some(cut(stop));
        }
        for (i, grid) in detection.grids.iter().enumerate() {
            // Reading a code takes no step of the search, so its time is
            // checked here.
            if deadline.is_some_and(|d| Instant::now() >= d) {
                found.cut.get_or_insert_with(|| cut(Stop::Deadline));
                break;
            }
            if let Some(max) = limits.max_codes
                && i >= max
            {
                found
                    .cut
                    .get_or_insert_with(|| format!("QR codes: more than {max} in an image"));
                break;
            }
            let mut bytes = Vec::new();
            if grid.decode_to(&mut bytes).is_ok() {
                found
                    .payloads
                    .push(String::from_utf8_lossy(&bytes).into_owned());
            }
        }
    });
    if read.is_none() {
        found.cut = Some("QR codes: the reader failed on this image".to_string());
    }
    found
}

/// What a caller's options say about reading the codes of an image, as the
/// options hold them: counts, milliseconds and bytes, `None` for no limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    /// As [`Limits::max_pixels`].
    pub max_pixels: Option<u64>,
    /// Milliseconds, as [`Limits::max_time`].
    pub max_millis: Option<u64>,
    /// As [`Limits::max_codes`].
    pub max_codes: Option<u64>,
    /// As [`Limits::max_finders`].
    pub max_finders: Option<u64>,
    /// As [`Limits::max_grids`].
    pub max_grids: Option<u64>,
    /// The caller's limit on one buffer: the decoder and the search each hold
    /// at most this, and at most [`crate::image::DECODE_MAX`].
    pub max_buffer_bytes: u64,
}

impl Settings {
    fn limits(&self) -> Limits {
        let count = |n: u64| usize::try_from(n).unwrap_or(usize::MAX);
        Limits {
            max_pixels: self.max_pixels,
            max_time: self.max_millis.map(Duration::from_millis),
            max_codes: self.max_codes.map(count),
            max_finders: self.max_finders.map(count),
            max_grids: self.max_grids.map(count),
        }
    }

    fn max_alloc(&self) -> u64 {
        self.max_buffer_bytes.min(crate::image::DECODE_MAX)
    }
}

/// Why an image that is recognised did not decode.
const NOT_DECODED: &str = "QR codes: the image does not decode";
/// Why a PDF image was not built: its dictionary, color space, predictor or
/// JBIG2 globals are not read.
const NOT_READ: &str = "QR codes: a PDF image whose dictionary, color space, predictor or JBIG2 \
                        globals are not read";

/// Whether [`search`] may read `data` when `head` is its first 64 bytes: it
/// starts like a file in a format [`crate::image`] knows, or `raster` says it
/// is a PDF image (raw samples, or a CCITT or JBIG2 stream). For a caller to
/// ask before it holds the whole of `data`.
pub fn wants(head: &[u8], raster: Option<&Raster>) -> bool {
    raster.is_some() || crate::image::Format::detect(head).is_some()
}

/// The reason a JBIG2 image is not decoded, when its regions, or the page
/// its stream declares (not the image dictionary's size), have more pixels
/// than `limits` allow. The decoder works per pixel of each region, wherever
/// it lies on the page, so the page's size does not bound it.
fn over_region_limit(raster: &Raster, data: &[u8], limits: &Limits) -> Option<String> {
    let Some(RasterCodec::Jbig2 { globals, .. }) = &raster.codec else {
        return None;
    };
    let globals = globals.as_deref();
    let pixels = crate::pdf_image::declared_pixels(data, globals)
        .max(crate::pdf_image::declared_page_pixels(data, globals));
    let max = limits.max_pixels.filter(|&max| pixels > max)?;
    Some(format!(
        "QR codes: the page or regions of a JBIG2 image are over the {max}-pixel limit"
    ))
}

/// The codes in the image `data`, read under `settings`: a file in a format
/// [`crate::image`] decodes, or, when `raster` describes it (a PDF image), its
/// samples. `None` when it is not an image: [`wants`] says no, or the file
/// starts like one of a format whose signature is short (BMP, ICO, PNM, DDS,
/// QOI, a bare JPEG XL codestream), has no header of it and does not decode.
/// There is nothing to report. Else the payloads read and, when part of the
/// image was not read, why: a limit stopped the reading, or the image is too
/// large for the buffer limit ([`Found::cut`]), or it does not decode, or is a
/// PDF image that is not read ([`Found::unread`]).
pub fn search(data: &[u8], raster: Option<&Raster>, settings: &Settings) -> Option<Found> {
    if !wants(&data[..data.len().min(64)], raster) {
        return None;
    }
    let max_alloc = settings.max_alloc();
    let limits = settings.limits();
    let mut nothing = Found::default();
    let found = match raster {
        Some(raster) => {
            let deadline = deadline(&limits);
            // Before the pixels are built or a codec runs over its stream.
            let pixels = u64::from(raster.width) * u64::from(raster.height);
            if let Some(cut) = over_pixel_limit(pixels, &limits)
                .or_else(|| over_region_limit(raster, data, &limits))
            {
                nothing.cut = Some(cut);
                return Some(nothing);
            }
            crate::image::from_raster(raster, data, max_alloc)
                .map(|px| find_pixels(px, max_alloc, &limits, deadline))
        }
        None => find(data, max_alloc, &limits),
    };
    let error = match found {
        Ok(found) => return Some(found),
        Err(error) => error,
    };
    // Not an image that does not decode: a file that only starts like one.
    if raster.is_none()
        && crate::image::Format::detect(data).is_some_and(|format| !format.has_header(data))
    {
        return None;
    }
    match error {
        crate::image::Error::TooLarge => {
            nothing.cut = Some(format!(
                "QR codes: an image past the {max_alloc}-byte decode limit"
            ));
        }
        crate::image::Error::Unsupported if raster.is_some() => {
            nothing.unread = Some(NOT_READ.to_string());
        }
        _ => nothing.unread = Some(NOT_DECODED.to_string()),
    }
    Some(nothing)
}

/// One sample of `px` as 0 to 255.
fn sample(px: &crate::image::Pixels, i: usize) -> u32 {
    use crate::image::Samples;
    match &px.samples {
        Samples::U8(v) => v.get(i).copied().map_or(255, u32::from),
        Samples::U16(v) => v.get(i).map_or(255, |s| u32::from(*s >> 8)),
        Samples::F32(v) => v.get(i).map_or(255, |s| (s.clamp(0.0, 1.0) * 255.0) as u32),
    }
}

/// The grey level at `(x, y)` of the image `px` of `w` pixels per row, over
/// white.
fn grey_level(px: &crate::image::Pixels, w: usize, x: usize, y: usize) -> u8 {
    use crate::image::Channels;
    let n = px.channels.count();
    let at = (y * w + x) * n;
    let (level, alpha) = match px.channels {
        Channels::Luma => (sample(px, at), 255),
        Channels::LumaAlpha => (sample(px, at), sample(px, at + 1)),
        Channels::Rgb | Channels::Rgba => {
            let l =
                (sample(px, at) * 299 + sample(px, at + 1) * 587 + sample(px, at + 2) * 114) / 1000;
            let a = if px.channels == Channels::Rgba {
                sample(px, at + 3)
            } else {
                255
            };
            (l, a)
        }
    };
    ((level * alpha + 255 * (255 - alpha)) / 255).min(255) as u8
}

/// The codes in the image `data`, of any format [`crate::image`] decodes. The
/// decoder may hold `max_alloc` bytes of pixels; they are freed once copied to
/// grey, and the search then holds at most `max_alloc` bytes of its own (the
/// grey image, the copy for a candidate grid, the working buffers), else
/// [`Found::cut`] says so. `Err` when it is not an image this build decodes or
/// does not decode, or is past `max_alloc`.
pub fn find(data: &[u8], max_alloc: u64, limits: &Limits) -> Result<Found, crate::image::Error> {
    let deadline = deadline(limits);
    let px = crate::image::decode_any_strict(data, max_alloc)?;
    Ok(find_pixels(px, max_alloc, limits, deadline))
}

/// The codes in the decoded pixels `px`, which are freed once the search has
/// copied them to its grey image.
fn find_pixels(
    px: crate::image::Pixels,
    max_alloc: u64,
    limits: &Limits,
    deadline: Option<Instant>,
) -> Found {
    let (w, h) = (px.width as usize, px.height as usize);
    find_in_grey_by(
        w,
        h,
        move |x, y| grey_level(&px, w, x, y),
        max_alloc,
        limits,
        deadline,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_image_over_the_pixel_limit_is_not_searched_and_says_so() {
        let limits = Limits {
            max_pixels: Some(99),
            ..Limits::default()
        };
        let f = find_in_grey(10, 10, |_, _| 255, 1 << 20, &limits);
        assert!(f.payloads.is_empty());
        assert!(f.cut.unwrap().contains("100 pixels"));
        let f = find_in_grey(10, 9, |_, _| 255, 1 << 20, &limits);
        assert_eq!(f, Found::default());
    }

    #[test]
    fn a_search_past_its_time_stops_and_says_so() {
        let limits = Limits {
            max_time: Some(Duration::ZERO),
            ..Limits::default()
        };
        let f = find_in_grey(256, 256, |_, _| 255, 1 << 20, &limits);
        assert!(f.cut.unwrap().contains("took over"));
    }

    #[test]
    fn a_search_over_its_memory_budget_is_refused_and_says_so() {
        // The grey image alone is 65536 bytes.
        let f = find_in_grey(256, 256, |_, _| 255, 65_535, &Limits::default());
        assert!(f.payloads.is_empty());
        assert!(f.cut.unwrap().contains("more than 65535 bytes of memory"));
        let f = find_in_grey(256, 256, |_, _| 255, 1 << 20, &Limits::default());
        assert_eq!(f, Found::default());
    }
}
