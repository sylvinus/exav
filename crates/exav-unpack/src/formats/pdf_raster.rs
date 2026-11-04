//! The [`Raster`] of a PDF image XObject: how to read the bytes of its stream
//! as pixels, from the image dictionary. Data only, no pixels are built.

use std::collections::HashMap;
use std::sync::Arc;

use super::pdf::{
    Objects, Source, apply_filters, decode_parms_list, filter_names, resolve_filter_references,
};
use super::pdf_parse::types::Primitive;
use crate::{Predictor, Raster, RasterCodec, RasterSpace};

type Dict = HashMap<String, Primitive>;

/// Decrypts, in place, a string or a stream of the object `(number, generation)`.
pub(super) type Decrypt<'a> = &'a dyn Fn(u32, u32, &mut Vec<u8>);

/// Filters that only undo a coding of the bytes: what they leave is still the
/// image's samples, or the stream of its codec.
const DECODERS: &[&str] = &[
    "FlateDecode",
    "Fl",
    "LZWDecode",
    "LZW",
    "ASCII85Decode",
    "A85",
    "ASCIIHexDecode",
    "AHx",
    "RunLengthDecode",
    "RL",
];

/// The decoders that take a `/Predictor`.
const PREDICTING: &[&str] = &["FlateDecode", "Fl", "LZWDecode", "LZW"];

/// The raster of the stream `this` whose dictionary is `info` (its references
/// to filters resolved), when it is an image whose bytes are samples or a
/// codec's stream that a consumer could decode. `None` for anything else: not
/// an image, a JPEG or JPEG 2000 file (read as the file it is), or a filter no
/// decoder here has. An image whose dictionary does not say how big it is or
/// how its samples are stored is a raster of the space
/// [`RasterSpace::Undescribed`] with no size, so that a consumer can say it
/// did not read it. `room` is the most the globals of a JBIG2 image may decode
/// to, when the document has not read them yet.
pub(super) fn raster_of(
    info: &Dict,
    objects: &mut Objects<'_>,
    this: (u32, u32),
    decrypt: Decrypt<'_>,
    room: u64,
) -> Option<Raster> {
    if !matches!(info.get("Subtype"), Some(Primitive::Name(n)) if n == "Image") {
        return None;
    }
    let (predictor, codec) = coding(info, objects, decrypt, room)?;
    Some(
        described(info, objects, this, decrypt, predictor, codec).unwrap_or_else(|| Raster {
            space: RasterSpace::Undescribed,
            ..Raster::default()
        }),
    )
}

/// The raster of an image whose bytes are coded as `predictor` and `codec`
/// say, or `None` when the dictionary leaves out or hides what a reader needs.
fn described(
    info: &Dict,
    objects: &mut Objects<'_>,
    this: (u32, u32),
    decrypt: Decrypt<'_>,
    predictor: Option<Predictor>,
    codec: Option<RasterCodec>,
) -> Option<Raster> {
    let size = |objects: &mut Objects<'_>, key: &str| -> Option<u32> {
        let (value, _) = objects.follow(info.get(key)?)?;
        u32::try_from(value.as_i64()?).ok().filter(|&n| n > 0)
    };
    let (width, height) = (size(objects, "Width")?, size(objects, "Height")?);
    let mask = matches!(info.get("ImageMask"), Some(Primitive::Boolean(true)));
    let bits = if mask || codec.is_some() {
        1
    } else {
        let (value, _) = objects.follow(info.get("BitsPerComponent")?)?;
        match value.as_i64()? {
            n @ (1 | 2 | 4 | 8 | 16) => n as u8,
            _ => return None,
        }
    };
    let space = if mask {
        RasterSpace::Mask
    } else {
        let this = Source::Object(this.0, this.1);
        space(info.get("ColorSpace")?, objects, this, decrypt, true)?
    };
    let decode = match info.get("Decode") {
        Some(Primitive::Array(a)) => a.iter().take(8).map(number).collect(),
        _ => None,
    };
    Some(Raster {
        width,
        height,
        bits,
        space,
        decode,
        predictor,
        codec,
    })
}

fn number(p: &Primitive) -> Option<f32> {
    let n = match p {
        Primitive::Integer(n) => *n as f32,
        Primitive::Real(r) => *r as f32,
        _ => return None,
    };
    n.is_finite().then_some(n)
}

/// What the filters leave of the stream: the predictor still to undo, or the
/// codec it still is. `None` when it is neither samples nor a codec's stream.
/// `room` is as for [`raster_of`].
fn coding(
    info: &Dict,
    objects: &mut Objects<'_>,
    decrypt: Decrypt<'_>,
    room: u64,
) -> Option<(Option<Predictor>, Option<RasterCodec>)> {
    let names = filter_names(info);
    let parms = decode_parms_list(info, names.len());
    let chain: Vec<(&str, Option<&Dict>)> = names
        .iter()
        .zip(parms)
        .map(|(n, p)| (n.as_str(), p))
        .filter(|(n, _)| *n != "Crypt")
        .collect();
    let Some((&(name, parm), before)) = chain.split_last() else {
        return Some((None, None));
    };
    // Only a coding of the bytes may come before the last filter, and the
    // predictor is the last one's: a stream another filter works on after it
    // is not rows of samples.
    if before
        .iter()
        .any(|&(n, p)| !DECODERS.contains(&n) || predictor_of(p).is_some())
    {
        return None;
    }
    match name {
        n if PREDICTING.contains(&n) => Some((predictor_of(parm), None)),
        n if DECODERS.contains(&n) => Some((None, None)),
        "CCITTFaxDecode" | "CCF" => Some((None, Some(ccitt(parm)))),
        "JBIG2Decode" => Some((None, Some(jbig2(parm, objects, decrypt, room)))),
        _ => None,
    }
}

/// A JBIG2 stream with the globals `parm` names, when it names any.
fn jbig2(
    parm: Option<&Dict>,
    objects: &mut Objects<'_>,
    decrypt: Decrypt<'_>,
    room: u64,
) -> RasterCodec {
    let Some(named) = parm.and_then(|p| p.get("JBIG2Globals")) else {
        return RasterCodec::Jbig2 {
            globals: None,
            globals_unread: false,
        };
    };
    let globals = globals(named, objects, decrypt, room);
    RasterCodec::Jbig2 {
        globals_unread: globals.is_none(),
        globals,
    }
}

/// The stream `named` refers to, decrypted and with its filters undone, when
/// that is a stream that decodes whole to at most `room` bytes. The bytes it
/// decodes to are counted with the ones parsed to reach it. A document reads
/// each stream once, whatever the number of images that name it, and the
/// answer (a failure too) is kept by its object number.
fn globals(
    named: &Primitive,
    objects: &mut Objects<'_>,
    decrypt: Decrypt<'_>,
    room: u64,
) -> Option<Arc<[u8]>> {
    let number = match named {
        Primitive::Reference(number) => Some(*number),
        _ => None,
    };
    if let Some(read) = number.and_then(|n| objects.globals.get(&n)) {
        return read.clone();
    }
    let read = read_globals(named, objects, decrypt, room);
    if let Some(n) = number {
        objects.globals.insert(n, read.clone());
    }
    read
}

fn read_globals(
    named: &Primitive,
    objects: &mut Objects<'_>,
    decrypt: Decrypt<'_>,
    room: u64,
) -> Option<Arc<[u8]>> {
    let (Primitive::Stream { info, mut data }, Source::Object(number, generation)) =
        objects.follow(named)?
    else {
        return None;
    };
    decrypt(number, generation, &mut data);
    let info = resolve_filter_references(info, objects);
    let outcome = apply_filters(&data, &info, room).ok()?;
    if outcome.truncated || outcome.decode_error || outcome.part_way || outcome.unknown_filter {
        return None;
    }
    objects.add_parsed(outcome.buf.len() as u64);
    Some(outcome.buf.into())
}

/// The integer `key` of a `/DecodeParms` dictionary, or `default`.
fn int(parm: Option<&Dict>, key: &str, default: i64) -> i64 {
    match parm.and_then(|p| p.get(key)) {
        Some(Primitive::Integer(n)) => *n,
        _ => default,
    }
}

fn flag(parm: Option<&Dict>, key: &str) -> bool {
    matches!(
        parm.and_then(|p| p.get(key)),
        Some(Primitive::Boolean(true))
    )
}

/// The predictor `parm` asks for. A value out of range is kept as one a
/// consumer refuses (0, or 255 for the kind).
fn predictor_of(parm: Option<&Dict>) -> Option<Predictor> {
    let kind = int(parm, "Predictor", 1);
    (kind > 1).then(|| Predictor {
        kind: u8::try_from(kind).unwrap_or(u8::MAX),
        colors: u32::try_from(int(parm, "Colors", 1)).unwrap_or(0),
        bits: u8::try_from(int(parm, "BitsPerComponent", 8)).unwrap_or(0),
        columns: u32::try_from(int(parm, "Columns", 1)).unwrap_or(0),
    })
}

fn ccitt(parm: Option<&Dict>) -> RasterCodec {
    RasterCodec::Ccitt {
        k: i32::try_from(int(parm, "K", 0)).unwrap_or(0),
        end_of_line: flag(parm, "EndOfLine"),
        encoded_byte_align: flag(parm, "EncodedByteAlign"),
        black_is_1: flag(parm, "BlackIs1"),
        columns: u32::try_from(int(parm, "Columns", 1728)).unwrap_or(0),
        rows: u32::try_from(int(parm, "Rows", 0)).unwrap_or(0),
    }
}

fn other(name: &str) -> RasterSpace {
    RasterSpace::Other(name.chars().take(32).collect())
}

fn named(name: &str) -> RasterSpace {
    match name {
        "DeviceGray" | "G" | "CalGray" => RasterSpace::Gray,
        "DeviceRGB" | "RGB" | "CalRGB" => RasterSpace::Rgb,
        "DeviceCMYK" | "CMYK" => RasterSpace::Cmyk,
        other_name => other(other_name),
    }
}

/// The color space `cs` names, found in the object `at` (where `cs` was found
/// when it is a reference). `None` when it is not a name or an array, or a
/// reference to nothing.
fn space(
    cs: &Primitive,
    objects: &mut Objects<'_>,
    at: Source,
    decrypt: Decrypt<'_>,
    indexed_ok: bool,
) -> Option<RasterSpace> {
    let (cs, from) = objects.follow(cs)?;
    let at = from.or(at);
    match &cs {
        Primitive::Name(n) => Some(named(n)),
        Primitive::Array(items) => {
            let Some(Primitive::Name(n)) = items.first() else {
                return None;
            };
            Some(match n.as_str() {
                "Indexed" | "I" if indexed_ok => {
                    indexed(items, objects, at, decrypt).unwrap_or_else(|| other("Indexed"))
                }
                "ICCBased" => icc(items.get(1), objects),
                n => named(n),
            })
        }
        _ => None,
    }
}

/// `[/ICCBased profile]`: by the profile's component count, else its
/// alternate space.
fn icc(profile: Option<&Primitive>, objects: &mut Objects<'_>) -> RasterSpace {
    let Some((Primitive::Stream { info, .. }, _)) = profile.and_then(|p| objects.follow(p)) else {
        return other("ICCBased");
    };
    match info.get("N") {
        Some(Primitive::Integer(1)) => RasterSpace::Gray,
        Some(Primitive::Integer(3)) => RasterSpace::Rgb,
        Some(Primitive::Integer(4)) => RasterSpace::Cmyk,
        _ => match info.get("Alternate") {
            Some(Primitive::Name(n)) => named(n),
            _ => other("ICCBased"),
        },
    }
}

/// `[/Indexed base hival lookup]`, the lookup a string or a stream.
fn indexed(
    items: &[Primitive],
    objects: &mut Objects<'_>,
    at: Source,
    decrypt: Decrypt<'_>,
) -> Option<RasterSpace> {
    let base = space(items.get(1)?, objects, at, decrypt, false)?;
    let components = match base {
        RasterSpace::Gray => 1,
        RasterSpace::Rgb => 3,
        RasterSpace::Cmyk => 4,
        _ => return None,
    };
    let (hival, _) = objects.follow(items.get(2)?)?;
    let hival = u8::try_from(hival.as_i64()?).ok()?;
    let want = (usize::from(hival) + 1) * components;
    let (lookup, from) = objects.follow(items.get(3)?)?;
    let at = from.or(at);
    let mut palette = match lookup {
        Primitive::String(mut s) => {
            at.decrypt(decrypt, &mut s);
            s
        }
        Primitive::Stream { info, mut data } => {
            at.decrypt(decrypt, &mut data);
            let info = resolve_filter_references(info, objects);
            apply_filters(&data, &info, want as u64).ok()?.buf
        }
        _ => return None,
    };
    palette.truncate(want);
    Some(RasterSpace::Indexed {
        base: Box::new(base),
        hival,
        palette,
    })
}
