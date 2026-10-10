//! One object record (ODA spec 20.1 and 20.2): its size, type and handle,
//! extended data, the common entity data, and the streams the rest is read
//! from: the data before the handles, from R2007 the strings after the data,
//! and the handles.

use super::bits::{BitError, BitResult, Bits, HandleRef};
use super::file::Dwg;
use super::Version;

/// A TV string as stored (spec 2): bytes in the drawing's code page to
/// R2004, UTF-16 from R2007.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Text {
    Bytes(Vec<u8>),
    Unicode(String),
}

impl Default for Text {
    fn default() -> Self {
        Text::Bytes(Vec::new())
    }
}

/// A TV: from R2007 a TU of the string stream (an empty string when the
/// object has none), before a T of the data.
pub(crate) fn read_tv(
    data: &mut Bits<'_>,
    strings: &mut Option<Bits<'_>>,
    unicode: bool,
) -> BitResult<Text> {
    if !unicode {
        return Ok(Text::Bytes(data.t()?));
    }
    match strings {
        Some(s) => Ok(Text::Unicode(s.tu()?)),
        None => Ok(Text::Unicode(String::new())),
    }
}

/// R2007 on (spec 20.1): the string stream at the end of a data stream that
/// starts at bit `start` and ends at bit `end`. The last bit says whether
/// there is one; if so the 16 bits before it are its size in bits (with
/// its 0x8000 bit, 15 more bits in the 16 before those), and the strings
/// are that many bits before the size. Returns where the data stream then
/// ends, and the strings.
pub(crate) fn split_strings(
    data: &[u8],
    start: u64,
    end: u64,
) -> BitResult<(u64, Option<Bits<'_>>)> {
    if end <= start {
        return Ok((end, None));
    }
    let flag = end - 1;
    if !Bits::window(data, flag, end).b()? {
        return Ok((flag, None));
    }
    let short =
        |at: u64| -> BitResult<u64> { Ok(u64::from(Bits::window(data, at, at + 16).rs()? as u16)) };
    let mut at = flag
        .checked_sub(16)
        .filter(|a| *a >= start)
        .ok_or(BitError::Invalid)?;
    let mut size = short(at)?;
    if size & 0x8000 != 0 {
        at = at
            .checked_sub(16)
            .filter(|a| *a >= start)
            .ok_or(BitError::Invalid)?;
        size = (size & 0x7FFF) | (short(at)? << 15);
    }
    let strings = at
        .checked_sub(size)
        .filter(|s| *s >= start)
        .ok_or(BitError::Invalid)?;
    Ok((strings, Some(Bits::window(data, strings, at))))
}

/// The header variables' streams (spec 9; 5.9 for R2007 on, which moves
/// the strings and the handles out of the data).
#[derive(Clone, Debug)]
pub struct HeaderStreams<'a> {
    pub data: Bits<'a>,
    pub strings: Option<Bits<'a>>,
    /// R2007 on; before, the handles are in the data.
    pub handles: Option<Bits<'a>>,
    pub(crate) unicode: bool,
}

impl HeaderStreams<'_> {
    /// The next TV.
    pub fn tv(&mut self) -> BitResult<Text> {
        read_tv(&mut self.data, &mut self.strings, self.unicode)
    }

    /// The next handle reference.
    pub fn h(&mut self) -> BitResult<HandleRef> {
        match &mut self.handles {
            Some(h) => h.h(),
            None => self.data.h(),
        }
    }
}

/// One application's extended data (spec 28): the APPID's handle and the
/// items' bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Eed {
    pub app: u64,
    pub data: Vec<u8>,
}

/// One extended data item; codes are DXF's (1000 to 1071).
#[derive(Clone, Debug, PartialEq)]
pub enum EedValue<'a> {
    /// 1000: bytes in the drawing's code page (R13 to 2004).
    Text(&'a [u8]),
    /// 1000 from 2007: UTF-16.
    Unicode(String),
    /// 1002: true for `{`.
    Open(bool),
    /// 1003 (layer) and 1005 (entity).
    Handle(u64),
    /// 1004
    Binary(&'a [u8]),
    /// 1010 to 1013
    Point([f64; 3]),
    /// 1040 to 1042
    Real(f64),
    /// 1070
    Short(i16),
    /// 1071
    Long(i32),
}

impl Eed {
    /// The items, up to the first one that does not read: `(code, value)`
    /// with `code` the DXF group code.
    pub fn items(&self, version: Version) -> Vec<(i16, EedValue<'_>)> {
        let mut out = Vec::new();
        let d = &self.data[..];
        let mut at = 0usize;
        let take = |at: &mut usize, n: usize| -> Option<&[u8]> {
            let s = d.get(*at..at.checked_add(n)?)?;
            *at += n;
            Some(s)
        };
        while let Some(&code) = d.get(at) {
            at += 1;
            let value = match code {
                0 if version >= Version::R2007 => take(&mut at, 2)
                    .map(|n| usize::from(u16::from_le_bytes([n[0], n[1]])))
                    .and_then(|n| take(&mut at, n * 2))
                    .map(|s| {
                        let units: Vec<u16> = s
                            .as_chunks::<2>()
                            .0
                            .iter()
                            .map(|c| u16::from_le_bytes(*c))
                            .collect();
                        EedValue::Unicode(String::from_utf16_lossy(&units))
                    }),
                // A length, a code page, the bytes.
                0 => take(&mut at, 3)
                    .map(|h| usize::from(h[0]))
                    .and_then(|n| take(&mut at, n))
                    .map(EedValue::Text),
                2 => take(&mut at, 1).map(|b| EedValue::Open(b[0] == 0)),
                3 | 5 => take(&mut at, 8).map(|b| {
                    EedValue::Handle(u64::from_be_bytes([
                        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                    ]))
                }),
                4 => take(&mut at, 1)
                    .map(|n| usize::from(n[0]))
                    .and_then(|n| take(&mut at, n))
                    .map(EedValue::Binary),
                10..=13 => take(&mut at, 24).map(|b| {
                    let f = |i: usize| {
                        let mut x = [0u8; 8];
                        x.copy_from_slice(&b[i * 8..i * 8 + 8]);
                        f64::from_le_bytes(x)
                    };
                    EedValue::Point([f(0), f(1), f(2)])
                }),
                40..=42 => take(&mut at, 8).map(|b| {
                    let mut x = [0u8; 8];
                    x.copy_from_slice(b);
                    EedValue::Real(f64::from_le_bytes(x))
                }),
                70 => take(&mut at, 2).map(|b| EedValue::Short(i16::from_le_bytes([b[0], b[1]]))),
                71 => take(&mut at, 4)
                    .map(|b| EedValue::Long(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))),
                _ => None,
            };
            match value {
                Some(v) => out.push((1000 + i16::from(code), v)),
                None => break,
            }
        }
        out
    }
}

/// An entity's colour as stored: R13 to R2000 an index (CMC as a BS), from
/// 2004 the ENC form (spec 2.11).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EntityColor {
    /// The colour index: 0 ByBlock, 256 ByLayer.
    pub index: i16,
    /// A true colour, `0x00RRGGBB`.
    pub rgb: Option<u32>,
    /// A colour book colour is referenced in the handle stream.
    pub has_book: bool,
    /// The transparency as stored, `0x020000AA` an opacity.
    pub transparency: Option<u32>,
}

/// The common entity data (spec 20.4.1 and 20.4.2).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct EntityCommon {
    /// Entmode: 0 owned by the handle in the stream, 1 paper space, 2
    /// model space.
    pub mode: u8,
    /// Proxy graphics: its bit position and byte length in the record.
    pub graphics: Option<(u64, u64)>,
    pub color: EntityColor,
    pub linetype_scale: f64,
    /// 0 ByLayer, 1 ByBlock, 2 Continuous, 3 the handle in `linetype`.
    pub linetype_flags: u8,
    /// 0 ByLayer, 1 ByBlock, 3 the handle in `plot_style`.
    pub plot_style_flags: u8,
    pub material_flags: u8,
    pub shadow_flags: u8,
    pub invisible: bool,
    /// The lineweight byte (R2000 on).
    pub lineweight: u8,
    /// Previous and next entity are the handle's neighbours (R13 to 2000).
    pub no_links: bool,
    pub layer: u64,
    pub linetype: u64,
    pub plot_style: u64,
    pub material: u64,
    pub color_book: u64,
    /// The full, face and edge visual styles (R2010 on); 0 for none.
    pub visual_styles: [u64; 3],
    /// The previous and next entity of a block, R13 to 2000; 0 for none.
    pub prev: u64,
    pub next: u64,
}

/// One object record.
#[derive(Clone, Debug)]
pub struct Object<'a> {
    pub handle: u64,
    pub type_code: u16,
    /// Where the record starts in [`Dwg::objects`], and its size without
    /// the size fields and the CRC.
    pub offset: usize,
    pub size: usize,
    pub eed: Vec<Eed>,
    /// The owner (parent) handle; for an entity, 0 unless `entity.mode` is 0.
    pub owner: u64,
    pub reactors: Vec<u64>,
    pub xdictionary: u64,
    /// R2013 on: the object has data in the AcDb:AcDsPrototype_1b section.
    pub has_ds_data: bool,
    pub entity: Option<EntityCommon>,
    /// The type's own data, up to the strings (R2007 on) or the handles.
    pub data: Bits<'a>,
    /// R2007 on: the strings of the type's TV fields, when it has any.
    pub strings: Option<Bits<'a>>,
    /// The type's own handles, after the common ones.
    pub handles: Bits<'a>,
    version: Version,
}

impl<'a> Object<'a> {
    pub(crate) fn read(dwg: &'a Dwg<'_>, offset: usize) -> BitResult<Object<'a>> {
        let data = dwg.objects();
        let version = dwg.version();
        let mut head = Bits::window(data, offset as u64 * 8, data.len() as u64 * 8);
        let size = usize::try_from(head.ms()?).map_err(|_| BitError::Invalid)?;
        // R2010 on, the handles' size in bits; the record's size counts
        // from after it (the CRC of every object of the corpus's R2010 to
        // R2018 files follows that many bytes after it, not after the MS).
        let handle_bits = if version >= Version::R2010 {
            Some(head.umc()?)
        } else {
            None
        };
        let start = head.position();
        let end = start.saturating_add(size as u64 * 8);
        if end > head.end() {
            return Err(BitError::End);
        }
        let mut b = Bits::window(data, start, end);
        let type_code = if version >= Version::R2010 {
            object_type(&mut b)?
        } else {
            b.bs()? as u16
        };
        let mut bitsize = match handle_bits {
            Some(n) => Some((end - start).checked_sub(n).ok_or(BitError::Invalid)?),
            None if version >= Version::R2000 => Some(u64::from(b.rl()? as u32)),
            None => None,
        };
        let handle = b.h()?.value;
        let eed = read_eed(&mut b)?;
        let is_entity = dwg.is_entity(type_code);

        let mut entity = None;
        let reactor_count;
        let mut xdic_missing = false;
        let mut has_ds_data = false;
        let mut styles = [false; 3];
        if is_entity {
            let mut e = EntityCommon::default();
            if b.b()? {
                let len = if version >= Version::R2010 {
                    b.bll()?
                } else {
                    u64::from(b.rl()? as u32)
                };
                e.graphics = Some((b.position(), len));
                b.skip(len.checked_mul(8).ok_or(BitError::End)?)?;
            }
            if bitsize.is_none() {
                bitsize = Some(u64::from(b.rl()? as u32));
            }
            e.mode = b.bb()?;
            reactor_count = b.bl()?;
            if version >= Version::R2004 {
                xdic_missing = b.b()?;
            }
            if version >= Version::R2013 {
                has_ds_data = b.b()?;
            }
            let mut by_layer_lt = false;
            if version <= Version::R14 {
                by_layer_lt = b.b()?;
            }
            // Spec 20.4.1 lists Nolinks in every version, "always 1" from
            // R2004. R2004 to R2018 files have no such bit: read with it,
            // every entity of the corpus's conversions has its colour, then
            // everything after it, one bit off (ByBlock for ByLayer, a
            // linetype scale of 0 for 1); read without, they match the DXF.
            e.no_links = version >= Version::R2004 || b.b()?;
            e.color = read_color(&mut b, version)?;
            e.linetype_scale = b.bd()?;
            if version >= Version::R2000 {
                e.linetype_flags = b.bb()?;
                e.plot_style_flags = b.bb()?;
            } else {
                e.linetype_flags = if by_layer_lt { 0 } else { 3 };
            }
            if version >= Version::R2007 {
                e.material_flags = b.bb()?;
                e.shadow_flags = b.rc()?;
            }
            if version >= Version::R2010 {
                styles = [b.b()?, b.b()?, b.b()?];
            }
            e.invisible = b.bs()? & 1 != 0;
            if version >= Version::R2000 {
                e.lineweight = b.rc()?;
            }
            entity = Some(e);
        } else {
            if bitsize.is_none() {
                bitsize = Some(u64::from(b.rl()? as u32));
            }
            reactor_count = b.bl()?;
            if version >= Version::R2004 {
                xdic_missing = b.b()?;
            }
            if version >= Version::R2013 {
                has_ds_data = b.b()?;
            }
        }

        // The handles start `bitsize` bits into the record.
        let handles_at = start.saturating_add(bitsize.unwrap_or(0));
        if handles_at < b.position() || handles_at > end {
            return Err(BitError::Invalid);
        }
        let mut data_stream = b.clone();
        data_stream.set_end(handles_at);
        let mut strings = None;
        if version >= Version::R2007 {
            let (data_end, s) = split_strings(data, b.position(), handles_at)?;
            data_stream.set_end(data_end);
            strings = s;
        }
        let mut h = Bits::window(data, handles_at, end);
        let get = |h: &mut Bits<'a>| -> BitResult<u64> { Ok(h.h()?.absolute(handle)) };

        let mut owner = 0;
        if entity.as_ref().is_none_or(|e| e.mode == 0) {
            owner = get(&mut h)?;
        }
        let reactor_count = u64::try_from(reactor_count).map_err(|_| BitError::Invalid)?;
        // A handle takes at least a byte.
        if reactor_count > h.remaining() / 8 {
            return Err(BitError::Invalid);
        }
        let mut reactors = Vec::with_capacity(reactor_count as usize);
        for _ in 0..reactor_count {
            reactors.push(get(&mut h)?);
        }
        let xdictionary = if xdic_missing { 0 } else { get(&mut h)? };
        if let Some(e) = entity.as_mut() {
            if version <= Version::R14 {
                e.layer = get(&mut h)?;
                if e.linetype_flags == 3 {
                    e.linetype = get(&mut h)?;
                }
            }
            if version <= Version::R2000 {
                if e.no_links {
                    e.prev = handle.wrapping_sub(1);
                    e.next = handle.wrapping_add(1);
                } else {
                    e.prev = get(&mut h)?;
                    e.next = get(&mut h)?;
                }
            }
            if e.color.has_book {
                e.color_book = get(&mut h)?;
            }
            if version >= Version::R2000 {
                e.layer = get(&mut h)?;
                if e.linetype_flags == 3 {
                    e.linetype = get(&mut h)?;
                }
                if version >= Version::R2007 && e.material_flags == 3 {
                    e.material = get(&mut h)?;
                }
                if e.plot_style_flags == 3 {
                    e.plot_style = get(&mut h)?;
                }
            }
            for (slot, present) in e.visual_styles.iter_mut().zip(styles) {
                if present {
                    *slot = get(&mut h)?;
                }
            }
        }

        Ok(Object {
            handle,
            type_code,
            offset,
            size,
            eed,
            owner,
            reactors,
            xdictionary,
            has_ds_data,
            entity,
            data: data_stream,
            strings,
            handles: h,
            version,
        })
    }

    /// The next TV of the type's own data: from R2007 the next string of
    /// the string stream.
    pub fn tv(&mut self) -> BitResult<Text> {
        read_tv(
            &mut self.data,
            &mut self.strings,
            self.version >= Version::R2007,
        )
    }

    /// The next handle of the type's own, made absolute.
    pub fn handle_ref(&mut self) -> BitResult<u64> {
        let base = self.handle;
        Ok(self.handles.h()?.absolute(base))
    }

    /// The raw next handle reference of the type's own.
    pub fn raw_handle_ref(&mut self) -> BitResult<HandleRef> {
        self.handles.h()
    }
}

/// The type of the object at `offset` (spec 20.1): after its size, and
/// from R2010 its handle stream size.
pub(crate) fn type_at(dwg: &Dwg<'_>, offset: usize) -> BitResult<u16> {
    let data = dwg.objects();
    let mut b = Bits::window(data, offset as u64 * 8, data.len() as u64 * 8);
    b.ms()?;
    if dwg.version() >= Version::R2010 {
        b.umc()?;
        object_type(&mut b)
    } else {
        Ok(b.bs()? as u16)
    }
}

/// The object type of R2010 on (spec 2.12): two bits, then a byte, a byte
/// plus 0x1F0, or a raw short.
fn object_type(b: &mut Bits<'_>) -> BitResult<u16> {
    Ok(match b.bb()? {
        0 => u16::from(b.rc()?),
        1 => u16::from(b.rc()?) + 0x1F0,
        _ => b.rs()? as u16,
    })
}

fn read_color(b: &mut Bits<'_>, version: Version) -> BitResult<EntityColor> {
    let raw = b.bs()?;
    if version < Version::R2004 {
        return Ok(EntityColor {
            index: raw,
            ..EntityColor::default()
        });
    }
    let flags = (raw as u16) & 0xFF00;
    let mut c = EntityColor {
        index: raw & 0x1FF,
        ..EntityColor::default()
    };
    // Spec 2.11 has the RGB value as a BS; it is a BL (a true colour LINE of
    // tests/fixtures/cad/make.py reads as its DXF's 420 so, and as an error
    // with a BS), an AcCmColor: a true colour when its top byte is 0xC2
    // (3.8 million in the local corpus), else the index stands (0xC5, the
    // foreground colour, once, 7 in the converter's DXF).
    if flags & 0x8000 != 0 {
        let value = b.bl()? as u32;
        if value >> 24 == 0xC2 {
            c.rgb = Some(value & 0x00FF_FFFF);
        }
    }
    if flags & 0x4000 != 0 {
        c.has_book = true;
    }
    if flags & 0x2000 != 0 {
        c.transparency = Some(b.bl()? as u32);
    }
    Ok(c)
}

/// Extended data blocks (spec 28): a BS length, the APPID handle and the
/// bytes, until a length of 0.
fn read_eed(b: &mut Bits<'_>) -> BitResult<Vec<Eed>> {
    let mut out = Vec::new();
    loop {
        let len = b.bs()?;
        if len == 0 {
            return Ok(out);
        }
        let len = usize::try_from(len).map_err(|_| BitError::Invalid)?;
        let app = b.h()?.value;
        let data = b.bytes(len)?;
        out.push(Eed { app, data });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An R2004+ entity colour (spec 2.11): BS 0x8007 (index 7, a colour
    /// value follows), then the value as a BL, an AcCmColor whose top byte
    /// says what it is: 0xC2 a true colour, 0xC5 the foreground colour (one
    /// ATTDEF of the local corpus, 7 in the converter's DXF), which is not
    /// black.
    #[test]
    fn only_a_true_colour_value_is_an_rgb() {
        let foreground = [0x01, 0xE0, 0x00, 0x00, 0x00, 0x0C, 0x50];
        let c = read_color(&mut Bits::new(&foreground), Version::R2013).unwrap();
        assert_eq!((c.index, c.rgb), (7, None));
        let orange = [0x01, 0xE0, 0x00, 0x08, 0x0F, 0xFC, 0x20];
        let c = read_color(&mut Bits::new(&orange), Version::R2013).unwrap();
        assert_eq!((c.index, c.rgb), (7, Some(0xFF8000)));
    }
}
