//! The PowerPoint 2000 text extension, kept in programmable tags named
//! "___PPT9" ([MS-PPT] 2.9.26 TextPFException9, 2.9.37 and 2.9.38
//! TextMasterStyle9, 2.9.67 and 2.9.68 StyleTextProp9, 2.9.72 and 2.9.73
//! the picture bullets): automatic numbering and picture bullets, which
//! the base paragraph formatting has no fields for.

use super::escher;
use super::records::{read_at, Children, Rec};
use crate::formats::office::common::bytes::Cur;

pub const PROG_TAGS: u16 = 0x1388;
const PROG_BINARY_TAG: u16 = 0x138A;
const BINARY_TAG_DATA: u16 = 0x138B;
const CSTRING: u16 = 0x0FBA;
pub const STYLE_TEXT_PROP9: u16 = 0x0FAC;
pub const TEXT_MASTER_STYLE9: u16 = 0x0FAD;
pub const BLIP_COLLECTION9: u16 = 0x07F8;
const BLIP_ENTITY9: u16 = 0x07F9;

/// What a TextPFException9 adds to a paragraph.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Pf9 {
    /// The picture bullet, an index into the picture bullets.
    pub blip: Option<u16>,
    /// Numbering scheme and first number; a scheme of `NO_NUMBERING` says
    /// the paragraph is not numbered.
    pub autonum: Option<(u16, u16)>,
}

pub const NO_NUMBERING: u16 = 0xFFFF;

/// A TextPFException9: its masks, then the optional picture reference,
/// the has-numbering flag and the scheme, in that order.
fn read_pf9(c: &mut Cur) -> Pf9 {
    let m = c.u32();
    let blip = (m & (1 << 23) != 0).then(|| c.u16());
    let has_scheme = (m & (1 << 25) != 0).then(|| c.u16());
    let scheme = (m & (1 << 24) != 0).then(|| (c.u16(), c.u16()));
    Pf9 {
        blip: blip.filter(|&b| b != 0xFFFF),
        autonum: match (has_scheme, scheme) {
            (Some(0), _) => Some((NO_NUMBERING, 0)),
            (_, s) => s,
        },
    }
}

/// A TextCFException9: its masks, and four more bytes when the PowerPoint
/// 2002 extension bit is set.
fn skip_cf9(c: &mut Cur) {
    let m = c.u32();
    if m & (1 << 20) != 0 {
        c.u32();
    }
}

/// A TextSIException, as far as its length is known: `false` with smart
/// tags, which have none.
fn skip_si(c: &mut Cur) -> bool {
    let m = c.u32();
    for bit in [0, 1, 2, 6] {
        if m & (1 << bit) != 0 {
            c.u16();
        }
    }
    if m & (1 << 5) != 0 {
        c.u32();
    }
    m & (1 << 9) == 0
}

/// The items of a StyleTextProp9Atom, one for each run of text that shares
/// a paragraph extension.
pub fn style_text_prop9(data: &[u8]) -> Vec<Pf9> {
    let mut c = Cur::new(data);
    let mut out = vec![];
    while c.left() >= 12 && out.len() < 1 << 16 {
        let pf = read_pf9(&mut c);
        skip_cf9(&mut c);
        let ok = skip_si(&mut c);
        if c.short {
            break;
        }
        out.push(pf);
        if !ok {
            break;
        }
    }
    out
}

/// A TextMasterStyle9Atom's levels (its type in the record's instance).
pub fn master_style9(r: &Rec) -> Vec<(usize, Pf9)> {
    let mut c = r.cur();
    let n = c.u16().min(5);
    let mut out = vec![];
    for level in 0..usize::from(n) {
        let pf = read_pf9(&mut c);
        skip_cf9(&mut c);
        if c.short {
            break;
        }
        out.push((level, pf));
    }
    out
}

/// The records of the "___PPT9" tag of a ProgTags container.
pub fn tag_records<'a>(prog_tags: &Rec<'a>) -> Vec<Rec<'a>> {
    for tag in prog_tags.children().filter(|t| t.typ == PROG_BINARY_TAG) {
        let mut kids = tag.children();
        let name_ok = kids.next().is_some_and(|n| {
            n.typ == CSTRING
                && n.data
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|b| u16::from_le_bytes(*b))
                    .take_while(|&u| u != 0)
                    .eq("___PPT9".encode_utf16())
        });
        if !name_ok {
            continue;
        }
        if let Some(blob) = kids.find(|k| k.typ == BINARY_TAG_DATA) {
            return Children::new(blob.data).collect();
        }
    }
    vec![]
}

/// The picture bullets of a BlipCollection9Container, each with its index.
pub fn bullet_pictures<'a>(coll: &Rec<'a>) -> Vec<(u16, Rec<'a>)> {
    let mut out = vec![];
    for e in coll.children().filter(|e| e.typ == BLIP_ENTITY9).take(256) {
        // The type and an unused byte, then a picture or a BSE holding it.
        let Some(block) = e.data.get(2..).and_then(|d| read_at(d, 0)) else {
            continue;
        };
        let rec = if block.typ == 0xF007 {
            let name_len = block.data.get(33).copied().unwrap_or(0) as usize;
            match block
                .data
                .get(36 + name_len..)
                .filter(|r| r.len() >= 8)
                .and_then(|r| read_at(r, 0))
            {
                Some(r) => r,
                None => continue,
            }
        } else {
            block
        };
        if escher::blip(&rec).is_some() {
            out.push((e.inst, rec));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn le16(v: u16) -> [u8; 2] {
        v.to_le_bytes()
    }

    fn le32(v: u32) -> [u8; 4] {
        v.to_le_bytes()
    }

    #[test]
    fn paragraph_extensions_are_read_in_order() {
        // Item 1: a picture bullet (index 2). Item 2: numbering scheme 3 from 5.
        let mut d = vec![];
        d.extend(le32(1 << 23));
        d.extend(le16(2));
        d.extend(le32(0)); // cf9
        d.extend(le32(0)); // si
        d.extend(le32((1 << 24) | (1 << 25)));
        d.extend(le16(1));
        d.extend(le16(3));
        d.extend(le16(5));
        d.extend(le32(1 << 20)); // cf9 with the pp10 extension
        d.extend(le32(0));
        d.extend(le32(1 << 1)); // si with a language
        d.extend(le16(0x409));
        let items = style_text_prop9(&d);
        assert_eq!(
            items,
            vec![
                Pf9 {
                    blip: Some(2),
                    autonum: None
                },
                Pf9 {
                    blip: None,
                    autonum: Some((3, 5))
                },
            ]
        );
    }

    #[test]
    fn numbering_can_be_turned_off() {
        let mut d = vec![];
        d.extend(le32(1 << 25));
        d.extend(le16(0));
        d.extend(le32(0));
        d.extend(le32(0));
        assert_eq!(
            style_text_prop9(&d),
            vec![Pf9 {
                blip: None,
                autonum: Some((NO_NUMBERING, 0))
            }]
        );
    }
}
