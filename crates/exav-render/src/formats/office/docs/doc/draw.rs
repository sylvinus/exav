//! Pictures and shapes: inline pictures in the data stream and floating
//! shapes in the drawing layer ([MS-DOC] 2.9.190, 2.9.253, [MS-ODRAW]).

use super::Reader;
use super::fib::idx;
use super::story::Story;
use crate::formats::office::common::bytes::{u16_at, u32_at};
use crate::formats::office::common::escher::{self, Rec, read_at};
use crate::formats::office::common::image;
use crate::formats::office::docs::error::Result;
use crate::formats::office::docs::model::*;

const TWIP_EMU: i64 = 635;

fn color_of(v: u32) -> Option<u32> {
    // A direct RGB value has no flags in the top byte.
    (v >> 24 == 0).then_some((v & 0xFF) << 16 | (v & 0xFF00) | (v >> 16) & 0xFF)
}

fn fixed(v: u32) -> i32 {
    // 16.16 fixed point to thousandths of a percent of the picture.
    ((i64::from(v as i32) * 100_000) >> 16) as i32
}

/// The picture record inside a BSE, or a bare picture record.
fn blip_of<'a>(r: &Rec<'a>) -> Option<Rec<'a>> {
    if r.typ == escher::BSE {
        let d = r.data;
        let name_len = d.get(33).copied().unwrap_or(0) as usize;
        let rest = d.get(36 + name_len..).filter(|x| x.len() >= 8)?;
        return read_at(rest, 0);
    }
    matches!(r.typ, 0xF01A..=0xF02A).then_some(*r)
}

impl Reader<'_> {
    fn add_blip(&mut self, b: escher::Blip) -> Result<Option<usize>> {
        let ext = match b.ext {
            "png" | "jpeg" | "gif" | "bmp" | "tiff" | "emf" | "wmf" => b.ext,
            _ => match image::ext(&b.data) {
                Some(e) => e,
                None => return Ok(None),
            },
        };
        self.b.alloc(b.data.len() as u64)?;
        Ok(Some(self.doc.add_media(ext, b.data)))
    }

    /// A picture character's picture, from the data stream.
    pub(crate) fn inline_picture(&mut self, loc: i32) -> Result<Option<Drawing>> {
        if self.word6 {
            return self.word6_picture(loc);
        }
        let at = loc as usize;
        if loc < 0 || at + 68 > self.data.len() {
            return Ok(None);
        }
        let lcb = u32_at(&self.data, at) as usize;
        let cb_header = usize::from(u16_at(&self.data, at + 4));
        let mm = u16_at(&self.data, at + 6);
        let (goal_x, goal_y) = (
            i64::from(u16_at(&self.data, at + 28)),
            i64::from(u16_at(&self.data, at + 30)),
        );
        let (mx, my) = (
            i64::from(u16_at(&self.data, at + 32)),
            i64::from(u16_at(&self.data, at + 34)),
        );
        if cb_header < 68 || lcb < cb_header {
            return Ok(None);
        }
        let end = at.saturating_add(lcb).min(self.data.len());
        let mut start = at + cb_header;
        if mm == 0x66 {
            start += 1 + usize::from(self.data.get(start).copied().unwrap_or(0));
        }
        let Some(body) = self.data.get(start..end) else {
            return Ok(None);
        };
        // The shape container, then the pictures it uses.
        let body = body.to_vec();
        let mut shape: Option<Vec<(u16, u32)>> = None;
        let mut blips = vec![];
        let mut pos = 0usize;
        while let Some(r) = read_at(&body, pos) {
            pos = pos + 8 + r.data.len();
            if r.typ == escher::SP_CONTAINER {
                let s = escher::sp_container(&r);
                shape = Some(s.props.0.iter().map(|p| (p.id, p.value)).collect());
            } else if let Some(bl) = blip_of(&r) {
                blips.push(bl);
            }
            if blips.len() > 4 {
                break;
            }
        }
        let props = shape.unwrap_or_default();
        let get = |id: u16| props.iter().rev().find(|p| p.0 == id).map(|p| p.1);
        let pib = get(0x0104).unwrap_or(1) as usize;
        let rec = blips.get(pib.saturating_sub(1)).or(blips.first()).copied();
        let Some(rec) = rec else { return Ok(None) };
        let Some(blip) = escher::blip(&rec) else {
            return Ok(None);
        };
        let Some(media) = self.add_blip(blip)? else {
            return Ok(None);
        };
        let crop = Crop {
            t: get(0x0100).map(fixed).unwrap_or(0),
            b: get(0x0101).map(fixed).unwrap_or(0),
            l: get(0x0102).map(fixed).unwrap_or(0),
            r: get(0x0103).map(fixed).unwrap_or(0),
        };
        let m = &self.doc.media[media];
        let natural = image::natural_emu(&m.data);
        let (mut cx, mut cy) = (goal_x * mx / 1000 * TWIP_EMU, goal_y * my / 1000 * TWIP_EMU);
        if cx <= 0 || cy <= 0 {
            let (nx, ny) = natural.unwrap_or((914_400, 914_400));
            cx = nx;
            cy = ny;
        }
        Ok(Some(Drawing {
            anchor: None,
            cx,
            cy,
            name: "Picture".into(),
            descr: None,
            kind: DrawingKind::Picture { media, crop },
        }))
    }

    /// The picture a floating shape shows, and its text, by shape id.
    pub(crate) fn floating_shape(&mut self, cp: u32, story: Story) -> Result<Option<Drawing>> {
        let hdr = story == Story::Header;
        let base = if hdr { self.base_hdd() } else { 0 };
        let spa = {
            let list = if hdr { &self.spa_hdr } else { &self.spa_main };
            list.iter().find(|s| s.cp + base == cp).cloned()
        };
        let Some(spa) = spa else { return Ok(None) };
        let (off, len) = self.fib.at(idx::DGG_INFO);
        let Some(area) = self
            .tbl
            .get(off..off.saturating_add(len).min(self.tbl.len()))
        else {
            return Ok(None);
        };
        // The drawing layer is read from a copy: the text of text boxes needs
        // the reader itself.
        let area = area.to_vec();
        self.floating_inner(&area, &spa, hdr)
    }

    fn floating_inner(
        &mut self,
        area: &[u8],
        spa: &super::Spa,
        hdr: bool,
    ) -> Result<Option<Drawing>> {
        let Some(dgg) = read_at(area, 0) else {
            return Ok(None);
        };
        // The drawings follow the group record: a byte, then a container.
        let mut pos = 8 + dgg.data.len();
        let mut drawing = None;
        for _ in 0..2 {
            let label = area.get(pos).copied();
            let Some(label) = label else { break };
            let Some(dg) = read_at(area, pos + 1) else {
                break;
            };
            pos += 1 + 8 + dg.data.len();
            if (label == 1) == hdr {
                drawing = Some(escher::drawing(&dg));
                break;
            }
        }
        let Some(d) = drawing else { return Ok(None) };
        fn find<'a, 'b>(v: &'b [escher::OShape<'a>], id: u32) -> Option<&'b escher::OShape<'a>> {
            for s in v {
                if s.spid == id {
                    return Some(s);
                }
                if let Some(x) = find(&s.children, id) {
                    return Some(x);
                }
            }
            None
        }
        let Some(shape) = find(&d.shapes, spa.lid) else {
            return Ok(None);
        };
        if shape.is_group() {
            return Ok(None);
        }
        let p = &shape.props;
        // Placement.
        let flags = spa.flags;
        let bx = (flags >> 1) & 3;
        let by = (flags >> 3) & 3;
        let wr = (flags >> 5) & 0xF;
        let below = flags & 0x4000 != 0;
        let width = i64::from(spa.rect[2]) - i64::from(spa.rect[0]);
        let height = i64::from(spa.rect[3]) - i64::from(spa.rect[1]);
        let anchor = Anchor {
            h_rel: match bx {
                0 => "margin",
                1 => "page",
                _ => "column",
            },
            v_rel: match by {
                0 => "margin",
                1 => "page",
                _ => "paragraph",
            },
            h_off: i64::from(spa.rect[0]) * TWIP_EMU,
            v_off: i64::from(spa.rect[1]) * TWIP_EMU,
            wrap: match wr {
                1 => Wrap::TopBottom,
                3 => Wrap::None,
                4 => Wrap::Tight,
                5 => Wrap::Through,
                _ => Wrap::Square,
            },
            behind: below,
            z: spa.cp % 1_000_000,
            dist: [
                p.get(0x0385).map(i64::from).unwrap_or(0),
                p.get(0x0387).map(i64::from).unwrap_or(0),
                p.get(0x0384).map(i64::from).unwrap_or(114_300),
                p.get(0x0386).map(i64::from).unwrap_or(114_300),
            ],
            ..Anchor::default()
        };
        let (cx, cy) = (width.max(0) * TWIP_EMU, height.max(0) * TWIP_EMU);
        // A picture shape; its bitmap may be in the delay stream (the
        // WordDocument stream).
        if let Some(pib) = p.get(0x0104).filter(|v| *v > 0) {
            let blip = escher::blip_records(&dgg, &self.wd)
                .get(pib as usize - 1)
                .copied()
                .flatten()
                .and_then(|r| escher::blip(&r));
            if let Some(blip) = blip
                && let Some(media) = self.add_blip(blip)?
            {
                let crop = Crop {
                    t: p.get(0x0100).map(fixed).unwrap_or(0),
                    b: p.get(0x0101).map(fixed).unwrap_or(0),
                    l: p.get(0x0102).map(fixed).unwrap_or(0),
                    r: p.get(0x0103).map(fixed).unwrap_or(0),
                };
                return Ok(Some(Drawing {
                    anchor: Some(anchor),
                    cx,
                    cy,
                    name: "Picture".into(),
                    descr: None,
                    kind: DrawingKind::Picture { media, crop },
                }));
            }
        }
        // A text box or an autoshape.
        let plc = if hdr { &self.txbx_hdr } else { &self.txbx_main };
        let base_tx = if hdr {
            self.base_hdr_txbx()
        } else {
            self.base_txbx()
        };
        let text_range = plc
            .data
            .iter()
            .position(|d| u32_at(d, 14) == spa.lid && u16_at(d, 8) == 0)
            .and_then(|k| {
                Some((
                    base_tx.checked_add(*plc.cps.get(k)?)?,
                    base_tx.checked_add(*plc.cps.get(k + 1)?)?,
                ))
            });
        let preset = match shape.spt {
            2 => "roundRect",
            3 => "ellipse",
            4 => "diamond",
            5 => "triangle",
            6 => "rtTriangle",
            7 => "parallelogram",
            8 => "trapezoid",
            9 => "hexagon",
            10 => "octagon",
            11 => "plus",
            12 => "star5",
            13 => "rightArrow",
            20 | 32 => "line",
            _ => "rect",
        };
        let mut sh = Shape {
            preset,
            ..Shape::default()
        };
        let filled = p.flag(0x01BF, 4) != Some(false);
        if filled {
            let c = p.get(0x0181).and_then(color_of).unwrap_or(0xFFFFFF);
            sh.fill = Fill::Solid(c);
        }
        if p.flag(0x01FF, 3) != Some(false) && (p.get(0x01C0).is_some() || shape.spt == 20) {
            let c = p.get(0x01C0).and_then(color_of).unwrap_or(0);
            sh.line = Some(Line {
                color: Color::Rgb(c),
                width: p.get(0x01CB).map(i64::from).unwrap_or(9525),
                dash: "solid",
            });
        }
        sh.insets = [
            p.get(0x0081).map(i64::from).unwrap_or(91_440),
            p.get(0x0082).map(i64::from).unwrap_or(45_720),
            p.get(0x0083).map(i64::from).unwrap_or(91_440),
            p.get(0x0084).map(i64::from).unwrap_or(45_720),
        ];
        sh.v_anchor = match p.get(0x0087).unwrap_or(0) {
            1 | 4 | 5 | 8 | 9 => "ctr",
            2 | 3 | 6 | 7 => "b",
            _ => "t",
        };
        sh.flip_h = shape.flags & escher::F_FLIP_H != 0;
        sh.flip_v = shape.flags & escher::F_FLIP_V != 0;
        sh.rot = ((p.get(0x0004).unwrap_or(0) as i32 as i64 * 60_000) >> 16) as i32;
        if let Some((a, b)) = text_range {
            let b = b.min(self.text.len() as u32);
            if b > a + 1 {
                let mut blocks = self.story_blocks(a, b, Story::Textbox)?;
                // The mark that ends the text box is not a paragraph of it.
                if blocks.len() > 1
                    && let Some(Block::Para(last)) = blocks.last()
                    && last.content.is_empty()
                {
                    blocks.pop();
                }
                sh.text = blocks;
            }
        }
        Ok(Some(Drawing {
            anchor: Some(anchor),
            cx,
            cy,
            name: "Shape".into(),
            descr: None,
            kind: DrawingKind::Shape(sh),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colours_and_fixed_point() {
        assert_eq!(color_of(0x0000_00FF), Some(0xFF0000));
        assert_eq!(color_of(0x0100_0000), None);
        assert_eq!(color_of(0x00FF_8000), Some(0x0080FF));
        // 0.25 of the picture.
        assert_eq!(fixed(0x4000), 25_000);
    }
}
