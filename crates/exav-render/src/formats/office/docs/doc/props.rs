//! Character, paragraph and section modifiers ([MS-DOC] 2.6) applied to the
//! model's property structs.

use super::sprm::{parse, Prl};
use crate::formats::office::common::bytes::Cur;
use crate::formats::office::docs::model::*;

/// The 16 colours of an Ico ([MS-DOC] 2.9.119); 0 is automatic.
pub fn ico(i: u8) -> Color {
    const P: [u32; 17] = [
        0, 0x000000, 0x0000FF, 0x00FFFF, 0x00FF00, 0xFF00FF, 0xFF0000, 0xFFFF00, 0xFFFFFF,
        0x000080, 0x008080, 0x008000, 0x800080, 0x800000, 0x808000, 0x808080, 0xC0C0C0,
    ];
    match i {
        1..=16 => Color::Rgb(P[usize::from(i)]),
        _ => Color::Auto,
    }
}

/// A COLORREF: red, green, blue, then 0xFF when automatic.
pub fn colorref(v: u32) -> Color {
    if v >> 24 == 0xFF {
        return Color::Auto;
    }
    let (r, g, b) = (v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF);
    Color::Rgb(r << 16 | g << 8 | b)
}

fn highlight(i: u8) -> Option<&'static str> {
    Some(match i {
        0 => "none",
        1 => "black",
        2 => "blue",
        3 => "cyan",
        4 => "green",
        5 => "magenta",
        6 => "red",
        7 => "yellow",
        8 => "white",
        9 => "darkBlue",
        10 => "darkCyan",
        11 => "darkGreen",
        12 => "darkMagenta",
        13 => "darkRed",
        14 => "darkYellow",
        15 => "darkGray",
        16 => "lightGray",
        _ => return None,
    })
}

fn underline(k: u8) -> Option<&'static str> {
    Some(match k {
        0 => "none",
        1 => "single",
        2 => "words",
        3 => "double",
        4 => "dotted",
        6 => "thick",
        7 => "dash",
        9 => "dotDash",
        10 => "dotDotDash",
        11 => "wave",
        0x14 => "dottedHeavy",
        0x17 => "dashedHeavy",
        0x19 => "dashDotHeavy",
        0x1A => "dashDotDotHeavy",
        0x1B => "wavyHeavy",
        0x27 => "dashLongHeavy",
        0x2B => "wavyDouble",
        _ => "single",
    })
}

fn border_style(t: u8) -> Option<&'static str> {
    Some(match t {
        0 => return None,
        1 | 5 => "single",
        3 => "double",
        6 => "dotted",
        7 => "dashed",
        8 => "dotDash",
        9 => "dotDotDash",
        10 => "triple",
        11 => "thinThickSmallGap",
        12 => "thickThinSmallGap",
        13 => "thinThickThinSmallGap",
        14 => "thinThickMediumGap",
        15 => "thickThinMediumGap",
        16 => "thinThickThinMediumGap",
        17 => "thinThickLargeGap",
        18 => "thickThinLargeGap",
        19 => "thinThickThinLargeGap",
        20 => "wave",
        21 => "doubleWave",
        22 => "dashSmallGap",
        23 => "dashDotStroked",
        24 => "threeDEmboss",
        25 => "threeDEngrave",
        26 => "outset",
        27 => "inset",
        0xFF => return None,
        _ => "single",
    })
}

/// A Brc80 (4 bytes). `None` for no border.
pub fn brc80(b: &[u8]) -> Option<Border> {
    if b.len() < 4 || b[..4] == [0xFF; 4] {
        return None;
    }
    let style = border_style(b[1])?;
    let size = u32::from(b[0]).clamp(2, 96);
    Some(Border {
        style,
        size,
        space: u32::from(b[3] & 0x1F),
        color: ico(b[2]),
        shadow: b[3] & 0x20 != 0,
    })
}

/// A Brc (8 bytes). `None` for no border.
pub fn brc(b: &[u8]) -> Option<Border> {
    if b.len() < 8 || b[4..8] == [0xFF; 4] {
        return None;
    }
    let style = border_style(b[5])?;
    let w = u32::from(b[4]);
    let size = if b[5] >= 0x40 { w * 8 } else { w }.clamp(2, 96);
    let flags = u16::from_le_bytes([b[6], b[7]]);
    Some(Border {
        style,
        size,
        space: u32::from(flags & 0x1F),
        color: colorref(u32::from_le_bytes([b[0], b[1], b[2], b[3]])),
        shadow: flags & 0x20 != 0,
    })
}

fn rgb_of(c: Color, auto: u32) -> u32 {
    match c {
        Color::Rgb(v) => v,
        Color::Auto => auto,
    }
}

/// The share of the foreground colour in a shading pattern.
fn coverage(ipat: u16) -> f64 {
    match ipat {
        0 => 0.0,
        1 => 1.0,
        2 => 0.05,
        3 => 0.10,
        4 => 0.20,
        5 => 0.25,
        6 => 0.30,
        7 => 0.40,
        8 => 0.50,
        9 => 0.60,
        10 => 0.70,
        11 => 0.75,
        12 => 0.80,
        13 => 0.90,
        14..=19 => 0.5,
        20..=25 => 0.25,
        0x23 => 0.025,
        0x24 => 0.075,
        0x25 => 0.125,
        0x26 => 0.15,
        0x27 => 0.175,
        0x28 => 0.225,
        0x29 => 0.275,
        0x2A => 0.325,
        0x2B => 0.35,
        0x2C => 0.375,
        0x2D => 0.425,
        0x2E => 0.45,
        0x2F => 0.475,
        0x30 => 0.525,
        0x31 => 0.55,
        0x32 => 0.575,
        0x33 => 0.625,
        0x34 => 0.65,
        0x35 => 0.675,
        0x36 => 0.725,
        0x37 => 0.775,
        0x38 => 0.825,
        0x39 => 0.85,
        0x3A => 0.875,
        0x3B => 0.925,
        0x3C => 0.95,
        0x3D => 0.975,
        _ => 0.0,
    }
}

/// The flat colour a pattern of `fore` on `back` looks like; `None` for
/// no shading.
pub fn blend(fore: Color, back: Color, ipat: u16) -> Option<Shading> {
    if ipat == 0xFFFF {
        return None;
    }
    let p = coverage(ipat);
    if p == 0.0 && back == Color::Auto {
        return None;
    }
    let (f, b) = (rgb_of(fore, 0x000000), rgb_of(back, 0xFFFFFF));
    let mix = |s: u32| {
        let (x, y) = (f64::from((f >> s) & 0xFF), f64::from((b >> s) & 0xFF));
        (x * p + y * (1.0 - p)).round() as u32
    };
    Some(Shading::fill(Color::Rgb(
        mix(16) << 16 | mix(8) << 8 | mix(0),
    )))
}

/// A Shd (10 bytes).
pub fn shd(b: &[u8]) -> Option<Shading> {
    if b.len() < 10 {
        return None;
    }
    let f = colorref(u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    let k = colorref(u32::from_le_bytes([b[4], b[5], b[6], b[7]]));
    blend(f, k, u16::from_le_bytes([b[8], b[9]]))
}

/// A Shd80 (2 bytes).
pub fn shd80(v: u16) -> Option<Shading> {
    if v == 0xFFFF {
        return None;
    }
    blend(
        ico((v & 0x1F) as u8),
        ico(((v >> 5) & 0x1F) as u8),
        (v >> 10) & 0x3F,
    )
}

/// What a character modifier list says beyond formatting.
#[derive(Clone, Debug, Default)]
pub struct ChpAux {
    pub pic_loc: Option<i32>,
    pub spec: bool,
    pub data: bool,
    pub ole2: bool,
    pub obj: bool,
    pub symbol: Option<(u16, u16)>,
    /// A character style set by sprmCIstd.
    pub istd: Option<u16>,
    pub fld_vanish: bool,
    pub deleted: bool,
    pub inserted: bool,
}

/// What a paragraph modifier list says beyond formatting.
#[derive(Clone, Debug, Default)]
pub struct PapAux {
    pub istd: Option<u16>,
    pub in_table: bool,
    pub ttp: bool,
    pub depth: Option<u32>,
    pub inner_cell: bool,
    pub inner_ttp: bool,
    /// The list instance a paragraph is in, when the modifiers set one.
    pub ilfo_set: Option<i32>,
    pub ilvl: u8,
    pub huge: Option<u32>,
    pub frame: Option<Frame>,
    pub drop_cap: Option<(u8, u8)>,
    pub tabs_cleared: Vec<i32>,
}

/// Font names by ftc, and the style values toggles are relative to.
pub struct Ctx<'a> {
    pub fonts: &'a [String],
    /// The style-level properties of the text a toggle is relative to.
    pub base: &'a RunProps,
}

impl Ctx<'_> {
    fn font(&self, i: u16) -> Option<String> {
        self.fonts.get(usize::from(i)).cloned()
    }
}

/// A ToggleOperand: 0 off, 1 on, 0x80 as the style, 0x81 as the style's
/// opposite.
fn toggle(v: u8, base: Option<bool>, cur: &mut Option<bool>) {
    match v {
        0 => *cur = Some(false),
        1 => *cur = Some(true),
        0x80 => *cur = None,
        0x81 => *cur = Some(!base.unwrap_or(false)),
        _ => {}
    }
}

fn bool8(v: u8) -> Option<bool> {
    Some(v & 1 != 0)
}

/// Applies a character modifier to `rp`.
pub fn apply_chp(rp: &mut RunProps, aux: &mut ChpAux, p: &Prl, cx: &Ctx) {
    let b = cx.base;
    match p.op {
        0x0800 => aux.deleted = p.u8() != 0,
        0x0801 => aux.inserted = p.u8() != 0,
        0x0802 => aux.fld_vanish = p.u8() & 1 != 0,
        0x6A03 => aux.pic_loc = Some(p.i32()),
        0x0806 => aux.data = p.u8() & 1 != 0,
        0x080A => aux.ole2 = p.u8() & 1 != 0,
        0x0855 => aux.spec = p.u8() & 1 != 0,
        0x0856 => aux.obj = p.u8() & 1 != 0,
        0x6A09 => {
            let mut c = Cur::new(p.val);
            let ftc = c.u16();
            aux.symbol = Some((ftc, c.u16()));
        }
        0x4A30 => aux.istd = Some(p.u16()),
        0x2A33 => {
            // sprmCPlain: the direct formatting is cleared.
            let style = rp.style.take();
            *rp = RunProps::default();
            rp.style = style;
        }
        0x0835 => toggle(p.u8(), b.bold, &mut rp.bold),
        0x0836 => toggle(p.u8(), b.italic, &mut rp.italic),
        0x0837 => toggle(p.u8(), b.strike, &mut rp.strike),
        0x0838 => toggle(p.u8(), b.outline, &mut rp.outline),
        0x0839 => toggle(p.u8(), b.shadow, &mut rp.shadow),
        0x083A => toggle(p.u8(), b.small_caps, &mut rp.small_caps),
        0x083B => toggle(p.u8(), b.caps, &mut rp.caps),
        0x083C => toggle(p.u8(), b.vanish, &mut rp.vanish),
        0x0854 => toggle(p.u8(), b.imprint, &mut rp.imprint),
        0x0858 => toggle(p.u8(), b.emboss, &mut rp.emboss),
        0x2A53 => toggle(p.u8(), b.dstrike, &mut rp.dstrike),
        0x085C => toggle(p.u8(), b.bold_cs, &mut rp.bold_cs),
        0x085D => toggle(p.u8(), b.italic_cs, &mut rp.italic_cs),
        0x085A => rp.rtl = bool8(p.u8()),
        0x0882 => rp.cs = bool8(p.u8()),
        0x2A3E => rp.underline = underline(p.u8()),
        0x8840 => rp.spacing = Some(i32::from(p.i16())),
        0x2A42 => rp.color = Some(ico(p.u8())),
        0x6870 => rp.color = Some(colorref(p.u32())),
        0x2A0C => rp.highlight = highlight(p.u8()),
        0x4A43 => rp.size = Some(u32::from(p.u16())),
        0x4A61 => rp.size_cs = Some(u32::from(p.u16())),
        0x4845 => rp.position = Some(i32::from(p.i16())),
        0x2A48 => {
            rp.vert_align = Some(match p.u8() {
                1 => VertAlign::Superscript,
                2 => VertAlign::Subscript,
                _ => VertAlign::Baseline,
            })
        }
        0x484B => rp.kerning = Some(u32::from(p.u16())),
        0x4852 => rp.scale = Some(u32::from(p.u16()).clamp(1, 600)),
        0x4A4F => rp.fonts.ascii = cx.font(p.u16()),
        0x4A50 => rp.fonts.east_asia = cx.font(p.u16()),
        0x4A51 => rp.fonts.hansi = cx.font(p.u16()),
        0x4A5E => rp.fonts.cs = cx.font(p.u16()),
        0x6865 => rp.border = brc80(p.val),
        0xCA72 => rp.border = brc(p.var()),
        0x4866 => rp.shading = shd80(p.u16()),
        0xCA71 => rp.shading = shd(p.var()),
        0x6877 => rp.underline_color = Some(colorref(p.u32())),
        0x4873 | 0x4874 => {}
        _ => {}
    }
}

/// Applies a list of character modifiers.
pub fn apply_chp_list(rp: &mut RunProps, aux: &mut ChpAux, grpprl: &[u8], cx: &Ctx) {
    for p in parse(grpprl) {
        if p.sgc() == super::sprm::SGC_CHAR {
            apply_chp(rp, aux, &p, cx);
        }
    }
}

fn tab_kind(tbd: u8) -> TabKind {
    match tbd & 7 {
        1 => TabKind::Center,
        2 => TabKind::Right,
        3 => TabKind::Decimal,
        4 => TabKind::Bar,
        _ => TabKind::Left,
    }
}

fn tab_leader(tbd: u8) -> TabLeader {
    match (tbd >> 3) & 7 {
        1 => TabLeader::Dot,
        2 => TabLeader::Hyphen,
        3 => TabLeader::Underscore,
        4 => TabLeader::Heavy,
        5 => TabLeader::MiddleDot,
        _ => TabLeader::None,
    }
}

/// sprmPChgTabs and sprmPChgTabsPapx: positions to clear, then to add.
fn change_tabs(pp: &mut ParaProps, aux: &mut PapAux, v: &[u8], close: bool) {
    let mut c = Cur::new(v);
    let del = usize::from(c.u8());
    let mut dels = vec![];
    for _ in 0..del.min(64) {
        dels.push(i32::from(c.i16()));
    }
    if close {
        c.skip(2 * del.min(64));
    }
    let add = usize::from(c.u8()).min(64);
    let mut poss = vec![];
    for _ in 0..add {
        poss.push(i32::from(c.i16()));
    }
    let mut tabs = vec![];
    for pos in poss {
        let tbd = c.u8();
        tabs.push(Tab {
            pos,
            kind: tab_kind(tbd),
            leader: tab_leader(tbd),
        });
    }
    for d in dels {
        if !tabs.iter().any(|t| (t.pos - d).abs() < 25) {
            pp.tabs.retain(|t| (t.pos - d).abs() >= 25);
            aux.tabs_cleared.push(d);
            pp.tabs.push(Tab {
                pos: d,
                kind: TabKind::Clear,
                leader: TabLeader::None,
            });
        }
    }
    for t in tabs {
        pp.tabs.retain(|x| x.pos != t.pos);
        pp.tabs.push(t);
    }
    pp.tabs.sort_by_key(|t| t.pos);
}

/// Table nesting beyond this is cut: one table builder is open per level.
const MAX_TABLE_DEPTH: u32 = 63;

/// Applies a paragraph modifier to `pp`.
pub fn apply_pap(pp: &mut ParaProps, aux: &mut PapAux, p: &Prl) {
    match p.op {
        0x4600 => aux.istd = Some(p.u16()),
        0x2403 | 0x2461 => {
            pp.jc = Some(match p.u8() {
                1 => Jc::Center,
                2 => Jc::Right,
                3..=5 | 7 => Jc::Both,
                8 => Jc::Distribute,
                _ => Jc::Left,
            })
        }
        0x2405 => pp.keep_lines = bool8(p.u8()),
        0x2406 => pp.keep_next = bool8(p.u8()),
        0x2407 => pp.page_break_before = bool8(p.u8()),
        0x260A => aux.ilvl = p.u8(),
        0x460B => {
            let v = i32::from(p.i16());
            // 0xF801 stands for no list.
            aux.ilfo_set = Some(if v == -2047 { 0 } else { v });
        }
        0x240C => pp.suppress_line_numbers = bool8(p.u8()),
        0xC60D => change_tabs(pp, aux, p.var(), false),
        0xC615 => change_tabs(pp, aux, p.var(), true),
        0x840E | 0x845D => pp.ind_right = Some(i32::from(p.i16())),
        0x840F | 0x845E => pp.ind_left = Some(i32::from(p.i16())),
        0x8411 | 0x8460 => {
            let v = i32::from(p.i16());
            if v >= 0 {
                pp.ind_first_line = Some(v);
                pp.ind_hanging = None;
            } else {
                pp.ind_first_line = None;
                pp.ind_hanging = Some(-v);
            }
        }
        0x6412 => {
            let mut c = Cur::new(p.val);
            let dya = c.i16();
            let mult = c.u16();
            if mult == 1 {
                pp.line = Some(i32::from(dya).max(0));
                pp.line_rule = Some(LineRule::Auto);
            } else if dya < 0 {
                pp.line = Some(-i32::from(dya));
                pp.line_rule = Some(LineRule::Exact);
            } else {
                pp.line = Some(i32::from(dya));
                pp.line_rule = Some(LineRule::AtLeast);
            }
        }
        0xA413 => pp.space_before = Some(i32::from(p.u16())),
        0xA414 => pp.space_after = Some(i32::from(p.u16())),
        0x245B => pp.before_auto = bool8(p.u8()),
        0x245C => pp.after_auto = bool8(p.u8()),
        0x2416 => aux.in_table = p.u8() & 1 != 0,
        0x2417 => aux.ttp = p.u8() & 1 != 0,
        0x6649 => aux.depth = Some(p.u32().min(MAX_TABLE_DEPTH)),
        0x664A => {
            // sprmPDtap: a change of table depth.
            let d = aux.depth.unwrap_or(0) as i64 + i64::from(p.i32());
            aux.depth = Some(d.clamp(0, i64::from(MAX_TABLE_DEPTH)) as u32);
        }
        0x244B => aux.inner_cell = p.u8() & 1 != 0,
        0x244C => aux.inner_ttp = p.u8() & 1 != 0,
        0x6646 => aux.huge = Some(p.u32()),
        0x2431 => pp.widow_control = bool8(p.u8()),
        0x2441 => pp.bidi = bool8(p.u8()),
        0x246D => pp.contextual_spacing = bool8(p.u8()),
        0x2640 => pp.outline_level = Some(u32::from(p.u8().min(9))),
        0x6424..=0x6428 => {
            let b = brc80(p.val);
            match p.op {
                0x6424 => pp.borders.top = b,
                0x6425 => pp.borders.left = b,
                0x6426 => pp.borders.bottom = b,
                0x6427 => pp.borders.right = b,
                _ => pp.borders.between = b,
            }
        }
        0xC64E..=0xC652 => {
            let b = brc(p.var());
            match p.op {
                0xC64E => pp.borders.top = b,
                0xC64F => pp.borders.left = b,
                0xC650 => pp.borders.bottom = b,
                0xC651 => pp.borders.right = b,
                _ => pp.borders.between = b,
            }
        }
        0x442D => pp.shading = shd80(p.u16()),
        0xC64D => pp.shading = shd(p.var()),
        0x442C => {
            // sprmPDcs: drop cap kind in the low 3 bits, lines in the next 5.
            let v = p.u16();
            aux.drop_cap = Some(((v & 7) as u8, ((v >> 3) & 0x1F) as u8));
        }
        0x261B => {
            let v = p.u8();
            let f = aux.frame.get_or_insert_with(Frame::default);
            f.v_anchor = Some(match (v >> 4) & 3 {
                0 => "margin",
                1 => "page",
                _ => "text",
            });
            f.h_anchor = Some(match (v >> 6) & 3 {
                0 => "text",
                1 => "margin",
                _ => "page",
            });
        }
        0x8418 => {
            let v = p.i16();
            let f = aux.frame.get_or_insert_with(Frame::default);
            match v {
                0 => f.x_align = Some("left"),
                -4 => f.x_align = Some("center"),
                -8 => f.x_align = Some("right"),
                -12 => f.x_align = Some("inside"),
                -16 => f.x_align = Some("outside"),
                v => f.x = Some(i32::from(v) - 1),
            }
        }
        0x8419 => {
            let v = p.i16();
            let f = aux.frame.get_or_insert_with(Frame::default);
            match v {
                0 => {}
                -4 => f.y_align = Some("top"),
                -8 => f.y_align = Some("center"),
                -12 => f.y_align = Some("bottom"),
                -16 => f.y_align = Some("inside"),
                -20 => f.y_align = Some("outside"),
                v => f.y = Some(i32::from(v) - 1),
            }
        }
        0x841A => {
            let v = p.u16();
            let f = aux.frame.get_or_insert_with(Frame::default);
            if v > 0 {
                f.width = Some(i32::from(v));
            }
        }
        0x442B => {
            let v = p.u16();
            let f = aux.frame.get_or_insert_with(Frame::default);
            if v & 0x7FFF != 0 {
                f.height = Some(i32::from(v & 0x7FFF));
                f.height_exact = v & 0x8000 != 0;
            }
        }
        0x2423 => {
            let f = aux.frame.get_or_insert_with(Frame::default);
            f.wrap = Some(match p.u8() {
                1 => "notBeside",
                2 => "around",
                3 => "none",
                4 => "tight",
                5 => "through",
                _ => "auto",
            });
        }
        0x842E => {
            let v = i32::from(p.i16());
            aux.frame.get_or_insert_with(Frame::default).v_space = Some(v);
        }
        0x842F => {
            let v = i32::from(p.i16());
            aux.frame.get_or_insert_with(Frame::default).h_space = Some(v);
        }
        _ => {}
    }
}

pub fn apply_pap_list(pp: &mut ParaProps, aux: &mut PapAux, grpprl: &[u8]) {
    for p in parse(grpprl) {
        if p.sgc() == super::sprm::SGC_PARA {
            apply_pap(pp, aux, &p);
        }
    }
}

/// Applies the section modifiers of `grpprl` to `s`.
pub fn apply_sep(s: &mut Section, grpprl: &[u8]) {
    let mut restart = false;
    let mut start: Option<u32> = None;
    let mut cols: Option<u32> = None;
    let mut widths: Vec<(usize, i32, i32)> = vec![];
    for p in parse(grpprl) {
        match p.op {
            0x3009 => {
                s.kind = match p.u8() {
                    0 => SectionType::Continuous,
                    1 => SectionType::NextColumn,
                    3 => SectionType::EvenPage,
                    4 => SectionType::OddPage,
                    _ => SectionType::NextPage,
                }
            }
            0x300A => s.title_page = p.u8() & 1 != 0,
            0x500B => cols = Some(u32::from(p.u16()) + 1),
            0x900C => s.columns.space = i32::from(p.u16()),
            0x3019 => s.columns.separator = p.u8() & 1 != 0,
            0x300E => {
                s.page_fmt = Some(match p.u8() {
                    1 => "upperRoman",
                    2 => "lowerRoman",
                    3 => "upperLetter",
                    4 => "lowerLetter",
                    _ => "decimal",
                })
            }
            0x3011 => restart = p.u8() & 1 != 0,
            0x501C | 0x7044 => {
                start = Some(if p.op == 0x501C {
                    u32::from(p.u16())
                } else {
                    p.u32()
                });
            }
            0xB017 => s.header = i32::from(p.u16()),
            0xB018 => s.footer = i32::from(p.u16()),
            0x301A => {
                s.v_align = match p.u8() {
                    1 => Some("center"),
                    2 => Some("both"),
                    3 => Some("bottom"),
                    _ => None,
                }
            }
            0x301D => s.landscape = p.u8() == 2,
            0xB01F => s.width = i32::from(p.u16()),
            0xB020 => s.height = i32::from(p.u16()),
            0xB021 => s.left = i32::from(p.u16()),
            0xB022 => s.right = i32::from(p.u16()),
            0x9023 => s.top = i32::from(p.i16()),
            0x9024 => s.bottom = i32::from(p.i16()),
            0xB025 => s.gutter = i32::from(p.u16()),
            0x3228 => s.bidi = p.u8() & 1 != 0,
            0x322A => s.rtl_gutter = p.u8() & 1 != 0,
            0x702B => s.page_borders.top = brc80(p.val),
            0x702C => s.page_borders.left = brc80(p.val),
            0x702D => s.page_borders.bottom = brc80(p.val),
            0x702E => s.page_borders.right = brc80(p.val),
            0xD234 => s.page_borders.top = brc(p.var()),
            0xD235 => s.page_borders.left = brc(p.var()),
            0xD236 => s.page_borders.bottom = brc(p.var()),
            0xD237 => s.page_borders.right = brc(p.var()),
            0x5015 => {
                let n = u32::from(p.u16());
                if n > 0 {
                    let ln = s.line_numbers.get_or_insert((1, n, 0));
                    ln.1 = n;
                }
            }
            0x9016 => {
                if let Some(ln) = s.line_numbers.as_mut() {
                    ln.2 = i32::from(p.u16());
                }
            }
            0x501B => {
                if let Some(ln) = s.line_numbers.as_mut() {
                    ln.0 = u32::from(p.u16()) + 1;
                }
            }
            0x5033 => {
                s.text_direction = match p.u16() {
                    1 => Some("tbRl"),
                    3 => Some("btLr"),
                    _ => None,
                }
            }
            _ => {}
        }
        // sprmSDxaColWidth and sprmSDxaColSpacing: (column, twips).
        if matches!(p.op, 0xF203 | 0xF204) {
            if let [_, i, a, b, ..] = p.val {
                let v = i32::from(u16::from_le_bytes([*a, *b]));
                let i = usize::from(*i);
                let e = match widths.iter().position(|w| w.0 == i) {
                    Some(k) => k,
                    None => {
                        widths.push((i, 0, 0));
                        widths.len() - 1
                    }
                };
                if p.op == 0xF203 {
                    widths[e].1 = v;
                } else {
                    widths[e].2 = v;
                }
            }
        }
    }
    if restart {
        s.page_start = Some(start.unwrap_or(1));
    }
    if let Some(n) = cols {
        s.columns.num = n;
        if !widths.is_empty() {
            widths.sort_by_key(|w| w.0);
            s.columns.widths = widths.iter().map(|w| (w.1, w.2)).collect();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cx() -> (Vec<String>, RunProps) {
        (vec!["Arial".into(), "Times".into()], RunProps::default())
    }

    #[test]
    fn character_modifiers() {
        let (fonts, base) = cx();
        let c = Ctx {
            fonts: &fonts,
            base: &base,
        };
        let mut rp = RunProps::default();
        let mut aux = ChpAux::default();
        // bold on, 12 pt, font 1, red.
        let g = [
            0x35, 0x08, 1, 0x43, 0x4A, 24, 0, 0x4F, 0x4A, 1, 0, 0x70, 0x68, 0xFF, 0, 0, 0,
        ];
        apply_chp_list(&mut rp, &mut aux, &g, &c);
        assert_eq!(rp.bold, Some(true));
        assert_eq!(rp.size, Some(24));
        assert_eq!(rp.fonts.ascii.as_deref(), Some("Times"));
        assert_eq!(rp.color, Some(Color::Rgb(0xFF0000)));
    }

    #[test]
    fn toggles_are_relative_to_the_style() {
        let fonts = vec![];
        let base = RunProps {
            bold: Some(true),
            ..RunProps::default()
        };
        let c = Ctx {
            fonts: &fonts,
            base: &base,
        };
        let mut rp = RunProps::default();
        let mut aux = ChpAux::default();
        apply_chp_list(&mut rp, &mut aux, &[0x35, 0x08, 0x81], &c);
        assert_eq!(rp.bold, Some(false));
        apply_chp_list(&mut rp, &mut aux, &[0x35, 0x08, 0x80], &c);
        assert_eq!(rp.bold, None);
    }

    #[test]
    fn paragraph_modifiers() {
        let mut pp = ParaProps::default();
        let mut aux = PapAux::default();
        // centered, left indent 720, first line -348 (hanging), exact 300.
        let g = [
            0x61, 0x24, 1, 0x5E, 0x84, 0xD0, 0x02, 0x60, 0x84, 0xA4, 0xFE, 0x12, 0x64, 0xD4, 0xFE,
            0, 0,
        ];
        apply_pap_list(&mut pp, &mut aux, &g);
        assert_eq!(pp.jc, Some(Jc::Center));
        assert_eq!(pp.ind_left, Some(720));
        assert_eq!(pp.ind_hanging, Some(348));
        assert_eq!(pp.line, Some(300));
        assert_eq!(pp.line_rule, Some(LineRule::Exact));
    }

    #[test]
    fn tab_stops_add_and_clear() {
        let mut pp = ParaProps::default();
        let mut aux = PapAux::default();
        // sprmPChgTabsPapx: no deletions, two tabs (1440 right with dot
        // leader, then 720 left); the stops end up in order.
        let g = [0x0D, 0xC6, 8, 0, 2, 0xA0, 0x05, 0xD0, 0x02, 0x0A, 0x00];
        apply_pap_list(&mut pp, &mut aux, &g);
        assert_eq!(pp.tabs.len(), 2);
        assert_eq!(pp.tabs[0].pos, 720);
        assert_eq!(pp.tabs[1].kind, TabKind::Right);
        assert_eq!(pp.tabs[1].leader, TabLeader::Dot);
    }

    #[test]
    fn colours_and_borders() {
        assert_eq!(ico(6), Color::Rgb(0xFF0000));
        assert_eq!(colorref(0xFF00_0000), Color::Auto);
        assert_eq!(colorref(0x00_33_22_11), Color::Rgb(0x11_22_33));
        let b = brc80(&[8, 1, 6, 0x32]).unwrap();
        assert_eq!(
            (b.style, b.size, b.space, b.shadow),
            ("single", 8, 18, true)
        );
        assert!(brc80(&[0xFF; 4]).is_none());
        // Yellow behind no pattern; a solid pattern is its foreground.
        let s = shd80(0x0008 | (7 << 5)).unwrap();
        assert_eq!(s.fill, Some(Color::Rgb(0xFFFF00)));
        let s = shd80(0x0001 | (7 << 5) | (1 << 10)).unwrap();
        assert_eq!(s.fill, Some(Color::Rgb(0x000000)));
        // A 50% pattern of black on white is mid grey.
        let s = shd80(1 | (8 << 5) | (8 << 10)).unwrap();
        assert_eq!(s.fill, Some(Color::Rgb(0x808080)));
        assert!(shd80(0xFFFF).is_none());
    }

    #[test]
    fn section_modifiers() {
        let mut s = Section::default();
        // page 11906 x 16838 landscape, left margin 1417, two columns, space 708.
        let g = [
            0x1F, 0xB0, 0x82, 0x2E, 0x20, 0xB0, 0xC6, 0x41, 0x1D, 0x30, 2, 0x21, 0xB0, 0x89, 0x05,
            0x0B, 0x50, 1, 0, 0x0C, 0x90, 0xC4, 0x02,
        ];
        apply_sep(&mut s, &g);
        assert_eq!((s.width, s.height), (11906, 16838));
        assert!(s.landscape);
        assert_eq!(s.left, 1417);
        assert_eq!((s.columns.num, s.columns.space), (2, 708));
    }
}
