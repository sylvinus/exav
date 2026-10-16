//! PPT text ([MS-PPT] 2.9): character and paragraph exceptions (CF, PF),
//! master text styles, a text body's atoms, and their resolution into the
//! model's paragraphs and runs with every property explicit.

use super::pp9::{Pf9, NO_NUMBERING};
use super::records::Rec;
use super::rt;
use crate::formats::office::common::bytes::Cur;
use crate::formats::office::slides::model::*;

/// Master units (576 per inch) to EMU.
pub fn mu(v: i32) -> Emu {
    (f64::from(v) * 1587.5).round() as Emu
}

/// A colour of text: a scheme index (0 to 7) or RGB.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TColor {
    Scheme(u8),
    Rgb(Rgb),
}

fn color_index(c: &mut Cur) -> Option<TColor> {
    let (r, g, b, i) = (c.u8(), c.u8(), c.u8(), c.u8());
    match i {
        0xFE => Some(TColor::Rgb(
            u32::from(r) << 16 | u32::from(g) << 8 | u32::from(b),
        )),
        0..=7 => Some(TColor::Scheme(i)),
        _ => None,
    }
}

/// Character exception ([MS-PPT] 2.9.14).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Cf {
    pub bold: Option<bool>,
    pub italic: Option<bool>,
    pub underline: Option<bool>,
    pub shadow: Option<bool>,
    pub emboss: Option<bool>,
    pub font: Option<u16>,
    pub ea_font: Option<u16>,
    pub sym_font: Option<u16>,
    pub size: Option<u16>,
    pub color: Option<TColor>,
    pub position: Option<i16>,
    /// The run grouping of the PP9 extension's items (CFStyle.pp9rt).
    pub pp9rt: Option<u8>,
}

impl Cf {
    pub fn overlay(&mut self, o: &Cf) {
        macro_rules! over {
            ($($f:ident),*) => { $( if o.$f.is_some() { self.$f = o.$f; } )* };
        }
        over!(
            bold, italic, underline, shadow, emboss, font, ea_font, sym_font, size, color,
            position, pp9rt
        );
    }
}

pub fn read_cf(c: &mut Cur) -> Cf {
    let m = c.u32();
    let mut cf = Cf::default();
    let bit = |n: u32| m & (1 << n) != 0;
    // bold, italic, underline, shadow, fehint, kumi, emboss, fHasStyle.
    if m & 0x0000_3EF7 != 0 {
        let s = c.u16();
        let get = |n: u32| s & (1 << n) != 0;
        if bit(0) {
            cf.bold = Some(get(0));
        }
        if bit(1) {
            cf.italic = Some(get(1));
        }
        if bit(2) {
            cf.underline = Some(get(2));
        }
        if bit(4) {
            cf.shadow = Some(get(4));
        }
        if bit(9) {
            cf.emboss = Some(get(9));
        }
        // The style bits' own field holds the run grouping.
        if m & 0x0000_3C00 != 0 {
            cf.pp9rt = Some(((s >> 10) & 0xF) as u8);
        }
    }
    if bit(16) {
        cf.font = Some(c.u16());
    }
    if bit(21) {
        cf.ea_font = Some(c.u16());
    }
    if bit(22) {
        // The ANSI font: read past it.
        c.u16();
    }
    if bit(23) {
        cf.sym_font = Some(c.u16());
    }
    if bit(17) {
        cf.size = Some(c.u16());
    }
    if bit(18) {
        cf.color = color_index(c);
    }
    if bit(19) {
        cf.position = Some(c.i16());
    }
    cf
}

/// Paragraph exception ([MS-PPT] 2.9.20).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Pf {
    pub has_bullet: Option<bool>,
    pub bullet_has_font: Option<bool>,
    pub bullet_has_color: Option<bool>,
    pub bullet_has_size: Option<bool>,
    pub bullet_char: Option<u16>,
    pub bullet_font: Option<u16>,
    pub bullet_size: Option<i16>,
    pub bullet_color: Option<TColor>,
    pub align: Option<u16>,
    pub line_spacing: Option<i16>,
    pub space_before: Option<i16>,
    pub space_after: Option<i16>,
    pub margin: Option<i16>,
    pub indent: Option<i16>,
    pub default_tab: Option<u16>,
    pub tabs: Option<Vec<(i16, u16)>>,
    pub rtl: Option<bool>,
    /// From the PP9 extension: an automatic numbering scheme and start.
    pub autonum: Option<(u16, u16)>,
    /// From the PP9 extension: the index of a picture bullet.
    pub bullet_blip: Option<u16>,
}

impl Pf {
    pub fn overlay(&mut self, o: &Pf) {
        macro_rules! over {
            ($($f:ident),*) => { $( if o.$f.is_some() { self.$f = o.$f.clone(); } )* };
        }
        over!(
            has_bullet,
            bullet_has_font,
            bullet_has_color,
            bullet_has_size,
            bullet_char,
            bullet_font,
            bullet_size,
            bullet_color,
            align,
            line_spacing,
            space_before,
            space_after,
            margin,
            indent,
            default_tab,
            tabs,
            rtl,
            autonum,
            bullet_blip
        );
    }

    /// Takes what a PP9 paragraph extension sets.
    pub fn overlay9(&mut self, p: &Pf9) {
        if p.blip.is_some() {
            self.bullet_blip = p.blip;
        }
        if let Some((scheme, start)) = p.autonum {
            self.autonum = (scheme != NO_NUMBERING).then_some((scheme, start));
            // Numbering turned off leaves any picture bullet alone.
        }
    }
}

fn tab_stops(c: &mut Cur) -> Vec<(i16, u16)> {
    let n = c.u16().min(64);
    let mut v = Vec::with_capacity(n.into());
    for _ in 0..n {
        let pos = c.i16();
        let t = c.u16();
        v.push((pos, t));
    }
    v
}

pub fn read_pf(c: &mut Cur) -> Pf {
    let m = c.u32();
    let bit = |n: u32| m & (1 << n) != 0;
    let mut pf = Pf::default();
    if m & 0xF != 0 {
        let f = c.u16();
        let get = |n: u32| f & (1 << n) != 0;
        if bit(0) {
            pf.has_bullet = Some(get(0));
        }
        if bit(1) {
            pf.bullet_has_font = Some(get(1));
        }
        if bit(2) {
            pf.bullet_has_color = Some(get(2));
        }
        if bit(3) {
            pf.bullet_has_size = Some(get(3));
        }
    }
    if bit(7) {
        pf.bullet_char = Some(c.u16());
    }
    if bit(4) {
        pf.bullet_font = Some(c.u16());
    }
    if bit(6) {
        pf.bullet_size = Some(c.i16());
    }
    if bit(5) {
        pf.bullet_color = color_index(c);
    }
    if bit(11) {
        pf.align = Some(c.u16());
    }
    if bit(12) {
        pf.line_spacing = Some(c.i16());
    }
    if bit(13) {
        pf.space_before = Some(c.i16());
    }
    if bit(14) {
        pf.space_after = Some(c.i16());
    }
    if bit(8) {
        pf.margin = Some(c.i16());
    }
    if bit(10) {
        pf.indent = Some(c.i16());
    }
    if bit(15) {
        pf.default_tab = Some(c.u16());
    }
    if bit(20) {
        pf.tabs = Some(tab_stops(c));
    }
    if bit(16) {
        c.u16(); // font alignment
    }
    if m & (7 << 17) != 0 {
        c.u16(); // wrap flags
    }
    if bit(21) {
        pf.rtl = Some(c.u16() == 1);
    }
    pf
}

/// A master's text style for one text type: five levels.
#[derive(Clone, Debug, Default)]
pub struct Levels(pub [(Pf, Cf); 5]);

/// A TextMasterStyleAtom.
pub fn read_master_style(r: &Rec) -> Levels {
    let mut c = r.cur();
    let n = c.u16().min(5);
    let mut out = Levels::default();
    for i in 0..n as usize {
        let level = if r.inst >= 5 { c.u16() as usize } else { i };
        let pf = read_pf(&mut c);
        let cf = read_cf(&mut c);
        if c.short {
            break;
        }
        if let Some(slot) = out.0.get_mut(level) {
            *slot = (pf, cf);
        }
    }
    out
}

/// A tab stop type to DrawingML.
fn tab_kind(t: u16) -> &'static str {
    match t {
        1 => "ctr",
        2 => "r",
        3 => "dec",
        _ => "l",
    }
}

/// A text ruler ([MS-PPT] 2.9.30): margins and indents per level, tabs.
#[derive(Clone, Debug, Default)]
pub struct Ruler {
    pub default_tab: Option<u16>,
    pub tabs: Option<Vec<(i16, u16)>>,
    pub margin: [Option<i16>; 5],
    pub indent: [Option<i16>; 5],
}

pub fn read_ruler(d: &[u8]) -> Ruler {
    let mut c = Cur::new(d);
    let m = c.u32();
    let bit = |n: u32| m & (1 << n) != 0;
    let mut r = Ruler::default();
    if bit(1) {
        c.u16(); // levels
    }
    if bit(0) {
        r.default_tab = Some(c.u16());
    }
    if bit(2) {
        r.tabs = Some(tab_stops(&mut c));
    }
    for k in 0..5 {
        if bit(3 + k) {
            r.margin[k as usize] = Some(c.i16());
        }
        if bit(8 + k) {
            r.indent[k as usize] = Some(c.i16());
        }
    }
    r
}

#[derive(Clone, Debug)]
pub enum Meta {
    SlideNumber,
    DateTime,
    Footer,
    Header,
}

/// A text body's atoms, as read.
#[derive(Clone, Debug, Default)]
pub struct RawText {
    pub text_type: u32,
    pub chars: Vec<u16>,
    pub pf_runs: Vec<(u32, u16, Pf)>,
    pub cf_runs: Vec<(u32, Cf)>,
    pub ruler: Option<Ruler>,
    /// Indent levels of a master's text without a style atom.
    pub master_levels: Vec<(u32, u16)>,
    pub meta: Vec<(u32, Meta)>,
    /// Character ranges and the InteractiveInfoAtom of their links.
    pub link_info: Vec<(u32, u32, [u8; 16])>,
    /// The PP9 paragraph extensions of the shape this text is in.
    pub pp9: Vec<Pf9>,
}

/// Groups `records` (a SlideListWithText's or a client textbox's) into text
/// bodies, each starting at a TextHeaderAtom.
pub fn read_bodies<'a>(records: impl Iterator<Item = Rec<'a>>) -> Vec<RawText> {
    let mut out: Vec<RawText> = vec![];
    let mut pending_link: Option<[u8; 16]> = None;
    for r in records {
        if r.typ == rt::TEXT_HEADER {
            out.push(RawText {
                text_type: Cur::new(r.data).u32(),
                ..RawText::default()
            });
            continue;
        }
        if r.typ == rt::TEXT_RULER {
            // A ruler may come before the header (an outline reference's).
            if let Some(t) = out.last_mut() {
                t.ruler = Some(read_ruler(r.data));
            }
            continue;
        }
        let Some(t) = out.last_mut() else {
            continue;
        };
        match r.typ {
            rt::TEXT_CHARS => {
                t.chars = r
                    .data
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|b| u16::from_le_bytes(*b))
                    .take(1 << 20)
                    .collect()
            }
            rt::TEXT_BYTES => {
                t.chars = r.data.iter().take(1 << 20).map(|&b| u16::from(b)).collect()
            }
            rt::STYLE_TEXT_PROP => {
                let total = t.chars.len() as u32 + 1;
                let mut c = r.cur();
                let mut seen = 0u32;
                while seen < total && !c.short && t.pf_runs.len() < 1 << 16 {
                    let n = c.u32();
                    let level = c.u16();
                    let pf = read_pf(&mut c);
                    if c.short || n == 0 {
                        break;
                    }
                    seen = seen.saturating_add(n);
                    t.pf_runs.push((n, level.min(4), pf));
                }
                let mut seen = 0u32;
                while seen < total && !c.short && t.cf_runs.len() < 1 << 16 {
                    let n = c.u32();
                    let cf = read_cf(&mut c);
                    if c.short || n == 0 {
                        break;
                    }
                    seen = seen.saturating_add(n);
                    t.cf_runs.push((n, cf));
                }
            }
            rt::MASTER_TEXT_PROP => {
                let mut c = r.cur();
                while c.left() >= 6 && t.master_levels.len() < 1 << 16 {
                    let n = c.u32();
                    let level = c.u16();
                    t.master_levels.push((n, level.min(4)));
                }
            }
            rt::SLIDE_NUMBER_MC => t.meta.push((Cur::new(r.data).u32(), Meta::SlideNumber)),
            rt::DATE_TIME_MC | rt::GENERIC_DATE_MC | rt::RTF_DATE_TIME_MC => {
                t.meta.push((Cur::new(r.data).u32(), Meta::DateTime))
            }
            rt::FOOTER_MC => t.meta.push((Cur::new(r.data).u32(), Meta::Footer)),
            rt::HEADER_MC => t.meta.push((Cur::new(r.data).u32(), Meta::Header)),
            rt::INTERACTIVE_INFO => {
                pending_link = r
                    .child(rt::INTERACTIVE_INFO_ATOM)
                    .and_then(|a| a.data.get(..16))
                    .map(|b| {
                        let mut x = [0u8; 16];
                        x.copy_from_slice(b);
                        x
                    });
            }
            rt::TEXT_INTERACTIVE_INFO => {
                let mut c = r.cur();
                let (a, b) = (c.u32(), c.u32());
                if let Some(info) = pending_link.take() {
                    if r.inst == 0 {
                        t.link_info.push((a, b, info));
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// What resolving a body needs from its slide and document.
pub struct TextCtx<'a> {
    pub fonts: &'a [String],
    pub scheme: &'a [Rgb; 8],
    /// Resolved style of each level before the body's own exceptions.
    pub base: &'a [(Pf, Cf); 5],
    /// The slide's number, for slide number fields.
    pub slide_number: usize,
    pub footer: &'a str,
    pub date: &'a str,
    pub links: &'a dyn Fn(&[u8; 16]) -> Option<Link>,
    /// The media index of each picture bullet, by its index.
    pub bullet_media: &'a [Option<usize>],
}

fn rgb_of(c: TColor, scheme: &[Rgb; 8]) -> Rgb {
    match c {
        TColor::Rgb(v) => v,
        TColor::Scheme(i) => scheme[usize::from(i) & 7],
    }
}

fn font_name(fonts: &[String], i: u16) -> Option<String> {
    fonts.get(usize::from(i)).filter(|s| !s.is_empty()).cloned()
}

/// A resolved CF as run properties.
pub fn run_props(cf: &Cf, ctx: &TextCtx) -> RunProps {
    RunProps {
        size: cf.size.map(|s| u32::from(s.clamp(1, 4000)) * 100),
        bold: cf.bold,
        italic: cf.italic,
        underline: cf.underline.map(|u| if u { "sng" } else { "none" }),
        color: cf.color.map(|c| Color::rgb(rgb_of(c, ctx.scheme))),
        font: cf.font.and_then(|f| font_name(ctx.fonts, f)),
        ea_font: cf.ea_font.and_then(|f| font_name(ctx.fonts, f)),
        sym_font: cf.sym_font.and_then(|f| font_name(ctx.fonts, f)),
        baseline: cf
            .position
            .filter(|&p| p != 0)
            .map(|p| i32::from(p.clamp(-100, 100)) * 1000),
        shadow: cf.shadow.filter(|&s| s).map(|_| Shadow {
            color: Color {
                rgb: 0,
                alpha: Some(40_000),
            },
            blur: 0,
            dist: 19050,
            dir: 45.0,
        }),
        ..RunProps::default()
    }
}

fn spacing(v: i16) -> Spacing {
    if v >= 0 {
        Spacing::Pct(i32::from(v.min(13200)) * 1000)
    } else {
        // Master units: 8 per point.
        Spacing::Pts((-i32::from(v)) * 100 / 8)
    }
}

fn autonum_scheme(s: u16) -> &'static str {
    match s {
        0 => "alphaLcPeriod",
        1 => "alphaUcPeriod",
        2 => "arabicParenR",
        3 => "arabicPeriod",
        4 => "romanLcParenBoth",
        5 => "romanLcParenR",
        6 => "romanLcPeriod",
        7 => "romanUcPeriod",
        8 => "alphaLcParenBoth",
        9 => "alphaLcParenR",
        10 => "alphaUcParenBoth",
        11 => "alphaUcParenR",
        12 => "arabicParenBoth",
        13 => "arabicPlain",
        14 => "romanUcParenBoth",
        15 => "romanUcParenR",
        _ => "arabicPeriod",
    }
}

/// A resolved PF as paragraph properties, with the ruler's margins.
pub fn para_props(pf: &Pf, cf: &Cf, level: u16, ruler: Option<&Ruler>, ctx: &TextCtx) -> ParaProps {
    let lv = usize::from(level.min(4));
    let margin = ruler.and_then(|r| r.margin[lv]).or(pf.margin);
    let indent = ruler.and_then(|r| r.indent[lv]).or(pf.indent);
    let bullet = if pf.has_bullet == Some(true) {
        let color = if pf.bullet_has_color == Some(true) {
            pf.bullet_color.map(|c| Color::rgb(rgb_of(c, ctx.scheme)))
        } else {
            cf.color.map(|c| Color::rgb(rgb_of(c, ctx.scheme)))
        };
        let size = if pf.bullet_has_size == Some(true) {
            pf.bullet_size
                .filter(|&s| (25..=400).contains(&s))
                .map(|s| u32::try_from(s).unwrap_or(100) * 1000)
        } else {
            None
        };
        let font = if pf.bullet_has_font == Some(true) {
            pf.bullet_font.and_then(|f| font_name(ctx.fonts, f))
        } else {
            None
        };
        let picture = pf
            .bullet_blip
            .and_then(|b| ctx.bullet_media.get(usize::from(b)).copied().flatten());
        match pf.autonum {
            _ if picture.is_some() => Some(Bullet::Picture {
                media: picture.unwrap_or_default(),
                size,
            }),
            Some((scheme, start)) => Some(Bullet::AutoNum {
                scheme: autonum_scheme(scheme),
                start: u32::from(start.max(1)),
                font,
                color,
                size,
            }),
            None => {
                let ch = pf
                    .bullet_char
                    .and_then(|c| char::from_u32(u32::from(c)))
                    .filter(|c| !c.is_control())
                    .unwrap_or('\u{2022}');
                Some(Bullet::Char {
                    ch,
                    font,
                    color,
                    size,
                })
            }
        }
    } else {
        Some(Bullet::None)
    };
    ParaProps {
        level: level.min(4) as u8,
        align: pf.align.map(|a| match a {
            1 => "ctr",
            2 => "r",
            3 | 6 => "just",
            4 | 5 => "dist",
            _ => "l",
        }),
        margin: margin.map(|m| mu(m.into())),
        indent: match (margin, indent) {
            (Some(m), Some(i)) => Some(mu(i32::from(i) - i32::from(m))),
            (None, Some(i)) => Some(mu(i.into())),
            _ => None,
        },
        line_spacing: pf.line_spacing.map(spacing),
        space_before: pf.space_before.map(spacing),
        space_after: pf.space_after.map(spacing),
        bullet,
        tabs: ruler
            .and_then(|r| r.tabs.as_ref())
            .or(pf.tabs.as_ref())
            .map(|t| {
                t.iter()
                    .map(|&(p, k)| (mu(p.into()), tab_kind(k)))
                    .collect()
            })
            .unwrap_or_default(),
        default_tab: ruler
            .and_then(|r| r.default_tab)
            .or(pf.default_tab)
            .map(|t| mu(t.into())),
        rtl: pf.rtl == Some(true),
    }
}

/// Overlays on `levels` the formatting a master placeholder's own text
/// carries: for each level, its first paragraph's exceptions and its first
/// character's.
pub fn overlay_levels(levels: &mut [(Pf, Cf); 5], t: &RawText) {
    let mut done = [false; 5];
    let mut start = 0u32;
    let n = t.chars.len() as u32;
    loop {
        let end = (start..n)
            .find(|&i| t.chars[i as usize] == 0x0D)
            .unwrap_or(n);
        if let Some((_, (level, pf))) = run_at_pf(&t.pf_runs, start) {
            let lv = usize::from((*level).min(4));
            if !done[lv] {
                done[lv] = true;
                levels[lv].0.overlay(pf);
                if let Some(cf) = run_at(&t.cf_runs, start) {
                    levels[lv].1.overlay(cf);
                }
            }
        }
        if end >= n {
            break;
        }
        start = end + 1;
    }
}

fn run_at_pf(runs: &[(u32, u16, Pf)], at: u32) -> Option<(u32, (&u16, &Pf))> {
    let mut start = 0u32;
    for (n, l, p) in runs {
        if at < start.saturating_add(*n) {
            return Some((*n, (l, p)));
        }
        start = start.saturating_add(*n);
    }
    None
}

/// The run of `runs` (counts) covering character `at`.
fn run_at<T>(runs: &[(u32, T)], at: u32) -> Option<&T> {
    let mut start = 0u32;
    for (n, v) in runs {
        if at < start.saturating_add(*n) {
            return Some(v);
        }
        start = start.saturating_add(*n);
    }
    runs.last().map(|r| &r.1)
}

/// The body's paragraphs, every property resolved.
pub fn paragraphs(t: &RawText, ctx: &TextCtx) -> Vec<Paragraph> {
    let pf_runs: Vec<(u32, (u16, Pf))> = if t.pf_runs.is_empty() {
        t.master_levels
            .iter()
            .map(|&(n, l)| (n, (l, Pf::default())))
            .collect()
    } else {
        t.pf_runs
            .iter()
            .map(|(n, l, p)| (*n, (*l, p.clone())))
            .collect()
    };
    let cf_runs: Vec<(u32, Cf)> = t.cf_runs.clone();
    // For each character run, its sequence among those that share a PP9
    // grouping, and the grouping.
    let mut pp9_seq: Vec<(usize, u8)> = vec![];
    for (i, (_, cf)) in cf_runs.iter().enumerate() {
        let g = cf.pp9rt.unwrap_or(0);
        let k = match pp9_seq.last() {
            None => 0,
            Some(&(k, prev)) if prev == g && i > 0 => k,
            Some(&(k, _)) => k + 1,
        };
        pp9_seq.push((k, g));
    }
    let links: Vec<(u32, u32, Option<Link>)> = t
        .link_info
        .iter()
        .map(|(a, b, i)| (*a, *b, (ctx.links)(i)))
        .collect();

    let mut out = vec![];
    let n = t.chars.len() as u32;
    let mut start = 0u32;
    loop {
        // The paragraph ends at a CR or the end of the text.
        let end = (start..n)
            .find(|&i| t.chars[i as usize] == 0x0D)
            .unwrap_or(n);
        let empty = (0u16, Pf::default());
        let (level, own_pf) = run_at(&pf_runs, start).unwrap_or(&empty);
        let lv = usize::from((*level).min(4));
        let mut pf = ctx.base[lv].0.clone();
        pf.overlay(own_pf);
        // The PP9 item of the run of text this paragraph starts in. The
        // items count runs that share a grouping; one whose number does not
        // match its grouping is ignored.
        if let Some(item) = pp9_seq
            .get(run_index(&cf_runs, start))
            .and_then(|&(k, rt9)| (k % 16 == usize::from(rt9)).then(|| t.pp9.get(k)).flatten())
        {
            pf.overlay9(item);
        }
        let mut first_cf = ctx.base[lv].1.clone();
        if let Some(c) = run_at(&cf_runs, start) {
            first_cf.overlay(c);
        }
        let props = para_props(&pf, &first_cf, *level, t.ruler.as_ref(), ctx);
        let mut runs: Vec<Run> = vec![];
        let mut i = start;
        while i < end {
            let mut cf = ctx.base[lv].1.clone();
            if let Some(c) = run_at(&cf_runs, i) {
                cf.overlay(c);
            }
            let mut rp = run_props(&cf, ctx);
            rp.link = links
                .iter()
                .find(|(a, b, _)| i >= *a && i < *b)
                .and_then(|l| l.2.clone());
            if rp.link.is_some() {
                rp.underline = Some("sng");
            }
            // Up to the next format change, special character or link edge.
            let mut j = i;
            let mut s = String::new();
            let mut kind = None;
            while j < end {
                let ch = t.chars[j as usize];
                if j > i
                    && (run_index(&cf_runs, j) != run_index(&cf_runs, i)
                        || link_index(&links, j) != link_index(&links, i))
                {
                    break;
                }
                if let Some(m) = t.meta.iter().find(|m| m.0 == j) {
                    if j > i {
                        break;
                    }
                    kind = Some(match m.1 {
                        Meta::SlideNumber => {
                            RunKind::Field("slidenum", ctx.slide_number.to_string())
                        }
                        Meta::DateTime => RunKind::Field("datetime", ctx.date.to_string()),
                        Meta::Footer => RunKind::Text(ctx.footer.to_string()),
                        Meta::Header => RunKind::Text(String::new()),
                    });
                    j += 1;
                    break;
                }
                if ch == 0x0B {
                    if j > i {
                        break;
                    }
                    kind = Some(RunKind::Break);
                    j += 1;
                    break;
                }
                s.push_str(&decode_unit(&t.chars, j as usize));
                if (0xD800..0xDC00).contains(&ch) && j + 1 < end {
                    j += 1;
                }
                j += 1;
            }
            let kind = kind.unwrap_or(RunKind::Text(s));
            runs.push(Run { kind, props: rp });
            i = j.max(i + 1);
        }
        let mut end_cf = ctx.base[lv].1.clone();
        if let Some(c) = run_at(&cf_runs, end) {
            end_cf.overlay(c);
        }
        out.push(Paragraph {
            props,
            runs,
            end: run_props(&end_cf, ctx),
        });
        if end >= n || out.len() >= 1 << 16 {
            break;
        }
        start = end + 1;
    }
    out
}

fn run_index<T>(runs: &[(u32, T)], at: u32) -> usize {
    let mut start = 0u32;
    for (k, (n, _)) in runs.iter().enumerate() {
        if at < start.saturating_add(*n) {
            return k;
        }
        start = start.saturating_add(*n);
    }
    runs.len()
}

fn link_index(links: &[(u32, u32, Option<Link>)], at: u32) -> Option<usize> {
    links.iter().position(|(a, b, _)| at >= *a && at < *b)
}

/// Character `i`, a surrogate pair joined; tabs kept, other controls
/// dropped.
fn decode_unit(chars: &[u16], i: usize) -> String {
    let c = chars[i];
    if (0xD800..0xDC00).contains(&c) {
        if let Some(&lo) = chars.get(i + 1) {
            return String::from_utf16_lossy(&[c, lo]);
        }
    }
    match c {
        0x09 => "\t".into(),
        0..=0x1F => String::new(),
        _ => String::from_utf16_lossy(&[c]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn le32(v: u32) -> [u8; 4] {
        v.to_le_bytes()
    }

    #[test]
    fn cf_fields_in_order() {
        // bold+italic valid, typeface, size, color (scheme 3).
        let mut d = le32(1 | 2 | 1 << 16 | 1 << 17 | 1 << 18).to_vec();
        d.extend([0x01, 0x00]); // style: bold on, italic off
        d.extend(2u16.to_le_bytes()); // font 2
        d.extend(24u16.to_le_bytes()); // 24 pt
        d.extend([0, 0, 0, 3]);
        let cf = read_cf(&mut Cur::new(&d));
        assert_eq!(cf.bold, Some(true));
        assert_eq!(cf.italic, Some(false));
        assert_eq!(cf.font, Some(2));
        assert_eq!(cf.size, Some(24));
        assert_eq!(cf.color, Some(TColor::Scheme(3)));
    }

    #[test]
    fn pf_fields_in_order() {
        // hasBullet, bulletChar, align, leftMargin, indent.
        let mut d = le32(1 | 1 << 7 | 1 << 11 | 1 << 8 | 1 << 10).to_vec();
        d.extend(1u16.to_le_bytes()); // bullet flags: has bullet
        d.extend(0x2013u16.to_le_bytes());
        d.extend(1u16.to_le_bytes()); // centre
        d.extend(576i16.to_le_bytes()); // margin 1 inch
        d.extend(288i16.to_le_bytes()); // indent half an inch
        let pf = read_pf(&mut Cur::new(&d));
        assert_eq!(pf.has_bullet, Some(true));
        assert_eq!(pf.bullet_char, Some(0x2013));
        assert_eq!(pf.align, Some(1));
        assert_eq!((pf.margin, pf.indent), (Some(576), Some(288)));
        let fonts = vec!["Arial".to_string()];
        let scheme = [0u32; 8];
        let base = <[(Pf, Cf); 5]>::default();
        let ctx = TextCtx {
            fonts: &fonts,
            scheme: &scheme,
            base: &base,
            slide_number: 1,
            footer: "",
            date: "",
            links: &|_| None,
            bullet_media: &[],
        };
        let p = para_props(&pf, &Cf::default(), 0, None, &ctx);
        assert_eq!(p.margin, Some(914_400));
        assert_eq!(p.indent, Some(-457_200));
        assert_eq!(p.align, Some("ctr"));
        assert!(matches!(
            p.bullet,
            Some(Bullet::Char { ch: '\u{2013}', .. })
        ));
    }

    #[test]
    fn pp9_items_give_picture_bullets_and_numbering() {
        // Two paragraphs, each in a run of its own grouping: the first takes
        // the first item (picture bullet 0), the second the second (a
        // numbering scheme).
        let t = RawText {
            chars: "A\rB".encode_utf16().collect(),
            cf_runs: vec![
                (
                    2,
                    Cf {
                        pp9rt: Some(0),
                        ..Cf::default()
                    },
                ),
                (
                    1,
                    Cf {
                        pp9rt: Some(1),
                        ..Cf::default()
                    },
                ),
            ],
            pp9: vec![
                Pf9 {
                    blip: Some(0),
                    autonum: None,
                },
                Pf9 {
                    blip: None,
                    autonum: Some((3, 5)),
                },
            ],
            ..RawText::default()
        };
        let fonts = vec![];
        let scheme = [0u32; 8];
        let mut base = <[(Pf, Cf); 5]>::default();
        base[0].0.has_bullet = Some(true);
        let ctx = TextCtx {
            fonts: &fonts,
            scheme: &scheme,
            base: &base,
            slide_number: 1,
            footer: "",
            date: "",
            links: &|_| None,
            bullet_media: &[Some(9)],
        };
        let p = paragraphs(&t, &ctx);
        assert!(matches!(
            p[0].props.bullet,
            Some(Bullet::Picture { media: 9, .. })
        ));
        assert!(matches!(
            p[1].props.bullet,
            Some(Bullet::AutoNum { start: 5, .. })
        ));
        // A picture bullet that could not be decoded is an ordinary bullet.
        let ctx = TextCtx {
            bullet_media: &[None],
            ..ctx
        };
        let p = paragraphs(&t, &ctx);
        assert!(matches!(p[0].props.bullet, Some(Bullet::Char { .. })));
    }

    #[test]
    fn paragraphs_runs_breaks_and_fields() {
        let chars: Vec<u16> = "Ab\u{b}c\r*".encode_utf16().collect();
        let t = RawText {
            chars,
            cf_runs: vec![
                (
                    1,
                    Cf {
                        bold: Some(true),
                        ..Cf::default()
                    },
                ),
                (6, Cf::default()),
            ],
            meta: vec![(5, Meta::SlideNumber)],
            ..RawText::default()
        };
        let fonts = vec![];
        let scheme = [0u32; 8];
        let base = <[(Pf, Cf); 5]>::default();
        let ctx = TextCtx {
            fonts: &fonts,
            scheme: &scheme,
            base: &base,
            slide_number: 7,
            footer: "",
            date: "",
            links: &|_| None,
            bullet_media: &[],
        };
        let p = paragraphs(&t, &ctx);
        assert_eq!(p.len(), 2);
        let kinds: Vec<_> = p[0].runs.iter().map(|r| r.kind.clone()).collect();
        assert_eq!(
            kinds,
            vec![
                RunKind::Text("A".into()),
                RunKind::Text("b".into()),
                RunKind::Break,
                RunKind::Text("c".into())
            ]
        );
        assert_eq!(p[0].runs[0].props.bold, Some(true));
        assert_eq!(p[1].runs[0].kind, RunKind::Field("slidenum", "7".into()));
    }
}
