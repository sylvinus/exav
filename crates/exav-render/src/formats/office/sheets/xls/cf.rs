//! Conditional formats (CFHEADER and CF; CONDFMT12 and CF12; CFEX) and
//! data validation (DV) of a sheet ([MS-XLS] 2.4.42 to 2.4.57, 2.4.105).

use super::formula::{self, Ctx};
use super::stream::Rec;
use super::{BORDER_STYLES, Globals, PATTERNS, SplitReader};
use crate::formats::office::common::bytes::Cur;
use crate::formats::office::sheets::model::*;

/// A CFHEADER or CONDFMT12 and the rules read after it.
pub(crate) struct Pending {
    id: u16,
    ranges: Vec<Range>,
    /// CF12 rules expected, or CF.
    twelve: bool,
    rules: Vec<(CfRule, u16)>,
}

fn ranges(c: &mut Cur) -> Vec<Range> {
    let n = c.u16() as usize;
    let mut out = vec![];
    for _ in 0..n.min(1026) {
        let r1 = c.u16() as u32;
        let r2 = c.u16() as u32;
        let c1 = c.u16() as u32;
        let c2 = c.u16() as u32;
        if c.short {
            break;
        }
        if r2 >= r1 && c2 >= c1 {
            out.push(Range { r1, c1, r2, c2 });
        }
    }
    out
}

/// CFHEADER (0x01B0) or CONDFMT12 (0x0879), whose 12-byte future record
/// header comes first.
pub(crate) fn header(d: &[u8], twelve: bool) -> Option<Pending> {
    let mut c = Cur::new(d);
    if twelve {
        c.skip(12);
    }
    c.u16();
    let id = c.u16() >> 1;
    c.skip(8);
    let ranges = ranges(&mut c);
    (!ranges.is_empty()).then_some(Pending {
        id,
        ranges,
        twelve,
        rules: vec![],
    })
}

/// The colours of the default Office theme, for theme colour references.
fn theme(i: u32, tint: f64) -> Option<Rgb> {
    const T: [u32; 12] = [
        0xFFFFFF, 0x000000, 0xEEECE1, 0x1F497D, 0x4F81BD, 0xC0504D, 0x9BBB59, 0x8064A2, 0x4BACC6,
        0xF79646, 0x0000FF, 0x800080,
    ];
    let c = *T.get(i as usize)?;
    if tint == 0.0 {
        return Some(c);
    }
    let ch = |s: u32| -> u32 {
        let v = f64::from((c >> s) & 0xFF);
        let v = if tint < 0.0 {
            v * (1.0 + tint)
        } else {
            v + (255.0 - v) * tint
        };
        (v.round().clamp(0.0, 255.0) as u32) << s
    };
    Some(ch(16) | ch(8) | ch(0))
}

/// A CFColor (16 bytes) or FullColorExt's colour.
fn full_color(g: &Globals, kind: u32, value: u32, tint: f64) -> Option<Rgb> {
    match kind {
        1 => g.color(value as u16),
        2 => Some((value & 0xFF) << 16 | (value & 0xFF00) | (value >> 16) & 0xFF),
        3 => theme(value, tint),
        _ => None,
    }
}

fn cf_color(g: &Globals, c: &mut Cur) -> Option<Rgb> {
    let kind = c.u32();
    let value = c.u32();
    let tint = c.f64();
    full_color(g, kind, value, tint)
}

/// DXFN ([MS-XLS] 2.5.95).
fn read_dxfn(g: &Globals, c: &mut Cur) -> Dxf {
    let f1 = c.u32();
    let f2 = c.u16();
    let mut d = Dxf::default();
    if f1 & (1 << 25) != 0 {
        if f2 & 1 != 0 {
            let cb = c.u16() as usize;
            let mut c2 = Cur::at(c.d, c.p);
            let n = c2.u16() as usize;
            let fl = c2.u8();
            if f1 & (1 << 19) == 0 {
                d.numfmt = Some(formula::read_chars(&mut c2, n, fl & 1 != 0));
            }
            c.skip(cb.saturating_sub(2));
        } else {
            c.u8();
            let id = u16::from(c.u8());
            if f1 & (1 << 19) == 0 {
                d.numfmt = Some(g.numfmt(id));
            }
        }
    }
    if f1 & (1 << 26) != 0 {
        let start = c.p;
        c.skip(64);
        let _height = c.i32();
        let ts = c.u32();
        let bls = c.u16();
        let _sss = c.u16();
        let uls = c.u8();
        c.skip(3);
        let icv = c.i32();
        c.u32();
        let ts_ninch = c.u32();
        let _sss_ninch = c.u32();
        let uls_ninch = c.u32();
        let bls_ninch = c.u32();
        c.p = start + 118;
        if icv != -1 && icv != 0x7FFF {
            d.font_color = g.color(icv as u16);
        }
        if bls_ninch == 0 && bls != 0xFFFF {
            d.bold = Some(bls >= 600);
        }
        if ts_ninch & 2 == 0 {
            d.italic = Some(ts & 2 != 0);
        }
        if ts_ninch & 0x80 == 0 {
            d.strike = Some(ts & 0x80 != 0);
        }
        if uls_ninch == 0 && uls != 0xFF {
            d.underline = Some(match uls {
                1 => "single",
                2 => "double",
                0x21 => "singleAccounting",
                0x22 => "doubleAccounting",
                _ => "none",
            });
        }
    }
    if f1 & (1 << 27) != 0 {
        c.skip(8);
    }
    if f1 & (1 << 28) != 0 {
        let b1 = c.u32();
        let b2 = c.u32();
        let e = |st: u32, col: u32, ninch: bool| -> Edge {
            if ninch {
                return Edge::default();
            }
            let s = BORDER_STYLES.get(st as usize).copied().flatten();
            Edge {
                style: s,
                color: if s.is_some() {
                    g.color(col as u16).or(Some(0))
                } else {
                    None
                },
            }
        };
        d.border = Some(Border {
            left: e(b1 & 15, (b1 >> 16) & 0x7F, f1 & (1 << 10) != 0),
            right: e((b1 >> 4) & 15, (b1 >> 23) & 0x7F, f1 & (1 << 11) != 0),
            top: e((b1 >> 8) & 15, b2 & 0x7F, f1 & (1 << 12) != 0),
            bottom: e((b1 >> 12) & 15, (b2 >> 7) & 0x7F, f1 & (1 << 13) != 0),
            ..Default::default()
        });
    }
    if f1 & (1 << 29) != 0 {
        let p = c.u32();
        let fls = ((p >> 10) & 0x3F) as usize;
        let fg = ((p >> 16) & 0x7F) as u16;
        let bg = ((p >> 23) & 0x7F) as u16;
        let pattern = if f1 & (1 << 16) != 0 {
            "solid"
        } else {
            PATTERNS.get(fls).copied().unwrap_or("none")
        };
        let fg = if f1 & (1 << 17) == 0 {
            g.color(fg)
        } else {
            None
        };
        let bg = if f1 & (1 << 18) == 0 {
            g.color(bg)
        } else {
            None
        };
        if pattern == "solid" {
            // A conditional format's solid fill is its background colour.
            if let Some(c) = bg.or(fg) {
                d.fill = Some(Fill::solid(c));
            }
        } else if pattern != "none" {
            d.fill = Some(Fill { pattern, fg, bg });
        }
    }
    if f1 & (1 << 30) != 0 {
        c.skip(2);
    }
    d
}

/// XFExtNoFRT after a DXFN in a DXFN12: full colours over the indexed ones.
fn read_xfext(g: &Globals, c: &mut Cur, end: usize, d: &mut Dxf) {
    c.skip(6);
    let n = c.u16();
    for _ in 0..n.min(64) {
        if c.p + 4 > end {
            break;
        }
        let start = c.p;
        let kind = c.u16();
        let cb = c.u16() as usize;
        if cb < 4 {
            break;
        }
        let xtype = u32::from(c.u16());
        let tint = f64::from(c.i16()) / 32767.0;
        let value = c.u32();
        let col = full_color(g, xtype, value, tint);
        match (kind, col) {
            // A solid fill shows its background colour (read_dxfn), kept in `fg`.
            (4, Some(rgb)) => {
                if let Some(f) = d.fill.as_mut().filter(|f| f.pattern != "solid") {
                    f.fg = Some(rgb);
                }
            }
            (5, Some(rgb)) => {
                if let Some(f) = d.fill.as_mut() {
                    if f.pattern == "solid" {
                        f.fg = Some(rgb);
                    } else {
                        f.bg = Some(rgb);
                    }
                }
            }
            (13, Some(rgb)) => d.font_color = Some(rgb),
            (7..=10, Some(rgb)) => {
                if let Some(b) = d.border.as_mut() {
                    let e = match kind {
                        7 => &mut b.top,
                        8 => &mut b.bottom,
                        9 => &mut b.left,
                        _ => &mut b.right,
                    };
                    if e.style.is_some() {
                        e.color = Some(rgb);
                    }
                }
            }
            _ => {}
        }
        c.p = start + cb;
    }
}

/// DXFN12: a DXFN and its extension, or nothing.
fn read_dxfn12(g: &Globals, c: &mut Cur) -> Option<Dxf> {
    let cb = c.u32() as usize;
    if cb == 0 {
        c.skip(2);
        return None;
    }
    let end = c.p.saturating_add(cb).min(c.d.len());
    let mut d = read_dxfn(g, c);
    if c.p + 8 <= end {
        read_xfext(g, c, end, &mut d);
    }
    c.p = end;
    Some(d)
}

fn operator(cp: u8) -> Option<&'static str> {
    Some(match cp {
        1 => "between",
        2 => "notBetween",
        3 => "equal",
        4 => "notEqual",
        5 => "greaterThan",
        6 => "lessThan",
        7 => "greaterThanOrEqual",
        8 => "lessThanOrEqual",
        _ => return None,
    })
}

fn cfvo(ctx: &Ctx, c: &mut Cur, anchor: (u32, u32)) -> Cfvo {
    let t = c.u8();
    let cce = c.u16() as usize;
    let rgce = c.bytes(cce).to_vec();
    let num = if cce == 0 && !matches!(t, 2 | 3) {
        Some(c.f64())
    } else {
        None
    };
    let kind = match t {
        2 => "min",
        3 => "max",
        4 => "percent",
        5 => "percentile",
        7 => "formula",
        _ => "num",
    };
    let val = if cce > 0 {
        formula::decode_relative(ctx, &rgce, anchor.0, anchor.1)
            .ok()
            .map(|d| d.text)
    } else {
        num.map(crate::formats::office::sheets::numtext::shortest)
    };
    let kind = if kind == "num" && cce > 0 {
        "formula"
    } else {
        kind
    };
    Cfvo { kind, val }
}

const ICON_SETS: [&str; 17] = [
    "3Arrows",
    "3ArrowsGray",
    "3Flags",
    "3TrafficLights1",
    "3TrafficLights2",
    "3Signs",
    "3Symbols",
    "3Symbols2",
    "4Arrows",
    "4ArrowsGray",
    "4RedToBlack",
    "4Rating",
    "4TrafficLights",
    "5Arrows",
    "5ArrowsGray",
    "5Rating",
    "5Quarters",
];

/// A CF, CF12 or CFEX record, added to the last pending header.
pub(crate) fn rule(g: &Globals, ctx: &Ctx, r: &Rec, cfs: &mut [Pending]) {
    if r.id == 0x087B {
        extend(g, &r.data, cfs);
        return;
    }
    let Some(p) = cfs.last_mut() else { return };
    let anchor = p
        .ranges
        .iter()
        .map(|r| (r.r1, r.c1))
        .min()
        .unwrap_or((0, 0));
    let mut c = Cur::new(&r.data);
    let twelve = r.id == 0x087A;
    if twelve {
        c.skip(12);
    }
    let ct = c.u8();
    let cp = c.u8();
    let cce1 = c.u16() as usize;
    let cce2 = c.u16() as usize;
    let dxf = if twelve {
        read_dxfn12(g, &mut c)
    } else {
        Some(read_dxfn(g, &mut c))
    };
    let r1 = c.bytes(cce1).to_vec();
    let r2 = c.bytes(cce2).to_vec();
    let dec = |r: &[u8]| -> Option<String> {
        if r.is_empty() {
            return None;
        }
        formula::decode_relative(ctx, r, anchor.0, anchor.1)
            .ok()
            .map(|d| d.text)
    };
    let (mut stop, mut priority, mut template, mut params) = (false, 0u16, 0u16, [0u8; 16]);
    if twelve {
        let n = c.u16() as usize;
        c.skip(n);
        let flags = c.u8();
        stop = flags & 2 != 0;
        priority = c.u16();
        template = c.u16();
        let cb = c.u8() as usize;
        let b = c.bytes(cb.min(16));
        params[..b.len()].copy_from_slice(b);
        c.skip(cb.saturating_sub(16));
    }
    let kind = match ct {
        1 => {
            let Some(op) = operator(cp) else { return };
            let Some(f1) = dec(&r1) else { return };
            let mut formulas = vec![f1];
            if matches!(cp, 1 | 2) {
                formulas.extend(dec(&r2));
            }
            CfKind::CellIs {
                operator: op,
                formulas,
            }
        }
        2 => {
            let Some(f) = dec(&r1) else { return };
            template_kind(template, &params, f, anchor)
        }
        3 => {
            c.skip(3);
            let n = c.u8() as usize;
            let m = c.u8() as usize;
            c.u8();
            let mut cfvos = vec![];
            for _ in 0..n.min(3) {
                cfvos.push(cfvo(ctx, &mut c, anchor));
                c.f64();
            }
            let mut colors = vec![];
            for _ in 0..m.min(3) {
                c.f64();
                colors.push(cf_color(g, &mut c).unwrap_or(0));
            }
            if cfvos.len() < 2 || cfvos.len() != colors.len() {
                return;
            }
            CfKind::ColorScale { cfvos, colors }
        }
        4 => {
            c.skip(3);
            c.u8();
            c.skip(2);
            let color = cf_color(g, &mut c).unwrap_or(0x638EC6);
            let min = cfvo(ctx, &mut c, anchor);
            let max = cfvo(ctx, &mut c, anchor);
            CfKind::DataBar { min, max, color }
        }
        5 => {
            c.skip(3);
            let flags = c.u8();
            let n = c.u16();
            let mut attrs = vec![("rank", n.to_string())];
            if flags & 1 == 0 {
                attrs.push(("bottom", "1".into()));
            }
            if flags & 2 != 0 {
                attrs.push(("percent", "1".into()));
            }
            CfKind::Other {
                kind: "top10",
                attrs,
                formulas: vec![],
            }
        }
        6 => {
            c.skip(3);
            let n = c.u8() as usize;
            let set = c.u8() as usize;
            let flags = c.u8();
            let mut cfvos = vec![];
            for _ in 0..n.min(5) {
                cfvos.push(cfvo(ctx, &mut c, anchor));
                c.u8();
                c.u32();
            }
            let Some(&name) = ICON_SETS.get(set) else {
                return;
            };
            CfKind::IconSet {
                set: name.to_string(),
                cfvos,
                reverse: flags & 4 != 0,
                show_value: flags & 1 == 0,
            }
        }
        _ => return,
    };
    if c.short && !twelve {
        return;
    }
    let dxf = if matches!(
        kind,
        CfKind::ColorScale { .. } | CfKind::DataBar { .. } | CfKind::IconSet { .. }
    ) {
        None
    } else {
        dxf
    };
    if p.rules.len() < 1024 {
        p.rules.push((
            CfRule {
                kind,
                dxf,
                stop,
                priority: u32::from(priority),
            },
            priority,
        ));
    }
}

/// An expression rule as the template it was made from, where XLSX has a
/// rule type for it; the formula stays, as Excel writes it.
fn template_kind(template: u16, params: &[u8; 16], f: String, anchor: (u32, u32)) -> CfKind {
    let _ = anchor;
    let period = match template {
        0x0F => Some("today"),
        0x10 => Some("tomorrow"),
        0x11 => Some("yesterday"),
        0x12 => Some("last7Days"),
        0x13 => Some("lastMonth"),
        0x14 => Some("nextMonth"),
        0x15 => Some("thisWeek"),
        0x16 => Some("nextWeek"),
        0x17 => Some("lastWeek"),
        0x18 => Some("thisMonth"),
        _ => None,
    };
    if let Some(p) = period {
        return CfKind::Other {
            kind: "timePeriod",
            attrs: vec![("timePeriod", p.into())],
            formulas: vec![f],
        };
    }
    match template {
        0x09 => CfKind::Other {
            kind: "containsBlanks",
            attrs: vec![],
            formulas: vec![f],
        },
        0x0A => CfKind::Other {
            kind: "notContainsBlanks",
            attrs: vec![],
            formulas: vec![f],
        },
        0x0B => CfKind::Other {
            kind: "containsErrors",
            attrs: vec![],
            formulas: vec![f],
        },
        0x0C => CfKind::Other {
            kind: "notContainsErrors",
            attrs: vec![],
            formulas: vec![f],
        },
        0x08 => {
            let (kind, op) = match u16::from_le_bytes([params[0], params[1]]) {
                1 => ("notContainsText", "notContains"),
                2 => ("beginsWith", "beginsWith"),
                3 => ("endsWith", "endsWith"),
                _ => ("containsText", "containsText"),
            };
            CfKind::Other {
                kind,
                attrs: vec![("operator", op.into())],
                formulas: vec![f],
            }
        }
        _ => CfKind::Expression { formula: f },
    }
}

/// CFEX: priority, stop flag and full colours of a CF rule.
fn extend(g: &Globals, d: &[u8], cfs: &mut [Pending]) {
    let mut c = Cur::new(d);
    c.skip(12);
    let is12 = c.u32() != 0;
    let id = c.u16();
    if is12 {
        return;
    }
    let icf = c.u16() as usize;
    let _cp = c.u8();
    let _template = c.u8();
    let priority = c.u16();
    let flags = c.u8();
    c.u8();
    let has_dxf = c.u8() != 0;
    let dxf = if has_dxf {
        read_dxfn12(g, &mut c)
    } else {
        None
    };
    let Some(p) = cfs.iter_mut().rev().find(|p| p.id == id && !p.twelve) else {
        return;
    };
    if let Some((rule, prio)) = p.rules.get_mut(icf) {
        rule.stop = flags & 2 != 0;
        rule.priority = u32::from(priority);
        *prio = priority;
        if let (Some(new), Some(old)) = (dxf, rule.dxf.as_mut()) {
            if new.font_color.is_some() {
                old.font_color = new.font_color;
            }
            if let (Some(nf), Some(of)) = (new.fill, old.fill.as_mut()) {
                of.fg = nf.fg.or(of.fg);
                of.bg = nf.bg.or(of.bg);
            }
        }
    }
}

pub(crate) fn finish(cfs: Vec<Pending>) -> Vec<CondFormat> {
    cfs.into_iter()
        .filter(|p| !p.rules.is_empty())
        .map(|p| CondFormat {
            ranges: p.ranges,
            rules: p.rules.into_iter().map(|r| r.0).collect(),
        })
        .collect()
}

/// DV ([MS-XLS] 2.4.105).
pub(crate) fn validation(ctx: &Ctx, d: &[u8], breaks: &[usize]) -> Option<Validation> {
    let mut c = Cur::new(d);
    let flags = c.u32();
    let mut strs: Vec<String> = Vec::with_capacity(4);
    for _ in 0..4 {
        let mut sr = SplitReader { d, breaks, p: c.p };
        let n = sr.u16() as usize;
        let f = sr.u8();
        let s = sr.chars(n, f & 1 != 0);
        c.p = sr.p.min(d.len());
        strs.push(if s == "\0" { String::new() } else { s });
    }
    let cce1 = c.u16() as usize;
    c.u16();
    let f1 = c.bytes(cce1).to_vec();
    let cce2 = c.u16() as usize;
    c.u16();
    let f2 = c.bytes(cce2).to_vec();
    let ranges = ranges(&mut c);
    if ranges.is_empty() {
        return None;
    }
    let anchor = ranges.iter().map(|r| (r.r1, r.c1)).min().unwrap_or((0, 0));
    let kind = match flags & 15 {
        1 => "whole",
        2 => "decimal",
        3 => "list",
        4 => "date",
        5 => "time",
        6 => "textLength",
        7 => "custom",
        _ => "none",
    };
    let dec = |r: &[u8]| -> Option<String> {
        if r.is_empty() {
            return None;
        }
        formula::decode_relative(ctx, r, anchor.0, anchor.1)
            .ok()
            .map(|d| d.text)
    };
    let mut formula1 = dec(&f1);
    if kind == "list" && flags & 0x80 != 0 {
        // An explicit list: a string with its items separated by NUL.
        formula1 = formula1.map(|f| f.replace('\0', ","));
    }
    let operator = match (flags >> 20) & 15 {
        1 => "notBetween",
        2 => "equal",
        3 => "notEqual",
        4 => "greaterThan",
        5 => "lessThan",
        6 => "greaterThanOrEqual",
        7 => "lessThanOrEqual",
        _ => "between",
    };
    let opt = |s: &String| if s.is_empty() { None } else { Some(s.clone()) };
    Some(Validation {
        ranges,
        kind,
        operator,
        formula1,
        formula2: dec(&f2),
        allow_blank: flags & 0x100 != 0,
        hide_dropdown: flags & 0x200 != 0,
        show_input: flags & 0x40000 != 0,
        show_error: flags & 0x80000 != 0,
        error_style: match (flags >> 4) & 7 {
            1 => "warning",
            2 => "information",
            _ => "stop",
        },
        prompt_title: opt(&strs[0]),
        error_title: opt(&strs[1]),
        prompt: opt(&strs[2]),
        error: opt(&strs[3]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_solid_fill_shows_its_background_colour() {
        // DXFN with a pattern block: solid, foreground 60 (#993300),
        // background 10 (red).
        let mut d = (1u32 << 29).to_le_bytes().to_vec();
        d.extend(0u16.to_le_bytes());
        d.extend(((1u32 << 10) | (60 << 16) | (10 << 23)).to_le_bytes());
        let g = Globals::new(8);
        let dxf = read_dxfn(&g, &mut Cur::new(&d));
        assert_eq!(dxf.fill, Some(Fill::solid(0xFF0000)));
    }
}
