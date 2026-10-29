//! XLS reader: Excel 2.x to 2003 (BIFF2 to BIFF8), worksheets and
//! workbooks, the BIFF4 workbook kind included. BIFF8 follows [MS-XLS];
//! BIFF2 to BIFF5 follow OpenOffice.org's documentation of the Excel file
//! format.

mod cf;
mod chart;
mod escher;
mod sheet;
pub(crate) mod stream;
#[cfg(test)]
mod tests;

use crate::formats::office::common::bytes::{Cur, u16_at, u32_at};
use crate::formats::office::sheets::error::{Error, Result};
use crate::formats::office::sheets::limits::Budget;
use crate::formats::office::sheets::model::*;
use exav_unpack::biff::Book;
pub(crate) use exav_unpack::biff::formula;
use exav_unpack::offcrypto::{DEFAULT_PASSWORDS, Decryptor, Refused};
use std::collections::HashMap;
use stream::Rec;

const DEFAULT_PALETTE: [u32; 56] = [
    0x000000, 0xFFFFFF, 0xFF0000, 0x00FF00, 0x0000FF, 0xFFFF00, 0xFF00FF, 0x00FFFF, 0x800000,
    0x008000, 0x000080, 0x808000, 0x800080, 0x008080, 0xC0C0C0, 0x808080, 0x9999FF, 0x993366,
    0xFFFFCC, 0xCCFFFF, 0x660066, 0xFF8080, 0x0066CC, 0xCCCCFF, 0x000080, 0xFF00FF, 0xFFFF00,
    0x00FFFF, 0x800080, 0x800000, 0x008080, 0x0000FF, 0x00CCFF, 0xCCFFFF, 0xCCFFCC, 0xFFFF99,
    0x99CCFF, 0xFF99CC, 0xCC99FF, 0xFFCC99, 0x3366FF, 0x33CCCC, 0x99CC00, 0xFFCC00, 0xFF9900,
    0xFF6600, 0x666699, 0x969696, 0x003366, 0x339966, 0x003300, 0x333300, 0x993300, 0x993366,
    0x333399, 0x333333,
];
const BIFF34_PALETTE: [u32; 8] = [
    0x800000, 0x008000, 0x000080, 0x808000, 0x800080, 0x008080, 0xC0C0C0, 0x808080,
];
const EGA: [u32; 8] = [
    0x000000, 0xFFFFFF, 0xFF0000, 0x00FF00, 0x0000FF, 0xFFFF00, 0xFF00FF, 0x00FFFF,
];

pub(crate) const BUILTIN_FMT: &[(u16, &str)] = &[
    (0, "General"),
    (1, "0"),
    (2, "0.00"),
    (3, "#,##0"),
    (4, "#,##0.00"),
    (5, "\"$\"#,##0_);\\(\"$\"#,##0\\)"),
    (6, "\"$\"#,##0_);[Red]\\(\"$\"#,##0\\)"),
    (7, "\"$\"#,##0.00_);\\(\"$\"#,##0.00\\)"),
    (8, "\"$\"#,##0.00_);[Red]\\(\"$\"#,##0.00\\)"),
    (9, "0%"),
    (10, "0.00%"),
    (11, "0.00E+00"),
    (12, "# ?/?"),
    (13, "# ??/??"),
    (14, "m/d/yyyy"),
    (15, "d-mmm-yy"),
    (16, "d-mmm"),
    (17, "mmm-yy"),
    (18, "h:mm AM/PM"),
    (19, "h:mm:ss AM/PM"),
    (20, "h:mm"),
    (21, "h:mm:ss"),
    (22, "m/d/yyyy h:mm"),
    (37, "#,##0_);\\(#,##0\\)"),
    (38, "#,##0_);[Red]\\(#,##0\\)"),
    (39, "#,##0.00_);\\(#,##0.00\\)"),
    (40, "#,##0.00_);[Red]\\(#,##0.00\\)"),
    (41, "_(* #,##0_);_(* \\(#,##0\\);_(* \"-\"_);_(@_)"),
    (
        42,
        "_(\"$\"* #,##0_);_(\"$\"* \\(#,##0\\);_(\"$\"* \"-\"_);_(@_)",
    ),
    (43, "_(* #,##0.00_);_(* \\(#,##0.00\\);_(* \"-\"??_);_(@_)"),
    (
        44,
        "_(\"$\"* #,##0.00_);_(\"$\"* \\(#,##0.00\\);_(\"$\"* \"-\"??_);_(@_)",
    ),
    (45, "mm:ss"),
    (46, "[h]:mm:ss"),
    (47, "mm:ss.0"),
    (48, "##0.0E+0"),
    (49, "@"),
];

pub(crate) const BORDER_STYLES: [Option<&str>; 14] = [
    None,
    Some("thin"),
    Some("medium"),
    Some("dashed"),
    Some("dotted"),
    Some("thick"),
    Some("double"),
    Some("hair"),
    Some("mediumDashed"),
    Some("dashDot"),
    Some("mediumDashDot"),
    Some("dashDotDot"),
    Some("mediumDashDotDot"),
    Some("slantDashDot"),
];
pub(crate) const PATTERNS: [&str; 19] = [
    "none",
    "solid",
    "mediumGray",
    "darkGray",
    "lightGray",
    "darkHorizontal",
    "darkVertical",
    "darkDown",
    "darkUp",
    "darkGrid",
    "darkTrellis",
    "lightHorizontal",
    "lightVertical",
    "lightDown",
    "lightUp",
    "lightGrid",
    "lightTrellis",
    "gray125",
    "gray0625",
];
const HALIGN: [Option<&str>; 8] = [
    None,
    Some("left"),
    Some("center"),
    Some("right"),
    Some("fill"),
    Some("justify"),
    Some("centerContinuous"),
    Some("distributed"),
];
const VALIGN: [Option<&str>; 5] = [
    Some("top"),
    Some("center"),
    None,
    Some("justify"),
    Some("distributed"),
];

#[derive(Clone, Default)]
pub(crate) struct FontRec {
    height: u16,
    italic: bool,
    strike: bool,
    outline: bool,
    shadow: bool,
    color: u16,
    bold: bool,
    script: u16,
    underline: u8,
    family: u8,
    charset: u8,
    name: String,
}

#[derive(Clone, Default)]
pub(crate) struct XfRec {
    font: u16,
    fmt: u16,
    locked: bool,
    hidden: bool,
    halign: u8,
    valign: u8,
    wrap: bool,
    rot: u8,
    indent: u8,
    shrink: bool,
    reading: u8,
    /// left, right, top, bottom.
    border_style: [u8; 4],
    border_color: [u16; 4],
    diag_style: u8,
    diag_color: u16,
    diag_up: bool,
    diag_down: bool,
    pattern: u8,
    fore: u16,
    back: u16,
    is_style: bool,
    parent: u16,
    /// Attribute groups a cell XF sets itself (number format, font,
    /// alignment, border, fill, protection as bits 0 to 5); it takes the
    /// others from its parent style.
    used: u8,
}

pub(crate) struct Globals {
    /// What formulas need: version, code page, sheets, names, references.
    pub book: Book,
    date1904: bool,
    fonts: Vec<FontRec>,
    formats: HashMap<u16, String>,
    fmt_index: u16,
    xfs: Vec<XfRec>,
    palette: Vec<u32>,
    sst: Vec<Value>,
    blips: Vec<escher::Blip>,
    xf_style: HashMap<u32, u32>,
    active: usize,
    first_tab: usize,
}

impl Globals {
    fn new(ver: u8) -> Globals {
        Globals {
            book: Book::new(ver),
            date1904: false,
            fonts: vec![],
            formats: HashMap::new(),
            fmt_index: 0,
            xfs: vec![],
            palette: if ver >= 5 {
                DEFAULT_PALETTE.to_vec()
            } else {
                BIFF34_PALETTE.to_vec()
            },
            sst: vec![],
            blips: vec![],
            xf_style: HashMap::new(),
            active: 0,
            first_tab: 0,
        }
    }

    pub fn color(&self, icv: u16) -> Option<Rgb> {
        match icv {
            0..=7 => Some(EGA[icv as usize]),
            8..=63 => self.palette.get(icv as usize - 8).copied().or(Some(0)),
            0x41 => Some(0xFFFFFF),
            _ => None,
        }
    }

    pub fn font(&self, idx: u16) -> Font {
        // There is no font 4: indexes from 5 on are one past the list.
        let i = if idx >= 4 {
            idx as usize - 1
        } else {
            idx as usize
        };
        let Some(f) = self.fonts.get(i).or_else(|| self.fonts.first()) else {
            return Font::default();
        };
        Font {
            name: f.name.clone(),
            size_centipt: u32::from(f.height) * 5,
            bold: f.bold,
            italic: f.italic,
            underline: match f.underline {
                1 => Some("single"),
                2 => Some("double"),
                0x21 => Some("singleAccounting"),
                0x22 => Some("doubleAccounting"),
                _ => None,
            },
            strike: f.strike,
            color: self.color(f.color),
            vert_align: match f.script {
                1 => Some("superscript"),
                2 => Some("subscript"),
                _ => None,
            },
            family: f.family,
            charset: if f.charset > 1 { Some(f.charset) } else { None },
            outline: f.outline,
            shadow: f.shadow,
        }
    }

    pub fn numfmt(&self, id: u16) -> String {
        if let Some(s) = self.formats.get(&id) {
            return s.clone();
        }
        if self.book.ver <= 4 {
            return "General".into();
        }
        BUILTIN_FMT
            .iter()
            .find(|e| e.0 == id)
            .map(|e| e.1.to_string())
            .unwrap_or_else(|| "General".into())
    }

    fn style_of_xf(&self, x: &XfRec) -> Style {
        let edge = |k: usize| -> Edge {
            let s = BORDER_STYLES
                .get(x.border_style[k] as usize)
                .copied()
                .flatten();
            Edge {
                style: s,
                color: if s.is_some() {
                    self.color(x.border_color[k]).or(Some(0))
                } else {
                    None
                },
            }
        };
        let diag_style = BORDER_STYLES
            .get(x.diag_style as usize)
            .copied()
            .flatten()
            .filter(|_| x.diag_up || x.diag_down);
        let pattern = PATTERNS.get(x.pattern as usize).copied().unwrap_or("none");
        let fill = if pattern == "none" {
            Fill::NONE
        } else {
            Fill {
                pattern,
                fg: self.color(x.fore).or(Some(0)),
                bg: self.color(x.back).or(Some(0xFFFFFF)),
            }
        };
        Style {
            font: self.font(x.font),
            fill,
            border: Border {
                left: edge(0),
                right: edge(1),
                top: edge(2),
                bottom: edge(3),
                diagonal: Edge {
                    style: diag_style,
                    color: diag_style.map(|_| self.color(x.diag_color).unwrap_or(0)),
                },
                diag_up: x.diag_up && diag_style.is_some(),
                diag_down: x.diag_down && diag_style.is_some(),
            },
            align: Align {
                horizontal: HALIGN.get(x.halign as usize).copied().flatten(),
                vertical: VALIGN.get(x.valign as usize).copied().flatten(),
                // Justified and distributed text is wrapped, as Excel lays it out.
                wrap: x.wrap || matches!(x.valign, 3 | 4),
                indent: x.indent,
                rotation: x.rot,
                shrink: x.shrink,
                reading_order: x.reading.min(2),
            },
            numfmt: self.numfmt(x.fmt),
            locked: x.locked,
            hidden: x.hidden,
        }
    }

    /// A cell XF with the attribute groups it does not set taken from its
    /// parent style. From BIFF5 on a cell XF holds every attribute itself,
    /// the flags saying only what follows the style when it is edited
    /// ([MS-XLS] 2.5.20 CellXF); BIFF3 and BIFF4 cell XFs take the groups whose
    /// flag is clear from the style.
    fn resolve_xf(&self, x: &XfRec) -> XfRec {
        let mut r = x.clone();
        if x.is_style || self.book.ver >= 5 {
            return r;
        }
        let Some(p) = self.xfs.get(x.parent as usize).filter(|p| p.is_style) else {
            return r;
        };
        if x.used & 1 == 0 {
            r.fmt = p.fmt;
        }
        if x.used & 2 == 0 {
            r.font = p.font;
        }
        if x.used & 4 == 0 {
            (
                r.halign, r.valign, r.wrap, r.rot, r.indent, r.shrink, r.reading,
            ) = (
                p.halign, p.valign, p.wrap, p.rot, p.indent, p.shrink, p.reading,
            );
        }
        if x.used & 8 == 0 {
            (
                r.border_style,
                r.border_color,
                r.diag_style,
                r.diag_color,
                r.diag_up,
                r.diag_down,
            ) = (
                p.border_style,
                p.border_color,
                p.diag_style,
                p.diag_color,
                p.diag_up,
                p.diag_down,
            );
        }
        if x.used & 16 == 0 {
            (r.pattern, r.fore, r.back) = (p.pattern, p.fore, p.back);
        }
        if x.used & 32 == 0 {
            (r.locked, r.hidden) = (p.locked, p.hidden);
        }
        r
    }

    fn default_xf(&self) -> usize {
        if self.book.ver >= 5 && self.xfs.len() > 15 {
            15
        } else {
            0
        }
    }

    /// The model style of XF `xf`, interned.
    pub fn style_id(&mut self, wb: &mut Workbook, xf: u16) -> u32 {
        let key = u32::from(xf);
        if let Some(&s) = self.xf_style.get(&key) {
            return s;
        }
        let id = match self.xfs.get(xf as usize) {
            Some(x) => {
                let st = self.style_of_xf(&self.resolve_xf(x));
                wb.styles.add(st)
            }
            None => 0,
        };
        self.xf_style.insert(key, id);
        id
    }

    /// BIFF2: the style of a cell's 3-byte attributes, through its XF when
    /// the file has XF records, from the attributes otherwise.
    pub fn style_of_attrs(&mut self, wb: &mut Workbook, attrs: [u8; 3], xf: u16) -> u32 {
        if !self.xfs.is_empty() {
            return self.style_id(wb, xf);
        }
        let key = 0x8000_0000
            | u32::from(attrs[1]) << 8
            | u32::from(attrs[2])
            | u32::from(attrs[0] & 0xC0) << 16;
        if let Some(&s) = self.xf_style.get(&key) {
            return s;
        }
        let mut x = XfRec {
            font: u16::from(attrs[1] >> 6),
            fmt: u16::from(attrs[1] & 0x3F),
            locked: attrs[0] & 0x40 != 0,
            hidden: attrs[0] & 0x80 != 0,
            valign: 2,
            ..Default::default()
        };
        biff2_look(&mut x, attrs[2]);
        let id = wb.styles.add(self.style_of_xf(&x));
        self.xf_style.insert(key, id);
        id
    }
}

/// BIFF2's alignment, border and shading byte.
fn biff2_look(x: &mut XfRec, a: u8) {
    x.halign = a & 7;
    for (k, bit) in [(0usize, 8u8), (1, 16), (2, 32), (3, 64)] {
        if a & bit != 0 {
            x.border_style[k] = 1;
            x.border_color[k] = 0;
        }
    }
    if a & 0x80 != 0 {
        x.pattern = 17;
        x.fore = 0;
        x.back = 1;
    }
}

/// Reads an XLS file.
pub(crate) fn read(bytes: &[u8], budget: &mut Budget) -> Result<Workbook> {
    let mut data = stream::open(bytes)?;
    budget.alloc(data.len() as u64 * 2)?;
    let mut found = exav_unpack::biff::records(&data);
    let first = found
        .next()
        .ok_or_else(|| Error::Malformed("empty stream".into()))?;
    let ver = stream::bof_version(&first);
    if ver == 0 {
        return Err(Error::NotFormat("no BOF record".into()));
    }
    let filepass = found
        .find(|r| r.id == 0x002F)
        .map(|r| (r.pos, r.data.into_owned()));
    if let Some((pos, body)) = filepass {
        let dec =
            Decryptor::from_filepass(&body, ver >= 8, DEFAULT_PASSWORDS).map_err(|e| match e {
                Refused::Password => Error::Encrypted,
                Refused::Method => Error::Unsupported("encryption method".into()),
            })?;
        dec.decrypt_stream(&mut data, pos);
    }
    let recs = stream::records(&data);
    let mut wb = Workbook::new(Style::default());
    if ver <= 4 && stream::bof_type(&recs[0]) == 0x0100 {
        read_biff4w(&recs, &mut wb, budget)?;
    } else if ver <= 4 {
        // A worksheet file: globals and cells in one substream.
        let mut g = Globals::new(ver);
        for r in &recs {
            globals_record(&mut g, r);
        }
        finish_globals(&mut g, &mut wb);
        g.book.sheet_names = vec!["Sheet1".into()];
        let mut sheet = Sheet::new("Sheet1".into());
        if stream::bof_type(&recs[0]) == 0x20 {
            wb.warn("a chart file");
        }
        let filter = sheet::read_sheet(&mut g, &mut wb, budget, &recs, &mut sheet)?;
        wb.sheets.push(sheet);
        finish_names(&g, &mut wb, &[filter], &[Some(0)]);
    } else {
        read_workbook(ver, &recs, &mut wb, budget)?;
    }
    if wb.sheets.is_empty() {
        return Err(Error::Malformed("no sheets".into()));
    }
    Ok(wb)
}

/// BIFF4W: a workspace whose sheets are each a BIFF4 worksheet stream after
/// a SHEETHDR record.
fn read_biff4w(recs: &[Rec], wb: &mut Workbook, budget: &mut Budget) -> Result<()> {
    let mut g0 = Globals::new(4);
    let mut i = 1;
    let mut names = vec![];
    while i < recs.len() {
        let r = &recs[i];
        if r.id == 0x008F {
            let mut c = Cur::new(&r.data);
            c.u32();
            names.push(g0.book.string(&mut c, 1));
        } else if stream::BOF_IDS.contains(&r.id) {
            let start = i;
            let end = substream_end(recs, start);
            if wb.sheets.len() >= budget.limits.max_sheets as usize {
                return Err(Error::TooLarge("sheets"));
            }
            let mut g = Globals::new(4);
            g.book.codepage = g0.book.codepage;
            for r in &recs[start..end] {
                globals_record(&mut g, r);
            }
            if wb.sheets.is_empty() {
                finish_globals(&mut g, wb);
            }
            let name = names
                .get(wb.sheets.len())
                .cloned()
                .unwrap_or_else(|| format!("Sheet{}", wb.sheets.len() + 1));
            g.book.sheet_names = names.clone();
            let mut sheet = Sheet::new(name);
            sheet::read_sheet(&mut g, wb, budget, &recs[start..end], &mut sheet)?;
            wb.sheets.push(sheet);
            i = end;
            continue;
        } else {
            globals_record(&mut g0, r);
        }
        i += 1;
    }
    Ok(())
}

/// The index one past the EOF that closes the substream at `start`.
fn substream_end(recs: &[Rec], start: usize) -> usize {
    let mut depth = 0i32;
    for (j, r) in recs.iter().enumerate().skip(start) {
        if stream::BOF_IDS.contains(&r.id) {
            depth += 1;
        } else if r.id == 0x000A {
            depth -= 1;
            if depth <= 0 {
                return j + 1;
            }
        }
    }
    recs.len()
}

fn read_workbook(ver: u8, recs: &[Rec], wb: &mut Workbook, budget: &mut Budget) -> Result<()> {
    let mut g = Globals::new(ver);
    let mut i = 1;
    while i < recs.len() && recs[i].id != 0x000A {
        globals_record(&mut g, &recs[i]);
        i += 1;
    }
    finish_globals(&mut g, wb);
    if g.book.sheets.len() > budget.limits.max_sheets as usize {
        return Err(Error::TooLarge("sheets"));
    }
    g.book.finish();
    budget.alloc(g.sst.iter().map(|v| v.text_len() as u64 + 32).sum())?;

    // Substreams, matched to BOUNDSHEET by their position, else by order.
    let by_pos: HashMap<usize, usize> = g
        .book
        .sheets
        .iter()
        .enumerate()
        .map(|(k, s)| (s.pos, k))
        .collect();
    let mut subs: Vec<(usize, usize, usize)> = vec![];
    let mut order = 0usize;
    i += 1;
    while i < recs.len() {
        if stream::BOF_IDS.contains(&recs[i].id) {
            let start = i;
            let end = substream_end(recs, start);
            let k = by_pos.get(&recs[start].pos).copied().unwrap_or_else(|| {
                while order < g.book.sheets.len() && g.book.sheets[order].kind == 6 {
                    order += 1;
                }
                order
            });
            order = k + 1;
            subs.push((k, start, end));
            i = end;
        } else {
            i += 1;
        }
    }
    let mut built: Vec<Option<Sheet>> = (0..g.book.sheets.len()).map(|_| None).collect();
    let mut filter = vec![false; g.book.sheets.len()];
    for (k, start, end) in subs {
        if k >= g.book.sheets.len() || built[k].is_some() {
            continue;
        }
        let mut sheet = Sheet::new(g.book.sheets[k].name.clone());
        sheet.state = match g.book.sheets[k].state & 3 {
            1 => SheetState::Hidden,
            2 => SheetState::VeryHidden,
            _ => SheetState::Visible,
        };
        let kind = g.book.sheets[k].kind;
        if kind == 2 || stream::bof_type(&recs[start]) == 0x20 {
            sheet.chart_sheet = true;
            if let Some(ch) = chart::read_chart(&g, &recs[start..end], None, wb) {
                sheet.charts.push(ch);
            }
        } else if kind != 6 {
            filter[k] = sheet::read_sheet(&mut g, wb, budget, &recs[start..end], &mut sheet)?;
        }
        built[k] = Some(sheet);
    }
    // Where each BOUNDSHEET ends up, VB modules left out.
    let mut index: Vec<Option<usize>> = vec![];
    let mut filters = vec![];
    for (k, s) in built.into_iter().enumerate() {
        if g.book.sheets[k].kind == 6 {
            index.push(None);
            continue;
        }
        index.push(Some(wb.sheets.len()));
        filters.push(filter[k]);
        let mut s = s.unwrap_or_else(|| Sheet::new(g.book.sheets[k].name.clone()));
        // A chart sheet whose chart could not be read stays a worksheet.
        if s.chart_sheet && s.charts.is_empty() {
            s.chart_sheet = false;
        }
        wb.sheets.push(s);
    }
    // The active tab counts the VB modules left out.
    let skipped = g
        .book
        .sheets
        .iter()
        .take(wb.active)
        .filter(|s| s.kind == 6)
        .count();
    wb.active = wb.active.saturating_sub(skipped);
    finish_names(&g, wb, &filters, &index);
    Ok(())
}

/// Defined names, now that the sheets are known. `filters`: whether each
/// sheet of the model has filter buttons; `index`: each BOUNDSHEET's sheet
/// in the model.
fn finish_names(g: &Globals, wb: &mut Workbook, filters: &[bool], index: &[Option<usize>]) {
    for n in &g.book.names {
        if n.rgce.is_empty() || n.name.starts_with("_xlfn.") {
            continue;
        }
        let Ok(d) = formula::decode(&g.book.ctx(&g.book.ext5), &n.rgce, &n.extra, 0, 0) else {
            continue;
        };
        if d.text.is_empty() || d.text.contains("#NAME?") {
            continue;
        }
        let scope = match n.sheet {
            0 => None,
            s => match index.get(s as usize - 1).copied().flatten() {
                Some(i) => Some(i),
                None => continue,
            },
        };
        if n.name == "_xlnm._FilterDatabase" {
            if let Some(s) = scope
                && let Some(sh) = wb
                    .sheets
                    .get_mut(s)
                    .filter(|_| filters.get(s) == Some(&true))
                && sh.autofilter.is_none()
            {
                sh.autofilter = parse_area(&d.text);
            }
            continue;
        }
        wb.names.push(DefinedName {
            name: n.name.clone(),
            sheet: scope,
            formula: d.text,
            hidden: n.hidden,
        });
    }
}

/// "Sheet1!$A$1:$C$9" (or without a sheet) to a range.
fn parse_area(s: &str) -> Option<Range> {
    let s = s.rsplit('!').next()?;
    let mut parts = s.split(':');
    let a = parse_cell(parts.next()?)?;
    let b = parts.next().map(parse_cell).unwrap_or(Some(a))?;
    Some(Range {
        r1: a.0,
        c1: a.1,
        r2: b.0,
        c2: b.1,
    })
}

/// Reads an XLUnicodeRichExtendedString across CONTINUE boundaries, where
/// the character width flag is repeated.
pub(crate) struct SplitReader<'a> {
    pub d: &'a [u8],
    pub breaks: &'a [usize],
    pub p: usize,
}

impl SplitReader<'_> {
    fn next_break(&self) -> usize {
        self.breaks
            .iter()
            .copied()
            .find(|&b| b > self.p)
            .unwrap_or(self.d.len())
    }

    pub fn u8(&mut self) -> u8 {
        let v = self.d.get(self.p).copied().unwrap_or(0);
        self.p = self.p.saturating_add(1);
        v
    }

    pub fn u16(&mut self) -> u16 {
        u16::from(self.u8()) | u16::from(self.u8()) << 8
    }

    fn u32(&mut self) -> u32 {
        u32::from(self.u16()) | u32::from(self.u16()) << 16
    }

    pub fn chars(&mut self, mut n: usize, mut wide: bool) -> String {
        let mut units: Vec<u16> = Vec::with_capacity(n.min(self.d.len()));
        // The header of the string ended with its record: the CONTINUE that
        // holds the characters starts with the width flag.
        if n > 0 && self.breaks.contains(&self.p) && self.p < self.d.len() {
            wide = self.u8() & 1 != 0;
        }
        while n > 0 && self.p < self.d.len() {
            let end = self.next_break();
            let w = if wide { 2 } else { 1 };
            let take = ((end - self.p) / w).min(n);
            for _ in 0..take {
                units.push(if wide {
                    self.u16()
                } else {
                    u16::from(self.u8())
                });
            }
            n -= take;
            if n > 0 {
                // A CONTINUE starts here, with the width flag again.
                self.p = end;
                if self.p >= self.d.len() {
                    break;
                }
                wide = self.u8() & 1 != 0;
            }
        }
        String::from_utf16_lossy(&units)
    }

    fn rich(&mut self) -> (String, Vec<(u16, u16)>) {
        let n = self.u16() as usize;
        let f = self.u8();
        let runs_n = if f & 8 != 0 { self.u16() as usize } else { 0 };
        let ext = if f & 4 != 0 { self.u32() as usize } else { 0 };
        let s = self.chars(n, f & 1 != 0);
        let mut runs = Vec::new();
        for _ in 0..runs_n {
            if self.p >= self.d.len() {
                break;
            }
            let ich = self.u16();
            let ifnt = self.u16();
            runs.push((ich, ifnt));
        }
        self.p = self.p.saturating_add(ext);
        (s, runs)
    }
}

/// Text split into runs at UTF-16 positions, each run in a font.
pub(crate) fn rich_value(g: &Globals, s: String, runs: &[(u16, u16)]) -> Value {
    let units: Vec<u16> = s.encode_utf16().collect();
    let mut bounds: Vec<(usize, Option<u16>)> = vec![(0, None)];
    for &(ich, ifnt) in runs {
        let ich = (ich as usize).min(units.len());
        if ich == 0 {
            bounds[0].1 = Some(ifnt);
        } else if bounds.last().is_some_and(|b| ich > b.0) {
            bounds.push((ich, Some(ifnt)));
        }
    }
    let mut out = Vec::new();
    for k in 0..bounds.len() {
        let a = bounds[k].0;
        let b = bounds.get(k + 1).map_or(units.len(), |x| x.0);
        if a >= b {
            continue;
        }
        out.push(Run {
            text: String::from_utf16_lossy(&units[a..b]),
            font: bounds[k].1.map(|f| g.font(f)),
        });
    }
    if out.len() <= 1 {
        Value::text(s)
    } else {
        Value::Rich(out.into())
    }
}

fn globals_record(g: &mut Globals, r: &Rec) {
    if g.book.record(r) {
        return;
    }
    let ver = g.book.ver;
    let mut c = Cur::new(&r.data);
    match r.id {
        0x0022 => g.date1904 = c.u16() == 1,
        0x0031 | 0x0231 => {
            let mut f = FontRec {
                height: c.u16(),
                ..Default::default()
            };
            let grbit = c.u16();
            f.italic = grbit & 2 != 0;
            f.strike = grbit & 8 != 0;
            f.outline = grbit & 0x10 != 0;
            f.shadow = grbit & 0x20 != 0;
            if ver <= 4 {
                f.color = if ver == 2 { 0x7FFF } else { c.u16() };
                f.bold = grbit & 1 != 0;
                f.underline = u8::from(grbit & 4 != 0);
            } else {
                f.color = c.u16();
                f.bold = c.u16() >= 600;
                f.script = c.u16();
                f.underline = c.u8();
                f.family = c.u8();
                f.charset = c.u8();
                c.u8();
            }
            f.name = g.book.string(&mut c, 1);
            g.fonts.push(f);
        }
        0x0045 => {
            if let Some(f) = g.fonts.last_mut() {
                f.color = c.u16();
            }
        }
        0x041E if ver >= 5 => {
            let id = c.u16();
            let s = g.book.string(&mut c, if ver >= 8 { 2 } else { 1 });
            g.formats.insert(id, s);
        }
        0x041E | 0x001E => {
            if r.id == 0x041E {
                c.u16();
            }
            let s = g.book.string(&mut c, 1);
            g.formats.insert(g.fmt_index, s);
            g.fmt_index = g.fmt_index.saturating_add(1);
        }
        0x00E0 if ver >= 5 => {
            let mut x = XfRec {
                font: c.u16(),
                fmt: c.u16(),
                ..Default::default()
            };
            let t = c.u16();
            x.locked = t & 1 != 0;
            x.hidden = t & 2 != 0;
            x.is_style = t & 4 != 0;
            x.parent = t >> 4;
            let al = c.u8();
            x.halign = al & 7;
            x.wrap = al & 8 != 0;
            x.valign = (al >> 4) & 7;
            if ver >= 8 {
                x.rot = c.u8();
                let b = c.u8();
                x.indent = b & 15;
                x.shrink = b & 16 != 0;
                x.reading = (b >> 6) & 3;
                x.used = c.u8() >> 2;
                let b1 = c.u32();
                let b2 = c.u32();
                let b3 = c.u16();
                x.border_style = [
                    (b1 & 15) as u8,
                    ((b1 >> 4) & 15) as u8,
                    ((b1 >> 8) & 15) as u8,
                    ((b1 >> 12) & 15) as u8,
                ];
                x.border_color = [
                    ((b1 >> 16) & 0x7F) as u16,
                    ((b1 >> 23) & 0x7F) as u16,
                    (b2 & 0x7F) as u16,
                    ((b2 >> 7) & 0x7F) as u16,
                ];
                x.diag_down = b1 & (1 << 30) != 0;
                x.diag_up = b1 & (1 << 31) != 0;
                x.diag_color = ((b2 >> 14) & 0x7F) as u16;
                x.diag_style = ((b2 >> 21) & 15) as u8;
                x.pattern = ((b2 >> 26) & 0x3F) as u8;
                x.fore = b3 & 0x7F;
                x.back = (b3 >> 7) & 0x7F;
            } else {
                let o = c.u8();
                x.used = o >> 2;
                x.rot = orientation(o & 3);
                let a = c.u32();
                let b = c.u32();
                x.fore = (a & 0x7F) as u16;
                x.back = ((a >> 7) & 0x7F) as u16;
                x.pattern = ((a >> 16) & 0x3F) as u8;
                x.border_style[3] = ((a >> 22) & 7) as u8;
                x.border_color[3] = ((a >> 25) & 0x7F) as u16;
                x.border_style[2] = (b & 7) as u8;
                x.border_style[0] = ((b >> 3) & 7) as u8;
                x.border_style[1] = ((b >> 6) & 7) as u8;
                x.border_color[2] = ((b >> 9) & 0x7F) as u16;
                x.border_color[0] = ((b >> 16) & 0x7F) as u16;
                x.border_color[1] = ((b >> 23) & 0x7F) as u16;
            }
            g.xfs.push(x);
        }
        0x0443 | 0x0243 => {
            let mut x = XfRec {
                font: u16::from(c.u8()),
                fmt: u16::from(c.u8()),
                ..Default::default()
            };
            if r.id == 0x0443 {
                let t = c.u16();
                x.locked = t & 1 != 0;
                x.hidden = t & 2 != 0;
                x.is_style = t & 4 != 0;
                x.parent = t >> 4;
                let al = c.u8();
                x.halign = al & 7;
                x.wrap = al & 8 != 0;
                x.valign = (al >> 4) & 3;
                x.rot = orientation((al >> 6) & 3);
                x.used = c.u8() >> 2;
            } else {
                let t = c.u8();
                x.locked = t & 1 != 0;
                x.hidden = t & 2 != 0;
                x.is_style = t & 4 != 0;
                x.used = c.u8() >> 2;
                let al = c.u16();
                x.halign = (al & 7) as u8;
                x.wrap = al & 8 != 0;
                x.valign = 2;
                x.parent = al >> 4;
            }
            let area = c.u16();
            x.pattern = (area & 0x3F) as u8;
            x.fore = (area >> 6) & 0x1F;
            x.back = (area >> 11) & 0x1F;
            let b = c.u32();
            x.border_style[2] = (b & 7) as u8;
            x.border_color[2] = ((b >> 3) & 0x1F) as u16;
            x.border_style[0] = ((b >> 8) & 7) as u8;
            x.border_color[0] = ((b >> 11) & 0x1F) as u16;
            x.border_style[3] = ((b >> 16) & 7) as u8;
            x.border_color[3] = ((b >> 19) & 0x1F) as u16;
            x.border_style[1] = ((b >> 24) & 7) as u8;
            x.border_color[1] = ((b >> 27) & 0x1F) as u16;
            g.xfs.push(x);
        }
        0x0043 => {
            let mut x = XfRec {
                font: u16::from(c.u8()),
                used: 0x3F,
                parent: 0xFFF,
                valign: 2,
                ..Default::default()
            };
            c.u8();
            let f = c.u8();
            x.fmt = u16::from(f & 0x3F);
            x.locked = f & 0x40 != 0;
            x.hidden = f & 0x80 != 0;
            biff2_look(&mut x, c.u8());
            g.xfs.push(x);
        }
        0x0092 => {
            let n = c.u16() as usize;
            for k in 0..n.min(56) {
                let b = c.bytes(4);
                if b.len() < 4 {
                    break;
                }
                let v = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
                if k < g.palette.len() {
                    g.palette[k] = v;
                } else {
                    g.palette.push(v);
                }
            }
        }
        0x00FC => {
            let mut sr = SplitReader {
                d: &r.data,
                breaks: &r.breaks,
                p: 8,
            };
            let unique = u32_at(&r.data, 4) as usize;
            for _ in 0..unique.min(r.data.len()) {
                if sr.p >= r.data.len() {
                    break;
                }
                let (s, runs) = sr.rich();
                let v = if runs.is_empty() {
                    Value::text(s)
                } else {
                    rich_value(g, s, &runs)
                };
                g.sst.push(v);
            }
        }
        0x00EB => g.blips.extend(escher::blips(&r.data)),
        // WINDOW1: the active tab (BIFF5 on).
        0x003D if ver >= 5 => {
            g.active = u16_at(&r.data, 10) as usize;
            g.first_tab = u16_at(&r.data, 12) as usize;
        }
        _ => {}
    }
}

/// BIFF4 and BIFF5 text orientation to an XLSX rotation.
fn orientation(o: u8) -> u8 {
    match o {
        1 => 255,
        2 => 90,
        3 => 180,
        _ => 0,
    }
}

fn finish_globals(g: &mut Globals, wb: &mut Workbook) {
    wb.date1904 = g.date1904;
    if !crate::formats::office::common::codepage::known(g.book.codepage) {
        wb.warn(format!(
            "code page {} read as Windows 1252",
            g.book.codepage
        ));
    }
    wb.active = g.active;
    wb.first_tab = g.first_tab;
    let d = g.default_xf();
    let st = match g.xfs.get(d) {
        Some(x) => g.style_of_xf(&g.resolve_xf(x)),
        None => {
            let mut s = Style::default();
            if !g.fonts.is_empty() {
                s.font = g.font(0);
            }
            s
        }
    };
    wb.styles = Styles::new(st);
    g.xf_style.insert(d as u32, 0);
}
