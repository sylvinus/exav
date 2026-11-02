//! styles.xml: fonts, fills, borders, number formats, cell formats and the
//! differential formats of conditional formats.

use super::xml::{argb, esc, esc_into};
use crate::formats::office::sheets::model::*;
use crate::formats::office::sheets::numtext;
use std::collections::HashMap;
use std::fmt::Write as _;

struct Interner<T: std::hash::Hash + Eq + Clone> {
    list: Vec<T>,
    map: HashMap<T, usize>,
}

impl<T: std::hash::Hash + Eq + Clone> Interner<T> {
    fn new() -> Self {
        Interner {
            list: vec![],
            map: HashMap::new(),
        }
    }

    fn get(&mut self, v: &T) -> usize {
        if let Some(&i) = self.map.get(v) {
            return i;
        }
        let i = self.list.len();
        self.list.push(v.clone());
        self.map.insert(v.clone(), i);
        i
    }
}

/// Metric-compatible fonts under the names of the fonts they stand in for,
/// which an XLSX reader is more likely to have or map.
pub fn ms_font_name(name: &str) -> &str {
    match name {
        "Liberation Sans" => "Arial",
        "Liberation Serif" => "Times New Roman",
        "Liberation Mono" => "Courier New",
        "Liberation Sans Narrow" => "Arial Narrow",
        "Carlito" => "Calibri",
        "Caladea" => "Cambria",
        _ => name,
    }
}

/// A font as `<font>` (cell formats) or `<rPr>` (rich text runs).
pub fn font_xml(o: &mut String, f: &Font, tag: &str) {
    let _ = write!(o, "<{tag}>");
    if f.bold {
        o.push_str("<b/>");
    }
    if f.italic {
        o.push_str("<i/>");
    }
    if f.strike {
        o.push_str("<strike/>");
    }
    if f.outline {
        o.push_str("<outline/>");
    }
    if f.shadow {
        o.push_str("<shadow/>");
    }
    match f.underline {
        Some("single") => o.push_str("<u/>"),
        Some(u) => {
            let _ = write!(o, "<u val=\"{u}\"/>");
        }
        None => {}
    }
    if let Some(v) = f.vert_align {
        let _ = write!(o, "<vertAlign val=\"{v}\"/>");
    }
    let _ = write!(o, "<sz val=\"{}\"/>", numtext::xml(f.size_pt()));
    if let Some(c) = f.color {
        let _ = write!(o, "<color rgb=\"{}\"/>", argb(c));
    }
    let name_tag = if tag == "rPr" { "rFont" } else { "name" };
    let _ = write!(o, "<{name_tag} val=\"");
    esc_into(o, ms_font_name(&f.name));
    o.push_str("\"/>");
    if (1..=5).contains(&f.family) {
        let _ = write!(o, "<family val=\"{}\"/>", f.family);
    }
    if let Some(cs) = f.charset {
        let _ = write!(o, "<charset val=\"{cs}\"/>");
    }
    let _ = write!(o, "</{tag}>");
}

fn fill_xml(o: &mut String, f: &Fill, dxf: bool) {
    if f.pattern == "none" {
        o.push_str("<fill><patternFill patternType=\"none\"/></fill>");
        return;
    }
    o.push_str("<fill><patternFill");
    if !(dxf && f.pattern == "solid") {
        let _ = write!(o, " patternType=\"{}\"", f.pattern);
    }
    o.push('>');
    if dxf && f.pattern == "solid" {
        // In a differential format a solid fill's colour is its background.
        if let Some(c) = f.fg.or(f.bg) {
            let _ = write!(o, "<bgColor rgb=\"{}\"/>", argb(c));
        }
    } else {
        if let Some(c) = f.fg {
            let _ = write!(o, "<fgColor rgb=\"{}\"/>", argb(c));
        }
        if let Some(c) = f.bg {
            let _ = write!(o, "<bgColor rgb=\"{}\"/>", argb(c));
        }
    }
    o.push_str("</patternFill></fill>");
}

fn edge_xml(o: &mut String, tag: &str, e: &Edge) {
    match e.style {
        None => {
            let _ = write!(o, "<{tag}/>");
        }
        Some(st) => match e.color {
            Some(c) => {
                let _ = write!(
                    o,
                    "<{tag} style=\"{st}\"><color rgb=\"{}\"/></{tag}>",
                    argb(c)
                );
            }
            None => {
                let _ = write!(o, "<{tag} style=\"{st}\"><color auto=\"1\"/></{tag}>");
            }
        },
    }
}

fn border_xml(o: &mut String, b: &Border) {
    o.push_str("<border");
    if b.diag_up {
        o.push_str(" diagonalUp=\"1\"");
    }
    if b.diag_down {
        o.push_str(" diagonalDown=\"1\"");
    }
    o.push('>');
    edge_xml(o, "left", &b.left);
    edge_xml(o, "right", &b.right);
    edge_xml(o, "top", &b.top);
    edge_xml(o, "bottom", &b.bottom);
    edge_xml(o, "diagonal", &b.diagonal);
    o.push_str("</border>");
}

fn align_xml(a: &Align) -> String {
    let mut s = String::new();
    if let Some(h) = a.horizontal {
        let _ = write!(s, " horizontal=\"{h}\"");
    }
    if let Some(v) = a.vertical {
        let _ = write!(s, " vertical=\"{v}\"");
    }
    if a.wrap {
        s.push_str(" wrapText=\"1\"");
    }
    if a.indent > 0 {
        let _ = write!(s, " indent=\"{}\"", a.indent);
    }
    if a.rotation > 0 {
        let _ = write!(s, " textRotation=\"{}\"", a.rotation);
    }
    if a.shrink {
        s.push_str(" shrinkToFit=\"1\"");
    }
    if a.reading_order > 0 {
        let _ = write!(s, " readingOrder=\"{}\"", a.reading_order);
    }
    if s.is_empty() {
        s
    } else {
        format!("<alignment{s}/>")
    }
}

/// Format codes Excel numbers itself, written by their id.
const BUILTIN_IDS: &[(&str, u32)] = &[
    ("General", 0),
    ("0", 1),
    ("0.00", 2),
    ("#,##0", 3),
    ("#,##0.00", 4),
    ("0%", 9),
    ("0.00%", 10),
    ("0.00E+00", 11),
    ("# ?/?", 12),
    ("# ??/??", 13),
    ("@", 49),
];

struct Formats {
    custom: Vec<(u32, String)>,
    map: HashMap<String, u32>,
}

impl Formats {
    fn id(&mut self, code: &str) -> u32 {
        if let Some(&(_, id)) = BUILTIN_IDS.iter().find(|(c, _)| *c == code) {
            return id;
        }
        if let Some(&id) = self.map.get(code) {
            return id;
        }
        let id = 164 + self.custom.len() as u32;
        self.map.insert(code.to_string(), id);
        self.custom.push((id, code.to_string()));
        id
    }
}

fn dxf_xml(o: &mut String, d: &Dxf, fmts: &mut Formats) {
    o.push_str("<dxf>");
    if d.font_color.is_some()
        || d.bold.is_some()
        || d.italic.is_some()
        || d.underline.is_some()
        || d.strike.is_some()
    {
        o.push_str("<font>");
        if let Some(b) = d.bold {
            o.push_str(if b { "<b/>" } else { "<b val=\"0\"/>" });
        }
        if let Some(i) = d.italic {
            o.push_str(if i { "<i/>" } else { "<i val=\"0\"/>" });
        }
        if let Some(st) = d.strike {
            o.push_str(if st {
                "<strike/>"
            } else {
                "<strike val=\"0\"/>"
            });
        }
        if let Some(u) = d.underline {
            let _ = write!(o, "<u val=\"{u}\"/>");
        }
        if let Some(c) = d.font_color {
            let _ = write!(o, "<color rgb=\"{}\"/>", argb(c));
        }
        o.push_str("</font>");
    }
    if let Some(n) = &d.numfmt {
        let id = fmts.id(n);
        let _ = write!(o, "<numFmt numFmtId=\"{id}\" formatCode=\"{}\"/>", esc(n));
    }
    if let Some(f) = &d.fill {
        fill_xml(o, f, true);
    }
    if let Some(b) = &d.border {
        border_xml(o, b);
    }
    o.push_str("</dxf>");
}

pub fn styles_xml(styles: &Styles, dxfs: &[Dxf]) -> String {
    let mut fonts = Interner::new();
    let mut fills = Interner::new();
    fills.get(&Fill::NONE);
    fills.get(&Fill {
        pattern: "gray125",
        fg: None,
        bg: None,
    });
    let mut borders = Interner::new();
    borders.get(&Border::default());
    let mut fmts = Formats {
        custom: vec![],
        map: HashMap::new(),
    };
    let mut xfs = String::new();
    fonts.get(&styles.list[0].font);
    for st in &styles.list {
        let f = fonts.get(&st.font);
        let fi = fills.get(&st.fill);
        let b = borders.get(&st.border);
        let n = fmts.id(&st.numfmt);
        let al = align_xml(&st.align);
        let prot = if !st.locked || st.hidden {
            format!(
                "<protection locked=\"{}\" hidden=\"{}\"/>",
                u8::from(st.locked),
                u8::from(st.hidden)
            )
        } else {
            String::new()
        };
        let _ = write!(
            xfs,
            "<xf numFmtId=\"{n}\" fontId=\"{f}\" fillId=\"{fi}\" borderId=\"{b}\" xfId=\"0\" applyNumberFormat=\"1\" applyFont=\"1\" applyFill=\"1\" applyBorder=\"1\" applyAlignment=\"1\" applyProtection=\"1\""
        );
        if al.is_empty() && prot.is_empty() {
            xfs.push_str("/>");
        } else {
            let _ = write!(xfs, ">{al}{prot}</xf>");
        }
    }
    let mut dx = String::new();
    for d in dxfs {
        dxf_xml(&mut dx, d, &mut fmts);
    }
    let mut s = String::from(concat!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>"#,
        "\n",
        r#"<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">"#
    ));
    if !fmts.custom.is_empty() {
        let _ = write!(s, "<numFmts count=\"{}\">", fmts.custom.len());
        for (id, code) in &fmts.custom {
            let _ = write!(
                s,
                "<numFmt numFmtId=\"{id}\" formatCode=\"{}\"/>",
                esc(code)
            );
        }
        s.push_str("</numFmts>");
    }
    let _ = write!(s, "<fonts count=\"{}\">", fonts.list.len());
    for f in &fonts.list {
        font_xml(&mut s, f, "font");
    }
    s.push_str("</fonts>");
    let _ = write!(s, "<fills count=\"{}\">", fills.list.len());
    for f in &fills.list {
        fill_xml(&mut s, f, false);
    }
    s.push_str("</fills>");
    let _ = write!(s, "<borders count=\"{}\">", borders.list.len());
    for b in &borders.list {
        border_xml(&mut s, b);
    }
    s.push_str("</borders>");
    s.push_str("<cellStyleXfs count=\"1\"><xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\"/></cellStyleXfs>");
    let _ = write!(
        s,
        "<cellXfs count=\"{}\">{xfs}</cellXfs>",
        styles.list.len()
    );
    s.push_str("<cellStyles count=\"1\"><cellStyle name=\"Normal\" xfId=\"0\" builtinId=\"0\"/></cellStyles>");
    let _ = write!(s, "<dxfs count=\"{}\">{dx}</dxfs>", dxfs.len());
    s.push_str("</styleSheet>");
    s
}
