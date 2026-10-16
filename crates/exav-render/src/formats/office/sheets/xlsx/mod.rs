//! The workbook model to an XLSX package (ECMA-376 SpreadsheetML). Each
//! worksheet is written into the ZIP as it is serialized, a buffer at a
//! time; the shared strings and styles, known only once every sheet is
//! written, follow them.

pub(crate) mod chart;
mod drawing;
mod styles;
pub(crate) mod xml;

use crate::formats::office::sheets::error::{Error, Result};
use crate::formats::office::sheets::model::*;
use crate::formats::office::sheets::numtext;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::{Cursor, Seek, SeekFrom, Write};
use xml::{argb, esc, esc_into};

pub(crate) use styles::ms_font_name;

const NS_MAIN: &str = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
const NS_R: &str = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
const REL: &str = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
const XML_HEAD: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n";

/// The output, refused past `limit` bytes.
struct Out {
    buf: Cursor<Vec<u8>>,
    limit: u64,
}

impl Write for Out {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if self.buf.position() + b.len() as u64 > self.limit {
            return Err(std::io::Error::other("output too large"));
        }
        self.buf.write(b)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Seek for Out {
    fn seek(&mut self, p: SeekFrom) -> std::io::Result<u64> {
        self.buf.seek(p)
    }
}

struct Package {
    z: zip::ZipWriter<Out>,
    content_types: Vec<(String, &'static str)>,
    defaults: Vec<(&'static str, &'static str)>,
}

fn zip_err(e: impl std::fmt::Display) -> Error {
    let s = e.to_string();
    if s.contains("too large") {
        Error::TooLarge("output")
    } else {
        Error::Malformed(format!("writing the package: {s}"))
    }
}

impl Package {
    fn start(&mut self, name: &str) -> Result<()> {
        let opt = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .compression_level(Some(6))
            .last_modified_time(zip::DateTime::default());
        self.z.start_file(name, opt).map_err(zip_err)
    }

    fn write(&mut self, data: &[u8]) -> Result<()> {
        self.z.write_all(data).map_err(zip_err)
    }

    fn put(&mut self, name: &str, data: &[u8]) -> Result<()> {
        self.start(name)?;
        self.write(data)
    }

    fn part(&mut self, name: &str, data: &[u8], content_type: &'static str) -> Result<()> {
        self.content_types.push((format!("/{name}"), content_type));
        self.put(name, data)
    }

    fn default_type(&mut self, ext: &'static str, mime: &'static str) {
        if !self.defaults.iter().any(|(e, _)| *e == ext) {
            self.defaults.push((ext, mime));
        }
    }
}

/// A sheet's relationships: (type, target, external).
#[derive(Default)]
pub(crate) struct Rels(Vec<(&'static str, String, bool)>);

impl Rels {
    pub fn add(&mut self, kind: &'static str, target: String, external: bool) -> String {
        self.0.push((kind, target, external));
        format!("rId{}", self.0.len())
    }

    fn xml(&self) -> String {
        let mut r = format!("{XML_HEAD}<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">");
        for (i, (kind, target, ext)) in self.0.iter().enumerate() {
            let _ = write!(
                r,
                "<Relationship Id=\"rId{}\" Type=\"{REL}/{kind}\" Target=\"{}\"",
                i + 1,
                esc(target)
            );
            if *ext {
                r.push_str(" TargetMode=\"External\"");
            }
            r.push_str("/>");
        }
        r.push_str("</Relationships>");
        r
    }
}

/// The shared string table, filled as cells are written.
struct Sst {
    list: Vec<String>,
    plain: HashMap<Str, u32>,
    rich: HashMap<String, u32>,
    count: u64,
}

impl Sst {
    fn index(&mut self, v: &Value) -> u32 {
        self.count += 1;
        match v {
            Value::Text(t) => {
                if let Some(&i) = self.plain.get(t) {
                    return i;
                }
                let mut x = String::from("<t xml:space=\"preserve\">");
                esc_into(&mut x, t);
                x.push_str("</t>");
                let i = self.list.len() as u32;
                self.list.push(x);
                self.plain.insert(t.clone(), i);
                i
            }
            Value::Rich(runs) => {
                let mut x = String::new();
                for r in runs.iter() {
                    x.push_str("<r>");
                    if let Some(f) = &r.font {
                        styles::font_xml(&mut x, f, "rPr");
                    }
                    x.push_str("<t xml:space=\"preserve\">");
                    esc_into(&mut x, &r.text);
                    x.push_str("</t></r>");
                }
                if let Some(&i) = self.rich.get(&x) {
                    return i;
                }
                let i = self.list.len() as u32;
                self.rich.insert(x.clone(), i);
                self.list.push(x);
                i
            }
            _ => 0,
        }
    }
}

/// Counters for part names, across sheets.
#[derive(Default)]
pub(crate) struct Numbers {
    pub image: usize,
    pub chart: usize,
    pub drawing: usize,
    pub comments: usize,
}

const FLUSH: usize = 1 << 16;

fn sheet_view(x: &mut String, sh: &Sheet, active: bool) {
    let mut view = String::from("<sheetView");
    if !sh.show_grid {
        view.push_str(" showGridLines=\"0\"");
    }
    if !sh.show_zeros {
        view.push_str(" showZeros=\"0\"");
    }
    if !sh.show_headers {
        view.push_str(" showRowColHeaders=\"0\"");
    }
    if sh.rtl {
        view.push_str(" rightToLeft=\"1\"");
    }
    if active {
        view.push_str(" tabSelected=\"1\"");
    }
    if sh.zoom != 100 && (10..=400).contains(&sh.zoom) {
        let _ = write!(view, " zoomScale=\"{}\"", sh.zoom);
    }
    if let Some((r, c)) = sh.top_left {
        if sh.freeze.is_none() && r <= MAX_ROW && c <= MAX_COL {
            let _ = write!(view, " topLeftCell=\"{}\"", cell_ref(r, c));
        }
    }
    view.push_str(" workbookViewId=\"0\">");
    if let Some((rows, cols)) = sh.freeze {
        if (rows > 0 || cols > 0) && rows <= MAX_ROW && cols <= MAX_COL {
            let pane = match (rows > 0, cols > 0) {
                (true, true) => "bottomRight",
                (true, false) => "bottomLeft",
                _ => "topRight",
            };
            view.push_str("<pane");
            if cols > 0 {
                let _ = write!(view, " xSplit=\"{cols}\"");
            }
            if rows > 0 {
                let _ = write!(view, " ySplit=\"{rows}\"");
            }
            let _ = write!(
                view,
                " topLeftCell=\"{}\" activePane=\"{pane}\" state=\"frozen\"/>",
                cell_ref(rows, cols)
            );
        }
    }
    view.push_str("</sheetView>");
    let _ = write!(x, "<sheetViews>{view}</sheetViews>");
}

fn cols_xml(x: &mut String, sh: &Sheet) {
    let mut cols = sh.cols.clone();
    cols.sort_by_key(|c| c.first);
    let mut cx = String::new();
    let mut next = 0u32;
    for c in &cols {
        let first = c.first.max(next);
        if first > c.last || first > MAX_COL {
            continue;
        }
        let last = c.last.min(MAX_COL);
        next = last + 1;
        let width = c.width.or(sh.default_col_width).unwrap_or(8.7109375);
        let _ = write!(
            cx,
            "<col min=\"{}\" max=\"{}\" width=\"{}\"",
            first + 1,
            last + 1,
            numtext::xml(width)
        );
        if let Some(s) = c.style {
            let _ = write!(cx, " style=\"{s}\"");
        }
        if c.hidden {
            cx.push_str(" hidden=\"1\"");
        }
        if c.width.is_some() {
            cx.push_str(" customWidth=\"1\"");
        }
        if c.outline > 0 {
            let _ = write!(cx, " outlineLevel=\"{}\"", c.outline.min(7));
        }
        cx.push_str("/>");
    }
    if !cx.is_empty() {
        let _ = write!(x, "<cols>{cx}</cols>");
    }
}

fn cell_xml(x: &mut String, sst: &mut Sst, sh: &Sheet, (r, c): (u32, u32), cell: &Cell) {
    x.push_str("<c r=\"");
    x.push_str(&cell_ref(r, c));
    x.push('"');
    if cell.style != 0 {
        let _ = write!(x, " s=\"{}\"", cell.style);
    }
    let mut f = String::new();
    if let Some(text) = &cell.formula {
        match sh.arrays.get(&(r, c)) {
            Some(a) => {
                let _ = write!(f, "<f t=\"array\" ref=\"{}\">", range_ref(a));
            }
            None => f.push_str("<f>"),
        }
        esc_into(&mut f, text);
        f.push_str("</f>");
    }
    match &cell.value {
        Value::Empty if f.is_empty() => x.push_str("/>"),
        Value::Empty => {
            let _ = write!(x, ">{f}</c>");
        }
        Value::Number(v) => {
            let _ = write!(x, ">{f}<v>{}</v></c>", numtext::xml(*v));
        }
        Value::Bool(b) => {
            let _ = write!(x, " t=\"b\">{f}<v>{}</v></c>", u8::from(*b));
        }
        Value::Error(e) => {
            let _ = write!(x, " t=\"e\">{f}<v>{}</v></c>", e.name());
        }
        Value::Text(t) if !f.is_empty() => {
            let _ = write!(x, " t=\"str\">{f}<v>");
            esc_into(x, t);
            x.push_str("</v></c>");
        }
        v @ Value::Rich(runs) if !f.is_empty() => {
            let _ = v;
            let t: String = runs.iter().map(|r| r.text.as_str()).collect();
            let _ = write!(x, " t=\"str\">{f}<v>");
            esc_into(x, &t);
            x.push_str("</v></c>");
        }
        v => {
            let i = sst.index(v);
            let _ = write!(x, " t=\"s\"><v>{i}</v></c>");
        }
    }
}

fn row_open(x: &mut String, sh: &Sheet, r: u32) {
    let _ = write!(x, "<row r=\"{}\"", r + 1);
    if let Some(i) = sh.rows.get(&r) {
        if let Some(h) = i.height {
            if i.custom_height || (h - sh.default_row_height).abs() > 1e-9 {
                let _ = write!(
                    x,
                    " ht=\"{}\" customHeight=\"1\"",
                    numtext::xml(h.clamp(0.0, 409.5))
                );
            }
        }
        if i.hidden {
            x.push_str(" hidden=\"1\"");
        }
        if let Some(s) = i.style {
            let _ = write!(x, " s=\"{s}\" customFormat=\"1\"");
        }
        if i.outline > 0 {
            let _ = write!(x, " outlineLevel=\"{}\"", i.outline.min(7));
        }
    }
    x.push('>');
}

/// The rows of a sheet, streamed into its part.
fn sheet_data(pkg: &mut Package, x: &mut String, sst: &mut Sst, sh: &Sheet) -> Result<()> {
    x.push_str("<sheetData>");
    let mut cells = sh.cells.range(..).peekable();
    let mut infos = sh
        .rows
        .iter()
        .filter(|(_, i)| {
            i.hidden
                || i.style.is_some()
                || i.outline > 0
                || i.height
                    .is_some_and(|h| i.custom_height || (h - sh.default_row_height).abs() > 1e-9)
        })
        .map(|(k, _)| *k)
        .peekable();
    loop {
        let next_cell = cells.peek().map(|(k, _)| k.0);
        let next_info = infos.peek().copied();
        let r = match (next_cell, next_info) {
            (None, None) => break,
            (Some(a), Some(b)) => a.min(b),
            (Some(a), None) => a,
            (None, Some(b)) => b,
        };
        if r > MAX_ROW {
            break;
        }
        if next_info == Some(r) {
            infos.next();
        }
        row_open(x, sh, r);
        while let Some((&(cr, cc), cell)) = cells.next_if(|(k, _)| k.0 == r) {
            if cc <= MAX_COL {
                cell_xml(x, sst, sh, (cr, cc), cell);
            }
        }
        x.push_str("</row>");
        if x.len() > FLUSH {
            pkg.write(x.as_bytes())?;
            x.clear();
        }
    }
    x.push_str("</sheetData>");
    Ok(())
}

fn cfvo(x: &mut String, v: &Cfvo) {
    match &v.val {
        Some(val) => {
            let _ = write!(x, "<cfvo type=\"{}\" val=\"{}\"/>", v.kind, esc(val));
        }
        None => {
            let _ = write!(x, "<cfvo type=\"{}\"/>", v.kind);
        }
    }
}

fn cond_formats(x: &mut String, sh: &Sheet, dxfs: &mut Vec<Dxf>) {
    // Rules without a priority of their own come after those with one, in
    // order.
    let explicit = sh
        .cond_formats
        .iter()
        .flat_map(|c| &c.rules)
        .map(|r| r.priority)
        .max()
        .unwrap_or(0);
    let mut next = explicit + 1;
    for cf in &sh.cond_formats {
        let sq: Vec<String> = cf
            .ranges
            .iter()
            .filter_map(|r| r.clipped())
            .map(|r| range_ref(&r))
            .collect();
        if sq.is_empty() || cf.rules.is_empty() {
            continue;
        }
        let _ = write!(x, "<conditionalFormatting sqref=\"{}\">", sq.join(" "));
        for rule in &cf.rules {
            let kind = match &rule.kind {
                CfKind::CellIs { .. } => "cellIs",
                CfKind::Expression { .. } => "expression",
                CfKind::ColorScale { .. } => "colorScale",
                CfKind::DataBar { .. } => "dataBar",
                CfKind::IconSet { .. } => "iconSet",
                CfKind::Other { kind, .. } => kind,
            };
            let _ = write!(x, "<cfRule type=\"{kind}\"");
            if let Some(d) = &rule.dxf {
                dxfs.push(d.clone());
                let _ = write!(x, " dxfId=\"{}\"", dxfs.len() - 1);
            }
            let prio = if rule.priority > 0 {
                rule.priority
            } else {
                next += 1;
                next - 1
            };
            let _ = write!(x, " priority=\"{prio}\"");
            if rule.stop {
                x.push_str(" stopIfTrue=\"1\"");
            }
            match &rule.kind {
                CfKind::CellIs { operator, formulas } => {
                    let _ = write!(x, " operator=\"{operator}\">");
                    for f in formulas {
                        let _ = write!(x, "<formula>{}</formula>", esc(f));
                    }
                }
                CfKind::Expression { formula } => {
                    let _ = write!(x, "><formula>{}</formula>", esc(formula));
                }
                CfKind::ColorScale { cfvos, colors } => {
                    x.push_str("><colorScale>");
                    for c in cfvos {
                        cfvo(x, c);
                    }
                    for c in colors {
                        let _ = write!(x, "<color rgb=\"{}\"/>", argb(*c));
                    }
                    x.push_str("</colorScale>");
                }
                CfKind::DataBar { min, max, color } => {
                    x.push_str("><dataBar>");
                    cfvo(x, min);
                    cfvo(x, max);
                    let _ = write!(x, "<color rgb=\"{}\"/></dataBar>", argb(*color));
                }
                CfKind::IconSet {
                    set,
                    cfvos,
                    reverse,
                    show_value,
                } => {
                    let _ = write!(x, "><iconSet iconSet=\"{}\"", esc(set));
                    if *reverse {
                        x.push_str(" reverse=\"1\"");
                    }
                    if !*show_value {
                        x.push_str(" showValue=\"0\"");
                    }
                    x.push('>');
                    for c in cfvos {
                        cfvo(x, c);
                    }
                    x.push_str("</iconSet>");
                }
                CfKind::Other {
                    attrs, formulas, ..
                } => {
                    for (k, v) in attrs {
                        let _ = write!(x, " {k}=\"{}\"", esc(v));
                    }
                    x.push('>');
                    for f in formulas {
                        let _ = write!(x, "<formula>{}</formula>", esc(f));
                    }
                }
            }
            x.push_str("</cfRule>");
        }
        x.push_str("</conditionalFormatting>");
    }
}

fn validations(x: &mut String, sh: &Sheet) {
    let list: Vec<&Validation> = sh
        .validations
        .iter()
        .filter(|v| v.ranges.iter().any(|r| r.clipped().is_some()))
        .collect();
    if list.is_empty() {
        return;
    }
    let _ = write!(x, "<dataValidations count=\"{}\">", list.len());
    for v in list {
        let sq: Vec<String> = v
            .ranges
            .iter()
            .filter_map(|r| r.clipped())
            .map(|r| range_ref(&r))
            .collect();
        let _ = write!(x, "<dataValidation type=\"{}\"", v.kind);
        if v.operator != "between" {
            let _ = write!(x, " operator=\"{}\"", v.operator);
        }
        if v.error_style != "stop" {
            let _ = write!(x, " errorStyle=\"{}\"", v.error_style);
        }
        if v.allow_blank {
            x.push_str(" allowBlank=\"1\"");
        }
        if v.hide_dropdown {
            x.push_str(" showDropDown=\"1\"");
        }
        if v.show_input {
            x.push_str(" showInputMessage=\"1\"");
        }
        if v.show_error {
            x.push_str(" showErrorMessage=\"1\"");
        }
        for (k, val) in [
            ("promptTitle", &v.prompt_title),
            ("prompt", &v.prompt),
            ("errorTitle", &v.error_title),
            ("error", &v.error),
        ] {
            if let Some(s) = val {
                let _ = write!(x, " {k}=\"{}\"", esc(s));
            }
        }
        let _ = write!(x, " sqref=\"{}\">", sq.join(" "));
        if let Some(f) = &v.formula1 {
            let _ = write!(x, "<formula1>{}</formula1>", esc(f));
        }
        if let Some(f) = &v.formula2 {
            let _ = write!(x, "<formula2>{}</formula2>", esc(f));
        }
        x.push_str("</dataValidation>");
    }
    x.push_str("</dataValidations>");
}

fn hyperlinks(x: &mut String, sh: &Sheet, rels: &mut Rels) {
    let list: Vec<(&Hyperlink, Range)> = sh
        .hyperlinks
        .iter()
        .filter_map(|h| Some((h, h.range.clipped()?)))
        .collect();
    if list.is_empty() {
        return;
    }
    x.push_str("<hyperlinks>");
    for (h, range) in list {
        let _ = write!(x, "<hyperlink ref=\"{}\"", range_ref(&range));
        if let Some(u) = &h.url {
            let id = rels.add("hyperlink", u.clone(), true);
            let _ = write!(x, " r:id=\"{id}\"");
        }
        if let Some(l) = &h.location {
            let _ = write!(x, " location=\"{}\"", esc(l));
        }
        if let Some(t) = &h.tooltip {
            let _ = write!(x, " tooltip=\"{}\"", esc(t));
        }
        if let Some(d) = &h.display {
            let _ = write!(x, " display=\"{}\"", esc(d));
        }
        x.push_str("/>");
    }
    x.push_str("</hyperlinks>");
}

fn comments(
    pkg: &mut Package,
    sh: &Sheet,
    rels: &mut Rels,
    n: &mut Numbers,
) -> Result<Option<String>> {
    if sh.comments.is_empty() {
        return Ok(None);
    }
    n.comments += 1;
    let k = n.comments;
    let mut authors: Vec<&str> = vec![];
    let mut list = String::new();
    for c in &sh.comments {
        let ai = match authors.iter().position(|a| *a == c.author) {
            Some(i) => i,
            None => {
                authors.push(&c.author);
                authors.len() - 1
            }
        };
        let _ = write!(
            list,
            "<comment ref=\"{}\" authorId=\"{ai}\"><text><r><t xml:space=\"preserve\">",
            cell_ref(c.row, c.col)
        );
        esc_into(&mut list, &c.text);
        list.push_str("</t></r></text></comment>");
    }
    let mut cx = format!("{XML_HEAD}<comments xmlns=\"{NS_MAIN}\"><authors>");
    for a in &authors {
        let _ = write!(cx, "<author>{}</author>", esc(a));
    }
    let _ = write!(cx, "</authors><commentList>{list}</commentList></comments>");
    pkg.part(
        &format!("xl/comments{k}.xml"),
        cx.as_bytes(),
        "application/vnd.openxmlformats-officedocument.spreadsheetml.comments+xml",
    )?;
    // The note shapes, which Excel needs to show the comments.
    let mut v = String::from(concat!(
        r#"<xml xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:x="urn:schemas-microsoft-com:office:excel">"#,
        r#"<o:shapelayout v:ext="edit"><o:idmap v:ext="edit" data="1"/></o:shapelayout>"#,
        r#"<v:shapetype id="_x0000_t202" coordsize="21600,21600" o:spt="202" path="m,l,21600r21600,l21600,xe"><v:stroke joinstyle="miter"/><v:path gradientshapeok="t" o:connecttype="rect"/></v:shapetype>"#
    ));
    for (i, c) in sh.comments.iter().enumerate() {
        let _ = write!(
            v,
            "<v:shape id=\"_x0000_s{}\" type=\"#_x0000_t202\" style=\"position:absolute;margin-left:59.25pt;margin-top:1.5pt;width:108pt;height:59.25pt;z-index:{};visibility:{}\" fillcolor=\"#ffffe1\" o:insetmode=\"auto\"><v:fill color2=\"#ffffe1\"/><v:shadow on=\"t\" color=\"black\" obscured=\"t\"/><v:path o:connecttype=\"none\"/><v:textbox style=\"mso-direction-alt:auto\"><div style=\"text-align:left\"></div></v:textbox><x:ClientData ObjectType=\"Note\"><x:MoveWithCells/><x:SizeWithCells/><x:AutoFill>False</x:AutoFill><x:Row>{}</x:Row><x:Column>{}</x:Column>{}</x:ClientData></v:shape>",
            1025 + i,
            i + 1,
            if c.visible { "visible" } else { "hidden" },
            c.row,
            c.col,
            if c.visible { "<x:Visible/>" } else { "" }
        );
    }
    v.push_str("</xml>");
    pkg.put(&format!("xl/drawings/vmlDrawing{k}.vml"), v.as_bytes())?;
    pkg.default_type(
        "vml",
        "application/vnd.openxmlformats-officedocument.vmlDrawing",
    );
    let id = rels.add(
        "vmlDrawing",
        format!("../drawings/vmlDrawing{k}.vml"),
        false,
    );
    rels.add("comments", format!("../comments{k}.xml"), false);
    Ok(Some(id))
}

fn worksheet(
    pkg: &mut Package,
    wb: &Workbook,
    si: usize,
    sst: &mut Sst,
    dxfs: &mut Vec<Dxf>,
    n: &mut Numbers,
) -> Result<Rels> {
    let sh = &wb.sheets[si];
    let mut rels = Rels::default();
    // Their parts first: the sheet's is then written in one go.
    let drawing_id = drawing::drawing(pkg, sh, &mut rels, n)?;
    let legacy_id = comments(pkg, sh, &mut rels, n)?;
    pkg.start(&format!("xl/worksheets/sheet{}.xml", si + 1))?;
    pkg.content_types.push((
        format!("/xl/worksheets/sheet{}.xml", si + 1),
        "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml",
    ));
    let mut x = String::with_capacity(FLUSH + 4096);
    let _ = write!(
        x,
        "{XML_HEAD}<worksheet xmlns=\"{NS_MAIN}\" xmlns:r=\"{NS_R}\">"
    );
    let mut pr = String::new();
    if let Some(c) = sh.tab_color {
        let _ = write!(pr, "<tabColor rgb=\"{}\"/>", argb(c));
    }
    if !sh.outline_below || !sh.outline_right {
        let _ = write!(
            pr,
            "<outlinePr summaryBelow=\"{}\" summaryRight=\"{}\"/>",
            u8::from(sh.outline_below),
            u8::from(sh.outline_right)
        );
    }
    if !pr.is_empty() {
        let _ = write!(x, "<sheetPr>{pr}</sheetPr>");
    }
    if let (Some(first), Some(last)) = (sh.cells.keys().next(), sh.cells.keys().next_back()) {
        let (mut c1, mut c2) = (u32::MAX, 0);
        for &(_, c) in sh.cells.keys() {
            c1 = c1.min(c);
            c2 = c2.max(c);
        }
        if let Some(d) = (Range {
            r1: first.0,
            c1,
            r2: last.0,
            c2,
        })
        .clipped()
        {
            let _ = write!(x, "<dimension ref=\"{}\"/>", range_ref(&d));
        }
    }
    sheet_view(&mut x, sh, si == wb.active);
    let _ = write!(
        x,
        "<sheetFormatPr defaultRowHeight=\"{}\"",
        numtext::xml(sh.default_row_height)
    );
    if let Some(w) = sh.default_col_width {
        let _ = write!(x, " defaultColWidth=\"{}\"", numtext::xml(w));
    }
    if let Some(b) = sh.base_col_width {
        let _ = write!(x, " baseColWidth=\"{}\"", b.min(255));
    }
    if sh.default_row_custom {
        x.push_str(" customHeight=\"1\"");
    }
    if sh.default_row_hidden {
        x.push_str(" zeroHeight=\"1\"");
    }
    x.push_str("/>");
    cols_xml(&mut x, sh);
    sheet_data(pkg, &mut x, sst, sh)?;
    if sh.protected {
        x.push_str("<sheetProtection sheet=\"1\" objects=\"1\" scenarios=\"1\"/>");
    }
    if let Some(a) = sh.autofilter.and_then(Range::clipped) {
        let _ = write!(x, "<autoFilter ref=\"{}\"/>", range_ref(&a));
    }
    let merges: Vec<Range> = sh.merges.iter().filter_map(|m| m.clipped()).collect();
    if !merges.is_empty() {
        let _ = write!(x, "<mergeCells count=\"{}\">", merges.len());
        for m in &merges {
            let _ = write!(x, "<mergeCell ref=\"{}\"/>", range_ref(m));
        }
        x.push_str("</mergeCells>");
    }
    cond_formats(&mut x, sh, dxfs);
    validations(&mut x, sh);
    hyperlinks(&mut x, sh, &mut rels);
    x.push_str("<pageMargins left=\"0.75\" right=\"0.75\" top=\"1\" bottom=\"1\" header=\"0.5\" footer=\"0.5\"/>");
    if let Some(id) = drawing_id {
        let _ = write!(x, "<drawing r:id=\"{id}\"/>");
    }
    if let Some(id) = legacy_id {
        let _ = write!(x, "<legacyDrawing r:id=\"{id}\"/>");
    }
    x.push_str("</worksheet>");
    pkg.write(x.as_bytes())?;
    Ok(rels)
}

/// Sheet names XLSX accepts, unique ignoring case. Names already valid and
/// unique are kept, so that readers can name sheets in formulas first.
pub(crate) fn sheet_names<'a>(names: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut used: Vec<String> = vec![];
    for (i, n) in names.enumerate() {
        let base = sanitize_sheet_name(n, i);
        let mut name = base.clone();
        let mut k = i + 1;
        while used.iter().any(|u| u.to_lowercase() == name.to_lowercase()) {
            name = format!("{}_{k}", base.chars().take(24).collect::<String>());
            k += 1;
        }
        used.push(name);
    }
    used
}

fn sanitize_sheet_name(name: &str, i: usize) -> String {
    let s: String = name
        .chars()
        .map(|c| {
            if "[]:*?/\\".contains(c) || c.is_control() {
                '_'
            } else {
                c
            }
        })
        .take(31)
        .collect();
    let s = s.trim_matches('\'').to_string();
    if s.is_empty() {
        format!("Sheet{}", i + 1)
    } else {
        s
    }
}

/// A defined name XLSX accepts: letters, digits, `_`, `.` and `\`, not a
/// cell reference.
fn valid_name(n: &str) -> bool {
    let mut ch = n.chars();
    let Some(first) = ch.next() else { return false };
    (first.is_alphabetic() || first == '_' || first == '\\')
        && n.chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '_' | '.' | '\\'))
        && parse_cell(n).is_none()
        && !matches!(
            n.to_ascii_uppercase().as_str(),
            "R" | "C" | "TRUE" | "FALSE"
        )
}

fn workbook_xml(wb: &Workbook, chart_sheets: &[bool]) -> String {
    let mut w = format!("{XML_HEAD}<workbook xmlns=\"{NS_MAIN}\" xmlns:r=\"{NS_R}\">");
    let _ = write!(
        w,
        "<workbookPr{}/>",
        if wb.date1904 { " date1904=\"1\"" } else { "" }
    );
    let active = wb.active.min(wb.sheets.len().saturating_sub(1));
    let first = wb.first_tab.min(wb.sheets.len().saturating_sub(1));
    let _ = write!(w, "<bookViews><workbookView activeTab=\"{active}\" firstSheet=\"{first}\"/></bookViews><sheets>");
    let sheet_list = sheet_names(wb.sheets.iter().map(|s| s.name.as_str()));
    for (i, (sh, name)) in wb.sheets.iter().zip(&sheet_list).enumerate() {
        let state = match sh.state {
            SheetState::Visible => "",
            SheetState::Hidden => " state=\"hidden\"",
            SheetState::VeryHidden => " state=\"veryHidden\"",
        };
        let _ = write!(
            w,
            "<sheet name=\"{}\" sheetId=\"{}\"{state} r:id=\"rId{}\"/>",
            esc(name),
            i + 1,
            i + 1
        );
    }
    w.push_str("</sheets>");
    let _ = chart_sheets;
    let mut seen = std::collections::HashSet::new();
    let mut names = String::new();
    for n in &wb.names {
        if n.formula.is_empty()
            || !valid_name(&n.name)
            || n.sheet.is_some_and(|s| s >= wb.sheets.len())
        {
            continue;
        }
        if !seen.insert((n.name.to_lowercase(), n.sheet)) {
            continue;
        }
        let _ = write!(names, "<definedName name=\"{}\"", esc(&n.name));
        if let Some(s) = n.sheet {
            let _ = write!(names, " localSheetId=\"{s}\"");
        }
        if n.hidden {
            names.push_str(" hidden=\"1\"");
        }
        let _ = write!(names, ">{}</definedName>", esc(&n.formula));
    }
    // A filter's range, as Excel names it beside the filter.
    for (i, sh) in wb.sheets.iter().enumerate() {
        let Some(a) = sh.autofilter.and_then(Range::clipped) else {
            continue;
        };
        if !seen.insert(("_xlnm._filterdatabase".into(), Some(i))) {
            continue;
        }
        let abs = |r: u32, c: u32| format!("${}${}", col_name(c), u64::from(r) + 1);
        let _ = write!(
            names,
            "<definedName name=\"_xlnm._FilterDatabase\" localSheetId=\"{i}\" hidden=\"1\">{}!{}:{}</definedName>",
            esc(&crate::formats::office::sheets::xls::formula::quote_sheet(&sheet_list[i])),
            abs(a.r1, a.c1),
            abs(a.r2, a.c2)
        );
    }
    if !names.is_empty() {
        let _ = write!(w, "<definedNames>{names}</definedNames>");
    }
    w.push_str("<calcPr calcId=\"0\"/></workbook>");
    w
}

/// Serializes `wb`; the output may take at most `max_bytes`.
pub(crate) fn write(wb: &Workbook, max_bytes: u64) -> Result<Vec<u8>> {
    if wb.sheets.is_empty() {
        return Err(Error::Malformed("no sheets".into()));
    }
    let out = Out {
        buf: Cursor::new(Vec::new()),
        limit: max_bytes,
    };
    let mut pkg = Package {
        z: zip::ZipWriter::new(out),
        content_types: vec![],
        defaults: vec![
            (
                "rels",
                "application/vnd.openxmlformats-package.relationships+xml",
            ),
            ("xml", "application/xml"),
        ],
    };
    let mut sst = Sst {
        list: vec![],
        plain: HashMap::new(),
        rich: HashMap::new(),
        count: 0,
    };
    let mut dxfs: Vec<Dxf> = vec![];
    let mut nums = Numbers::default();
    let mut chart_sheets = vec![];
    for si in 0..wb.sheets.len() {
        let sh = &wb.sheets[si];
        let rels = if sh.chart_sheet && !sh.charts.is_empty() {
            chart_sheets.push(true);
            drawing::chartsheet(&mut pkg, wb, si, &mut nums)?
        } else {
            chart_sheets.push(false);
            worksheet(&mut pkg, wb, si, &mut sst, &mut dxfs, &mut nums)?
        };
        if !rels.0.is_empty() {
            let dir = if chart_sheets[si] {
                "chartsheets"
            } else {
                "worksheets"
            };
            pkg.put(
                &format!("xl/{dir}/_rels/sheet{}.xml.rels", si + 1),
                rels.xml().as_bytes(),
            )?;
        }
    }

    pkg.part(
        "xl/workbook.xml",
        workbook_xml(wb, &chart_sheets).as_bytes(),
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
    )?;
    let mut wrels = Rels::default();
    for (i, &cs) in chart_sheets.iter().enumerate() {
        if cs {
            wrels.add(
                "chartsheet",
                format!("chartsheets/sheet{}.xml", i + 1),
                false,
            );
        } else {
            wrels.add("worksheet", format!("worksheets/sheet{}.xml", i + 1), false);
        }
    }
    wrels.add("styles", "styles.xml".into(), false);
    if !sst.list.is_empty() {
        wrels.add("sharedStrings", "sharedStrings.xml".into(), false);
    }
    pkg.put("xl/_rels/workbook.xml.rels", wrels.xml().as_bytes())?;
    pkg.part(
        "xl/styles.xml",
        styles::styles_xml(&wb.styles, &dxfs).as_bytes(),
        "application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml",
    )?;
    if !sst.list.is_empty() {
        pkg.content_types.push((
            "/xl/sharedStrings.xml".into(),
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml",
        ));
        pkg.start("xl/sharedStrings.xml")?;
        let mut s = format!(
            "{XML_HEAD}<sst xmlns=\"{NS_MAIN}\" count=\"{}\" uniqueCount=\"{}\">",
            sst.count,
            sst.list.len()
        );
        for e in &sst.list {
            s.push_str("<si>");
            s.push_str(e);
            s.push_str("</si>");
            if s.len() > FLUSH {
                pkg.write(s.as_bytes())?;
                s.clear();
            }
        }
        s.push_str("</sst>");
        pkg.write(s.as_bytes())?;
    }
    pkg.put(
        "_rels/.rels",
        format!("{XML_HEAD}<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"{REL}/officeDocument\" Target=\"xl/workbook.xml\"/></Relationships>").as_bytes(),
    )?;
    let mut ct = format!(
        "{XML_HEAD}<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">"
    );
    for (e, m) in &pkg.defaults {
        let _ = write!(ct, "<Default Extension=\"{e}\" ContentType=\"{m}\"/>");
    }
    for (p, t) in &pkg.content_types {
        let _ = write!(ct, "<Override PartName=\"{p}\" ContentType=\"{t}\"/>");
    }
    ct.push_str("</Types>");
    pkg.put("[Content_Types].xml", ct.as_bytes())?;
    let out = pkg.z.finish().map_err(zip_err)?;
    Ok(out.buf.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sheet_names_are_valid_and_unique() {
        let long = "x".repeat(40);
        let names = sheet_names(["a:b", "", "A:B", &long, &long, &long].into_iter());
        assert_eq!(names[0], "a_b");
        assert_eq!(names[1], "Sheet2");
        assert_eq!(names[2], "A_B_3");
        assert_eq!(names[3].len(), 31);
        assert_eq!(names[4], format!("{}_5", "x".repeat(24)));
        assert_eq!(names[5], format!("{}_6", "x".repeat(24)));
        // Many duplicates end, each its own name.
        let many = sheet_names(std::iter::repeat_n(long.as_str(), 300));
        let unique: std::collections::HashSet<String> =
            many.iter().map(|n| n.to_lowercase()).collect();
        assert_eq!(unique.len(), 300);
        assert!(many.iter().all(|n| n.chars().count() <= 31));
    }

    #[test]
    fn a_filter_is_named() {
        let mut wb = Workbook::new(Style::default());
        let mut sh = Sheet::new("My data".into());
        sh.autofilter = Some(Range {
            r1: 0,
            c1: 0,
            r2: 5,
            c2: 3,
        });
        wb.sheets.push(sh);
        let x = workbook_xml(&wb, &[false]);
        assert!(x.contains(r#"<definedName name="_xlnm._FilterDatabase" localSheetId="0" hidden="1">'My data'!$A$1:$D$6</definedName>"#), "{x}");
    }
}
