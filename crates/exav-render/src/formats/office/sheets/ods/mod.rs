//! ODS, OTS and flat ODS (FODS) reader (ODF 1.2 and 1.3, with the
//! calcext extensions some producers write).

mod cf;
pub(crate) mod chart;
mod draw;
pub(crate) mod formula;
mod numfmt;
mod styles;
mod table;

use crate::formats::office::common::package::MAX_NAMES;
use crate::formats::office::common::xml::{self, Child, Node};
use crate::formats::office::sheets::error::{Error, Result};
use crate::formats::office::sheets::limits::Budget;
use crate::formats::office::sheets::model::*;
use exav_unpack::package::{Package, PartError};
use std::collections::HashMap;
use styles::Styles;

/// A ZIP package's members, read within the limits.
pub(crate) struct Zip<'a>(Package<'a>);

impl<'a> Zip<'a> {
    pub fn open(bytes: &'a [u8]) -> Result<Zip<'a>> {
        Package::from_bytes(bytes)
            .map(Zip)
            .map_err(|e| Error::NotFormat(format!("not a ZIP package: {e}")))
    }

    pub fn names(&self) -> Vec<String> {
        self.0.names(MAX_NAMES)
    }

    /// A member, `None` when absent or unreadable; past `max` bytes, an
    /// error.
    pub fn get(&mut self, name: &str, max: u64, budget: &mut Budget) -> Result<Option<Vec<u8>>> {
        let part = self.0.read(name, max).map_err(|e| match e {
            PartError::Encrypted => Error::Encrypted,
            PartError::TooLarge => Error::TooLarge("a package part"),
        })?;
        if let Some(v) = &part {
            budget.alloc(v.len() as u64)?;
        }
        Ok(part)
    }
}

pub(crate) fn read_ods(bytes: &[u8], budget: &mut Budget) -> Result<Workbook> {
    let mut z = Zip::open(bytes)?;
    let max = budget.limits.max_part;
    if let Some(m) = z.get("mimetype", 256, budget)? {
        let m = String::from_utf8_lossy(&m);
        if !m.contains("spreadsheet") {
            return Err(Error::NotFormat(format!(
                "an OpenDocument file of type {}",
                m.trim()
            )));
        }
    }
    // Encrypted when content.xml is (a password on Basic libraries alone
    // encrypts only those).
    if let Some(m) = z.get("META-INF/manifest.xml", 16 << 20, budget)? {
        let m = String::from_utf8_lossy(&m);
        if let Some(i) = m.find("manifest:full-path=\"content.xml\"") {
            let entry = &m[i..];
            let end = entry
                .find("</manifest:file-entry>")
                .or_else(|| entry.find("/>"))
                .unwrap_or(entry.len());
            if entry[..end].contains("encryption-data") {
                return Err(Error::Encrypted);
            }
        }
    }
    let content = z
        .get("content.xml", max, budget)?
        .ok_or_else(|| Error::NotFormat("no content.xml".into()))?;
    let styles = z.get("styles.xml", max, budget)?;
    let settings = z.get("settings.xml", max, budget)?;
    let content = xml::parse(&content, &mut budget.tree())?;
    let styles = match styles {
        Some(s) => xml::parse(&s, &mut budget.tree()).ok(),
        None => None,
    };
    let settings = settings.and_then(|s| xml::parse(&s, &mut budget.tree()).ok());
    let mut parts: HashMap<String, Vec<u8>> = HashMap::new();
    for n in z.names() {
        let name = n.trim_start_matches("./").to_string();
        let object = name.starts_with("Object ") && name.ends_with("/content.xml");
        let picture = name.starts_with("Pictures/")
            || name.starts_with("media/")
            || name.starts_with("ObjectReplacements/");
        if (object || picture)
            && let Some(v) = z.get(&n, 64 << 20, budget)?
        {
            parts.insert(name, v);
        }
    }
    read_doc(&content, styles.as_ref(), settings.as_ref(), &parts, budget)
}

pub(crate) fn read_fods(bytes: &[u8], budget: &mut Budget) -> Result<Workbook> {
    let doc = xml::parse(bytes, &mut budget.tree())?;
    if doc.name != "office:document" {
        return Err(Error::NotFormat(format!(
            "not a flat ODF document: {}",
            doc.name
        )));
    }
    if let Some(m) = doc.attr("office:mimetype")
        && !m.contains("spreadsheet")
    {
        return Err(Error::NotFormat(format!(
            "a flat OpenDocument file of type {m}"
        )));
    }
    let settings = doc.child("office:settings");
    read_doc(&doc, None, settings, &HashMap::new(), budget)
}

// ------------------------------------------------------------ text helpers

/// The text of a node, spaces, tabs and line breaks included, notes not.
pub(crate) fn text_of(n: &Node, out: &mut String) {
    for c in &n.children {
        if out.len() > 1 << 20 {
            return;
        }
        match c {
            Child::Text(t) => out.push_str(t),
            Child::Node(x) => match x.name.as_str() {
                "text:s" => {
                    let k = x
                        .attr("text:c")
                        .and_then(|v| v.parse::<usize>().ok())
                        .unwrap_or(1)
                        .min(1000);
                    out.push_str(&" ".repeat(k));
                }
                "text:tab" => out.push('\t'),
                "text:line-break" => out.push('\n'),
                "office:annotation" | "text:note" | "office:annotation-end" => {}
                _ => text_of(x, out),
            },
        }
    }
}

/// The paragraphs of a node, joined by line feeds.
pub(crate) fn paragraphs(n: &Node) -> String {
    let mut out = String::new();
    let mut first = true;
    for p in n.nodes() {
        if matches!(p.name.as_str(), "text:p" | "text:h" | "text:list") {
            if !first {
                out.push('\n');
            }
            first = false;
            text_of(p, &mut out);
        }
    }
    out
}

pub(crate) fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// An xsd:dateTime to a serial date counted from `null`.
pub(crate) fn parse_date(s: &str, null: (i64, i64, i64)) -> Option<f64> {
    let (date, time) = match s.find('T') {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    };
    let neg = date.starts_with('-');
    let mut it = date.trim_start_matches('-').split('-');
    let mut y: i64 = it.next()?.parse().ok()?;
    if neg {
        y = -y;
    }
    let m: i64 = it.next()?.parse().ok()?;
    let d: i64 = it.next().unwrap_or("1").parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || y.abs() > 100_000 {
        return None;
    }
    let days = days_from_civil(y, m, d) - days_from_civil(null.0, null.1, null.2);
    let mut frac = 0.0;
    if let Some(t) = time {
        let t = t.trim_end_matches('Z');
        let mut p = t.split(':');
        let h: f64 = p.next().and_then(|v| v.parse().ok()).unwrap_or(0.0);
        let mi: f64 = p.next().and_then(|v| v.parse().ok()).unwrap_or(0.0);
        let se: f64 = p
            .next()
            .and_then(|v| v.split(['+', '-']).next()?.parse().ok())
            .unwrap_or(0.0);
        frac = (h * 3600.0 + mi * 60.0 + se) / 86400.0;
    }
    Some(days as f64 + frac)
}

/// "PT12H30M15S" or "P1DT2H" to a fraction of days.
pub(crate) fn parse_duration(s: &str) -> Option<f64> {
    let neg = s.starts_with('-');
    let s = s.trim_start_matches('-').strip_prefix('P')?;
    let mut days = 0.0;
    let mut num = String::new();
    let mut in_time = false;
    for c in s.chars() {
        match c {
            'T' => in_time = true,
            '0'..='9' | '.' => num.push(c),
            'D' | 'H' | 'S' | 'M' if !num.is_empty() => {
                let v: f64 = num.parse().ok()?;
                num.clear();
                days += match c {
                    'D' => v,
                    'H' => v / 24.0,
                    'M' if in_time => v / 1440.0,
                    'M' => v * 30.0,
                    _ => v / 86400.0,
                };
            }
            'Y' if !num.is_empty() => {
                days += num.parse::<f64>().ok()? * 365.0;
                num.clear();
            }
            _ => return None,
        }
    }
    Some(if neg { -days } else { days })
}

/// "Sheet1.A1" or "$Sheet1.$A$1" to (sheet, row, col).
pub(crate) fn parse_addr(s: &str) -> Option<(String, u32, u32)> {
    let s = s.trim();
    let dot = s.rfind('.')?;
    let sheet = s[..dot]
        .trim_start_matches('$')
        .trim_matches('\'')
        .replace("''", "'");
    let (r, c) = parse_cell(&s[dot + 1..])?;
    Some((sheet, r, c))
}

/// "Sheet1.A1:Sheet1.B2", "Sheet1.A1:.B2" or "Sheet1.A1" to (sheet, range).
pub(crate) fn parse_range_addr(s: &str) -> Option<(String, Range)> {
    let s = s.trim();
    let mut parts = s.splitn(2, ':');
    let a = parse_addr(parts.next()?)?;
    let b = match parts.next() {
        Some(p) if p.starts_with('.') => {
            let (r, c) = parse_cell(&p[1..])?;
            (a.0.clone(), r, c)
        }
        Some(p) => parse_addr(p)?,
        None => a.clone(),
    };
    Some((
        a.0,
        Range {
            r1: a.1.min(b.1),
            c1: a.2.min(b.2),
            r2: a.1.max(b.1),
            c2: a.2.max(b.2),
        },
    ))
}

struct Settings {
    active: Option<String>,
    per_table: HashMap<String, HashMap<String, String>>,
    global: HashMap<String, String>,
}

fn read_settings(s: Option<&Node>) -> Settings {
    let mut out = Settings {
        active: None,
        per_table: HashMap::new(),
        global: HashMap::new(),
    };
    let Some(s) = s else { return out };
    fn items(n: &Node, into: &mut HashMap<String, String>) {
        for i in n.all("config:config-item") {
            if let Some(k) = i.attr("config:name") {
                into.insert(k.to_string(), i.own_text());
            }
        }
    }
    fn walk(n: &Node, out: &mut Settings, depth: u32) {
        if depth > 32 {
            return;
        }
        for c in n.nodes() {
            if c.name == "config:config-item-map-named" && c.attr("config:name") == Some("Tables") {
                for e in c.all("config:config-item-map-entry") {
                    if let Some(name) = e.attr("config:name") {
                        let mut m = HashMap::new();
                        items(e, &mut m);
                        out.per_table.insert(name.to_string(), m);
                    }
                }
                continue;
            }
            if c.name == "config:config-item-map-entry" && out.global.is_empty() {
                items(c, &mut out.global);
            }
            walk(c, out, depth + 1);
        }
    }
    walk(s, &mut out, 0);
    out.active = out.global.get("ActiveTable").cloned();
    out
}

/// An embedded object to read once every sheet is: where it is, its
/// directory in the package, and the picture that stands for it.
pub(crate) type PendingChart = (Anchor, String, Option<Image>);

/// What reading a table needs from the document.
pub(crate) struct Doc<'a> {
    pub st: Styles,
    pub fc: formula::Converter,
    pub null: (i64, i64, i64),
    pub parts: &'a HashMap<String, Vec<u8>>,
    pub validations: HashMap<String, Validation>,
    pub style_ids: HashMap<String, u32>,
    /// The cells of the table being read whose style has conditions
    /// (style:map), by style: model styles do not tell them apart.
    pub map_cells: HashMap<String, Vec<(u32, u32)>>,
}

impl Doc<'_> {
    /// Notes the cell at `r`, `c` when its style `name` has conditions.
    pub fn note_maps(&mut self, name: Option<&str>, r: u32, c: u32) {
        let name = name.unwrap_or("Default");
        if self.st.has_maps(name) {
            self.map_cells
                .entry(name.to_string())
                .or_default()
                .push((r, c));
        }
    }

    /// The model style of a cell style, interned.
    pub fn sid(&mut self, wb: &mut Workbook, name: Option<&str>) -> u32 {
        let name = name.unwrap_or("Default");
        if let Some(&i) = self.style_ids.get(name) {
            return i;
        }
        let i = wb.styles.add(self.st.style(name));
        if self.style_ids.len() < 1 << 16 {
            self.style_ids.insert(name.to_string(), i);
        }
        i
    }
}

fn read_doc(
    content: &Node,
    styles_doc: Option<&Node>,
    settings: Option<&Node>,
    parts: &HashMap<String, Vec<u8>>,
    budget: &mut Budget,
) -> Result<Workbook> {
    let mut roots: Vec<&Node> = vec![];
    if let Some(s) = styles_doc {
        roots.push(s);
    }
    roots.push(content);
    let st = Styles::collect(&roots);
    let body = content
        .child("office:body")
        .ok_or_else(|| Error::NotFormat("no office:body".into()))?;
    let ss = body
        .child("office:spreadsheet")
        .ok_or_else(|| Error::NotFormat("not a spreadsheet".into()))?;
    let settings = read_settings(settings);
    let mut wb = Workbook::new(st.style("Default"));

    let mut null = (1899, 12, 30);
    if let Some(v) = ss
        .child("table:calculation-settings")
        .and_then(|cs| cs.child("table:null-date"))
        .and_then(|nd| nd.attr("table:date-value"))
    {
        let p: Vec<i64> = v.split('-').filter_map(|x| x.parse().ok()).collect();
        if p.len() == 3
            && (1..=12).contains(&p[1])
            && (1..=31).contains(&p[2])
            && p[0].abs() < 10_000
        {
            null = (p[0], p[1], p[2]);
        }
    }
    if null == (1904, 1, 1) {
        wb.date1904 = true;
    }
    let mut doc = Doc {
        st,
        fc: formula::Converter::default(),
        null,
        parts,
        validations: HashMap::new(),
        style_ids: HashMap::new(),
        map_cells: HashMap::new(),
    };
    if let Some(cv) = ss.child("table:content-validations") {
        for v in cv.all("table:content-validation") {
            if let (Some(name), Some(val)) =
                (v.attr("table:name"), cf::read_validation(v, &mut doc.fc))
            {
                doc.validations.insert(name.to_string(), val);
            }
        }
    }

    // The cached copies of other documents' sheets that external references
    // read from are not sheets of this one (the application does not show
    // them); a sheet linked to another document is.
    let tables: Vec<&Node> = ss
        .all("table:table")
        .filter(|t| {
            !(t.child("table:table-source").is_some()
                && t.attr("table:name")
                    .is_some_and(|n| n.starts_with('\'') && n.contains("'#")))
        })
        .collect();
    if tables.len() > budget.limits.max_sheets as usize {
        return Err(Error::TooLarge("sheets"));
    }
    let sheet_names: Vec<String> = tables
        .iter()
        .map(|t| t.attr("table:name").unwrap_or("Sheet").to_string())
        .collect();
    let mut pending_charts: Vec<Vec<PendingChart>> = vec![];
    for (ti, t) in tables.iter().enumerate() {
        let mut sheet = Sheet::new(sheet_names[ti].clone());
        sheet.default_row_height = 12.8;
        if let Some(sn) = t.attr("table:style-name") {
            let tp = doc.st.chain("table", Some(sn));
            if tp.get("table/table:display") == Some("false") {
                sheet.state = SheetState::Hidden;
            }
            if let Some(c) = tp
                .get("table/tableooo:tab-color")
                .or(tp.get("table/table:tab-color"))
            {
                sheet.tab_color = styles::parse_color(c).flatten();
            }
            if tp.get("table/style:writing-mode") == Some("rl-tb") {
                sheet.rtl = true;
            }
        }
        let mut charts = vec![];
        table::read_table(t, &mut doc, &mut wb, budget, &mut sheet, &mut charts)?;
        pending_charts.push(charts);
        if let Some(m) = settings.per_table.get(&sheet.name) {
            let g = |k: &str| m.get(k).and_then(|v| v.parse::<u32>().ok());
            let (hm, hp, vm, vp) = (
                g("HorizontalSplitMode"),
                g("HorizontalSplitPosition"),
                g("VerticalSplitMode"),
                g("VerticalSplitPosition"),
            );
            let cols = if hm == Some(2) { hp.unwrap_or(0) } else { 0 };
            let rows = if vm == Some(2) { vp.unwrap_or(0) } else { 0 };
            if rows > 0 || cols > 0 {
                sheet.freeze = Some((rows, cols));
            }
            if let Some(v) = m.get("ShowGrid") {
                sheet.show_grid = v == "true";
            }
            if let Some(z) = g("ZoomValue") {
                sheet.zoom = z;
            }
            if let Some(c) = m.get("TabColor").and_then(|v| v.parse::<i64>().ok())
                && (0..0x100_0000).contains(&c)
                && sheet.tab_color.is_none()
            {
                sheet.tab_color = Some(c as u32);
            }
        }
        if settings
            .per_table
            .get(&sheet.name)
            .and_then(|m| m.get("ShowGrid"))
            .is_none()
            && let Some(v) = settings.global.get("ShowGrid")
        {
            sheet.show_grid = v == "true";
        }
        if let Some(v) = settings.global.get("ShowZeroValues") {
            sheet.show_zeros = v == "true";
        }
        if settings.active.as_deref() == Some(sheet.name.as_str()) {
            wb.active = ti;
        }
        wb.sheets.push(sheet);
    }
    // A spreadsheet of no table (an empty template) is one ODF allows: an
    // empty workbook.
    // Charts, once every sheet's values are known.
    for (i, list) in pending_charts.into_iter().enumerate() {
        for (anchor, href, fallback) in list {
            let chart = match parts.get(&format!("{href}/content.xml")) {
                Some(xml) => chart::read(xml, anchor, &wb.sheets, &mut budget.tree())?,
                None => None,
            };
            match chart {
                Some(c) => wb.sheets[i].charts.push(c),
                None => wb.sheets[i].images.extend(fallback),
            }
        }
    }
    // Named ranges and expressions.
    let add_names = |ne: &Node,
                     scope: Option<usize>,
                     wb: &mut Workbook,
                     fc: &mut formula::Converter| {
        for n in ne.nodes() {
            let Some(name) = n.attr("table:name") else {
                continue;
            };
            let f = match n.name.as_str() {
                "table:named-range" => n
                    .attr("table:cell-range-address")
                    .map(|a| range_list(a, fc)),
                "table:named-expression" => n.attr("table:expression").and_then(|e| fc.convert(e)),
                _ => None,
            };
            if let Some(f) = f.filter(|f| !f.is_empty())
                && wb.names.len() < 1 << 16
            {
                wb.names.push(DefinedName {
                    name: name.to_string(),
                    sheet: scope,
                    formula: f,
                    hidden: false,
                });
            }
        }
    };
    if let Some(ne) = ss.child("table:named-expressions") {
        add_names(ne, None, &mut wb, &mut doc.fc);
    }
    for (ti, t) in tables.iter().enumerate() {
        if let Some(ne) = t.child("table:named-expressions") {
            add_names(ne, Some(ti), &mut wb, &mut doc.fc);
        }
    }
    if let Some(dr) = ss.child("table:database-ranges") {
        for d in dr.all("table:database-range") {
            if d.attr("table:display-filter-buttons") != Some("true") {
                continue;
            }
            if let Some((sheet, r)) = d
                .attr("table:target-range-address")
                .and_then(parse_range_addr)
                && let Some(s) = wb.sheets.iter_mut().find(|s| s.name == sheet)
            {
                s.autofilter = Some(r);
            }
        }
    }
    Ok(wb)
}

/// The addresses of a list separated by spaces; a quoted sheet name may
/// hold spaces ("'My sheet'.A1:'My sheet'.B2 Other.C3").
pub(crate) fn split_ranges(s: &str) -> impl Iterator<Item = &str> {
    let mut rest = s;
    std::iter::from_fn(move || {
        rest = rest.trim_start();
        if rest.is_empty() {
            return None;
        }
        let mut quoted = false;
        let end = rest
            .char_indices()
            .find(|&(_, c)| {
                if c == '\'' {
                    quoted = !quoted;
                }
                c.is_whitespace() && !quoted
            })
            .map_or(rest.len(), |(i, _)| i);
        let (a, b) = rest.split_at(end);
        rest = b;
        Some(a)
    })
}

/// "$Sheet1.$A$1:.$B$2 $Sheet1.C3" to "Sheet1!$A$1:$B$2,Sheet1!C3".
fn range_list(s: &str, fc: &mut formula::Converter) -> String {
    split_ranges(s)
        .take(256)
        .filter_map(|r| fc.convert(&format!("of:=[{r}]")))
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_lists_keep_quoted_spaces() {
        let v: Vec<&str> = split_ranges(" 'My sheet'.A1:'My sheet'.B2  Other.C3 ").collect();
        assert_eq!(v, ["'My sheet'.A1:'My sheet'.B2", "Other.C3"]);
        assert_eq!(
            parse_range_addr(v[0]).map(|x| x.0).as_deref(),
            Some("My sheet")
        );
    }

    #[test]
    fn style_conditions_cover_their_style_alone() {
        // ce1 has a condition, ce2 looks the same and has none.
        let fods = r##"<?xml version="1.0"?>
<office:document xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0" office:mimetype="application/vnd.oasis.opendocument.spreadsheet">
<office:styles><style:style style:name="Hot" style:family="table-cell"><style:table-cell-properties fo:background-color="#ff0000"/></style:style></office:styles>
<office:automatic-styles>
<style:style style:name="ce1" style:family="table-cell"><style:map style:condition="cell-content()&gt;5" style:apply-style-name="Hot" style:base-cell-address="S.A1"/></style:style>
<style:style style:name="ce2" style:family="table-cell"/>
</office:automatic-styles>
<office:body><office:spreadsheet><table:table table:name="S">
<table:table-row><table:table-cell table:style-name="ce1" office:value-type="float" office:value="9"/><table:table-cell table:style-name="ce2" office:value-type="float" office:value="9"/></table:table-row>
</table:table></office:spreadsheet></office:body></office:document>"##;
        let wb = read_fods(
            fods.as_bytes(),
            &mut Budget::new(crate::formats::office::sheets::limits::Limits::default()),
        )
        .unwrap();
        let cfs = &wb.sheets[0].cond_formats;
        assert_eq!(cfs.len(), 1);
        assert_eq!(cfs[0].ranges, [Range::cell(0, 0)]);
    }

    /// Checking what a styled empty cell shows along its width costs the
    /// width for each row, so it is bounded over a workbook; past the bound
    /// the formatting of the area is left out, with a warning.
    #[test]
    fn the_width_swept_for_styled_empty_cells_is_bounded() {
        let row = r#"<table:table-row table:number-rows-repeated="1025"><table:table-cell table:style-name="ce1" table:number-columns-repeated="1048576"/></table:table-row>"#;
        let fods = format!(
            r##"<?xml version="1.0"?>
<office:document xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" office:mimetype="application/vnd.oasis.opendocument.spreadsheet">
<office:automatic-styles><style:style style:name="ce1" style:family="table-cell"/></office:automatic-styles>
<office:body><office:spreadsheet><table:table table:name="S">{}<table:table-row><table:table-cell office:value-type="string"><text:p>end</text:p></table:table-cell></table:table-row></table:table></office:spreadsheet></office:body></office:document>"##,
            row.repeat(6)
        );
        let read = |sweeps: u64| {
            let limits = crate::formats::office::sheets::limits::Limits::default();
            let mut budget = Budget::new(limits).with_max_swept(sweeps << 14);
            read_fods(fods.as_bytes(), &mut budget).unwrap().warnings
        };
        assert!(read(6).is_empty());
        let warnings = read(3);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("formatting"), "{warnings:?}");
    }

    const NS: &str = r#"xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0" xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0" xmlns:number="urn:oasis:names:tc:opendocument:xmlns:datastyle:1.0""#;

    /// A flat spreadsheet of one table, with the styles and rows given.
    fn fods_of(styles: &str, auto: &str, table: &str) -> String {
        format!(
            r##"<?xml version="1.0"?>
<office:document {NS} office:mimetype="application/vnd.oasis.opendocument.spreadsheet">
<office:font-face-decls><style:font-face style:name="F1" svg:font-family="Arial"/></office:font-face-decls>
<office:styles>{styles}</office:styles>
<office:automatic-styles>{auto}</office:automatic-styles>
<office:body><office:spreadsheet><table:table table:name="S">{table}</table:table></office:spreadsheet></office:body></office:document>"##
        )
    }

    fn read(
        fods: &str,
        limits: crate::formats::office::sheets::limits::Limits,
    ) -> Result<Workbook> {
        read_fods(fods.as_bytes(), &mut Budget::new(limits))
    }

    #[test]
    fn a_style_used_many_times_is_resolved_once() {
        let fods = fods_of(
            r#"<style:style style:name="a" style:family="table-cell"><style:text-properties fo:font-weight="bold"/></style:style>
<style:style style:name="b" style:family="table-cell" style:parent-style-name="a"><style:text-properties fo:font-size="9pt"/></style:style>
<style:style style:name="T1" style:family="text"><style:text-properties fo:font-style="italic"/></style:style>"#,
            "",
            "",
        );
        let doc = xml::parse(fods.as_bytes(), &mut xml::within(1 << 20)).unwrap();
        let st = Styles::collect(&[&doc]);
        let base = st.font("b");
        for i in 0..1000 {
            assert!(st.style("b").font.bold);
            // Names that are no style resolve as one.
            st.style(&format!("missing{i}"));
            st.dxf("b", false);
            assert!(st.span_font("T1", &base).unwrap().italic);
        }
        // "b", no style, and the text style.
        assert_eq!(st.walks(), 3);
    }

    #[test]
    fn resolved_styles_count_in_the_memory_limit() {
        // 30 styles deep with 40 properties each: a style resolved from the
        // bottom holds all 1200.
        let mut styles = String::new();
        for k in 0..30 {
            let parent = match k {
                0 => String::new(),
                _ => format!(r#" style:parent-style-name="c{}""#, k - 1),
            };
            let props: String = (0..40).map(|j| format!(r#" svg:k{k}a{j}="v""#)).collect();
            styles += &format!(
                r#"<style:style style:name="c{k}" style:family="table-cell"{parent}><style:table-cell-properties{props}/></style:style>"#
            );
        }
        let leaves: String = (0..150)
            .map(|i| format!(r#"<style:style style:name="l{i}" style:family="table-cell" style:parent-style-name="c29"/>"#))
            .collect();
        let row = |name: &dyn Fn(usize) -> String| -> String {
            let cells: String = (0..150)
                .map(|i| format!(r#"<table:table-cell table:style-name="{}" office:value-type="float" office:value="1"/>"#, name(i)))
                .collect();
            format!("<table:table-row>{cells}</table:table-row>")
        };
        let limits =
            || crate::formats::office::sheets::limits::Limits::default().with_max_memory(4 << 20);
        // One style used 150 times is resolved once.
        let same = fods_of(&styles, &leaves, &row(&|_| "l0".into()));
        assert!(read(&same, limits()).is_ok());
        // 150 styles are 150 resolutions, 16 MB or so.
        let each = fods_of(&styles, &leaves, &row(&|i| format!("l{i}")));
        let err = read(&each, limits()).err();
        assert!(matches!(err, Some(Error::TooLarge("memory"))), "{err:?}");
    }

    #[test]
    fn styles_other_than_cell_styles_follow_their_parents() {
        let fods = fods_of(
            r#"<style:style style:name="co1" style:family="table-column"><style:table-column-properties style:column-width="3cm"/></style:style>
<style:style style:name="T1" style:family="text"><style:text-properties fo:font-weight="bold"/></style:style>"#,
            r#"<style:style style:name="co2" style:family="table-column" style:parent-style-name="co1"/>
<style:style style:name="T2" style:family="text" style:parent-style-name="T1"/>"#,
            r#"<table:table-column table:style-name="co2"/>
<table:table-row><table:table-cell office:value-type="string"><text:p>a<text:span text:style-name="T2">b</text:span></text:p></table:table-cell></table:table-row>"#,
        );
        let wb = read(&fods, Default::default()).unwrap();
        let s = &wb.sheets[0];
        assert!(s.cols[0].width.is_some());
        let Value::Rich(runs) = &s.cells[&(0, 0)].value else {
            panic!("{:?}", s.cells[&(0, 0)].value);
        };
        let bold: Vec<bool> = runs.iter().map(|r| r.font.as_ref().unwrap().bold).collect();
        assert_eq!(bold, [false, true]);
    }

    /// A style that sets a value replaces the one its parent set it through
    /// another attribute.
    #[test]
    fn a_style_replaces_what_its_parent_set_however_it_did() {
        let fods = fods_of(
            r##"<style:style style:name="P" style:family="table-cell"><style:table-cell-properties fo:border-bottom="2pt solid #000000"/><style:text-properties style:use-window-font-color="true" style:font-name="F1" style:text-underline-style="solid" style:text-underline-type="double"/></style:style>
<style:style style:name="C" style:family="table-cell" style:parent-style-name="P"><style:table-cell-properties fo:border="none"/><style:text-properties fo:color="#ff0000" fo:font-family="Courier" style:text-underline-style="solid"/></style:style>
<style:style style:name="D" style:family="table-cell" style:parent-style-name="P"/>"##,
            "",
            r#"<table:table-row><table:table-cell table:style-name="C" office:value-type="float" office:value="1"/><table:table-cell table:style-name="D" office:value-type="float" office:value="1"/></table:table-row>"#,
        );
        let wb = read(&fods, Default::default()).unwrap();
        let cells = &wb.sheets[0].cells;
        let c = wb.styles.get(cells[&(0, 0)].style);
        assert_eq!(c.border.bottom, Edge::default());
        assert_eq!(c.font.color, Some(0xFF0000));
        assert_eq!(c.font.name, "Courier");
        assert_eq!(c.font.underline, Some("single"));
        // The parent's own values, through the declared face.
        let d = wb.styles.get(cells[&(0, 1)].style);
        assert_eq!(d.border.bottom.style, Some("medium"));
        assert_eq!(d.font.color, None);
        assert_eq!(d.font.name, "Arial");
        assert_eq!(d.font.underline, Some("double"));
    }

    /// A percentage size is taken of the size of the parent style, or of the
    /// cell's font for a text style.
    #[test]
    fn a_percentage_size_is_taken_of_the_size_of_the_parent_style() {
        let fods = fods_of(
            r#"<style:style style:name="P" style:family="table-cell"><style:text-properties fo:font-size="20pt"/></style:style>
<style:style style:name="C" style:family="table-cell" style:parent-style-name="P"><style:text-properties fo:font-size="50%"/></style:style>
<style:style style:name="T" style:family="text"><style:text-properties fo:font-size="150%"/></style:style>"#,
            "",
            r#"<table:table-row><table:table-cell table:style-name="C" office:value-type="string"><text:p>a<text:span text:style-name="T">b</text:span></text:p></table:table-cell></table:table-row>"#,
        );
        let wb = read(&fods, Default::default()).unwrap();
        let cell = &wb.sheets[0].cells[&(0, 0)];
        assert_eq!(wb.styles.get(cell.style).font.size_centipt, 1000);
        let Value::Rich(runs) = &cell.value else {
            panic!("{:?}", cell.value);
        };
        let sizes: Vec<u32> = runs
            .iter()
            .map(|r| r.font.as_ref().map_or(1000, |f| f.size_centipt))
            .collect();
        assert_eq!(sizes, [1000, 1500]);
    }

    #[test]
    fn dates_and_durations() {
        assert_eq!(parse_date("1900-01-01", (1899, 12, 30)), Some(2.0));
        assert_eq!(
            parse_date("2024-02-29T12:00:00", (1899, 12, 30)),
            Some(45351.5)
        );
        assert_eq!(parse_date("2024-13-01", (1899, 12, 30)), None);
        assert_eq!(parse_duration("PT12H30M"), Some(0.5208333333333334));
        assert_eq!(parse_duration("-P1DT6H"), Some(-1.25));
        assert_eq!(parse_duration("PTxH"), None);
    }

    #[test]
    fn addresses() {
        assert_eq!(
            parse_range_addr("$'A b'.$B$2:.C3"),
            Some((
                "A b".into(),
                Range {
                    r1: 1,
                    c1: 1,
                    r2: 2,
                    c2: 2
                }
            ))
        );
    }
}
