//! ODS, OTS and flat ODS (FODS) reader (ODF 1.2 and 1.3, with the
//! calcext extensions some producers write).

mod cf;
pub(crate) mod chart;
mod draw;
pub(crate) mod formula;
mod numfmt;
mod styles;
mod table;

use crate::formats::office::common::xml::{self, Child, Node};
use crate::formats::office::sheets::error::{Error, Result};
use crate::formats::office::sheets::limits::Budget;
use crate::formats::office::sheets::model::*;
use std::collections::HashMap;
use std::io::Read;
use styles::{Props, Styles};

/// A ZIP package's members, read within the limits.
pub(crate) struct Zip<'a> {
    z: zip::ZipArchive<std::io::Cursor<&'a [u8]>>,
}

impl<'a> Zip<'a> {
    pub fn open(bytes: &'a [u8]) -> Result<Zip<'a>> {
        let z = zip::ZipArchive::new(std::io::Cursor::new(bytes))
            .map_err(|e| Error::NotFormat(format!("not a ZIP package: {e}")))?;
        Ok(Zip { z })
    }

    pub fn names(&self) -> Vec<String> {
        self.z
            .file_names()
            .take(1 << 16)
            .filter_map(|s| s.ok().map(|s| s.to_string()))
            .collect()
    }

    /// A member, `None` when absent or unreadable; past `max` bytes, an
    /// error.
    pub fn get(&mut self, name: &str, max: u64, budget: &mut Budget) -> Result<Option<Vec<u8>>> {
        let Ok(f) = self.z.by_name(name) else {
            return Ok(None);
        };
        if f.encrypted() {
            return Err(Error::Encrypted);
        }
        let mut v = Vec::new();
        let n = f.take(max + 1).read_to_end(&mut v);
        if n.is_err() {
            return Ok(None);
        }
        if v.len() as u64 > max {
            return Err(Error::TooLarge("a package part"));
        }
        budget.alloc(v.len() as u64)?;
        Ok(Some(v))
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
    pub text_styles: HashMap<String, Props>,
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
        if self.st.defs.get(name).is_some_and(|d| !d.maps.is_empty()) {
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
        let p = self.st.resolve(name);
        let i = wb.styles.add(self.st.to_style(&p));
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
    let mut st = Styles::collect(&roots);
    let body = content
        .child("office:body")
        .ok_or_else(|| Error::NotFormat("no office:body".into()))?;
    let ss = body
        .child("office:spreadsheet")
        .ok_or_else(|| Error::NotFormat("not a spreadsheet".into()))?;
    let settings = read_settings(settings);
    let default_style = {
        let p = if st.defs.contains_key("Default") {
            st.resolve("Default")
        } else {
            st.default.clone()
        };
        st.to_style(&p)
    };
    let mut wb = Workbook::new(default_style);

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
    let mut text_styles: HashMap<String, Props> = HashMap::new();
    for ((fam, name), node) in &st.other {
        if fam == "text" {
            let mut p = Props::default();
            if let Some(tp) = node.child("style:text-properties") {
                styles::text_props(tp, &st.fonts, &mut p);
            }
            text_styles.insert(name.clone(), p);
        }
    }
    let mut doc = Doc {
        st,
        fc: formula::Converter::default(),
        null,
        text_styles,
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
        if let Some(tp) = t
            .attr("table:style-name")
            .and_then(|sn| doc.st.other("table", sn))
            .and_then(|ts| ts.child("style:table-properties"))
        {
            if tp.attr("table:display") == Some("false") {
                sheet.state = SheetState::Hidden;
            }
            if let Some(c) = tp.attr("tableooo:tab-color").or(tp.attr("table:tab-color")) {
                sheet.tab_color = styles::parse_color(c).flatten();
            }
            if tp.attr("style:writing-mode") == Some("rl-tb") {
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
    if wb.sheets.is_empty() {
        return Err(Error::Malformed("no sheets".into()));
    }
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
