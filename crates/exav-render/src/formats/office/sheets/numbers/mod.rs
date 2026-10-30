//! Apple Numbers documents of Numbers 3 (2013) and later: a ZIP, or a
//! package directory, of `Index/*.iwa` streams (in older versions inside a
//! nested `Index.zip`), each a run of Snappy-compressed protobuf archives.
//! Messages are read by field number; the numbers used are written where
//! they are read, after the message definitions numbers-parser (MIT, Jon
//! Connell) extracted from the applications. Each table becomes a sheet.
//! Numbers '08 and '09 documents, XML, are read by `v09`.
//!
//! TN.DocumentArchive (object 1): sheets 1, super 8 (TSA.DocumentArchive:
//! custom_format_list 12). TN.SheetArchive: name 1, drawable_infos 2,
//! is_hidden 25. TST.TableInfoArchive: super 1 (TSD.DrawableArchive:
//! parent 2), tableModel 2. TSD.GroupArchive: children 2.

mod cells;
mod fonts;
mod format;
mod formula;
mod functions;
mod style;
mod table;
#[cfg(test)]
mod tests;
mod v09;

use crate::formats::office::common::iwa::{self, proto};
use crate::formats::office::sheets::error::{Error, Result};
use crate::formats::office::sheets::limits::Budget;
use crate::formats::office::sheets::model::*;
use formula::TableDims;
use iwa::Store;
use proto::Msg;
use std::collections::HashMap;

const DOCUMENT: u32 = 1;
const SHEET: u32 = 2;
const TABLE_INFO: u32 = 6000;
const GROUP: u32 = 3008;
const CHART: u32 = 5021;
const IMAGE: u32 = 3005;
const CALC_ENGINE: u32 = 4000;
const OWNER_DEPS: u32 = 4008;
const CUSTOM_FORMATS: u32 = 222;

/// Reads a document saved as one file.
pub(crate) fn read(bytes: &[u8], budget: &mut Budget) -> Result<Workbook> {
    let mut z = crate::formats::office::sheets::ods::Zip::open(bytes).map_err(|_| Error::NotFormat("not a ZIP package (a Numbers document saved as a package directory must be read file by file)".into()))?;
    let names = z.names();
    check_kind(&names.iter().map(String::as_str).collect::<Vec<_>>())?;
    let max = budget.limits.max_part;
    if let Some(n) = xml_index(names.iter().map(String::as_str)) {
        let data = z.get(n, max, budget)?.unwrap_or_default();
        return read_xml(&data, budget);
    }
    let mut files: Vec<(String, Vec<u8>)> = vec![];
    if let Some(inner) = names.iter().find(|n| leaf(n) == "index.zip") {
        let data = z.get(inner, max, budget)?.unwrap_or_default();
        let mut iz = crate::formats::office::sheets::ods::Zip::open(&data)?;
        for n in iz.names() {
            if n.ends_with(".iwa")
                && let Some(d) = iz.get(&n, max, budget)?
            {
                files.push((n, d));
            }
        }
    }
    for n in &names {
        if n.ends_with(".iwa")
            && let Some(d) = z.get(n, max, budget)?
        {
            files.push((n.clone(), d));
        }
    }
    read_iwa(
        files.iter().map(|(n, d)| (n.as_str(), d.as_slice())),
        budget,
    )
}

/// Reads a package directory given as its files: relative paths and
/// contents.
pub(crate) fn read_package<'a>(
    files: &[(&'a str, &'a [u8])],
    budget: &mut Budget,
) -> Result<Workbook> {
    let names: Vec<&str> = files.iter().map(|f| f.0).collect();
    check_kind(&names)?;
    if let Some(n) = xml_index(names.iter().copied()) {
        let data = files.iter().find(|f| f.0 == n).map_or(&[][..], |f| f.1);
        return read_xml(data, budget);
    }
    let mut all: Vec<(String, Vec<u8>)> = vec![];
    if let Some((_, data)) = files.iter().find(|f| leaf(f.0) == "index.zip") {
        let max = budget.limits.max_part;
        let mut iz = crate::formats::office::sheets::ods::Zip::open(data)?;
        for n in iz.names() {
            if n.ends_with(".iwa")
                && let Some(d) = iz.get(&n, max, budget)?
            {
                all.push((n, d));
            }
        }
    }
    let iwa = files
        .iter()
        .filter(|f| f.0.ends_with(".iwa"))
        .map(|f| (f.0, f.1));
    let nested = all.iter().map(|(n, d)| (n.as_str(), d.as_slice()));
    read_iwa(iwa.chain(nested), budget)
}

/// The last component of a package path, folded to lower case: a zipped
/// package may hold the package directory itself.
fn leaf(name: &str) -> String {
    name.rsplit('/').next().unwrap_or(name).to_ascii_lowercase()
}

/// Refuses encrypted documents: a password verifier, `.iwpv2`, or hint,
/// `.iwph`.
fn check_kind(names: &[&str]) -> Result<()> {
    if names
        .iter()
        .any(|n| matches!(leaf(n).as_str(), ".iwpv2" | ".iwph"))
    {
        return Err(Error::Encrypted);
    }
    Ok(())
}

/// The XML of a Numbers '08 or '09 document, `index.xml` or
/// `index.xml.gz`, the one nearest the package root.
fn xml_index<'a>(names: impl Iterator<Item = &'a str>) -> Option<&'a str> {
    names
        .filter(|n| matches!(leaf(n).as_str(), "index.xml" | "index.xml.gz"))
        .min_by_key(|n| n.matches('/').count())
}

/// Reads a Numbers '08 or '09 document's XML, gzipped or not.
fn read_xml(data: &[u8], budget: &mut Budget) -> Result<Workbook> {
    use std::io::Read;
    if !data.starts_with(&[0x1F, 0x8B]) {
        return v09::read(data, budget);
    }
    let max = budget.limits.max_part;
    let mut xml = Vec::new();
    flate2::read::MultiGzDecoder::new(data)
        .take(max + 1)
        .read_to_end(&mut xml)
        .map_err(|e| Error::Malformed(format!("gzip: {e}")))?;
    if xml.len() as u64 > max {
        return Err(Error::TooLarge("a package part"));
    }
    budget.alloc(xml.len() as u64)?;
    v09::read(&xml, budget)
}

fn read_iwa<'a>(
    files: impl Iterator<Item = (&'a str, &'a [u8])>,
    budget: &mut Budget,
) -> Result<Workbook> {
    let mut store = Store::default();
    for (_, data) in files {
        let left = budget.limits.max_part.min(budget.limits.max_memory) as usize;
        let used = store.add(data, left);
        budget.alloc(used as u64 * 2)?;
    }
    let doc = store
        .typed(1, DOCUMENT)
        .or_else(|| {
            store
                .ids_of(DOCUMENT)
                .first()
                .and_then(|&i| store.typed(i, DOCUMENT))
        })
        .ok_or_else(|| {
            Error::NotFormat(
                "no Numbers document object (not a Numbers file, or a damaged one)".into(),
            )
        })?;
    convert(&store, doc, budget)
}

struct TableRef {
    model: u64,
    sheet: usize,
    name: String,
}

/// The tables of a drawable, in drawing order: a table, or a group's.
fn collect_tables(
    store: &Store,
    id: u64,
    out: &mut Vec<u64>,
    skipped: &mut Vec<&'static str>,
    depth: u32,
) {
    let Some((kind, m)) = store.get(id) else {
        return;
    };
    match kind {
        TABLE_INFO => {
            if let Some(t) = m.reference(2) {
                out.push(t);
            }
        }
        GROUP if depth < 16 => {
            for c in m.references(2).take(4096) {
                collect_tables(store, c, out, skipped, depth + 1);
            }
        }
        CHART => skipped.push("charts"),
        IMAGE => skipped.push("pictures"),
        _ => {}
    }
}

fn convert(store: &Store, doc: Msg, budget: &mut Budget) -> Result<Workbook> {
    let mut wb = Workbook::new(Style {
        font: Font {
            name: "Helvetica Neue".into(),
            ..Font::default()
        },
        align: Align {
            vertical: Some("top"),
            wrap: true,
            ..Align::default()
        },
        ..Style::default()
    });
    let mut tables: Vec<TableRef> = vec![];
    let mut sheet_names: Vec<(String, bool)> = vec![];
    let mut skipped = vec![];
    for (si, sid) in doc.references(1).take(4096).enumerate() {
        let Some(sh) = store.typed(sid, SHEET) else {
            continue;
        };
        let name = sh.string(1).unwrap_or_else(|| format!("Sheet {}", si + 1));
        let mut ids = vec![];
        for d in sh.references(2).take(1 << 16) {
            collect_tables(store, d, &mut ids, &mut skipped, 0);
        }
        if ids.is_empty() {
            // Older documents list only some drawables: tables name their sheet.
            for ti in store.ids_of(TABLE_INFO) {
                if let Some(m) = store.typed(ti, TABLE_INFO)
                    && m.msg(1).and_then(|s| s.reference(2)) == Some(sid)
                {
                    ids.extend(m.reference(2));
                }
            }
        }
        let k = sheet_names.len();
        sheet_names.push((name, sh.boolean(25).unwrap_or(false)));
        for t in ids {
            if tables.iter().any(|x| x.model == t) {
                continue;
            }
            let tname = store.get(t).and_then(|m| m.1.string(8)).unwrap_or_default();
            tables.push(TableRef {
                model: t,
                sheet: k,
                name: tname,
            });
        }
    }
    skipped.sort_unstable();
    skipped.dedup();
    for s in skipped {
        wb.warn(format!("{s} are not converted"));
    }
    if tables.is_empty() {
        return Err(Error::Unsupported(
            "a Numbers document without tables".into(),
        ));
    }
    if tables.len() > budget.limits.max_sheets as usize {
        return Err(Error::TooLarge("sheets"));
    }

    // A sheet with one table is named after the sheet, others "Sheet -
    // Table".
    let raw: Vec<String> = tables
        .iter()
        .map(|t| {
            let (sname, _) = &sheet_names[t.sheet];
            if tables.iter().filter(|x| x.sheet == t.sheet).count() == 1 {
                sname.clone()
            } else {
                format!("{sname} - {}", t.name)
            }
        })
        .collect();
    let names = crate::formats::office::sheets::xlsx::sheet_names(raw.iter().map(String::as_str));
    let dims: Vec<TableDims> = tables
        .iter()
        .zip(&names)
        .map(|(t, n)| {
            let m = store.get(t.model).map(|m| m.1).unwrap_or_default();
            let rows = (m.uint(6).unwrap_or(0) as u32).min(MAX_ROW + 1);
            let cols = (m.uint(7).unwrap_or(0) as u32).min(MAX_COL + 1);
            TableDims {
                name: n.clone(),
                rows,
                cols,
                header_rows: (m.uint(9).unwrap_or(0) as u32).min(rows),
                header_cols: (m.uint(10).unwrap_or(0) as u32).min(cols),
                footer_rows: (m.uint(11).unwrap_or(0) as u32).min(rows),
            }
        })
        .collect();
    let by_uuid = table_uuids(store, &tables);
    let custom_formats = custom_formats(store, doc);
    let merges = merge_owners(store, &by_uuid);
    let mut cx = table::Cx {
        store,
        tables: dims,
        by_uuid,
        custom_formats,
        merges,
        cell_props: HashMap::new(),
        text_props: HashMap::new(),
    };
    for (i, t) in tables.iter().enumerate() {
        let mut sheet = Sheet::new(cx.tables[i].name.clone());
        sheet.show_grid = false;
        if sheet_names[t.sheet].1 {
            sheet.state = SheetState::Hidden;
        }
        if let Some((_, m)) = store.get(t.model) {
            table::read_table(&mut cx, i, m, &mut sheet, &mut wb, budget)?;
        }
        wb.sheets.push(sheet);
    }
    if wb.sheets.iter().all(|s| s.state != SheetState::Visible)
        && let Some(s) = wb.sheets.first_mut()
    {
        s.state = SheetState::Visible;
    }
    wb.active = wb
        .sheets
        .iter()
        .position(|s| s.state == SheetState::Visible)
        .unwrap_or(0);
    Ok(wb)
}

/// The UUIDs cross-table references name tables by. A table's formula
/// owner (TSCE.FormulaOwnerDependenciesArchive: formula_owner_uid 1,
/// owner_kind 3, formula_owner 11, base_owner_uid 12) of kind 1 names the
/// table model; one of kind 35 (a "haunted" owner) maps the table's
/// haunted_owner UUID to the base UUID references use.
fn table_uuids(store: &Store, tables: &[TableRef]) -> HashMap<u128, usize> {
    let index: HashMap<u64, usize> = tables
        .iter()
        .enumerate()
        .map(|(i, t)| (t.model, i))
        .collect();
    let mut haunted: HashMap<u128, u128> = HashMap::new();
    let mut out = HashMap::new();
    for id in store.ids_of(OWNER_DEPS) {
        let Some(m) = store.typed(id, OWNER_DEPS) else {
            continue;
        };
        let Some(uid) = m.msg(1).and_then(formula::uuid) else {
            continue;
        };
        match m.uint(3).unwrap_or(0) {
            1 => {
                if let Some(&t) = m.reference(11).and_then(|o| index.get(&o)) {
                    out.insert(uid, t);
                }
            }
            35 => {
                if let Some(base) = m.msg(12).and_then(formula::uuid) {
                    haunted.insert(uid, base);
                }
            }
            _ => {}
        }
    }
    for (i, t) in tables.iter().enumerate() {
        let owner = store
            .get(t.model)
            .and_then(|m| m.1.msg(84))
            .and_then(|h| h.msg(1))
            .and_then(formula::uuid);
        if let Some(base) = owner.and_then(|o| haunted.get(&o)) {
            out.insert(*base, i);
        }
    }
    out
}

/// Merged ranges as some documents record them: a formula owner of kind 5
/// whose range_dependencies 5 hold back_dependency 2 entries, each an
/// internal_range_reference 4 (owner_id 1, range 2: top_left_column 1,
/// top_left_row 2, bottom_right_column 3, bottom_right_row 4). The owner
/// id is an index into the calculation engine's map (TSCE.
/// CalculationEngineArchive: dependency_tracker 2, owner_id_map 3,
/// map_entry 1: internal_owner_id 1, owner_id 2) of table UUIDs.
fn merge_owners(
    store: &Store,
    by_uuid: &HashMap<u128, usize>,
) -> HashMap<usize, Vec<(u32, u32, u32, u32)>> {
    let mut out: HashMap<usize, Vec<(u32, u32, u32, u32)>> = HashMap::new();
    let mut owners: HashMap<u64, u128> = HashMap::new();
    for ce in store.ids_of(CALC_ENGINE) {
        let Some(m) = store.typed(ce, CALC_ENGINE) else {
            continue;
        };
        for e in m
            .msg(2)
            .and_then(|t| t.msg(3))
            .into_iter()
            .flat_map(|o| o.msgs(1))
        {
            if let (Some(i), Some(u)) = (e.uint(1), e.msg(2).and_then(formula::cfuuid)) {
                owners.insert(i, u);
            }
        }
    }
    for id in store.ids_of(OWNER_DEPS) {
        let Some(m) = store.typed(id, OWNER_DEPS) else {
            continue;
        };
        if m.uint(3) != Some(5) {
            continue;
        }
        for dep in m.msg(5).into_iter().flat_map(|r| r.msgs(2)).take(1 << 16) {
            let Some(rr) = dep.msg(4) else { continue };
            let Some(&t) = rr
                .uint(1)
                .and_then(|o| owners.get(&o))
                .and_then(|u| by_uuid.get(u))
            else {
                continue;
            };
            let Some(r) = rr.msg(2) else { continue };
            let v = |n| r.uint(n).map(|x| x as u32);
            if let (Some(c1), Some(r1), Some(c2), Some(r2)) = (v(1), v(2), v(3), v(4)) {
                out.entry(t).or_default().push((r1, c1, r2, c2));
            }
        }
    }
    out
}

/// TSK.CustomFormatListArchive (uuids 1, custom_formats 2): UUID to format.
fn custom_formats<'a>(store: &'a Store, doc: Msg<'a>) -> HashMap<u128, Msg<'a>> {
    let mut out = HashMap::new();
    let list = doc
        .msg(8)
        .and_then(|s| s.reference(12))
        .and_then(|i| store.get(i))
        .map(|o| o.1)
        .or_else(|| {
            store
                .ids_of(CUSTOM_FORMATS)
                .first()
                .and_then(|&i| store.typed(i, CUSTOM_FORMATS))
        });
    if let Some(l) = list {
        for (u, f) in l.msgs(1).zip(l.msgs(2)) {
            if let Some(u) = formula::uuid(u) {
                out.insert(u, f);
            }
        }
    }
    out
}
