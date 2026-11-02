//! The text of a workbook, read from the model the readers fill (no XLSX is
//! written): a section for each sheet with its name and its cells row by row,
//! then its notes and its drawings' text.
//!
//! Left out: formula sources, defined names, styles, pictures, and number
//! formats: the model holds no displayed text, so a number is written as a
//! decimal of at most 15 significant digits (a date is its serial).

use crate::formats::office::sheets::model::*;
use crate::formats::office::sheets::numtext;
use crate::formats::office::text::{Out, Text};
use std::collections::HashSet;

/// Characters kept of a validation title or message: Excel's own limit for
/// the longest of them.
const NOTE_CHARS: usize = 255;

/// The text of `wb`, cut at `cap` bytes.
pub(super) fn of(wb: &Workbook, cap: usize) -> Text {
    let mut out = Out::new(cap);
    for sh in &wb.sheets {
        if out.full() {
            break;
        }
        let hidden = if sh.state == SheetState::Visible {
            ""
        } else {
            "hidden "
        };
        out.section(format!("{hidden}sheet \"{}\"", sh.name));
        out.line(&sh.name);
        cells(sh, &mut out);
        notes(sh, hidden, &mut out);
        drawings(sh, hidden, &mut out);
    }
    out.finish()
}

/// Where the cells of a row are written: a line to a row, a tab between
/// cells that have text.
struct Rows {
    row: Option<u32>,
    started: bool,
}

impl Rows {
    /// Starts the next cell, on a new line when `row` is not the current one.
    fn next(&mut self, out: &mut Out, row: u32) {
        if self.row != Some(row) {
            out.newline();
            self.row = Some(row);
            self.started = false;
        }
        if self.started {
            out.push("\t");
        }
        self.started = true;
    }
}

fn cells(sh: &Sheet, out: &mut Out) {
    // A link belongs to the first cell of its range. Stable: links on one
    // cell keep their order.
    let mut links: Vec<((u32, u32), &Hyperlink)> = sh
        .hyperlinks
        .iter()
        .filter_map(|h| {
            let r = h.range.clipped()?;
            Some(((r.r1, r.c1), h))
        })
        .collect();
    links.sort_by_key(|l| l.0);
    let mut links = links.into_iter().peekable();
    let mut rows = Rows {
        row: None,
        started: false,
    };
    for (&key, cell) in &sh.cells {
        // Links on cells the sheet has no value for come in their place.
        while let Some((at, h)) = links.next_if(|l| l.0 < key) {
            item(out, &mut rows, at, None, Some(h));
        }
        let link = links.next_if(|l| l.0 == key).map(|l| l.1);
        item(out, &mut rows, key, Some(cell), link);
        if out.full() {
            return;
        }
    }
    for (at, h) in links {
        item(out, &mut rows, at, None, Some(h));
        if out.full() {
            return;
        }
    }
}

/// One cell: its value, or the link's display when there is no value, with
/// the link's target after it. Nothing when it has neither text nor target.
fn item(
    out: &mut Out,
    rows: &mut Rows,
    at: (u32, u32),
    cell: Option<&Cell>,
    link: Option<&Hyperlink>,
) {
    let value = cell.map(|c| &c.value).filter(|v| has_text(v));
    let target = link.map(target).filter(|t| !t.is_empty());
    let display = link
        .and_then(|h| h.display.as_deref())
        .filter(|d| !d.trim().is_empty());
    if value.is_none() && target.is_none() {
        return;
    }
    rows.next(out, at.0);
    if let Some(t) = &target {
        out.begin_link(t);
    }
    match (value, display) {
        (Some(v), _) => push_value(out, v),
        (None, Some(d)) if target.is_some() => out.push(d),
        _ => {}
    }
    if target.is_some() {
        out.end_link();
    }
}

/// Where a link leads: its address, with the place in it after a `#`.
fn target(h: &Hyperlink) -> String {
    let url = h.url.as_deref().unwrap_or("").trim();
    let place = h.location.as_deref().unwrap_or("").trim();
    match (url.is_empty(), place.is_empty()) {
        (false, false) => format!("{url}#{place}"),
        (false, true) => url.to_string(),
        (true, false) => format!("#{place}"),
        (true, true) => String::new(),
    }
}

fn has_text(v: &Value) -> bool {
    match v {
        Value::Empty => false,
        Value::Text(t) => !t.trim().is_empty(),
        Value::Rich(runs) => runs.iter().any(|r| !r.text.trim().is_empty()),
        _ => true,
    }
}

fn push_value(out: &mut Out, v: &Value) {
    match v {
        Value::Empty => {}
        Value::Text(t) => out.push(t),
        Value::Rich(runs) => {
            for r in runs.iter() {
                out.push(&r.text);
            }
        }
        Value::Number(n) => out.push(&numtext::shortest(*n)),
        Value::Bool(b) => out.push(if *b { "TRUE" } else { "FALSE" }),
        Value::Error(e) => out.push(e.name()),
    }
}

/// Cell comments, then the prompts and messages of data validations, which a
/// person can see on selecting or filling a cell, whether or not the file
/// asks for them to be shown.
fn notes(sh: &Sheet, hidden: &str, out: &mut Out) {
    if sh.comments.is_empty() && sh.validations.is_empty() {
        return;
    }
    out.section(format!("{hidden}sheet \"{}\" comments", sh.name));
    for c in &sh.comments {
        out.line(&c.text);
        if out.full() {
            return;
        }
    }
    let mut seen = HashSet::new();
    for v in &sh.validations {
        let texts = [&v.prompt_title, &v.prompt, &v.error_title, &v.error];
        for t in texts.into_iter().flatten() {
            let t = t.trim();
            if t.is_empty() || !seen.insert(t) {
                continue;
            }
            let end = t.char_indices().nth(NOTE_CHARS).map_or(t.len(), |i| i.0);
            out.line(&t[..end]);
            if out.full() {
                return;
            }
        }
    }
}

/// The text of shapes, and the titles and series names of charts.
fn drawings(sh: &Sheet, hidden: &str, out: &mut Out) {
    if sh.shapes.is_empty() && sh.charts.is_empty() {
        return;
    }
    out.section(format!("{hidden}sheet \"{}\" drawings", sh.name));
    for s in &sh.shapes {
        out.line(&s.text.text);
    }
    for c in &sh.charts {
        let titles = [&c.title, &c.cat_title, &c.val_title];
        for t in titles.into_iter().flatten() {
            out.line(t);
        }
        for s in c.series.iter().filter_map(|s| s.name.as_deref()) {
            out.line(s);
        }
        if out.full() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::rc::Rc;

    fn book(sheets: Vec<Sheet>) -> Workbook {
        let mut wb = Workbook::new(Style::default());
        wb.sheets = sheets;
        wb
    }

    fn put(sh: &mut Sheet, r: u32, c: u32, value: Value) {
        sh.cells.insert(
            (r, c),
            Cell {
                value,
                formula: None,
                style: 0,
            },
        );
    }

    fn link(r: u32, c: u32, url: Option<&str>, display: Option<&str>) -> Hyperlink {
        Hyperlink {
            range: Range::cell(r, c),
            url: url.map(Into::into),
            location: None,
            tooltip: None,
            display: display.map(Into::into),
        }
    }

    fn labels(t: &Text) -> Vec<&str> {
        t.sections.iter().map(|s| s.label.as_str()).collect()
    }

    #[test]
    fn rows_are_lines_and_cells_are_tab_separated() {
        let mut s = Sheet::new("Data".into());
        put(&mut s, 0, 0, Value::text("Item"));
        put(&mut s, 0, 3, Value::text("Amount"));
        put(&mut s, 0, 4, Value::Empty);
        put(&mut s, 1, 1, Value::text("  "));
        put(&mut s, 2, 0, Value::text("Rent"));
        put(&mut s, 2, 1, Value::text(" "));
        put(&mut s, 2, 2, Value::Number(1635.49));
        put(&mut s, 2, 5, Value::Number(-0.5));
        let t = of(&book(vec![s]), 1000);
        assert_eq!(t.text, "Data\nItem\tAmount\nRent\t1635.49\t-0.5\n");
        assert_eq!(labels(&t), ["sheet \"Data\""]);
        assert!(!t.truncated);
    }

    #[test]
    fn values_are_written_as_a_reader_reads_them() {
        let mut s = Sheet::new("V".into());
        put(&mut s, 0, 0, Value::Bool(true));
        put(&mut s, 0, 1, Value::Bool(false));
        put(&mut s, 0, 2, Value::Error(CellError::Div0));
        put(&mut s, 0, 3, Value::Error(CellError::NA));
        let runs = vec![
            Run {
                text: "Hel".into(),
                font: None,
            },
            Run {
                text: "lo".into(),
                font: None,
            },
        ];
        put(&mut s, 0, 4, Value::Rich(Rc::from(runs)));
        put(&mut s, 0, 5, Value::Number(0.1 + 0.2));
        put(&mut s, 0, 6, Value::Number(1e20));
        let t = of(&book(vec![s]), 1000);
        assert_eq!(t.text, "V\nTRUE\tFALSE\t#DIV/0!\t#N/A\tHello\t0.3\t1E+20\n");
    }

    #[test]
    fn a_formula_is_its_cached_value() {
        let mut s = Sheet::new("F".into());
        s.cells.insert(
            (0, 0),
            Cell {
                value: Value::Number(1635.49),
                formula: Some("SUM(B2:B4)".into()),
                style: 0,
            },
        );
        s.cells.insert(
            (0, 1),
            Cell {
                value: Value::Empty,
                formula: Some("HYPERLINK(\"http://x.test\")".into()),
                style: 0,
            },
        );
        let mut wb = book(vec![s]);
        wb.names.push(DefinedName {
            name: "Auto_Open".into(),
            sheet: None,
            formula: "EXEC(\"calc.exe\")".into(),
            hidden: false,
        });
        let t = of(&wb, 1000);
        assert_eq!(t.text, "F\n1635.49\n");
    }

    #[test]
    fn a_hidden_sheet_is_text_labelled_as_hidden() {
        let mut v = Sheet::new("Shown".into());
        put(&mut v, 0, 0, Value::text("a"));
        let mut h = Sheet::new("Secret".into());
        h.state = SheetState::Hidden;
        put(&mut h, 0, 0, Value::text("b"));
        let mut vh = Sheet::new("Deeper".into());
        vh.state = SheetState::VeryHidden;
        put(&mut vh, 0, 0, Value::text("c"));
        vh.comments.push(Comment {
            row: 0,
            col: 0,
            author: String::new(),
            text: "note".into(),
            visible: false,
        });
        let t = of(&book(vec![v, h, vh]), 1000);
        assert_eq!(
            labels(&t),
            [
                "sheet \"Shown\"",
                "hidden sheet \"Secret\"",
                "hidden sheet \"Deeper\"",
                "hidden sheet \"Deeper\" comments",
            ]
        );
        assert_eq!(t.text, "Shown\na\nSecret\nb\nDeeper\nc\nnote\n");
        let s = &t.sections[1];
        assert_eq!(&t.text[s.range.clone()], "Secret\nb\n");
    }

    #[test]
    fn a_sheet_without_cells_is_its_name() {
        let t = of(&book(vec![Sheet::new("Empty".into())]), 1000);
        assert_eq!(t.text, "Empty\n");
    }

    #[test]
    fn hyperlinks_follow_the_text_of_their_first_cell() {
        let mut s = Sheet::new("L".into());
        put(&mut s, 0, 0, Value::text("Docs"));
        put(&mut s, 1, 0, Value::text("https://same.test/"));
        put(&mut s, 2, 1, Value::text("B3"));
        s.hyperlinks.push(Hyperlink {
            range: Range {
                r1: 0,
                c1: 0,
                r2: 3,
                c2: 0,
            },
            ..link(0, 0, Some("https://docs.test/x"), None)
        });
        s.hyperlinks
            .push(link(1, 0, Some("https://same.test/"), None));
        // A cell with no value takes the link's display.
        s.hyperlinks
            .push(link(2, 0, Some("mailto:a@b.test"), Some("Mail me")));
        // Nothing to show and nothing to follow.
        s.hyperlinks.push(link(4, 0, None, Some("lost")));
        // A place in the sheet.
        s.hyperlinks.push(Hyperlink {
            location: Some("Other!A1".into()),
            ..link(2, 1, None, None)
        });
        let t = of(&book(vec![s]), 1000);
        assert_eq!(
            t.text,
            "L\nDocs (https://docs.test/x)\nhttps://same.test/\n\
             Mail me (mailto:a@b.test)\tB3 (#Other!A1)\n"
        );
        assert_eq!(
            t.links,
            [
                ("Docs".to_string(), "https://docs.test/x".to_string()),
                ("Mail me".to_string(), "mailto:a@b.test".to_string()),
                ("B3".to_string(), "#Other!A1".to_string()),
            ]
        );
    }

    #[test]
    fn a_second_link_on_a_cell_is_not_lost() {
        let mut s = Sheet::new("L".into());
        put(&mut s, 0, 0, Value::text("Go"));
        s.hyperlinks
            .push(link(0, 0, Some("https://one.test/"), None));
        s.hyperlinks
            .push(link(0, 0, Some("https://two.test/"), None));
        let t = of(&book(vec![s]), 1000);
        assert_eq!(t.text, "L\nGo (https://one.test/)\t (https://two.test/)\n");
        assert_eq!(t.links.len(), 2);
    }

    #[test]
    fn comments_validations_and_drawings_are_their_own_sections() {
        let mut s = Sheet::new("N".into());
        put(&mut s, 0, 0, Value::text("cell"));
        s.comments.push(Comment {
            row: 0,
            col: 0,
            author: "Someone".into(),
            text: "first\nsecond".into(),
            visible: true,
        });
        let msg = |p: &str| Validation {
            prompt_title: Some("Title".into()),
            prompt: Some(p.into()),
            error_title: None,
            error: Some("x".repeat(400)),
            ..Default::default()
        };
        s.validations.push(msg("Pick one"));
        s.validations.push(msg("Pick one"));
        let anchor = Anchor {
            from: (0, 0, 0, 0),
            to: (1, 1, 0, 0),
        };
        let mut sh = Shape::new(anchor, "rect");
        sh.text.text = "In a box".into();
        s.shapes.push(sh);
        let mut ch = Chart::new(anchor, ChartKind::Bar);
        ch.title = Some("Sales".into());
        ch.val_title = Some("Euros".into());
        ch.series.push(ChartSeries {
            name: Some("Q1".into()),
            name_ref: Some("N!A1".into()),
            ..Default::default()
        });
        ch.series.push(ChartSeries::default());
        s.charts.push(ch);
        let t = of(&book(vec![s]), 10_000);
        assert_eq!(
            labels(&t),
            [
                "sheet \"N\"",
                "sheet \"N\" comments",
                "sheet \"N\" drawings"
            ]
        );
        let want = format!(
            "N\ncell\nfirst\nsecond\nTitle\nPick one\n{}\nIn a box\nSales\nEuros\nQ1\n",
            "x".repeat(255)
        );
        assert_eq!(t.text, want);
    }

    #[test]
    fn the_cap_cuts_the_text_and_stops_the_walk() {
        let mut s = Sheet::new("Big".into());
        for r in 0..1000 {
            put(&mut s, r, 0, Value::text("0123456789"));
        }
        let t = of(&book(vec![s, Sheet::new("Never".into())]), 100);
        assert!(t.truncated);
        assert!(t.text.len() <= 100, "{}", t.text.len());
        assert!(!t.text.contains("Never"));
        assert_eq!(labels(&t), ["sheet \"Big\""]);
        // A cap that fits it all does not truncate.
        let mut s = Sheet::new("S".into());
        put(&mut s, 0, 0, Value::text("ab"));
        let t = of(&book(vec![s]), 5);
        assert_eq!(t.text, "S\nab\n");
        assert!(!t.truncated);
    }
}
