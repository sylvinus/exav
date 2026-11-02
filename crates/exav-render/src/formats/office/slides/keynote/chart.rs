//! Keynote charts (TSCH.ChartDrawableArchive) as DrawingML charts, through
//! an ODF chart object holding the chart's data, which the sheets module
//! converts. The chart's type and data are read; its
//! colours, titles and axis settings are not, and the chart is drawn in
//! the renderer's own style.
//!
//! TSCH.ChartDrawableArchive: drawable 1, chart (TSCH.ChartArchive, an
//! extension) 10000. ChartArchive: chart_type 1 (TSCH.ChartType),
//! series_direction 5 (1 by row, 2 by column), grid 7. ChartGridArchive:
//! row_name 1, column_name 2, grid_row 3 (value 1: numeric_value 1).
//! The numbers are those of the message definitions keynote-parser (MIT)
//! extracted from the application.

use super::Reader;
use crate::formats::office::common::iwa::proto::Msg;
use crate::formats::office::slides::error::Result;
use crate::formats::office::slides::limits::Budget;
use crate::formats::office::slides::model::*;

/// Rows and columns of data a chart is converted from.
const MAX_CELLS: usize = 1 << 16;

/// The ODF chart class and options of a TSCH.ChartType: the class, whether
/// bars lie down, whether series stack.
fn class(chart_type: u64) -> (&'static str, bool, bool) {
    match chart_type {
        2 | 13 => ("chart:bar", true, false),
        3 | 14 => ("chart:line", false, false),
        4 | 15 => ("chart:area", false, false),
        5 | 16 => ("chart:circle", false, false),
        6 | 17 => ("chart:bar", false, true),
        7 | 18 => ("chart:bar", true, true),
        8 | 19 => ("chart:area", false, true),
        9 | 23 => ("chart:scatter", false, false),
        22 | 24 => ("chart:bubble", false, false),
        25 | 26 => ("chart:ring", false, false),
        27 => ("chart:radar", false, false),
        21 => ("chart:bar", true, false),
        _ => ("chart:bar", false, false),
    }
}

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            c if (c as u32) < 0x20 => {}
            c => out.push(c),
        }
    }
    out
}

/// The ODF chart object for a type and its data: `series` are columns of
/// the table, `names` their names, `categories` the row labels.
fn odf(
    chart_type: u64,
    names: &[String],
    categories: &[String],
    series: &[Vec<Option<f64>>],
) -> String {
    let (class, horizontal, stacked) = class(chart_type);
    let rows = categories.len();
    let cols = series.len();
    let mut t = String::new();
    t.push_str("<table:table-header-rows><table:table-row><table:table-cell office:value-type=\"string\"><text:p></text:p></table:table-cell>");
    for n in names {
        t.push_str(&format!(
            "<table:table-cell office:value-type=\"string\"><text:p>{}</text:p></table:table-cell>",
            esc(n)
        ));
    }
    t.push_str("</table:table-row></table:table-header-rows><table:table-rows>");
    for (r, cat) in categories.iter().enumerate() {
        t.push_str(&format!(
            "<table:table-row><table:table-cell office:value-type=\"string\"><text:p>{}</text:p></table:table-cell>",
            esc(cat)
        ));
        for s in series {
            match s.get(r).copied().flatten() {
                Some(v) => t.push_str(&format!(
                    "<table:table-cell office:value-type=\"float\" office:value=\"{v}\"><text:p>{v}</text:p></table:table-cell>"
                )),
                None => t.push_str("<table:table-cell/>"),
            }
        }
        t.push_str("</table:table-row>");
    }
    t.push_str("</table:table-rows>");
    let col_letter = |c: usize| {
        let mut s = String::new();
        let mut n = c + 1;
        while n > 0 {
            s.insert(0, (b'A' + ((n - 1) % 26) as u8) as char);
            n = (n - 1) / 26;
        }
        s
    };
    let mut ser = String::new();
    for c in 0..cols {
        let l = col_letter(c + 1);
        ser.push_str(&format!(
            "<chart:series chart:values-cell-range-address=\"local-table.${l}$2:.${l}${}\" chart:label-cell-address=\"local-table.${l}$1\" chart:class=\"{class}\"/>",
            rows + 1
        ));
    }
    let last = col_letter(cols);
    format!(
        concat!(
            r#"<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" "#,
            r#"xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" "#,
            r#"xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" "#,
            r#"xmlns:chart="urn:oasis:names:tc:opendocument:xmlns:chart:1.0" "#,
            r#"xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0">"#,
            r#"<office:automatic-styles><style:style style:name="plot" style:family="chart">"#,
            r#"<style:chart-properties chart:vertical="{v}" chart:stacked="{s}"/></style:style></office:automatic-styles>"#,
            r#"<office:body><office:chart><chart:chart chart:class="{class}">"#,
            r#"<chart:legend chart:legend-position="end"/>"#,
            r#"<chart:plot-area chart:style-name="plot" table:cell-range-address="local-table.$A$1:.${last}${rows1}" chart:data-source-has-labels="both">"#,
            r#"<chart:axis chart:dimension="x" chart:name="primary-x"><chart:categories table:cell-range-address="local-table.$A$2:.$A${rows1}"/></chart:axis>"#,
            r#"<chart:axis chart:dimension="y" chart:name="primary-y"/>{ser}</chart:plot-area>"#,
            r#"<table:table table:name="local-table">{t}</table:table></chart:chart></office:chart></office:body></office:document-content>"#
        ),
        v = horizontal,
        s = stacked,
        class = class,
        last = last,
        rows1 = rows + 1,
        ser = ser,
        t = t
    )
}

/// A chart as a shape. `None` when its data is missing or cannot be
/// converted.
pub fn chart(r: &mut Reader, m: Msg, budget: &mut Budget) -> Result<Option<Shape>> {
    let Some(d) = m.msg(1) else { return Ok(None) };
    let Some(ch) = m.msg(10000) else {
        return Ok(None);
    };
    let Some(grid) = ch.msg(7) else {
        return Ok(None);
    };
    let by_row = ch.uint(5) != Some(2);
    let row_names: Vec<String> = grid
        .all(1)
        .filter_map(|v| match v {
            crate::formats::office::common::iwa::proto::Val::Bytes(b) => {
                Some(String::from_utf8_lossy(b).into_owned())
            }
            _ => None,
        })
        .take(MAX_CELLS)
        .collect();
    let col_names: Vec<String> = grid
        .all(2)
        .filter_map(|v| match v {
            crate::formats::office::common::iwa::proto::Val::Bytes(b) => {
                Some(String::from_utf8_lossy(b).into_owned())
            }
            _ => None,
        })
        .take(MAX_CELLS)
        .collect();
    let values: Vec<Vec<Option<f64>>> = grid
        .msgs(3)
        .take(MAX_CELLS)
        .map(|row| {
            row.msgs(1)
                .take(MAX_CELLS)
                .map(|v| v.double(1).filter(|x| x.is_finite()))
                .collect()
        })
        .collect();
    let cells: usize = values.iter().map(Vec::len).sum();
    if values.is_empty() || cells == 0 || cells > MAX_CELLS {
        return Ok(None);
    }
    // The table's columns are the series: those of the grid when its rows
    // are the series' categories (series by column), else its rows.
    let width = values.iter().map(Vec::len).max().unwrap_or(0);
    let (names, categories, series): (Vec<String>, Vec<String>, Vec<Vec<Option<f64>>>) = if by_row {
        // Each row is a series; the columns are the categories.
        let cats: Vec<String> = (0..width)
            .map(|c| col_names.get(c).cloned().unwrap_or_default())
            .collect();
        let names = (0..values.len())
            .map(|i| row_names.get(i).cloned().unwrap_or_default())
            .collect();
        (names, cats, values)
    } else {
        let cats: Vec<String> = (0..values.len())
            .map(|i| row_names.get(i).cloned().unwrap_or_default())
            .collect();
        let names = (0..width)
            .map(|c| col_names.get(c).cloned().unwrap_or_default())
            .collect();
        let series = (0..width)
            .map(|c| {
                values
                    .iter()
                    .map(|row| row.get(c).copied().flatten())
                    .collect()
            })
            .collect();
        (names, cats, series)
    };
    let (xf, _, _) = super::shapes::xfrm(d);
    budget.shape(0)?;
    let xml = odf(ch.uint(1).unwrap_or(1), &names, &categories, &series);
    budget.alloc(xml.len() as u64 * 4)?;
    match crate::formats::office::sheets::odf_chart_part(xml.as_bytes()) {
        Some(part) => return Ok(Some(Shape::new(ShapeKind::Chart(part), xf))),
        None => r.p.warn("charts that could not be converted"),
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn types_map_to_classes() {
        assert_eq!(class(1), ("chart:bar", false, false));
        assert_eq!(class(2), ("chart:bar", true, false));
        assert_eq!(class(7), ("chart:bar", true, true));
        assert_eq!(class(5), ("chart:circle", false, false));
        assert_eq!(class(0), ("chart:bar", false, false));
    }

    #[test]
    fn the_data_table_has_a_header_and_a_column_of_labels() {
        let x = odf(
            1,
            &["A & B".into()],
            &["Q1".into(), "Q2".into()],
            &[vec![Some(1.5), None]],
        );
        assert!(x.contains("<text:p>A &amp; B</text:p>"));
        assert!(x.contains(r#"office:value="1.5""#));
        assert!(x.contains("local-table.$B$2:.$B$3"));
        assert!(x.contains("<table:table-cell/>"));
    }
}
