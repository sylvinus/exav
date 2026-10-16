//! Charts held by OLE objects ([MS-PPT] 2.10.34 ExOleObjStg): the object's
//! compound file, zlib-compressed when the record's instance is 1. A chart
//! stored as an ODF package is in its "package_stream"; the shape's picture
//! is shown for any other object.

use super::records::Rec;
use crate::formats::office::slides::error::Result;
use crate::formats::office::slides::limits::Budget;

/// The object's compound file.
fn storage(stg: &Rec, budget: &mut Budget) -> Result<Vec<u8>> {
    use crate::formats::office::slides::error::Error;
    use std::io::Read;
    let max = budget.limits.max_part;
    let out = if stg.inst == 1 {
        let body = stg.data.get(4..).unwrap_or_default();
        let mut out = Vec::new();
        let n = flate2::read::ZlibDecoder::new(body)
            .take(max + 1)
            .read_to_end(&mut out);
        if n.is_err() {
            return Ok(vec![]);
        }
        if out.len() as u64 > max {
            return Err(Error::TooLarge("an embedded object"));
        }
        out
    } else {
        stg.data.to_vec()
    };
    budget.alloc(out.len() as u64)?;
    Ok(out)
}

/// The chart of an ExOleObjStg record as a DrawingML chart part. `None`
/// when the object is not a chart.
pub(super) fn chart(stg: &Rec, budget: &mut Budget) -> Result<Option<String>> {
    use crate::formats::office::common::cfb::Compound;
    let bytes = storage(stg, budget)?;
    let Some(cf) = Compound::open(&bytes) else {
        return Ok(None);
    };
    let Some(pkg) = cf.stream(&["package_stream"]) else {
        return Ok(None);
    };
    let Ok(mut zip) = crate::formats::office::slides::package::Zip::open(&pkg) else {
        return Ok(None);
    };
    let Some(content) = zip.get("content.xml", budget.limits.max_part, budget)? else {
        return Ok(None);
    };
    budget.alloc(content.len() as u64 * 4)?;
    Ok(crate::formats::office::sheets::odf_chart_part(&content))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::office::common::cfb::tests::build;
    use crate::formats::office::slides::error::Error;
    use crate::formats::office::slides::ppt::records::build::rec;
    use crate::formats::office::slides::ppt::records::read_at;
    use std::io::Write;

    const CHART: &str = r#"<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:chart="urn:oasis:names:tc:opendocument:xmlns:chart:1.0" xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0"><office:body><office:chart><chart:chart chart:class="chart:bar" svg:width="8cm" svg:height="6cm"><chart:plot-area table:cell-range-address="local-table.$A$1:.$B$2" chart:data-source-has-labels="both"><chart:axis chart:dimension="x" chart:name="primary-x"><chart:categories table:cell-range-address="local-table.$A$2:.$A$2"/></chart:axis><chart:axis chart:dimension="y" chart:name="primary-y"/><chart:series chart:values-cell-range-address="local-table.$B$2:.$B$2" chart:label-cell-address="local-table.$B$1" chart:class="chart:bar"/></chart:plot-area><table:table table:name="local-table"><table:table-header-rows><table:table-row><table:table-cell/><table:table-cell office:value-type="string"><text:p>Sales</text:p></table:table-cell></table:table-row></table:table-header-rows><table:table-rows><table:table-row><table:table-cell office:value-type="string"><text:p>Q1</text:p></table:table-cell><table:table-cell office:value-type="float" office:value="42"><text:p>42</text:p></table:table-cell></table:table-row></table:table-rows></table:table></chart:chart></office:chart></office:body></office:document-content>"#;

    fn package(content: &str) -> Vec<u8> {
        let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default();
        z.start_file("content.xml", opts).unwrap();
        z.write_all(content.as_bytes()).unwrap();
        z.finish().unwrap().into_inner()
    }

    /// An ExOleObjStg record of `storage`, compressed or not.
    fn stg(storage: &[u8], compressed: bool) -> Vec<u8> {
        if !compressed {
            return rec(0, 0, 0x1011, storage);
        }
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        z.write_all(storage).unwrap();
        let mut body = (storage.len() as u32).to_le_bytes().to_vec();
        body.extend(z.finish().unwrap());
        rec(0, 1, 0x1011, &body)
    }

    fn chart_of(record: &[u8], budget: &mut Budget) -> Result<Option<String>> {
        chart(&read_at(record, 0).unwrap(), budget)
    }

    #[test]
    fn an_odf_package_in_the_object_is_a_chart() {
        let cf = build(&[("package_stream", &package(CHART))]);
        for compressed in [true, false] {
            let mut b = Budget::new(Default::default());
            let c = chart_of(&stg(&cf, compressed), &mut b).unwrap().unwrap();
            assert!(c.contains("<c:barChart>") && c.contains("Sales"), "{c}");
        }
    }

    #[test]
    fn other_objects_and_damaged_ones_are_not_charts() {
        let mut b = Budget::new(Default::default());
        let other = build(&[("Workbook", b"BIFF")]);
        assert_eq!(chart_of(&stg(&other, true), &mut b).unwrap(), None);
        assert_eq!(
            chart_of(&stg(b"not a compound file", true), &mut b).unwrap(),
            None
        );
        let bad = rec(0, 1, 0x1011, &[9, 9, 9, 9, 1, 2, 3]);
        assert_eq!(chart_of(&bad, &mut b).unwrap(), None);
        let text = build(&[("package_stream", &package("<a/>"))]);
        assert_eq!(chart_of(&stg(&text, true), &mut b).unwrap(), None);
    }

    #[test]
    fn an_object_past_the_part_limit_is_refused() {
        let cf = build(&[("package_stream", &package(CHART))]);
        let limits = crate::formats::office::slides::Limits {
            max_part: 1024,
            ..Default::default()
        };
        let mut b = Budget::new(limits);
        let big = build(&[("package_stream", &vec![0u8; 4096])]);
        assert!(matches!(
            chart_of(&stg(&big, true), &mut b),
            Err(Error::TooLarge(_))
        ));
        // A compact object within the limit is read.
        assert!(
            chart_of(&stg(&cf, true), &mut Budget::new(Default::default()))
                .unwrap()
                .is_some()
        );
    }
}
