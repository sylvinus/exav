//! What a converter holds, against what its limits say it holds.
//!
//! `Limits::max_memory` is an estimate the converter keeps as it builds its
//! model: so much a paragraph, a shape, a cell, a tree node. An estimate that
//! drifts from what the model really takes turns the limit into a number that
//! protects nothing, and the scanner's own memory bound (the scan's budget is
//! handed to these limits) with it. Each test here makes a document of one
//! kind of unit, as many as the limit admits, and counts what the conversion
//! allocated at its peak. The peak has to be within a small factor of the
//! limit: the factor is the estimate's slack (the allocator's rounding, the
//! output beside the model), not an excuse for ten times.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Counting;

static NOW: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            let now = NOW.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        unsafe { System.dealloc(p, layout) };
        NOW.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, p: *mut u8, layout: Layout, new: usize) -> *mut u8 {
        let q = unsafe { System.realloc(p, layout, new) };
        if !q.is_null() {
            if new >= layout.size() {
                let now =
                    NOW.fetch_add(new - layout.size(), Ordering::Relaxed) + new - layout.size();
                PEAK.fetch_max(now, Ordering::Relaxed);
            } else {
                NOW.fetch_sub(layout.size() - new, Ordering::Relaxed);
            }
        }
        q
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// The counters are the process's: one test measures at a time.
static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// What `f` allocated at its peak, beyond what was held when it began. What it
/// returns is kept alive until the measure is taken.
fn peak_of<T>(f: impl FnOnce() -> T) -> (usize, T) {
    let before = NOW.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let out = f();
    (PEAK.load(Ordering::Relaxed).saturating_sub(before), out)
}

/// The most the limit may be exceeded by in practice.
const SLACK: f64 = 2.0;

/// Makes the document of `n` units, converts it under `limit` bytes of
/// memory, and says what the conversion allocated at its peak, or `None` when
/// it was refused.
type Probe = dyn Fn(usize, u64) -> Option<usize>;

/// The largest `n` in `1..=max` the probe admits, by bisection (admitting is
/// monotone in `n`), and the peak of that conversion.
fn largest(probe: &Probe, max: usize, limit: u64) -> (usize, usize) {
    let (mut lo, mut hi) = (1usize, max);
    let mut best = (0, 0);
    while lo <= hi {
        let mid = lo + (hi - lo) / 2;
        match probe(mid, limit) {
            Some(peak) => {
                best = (mid, peak);
                lo = mid + 1;
            }
            None => hi = mid - 1,
        }
    }
    best
}

/// A conversion admitted at the limit must stay within [`SLACK`] times it.
fn within_the_limit(what: &str, probe: &Probe, max: usize) {
    within_the_limit_of(what, probe, max, 32 << 20);
}

/// As [`within_the_limit`], under `limit` bytes: for a unit so small that the
/// largest document the test can build is under the usual limit.
fn within_the_limit_of(what: &str, probe: &Probe, max: usize, limit: u64) {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let (n, peak) = largest(probe, max, limit);
    eprintln!(
        "{what}: {n} units admitted at {} MiB, peak {:.1} MiB ({:.2}x)",
        limit >> 20,
        peak as f64 / (1 << 20) as f64,
        peak as f64 / limit as f64
    );
    assert!(n > 0, "{what}: not even one unit was admitted");
    assert!(
        (peak as f64) <= SLACK * limit as f64,
        "{what}: the limit is {limit} bytes and the conversion held {peak} at {n} units"
    );
}

mod docs {
    use super::*;
    use exav_render::docs::{Error, Format, Limits, convert};

    fn at(input: &[u8], format: Format, limit: u64) -> Option<usize> {
        let limits = Limits::default().with_max_memory(limit);
        let (peak, out) = peak_of(|| convert(input, format, &limits));
        match out {
            Ok(_) => Some(peak),
            Err(Error::TooLarge(_)) => None,
            Err(e) => panic!("the document was not read: {e}"),
        }
    }

    #[test]
    fn a_flat_odt_of_paragraphs() {
        within_the_limit(
            "fodt paragraphs",
            &|n, limit| {
                let mut s = String::from(
                    "<?xml version=\"1.0\"?><office:document \
                     xmlns:office=\"urn:oasis:names:tc:opendocument:xmlns:office:1.0\" \
                     xmlns:text=\"urn:oasis:names:tc:opendocument:xmlns:text:1.0\" \
                     office:mimetype=\"application/vnd.oasis.opendocument.text\">\
                     <office:body><office:text>",
                );
                for _ in 0..n {
                    s.push_str("<text:p>a</text:p>");
                }
                s.push_str("</office:text></office:body></office:document>");
                at(s.as_bytes(), Format::Fodt, limit)
            },
            2_000_000,
        );
    }

    #[test]
    fn a_flat_odt_of_text() {
        within_the_limit(
            "fodt text",
            &|n, limit| {
                let mut s = String::from(
                    "<?xml version=\"1.0\"?><office:document \
                     xmlns:office=\"urn:oasis:names:tc:opendocument:xmlns:office:1.0\" \
                     xmlns:text=\"urn:oasis:names:tc:opendocument:xmlns:text:1.0\" \
                     office:mimetype=\"application/vnd.oasis.opendocument.text\">\
                     <office:body><office:text>",
                );
                let line = "a".repeat(20_000);
                for _ in 0..n {
                    s.push_str("<text:p>");
                    s.push_str(&line);
                    s.push_str("</text:p>");
                }
                s.push_str("</office:text></office:body></office:document>");
                at(s.as_bytes(), Format::Fodt, limit)
            },
            4_000,
        );
    }

    #[test]
    fn an_rtf_of_paragraphs() {
        within_the_limit(
            "rtf paragraphs",
            &|n, limit| {
                let mut s = String::from("{\\rtf1\\ansi ");
                for _ in 0..n {
                    s.push_str("a\\par ");
                }
                s.push('}');
                at(s.as_bytes(), Format::Rtf, limit)
            },
            4_000_000,
        );
    }

    #[test]
    fn an_rtf_of_text() {
        within_the_limit(
            "rtf text",
            &|n, limit| {
                let line = "a".repeat(20_000);
                let mut s = String::from("{\\rtf1\\ansi ");
                for _ in 0..n {
                    s.push_str(&line);
                    s.push_str("\\par ");
                }
                s.push('}');
                at(s.as_bytes(), Format::Rtf, limit)
            },
            4_000,
        );
    }

    #[test]
    fn a_word_2003_xml_of_paragraphs() {
        within_the_limit(
            "wml paragraphs",
            &|n, limit| {
                let mut s = String::from(
                    "<w:wordDocument xmlns:w=\"http://schemas.microsoft.com/office/word/2003/wordml\">\
                     <w:body>",
                );
                for _ in 0..n {
                    s.push_str("<w:p><w:r><w:t>a</w:t></w:r></w:p>");
                }
                s.push_str("</w:body></w:wordDocument>");
                at(s.as_bytes(), Format::Wml2003, limit)
            },
            2_000_000,
        );
    }

    #[test]
    fn a_word_2003_xml_of_text() {
        within_the_limit(
            "wml text",
            &|n, limit| {
                let line = "a".repeat(20_000);
                let mut s = String::from(
                    "<w:wordDocument xmlns:w=\"http://schemas.microsoft.com/office/word/2003/wordml\">\
                     <w:body>",
                );
                for _ in 0..n {
                    s.push_str("<w:p><w:r><w:t>");
                    s.push_str(&line);
                    s.push_str("</w:t></w:r></w:p>");
                }
                s.push_str("</w:body></w:wordDocument>");
                at(s.as_bytes(), Format::Wml2003, limit)
            },
            4_000,
        );
    }
}

mod word6 {
    use super::*;
    use exav_render::docs::{Error, Format, Limits, convert};
    use exav_render::formats::office::test_util::build_cfb;

    /// A Word 6 document of `n` one-letter paragraphs, its text in one piece.
    fn doc6(n: usize) -> Vec<u8> {
        let text = b"X\r".repeat(n);
        let mut wd = vec![0u8; 512];
        wd[0..2].copy_from_slice(&0xA5DBu16.to_le_bytes());
        wd[2..4].copy_from_slice(&0x0065u16.to_le_bytes());
        // Complex, not encrypted.
        wd[10..12].copy_from_slice(&0x0004u16.to_le_bytes());
        wd[28..32].copy_from_slice(&(text.len() as u32).to_le_bytes());
        wd[52..56].copy_from_slice(&((n * 2) as i32).to_le_bytes());
        let mut plc = vec![0u8, 0];
        plc.extend(531u32.to_le_bytes());
        plc.extend([0u8, 0]);
        let mut clx = vec![2u8];
        clx.extend((plc.len() as u16).to_le_bytes());
        clx.extend(plc);
        wd[352..356].copy_from_slice(&512u32.to_le_bytes());
        wd[356..360].copy_from_slice(&(clx.len() as u32).to_le_bytes());
        wd.extend(clx);
        wd.extend(text);
        build_cfb(&[("WordDocument", &wd)])
    }

    #[test]
    fn paragraphs() {
        within_the_limit(
            "doc (Word 6) paragraphs",
            &|n, limit| {
                let input = doc6(n);
                let limits = Limits::default().with_max_memory(limit);
                let (peak, out) = peak_of(|| convert(&input, Format::Doc, &limits));
                match out {
                    Ok(_) => Some(peak),
                    Err(Error::TooLarge(_)) => None,
                    Err(e) => panic!("the document was not read: {e}"),
                }
            },
            400_000,
        );
    }
}

mod slides {
    use super::*;
    use exav_render::formats::office::test_util::build_cfb;
    use exav_render::slides::{Error, Format, Limits, convert};

    fn rec(typ: u32, flag: u32, id: u32, body: &[u8]) -> Vec<u8> {
        let mut v = vec![];
        for x in [typ, flag, body.len() as u32, id] {
            v.extend(x.to_le_bytes());
        }
        v.extend(body);
        v
    }

    fn container(typ: u32, kids: &[Vec<u8>]) -> Vec<u8> {
        rec(typ, 0xFFFF, 0, &kids.concat())
    }

    fn i32s(v: &[i32]) -> Vec<u8> {
        v.iter().flat_map(|x| x.to_le_bytes()).collect()
    }

    /// A PowerPoint 95 stream of one slide holding `n` filled hexagons.
    fn stream(n: usize) -> Vec<u8> {
        let mut look = vec![0u8; 56];
        look[12] = 0;
        look[13] = 1;
        let shape = container(
            0x0BC0,
            &[
                rec(0x0BC1, 0, 0, &i32s(&[5, 0, 0, 0, 0, 100, 100, 0, 0, 0])),
                rec(0x0BBD, 0, 0, &look),
            ],
        );
        let shapes: Vec<Vec<u8>> = (0..n).map(|_| shape.clone()).collect();
        let atom = rec(0x03E9, 0, 0, &i32s(&[5760, 4320]));
        let slide = container(0x03EE, &[container(0x0BB8, &shapes)]);
        let doc = container(0x03E8, &[atom, container(0x07D0, &[slide])]);
        container(3, &[doc])
    }

    #[test]
    fn shapes() {
        // A shape is 150 bytes of file and well over 400 of memory, so the
        // limit is one the largest file the builder writes (7 MB: past it the
        // compound file needs a DIFAT) goes past.
        within_the_limit_of(
            "ppt (95) shapes",
            &|n, limit| {
                let input = build_cfb(&[("PowerPoint Document", &stream(n))]);
                let limits = Limits::default().with_max_memory(limit);
                let (peak, out) = peak_of(|| convert(&input, Format::Ppt, &limits));
                match out {
                    Ok(_) => Some(peak),
                    Err(Error::TooLarge(_)) => None,
                    Err(e) => panic!("the presentation was not read: {e}"),
                }
            },
            45_000,
            8 << 20,
        );
    }
}

mod sheets {
    use super::*;
    use exav_render::sheets::{Error, Format, Limits, convert};

    fn record(id: u16, body: &[u8]) -> Vec<u8> {
        let mut v = id.to_le_bytes().to_vec();
        v.extend((body.len() as u16).to_le_bytes());
        v.extend(body);
        v
    }

    /// A BIFF8 workbook of one sheet of `n` shared-string cells.
    fn workbook(n: usize) -> Vec<u8> {
        let bof = |dt: u16| {
            let mut b = vec![];
            b.extend(0x0600u16.to_le_bytes());
            b.extend(dt.to_le_bytes());
            b.extend([0u8; 12]);
            record(0x0809, &b)
        };
        let mut sst = vec![];
        sst.extend(1u32.to_le_bytes());
        sst.extend(1u32.to_le_bytes());
        sst.extend([1, 0, 0, b'a']);
        // The globals, with the sheet's BOF where the BOUNDSHEET says: the
        // length of the globals does not depend on the offset.
        let globals = |at: usize| {
            let mut out = bof(0x0005);
            out.extend(record(0x00FC, &sst));
            let mut bound = vec![];
            bound.extend((at as u32).to_le_bytes());
            bound.extend([0, 0, 1, 0, b'S']);
            out.extend(record(0x0085, &bound));
            out.extend(record(0x000A, &[]));
            out
        };
        let mut out = globals(globals(0).len());
        out.extend(bof(0x0010));
        for i in 0..n {
            let mut c = vec![];
            c.extend(((i / 200) as u16).to_le_bytes());
            c.extend(((i % 200) as u16).to_le_bytes());
            c.extend(0u16.to_le_bytes());
            c.extend(0u32.to_le_bytes());
            out.extend(record(0x00FD, &c));
        }
        out.extend(record(0x000A, &[]));
        out
    }

    /// The spreadsheet name of column `n` (1 is `A`, 27 is `AA`).
    fn column_name(mut n: usize) -> String {
        let mut name = Vec::new();
        while n > 0 {
            n -= 1;
            name.push(b'A' + (n % 26) as u8);
            n /= 26;
        }
        name.reverse();
        String::from_utf8(name).unwrap()
    }

    /// An ODS of 10,000 text cells and a chart of `n` series over all of them.
    fn chart_ods(n: usize) -> Vec<u8> {
        chart_ods_of(n, 20, 500)
    }

    /// An ODS of `cols` by `rows` text cells and a chart of `n` series over
    /// all of them.
    fn chart_ods_of(n: usize, cols: usize, rows: usize) -> Vec<u8> {
        use std::io::Write as _;
        let range = format!("Sheet.A1:.{}{rows}", column_name(cols));
        let ns = "xmlns:office=\"urn:oasis:names:tc:opendocument:xmlns:office:1.0\" \
                  xmlns:table=\"urn:oasis:names:tc:opendocument:xmlns:table:1.0\" \
                  xmlns:text=\"urn:oasis:names:tc:opendocument:xmlns:text:1.0\" \
                  xmlns:draw=\"urn:oasis:names:tc:opendocument:xmlns:drawing:1.0\" \
                  xmlns:chart=\"urn:oasis:names:tc:opendocument:xmlns:chart:1.0\" \
                  xmlns:xlink=\"http://www.w3.org/1999/xlink\"";
        let cell = format!(
            "<table:table-cell office:value-type=\"string\"><text:p>{}</text:p></table:table-cell>",
            "A".repeat(40)
        );
        let mut content = format!(
            "<?xml version=\"1.0\"?><office:document-content {ns}><office:body><office:spreadsheet>\
             <table:table table:name=\"Sheet\"><table:table-column table:number-columns-repeated=\"{cols}\"/>"
        );
        for r in 0..rows {
            content.push_str("<table:table-row>");
            content.push_str(&cell.repeat(cols));
            if r == 0 {
                content.push_str(
                    "<table:table-cell><draw:frame draw:name=\"c1\"><draw:object xlink:href=\"./Object 1\"/>\
                     </draw:frame></table:table-cell>",
                );
            }
            content.push_str("</table:table-row>");
        }
        content.push_str(
            "</table:table></office:spreadsheet></office:body></office:document-content>",
        );
        let series = format!(
            "<chart:series chart:values-cell-range-address=\"{range}\" \
             chart:label-cell-address=\"Sheet.A1\"/>"
        )
        .repeat(n);
        let chart = format!(
            "<?xml version=\"1.0\"?><office:document-content {ns}><office:body><office:chart>\
             <chart:chart chart:class=\"chart:bar\"><chart:plot-area><chart:axis chart:dimension=\"x\">\
             <chart:categories table:cell-range-address=\"{range}\"/></chart:axis>{series}\
             </chart:plot-area></chart:chart></office:chart></office:body></office:document-content>"
        );
        let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let stored = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        z.start_file("mimetype", stored).unwrap();
        z.write_all(b"application/vnd.oasis.opendocument.spreadsheet")
            .unwrap();
        let deflated = zip::write::SimpleFileOptions::default();
        z.start_file("content.xml", deflated).unwrap();
        z.write_all(content.as_bytes()).unwrap();
        z.start_file("Object 1/content.xml", deflated).unwrap();
        z.write_all(chart.as_bytes()).unwrap();
        z.finish().unwrap().into_inner()
    }

    /// Every series of a chart gets its own copy of the cells it draws.
    #[test]
    fn chart_series_over_the_same_cells() {
        within_the_limit(
            "ods chart series",
            &|n, limit| {
                let input = chart_ods(n);
                let limits = Limits::default().with_max_memory(limit);
                let (peak, out) = peak_of(|| convert(&input, Format::Ods, &limits));
                match out {
                    Ok(_) => Some(peak),
                    Err(Error::TooLarge(_)) => None,
                    Err(e) => panic!("the workbook was not read: {e}"),
                }
            },
            256,
        );
    }

    /// The same at a hundred thousand cells, where a copy of the cells per
    /// series is megabytes a series.
    #[test]
    fn chart_series_over_a_large_range() {
        let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
        for (series, limit) in [(256, 256u64 << 20), (1024, 256 << 20), (1024, 1 << 30)] {
            let input = chart_ods_of(series, 100, 1000);
            let limits = Limits::default().with_max_memory(limit);
            let (peak, out) = peak_of(|| convert(&input, Format::Ods, &limits));
            let verdict = match &out {
                Ok(_) => "converted",
                Err(Error::TooLarge(_)) => "refused",
                Err(e) => panic!("the workbook was not read: {e}"),
            };
            eprintln!(
                "{series} series over 100,000 cells, limit {} MiB: {verdict}, peak {:.1} MiB",
                limit >> 20,
                peak as f64 / (1 << 20) as f64
            );
            assert!(
                peak as f64 <= SLACK * limit as f64,
                "the limit is {limit} bytes and the conversion held {peak} at {series} series"
            );
        }
    }

    #[test]
    fn cells() {
        within_the_limit(
            "xls (BIFF8) cells",
            &|n, limit| {
                let input = workbook(n);
                let limits = Limits::default().with_max_memory(limit);
                let (peak, out) = peak_of(|| convert(&input, Format::Xls, &limits));
                match out {
                    Ok(_) => Some(peak),
                    Err(Error::TooLarge(_)) => None,
                    Err(e) => panic!("the workbook was not read: {e}"),
                }
            },
            1_000_000,
        );
    }
}
