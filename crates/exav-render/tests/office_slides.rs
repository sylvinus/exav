//! The public API over the fixtures (see fixtures/office/slides/README.md).

use exav_render::formats::office::test_util::Compound;
use exav_render::formats::office::test_util::build_cfb as build;
use exav_render::slides::{
    Error, Format, Limits, convert, convert_first, convert_first_from, convert_keynote_package,
};
use std::io::Read;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/office/slides/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

/// A part of a PPTX, as text.
fn part(pptx: &[u8], name: &str) -> String {
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(pptx)).unwrap();
    let mut s = String::new();
    z.by_name(name).unwrap().read_to_string(&mut s).unwrap();
    s
}

/// An ODP of one slide holding a bar chart object, written per ODF 1.3,
/// whose series takes its values from `table`.
fn chart_odp(table: &str) -> Vec<u8> {
    use std::io::Write;
    const NS: &str = r#"xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:chart="urn:oasis:names:tc:opendocument:xmlns:chart:1.0" xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0""#;
    let content = format!(
        r#"<office:document-content {NS}><office:body><office:presentation><draw:page draw:name="p1"><draw:frame svg:x="1cm" svg:y="1cm" svg:width="8cm" svg:height="6cm"><draw:object xlink:href="./Object 1"/></draw:frame></draw:page></office:presentation></office:body></office:document-content>"#
    );
    let cell = |v: &str| match v.parse::<f64>() {
        Ok(_) => format!(
            r#"<table:table-cell office:value-type="float" office:value="{v}"><text:p>{v}</text:p></table:table-cell>"#
        ),
        Err(_) => format!(
            r#"<table:table-cell office:value-type="string"><text:p>{v}</text:p></table:table-cell>"#
        ),
    };
    let row =
        |a: &str, b: &str| format!("<table:table-row>{}{}</table:table-row>", cell(a), cell(b));
    let chart = format!(
        r#"<office:document-content {NS}><office:body><office:chart><chart:chart chart:class="chart:bar" svg:width="8cm" svg:height="6cm"><chart:plot-area table:cell-range-address="local-table.$A$1:.$B$3" chart:data-source-has-labels="both"><chart:axis chart:dimension="x" chart:name="primary-x"><chart:categories table:cell-range-address="local-table.$A$2:.$A$3"/></chart:axis><chart:axis chart:dimension="y" chart:name="primary-y"/><chart:series chart:values-cell-range-address="{table}.$B$2:.$B$3" chart:label-cell-address="local-table.$B$1" chart:class="chart:bar"/></chart:plot-area><table:table table:name="local-table"><table:table-header-rows>{}</table:table-header-rows><table:table-rows>{}{}</table:table-rows></table:table></chart:chart></office:chart></office:body></office:document-content>"#,
        row("", "Sales"),
        row("Q1", "10"),
        row("Q2", "20")
    );
    let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default();
    for (name, data) in [
        (
            "mimetype",
            "application/vnd.oasis.opendocument.presentation",
        ),
        ("content.xml", content.as_str()),
        ("Object 1/content.xml", chart.as_str()),
    ] {
        z.start_file(name, opts).unwrap();
        z.write_all(data.as_bytes()).unwrap();
    }
    z.finish().unwrap().into_inner()
}

#[test]
fn chart_objects_become_charts() {
    let c = convert(&chart_odp("local-table"), Format::Odp, &Limits::default()).unwrap();
    let s1 = part(&c.pptx, "ppt/slides/slide1.xml");
    assert!(s1.contains("<c:chart "), "{s1}");
    let chart = part(&c.pptx, "ppt/charts/chart1.xml");
    assert!(chart.contains("<c:barChart>"), "{chart}");
    assert!(chart.contains("Sales") && chart.contains("Q2") && chart.contains("<c:v>20</c:v>"));
    assert!(part(&c.pptx, "[Content_Types].xml").contains("/ppt/charts/chart1.xml"));
    // A range in another table: no reference, as there is no workbook for
    // it to name.
    let c = convert(&chart_odp("Table1"), Format::Odp, &Limits::default()).unwrap();
    let chart = part(&c.pptx, "ppt/charts/chart1.xml");
    assert!(
        chart.contains("<c:barChart>") && !chart.contains("<c:f>"),
        "{chart}"
    );
}

fn names(pptx: &[u8]) -> Vec<String> {
    let z = zip::ZipArchive::new(std::io::Cursor::new(pptx)).unwrap();
    z.file_names()
        .filter_map(|n| n.ok().map(|n| n.to_string()))
        .collect()
}

/// The PPTX's own structure: a presentation naming its slides, which name
/// their layouts, which name their masters.
fn check_package(pptx: &[u8], slides: usize) {
    let n = names(pptx);
    for p in [
        "[Content_Types].xml",
        "_rels/.rels",
        "ppt/presentation.xml",
        "ppt/slideMasters/slideMaster1.xml",
        "ppt/slideLayouts/slideLayout1.xml",
        "ppt/theme/theme1.xml",
    ] {
        assert!(n.iter().any(|x| x == p), "{p} missing");
    }
    let pres = part(pptx, "ppt/presentation.xml");
    assert_eq!(pres.matches("<p:sldId ").count(), slides);
    let types = part(pptx, "[Content_Types].xml");
    for i in 1..=slides {
        assert!(types.contains(&format!("/ppt/slides/slide{i}.xml")));
        let rels = part(pptx, &format!("ppt/slides/_rels/slide{i}.xml.rels"));
        assert!(rels.contains("slideLayout"));
    }
}

#[test]
fn flat_opendocument() {
    let c = convert(&fixture("sample.fodp"), Format::Fodp, &Limits::default()).unwrap();
    assert_eq!(c.slides, 2);
    check_package(&c.pptx, 2);
    let s1 = part(&c.pptx, "ppt/slides/slide1.xml");
    assert!(s1.contains("Quarterly budget"));
    assert!(s1.contains("<p:ph type=\"title\""));
    // The list's bullets, the box's fill, the ellipse.
    assert!(s1.contains("<a:buChar char=\"•\"/>"));
    assert!(s1.contains("<a:srgbClr val=\"2A6099\"/>"));
    assert!(s1.contains("prst=\"ellipse\""));
    // The page size: 28 by 15.75 cm.
    assert!(
        part(&c.pptx, "ppt/presentation.xml").contains("<p:sldSz cx=\"10080000\" cy=\"5670000\"/>")
    );
    assert!(part(&c.pptx, "ppt/slides/slide2.xml").contains("Second slide text"));
}

#[test]
fn opendocument_package() {
    let c = convert(&fixture("sample.odp"), Format::Odp, &Limits::default()).unwrap();
    assert_eq!(c.slides, 2);
    check_package(&c.pptx, 2);
    let s1 = part(&c.pptx, "ppt/slides/slide1.xml");
    assert!(s1.contains("Revenue up 12%") && s1.contains("Costs flat"));
    assert!(s1.contains("2A6099"));
}

#[test]
fn powerpoint_97() {
    let c = convert(&fixture("sample.ppt"), Format::Ppt, &Limits::default()).unwrap();
    assert_eq!(c.slides, 2);
    check_package(&c.pptx, 2);
    let s1 = part(&c.pptx, "ppt/slides/slide1.xml");
    assert!(s1.contains("Quarterly budget"));
    assert!(s1.contains("Revenue up 12%"));
    assert!(s1.contains("2A6099"), "the box's fill");
    assert!(s1.contains("prst=\"ellipse\""));
    assert!(part(&c.pptx, "ppt/slides/slide2.xml").contains("Second slide text"));
}

/// The chart of `chart.fodp`: a bar chart of three quarters' sales.
fn check_sales_chart(pptx: &[u8]) {
    assert!(part(pptx, "ppt/slides/slide1.xml").contains("<c:chart "));
    let chart = part(pptx, "ppt/charts/chart1.xml");
    assert!(chart.contains("<c:barChart>"), "{chart}");
    for v in ["Sales", "Q1", "Q3", "<c:v>25</c:v>"] {
        assert!(chart.contains(v), "{v} in {chart}");
    }
}

#[test]
fn charts_in_every_format_that_holds_them() {
    for (name, format) in [
        ("chart.ppt", Format::Ppt),
        ("chart.odp", Format::Odp),
        ("chart.fodp", Format::Fodp),
    ] {
        let c = convert(&fixture(name), format, &Limits::default()).unwrap();
        check_sales_chart(&c.pptx);
    }
}

#[test]
fn keynote() {
    let c = convert(&fixture("sample.key"), Format::Keynote, &Limits::default()).unwrap();
    assert_eq!(c.slides, 1);
    check_package(&c.pptx, 1);
    let s1 = part(&c.pptx, "ppt/slides/slide1.xml");
    assert!(s1.contains("Example Presentation"));
    assert!(s1.contains("This is a subtitle."));
    // The same document as a package directory, given file by file.
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(fixture("sample.key"))).unwrap();
    let mut files = vec![];
    for i in 0..z.len() {
        let mut f = z.by_index(i).unwrap();
        if f.is_dir() {
            continue;
        }
        let mut v = vec![];
        f.read_to_end(&mut v).unwrap();
        files.push((f.name().map(|n| n.to_string()).unwrap_or_default(), v));
    }
    let refs: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(n, d)| (n.as_str(), d.as_slice()))
        .collect();
    let p = convert_keynote_package(&refs, &Limits::default()).unwrap();
    assert!(part(&p.pptx, "ppt/slides/slide1.xml").contains("Example Presentation"));
}

#[test]
fn keynote_tables() {
    let c = convert(&fixture("table.key"), Format::Keynote, &Limits::default()).unwrap();
    let s1 = part(&c.pptx, "ppt/slides/slide1.xml");
    // Four columns of 413.5 points, five rows of 160, and the style's
    // banding on the body's every second row.
    assert_eq!(s1.matches("<a:gridCol w=\"5251450\"/>").count(), 4, "{s1}");
    assert_eq!(s1.matches("<a:tr h=\"2032000\">").count(), 5, "{s1}");
    assert_eq!(s1.matches("E3E5E8").count(), 8, "{s1}");
    assert!(!c.warnings.iter().any(|w| w.contains("tables")));
}

#[test]
fn first_slides_only() {
    for (name, format, total) in [
        ("sample.ppt", Format::Ppt, 2),
        ("sample.odp", Format::Odp, 2),
        ("sample.fodp", Format::Fodp, 2),
        ("sample.key", Format::Keynote, 1),
    ] {
        let c = convert_first(&fixture(name), format, &Limits::default(), 1).unwrap();
        assert_eq!((c.slides, c.total_slides), (1, total), "{name}");
        check_package(&c.pptx, 1);
        assert!(!names(&c.pptx).iter().any(|n| n == "ppt/slides/slide2.xml"));
        let all = convert(&fixture(name), format, &Limits::default()).unwrap();
        assert_eq!((all.slides, all.total_slides), (total, total));
    }
}

/// An ODP of two slides, the second showing a picture of `size` bytes.
fn odp_with_picture(size: usize) -> Vec<u8> {
    use std::io::Write;
    let ns = r#"xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0" xmlns:xlink="http://www.w3.org/1999/xlink""#;
    let content = format!(
        r#"<office:document-content {ns}><office:body><office:presentation><draw:page/><draw:page><draw:frame svg:width="8cm" svg:height="6cm"><draw:image xlink:href="Pictures/a.png"/></draw:frame></draw:page></office:presentation></office:body></office:document-content>"#
    );
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png.resize(size, 7);
    let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    // Stored, as pictures are: the package is as large as they are.
    let opts =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, data) in [
        (
            "mimetype",
            &b"application/vnd.oasis.opendocument.presentation"[..],
        ),
        ("content.xml", content.as_bytes()),
        ("Pictures/a.png", &png),
    ] {
        z.start_file(name, opts).unwrap();
        z.write_all(data).unwrap();
    }
    z.finish().unwrap().into_inner()
}

#[test]
fn pictures_are_read_when_a_slide_shows_them() {
    let odp = odp_with_picture(2 << 20);
    let all = convert(&odp, Format::Odp, &Limits::default()).unwrap();
    assert!(names(&all.pptx).iter().any(|n| n == "ppt/media/image1.png"));
    // Within a memory bound the picture is past, the first slide converts
    // alone: the picture is never read.
    let small = Limits::default().with_max_memory(1 << 20);
    assert_eq!(
        convert(&odp, Format::Odp, &small).unwrap_err(),
        Error::TooLarge("memory")
    );
    let first = convert_first(&odp, Format::Odp, &small, 1).unwrap();
    assert!(
        !names(&first.pptx)
            .iter()
            .any(|n| n.starts_with("ppt/media/"))
    );
}

fn base64(d: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in d.chunks(3) {
        let n = c
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        for k in 0..=c.len() {
            s.push(A[(n >> (18 - 6 * k) & 63) as usize] as char);
        }
    }
    while !s.len().is_multiple_of(4) {
        s.push('=');
    }
    s
}

#[test]
fn tiled_backgrounds_are_scaled_to_the_pictures_resolution() {
    // A 100 by 50 PNG at 144 dpi (5669 dots per metre): two thirds of its 96 dpi size.
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png.extend_from_slice(&13u32.to_be_bytes());
    png.extend_from_slice(b"IHDR");
    png.extend_from_slice(&100u32.to_be_bytes());
    png.extend_from_slice(&50u32.to_be_bytes());
    png.extend_from_slice(&[8, 2, 0, 0, 0, 0, 0, 0, 0]);
    png.extend_from_slice(&9u32.to_be_bytes());
    png.extend_from_slice(b"pHYs");
    png.extend_from_slice(&5669u32.to_be_bytes());
    png.extend_from_slice(&5669u32.to_be_bytes());
    png.push(1);
    png.extend_from_slice(&[0; 4]);
    png.extend_from_slice(&[0, 0, 0, 0]);
    png.extend_from_slice(b"IDAT");
    let slide = |size: &str| {
        let fodp = format!(
            r#"<office:document xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" office:mimetype="application/vnd.oasis.opendocument.presentation"><office:styles><draw:fill-image draw:name="tile"><office:binary-data>{}</office:binary-data></draw:fill-image></office:styles><office:automatic-styles><style:style style:name="dp1" style:family="drawing-page"><style:drawing-page-properties draw:fill="bitmap" draw:fill-image-name="tile" style:repeat="repeat"{size}/></style:style></office:automatic-styles><office:body><office:presentation><draw:page draw:style-name="dp1"/></office:presentation></office:body></office:document>"#,
            base64(&png)
        );
        let c = convert(fodp.as_bytes(), Format::Fodp, &Limits::default()).unwrap();
        part(&c.pptx, "ppt/slides/slide1.xml")
    };
    let s1 = slide("");
    // Two thirds, within what the resolution's rounding gives.
    let sx: u32 = s1
        .split_once(r#"<a:tile tx="0" ty="0" sx=""#)
        .and_then(|(_, r)| r.split_once('"'))
        .and_then(|(n, _)| n.parse().ok())
        .unwrap_or_else(|| panic!("{s1}"));
    assert!((66_600..=66_700).contains(&sx), "{sx}");
    // A tile as large as the page is the picture stretched.
    let s1 = slide(r#" draw:fill-image-width="100%" draw:fill-image-height="100%""#);
    assert!(
        s1.contains("<a:stretch>") && !s1.contains("<a:tile"),
        "{s1}"
    );
}

#[test]
fn pictures_of_slides_not_converted_are_not_decoded() {
    // The second slide's picture is 190 KB of noise: decoding it would pass
    // a memory bound (100 KB) that the first slide alone, at about 12 KB,
    // is well within.
    for (name, format) in [("pictures.ppt", Format::Ppt), ("pictures.odp", Format::Odp)] {
        let small = Limits::default().with_max_memory(100 << 10);
        let media = |n: usize, limits: &Limits| {
            let c = convert_first(&fixture(name), format, limits, n).unwrap();
            let pics = names(&c.pptx)
                .into_iter()
                .filter(|n| n.starts_with("ppt/media/"))
                .count();
            (c.slides, c.total_slides, pics)
        };
        assert_eq!(media(1, &small), (1, 2, 1), "{name}");
        assert_eq!(media(2, &Limits::default()), (2, 2, 2), "{name}");
        let err = convert_first(&fixture(name), format, &small, 2).unwrap_err();
        assert!(matches!(err, Error::TooLarge(_)), "{name}: {err:?}");
    }
}

#[test]
fn a_picture_past_64_mib_fails_the_conversion_that_reads_it() {
    let odp = odp_with_picture((64 << 20) + 1);
    assert_eq!(
        convert(&odp, Format::Odp, &Limits::default()).unwrap_err(),
        Error::TooLarge("a package part")
    );
    // At the bound it is read.
    let odp = odp_with_picture(64 << 20);
    let ok = convert(&odp, Format::Odp, &Limits::default()).unwrap();
    assert!(names(&ok.pptx).iter().any(|n| n == "ppt/media/image1.png"));
    // The first slide alone never reads it.
    let odp = odp_with_picture((64 << 20) + 1);
    assert!(convert_first(&odp, Format::Odp, &Limits::default(), 1).is_ok());
}

#[test]
fn a_package_with_bytes_before_it_is_still_opened() {
    // Something ahead of the archive (a self-extractor's stub) moves every offset.
    let mut odp = vec![b'M'; 1000];
    odp.extend(odp_with_picture(1 << 10));
    let c = convert_first(&odp, Format::Odp, &Limits::default(), 1).unwrap();
    assert_eq!((c.slides, c.total_slides), (1, 2));
}

/// A source that counts the bytes read from it.
struct Counting<'a> {
    c: std::io::Cursor<&'a [u8]>,
    read: usize,
}

impl Read for Counting<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.c.read(buf)?;
        self.read += n;
        Ok(n)
    }
}

impl std::io::Seek for Counting<'_> {
    fn seek(&mut self, to: std::io::SeekFrom) -> std::io::Result<u64> {
        self.c.seek(to)
    }
}

#[test]
fn packages_are_read_part_by_part_from_a_source() {
    let odp = odp_with_picture(2 << 20);
    let mut src = Counting {
        c: std::io::Cursor::new(&odp),
        read: 0,
    };
    let c = convert_first_from(&mut src, Format::Odp, &Limits::default(), 1).unwrap();
    assert_eq!((c.slides, c.total_slides), (1, 2));
    assert!(src.read < 64 << 10, "{} bytes read", src.read);
    // The whole document, through the same source: the picture is read.
    let mut src = Counting {
        c: std::io::Cursor::new(&odp),
        read: 0,
    };
    let c = convert_first_from(&mut src, Format::Odp, &Limits::default(), 2).unwrap();
    assert!(names(&c.pptx).iter().any(|n| n == "ppt/media/image1.png"));
    assert!(src.read > 2 << 20);
}

#[test]
fn wrong_formats_are_refused() {
    let ppt = fixture("sample.ppt");
    assert!(matches!(
        convert(&ppt, Format::Odp, &Limits::default()),
        Err(Error::NotFormat(_))
    ));
    assert!(matches!(
        convert(b"hello", Format::Ppt, &Limits::default()),
        Err(Error::NotFormat(_))
    ));
    assert!(matches!(
        convert(&fixture("sample.odp"), Format::Keynote, &Limits::default()),
        Err(Error::NotFormat(_))
    ));
    assert!(matches!(
        convert(b"<a/>", Format::Fodp, &Limits::default()),
        Err(Error::NotFormat(_))
    ));
}

#[test]
fn limits_are_kept() {
    let odp = fixture("sample.odp");
    let few = Limits::default().with_max_shapes(2);
    assert_eq!(
        convert(&odp, Format::Odp, &few).unwrap_err(),
        Error::TooLarge("shapes")
    );
    let small = Limits::default().with_max_memory(10_000);
    assert_eq!(
        convert(&odp, Format::Odp, &small).unwrap_err().kind(),
        "too-large"
    );
    let mut tiny = Limits::default();
    tiny.max_input = 100;
    assert_eq!(
        convert(&odp, Format::Odp, &tiny).unwrap_err(),
        Error::TooLarge("input")
    );
}

#[test]
fn damaged_files_do_not_panic() {
    for (name, format) in [
        ("sample.ppt", Format::Ppt),
        ("sample.odp", Format::Odp),
        ("sample.fodp", Format::Fodp),
        ("sample.key", Format::Keynote),
    ] {
        let data = fixture(name);
        for cut in [10, data.len() / 3, data.len() / 2, data.len() - 1] {
            let _ = convert(&data[..cut], format, &Limits::default());
        }
        let mut flipped = data.clone();
        for i in (0..flipped.len()).step_by(97) {
            flipped[i] ^= 0x5A;
        }
        let _ = convert(&flipped, format, &Limits::default());
    }
    // The PPT's records damaged in a sound compound file, which damage to
    // the file around them mostly hides.
    let ppt = fixture("sample.ppt");
    let stream = Compound::open(&ppt)
        .unwrap()
        .stream(&["PowerPoint Document"])
        .unwrap();
    let cuts = (1..16).map(|k| stream.len() * k / 16);
    for s in cuts
        .map(|cut| stream[..cut].to_vec())
        .chain((0..8).map(|k| {
            let mut s = stream.clone();
            for i in (k * 13..s.len()).step_by(211) {
                s[i] ^= 0xA5;
            }
            s
        }))
    {
        let _ = convert(
            &build(&[("PowerPoint Document", &s)]),
            Format::Ppt,
            &Limits::default(),
        );
    }
}

/// The memory bound counts what a shape takes in the model, some 7 kB:
/// 20,000 text boxes hold more than 100 MB.
#[test]
fn shapes_are_counted_at_what_they_take() {
    let fodp = format!(
        r#"<office:document xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" office:mimetype="application/vnd.oasis.opendocument.presentation"><office:body><office:presentation><draw:page>{}</draw:page></office:presentation></office:body></office:document>"#,
        "<draw:frame><draw:text-box><text:p>x</text:p></draw:text-box></draw:frame>".repeat(20_000)
    );
    let within = |mib: u64| {
        let limits = Limits::default().with_max_memory(mib << 20);
        convert(fodp.as_bytes(), Format::Fodp, &limits)
    };
    assert_eq!(within(64).unwrap_err(), Error::TooLarge("memory"));
    assert!(within(512).is_ok());
}

#[test]
fn a_tree_of_elements_nothing_reads_is_charged_for() {
    let x = format!(
        "<office:document xmlns:office=\"urn:oasis:names:tc:opendocument:xmlns:office:1.0\" office:mimetype=\"application/vnd.oasis.opendocument.presentation\">{}</office:document>",
        "<office:x/>".repeat(100_000)
    );
    let small = Limits::default().with_max_memory(8 << 20);
    assert_eq!(
        convert(x.as_bytes(), Format::Fodp, &small).unwrap_err(),
        Error::TooLarge("memory")
    );
}
