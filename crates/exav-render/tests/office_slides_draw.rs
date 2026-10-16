//! OpenDocument drawings (ODG, OTG, FODG) as slides: one slide to a page,
//! named as the page is, in the pages' largest size.

use exav_render::slides::{convert, Error, Format, Limits};
use std::io::Read;

fn fixture(name: &str) -> Vec<u8> {
    let p = format!(
        "{}/tests/fixtures/office/draw/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

fn part(pptx: &[u8], name: &str) -> String {
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(pptx)).unwrap();
    let mut s = String::new();
    z.by_name(name).unwrap().read_to_string(&mut s).unwrap();
    s
}

#[test]
fn each_page_is_a_slide_named_as_the_page_is() {
    let c = convert(&fixture("sample.fodg"), Format::Fodg, &Limits::default()).unwrap();
    assert_eq!((c.slides, c.total_slides), (2, 2));
    assert!(part(&c.pptx, "ppt/slides/slide1.xml").contains(r#"<p:cSld name="Plan">"#));
    assert!(part(&c.pptx, "ppt/slides/slide2.xml").contains(r#"<p:cSld name="Detail">"#));
}

#[test]
fn the_presentation_has_the_largest_page_size() {
    let c = convert(&fixture("sample.fodg"), Format::Fodg, &Limits::default()).unwrap();
    // 21 by 14.8 cm, the other page being 10 by 10.
    assert!(part(&c.pptx, "ppt/presentation.xml").contains(r#"cx="7560000" cy="5328000""#));
}

#[test]
fn the_largest_page_is_found_wherever_it_is() {
    // The first page now has the small master page, the second the large one.
    let doc = String::from_utf8(fixture("sample.fodg"))
        .unwrap()
        .replace(r#"master-page-name="Large""#, "master-page-name=\"X\"")
        .replace(r#"master-page-name="Small""#, r#"master-page-name="Large""#)
        .replace("master-page-name=\"X\"", r#"master-page-name="Small""#);
    let c = convert(doc.as_bytes(), Format::Fodg, &Limits::default()).unwrap();
    assert!(part(&c.pptx, "ppt/presentation.xml").contains(r#"cx="7560000" cy="5328000""#));
}

#[test]
fn a_layer_that_is_not_displayed_leaves_its_shapes_out() {
    let c = convert(&fixture("sample.fodg"), Format::Fodg, &Limits::default()).unwrap();
    let one = part(&c.pptx, "ppt/slides/slide1.xml");
    assert!(one.contains("Red box"));
    assert!(!one.contains("Hidden note"));
    assert!(part(&c.pptx, "ppt/slides/slide2.xml").contains("Detail"));
}

#[test]
fn the_page_background_and_master_shapes_are_kept() {
    let c = convert(&fixture("sample.fodg"), Format::Fodg, &Limits::default()).unwrap();
    assert!(part(&c.pptx, "ppt/slides/slide1.xml").contains(r#"<a:srgbClr val="F4F0D8"/>"#));
    // The master page of the first drawing holds a frame.
    let master = part(&c.pptx, "ppt/slideMasters/slideMaster1.xml");
    assert!(master.contains("<p:sp>"));
}

#[test]
fn a_package_and_a_flat_file_give_the_same_pages() {
    let flat = convert(&fixture("sample.fodg"), Format::Fodg, &Limits::default()).unwrap();
    let zipped = convert(&fixture("sample.odg"), Format::Odg, &Limits::default()).unwrap();
    assert_eq!(zipped.slides, flat.slides);
    for n in 1..=2 {
        let name = format!("ppt/slides/slide{n}.xml");
        let a = part(&flat.pptx, &name);
        let b = part(&zipped.pptx, &name);
        let title = |s: &str| {
            s.split("<p:cSld name=\"")
                .nth(1)
                .map(|t| t[..t.find('"').unwrap()].to_string())
        };
        assert_eq!(title(&a), title(&b));
    }
}

#[test]
fn extensions_name_the_drawing_formats() {
    for (ext, format) in [
        ("odg", Format::Odg),
        ("otg", Format::Odg),
        ("fodg", Format::Fodg),
    ] {
        assert_eq!(Format::from_extension(ext), Some(format));
    }
}

#[test]
fn a_presentation_is_not_a_drawing_and_a_drawing_is_not_a_presentation() {
    let odp = std::fs::read(format!(
        "{}/tests/fixtures/office/slides/sample.odp",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    assert!(matches!(
        convert(&odp, Format::Odg, &Limits::default()),
        Err(Error::NotFormat(_))
    ));
    assert!(matches!(
        convert(&fixture("sample.odg"), Format::Odp, &Limits::default()),
        Err(Error::NotFormat(_))
    ));
    assert!(matches!(
        convert(&fixture("sample.fodg"), Format::Fodp, &Limits::default()),
        Err(Error::NotFormat(_))
    ));
}

#[test]
fn the_old_media_type_of_a_drawing_is_read() {
    let doc = String::from_utf8(fixture("sample.fodg"))
        .unwrap()
        .replace("opendocument.graphics", "opendocument.drawing");
    assert!(convert(doc.as_bytes(), Format::Fodg, &Limits::default()).is_ok());
}

#[test]
fn a_stroke_width_without_a_unit_is_in_hundredths_of_a_millimetre() {
    let doc = String::from_utf8(fixture("sample.fodg"))
        .unwrap()
        .replace(r#"svg:stroke-width="0.05cm""#, r#"svg:stroke-width="5""#);
    let c = convert(doc.as_bytes(), Format::Fodg, &Limits::default()).unwrap();
    // 5 hundredths of a millimetre: 1800 EMU.
    assert!(part(&c.pptx, "ppt/slides/slide1.xml").contains(r#"<a:ln w="1800">"#));
}

#[test]
fn a_page_limit_applies_to_drawings_as_to_slides() {
    let mut limits = Limits::default();
    limits.max_slides = 1;
    assert!(matches!(
        convert(&fixture("sample.fodg"), Format::Fodg, &limits),
        Err(Error::TooLarge(_))
    ));
}
