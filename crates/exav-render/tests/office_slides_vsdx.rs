//! Visio drawings (VSDX) as slides: one slide to a page, named as the page
//! is, in the pages' largest size; shapes with their geometry, formats and
//! text; masters, styles and themes resolved.

use exav_render::formats::office::test_util::{build_cfb, PackageWriter};
use exav_render::slides::{convert, convert_first, convert_first_from, Error, Format, Limits};
use std::io::{Cursor, Read};

const NS: &str = "xmlns='http://schemas.microsoft.com/office/visio/2012/main' xmlns:r='http://schemas.openxmlformats.org/officeDocument/2006/relationships'";
const REL: &str = "http://schemas.microsoft.com/visio/2010/relationships";
const OPC: &str = "http://schemas.openxmlformats.org/package/2006/relationships";

fn fixture(name: &str) -> Vec<u8> {
    let p = format!(
        "{}/tests/fixtures/office/draw/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

fn part(pptx: &[u8], name: &str) -> String {
    let mut z = zip::ZipArchive::new(Cursor::new(pptx)).unwrap();
    let mut s = String::new();
    z.by_name(name)
        .unwrap_or_else(|_| panic!("no part {name}"))
        .read_to_string(&mut s)
        .unwrap();
    s
}

fn has_part(pptx: &[u8], name: &str) -> bool {
    zip::ZipArchive::new(Cursor::new(pptx))
        .unwrap()
        .by_name(name)
        .is_ok()
}

fn rels(items: &[(&str, &str, &str)]) -> String {
    let body: String = items
        .iter()
        .map(|(i, t, g)| format!(r#"<Relationship Id="{i}" Type="{t}" Target="{g}"/>"#))
        .collect();
    format!(r#"<Relationships xmlns="{OPC}">{body}</Relationships>"#)
}

/// A package of `parts`, each deflated.
fn package(parts: &[(&str, String)]) -> Vec<u8> {
    let mut w = PackageWriter::new(1 << 24);
    for (name, data) in parts {
        w.put(name, data.as_bytes(), true).unwrap();
    }
    w.finish().unwrap()
}

fn cell(n: &str, v: &str) -> String {
    format!("<Cell N='{n}' V='{v}'/>")
}

fn rect(w: f64, h: f64) -> String {
    format!(
        "<Section N='Geometry' IX='0'>\
         <Row T='MoveTo' IX='1'>{}{}</Row><Row T='LineTo' IX='2'>{}{}</Row>\
         <Row T='LineTo' IX='3'>{}{}</Row><Row T='LineTo' IX='4'>{}{}</Row>\
         <Row T='LineTo' IX='5'>{}{}</Row></Section>",
        cell("X", "0"),
        cell("Y", "0"),
        cell("X", &w.to_string()),
        cell("Y", "0"),
        cell("X", &w.to_string()),
        cell("Y", &h.to_string()),
        cell("X", "0"),
        cell("Y", &h.to_string()),
        cell("X", "0"),
        cell("Y", "0"),
    )
}

/// A shape `w` by `h` inches centred on (`x`, `y`) with `extra` cells and
/// children, and a rectangle for its geometry.
fn boxed(id: u32, x: f64, y: f64, w: f64, h: f64, extra: &str) -> String {
    format!(
        "<Shape ID='{id}' Type='Shape'>{}{}{}{}{}{}{extra}{}</Shape>",
        cell("PinX", &x.to_string()),
        cell("PinY", &y.to_string()),
        cell("Width", &w.to_string()),
        cell("Height", &h.to_string()),
        cell("LocPinX", &(w / 2.0).to_string()),
        cell("LocPinY", &(h / 2.0).to_string()),
        rect(w, h)
    )
}

struct Page<'a> {
    name: &'a str,
    /// Cells of the page sheet.
    sheet: String,
    shapes: String,
}

fn page<'a>(name: &'a str, w: f64, h: f64, shapes: &str) -> Page<'a> {
    Page {
        name,
        sheet: cell("PageWidth", &w.to_string()) + &cell("PageHeight", &h.to_string()),
        shapes: shapes.to_string(),
    }
}

/// A drawing of `pages`, `document` being what goes in the VisioDocument.
fn drawing(pages: &[Page], document: &str) -> Vec<u8> {
    let mut parts: Vec<(&str, String)> = vec![];
    let names: Vec<String> = (0..pages.len())
        .map(|i| format!("visio/pages/page{}.xml", i + 1))
        .collect();
    let mut page_els = String::new();
    let mut page_rels = vec![];
    let ids: Vec<String> = (0..pages.len()).map(|i| format!("rId{}", i + 1)).collect();
    for (i, p) in pages.iter().enumerate() {
        page_els.push_str(&format!(
            "<Page ID='{i}' Name='{0}' NameU='{0}'><PageSheet>{1}</PageSheet><Rel r:id='{2}'/></Page>",
            p.name, p.sheet, ids[i]
        ));
        page_rels.push((
            ids[i].as_str(),
            format!("{REL}/page"),
            format!("page{}.xml", i + 1),
        ));
    }
    parts.push((
        "_rels/.rels",
        rels(&[("rId1", &format!("{REL}/document"), "visio/document.xml")]),
    ));
    parts.push((
        "visio/document.xml",
        format!("<VisioDocument {NS}>{document}</VisioDocument>"),
    ));
    parts.push((
        "visio/_rels/document.xml.rels",
        rels(&[("rId2", &format!("{REL}/pages"), "pages/pages.xml")]),
    ));
    parts.push((
        "visio/pages/pages.xml",
        format!("<Pages {NS}>{page_els}</Pages>"),
    ));
    let pr: Vec<(&str, &str, &str)> = page_rels
        .iter()
        .map(|(i, t, g)| (*i, t.as_str(), g.as_str()))
        .collect();
    parts.push(("visio/pages/_rels/pages.xml.rels", rels(&pr)));
    for (i, p) in pages.iter().enumerate() {
        parts.push((
            names[i].as_str(),
            format!(
                "<PageContents {NS}><Shapes>{}</Shapes></PageContents>",
                p.shapes
            ),
        ));
    }
    package(&parts)
}

fn one(shapes: &str) -> Vec<u8> {
    drawing(&[page("Page-1", 6.0, 4.0, shapes)], "")
}

fn slide(d: &[u8]) -> String {
    let c = convert(d, Format::Vsdx, &Limits::default()).unwrap();
    part(&c.pptx, "ppt/slides/slide1.xml")
}

#[test]
fn each_page_is_a_slide_named_as_the_page_is() {
    let c = convert(&fixture("sample.vsdx"), Format::Vsdx, &Limits::default()).unwrap();
    // The background page is a master, not a slide.
    assert_eq!((c.slides, c.total_slides), (2, 2));
    assert!(part(&c.pptx, "ppt/slides/slide1.xml").contains(r#"<p:cSld name="Plan">"#));
    assert!(part(&c.pptx, "ppt/slides/slide2.xml").contains(r#"<p:cSld name="Detail">"#));
}

#[test]
fn the_presentation_has_the_largest_page_size() {
    let c = convert(&fixture("sample.vsdx"), Format::Vsdx, &Limits::default()).unwrap();
    // 11 by 8.5 inches, the other page being 5.8 by 8.2.
    assert!(part(&c.pptx, "ppt/presentation.xml").contains(r#"cx="10058400" cy="7772400""#));
    // The largest side and the other come from different pages.
    let d = drawing(&[page("A", 10.0, 2.0, ""), page("B", 3.0, 6.0, "")], "");
    let c = convert(&d, Format::Vsdx, &Limits::default()).unwrap();
    assert!(part(&c.pptx, "ppt/presentation.xml").contains(r#"cx="9144000" cy="5486400""#));
}

#[test]
fn a_page_scale_gives_paper_inches_and_a_page_too_big_is_made_to_fit() {
    // 12 by 8 inches of drawing to 1 of paper for 2: a 6 by 4 inch slide,
    // and the shape's coordinates in paper inches too.
    let sheet = cell("PageWidth", "12")
        + &cell("PageHeight", "8")
        + &cell("PageScale", "1")
        + &cell("DrawingScale", "2");
    let p = Page {
        name: "Scaled",
        sheet,
        shapes: boxed(1, 6.0, 4.0, 2.0, 2.0, ""),
    };
    let c = convert(&drawing(&[p], ""), Format::Vsdx, &Limits::default()).unwrap();
    assert!(part(&c.pptx, "ppt/presentation.xml").contains(r#"cx="5486400" cy="3657600""#));
    let s = part(&c.pptx, "ppt/slides/slide1.xml");
    // 2 inches of drawing are 1 inch of paper, centred on (3, 2).
    assert!(
        s.contains(r#"<a:off x="2286000" y="1371600"/><a:ext cx="914400" cy="914400"/>"#),
        "{s}"
    );
    // A page of 1000 inches is 55 inches at most, and its shapes with it.
    let d = drawing(
        &[page(
            "Huge",
            1000.0,
            500.0,
            &boxed(1, 500.0, 250.0, 100.0, 50.0, ""),
        )],
        "",
    );
    let c = convert(&d, Format::Vsdx, &Limits::default()).unwrap();
    assert!(part(&c.pptx, "ppt/presentation.xml").contains(r#"cx="50292000" cy="25146000""#));
    assert!(
        part(&c.pptx, "ppt/slides/slide1.xml").contains(r#"<a:ext cx="5029200" cy="2514600"/>"#)
    );
}

#[test]
fn a_shape_is_placed_from_the_top_left_corner_of_the_page() {
    let s = slide(&one(&boxed(1, 2.0, 3.0, 2.0, 1.0, "")));
    // The page is 4 inches high and the box's top is at 3.5: 0.5 from the top.
    assert!(
        s.contains(r#"<a:off x="914400" y="457200"/><a:ext cx="1828800" cy="914400"/>"#),
        "{s}"
    );
    // The path starts at the lower left of the box, y pointing down.
    assert!(
        s.contains(r#"<a:path w="1828800" h="914400"><a:moveTo><a:pt x="0" y="914400"/>"#),
        "{s}"
    );
    assert!(s.contains(
        r#"<a:lnTo><a:pt x="1828800" y="914400"/></a:lnTo><a:lnTo><a:pt x="1828800" y="0"/>"#
    ));
    assert!(s.contains("<a:close/>"));
}

#[test]
fn rotation_is_counterclockwise_and_mirrors_stay_on_the_pin() {
    // A quarter turn counterclockwise is three quarters clockwise.
    let s = slide(&one(&boxed(
        1,
        3.0,
        2.0,
        2.0,
        1.0,
        &cell("Angle", "1.5707963267949"),
    )));
    assert!(s.contains(r#"<a:xfrm rot="16200000">"#), "{s}");
    let s = slide(&one(&boxed(
        1,
        3.0,
        2.0,
        2.0,
        1.0,
        &(cell("FlipX", "1") + &cell("FlipY", "1")),
    )));
    assert!(s.contains(r#"flipH="1" flipV="1""#), "{s}");
    // A pin at a corner: the box turns about it. Turned a quarter about its
    // lower left corner at (2, 1), a 2 by 1 box covers x 1 to 2, y 1 to 3.
    let extra = cell("Angle", "1.5707963267949") + &cell("LocPinX", "0") + &cell("LocPinY", "0");
    let s = slide(&one(&boxed(1, 2.0, 1.0, 2.0, 1.0, &extra)));
    // Its unturned box is centred on (1.5, 2): 2 wide, 1 high.
    assert!(
        s.contains(r#"<a:off x="457200" y="1371600"/><a:ext cx="1828800" cy="914400"/>"#),
        "{s}"
    );
}

#[test]
fn fill_line_and_dash_come_from_the_cells_and_the_colour_table() {
    let doc = "<Colors><ColorEntry IX='24' RGB='#336699'/></Colors>";
    let extra = cell("FillPattern", "1")
        + &cell("FillForegnd", "24")
        + &cell("FillForegndTrans", "0.5")
        + &cell("LinePattern", "2")
        + &cell("LineWeight", "0.0208333333")
        + &cell("LineColor", "#FF0000")
        + &cell("EndArrow", "4");
    let d = drawing(
        &[page("P", 6.0, 4.0, &boxed(1, 3.0, 2.0, 2.0, 1.0, &extra))],
        doc,
    );
    let s = slide(&d);
    assert!(s.contains(r#"<a:solidFill><a:srgbClr val="336699"><a:alpha val="50000"/></a:srgbClr></a:solidFill>"#), "{s}");
    assert!(s.contains(r#"<a:ln w="19050">"#), "{s}");
    assert!(s.contains(r#"<a:srgbClr val="FF0000"/>"#));
    assert!(s.contains(r#"<a:prstDash val="dash"/>"#));
    assert!(s.contains(r#"<a:tailEnd type="triangle""#));
    assert!(!s.contains("headEnd"));
    // Without a pattern a shape is neither filled nor stroked.
    let s = slide(&one(&boxed(1, 3.0, 2.0, 2.0, 1.0, "")));
    assert!(s.contains("<a:noFill/><a:ln><a:noFill/></a:ln>"), "{s}");
}

#[test]
fn a_style_sheet_gives_what_the_shape_leaves_out_through_its_parents() {
    let doc = "<StyleSheets>\
        <StyleSheet ID='0'><Cell N='FillPattern' V='1'/><Cell N='FillForegnd' V='#111111'/><Cell N='LinePattern' V='1'/><Cell N='LineColor' V='#222222'/><Cell N='LineWeight' V='0.01'/></StyleSheet>\
        <StyleSheet ID='1' FillStyle='0' LineStyle='0'><Cell N='FillForegnd' V='#AABBCC'/></StyleSheet>\
        </StyleSheets>";
    let sh = "<Shape ID='1' FillStyle='1' LineStyle='1'><Cell N='PinX' V='3'/><Cell N='PinY' V='2'/><Cell N='Width' V='1'/><Cell N='Height' V='1'/><Cell N='LocPinX' V='0.5'/><Cell N='LocPinY' V='0.5'/>".to_string()
        + &rect(1.0, 1.0)
        + "</Shape>";
    let d = drawing(&[page("P", 6.0, 4.0, &sh)], doc);
    let s = slide(&d);
    // The fill colour of the style, its pattern and the line of its parent.
    assert!(
        s.contains(r#"<a:solidFill><a:srgbClr val="AABBCC"/></a:solidFill>"#),
        "{s}"
    );
    assert!(
        s.contains(r#"<a:ln w="9144"><a:solidFill><a:srgbClr val="222222"/>"#),
        "{s}"
    );
}

fn master_package(instance: &str) -> Vec<u8> {
    let master = "<Shape ID='1' Type='Shape'><Cell N='PinX' V='1'/><Cell N='PinY' V='0.5'/>\
        <Cell N='Width' V='2'/><Cell N='Height' V='1'/><Cell N='LocPinX' V='1' F='Width*0.5'/><Cell N='LocPinY' V='0.5' F='Height*0.5'/>\
        <Cell N='FillPattern' V='1'/><Cell N='FillForegnd' V='#00FF00'/>\
        <Section N='Geometry' IX='0'>\
        <Row T='MoveTo' IX='1'><Cell N='X' V='0' F='Width*0'/><Cell N='Y' V='0' F='Height*0'/></Row>\
        <Row T='LineTo' IX='2'><Cell N='X' V='2' F='Width*1'/><Cell N='Y' V='0' F='Height*0'/></Row>\
        <Row T='LineTo' IX='3'><Cell N='X' V='2' F='Width*1'/><Cell N='Y' V='1' F='Height*1'/></Row>\
        </Section></Shape>";
    package(&[
        (
            "_rels/.rels",
            rels(&[("rId1", &format!("{REL}/document"), "visio/document.xml")]),
        ),
        ("visio/document.xml", format!("<VisioDocument {NS}/>")),
        (
            "visio/_rels/document.xml.rels",
            rels(&[
                ("rId1", &format!("{REL}/masters"), "masters/masters.xml"),
                ("rId2", &format!("{REL}/pages"), "pages/pages.xml"),
            ]),
        ),
        (
            "visio/masters/masters.xml",
            format!("<Masters {NS}><Master ID='7'><Rel r:id='rId1'/></Master></Masters>"),
        ),
        (
            "visio/masters/_rels/masters.xml.rels",
            rels(&[("rId1", &format!("{REL}/master"), "master1.xml")]),
        ),
        (
            "visio/masters/master1.xml",
            format!("<MasterContents {NS}><Shapes>{master}</Shapes></MasterContents>"),
        ),
        (
            "visio/pages/pages.xml",
            format!("<Pages {NS}><Page ID='0' Name='P'><PageSheet><Cell N='PageWidth' V='6'/><Cell N='PageHeight' V='4'/></PageSheet><Rel r:id='rId1'/></Page></Pages>"),
        ),
        (
            "visio/pages/_rels/pages.xml.rels",
            rels(&[("rId1", &format!("{REL}/page"), "page1.xml")]),
        ),
        (
            "visio/pages/page1.xml",
            format!("<PageContents {NS}><Shapes>{instance}</Shapes></PageContents>"),
        ),
    ])
}

#[test]
fn an_instance_inherits_its_master_and_the_master_formulas_follow_its_size() {
    // Twice as wide as the master and one cell of its own.
    let inst = "<Shape ID='3' Type='Shape' Master='7'><Cell N='PinX' V='3'/><Cell N='PinY' V='2'/><Cell N='Width' V='4'/>\
                <Cell N='FillForegnd' V='#0000FF'/></Shape>";
    let s = slide(&master_package(inst));
    // LocPinX = Width*0.5 gives a box from x = 1 to 5.
    assert!(
        s.contains(r#"<a:off x="914400" y="1371600"/><a:ext cx="3657600" cy="914400"/>"#),
        "{s}"
    );
    // The path follows Width*1 (4 inches), and Height*0.
    assert!(
        s.contains(
            r#"<a:lnTo><a:pt x="3657600" y="914400"/></a:lnTo><a:lnTo><a:pt x="3657600" y="0"/>"#
        ),
        "{s}"
    );
    // The instance's colour, not the master's.
    assert!(
        s.contains(r#"<a:srgbClr val="0000FF"/>"#) && !s.contains("00FF00"),
        "{s}"
    );
    // Without the colour, the master's.
    let inst = "<Shape ID='3' Type='Shape' Master='7'><Cell N='PinX' V='3'/><Cell N='PinY' V='2'/></Shape>";
    let s = slide(&master_package(inst));
    assert!(s.contains(r#"<a:srgbClr val="00FF00"/>"#), "{s}");
    assert!(
        s.contains(r#"<a:off x="1828800" y="1371600"/><a:ext cx="1828800" cy="914400"/>"#),
        "{s}"
    );
}

#[test]
fn a_group_has_its_members_in_its_own_coordinates() {
    let group = format!(
        "<Shape ID='1' Type='Group'>{}{}{}{}{}{}{}<Shapes>{}</Shapes></Shape>",
        cell("PinX", "3"),
        cell("PinY", "2"),
        cell("Width", "2"),
        cell("Height", "1"),
        cell("LocPinX", "1"),
        cell("LocPinY", "0.5"),
        cell("Angle", "0.5235987756"),
        // A member at the group's lower left, a unit square.
        boxed(2, 0.5, 0.5, 1.0, 1.0, "")
    );
    let s = slide(&one(&group));
    assert!(s.contains("<p:grpSp>"), "{s}");
    // The group's box, turned 30 degrees counterclockwise, and the space its
    // members are in: its own size, y pointing down.
    assert!(s.contains(r#"<a:xfrm rot="19800000"><a:off x="1828800" y="1371600"/><a:ext cx="1828800" cy="914400"/><a:chOff x="0" y="0"/><a:chExt cx="1828800" cy="914400"/></a:xfrm>"#), "{s}");
    // The member fills the left half of it.
    assert!(
        s.contains(r#"<a:xfrm><a:off x="0" y="0"/><a:ext cx="914400" cy="914400"/></a:xfrm>"#),
        "{s}"
    );
}

#[test]
fn text_has_runs_paragraphs_and_a_block_where_the_cells_put_it() {
    let extra = "<Section N='Character'><Row IX='0'>\
        <Cell N='Size' V='0.25'/><Cell N='Style' V='1'/><Cell N='Color' V='#FF0000'/><Cell N='Font' V='Arial'/></Row></Section>\
        <Section N='Paragraph'><Row IX='0'><Cell N='HorzAlign' V='2'/></Row></Section>\
        <Cell N='VerticalAlign' V='2'/>\
        <Text><cp IX='0'/>Bold red<cp IX='0'/> and more\nSecond</Text>";
    let s = slide(&one(&boxed(1, 3.0, 2.0, 2.0, 1.0, extra)));
    assert_eq!(s.matches("<a:p>").count(), 2, "{s}");
    assert!(s.contains(r#"sz="1800" b="1""#), "{s}");
    assert!(s.contains(r#"<a:srgbClr val="FF0000"/>"#), "{s}");
    assert!(s.contains(r#"<a:latin typeface="Arial"/>"#), "{s}");
    assert!(
        s.contains("<a:t>Bold red</a:t>") && s.contains("<a:t>Second</a:t>"),
        "{s}"
    );
    assert!(s.contains(r#"algn="r""#), "{s}");
    assert!(s.contains(r#"anchor="b""#), "{s}");
    // A text block that is a part of the box: the insets are what is left.
    let extra = "<Cell N='TxtPinX' V='1.5'/><Cell N='TxtPinY' V='0.5'/><Cell N='TxtWidth' V='1'/><Cell N='TxtHeight' V='0.5'/>\
        <Cell N='TxtLocPinX' V='0.5'/><Cell N='TxtLocPinY' V='0.25'/><Text>Right part</Text>";
    let s = slide(&one(&boxed(1, 3.0, 2.0, 2.0, 1.0, extra)));
    // The block starts at x = 1 of 2 and is 0.5 of 1 high, centred.
    assert!(
        s.contains(r#"lIns="914400" tIns="228600" rIns="0" bIns="228600""#),
        "{s}"
    );
    // A block turned or outside the box is a shape of its own.
    let extra = "<Cell N='TxtPinX' V='1'/><Cell N='TxtPinY' V='0.5'/><Cell N='TxtWidth' V='1'/><Cell N='TxtHeight' V='0.5'/>\
        <Cell N='TxtLocPinX' V='0.5'/><Cell N='TxtLocPinY' V='0.25'/><Cell N='TxtAngle' V='1.5707963267949'/><Text>Turned</Text>";
    let s = slide(&one(&boxed(1, 3.0, 2.0, 2.0, 1.0, extra)));
    assert_eq!(s.matches("<p:sp>").count(), 2, "{s}");
    assert!(s.contains(r#"<a:xfrm rot="16200000">"#), "{s}");
}

#[test]
fn what_is_hidden_deleted_or_a_guide_is_left_out() {
    let layers =
        "<Section N='Layer'><Row IX='0'><Cell N='Name' V='A'/><Cell N='Visible' V='1'/></Row>\
                  <Row IX='1'><Cell N='Name' V='B'/><Cell N='Visible' V='0'/></Row></Section>";
    let shapes = [
        boxed(1, 1.0, 1.0, 1.0, 1.0, &(cell("LayerMember", "0") + "<Text>shown</Text>")),
        boxed(2, 2.0, 1.0, 1.0, 1.0, &(cell("LayerMember", "0;1") + "<Text>on a hidden layer</Text>")),
        boxed(3, 3.0, 1.0, 1.0, 1.0, "<Text>no layer</Text>"),
        "<Shape ID='4' Type='Guide'><Cell N='PinX' V='1'/><Text>guide</Text></Shape>".to_string(),
        boxed(5, 4.0, 1.0, 1.0, 1.0, "<Text>on page</Text>").replace("Type='Shape'", "Type='Shape' Del='1'"),
        // A path that does not show leaves nothing but the text.
        format!(
            "<Shape ID='6' Type='Shape'>{}{}{}{}<Section N='Geometry' IX='0'><Cell N='NoShow' V='1'/><Row T='MoveTo' IX='1'><Cell N='X' V='0'/><Cell N='Y' V='0'/></Row><Row T='LineTo' IX='2'><Cell N='X' V='1'/><Cell N='Y' V='1'/></Row></Section></Shape>",
            cell("PinX", "5"), cell("PinY", "2"), cell("Width", "1"), cell("Height", "1")
        ),
    ]
    .concat();
    let p = Page {
        name: "P",
        sheet: cell("PageWidth", "6") + &cell("PageHeight", "4") + layers,
        shapes,
    };
    let s = slide(&drawing(&[p], ""));
    assert!(s.contains("shown") && s.contains("no layer"), "{s}");
    for gone in ["on a hidden layer", "guide", "on page"] {
        assert!(!s.contains(gone), "{gone}");
    }
    // Two shapes with a path, and the one whose only path does not show
    // has none.
    assert_eq!(s.matches("<a:custGeom>").count(), 2, "{s}");
}

#[test]
fn a_picture_and_the_links_of_the_sample_drawing() {
    let c = convert(&fixture("sample.vsdx"), Format::Vsdx, &Limits::default()).unwrap();
    // The PNG of the second page is a picture of the PPTX.
    assert!(has_part(&c.pptx, "ppt/media/image1.png"));
    assert!(part(&c.pptx, "ppt/slides/slide2.xml").contains("<p:pic>"));
    // A link to an address, and one to the first page.
    let r1 = part(&c.pptx, "ppt/slides/_rels/slide1.xml.rels");
    assert!(
        r1.contains(r#"Target="https://example.org/" TargetMode="External""#),
        "{r1}"
    );
    let s2 = part(&c.pptx, "ppt/slides/slide2.xml");
    assert!(s2.contains(r#"action="ppaction://hlinksldjump""#), "{s2}");
    assert!(part(&c.pptx, "ppt/slides/_rels/slide2.xml.rels").contains("slide1.xml"));
    // Its hidden layer's shape is not in the first slide, the rest is.
    let s1 = part(&c.pptx, "ppt/slides/slide1.xml");
    assert!(
        !s1.contains("Hidden note") && s1.contains("Wide box"),
        "{s1}"
    );
    assert!(s1.contains(r#"<p:grpSp>"#) && s1.contains("First line"));
    // The master's own formulas, the instance's colour and the turn.
    assert!(s1.contains(r#"flipH="1""#) && s1.contains(r#"val="00FF00""#));
    // The first instance gets the master's fill through its style and the
    // colour table (24 is 336699).
    assert!(s1.contains(r#"val="336699""#), "{s1}");
}

#[test]
fn a_background_page_is_the_master_of_the_pages_that_use_it() {
    let c = convert(&fixture("sample.vsdx"), Format::Vsdx, &Limits::default()).unwrap();
    // The first master is the blank one, the second the page "Back".
    let m = part(&c.pptx, "ppt/slideMasters/slideMaster2.xml");
    assert!(m.contains("CCCCCC"), "{m}");
    assert!(part(&c.pptx, "ppt/slides/_rels/slide1.xml.rels").contains("slideLayout2.xml"));
    assert!(part(&c.pptx, "ppt/slides/_rels/slide2.xml.rels").contains("slideLayout1.xml"));
}

#[test]
fn the_theme_gives_what_a_themed_cell_leaves_to_it() {
    let c = convert(&fixture("themed.vsdx"), Format::Vsdx, &Limits::default()).unwrap();
    let s = part(&c.pptx, "ppt/slides/slide1.xml");
    let fills: Vec<&str> = s
        .split("<a:solidFill><a:srgbClr val=\"")
        .skip(1)
        .map(|t| &t[..6])
        .collect();
    // For each box the fill and then the line. The first has no quick style:
    // the root style's white and black; then accent 1 and the line in
    // accent 2; a variation's second colour; the first variation, as the
    // index 65534 is not one; the background colour.
    assert_eq!(
        fills,
        [
            "FFFFFF", "000000", "4472C4", "ED7D31", "00AA00", "000000", "222222", "000000",
            "F0F0F0", "000000"
        ],
        "{s}"
    );
    // The theme's body font for text that names none.
    assert!(s.contains(r#"typeface="Verdana""#), "{s}");
}

#[test]
fn an_effect_that_is_not_drawn_is_a_warning() {
    let d = one(&boxed(1, 3.0, 2.0, 1.0, 1.0, &cell("ShapeShdwType", "1")));
    let c = convert(&d, Format::Vsdx, &Limits::default()).unwrap();
    assert!(
        c.warnings.iter().any(|w| w.contains("shadows")),
        "{:?}",
        c.warnings
    );
    let c = convert(
        &one(&boxed(1, 3.0, 2.0, 1.0, 1.0, "")),
        Format::Vsdx,
        &Limits::default(),
    )
    .unwrap();
    assert!(c.warnings.is_empty(), "{:?}", c.warnings);
    // No page is said, too.
    let c = convert(&drawing(&[], ""), Format::Vsdx, &Limits::default()).unwrap();
    assert_eq!(c.slides, 0);
    assert!(c.warnings.iter().any(|w| w.contains("no pages")));
}

#[test]
fn the_first_pages_alone_and_a_source_read_part_by_part() {
    let d = fixture("sample.vsdx");
    let c = convert_first(&d, Format::Vsdx, &Limits::default(), 1).unwrap();
    assert_eq!((c.slides, c.total_slides), (1, 2));
    assert!(!has_part(&c.pptx, "ppt/media/image1.png"));
    let whole = convert(&d, Format::Vsdx, &Limits::default()).unwrap();
    let from =
        convert_first_from(Cursor::new(d), Format::Vsdx, &Limits::default(), usize::MAX).unwrap();
    assert_eq!(from.slides, whole.slides);
    assert_eq!(
        part(&from.pptx, "ppt/slides/slide1.xml"),
        part(&whole.pptx, "ppt/slides/slide1.xml")
    );
}

#[test]
fn the_extensions_name_the_format() {
    for e in ["vsdx", "VSDM", "vstx", "vstm"] {
        assert_eq!(Format::from_extension(e), Some(Format::Vsdx), "{e}");
    }
    assert_eq!(Format::Vsdx.name(), "vsdx");
    assert_eq!(Format::from_extension("vsd"), None);
    assert_eq!(Format::from_extension("vdx"), None);
}

#[test]
fn what_is_not_a_drawing_is_refused_by_kind() {
    let l = Limits::default();
    let kind = |d: &[u8]| convert(d, Format::Vsdx, &l).unwrap_err().kind();
    assert_eq!(kind(b"not a zip at all"), "not-format");
    assert_eq!(kind(b""), "not-format");
    // A package without the Visio parts, and another document's.
    let other = package(&[("word/document.xml", "<w:document/>".into())]);
    assert_eq!(kind(&other), "not-format");
    let odp = std::fs::read(format!(
        "{}/tests/fixtures/office/slides/sample.odp",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    assert_eq!(kind(&odp), "not-format");
    // A document part that is not a Visio document.
    let wrong = package(&[
        (
            "_rels/.rels",
            rels(&[("rId1", &format!("{REL}/document"), "visio/document.xml")]),
        ),
        ("visio/document.xml", "<Other/>".into()),
    ]);
    assert_eq!(kind(&wrong), "not-format");
    // A binary file (a compound file) is not a package; a password protected
    // package is a compound file with an encrypted stream.
    let cfb = build_cfb(&[("WordDocument", &[1u8; 600][..])]);
    assert_eq!(kind(&cfb), "not-format");
    let enc = build_cfb(&[
        ("EncryptedPackage", &[1u8; 600][..]),
        ("EncryptionInfo", &[2u8; 100][..]),
    ]);
    assert_eq!(kind(&enc), "encrypted");
    assert_eq!(
        convert_first_from(Cursor::new(enc), Format::Vsdx, &l, 1).unwrap_err(),
        Error::Encrypted
    );
    // A member of the package that is encrypted.
    let mut e = fixture("sample.vsdx");
    for i in 0..e.len().saturating_sub(10) {
        if e[i..].starts_with(b"PK\x03\x04") {
            e[i + 6] |= 1;
        } else if e[i..].starts_with(b"PK\x01\x02") {
            e[i + 8] |= 1;
        }
    }
    assert_eq!(kind(&e), "encrypted");
}

#[test]
fn damaged_xml_is_malformed_and_limits_are_too_large() {
    let l = Limits::default();
    let mut parts: Vec<(&str, String)> = vec![
        (
            "_rels/.rels",
            rels(&[("rId1", &format!("{REL}/document"), "visio/document.xml")]),
        ),
        ("visio/document.xml", format!("<VisioDocument {NS}")),
    ];
    let e = convert(&package(&parts), Format::Vsdx, &l).unwrap_err();
    assert_eq!(e.kind(), "malformed", "{e}");
    parts[1].1 = format!("<VisioDocument {NS}></Wrong></VisioDocument>");
    parts.push((
        "visio/_rels/document.xml.rels",
        rels(&[("rId2", &format!("{REL}/pages"), "pages/pages.xml")]),
    ));
    parts.push((
        "visio/pages/pages.xml",
        format!("<Pages {NS}><Page ID='0' Name='P'><Rel r:id='rId1'/></Page></Pages>"),
    ));
    parts.push((
        "visio/pages/_rels/pages.xml.rels",
        rels(&[("rId1", &format!("{REL}/page"), "p.xml")]),
    ));
    parts.push(("visio/pages/p.xml", "<PageContents ".into()));
    assert_eq!(
        convert(&package(&parts), Format::Vsdx, &l)
            .unwrap_err()
            .kind(),
        "malformed"
    );

    let many: String = (0..50).map(|i| boxed(i, 1.0, 1.0, 1.0, 1.0, "")).collect();
    let d = one(&many);
    assert_eq!(
        convert(&d, Format::Vsdx, &Limits::default().with_max_shapes(10)).unwrap_err(),
        Error::TooLarge("shapes")
    );
    let mut small = Limits::default();
    small.max_slides = 1;
    assert_eq!(
        convert(&fixture("sample.vsdx"), Format::Vsdx, &small).unwrap_err(),
        Error::TooLarge("slides")
    );
    let mut small = Limits::default();
    small.max_part = 300;
    assert!(matches!(
        convert(&fixture("sample.vsdx"), Format::Vsdx, &small),
        Err(Error::TooLarge(_))
    ));
    assert!(matches!(
        convert(&d, Format::Vsdx, &Limits::default().with_max_memory(10_000)),
        Err(Error::TooLarge(_))
    ));
    let mut small = Limits::default();
    small.max_input = 100;
    assert_eq!(
        convert(&d, Format::Vsdx, &small).unwrap_err(),
        Error::TooLarge("input")
    );
}

#[test]
fn a_shape_with_too_many_path_segments_is_too_large() {
    let mut rows =
        String::from("<Row T='MoveTo' IX='1'><Cell N='X' V='0'/><Cell N='Y' V='0'/></Row>");
    for i in 2..40_000 {
        rows.push_str(&format!(
            "<Row T='LineTo' IX='{i}'><Cell N='X' V='1'/><Cell N='Y' V='1'/></Row>"
        ));
    }
    let shape = format!(
        "<Shape ID='1'>{}<Section N='Geometry' IX='0'>{rows}</Section></Shape>",
        cell("Width", "1") + &cell("Height", "1")
    );
    // Within the bound of a shape.
    assert!(convert(&one(&shape), Format::Vsdx, &Limits::default()).is_ok());
    // Nine such sections in one shape are past it.
    let many = format!(
        "<Shape ID='1'>{}{}</Shape>",
        cell("Width", "1") + &cell("Height", "1"),
        (0..6)
            .map(|k| format!("<Section N='Geometry' IX='{k}'>{rows}</Section>"))
            .collect::<String>()
    );
    assert_eq!(
        convert(&one(&many), Format::Vsdx, &Limits::default()).unwrap_err(),
        Error::TooLarge("geometry segments")
    );
}

#[test]
fn hostile_structure_does_not_loop_or_panic() {
    // A page whose part is the pages part, and a master that instantiates
    // itself.
    let cyc = package(&[
        (
            "_rels/.rels",
            rels(&[("rId1", &format!("{REL}/document"), "visio/document.xml")]),
        ),
        ("visio/document.xml", format!("<VisioDocument {NS}/>")),
        (
            "visio/_rels/document.xml.rels",
            rels(&[("rId2", &format!("{REL}/pages"), "pages/pages.xml")]),
        ),
        (
            "visio/pages/pages.xml",
            format!("<Pages {NS}><Page ID='0' Name='P'><Rel r:id='rId1'/></Page></Pages>"),
        ),
        (
            "visio/pages/_rels/pages.xml.rels",
            rels(&[("rId1", &format!("{REL}/page"), "pages.xml")]),
        ),
    ]);
    let c = convert(&cyc, Format::Vsdx, &Limits::default()).unwrap();
    assert_eq!(c.slides, 1);
    let inst = "<Shape ID='1' Type='Shape' Master='7'><Cell N='PinX' V='3'/></Shape>";
    let mut d = master_package(inst);
    // The master holds an instance of itself.
    let looping =
        "<Shape ID='1' Type='Group' Master='7'><Shapes><Shape ID='2' Master='7'/></Shapes></Shape>";
    let doc = package(&[
        (
            "_rels/.rels",
            rels(&[("rId1", &format!("{REL}/document"), "visio/document.xml")]),
        ),
        ("visio/document.xml", format!("<VisioDocument {NS}/>")),
        (
            "visio/_rels/document.xml.rels",
            rels(&[
                ("rId1", &format!("{REL}/masters"), "masters/masters.xml"),
                ("rId2", &format!("{REL}/pages"), "pages/pages.xml"),
            ]),
        ),
        (
            "visio/masters/masters.xml",
            format!("<Masters {NS}><Master ID='7'><Rel r:id='rId1'/></Master></Masters>"),
        ),
        (
            "visio/masters/_rels/masters.xml.rels",
            rels(&[("rId1", &format!("{REL}/master"), "m.xml")]),
        ),
        (
            "visio/masters/m.xml",
            format!("<MasterContents {NS}><Shapes>{looping}</Shapes></MasterContents>"),
        ),
        (
            "visio/pages/pages.xml",
            format!("<Pages {NS}><Page ID='0' Name='P'><Rel r:id='rId1'/></Page></Pages>"),
        ),
        (
            "visio/pages/_rels/pages.xml.rels",
            rels(&[("rId1", &format!("{REL}/page"), "p.xml")]),
        ),
        (
            "visio/pages/p.xml",
            format!("<PageContents {NS}><Shapes>{looping}</Shapes></PageContents>"),
        ),
    ]);
    let r = convert(
        &doc,
        Format::Vsdx,
        &Limits::default().with_max_shapes(10_000),
    );
    assert!(r.is_ok() || matches!(r, Err(Error::TooLarge(_))), "{r:?}");
    d.truncate(d.len() / 2);
    let _ = convert(&d, Format::Vsdx, &Limits::default());
}
