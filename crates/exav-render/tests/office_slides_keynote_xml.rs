//! Keynote 1 to 5 documents (XML), over documents written here.

use exav_render::slides::{convert, convert_keynote_package, Error, Format, Limits};
use std::io::{Read, Write};

fn part(pptx: &[u8], name: &str) -> String {
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(pptx)).unwrap();
    let mut s = String::new();
    z.by_name(name).unwrap().read_to_string(&mut s).unwrap();
    s
}

fn zip_of(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default();
    for (name, data) in files {
        z.start_file(*name, opts).unwrap();
        z.write_all(data).unwrap();
    }
    z.finish().unwrap().into_inner()
}

fn gzip(d: &[u8]) -> Vec<u8> {
    let mut g = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    g.write_all(d).unwrap();
    g.finish().unwrap()
}

/// The header of a 2 by 2 pixel PNG: enough to be a picture.
const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\0\x02\0\0\0\x02\x08\x02\0\0\0";

fn color(r: f64, g: f64, b: f64) -> String {
    format!(r#"<sf:color sfa:r="{r}" sfa:g="{g}" sfa:b="{b}" sfa:a="1"/>"#)
}

fn geometry(x: f64, y: f64, w: f64, h: f64) -> String {
    format!(
        r#"<sf:geometry><sf:size sfa:w="{w}" sfa:h="{h}"/><sf:position sfa:x="{x}" sfa:y="{y}"/></sf:geometry>"#
    )
}

/// A text frame holding one paragraph per entry: its style and its text.
fn frame(paras: &[(&str, &str)]) -> String {
    let ps: String = paras
        .iter()
        .map(|(style, text)| format!(r#"<sf:p sf:style="{style}">{text}<sf:br/></sf:p>"#))
        .collect();
    format!(
        r#"<sf:text-storage><sf:stylesheet-ref sfa:IDREF="ss1"/><sf:text-body>{ps}</sf:text-body></sf:text-storage>"#
    )
}

const NS: &str = r#"xmlns:key="http://developer.apple.com/namespaces/keynote2" xmlns:sf="http://developer.apple.com/namespaces/sf" xmlns:sfa="http://developer.apple.com/namespaces/sfa" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance""#;

/// A Keynote 2 to 5 document of two slides: a master with a shape of its
/// own, a title placeholder and a body, styles that inherit one another,
/// and on the first slide a shape with text, a cropped picture and a movie.
fn document() -> String {
    let green = color(0.0, 1.0, 0.0);
    let blue = color(0.0, 0.0, 1.0);
    let red = color(1.0, 0.0, 0.0);
    let grey = color(0.5, 0.5, 0.5);
    let white = color(1.0, 1.0, 1.0);
    let title = frame(&[("child", "Slide <sf:span sf:style=\"base\">title</sf:span>")]);
    let body_frame = frame(&[("child", "Body text")]);
    let hello = frame(&[
        (
            "child",
            "Hello<sf:br/>again<sf:span sf:style=\"nullc\">spanned</sf:span>",
        ),
        ("plain", "Plain"),
    ]);
    let pos = geometry(100.0, 150.0, 300.0, 80.0);
    let stub = r#"<sf:geometry><sf:size sfa:w="1" sfa:h="1"/><sf:position sfa:x="0" sfa:y="0"/></sf:geometry>"#;
    let ph_geom = geometry(40.0, 20.0, 720.0, 90.0);
    let frame_geom = geometry(300.0, 300.0, 200.0, 100.0);
    let window = r#"<sf:size sfa:w="100" sfa:h="50"/><sf:position sfa:x="350" sfa:y="325"/>"#;
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<key:presentation {NS}>
 <key:size sfa:w="800" sfa:h="600"/>
 <key:theme-list><key:theme sfa:ID="th1">
  <key:stylesheet sfa:ID="ss1"><sf:styles>
   <sf:paragraphstyle sfa:ID="ps1" sf:ident="base"><sf:property-map>
    <sf:fontName><sf:string sfa:string="Helvetica-Bold"/></sf:fontName>
    <sf:fontSize><sf:number sfa:number="30"/></sf:fontSize>
    <sf:fontColor>{red}</sf:fontColor>
    <sf:alignment><sf:number sfa:number="2"/></sf:alignment>
   </sf:property-map></sf:paragraphstyle>
   <sf:paragraphstyle sfa:ID="ps2" sf:ident="child" sf:parent-ident="base"><sf:property-map>
    <sf:fontSize><sf:number sfa:number="20"/></sf:fontSize>
   </sf:property-map></sf:paragraphstyle>
   <sf:characterstyle sfa:ID="cs1" sf:ident="nullc"><sf:property-map>
    <sf:fontColor><sf:null/></sf:fontColor>
   </sf:property-map></sf:characterstyle>
   <sf:paragraphstyle sfa:ID="ps3" sf:ident="plain" sf:parent-ident="child"><sf:property-map>
    <sf:fontColor><sf:null/></sf:fontColor>
   </sf:property-map></sf:paragraphstyle>
   <sf:shape-style sfa:ID="sh1" sf:ident="shape1"><sf:property-map>
    <sf:fill>{green}</sf:fill>
    <sf:stroke><sf:stroke sf:width="2" sf:cap="round">{blue}<sf:pattern sf:type="solid"/></sf:stroke></sf:stroke>
   </sf:property-map></sf:shape-style>
   <sf:placeholder-style sfa:ID="ph1"><sf:property-map><sf:geometry>{ph_geom}</sf:geometry></sf:property-map></sf:placeholder-style>
  </sf:styles></key:stylesheet>
 </key:theme></key:theme-list>
 <key:master-slide-list>
  <key:master-slide sfa:ID="m1" key:name="Plain">
   <key:stylesheet sfa:ID="ssm1"><sf:parent-ref sfa:IDREF="ss1"/><sf:styles>
    <sf:slide-style sfa:ID="bgm"><sf:property-map><sf:fill>{grey}</sf:fill></sf:property-map></sf:slide-style>
   </sf:styles></key:stylesheet>
   <key:style-ref sfa:IDREF="bgm"/>
   <key:page><sf:layers>
    <sf:layer><sf:type><sf:string sfa:string="BGMasterSlideLayer"/></sf:type><sf:drawables>
     <sf:shape sfa:ID="mshape">{pos}<sf:style><sf:shape-style-ref sfa:IDREF="sh1"/></sf:style></sf:shape>
     <sf:title-placeholder sfa:ID="mtp">{stub}<sf:style><sf:placeholder-style-ref sfa:IDREF="ph1"/></sf:style><sf:text>{title}</sf:text></sf:title-placeholder>
    </sf:drawables></sf:layer>
    <sf:layer><sf:type><sf:string sfa:string="BGMasterSlidePrototypeLayer"/></sf:type><sf:drawables>
     <sf:shape sfa:ID="mproto">{geom}<sf:style><sf:shape-style-ref sfa:IDREF="sh1"/></sf:style></sf:shape>
    </sf:drawables></sf:layer>
   </sf:layers></key:page>
  </key:master-slide>
 </key:master-slide-list>
 <key:slide-list>
  <key:slide sfa:ID="s1">
   <key:stylesheet sfa:ID="sss1"><sf:parent-ref sfa:IDREF="ssm1"/><sf:styles>
    <sf:slide-style sfa:ID="bgs1"><sf:property-map><sf:fill>{white}</sf:fill></sf:property-map></sf:slide-style>
   </sf:styles></key:stylesheet>
   <key:master-ref sfa:IDREF="m1"/>
   <key:style-ref sfa:IDREF="bgs1"/>
   <key:bullets>
    <key:headline key:depth="0"><key:text>{title}</key:text></key:headline>
    <key:headline key:depth="1"><key:text>{body_frame}</key:text></key:headline>
   </key:bullets>
   <key:page><sf:layers><sf:layer><sf:drawables>
    <sf:title-placeholder sfa:ID="tp1">{stub}<sf:style><sf:placeholder-style-ref sfa:IDREF="ph1"/></sf:style></sf:title-placeholder>
    <sf:shape sfa:ID="a">{pos}<sf:style><sf:shape-style-ref sfa:IDREF="sh1"/></sf:style><sf:path><sf:bezier-path><sf:bezier sfa:path="M 0 0 L 300 0 L 300 80 Z"/></sf:bezier-path></sf:path><sf:text>{hello}</sf:text></sf:shape>
    <sf:media sfa:ID="pic">{frame_geom}<sf:crop-geometry>{window}</sf:crop-geometry><sf:content><sf:image-media><sf:filtered-image><sf:unfiltered><sf:data sf:path="Data/pic.png"/></sf:unfiltered></sf:filtered-image></sf:image-media></sf:content></sf:media>
    <sf:media sfa:ID="mov">{frame_geom2}<sf:content><sf:movie-media/></sf:content></sf:media>
   </sf:drawables></sf:layer></sf:layers></key:page>
  </key:slide>
  <key:slide sfa:ID="s2">
   <key:master-ref sfa:IDREF="m1"/>
   <key:bullets><key:headline key:depth="0"><key:text>{second}</key:text></key:headline></key:bullets>
   <key:page><sf:layers><sf:layer><sf:drawables>
    <sf:title-placeholder sfa:ID="tp2">{stub}<sf:style><sf:placeholder-style-ref sfa:IDREF="ph1"/></sf:style></sf:title-placeholder>
   </sf:drawables></sf:layer></sf:layers></key:page>
  </key:slide>
 </key:slide-list>
</key:presentation>"#,
        geom = geometry(0.0, 0.0, 10.0, 10.0),
        frame_geom2 = geometry(500.0, 300.0, 100.0, 60.0),
        second = frame(&[("child", "Second slide")]),
    )
}

/// The properties of the run holding `text`, and the run itself up to it.
fn run_before<'a>(x: &'a str, text: &str) -> &'a str {
    let to = &x[..x.find(text).unwrap_or_else(|| panic!("{text} in {x}"))];
    &to[to.rfind("<a:r>").unwrap()..]
}

/// The shape that holds `text`.
fn shape_of<'a>(x: &'a str, text: &str) -> &'a str {
    let to = &x[..x.find(text).unwrap_or_else(|| panic!("{text} in {x}"))];
    &to[to.rfind("<p:sp>").unwrap()..]
}

fn slide(pptx: &[u8], n: usize) -> String {
    part(pptx, &format!("ppt/slides/slide{n}.xml"))
}

#[test]
fn styles_inherit_and_shapes_have_their_fill_line_and_text() {
    let c = convert(
        &zip_of(&[("index.apxl", document().as_bytes()), ("Data/pic.png", PNG)]),
        Format::Keynote,
        &Limits::default(),
    )
    .unwrap();
    assert_eq!((c.slides, c.total_slides), (2, 2));
    let x = slide(&c.pptx, 1);
    // Slide size in points.
    assert!(part(&c.pptx, "ppt/presentation.xml").contains(r#"cx="10160000" cy="7620000""#));
    // The shape: green fill, a blue 2 point round line, its path.
    assert!(x.contains(r#"<a:srgbClr val="00FF00"/>"#), "{x}");
    assert!(
        x.contains(r#"w="25400""#) && x.contains(r#"<a:srgbClr val="0000FF"/>"#),
        "{x}"
    );
    assert!(
        x.contains(r#"<a:off x="1270000" y="1905000"/><a:ext cx="3810000" cy="1016000"/>"#),
        "{x}"
    );
    assert!(x.contains("<a:custGeom>"), "{x}");
    // The text: the child style's 20 points over the parent's bold, red,
    // centred text; a span of the parent's 30 points.
    assert!(x.contains(">Hello<") && x.contains(">againspanned<"), "{x}");
    // A break inside a paragraph is a line break; the last one ends it.
    assert_eq!(x.matches("<a:br>").count(), 1, "{x}");
    // `sf:null` in a paragraph style unsets what its parents give: black.
    // In a character style it sets nothing: the span keeps the paragraph's
    // look and so joins its run (">againspanned<" above).
    assert!(run_before(&x, ">Plain<").contains(r#"<a:srgbClr val="000000"/>"#));
    assert!(
        x.contains(r#"sz="2000""#) && x.contains(r#"sz="3000""#),
        "{x}"
    );
    assert!(
        x.contains(r#"b="1""#) && x.contains(r#"<a:srgbClr val="FF0000"/>"#),
        "{x}"
    );
    assert!(x.contains(r#"algn="ctr""#), "{x}");
    // The title is in the slide's headlines, placed by its placeholder's
    // style; the body has no placeholder in the slide's layer: hidden.
    assert!(x.contains(">title<") && x.contains(">Slide <"), "{x}");
    assert!(
        x.contains(r#"<a:off x="508000" y="254000"/><a:ext cx="9144000" cy="1143000"/>"#),
        "{x}"
    );
    assert!(!x.contains("Body text"), "{x}");
    // The slide's own background; the second slide has the master's.
    assert!(
        x.contains(r#"<p:bg><p:bgPr><a:solidFill><a:srgbClr val="FFFFFF"/>"#),
        "{x}"
    );
    let x2 = slide(&c.pptx, 2);
    assert!(!x2.contains("<p:bg>"), "{x2}");
    assert!(x2.contains("Second slide"), "{x2}");
    let m = part(&c.pptx, "ppt/slideMasters/slideMaster1.xml");
    assert!(
        m.contains(r#"<p:bg><p:bgPr><a:solidFill><a:srgbClr val="808080"/>"#),
        "{m}"
    );
}

#[test]
fn masters_show_their_objects_and_not_their_prototypes() {
    let c = convert(
        &zip_of(&[("index.apxl", document().as_bytes()), ("Data/pic.png", PNG)]),
        Format::Keynote,
        &Limits::default(),
    )
    .unwrap();
    let m = part(&c.pptx, "ppt/slideMasters/slideMaster1.xml");
    // The master's shape is there once, as is its green; the prototype
    // layer's 10 by 10 point shape (127000 EMU) is not, nor is its
    // placeholder's text.
    assert_eq!(m.matches("<p:sp>").count(), 1, "{m}");
    assert!(!m.contains(r#"cx="127000""#), "{m}");
    assert!(!m.contains("Slide "), "{m}");
}

#[test]
fn pictures_are_cropped_and_movies_are_boxes() {
    let c = convert(
        &zip_of(&[("index.apxl", document().as_bytes()), ("Data/pic.png", PNG)]),
        Format::Keynote,
        &Limits::default(),
    )
    .unwrap();
    let x = slide(&c.pptx, 1);
    // The window is the middle half of the frame each way.
    assert!(
        x.contains(r#"<a:srcRect l="25000" t="25000" r="25000" b="25000"/>"#),
        "{x}"
    );
    assert!(
        x.contains(r#"<a:off x="4445000" y="4127500"/><a:ext cx="1270000" cy="635000"/>"#),
        "{x}"
    );
    // The movie: a dark box with a triangle.
    assert!(x.contains(r#"prst="triangle""#), "{x}");
    assert!(
        c.warnings.iter().any(|w| w.contains("videos and sounds")),
        "{:?}",
        c.warnings
    );
    // Without the picture's file the shape is left out.
    let c = convert(
        &zip_of(&[("index.apxl", document().as_bytes())]),
        Format::Keynote,
        &Limits::default(),
    )
    .unwrap();
    assert!(!slide(&c.pptx, 1).contains("srcRect"));
}

#[test]
fn every_way_a_package_holds_the_xml() {
    let doc = document();
    let want = |pptx: &[u8]| {
        let x = slide(pptx, 1);
        assert!(x.contains(">Hello<") && x.contains("srcRect"), "{x}");
    };
    let gz = gzip(doc.as_bytes());
    for files in [
        vec![("index.apxl", doc.as_bytes()), ("Data/pic.png", PNG)],
        vec![("index.apxl.gz", &gz[..]), ("Data/pic.png", PNG)],
        // In a package directory, one level down.
        vec![
            ("Doc.key/index.apxl", doc.as_bytes()),
            ("Doc.key/Data/pic.png", PNG),
        ],
    ] {
        let c = convert(&zip_of(&files), Format::Keynote, &Limits::default()).unwrap();
        want(&c.pptx);
    }
    // As a directory's files.
    let c = convert_keynote_package(
        &[("index.apxl.gz", &gz[..]), ("Data/pic.png", PNG)],
        &Limits::default(),
    )
    .unwrap();
    want(&c.pptx);
    // As the XML alone, plain or gzipped: no pictures.
    let c = convert(doc.as_bytes(), Format::Keynote, &Limits::default()).unwrap();
    assert!(slide(&c.pptx, 1).contains(">Hello<"));
    let c = convert(&gz, Format::Keynote, &Limits::default()).unwrap();
    assert!(slide(&c.pptx, 1).contains(">Hello<"));
}

#[test]
fn headlines_are_the_text_of_slides_of_keynote_2_and_3() {
    // The same document without the placeholder's own text: the slide's
    // headlines give it, each at its depth, the title first.
    let c = convert(document().as_bytes(), Format::Keynote, &Limits::default()).unwrap();
    assert!(slide(&c.pptx, 1).contains("Slide "));
    let no_headlines = document()
        .replace("<key:headline", "<key:other")
        .replace("</key:headline>", "</key:other>");
    let c = convert(no_headlines.as_bytes(), Format::Keynote, &Limits::default()).unwrap();
    assert!(!slide(&c.pptx, 1).contains("Slide "));
}

/// A Keynote 1 document: the theme's slide size and prototypes, one master
/// with title and body placeholders and a slide with a title, a bullet, a
/// text box and a rotated shape.
fn keynote1() -> String {
    r#"<?xml version="1.0" encoding="UTF-8"?>
<presentation>
 <theme slide-size="800 600">
  <prototype-drawables>
   <shape stroke-color="0 0 1" stroke-width="3"><styles><fill-style fill-type="color" fill-color="0 1 0"/></styles></shape>
   <textbox transformation="1 0 0 1 0 0"><content font-name="Helvetica" font-size="18" font-color="g 0"/></textbox>
  </prototype-drawables>
  <master-slides>
   <master-slide id="m1" name="Plain">
    <background-fill-style fill-type="color" fill-color="0.5 0.5 0.5"/>
    <drawables>
     <title size="700 80" location="50 30" vertical-alignment="middle"/>
     <body size="700 400" location="50 130" bullet-indentation="0 30"/>
    </drawables>
    <prototype-bullets>
     <bullet level="1" marker-type="character"><character-bullet-style size="1"><bullet-characters font-size="20">*</bullet-characters></character-bullet-style><content font-size="20"/></bullet>
    </prototype-bullets>
   </master-slide>
  </master-slides>
 </theme>
 <slide-list>
  <slide master-slide-id="m1">
   <bullets>
    <bullet level="0"><content font-size="40" font-color="1 0 0">Title one</content></bullet>
    <bullet level="1" marker-type="inherited"><content>First point</content></bullet>
   </bullets>
   <drawables>
    <title/>
    <body/>
    <textbox size="200 50" transformation="1 0 0 1 100 500"><content>Free <span font-size="30">text</span></content></textbox>
    <shape path="M 0 0 L 100 0 L 100 50 Z" transformation="0 1 -1 0 300 300"/>
   </drawables>
  </slide>
  <slide master-slide-id="m1">
   <bullets><bullet level="0"><content>Second title</content></bullet></bullets>
   <drawables><title visibility="hidden"/></drawables>
  </slide>
 </slide-list>
</presentation>"#
        .to_string()
}

#[test]
fn keynote_1_documents() {
    let c = convert(keynote1().as_bytes(), Format::Keynote, &Limits::default()).unwrap();
    assert_eq!((c.slides, c.total_slides), (2, 2));
    let x = slide(&c.pptx, 1);
    assert!(part(&c.pptx, "ppt/presentation.xml").contains(r#"cx="10160000" cy="7620000""#));
    // The title and the bullet fill the master's placeholders.
    assert!(x.contains("Title one") && x.contains("First point"), "{x}");
    assert!(shape_of(&x, "Title one").contains(r#"<p:ph type="title"/>"#));
    assert!(shape_of(&x, "First point").contains(r#"<p:ph type="body""#));
    // A placeholder the slide hides shows nothing.
    assert!(!slide(&c.pptx, 2).contains("Second title"));
    assert!(
        x.contains(r#"sz="4000""#) && x.contains(r#"<a:srgbClr val="FF0000"/>"#),
        "{x}"
    );
    assert!(x.contains(r#"<a:buChar char="*""#), "{x}");
    assert!(x.contains(r#"anchor="ctr""#), "{x}");
    // The text box takes its prototype's size and a span's own.
    assert!(x.contains(">Free <") && x.contains(">text<"), "{x}");
    assert!(
        x.contains(r#"sz="1800""#) && x.contains(r#"sz="3000""#),
        "{x}"
    );
    // The shape takes its prototype's green fill and 3 point blue line, and
    // is turned a quarter.
    assert!(x.contains(r#"<a:srgbClr val="00FF00"/>"#), "{x}");
    assert!(x.contains(r#"w="38100""#), "{x}");
    assert!(x.contains(r#"rot="5400000""#), "{x}");
    let m = part(&c.pptx, "ppt/slideMasters/slideMaster1.xml");
    assert!(m.contains(r#"<a:srgbClr val="808080"/>"#), "{m}");
}

#[test]
fn xml_that_is_not_a_keynote_document_is_refused() {
    for xml in [
        "<other/>",
        "<key:presentation xmlns:key=\"http://developer.apple.com/namespaces/keynote2\"/>",
        "<presentation/>",
    ] {
        let e = convert(xml.as_bytes(), Format::Keynote, &Limits::default()).unwrap_err();
        assert!(matches!(e, Error::NotFormat(_)), "{xml}: {e:?}");
    }
}

#[test]
fn a_damaged_document_does_not_panic() {
    let doc = document();
    for n in (0..doc.len()).step_by(97) {
        let _ = convert(&doc.as_bytes()[..n], Format::Keynote, &Limits::default());
    }
    let one = keynote1();
    for n in (0..one.len()).step_by(31) {
        let _ = convert(&one.as_bytes()[..n], Format::Keynote, &Limits::default());
    }
}
