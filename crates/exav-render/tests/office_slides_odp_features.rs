//! OpenDocument features, over flat documents written here.

use exav_render::slides::{Error, Format, Limits, convert};
use exav_unpack::package::Package;

fn part(pptx: &[u8], name: &str) -> String {
    let part = Package::from_bytes(pptx)
        .unwrap()
        .read(name, u64::MAX)
        .unwrap()
        .unwrap();
    String::from_utf8(part).unwrap()
}

fn names(pptx: &[u8]) -> Vec<String> {
    Package::from_bytes(pptx).unwrap().names(usize::MAX)
}

const NS: &str = r#"xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0" xmlns:presentation="urn:oasis:names:tc:opendocument:xmlns:presentation:1.0" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0""#;

/// A flat presentation with `styles` in its common styles, `auto` in its
/// automatic styles and one page holding `page`.
fn fodp(styles: &str, auto: &str, page: &str) -> String {
    format!(
        r#"<office:document {NS} office:mimetype="application/vnd.oasis.opendocument.presentation"><office:styles>{styles}</office:styles><office:automatic-styles>{auto}</office:automatic-styles><office:body><office:presentation><draw:page>{page}</draw:page></office:presentation></office:body></office:document>"#
    )
}

fn slide1(doc: &str) -> String {
    let c = convert(doc.as_bytes(), Format::Fodp, &Limits::default()).unwrap();
    part(&c.pptx, "ppt/slides/slide1.xml")
}

/// A custom shape of 10 by 10 cm with an enhanced path in a 100 by 100
/// view box.
fn custom(path: &str, extra: &str) -> String {
    format!(
        r#"<draw:custom-shape svg:x="0cm" svg:y="0cm" svg:width="10cm" svg:height="10cm"><text:p>T</text:p><draw:enhanced-geometry svg:viewBox="0 0 100 100" draw:enhanced-path="{path}" {extra}/></draw:custom-shape>"#
    )
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

/// The header of a 2 by 2 pixel PNG: enough to be a picture.
const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\0\x02\0\0\0\x02\x08\x02\0\0\0";

#[test]
fn the_page_has_the_size_odf_defaults_to() {
    // No page layout: 28 by 15.75 cm.
    let c = convert(
        fodp("", "", "").as_bytes(),
        Format::Fodp,
        &Limits::default(),
    )
    .unwrap();
    assert!(part(&c.pptx, "ppt/presentation.xml").contains(r#"cx="10080000" cy="5670000""#));
}

#[test]
fn shapes_without_a_style_have_the_style_called_standard() {
    let rect = r#"<draw:rect svg:x="0cm" svg:y="0cm" svg:width="2cm" svg:height="2cm"/>"#;
    // Without it: filled blue.
    let x = slide1(&fodp("", "", rect));
    assert!(x.contains(r#"<a:srgbClr val="729FCF"/>"#), "{x}");
    // With it: what it says, here nothing to draw.
    let std = r#"<style:style style:name="standard" style:family="graphic"><style:graphic-properties draw:fill="none" draw:stroke="none"/></style:style>"#;
    let x = slide1(&fodp(std, "", rect));
    assert!(
        !x.contains("729FCF") && x.contains("<a:noFill/><a:ln><a:noFill/></a:ln>"),
        "{x}"
    );
}

#[test]
fn empty_placeholders_show_only_what_they_fill_and_draw() {
    let auto = r##"<style:style style:name="red" style:family="graphic"><style:graphic-properties draw:fill="solid" draw:fill-color="#ff0000" draw:stroke="none"/></style:style><style:style style:name="none" style:family="graphic"><style:graphic-properties draw:fill="none" draw:stroke="none"/></style:style>"##;
    let frame = |style: &str, x: u32| {
        format!(
            r#"<draw:frame draw:style-name="{style}" presentation:class="outline" presentation:placeholder="true" svg:x="{x}cm" svg:y="0cm" svg:width="4cm" svg:height="2cm"><draw:text-box/></draw:frame>"#
        )
    };
    let x = slide1(&fodp("", auto, &(frame("red", 0) + &frame("none", 5))));
    assert_eq!(x.matches("<p:sp>").count(), 1, "{x}");
    assert!(x.contains(r#"<a:srgbClr val="FF0000"/>"#), "{x}");
}

/// The paragraph of `x` that holds `text`, up to the text.
fn paragraph<'a>(x: &'a str, text: &str) -> &'a str {
    let to = x.find(text).unwrap_or_else(|| panic!("{text} in {x}"));
    &x[x[..to].rfind("<a:p>").unwrap()..to]
}

#[test]
fn list_headers_are_not_bulleted_and_items_are() {
    let auto = r#"<text:list-style style:name="L1"><text:list-level-style-bullet text:level="1" text:bullet-char="*"/></text:list-style>"#;
    let page = r#"<draw:frame svg:x="0cm" svg:y="0cm" svg:width="8cm" svg:height="4cm"><draw:text-box><text:list text:style-name="L1"><text:list-header><text:p>Head</text:p></text:list-header><text:list-item><text:p>Item</text:p></text:list-item></text:list></draw:text-box></draw:frame>"#;
    let x = slide1(&fodp("", auto, page));
    assert!(!paragraph(&x, ">Head<").contains("buChar"), "{x}");
    assert!(
        paragraph(&x, ">Item<").contains(r#"<a:buChar char="*""#),
        "{x}"
    );
}

#[test]
fn picture_bullets_are_pictures() {
    let auto = format!(
        r#"<text:list-style style:name="L1"><text:list-level-style-image text:level="1"><office:binary-data>{}</office:binary-data></text:list-level-style-image></text:list-style>"#,
        base64(PNG)
    );
    let page = r#"<draw:frame svg:x="0cm" svg:y="0cm" svg:width="8cm" svg:height="4cm"><draw:text-box><text:list text:style-name="L1"><text:list-item><text:p>Item</text:p></text:list-item></text:list></draw:text-box></draw:frame>"#;
    let c = convert(
        fodp("", &auto, page).as_bytes(),
        Format::Fodp,
        &Limits::default(),
    )
    .unwrap();
    let x = part(&c.pptx, "ppt/slides/slide1.xml");
    assert!(x.contains("<a:buBlip>"), "{x}");
    assert!(names(&c.pptx).iter().any(|n| n == "ppt/media/image1.png"));
    // A picture that cannot be read is a round bullet.
    let broken = auto.replace(&base64(PNG), "AAAA");
    let x = slide1(&fodp("", &broken, page));
    assert!(!x.contains("buBlip") && x.contains("<a:buChar"), "{x}");
}

#[test]
fn custom_shapes_follow_their_enhanced_paths() {
    // Even-odd: the inner square is drawn against the outer one's
    // direction, so that it is a hole under the nonzero rule.
    let x = slide1(&fodp(
        "",
        "",
        &custom(
            "M 0 0 L 100 0 100 100 0 100 Z M 20 20 L 80 20 80 80 20 80 Z N",
            "",
        ),
    ));
    assert!(
        x.contains(r#"<a:close/><a:moveTo><a:pt x="20000" y="80000"/>"#),
        "{x}"
    );
    // A path that does not nest stays as it is.
    let x = slide1(&fodp(
        "",
        "",
        &custom(
            "M 0 0 L 40 0 40 40 0 40 Z M 60 60 L 100 60 100 100 60 100 Z N",
            "",
        ),
    ));
    assert!(
        x.contains(r#"<a:close/><a:moveTo><a:pt x="60000" y="60000"/>"#),
        "{x}"
    );
    // A line that comes first starts the path.
    let x = slide1(&fodp("", "", &custom("L 10 10 90 10 90 90 Z N", "")));
    assert!(
        x.contains(r#"<a:path w="100000" h="100000"><a:moveTo><a:pt x="10000" y="10000"/>"#),
        "{x}"
    );
    // An arc that ends before it starts turns the long way round: from the
    // bottom of the circle clockwise to its right, three quarters.
    let x = slide1(&fodp("", "", &custom("M 50 100 T 50 50 50 50 90 0 N", "")));
    assert_eq!(x.matches("<a:cubicBezTo>").count(), 3, "{x}");
    assert!(
        x.contains(r#"<a:pt x="100000" y="50000"/></a:cubicBezTo>"#),
        "{x}"
    );
    // An arc: from the right of the circle a quarter turn to its bottom.
    let x = slide1(&fodp("", "", &custom("M 100 50 T 50 50 50 50 0 90 N", "")));
    assert!(
        x.contains(r#"<a:cubicBezTo><a:pt x="100000" y="77614"/><a:pt x="77614" y="100000"/><a:pt x="50000" y="100000"/></a:cubicBezTo>"#),
        "{x}"
    );
}

#[test]
fn paths_with_no_fill_or_no_stroke_become_shapes_of_their_own() {
    let x = slide1(&fodp(
        "",
        "",
        &custom("M 0 0 L 100 0 100 100 Z F N M 0 0 L 100 100 S N", ""),
    ));
    assert_eq!(x.matches("<p:sp>").count(), 2, "{x}");
    // The first is stroked and not filled, the second filled and not stroked.
    let (a, b) = x.split_once("</p:sp>").unwrap();
    assert!(a.contains("<a:noFill/><a:ln w=\"9525\">"), "{a}");
    assert!(
        b.contains("<a:ln><a:noFill/></a:ln>") && b.contains("729FCF"),
        "{b}"
    );
}

#[test]
fn text_stays_in_the_shapes_text_area() {
    let x = slide1(&fodp(
        "",
        "",
        &custom(
            "M 0 0 L 100 0 100 100 0 100 Z N",
            r#"draw:text-areas="10 20 70 90""#,
        ),
    ));
    // 10, 20, 30 and 10 percent of the 10 cm (3600000 EMU) box.
    assert!(
        x.contains(r#"lIns="360000" tIns="720000" rIns="1080000" bIns="360000""#),
        "{x}"
    );
}

#[test]
fn videos_and_sounds_are_boxes() {
    let plugin = |href: &str| {
        format!(
            r#"<draw:frame svg:x="0cm" svg:y="0cm" svg:width="8cm" svg:height="6cm"><draw:plugin xlink:href="{href}"/></draw:frame>"#
        )
    };
    let c = convert(
        fodp("", "", &plugin("movie.mp4")).as_bytes(),
        Format::Fodp,
        &Limits::default(),
    )
    .unwrap();
    let x = part(&c.pptx, "ppt/slides/slide1.xml");
    assert!(
        x.contains(r#"<a:srgbClr val="202020"/>"#) && x.contains("triangle"),
        "{x}"
    );
    assert!(c.warnings.iter().any(|w| w.contains("videos and sounds")));
    let x = slide1(&fodp("", "", &plugin("song.mp3")));
    assert!(x.contains(r#"<a:srgbClr val="E8E8E8"/>"#), "{x}");
}

#[test]
fn a_link_after_text_of_the_same_style_keeps_its_link() {
    let rect = r#"<draw:rect svg:x="0cm" svg:y="0cm" svg:width="8cm" svg:height="2cm"><text:p>go <text:a xlink:href="https://example.test/x">here</text:a> now</text:p></draw:rect>"#;
    let c = convert(
        fodp("", "", rect).as_bytes(),
        Format::Fodp,
        &Limits::default(),
    )
    .unwrap();
    let x = part(&c.pptx, "ppt/slides/slide1.xml");
    // Three runs, the middle one a link to the address.
    assert_eq!(x.matches("<a:hlinkClick").count(), 1, "{x}");
    assert!(part(&c.pptx, "ppt/slides/_rels/slide1.xml.rels").contains("https://example.test/x"));
    let i = x.find("<a:hlinkClick").unwrap();
    assert!(x[i..].contains(">here</a:t>"), "{x}");
}

#[test]
fn a_paragraph_property_is_not_read_as_a_text_property() {
    // Both name fo:background-color: a text style's is the highlight of its
    // text, a paragraph style's is not.
    let auto = r##"<style:style style:name="P1" style:family="paragraph"><style:paragraph-properties fo:background-color="#ff0000"/></style:style><style:style style:name="T1" style:family="text"><style:text-properties fo:background-color="#00ff00"/></style:style>"##;
    let page = r#"<draw:frame svg:x="0cm" svg:y="0cm" svg:width="8cm" svg:height="4cm"><draw:text-box><text:p text:style-name="P1">plain</text:p><text:p><text:span text:style-name="T1">marked</text:span></text:p></draw:text-box></draw:frame>"#;
    let x = slide1(&fodp("", auto, page));
    assert!(!paragraph(&x, ">plain<").contains("highlight"), "{x}");
    assert!(
        paragraph(&x, ">marked<").contains(r#"<a:highlight><a:srgbClr val="00FF00"/>"#),
        "{x}"
    );
}

#[test]
fn a_number_with_a_prefix_and_a_suffix_is_numbered_in_parentheses() {
    let auto = r#"<text:list-style style:name="L1"><text:list-level-style-number text:level="1" style:num-prefix="(" style:num-suffix=")" style:num-format="1"/></text:list-style>"#;
    let page = r#"<draw:frame svg:x="0cm" svg:y="0cm" svg:width="8cm" svg:height="4cm"><draw:text-box><text:list text:style-name="L1"><text:list-item><text:p>Item</text:p></text:list-item></text:list></draw:text-box></draw:frame>"#;
    let x = slide1(&fodp("", auto, page));
    assert!(
        paragraph(&x, ">Item<").contains(r#"<a:buAutoNum type="arabicParenBoth""#),
        "{x}"
    );
}

#[test]
fn a_shorthand_of_a_style_replaces_the_sides_of_its_parent() {
    // The parent sets the left padding, the child sets all four.
    let auto = r#"<style:style style:name="g1" style:family="graphic"><style:graphic-properties fo:padding-left="1cm"/></style:style><style:style style:name="g2" style:family="graphic" style:parent-style-name="g1"><style:graphic-properties fo:padding="2cm"/></style:style>"#;
    let page = r#"<draw:frame draw:style-name="g2" svg:x="0cm" svg:y="0cm" svg:width="8cm" svg:height="4cm"><draw:text-box><text:p>T</text:p></draw:text-box></draw:frame>"#;
    let x = slide1(&fodp("", auto, page));
    assert!(
        x.contains(r#"lIns="720000" tIns="720000" rIns="720000" bIns="720000""#),
        "{x}"
    );
}

#[test]
fn a_margin_shorthand_gives_the_margins_of_a_paragraph() {
    let auto = r#"<style:style style:name="P1" style:family="paragraph"><style:paragraph-properties fo:margin="1cm"/></style:style>"#;
    let page = r#"<draw:frame svg:x="0cm" svg:y="0cm" svg:width="8cm" svg:height="4cm"><draw:text-box><text:p text:style-name="P1">T</text:p></draw:text-box></draw:frame>"#;
    let x = slide1(&fodp("", auto, page));
    let p = paragraph(&x, ">T<");
    assert!(p.contains(r#"marL="360000""#), "{x}");
    assert!(p.contains(r#"<a:spcBef><a:spcPts val="2835"/>"#), "{x}");
}

#[test]
fn the_nearer_style_gives_the_colour_whichever_way() {
    let auto = r##"<style:style style:name="T1" style:family="text"><style:text-properties fo:color="#ff0000"/></style:style><style:style style:name="T2" style:family="text" style:parent-style-name="T1"><style:text-properties style:use-window-font-color="true"/></style:style>"##;
    let page = r#"<draw:frame svg:x="0cm" svg:y="0cm" svg:width="8cm" svg:height="4cm"><draw:text-box><text:p><text:span text:style-name="T2">auto</text:span></text:p></draw:text-box></draw:frame>"#;
    let x = slide1(&fodp("", auto, page));
    assert!(!paragraph(&x, ">auto<").contains("FF0000"), "{x}");
}

#[test]
fn a_percentage_size_is_taken_of_the_size_of_the_parent_style() {
    let auto = r#"<style:style style:name="T1" style:family="text"><style:text-properties fo:font-size="20pt"/></style:style><style:style style:name="T2" style:family="text" style:parent-style-name="T1"><style:text-properties fo:font-size="50%"/></style:style>"#;
    let page = r#"<draw:frame svg:x="0cm" svg:y="0cm" svg:width="8cm" svg:height="4cm"><draw:text-box><text:p><text:span text:style-name="T2">half</text:span></text:p></draw:text-box></draw:frame>"#;
    let x = slide1(&fodp("", auto, page));
    assert!(paragraph(&x, ">half<").contains(r#"sz="1000""#), "{x}");
}

#[test]
fn a_font_family_of_the_asian_or_complex_script_gives_its_font() {
    // The child's family replaces the parent's face.
    let auto = r#"<style:style style:name="T1" style:family="text"><style:text-properties style:font-name-asian="Mincho" style:font-name-complex="Naskh"/></style:style><style:style style:name="T2" style:family="text" style:parent-style-name="T1"><style:text-properties style:font-family-asian="Gothic" style:font-family-complex="Amiri"/></style:style>"#;
    let page = r#"<draw:frame svg:x="0cm" svg:y="0cm" svg:width="8cm" svg:height="4cm"><draw:text-box><text:p><text:span text:style-name="T2">fonts</text:span></text:p></draw:text-box></draw:frame>"#;
    let x = slide1(&fodp("", auto, page));
    let p = paragraph(&x, ">fonts<");
    assert!(p.contains(r#"<a:ea typeface="Gothic"/>"#), "{x}");
    assert!(p.contains(r#"<a:cs typeface="Amiri"/>"#), "{x}");
}

#[test]
fn resolved_styles_count_in_the_memory_limit() {
    // 30 styles deep with 40 properties each: a style resolved from the
    // bottom holds all 1200.
    let mut styles = String::new();
    for k in 0..30 {
        let parent = match k {
            0 => String::new(),
            _ => format!(r#" style:parent-style-name="c{}""#, k - 1),
        };
        let props: String = (0..40).map(|j| format!(r#" svg:k{k}a{j}="v""#)).collect();
        styles += &format!(
            r#"<style:style style:name="c{k}" style:family="graphic"{parent}><style:graphic-properties{props}/></style:style>"#
        );
    }
    let leaves: String = (0..150)
        .map(|i| format!(r#"<style:style style:name="l{i}" style:family="graphic" style:parent-style-name="c29"/>"#))
        .collect();
    let rects = |name: &dyn Fn(usize) -> String| -> String {
        (0..150)
            .map(|i| format!(r#"<draw:rect draw:style-name="{}" svg:x="0cm" svg:y="0cm" svg:width="1cm" svg:height="1cm"/>"#, name(i)))
            .collect()
    };
    let limits = Limits::default().with_max_memory(4 << 20);
    // One style used 150 times is resolved once.
    let same = fodp(&styles, &leaves, &rects(&|_| "l0".into()));
    assert!(convert(same.as_bytes(), Format::Fodp, &limits).is_ok());
    // 150 styles are 150 resolutions, 16 MB or so.
    let each = fodp(&styles, &leaves, &rects(&|i| format!("l{i}")));
    let err = convert(each.as_bytes(), Format::Fodp, &limits).err();
    assert!(matches!(err, Some(Error::TooLarge("memory"))), "{err:?}");
}
