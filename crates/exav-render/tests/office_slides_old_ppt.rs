//! PowerPoint 95 and the older versions, over documents built here: a
//! PowerPoint 95 stream in a compound file, and the headers of versions 2
//! to 4.

use exav_render::formats::office::test_util::build_cfb as build;
use exav_render::slides::{Error, Format, Limits, convert};
use std::io::Read;

fn part(pptx: &[u8], name: &str) -> String {
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(pptx)).unwrap();
    let mut s = String::new();
    z.by_name(name).unwrap().read_to_string(&mut s).unwrap();
    s
}

/// A PowerPoint 95 record: type, flag (0xFFFF for a container), length and
/// identifier, then the body.
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

/// A colour as the format has it: red, green, blue and 0xFE for "this RGB".
const fn rgb(r: u8, g: u8, b: u8) -> [u8; 4] {
    [r, g, b, 0xFE]
}

/// A shape's look (0x0BBD, 56 bytes): the line and the fill.
fn look(line: Option<([u8; 4], u8)>, fill: Option<[u8; 4]>) -> Vec<u8> {
    let mut d = vec![0u8; 56];
    match line {
        Some((c, width)) => {
            d[3] = width;
            d[4..8].copy_from_slice(&c);
        }
        None => d[0] = 0xFF,
    }
    match fill {
        Some(c) => {
            d[13] = 1;
            d[20..24].copy_from_slice(&c);
        }
        None => d[12] = 0xFF,
    }
    d
}

/// A shape's bounds (0x0BC1, 40 bytes), the origin at the slide's centre.
fn bounds(code: i32, l: i32, t: i32, r: i32, b: i32, rot: i32) -> Vec<u8> {
    i32s(&[code, 0, 0, l, t, r, b, rot, 0, 0])
}

fn shape(b: Vec<u8>, look: Vec<u8>, extra: &[Vec<u8>]) -> Vec<u8> {
    let mut kids = vec![rec(0x0BC1, 0, 0, &b), rec(0x0BBD, 0, 0, &look)];
    kids.extend_from_slice(extra);
    container(0x0BC0, &kids)
}

/// A run: characters it covers, its kind, and its properties.
fn run(count: u32, typ: u32, props: &[u8]) -> Vec<u8> {
    let mut v = vec![];
    for x in [count, typ, 0, props.len() as u32, 0] {
        v.extend(x.to_le_bytes());
    }
    v.extend(props);
    v
}

/// Character properties: font index, size, flags, colour.
fn char_props(font: u16, size: u16, flags: u16, color: [u8; 4]) -> Vec<u8> {
    let mut p = vec![0u8; 24];
    p[0..2].copy_from_slice(&font.to_le_bytes());
    p[4..6].copy_from_slice(&size.to_le_bytes());
    p[8..10].copy_from_slice(&flags.to_le_bytes());
    p[10..14].copy_from_slice(&color);
    p
}

/// Paragraph properties: bullet flags, bullet character, alignment and the
/// bullet's size in percent.
fn para_props(bullet: bool, ch: u8, align: u32, size: u32) -> Vec<u8> {
    let mut p = vec![0u8; 44];
    p[0] = u8::from(bullet);
    p[6] = ch;
    p[12..16].copy_from_slice(&size.to_le_bytes());
    p[28..32].copy_from_slice(&align.to_le_bytes());
    p
}

/// A text object: the characters (in Windows 1252) and runs of each kind.
fn text(chars: &[u8], char_runs: &[Vec<u8>], para_runs: &[Vec<u8>]) -> Vec<u8> {
    let runs =
        |typ: u32, rs: &[Vec<u8>]| rec(0x07EC, 0xFFFF, 0, &rec(0x07EE, 0, typ, &rs.concat()));
    let body = container(
        0x0FE0,
        &[
            rec(0x07EE, 0, 53, chars),
            runs(0x0FE2, char_runs),
            runs(0x0FE3, para_runs),
        ],
    );
    container(0x0FA1, &[container(0x0FA2, &[body])])
}

/// A PowerPoint 95 stream of one slide holding `shapes` on a 10 by 7.5
/// inch page, and one font, "Arial".
fn stream(shapes: &[Vec<u8>]) -> Vec<u8> {
    let atom = rec(0x03E9, 0, 0, &i32s(&[5760, 4320]));
    let mut font = vec![0u8; 60];
    font[28..33].copy_from_slice(b"Arial");
    let env = container(0x03F2, &[rec(0x0FB7, 0, 0, &font)]);
    let slide = container(0x03EE, &[container(0x0BB8, shapes)]);
    let doc = container(0x03E8, &[atom, env, container(0x07D0, &[slide])]);
    container(3, &[doc])
}

fn convert95(stream: &[u8]) -> Result<exav_render::slides::Converted, Error> {
    let cf = build(&[("PowerPoint Document", stream)]);
    convert(&cf, Format::Ppt, &Limits::default())
}

fn slide1(stream: &[u8]) -> String {
    let c = convert95(stream).unwrap();
    assert_eq!((c.slides, c.total_slides), (1, 1));
    part(&c.pptx, "ppt/slides/slide1.xml")
}

#[test]
fn shapes_have_their_geometry_fill_and_line() {
    let s = stream(&[
        // A rectangle 1 inch wide and 0.5 high at the page's centre, filled
        // red, with a blue line.
        shape(
            bounds(-3, 0, 0, 576, 288, 0),
            look(Some((rgb(0, 0, 255), 0)), Some(rgb(255, 0, 0))),
            &[],
        ),
        // An ellipse without a line, filled green, rotated.
        shape(
            bounds(-1, -576, -288, -288, 0, 1344),
            look(None, Some(rgb(0, 255, 0))),
            &[],
        ),
        // A shape without a line or a fill is not drawn.
        shape(bounds(-3, 0, 0, 10, 10, 0), look(None, None), &[]),
    ]);
    let x = slide1(&s);
    assert_eq!(x.matches("<p:sp>").count(), 2, "{x}");
    assert!(x.contains(r#"<a:srgbClr val="FF0000"/>"#), "{x}");
    assert!(x.contains(r#"<a:srgbClr val="0000FF"/>"#), "{x}");
    assert!(x.contains(r#"<a:srgbClr val="00FF00"/>"#), "{x}");
    assert!(x.contains(r#"prst="ellipse""#), "{x}");
    // The centre of a 10 by 7.5 inch page is at 5 by 3.75 inches; the
    // rectangle is 1 by 0.5 inch from there.
    assert!(
        x.contains(r#"<a:off x="4572000" y="3429000"/><a:ext cx="914400" cy="457200"/>"#),
        "{x}"
    );
    // 1344 of 5376 is a quarter turn.
    assert!(x.contains(r#"rot="5400000""#), "{x}");
}

#[test]
fn lines_have_arrows() {
    let l = container(
        0x0BC6,
        &[
            rec(0x0BC7, 0, 0, &i32s(&[-288, -144, 288, 144])),
            rec(0x0BBD, 0, 0, &look(Some((rgb(0, 0, 0), 1)), None)),
            rec(0x0BBF, 0, 0, &[0, 1, 0, 0]),
        ],
    );
    let x = slide1(&stream(&[l]));
    assert!(x.contains("<a:tailEnd type=\"triangle\""), "{x}");
    assert!(!x.contains("<a:headEnd type"), "{x}");
    // 2 points wide.
    assert!(x.contains(r#"w="25400""#), "{x}");
}

#[test]
fn text_has_its_runs_paragraphs_and_fonts() {
    let chars = b"Hello\rWorld caf\xe9";
    let t = text(
        chars,
        &[
            run(5, 0x0FE2, &char_props(0, 24, 1, rgb(255, 0, 0))),
            run(12, 0x0FE2, &char_props(0, 12, 2, rgb(0, 0, 0))),
        ],
        &[
            run(6, 0x0FE3, &para_props(false, 0, 1, 0)),
            run(11, 0x0FE3, &para_props(true, b'*', 0, 80)),
        ],
    );
    let x = slide1(&stream(&[shape(
        bounds(-3, -576, -288, 576, 288, 0),
        look(None, Some(rgb(255, 255, 255))),
        &[t],
    )]));
    assert!(x.contains(">Hello<"), "{x}");
    assert!(x.contains(">World caf\u{e9}<"), "{x}");
    assert!(x.contains(r#"sz="2400""#) && x.contains(r#"b="1""#), "{x}");
    assert!(x.contains(r#"sz="1200""#) && x.contains(r#"i="1""#), "{x}");
    assert!(x.contains(r#"typeface="Arial""#), "{x}");
    assert!(x.contains(r#"algn="ctr""#), "{x}");
    assert!(x.contains(r#"<a:buChar char="*""#), "{x}");
    assert!(x.contains(r#"<a:buSzPct val="80000"/>"#), "{x}");
}

/// The bullet's size, a percent, is kept from 25 to 400: past it there is none,
/// and a size too big to take a thousand times is not an overflow.
#[test]
fn a_bullet_size_out_of_range_is_dropped() {
    let slide = |size: u32| {
        let t = text(
            b"abc",
            &[run(3, 0x0FE2, &char_props(0, 12, 0, rgb(0, 0, 0)))],
            &[run(3, 0x0FE3, &para_props(true, b'*', 0, size))],
        );
        slide1(&stream(&[shape(
            bounds(-3, -576, -288, 576, 288, 0),
            look(None, Some(rgb(255, 255, 255))),
            &[t],
        )]))
    };
    assert!(slide(400).contains(r#"<a:buSzPct val="400000"/>"#));
    for size in [24, 401, 4_294_968, u32::MAX] {
        let x = slide(size);
        assert!(x.contains("<a:buChar"), "{size}: {x}");
        assert!(!x.contains("buSzPct"), "{size}: {x}");
    }
}

#[test]
fn a_damaged_stream_does_not_panic() {
    let t = text(
        b"abc",
        &[run(3, 0x0FE2, &char_props(0, 12, 0, rgb(0, 0, 0)))],
        &[run(3, 0x0FE3, &para_props(false, 0, 0, 0))],
    );
    let s = stream(&[shape(
        bounds(-3, -576, -288, 576, 288, 0),
        look(Some((rgb(0, 0, 0), 0)), Some(rgb(1, 2, 3))),
        &[t],
    )]);
    for n in 0..s.len() {
        let _ = convert95(&s[..n]);
    }
    let mut s = s;
    for i in (0..s.len()).step_by(7) {
        let keep = s[i];
        s[i] = 0xFF;
        let _ = convert95(&s);
        s[i] = keep;
    }
}

#[test]
fn old_versions_are_recognised_and_refused_as_unsupported() {
    let le = |v: u8| [0xED, 0xDE, 0xAD, 0x0B, v, 0, 0, 0, 1, 2, 3, 4];
    for (bytes, what) in [
        (le(2).to_vec(), "PowerPoint 2"),
        (le(3).to_vec(), "PowerPoint 3"),
        (
            vec![0x0B, 0xAD, 0xDE, 0xED, 0, 0, 0, 3, 1, 2, 3, 4],
            "PowerPoint 3 for Macintosh",
        ),
        // Version 4 is a stream of a compound file.
        (build(&[("PP40", &le(4))]), "PowerPoint 4"),
    ] {
        let e = convert(&bytes, Format::Ppt, &Limits::default()).unwrap_err();
        assert_eq!(e.kind(), "unsupported", "{what}");
        assert!(e.to_string().contains(what), "{what}: {e}");
    }
    // A version they never had.
    let e = convert(&le(9), Format::Ppt, &Limits::default()).unwrap_err();
    assert_eq!(e.kind(), "not-format");
}
