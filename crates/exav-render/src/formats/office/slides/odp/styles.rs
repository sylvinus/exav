//! ODF styles for the presentation converter: the shared ones
//! (`common::odf`), whose property keys carry the kind of property element
//! (`graphic/draw:fill`), and the length values of drawings.

use crate::formats::office::slides::model::{Emu, Rgb};

use crate::formats::office::common::odf::split_len;
// "#RRGGBB" as an `Rgb`, "50%" as 0.5, and the text of a node and its
// descendants, as the other ODF readers have them.
pub use crate::formats::office::common::odf::{
    ListDef, ListLevel, Props, Styles, color, percent, text_of,
};

/// A length to EMU: cm, mm, in, pt, pc, px; a bare number is taken as cm
/// (the unit drawings use when none is given).
pub fn len(s: &str) -> Option<Emu> {
    let (v, unit) = split_len(s)?;
    let emu = match unit {
        "cm" | "" => v * 360_000.0,
        "mm" => v * 36_000.0,
        "in" | "inch" => v * 914_400.0,
        "pt" => v * 12_700.0,
        "pc" => v * 152_400.0,
        "px" => v * 9_525.0,
        _ => return None,
    };
    Some(emu.clamp(-1e13, 1e13).round() as Emu)
}

/// The kinds of property element a drawing shape's properties are in.
pub const GRAPHIC: &[&str] = &["graphic"];
/// A page's.
pub const PAGE: &[&str] = &["drawing-page"];
/// A table cell's: writers put its fill in the graphic properties too.
pub const CELL: &[&str] = &["table-cell", "graphic"];

/// Lengths in EMU, and properties looked up in several kinds of property
/// element, the first kind that has the property giving it.
pub trait PropsExt {
    /// A property of the exact key (`text/fo:font-size`) as a length.
    fn len(&self, k: &str) -> Option<Emu>;
    fn get_in(&self, kinds: &[&str], k: &str) -> Option<&str>;
    fn is_in(&self, kinds: &[&str], k: &str, v: &str) -> bool;
    fn len_in(&self, kinds: &[&str], k: &str) -> Option<Emu>;
    fn color_in(&self, kinds: &[&str], k: &str) -> Option<Rgb>;
}

impl PropsExt for Props {
    fn len(&self, k: &str) -> Option<Emu> {
        self.get(k).and_then(len)
    }

    fn get_in(&self, kinds: &[&str], k: &str) -> Option<&str> {
        kinds
            .iter()
            .find_map(|kind| self.get(&format!("{kind}/{k}")))
    }

    fn is_in(&self, kinds: &[&str], k: &str, v: &str) -> bool {
        self.get_in(kinds, k) == Some(v)
    }

    fn len_in(&self, kinds: &[&str], k: &str) -> Option<Emu> {
        self.get_in(kinds, k).and_then(len)
    }

    fn color_in(&self, kinds: &[&str], k: &str) -> Option<Rgb> {
        self.get_in(kinds, k).and_then(color)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn styles_of(x: &[u8]) -> Styles {
        let n = crate::formats::office::common::xml::parse(
            x,
            &mut crate::formats::office::common::xml::within(1 << 20),
        )
        .unwrap();
        let mut s = Styles::default();
        s.add(&n, false);
        s
    }

    #[test]
    fn lengths_and_colours() {
        assert_eq!(len("2.54cm"), Some(914_400));
        assert_eq!(len("1in"), Some(914_400));
        assert_eq!(len("10pt"), Some(127_000));
        assert_eq!(len("x"), None);
        assert_eq!(color("#3465a4"), Some(0x3465A4));
        assert_eq!(color("#fff"), Some(0xFFFFFF));
        assert_eq!(percent("50%"), Some(0.5));
    }

    #[test]
    fn styles_resolve_through_parents_and_defaults() {
        let s = styles_of(br##"<office:styles xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0"><style:default-style style:family="graphic"><style:graphic-properties draw:fill-color="#729fcf" draw:stroke="solid"/></style:default-style><style:style style:name="a" style:family="graphic"><style:graphic-properties draw:fill="solid"/></style:style><style:style style:name="b" style:family="graphic" style:parent-style-name="a"><style:graphic-properties draw:fill-color="#ff0000"/></style:style></office:styles>"##);
        let p = s.resolve("graphic", Some("b"));
        assert_eq!(p.get("graphic/draw:fill"), Some("solid"));
        assert_eq!(p.color("graphic/draw:fill-color"), Some(0xFF0000));
        assert_eq!(p.get("graphic/draw:stroke"), Some("solid"));
        // A presentation style falls back to a graphic one.
        assert_eq!(
            s.resolve("presentation", Some("a"))
                .get("graphic/draw:fill"),
            Some("solid")
        );
        // `chain` leaves the default out.
        let p = s.chain("graphic", Some("b"));
        assert_eq!(p.get("graphic/draw:fill"), Some("solid"));
        assert_eq!(p.get("graphic/draw:stroke"), None);
    }

    #[test]
    fn a_style_that_is_its_own_parent_is_read_once() {
        let s = styles_of(br##"<office:styles xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0"><style:style style:name="a" style:family="graphic" style:parent-style-name="a"><style:graphic-properties draw:fill="solid"/></style:style></office:styles>"##);
        assert_eq!(s.chain("graphic", Some("a")).size(), 1);
        assert_eq!(s.resolve("presentation", Some("a")).size(), 1);
    }
}
