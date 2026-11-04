//! Hyperlinks: the extended data AutoCAD's HYPERLINK command stores on an
//! object, under the application name `PE_URL`.
//!
//! Neither the ODA specification nor the DXF reference gives its layout
//! (extended data is application-defined); this is what AutoLISP listings of
//! AutoCAD's own output show, one item a line:
//!
//! ```text
//! 1000 target          the address, empty for a link to a view of the drawing
//! 1002 {
//! 1000 description
//! 1000 named location  only for a link to a view
//! 1002 {
//! 1071 flag
//! 1002 }
//! 1002 }
//! ```
//!
//! What is read is looser than that, since nothing says it is complete: a
//! string outside the braces is a target (so a second link on the object is
//! found), the strings inside them are the link's texts, and any other item
//! is passed over.

use std::collections::HashSet;

use super::{Decoder, Dwg, EedValue, Text, code_page_name, trim_zeros};

/// The APPID entry's fixed type code (spec 20.3).
const APPID: u16 = 0x43;

/// The application name AutoCAD stores hyperlinks under.
const APP: &str = "PE_URL";

/// A hyperlink of an object.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Hyperlink {
    /// Where it goes; empty for a link to a named view of the drawing.
    pub url: String,
    /// The strings inside the braces: the description the user sees, then
    /// for a link to a view the view's name.
    pub texts: Vec<String>,
}

/// The hyperlinks of a drawing's objects, [`Dwg::hyperlinks`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Hyperlinks {
    /// Each distinct link once, in the order of the object map.
    pub links: Vec<Hyperlink>,
    /// More links than were asked for: the rest were not collected.
    pub cut: bool,
}

impl Dwg<'_> {
    /// The hyperlinks on the drawing's objects, at most `max` distinct ones.
    ///
    /// Reads the extended data of every object the map lists, once the
    /// APPID entries have said which application is `PE_URL`; a drawing
    /// with none is not read further. What is kept is bounded by `max` and
    /// by the size of the objects it comes from.
    pub fn hyperlinks(&self, max: usize) -> Hyperlinks {
        let apps = self.hyperlink_apps();
        if apps.is_empty() {
            return Hyperlinks::default();
        }
        let version = self.version();
        let (decoder, _) = Decoder::for_drawing(
            version.acadver(),
            code_page_name(self.code_page()).unwrap_or(""),
        );
        let found = self.object_map().iter().flat_map(|&(_, offset)| {
            let eed = self.object_at(offset).map(|o| o.eed).unwrap_or_default();
            eed.into_iter()
                .filter(|e| apps.contains(&e.app))
                .flat_map(|e| parse(&e.items(version), &decoder))
                .collect::<Vec<_>>()
        });
        // A link is a copy of bytes of the objects: never more than they hold.
        collect(found, max, self.objects().len().saturating_mul(2))
    }

    /// The handles of the APPID entries named `PE_URL`.
    fn hyperlink_apps(&self) -> HashSet<u64> {
        let mut apps = HashSet::new();
        for &(handle, offset) in self.object_map() {
            if !matches!(self.type_at(offset), Ok(APPID)) {
                continue;
            }
            let Ok(mut o) = self.object_at(offset) else {
                continue;
            };
            let named = match o.tv() {
                Ok(Text::Unicode(s)) => s.trim_end_matches('\0').eq_ignore_ascii_case(APP),
                Ok(Text::Bytes(b)) => trim_zeros(&b).eq_ignore_ascii_case(APP.as_bytes()),
                Err(_) => false,
            };
            if named {
                apps.insert(handle);
            }
        }
        apps
    }
}

/// Each distinct link of `found` once, up to `max` of them and `room` bytes
/// of text; past either the rest are not taken and the result is `cut`.
fn collect(found: impl IntoIterator<Item = Hyperlink>, max: usize, mut room: usize) -> Hyperlinks {
    let mut out = Hyperlinks::default();
    let mut seen: HashSet<Hyperlink> = HashSet::new();
    for link in found {
        if seen.contains(&link) {
            continue;
        }
        let size = link.url.len() + link.texts.iter().map(String::len).sum::<usize>();
        if out.links.len() >= max || size > room {
            out.cut = true;
            break;
        }
        room -= size;
        seen.insert(link.clone());
        out.links.push(link);
    }
    out
}

/// The links in one application's items (`(code, value)` as
/// [`Eed::items`](super::Eed::items) gives them).
fn parse(items: &[(i16, EedValue<'_>)], decoder: &Decoder) -> Vec<Hyperlink> {
    let text = |v: &EedValue<'_>| -> Option<String> {
        match v {
            EedValue::Unicode(s) => Some(s.trim_end_matches('\0').to_string()),
            EedValue::Text(b) => Some(decoder.decode(trim_zeros(b))),
            _ => None,
        }
    };
    let mut out = Vec::new();
    let mut current: Option<Hyperlink> = None;
    let mut depth = 0usize;
    for (code, value) in items {
        match (*code, value) {
            (1002, EedValue::Open(true)) => depth += 1,
            (1002, EedValue::Open(false)) => depth = depth.saturating_sub(1),
            (1000, v) => {
                let Some(s) = text(v) else { continue };
                if depth == 0 {
                    out.extend(current.take());
                    current = Some(Hyperlink {
                        url: s,
                        texts: Vec::new(),
                    });
                } else {
                    current
                        .get_or_insert_with(|| Hyperlink {
                            url: String::new(),
                            texts: Vec::new(),
                        })
                        .texts
                        .push(s);
                }
            }
            _ => {}
        }
    }
    out.extend(current);
    out.retain(|l| !l.url.trim().is_empty() || l.texts.iter().any(|t| !t.trim().is_empty()));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> EedValue<'static> {
        EedValue::Unicode(v.to_string())
    }

    fn link(url: &str, texts: &[&str]) -> Hyperlink {
        Hyperlink {
            url: url.to_string(),
            texts: texts.iter().map(|t| t.to_string()).collect(),
        }
    }

    /// AutoCAD's listing of a link to a web page (see the module doc).
    #[test]
    fn a_link_to_an_address_has_its_target_and_description() {
        let items = [
            (1000, s("http://www.example.org")),
            (1002, EedValue::Open(true)),
            (1000, s("Example")),
            (1002, EedValue::Open(true)),
            (1071, EedValue::Long(0)),
            (1002, EedValue::Open(false)),
            (1002, EedValue::Open(false)),
        ];
        assert_eq!(
            parse(&items, &Decoder::UTF8),
            [link("http://www.example.org", &["Example"])]
        );
    }

    /// AutoCAD's listing of a link to the view "Detail 1" of the drawing: no
    /// target, a description, the view's name.
    #[test]
    fn a_link_to_a_view_has_no_target() {
        let items = [
            (1000, s("")),
            (1002, EedValue::Open(true)),
            (1000, s("Detail text display")),
            (1000, s("Detail 1")),
            (1002, EedValue::Open(true)),
            (1071, EedValue::Long(1)),
            (1002, EedValue::Open(false)),
            (1002, EedValue::Open(false)),
        ];
        assert_eq!(
            parse(&items, &Decoder::UTF8),
            [link("", &["Detail text display", "Detail 1"])]
        );
    }

    #[test]
    fn a_second_target_outside_the_braces_is_a_second_link() {
        let items = [
            (1000, s("http://a.example")),
            (1002, EedValue::Open(true)),
            (1000, s("A")),
            (1002, EedValue::Open(false)),
            (1000, s("http://b.example")),
        ];
        assert_eq!(
            parse(&items, &Decoder::UTF8),
            [
                link("http://a.example", &["A"]),
                link("http://b.example", &[])
            ]
        );
    }

    /// R13 to R2004 keep their strings in the drawing's code page.
    #[test]
    fn a_target_in_a_code_page_is_decoded() {
        let (decoder, _) = Decoder::for_drawing("AC1015", "ANSI_1251");
        let items = [(
            1000,
            EedValue::Text(b"http://example.org/\xEF\xF0\xE8\xE2\xE5\xF2\0"),
        )];
        assert_eq!(
            parse(&items, &decoder),
            [link(
                "http://example.org/\u{43f}\u{440}\u{438}\u{432}\u{435}\u{442}",
                &[]
            )]
        );
    }

    #[test]
    fn the_same_link_is_kept_once() {
        let a = link("http://a.example", &["A"]);
        let got = collect([a.clone(), a.clone()], 10, 1000);
        assert_eq!(got.links, [a]);
        assert!(!got.cut);
    }

    #[test]
    fn links_past_the_count_asked_for_are_cut() {
        let all = [link("http://a.example", &[]), link("http://b.example", &[])];
        let got = collect(all.clone(), 1, 1000);
        assert_eq!(got.links, [all[0].clone()]);
        assert!(got.cut);
        // Room for exactly the two is not a cut.
        assert!(!collect(all, 2, 1000).cut);
    }

    #[test]
    fn links_past_the_room_for_their_text_are_cut() {
        // 16 bytes each, 20 of room.
        let all = [link("http://a.example", &[]), link("http://b.example", &[])];
        let got = collect(all, 10, 20);
        assert_eq!(got.links.len(), 1);
        assert!(got.cut);
    }

    #[test]
    fn items_that_are_not_strings_and_empty_links_are_passed_over() {
        let items = [
            (1070, EedValue::Short(3)),
            (1000, s("  ")),
            (1002, EedValue::Open(true)),
            (1002, EedValue::Open(false)),
            (1040, EedValue::Real(1.0)),
        ];
        assert_eq!(parse(&items, &Decoder::UTF8), Vec::<Hyperlink>::new());
        // Braces closed more often than they were opened do not underflow.
        let items = [(1002, EedValue::Open(false)), (1000, s("http://x.example"))];
        assert_eq!(
            parse(&items, &Decoder::UTF8),
            [link("http://x.example", &[])]
        );
    }
}
