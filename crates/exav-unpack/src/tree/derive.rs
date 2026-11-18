//! Objects found inside an object besides its members: a ZIP appended to it,
//! the object read as a second format, and the payloads encoded in its text.
//!
//! [`derive`] finds them with the functions of this crate that know each
//! kind. Whether a kind applies to an object (a text, a markup document, a
//! carrier that is not itself a derived object) is the consumer's to decide:
//! a consumer that scans in an order of its own calls [`derive`] where it
//! chooses and enters each child with [`Cx::child`](super::Cx::child); one
//! that wants every node gives [`Cx::derived`](super::Cx::derived) a visitor.

#[cfg(feature = "base64scan")]
use super::EncodedKind;
use super::{Name, NameKind, Origin, SecondReading};
use crate::source::{ByteSource, Sub};
use crate::{Format, Limits};

/// A kind of object found inside another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeriveKind {
    /// A ZIP appended to the object, found by its end record.
    AppendedZip,
    /// The object read as another format, for the formats that leave their
    /// start free. The format is the one it was first read as.
    AlsoReadsAs(Format),
    /// Executables, archives and images that are long base64 runs of a text.
    Base64Runs,
    /// The `data:` assets and base64 element bodies of a markup document.
    MarkupAssets,
}

/// What a derived child is made of.
pub enum DerivedBody<'a> {
    /// Bytes made from the object.
    Bytes(Vec<u8>),
    /// The object's bytes from some offset to its end.
    Window(Sub<'a>),
    /// The object itself, to be read as this format.
    ReadAs(Format),
}

/// One object found inside another.
pub struct DerivedChild<'a> {
    pub origin: Origin,
    /// Its segment of a path, if it has one: what is read from the object a
    /// second way has none.
    name: Option<String>,
    pub body: DerivedBody<'a>,
}

impl<'a> DerivedChild<'a> {
    /// Its segment of a path.
    pub fn name(&self) -> Option<Name<'_>> {
        self.name
            .as_deref()
            .map(|name| Name::new(name, NameKind::Derived))
    }

    /// Its bytes, unless it is the object itself.
    pub fn source(&self) -> Option<&dyn ByteSource> {
        match &self.body {
            DerivedBody::Bytes(bytes) => Some(bytes),
            DerivedBody::Window(sub) => Some(sub),
            DerivedBody::ReadAs(_) => None,
        }
    }
}

/// The children found, in the order they are entered.
pub struct Derived<'a> {
    pub children: Vec<DerivedChild<'a>>,
    /// More were there than the kind returns.
    pub capped: bool,
}

impl Derived<'_> {
    fn none() -> Self {
        Derived {
            children: Vec::new(),
            capped: false,
        }
    }
}

/// The children of `src` of one kind. Payloads over `max_buffer_bytes` are
/// not decoded.
pub fn derive<'a>(src: &'a dyn ByteSource, kind: DeriveKind, limits: &Limits) -> Derived<'a> {
    match kind {
        DeriveKind::AppendedZip => match crate::appended_zip_start(src) {
            Some(at) if at < src.len() as u64 => {
                let at = at as usize;
                Derived {
                    children: vec![DerivedChild {
                        origin: Origin::Second(SecondReading::AppendedZip),
                        name: None,
                        body: DerivedBody::Window(Sub::new(src, at, src.len() - at)),
                    }],
                    capped: false,
                }
            }
            _ => Derived::none(),
        },
        DeriveKind::AlsoReadsAs(first) => match crate::also_reads_as(src, first) {
            Some(other) => Derived {
                children: vec![DerivedChild {
                    origin: Origin::Second(SecondReading::AlsoReadsAs(other)),
                    name: None,
                    body: DerivedBody::ReadAs(other),
                }],
                capped: false,
            },
            None => Derived::none(),
        },
        #[cfg(feature = "base64scan")]
        DeriveKind::Base64Runs => payloads(
            crate::base64_payloads_capped(
                src,
                limits.max_buffer_bytes,
                limits.max_base64_payloads,
                limits.max_base64_runs,
            ),
            EncodedKind::Base64Run,
            "base64-payload",
        ),
        #[cfg(feature = "base64scan")]
        DeriveKind::MarkupAssets => payloads(
            crate::markup_embedded_payloads_capped(
                src,
                limits.max_buffer_bytes,
                limits.max_page_assets,
            ),
            EncodedKind::MarkupAsset,
            "embedded-asset",
        ),
        // Without the `base64scan` feature nothing is decoded out of a text.
        #[cfg(not(feature = "base64scan"))]
        DeriveKind::Base64Runs | DeriveKind::MarkupAssets => {
            let _ = limits;
            Derived::none()
        }
    }
}

/// The payloads a decoder found, as children named `label-N` from 1.
#[cfg(feature = "base64scan")]
fn payloads<'a>(
    (found, capped): (Vec<Vec<u8>>, bool),
    kind: EncodedKind,
    label: &str,
) -> Derived<'a> {
    Derived {
        children: found
            .into_iter()
            .enumerate()
            .map(|(i, payload)| DerivedChild {
                origin: Origin::Encoded(kind, i + 1),
                name: Some(format!("{label}-{}", i + 1)),
                body: DerivedBody::Bytes(payload),
            })
            .collect(),
        capped,
    }
}

/// A ZIP of one stored member, for tests.
#[cfg(all(test, feature = "zip"))]
pub(super) fn stored_zip(name: &str, data: &[u8]) -> Vec<u8> {
    fn crc32(data: &[u8]) -> u32 {
        let mut crc = !0u32;
        for &b in data {
            crc ^= u32::from(b);
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0xEDB8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }
    let crc = crc32(data);
    let size = data.len() as u32;
    let mut out = Vec::new();
    out.extend_from_slice(b"PK\x03\x04");
    out.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    for field in [crc, size, size] {
        out.extend_from_slice(&field.to_le_bytes());
    }
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(data);
    let directory = out.len() as u32;
    out.extend_from_slice(b"PK\x01\x02");
    out.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    for field in [crc, size, size] {
        out.extend_from_slice(&field.to_le_bytes());
    }
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(&[0; 12]);
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(name.as_bytes());
    let directory_size = out.len() as u32 - directory;
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&[0, 0, 0, 0, 1, 0, 1, 0]);
    out.extend_from_slice(&directory_size.to_le_bytes());
    out.extend_from_slice(&directory.to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out
}

/// A text with one base64 run per marker, each a PE that `derive` decodes, for
/// tests.
#[cfg(all(test, feature = "base64scan"))]
pub(super) fn pe_carrier(markers: &[u8]) -> Vec<u8> {
    let mut text = String::new();
    for (i, marker) in markers.iter().enumerate() {
        text.push_str(&format!("v{i} = \"{}\";\n", b64_of(&pe_of(*marker))));
    }
    text.into_bytes()
}

#[cfg(all(test, feature = "base64scan"))]
pub(super) fn pe_of(marker: u8) -> Vec<u8> {
    let mut v = vec![0u8; 1200];
    v[..2].copy_from_slice(b"MZ");
    v[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    v[0x80..0x84].copy_from_slice(b"PE\0\0");
    v[0x100] = marker;
    v
}

#[cfg(all(test, feature = "base64scan"))]
fn b64_of(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

#[cfg(all(test, any(feature = "zip", feature = "iso", feature = "base64scan")))]
mod tests {
    use super::*;

    fn limits() -> Limits {
        Limits::default()
    }

    /// What a child is made of, for comparing.
    #[cfg(any(feature = "zip", feature = "base64scan"))]
    fn bytes_of(child: &DerivedChild<'_>) -> Vec<u8> {
        let src = child.source().expect("bytes");
        src.window(0, src.len()).into_owned()
    }

    #[cfg(feature = "zip")]
    #[test]
    fn a_zip_appended_to_an_object_is_one_unnamed_child_from_where_it_starts() {
        let zip = stored_zip("z.txt", b"inside");
        let mut data = b"not a zip at all, then a zip: ".to_vec();
        let start = data.len();
        data.extend_from_slice(&zip);
        let found = derive(&data, DeriveKind::AppendedZip, &limits());
        assert!(!found.capped);
        assert_eq!(found.children.len(), 1);
        let child = &found.children[0];
        assert_eq!(child.origin, Origin::Second(SecondReading::AppendedZip));
        assert!(child.name().is_none());
        assert!(matches!(child.body, DerivedBody::Window(_)));
        assert_eq!(bytes_of(child), zip);
        assert_eq!(child.source().unwrap().len(), data.len() - start);
    }

    #[cfg(feature = "zip")]
    #[test]
    fn a_zip_that_starts_where_its_offsets_say_is_not_appended_to_anything() {
        let zip = stored_zip("z.txt", b"inside");
        assert!(
            derive(&zip, DeriveKind::AppendedZip, &limits())
                .children
                .is_empty()
        );
        let plain: &[u8] = b"plain bytes";
        assert!(
            derive(&plain, DeriveKind::AppendedZip, &limits())
                .children
                .is_empty()
        );
    }

    #[cfg(feature = "iso")]
    #[test]
    fn an_object_that_is_also_an_iso_is_one_unnamed_child_to_read_as_it() {
        let mut data = vec![0u8; 32769 + 8];
        data[32769..32774].copy_from_slice(b"CD001");
        let found = derive(&data, DeriveKind::AlsoReadsAs(Format::Tar), &limits());
        assert_eq!(found.children.len(), 1);
        let child = &found.children[0];
        assert_eq!(
            child.origin,
            Origin::Second(SecondReading::AlsoReadsAs(Format::Iso))
        );
        assert!(child.name().is_none());
        assert!(matches!(child.body, DerivedBody::ReadAs(Format::Iso)));
        assert!(child.source().is_none());
        // Not a second reading of what it was read as already.
        let again = derive(&data, DeriveKind::AlsoReadsAs(Format::Iso), &limits());
        assert!(again.children.is_empty());
        let zeros = vec![0u8; 40000];
        let plain = derive(&zeros, DeriveKind::AlsoReadsAs(Format::Tar), &limits());
        assert!(plain.children.is_empty());
    }

    #[cfg(feature = "base64scan")]
    use super::{b64_of as b64, pe_of as pe};

    #[cfg(feature = "base64scan")]
    #[test]
    fn base64_runs_are_children_named_and_numbered_from_one_in_the_order_they_lie() {
        let text = format!("a = \"{}\";\nb = \"{}\";\n", b64(&pe(1)), b64(&pe(2)));
        let text = text.as_bytes();
        let found = derive(&text, DeriveKind::Base64Runs, &limits());
        assert!(!found.capped);
        assert_eq!(found.children.len(), 2);
        for (i, marker) in [1u8, 2].into_iter().enumerate() {
            let child = &found.children[i];
            assert_eq!(child.origin, Origin::Encoded(EncodedKind::Base64Run, i + 1));
            let name = child.name().expect("a name");
            assert_eq!(name.raw, format!("base64-payload-{}", i + 1));
            assert_eq!(name.kind, NameKind::Derived);
            assert!(matches!(child.body, DerivedBody::Bytes(_)));
            assert_eq!(bytes_of(child), pe(marker));
        }
    }

    #[cfg(feature = "base64scan")]
    #[test]
    fn base64_runs_past_what_is_decoded_in_one_object_say_so() {
        let text: String = (0..9u8)
            .map(|i| format!("v{i} = \"{}\";\n", b64(&pe(i))))
            .collect();
        let text = text.as_bytes();
        let found = derive(&text, DeriveKind::Base64Runs, &limits());
        assert_eq!(found.children.len(), 8);
        assert!(found.capped);
        let one = format!("v = \"{}\";\n", b64(&pe(0)));
        assert!(!derive(&one.as_bytes(), DeriveKind::Base64Runs, &limits()).capped);
    }

    #[cfg(feature = "base64scan")]
    #[test]
    fn a_payload_over_the_buffer_limit_is_not_decoded() {
        let text = format!("v = \"{}\";\n", b64(&pe(1)));
        let small = Limits {
            max_buffer_bytes: 1199,
            ..limits()
        };
        assert!(
            derive(&text.as_bytes(), DeriveKind::Base64Runs, &small)
                .children
                .is_empty()
        );
        let fits = Limits {
            max_buffer_bytes: 1200,
            ..limits()
        };
        assert_eq!(
            derive(&text.as_bytes(), DeriveKind::Base64Runs, &fits)
                .children
                .len(),
            1
        );
        // The same bound for the assets of a page.
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend_from_slice(&[0x5a; 200]);
        let page = format!("<img src=\"data:image/png;base64,{}\">", b64(&png));
        let page = page.as_bytes();
        for (bound, assets) in [(207, 0), (208, 1)] {
            let l = Limits {
                max_buffer_bytes: bound,
                ..limits()
            };
            let found = derive(&page, DeriveKind::MarkupAssets, &l);
            assert_eq!(found.children.len(), assets, "bound {bound}");
        }
    }

    #[cfg(feature = "base64scan")]
    #[test]
    fn markup_assets_are_children_named_and_numbered_from_one() {
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend_from_slice(&[0x5a; 200]);
        let page = format!(
            "<img src=\"data:image/png;base64,{0}\"><img src=\"data:image/png;base64,{0}\">",
            b64(&png)
        );
        let page = page.as_bytes();
        let found = derive(&page, DeriveKind::MarkupAssets, &limits());
        assert_eq!(found.children.len(), 2);
        for (i, child) in found.children.iter().enumerate() {
            assert_eq!(
                child.origin,
                Origin::Encoded(EncodedKind::MarkupAsset, i + 1)
            );
            assert_eq!(
                child.name().unwrap().raw,
                format!("embedded-asset-{}", i + 1)
            );
            assert_eq!(bytes_of(child), png);
        }
        // The same text has no executable run to decode.
        assert!(
            derive(&page, DeriveKind::Base64Runs, &limits())
                .children
                .is_empty()
        );
    }
}
