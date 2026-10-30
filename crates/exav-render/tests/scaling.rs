//! Documents of one kind of unit, many times over, converted in the time they
//! take to read.
//!
//! A step that looks at everything made so far for each unit it makes is
//! invisible in a document of a hundred units and takes minutes in one of a
//! million. Each test here makes a document of one unit, enough of them that
//! the step would take several times the limit, and gives the conversion that
//! limit. The limits are generous (an order above what the linear conversion
//! takes at the test profile's `opt-level = 1`, a quarter of the quadratic).

#![cfg(all(
    feature = "office-docs",
    feature = "office-slides",
    feature = "office-sheets"
))]

use std::time::{Duration, Instant};

const ODF_NS: &str = "xmlns:office=\"urn:oasis:names:tc:opendocument:xmlns:office:1.0\" \
    xmlns:text=\"urn:oasis:names:tc:opendocument:xmlns:text:1.0\" office:version=\"1.2\"";

fn flat_odt(body: &str) -> Vec<u8> {
    format!(
        "<?xml version=\"1.0\"?><office:document {ODF_NS} \
         office:mimetype=\"application/vnd.oasis.opendocument.text\"><office:body>\
         <office:text>{body}</office:text></office:body></office:document>"
    )
    .into_bytes()
}

fn converts_within(what: &str, input: &[u8], format: exav_render::docs::Format, limit: Duration) {
    let limits = exav_render::docs::Limits::default().with_max_memory(2 << 30);
    let started = Instant::now();
    let r = exav_render::docs::convert(input, format, &limits);
    let took = started.elapsed();
    assert!(r.is_ok(), "{what}: {:?}", r.err());
    assert!(
        took < limit,
        "{what}: {:.1} s, the limit is {limit:?}",
        took.as_secs_f64()
    );
}

/// Each note looked for itself among all the notes before it, from the first:
/// 160,000 of them took 5 s, and 300,000 would take 18.
#[test]
fn a_document_of_300_000_footnotes() {
    let note = "<text:note text:note-class=\"footnote\"><text:note-citation>1</text:note-citation>\
                <text:note-body><text:p>n</text:p></text:note-body></text:note>";
    let doc = flat_odt(&format!("<text:p>{}</text:p>", note.repeat(300_000)));
    converts_within(
        "300,000 footnotes",
        &doc,
        exav_render::docs::Format::Fodt,
        Duration::from_secs(10),
    );
}
