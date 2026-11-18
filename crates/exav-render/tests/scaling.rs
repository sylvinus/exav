//! Documents of one kind of unit, many times over, converted in time that
//! grows with their size.
//!
//! A step that looks at everything made so far for each unit it makes is
//! invisible in a document of a hundred units and takes minutes in one of a
//! million. Each test here converts a document of one unit at two sizes, the
//! second four times the first, and requires the second to take less than
//! seven times as long: a linear conversion takes about four, a quadratic one
//! sixteen at the limit (eleven measured for the footnotes below, whose linear
//! part still counts at these sizes). Time is the process's user CPU time where
//! the system gives it, so the kernel's time handing out memory, which depends
//! on how much the machine has free, is left out. The sizes stay small: past
//! the caches, reading a large model costs more per unit, and the ratio of a
//! linear conversion grows too.

#![cfg(all(
    feature = "office-docs",
    feature = "office-slides",
    feature = "office-sheets"
))]

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

/// User CPU time of this process, in the clock's ticks.
#[cfg(target_os = "linux")]
fn now() -> u64 {
    let stat = std::fs::read_to_string("/proc/self/stat").expect("/proc/self/stat");
    // The command name is in parentheses and may hold spaces: count after it.
    let after = &stat[stat.rfind(')').expect("a command name") + 2..];
    after
        .split(' ')
        .nth(11)
        .and_then(|t| t.parse().ok())
        .expect("utime")
}

/// Elsewhere, wall-clock microseconds.
#[cfg(not(target_os = "linux"))]
fn now() -> u64 {
    use std::sync::OnceLock;
    static START: OnceLock<std::time::Instant> = OnceLock::new();
    START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_micros() as u64
}

/// The time converting `input` takes, as [`now`] counts it.
fn cost(what: &str, input: &[u8], format: exav_render::docs::Format) -> u64 {
    let limits = exav_render::docs::Limits::default().with_max_memory(2 << 30);
    let started = now();
    let r = exav_render::docs::convert(input, format, &limits);
    let took = now() - started;
    assert!(r.is_ok(), "{what}: {:?}", r.err());
    took
}

/// The document `make` builds of `4 * n` units converts in less than seven
/// times what the one of `n` units takes.
fn grows_linearly(
    what: &str,
    n: usize,
    make: impl Fn(usize) -> Vec<u8>,
    format: exav_render::docs::Format,
) {
    // What a first conversion pays once is paid here.
    cost(what, &make(n / 100), format);
    let (small, large) = (make(n), make(4 * n));
    let small = cost(what, &small, format).max(1);
    let large = cost(what, &large, format);
    assert!(
        large < 7 * small,
        "{what}: four times the units took {:.1} times as long ({large} against {small})",
        large as f64 / small as f64
    );
}

/// Each note looked for itself among all the notes before it, from the first:
/// 160,000 of them took 5 s, and 300,000 would take 18.
#[test]
fn a_document_of_150_000_footnotes() {
    let note = "<text:note text:note-class=\"footnote\"><text:note-citation>1</text:note-citation>\
                <text:note-body><text:p>n</text:p></text:note-body></text:note>";
    grows_linearly(
        "footnotes",
        37_500,
        |n| flat_odt(&format!("<text:p>{}</text:p>", note.repeat(n))),
        exav_render::docs::Format::Fodt,
    );
}
