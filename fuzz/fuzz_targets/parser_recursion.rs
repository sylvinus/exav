#![no_main]
//! Depth, specifically. Every other target feeds bytes and hopes; this one
//! builds nesting on purpose.
//!
//! WHY IT EXISTS SEPARATELY: `catch_unwind` at the extraction boundary contains
//! a panic, and a panic is what a bounds check produces. It does not contain a
//! stack overflow, which is what unbounded recursive descent produces — the
//! process dies with no verdict, and in the daemon that costs a worker. The
//! container-nesting budget (`max_recursion`) does not help: it counts
//! archives-inside-archives, while this is one file whose *own grammar* nests
//! into itself.
//!
//! Random mutation reaches depth two or three and stops, because every extra
//! level needs another well-formed pair of delimiters. Constructing the nesting
//! from a couple of input bytes reaches thousands, which is where the cliff is.
//!
//! A finding here looks like a crash with no panic message — that is the shape
//! of a stack overflow, and it is worth checking `ulimit -s` before concluding
//! the parser is at fault.

use exav_unpack::{extract, Budget, Format, Limits};
use libfuzzer_sys::fuzz_target;

/// Small enough that a bomb cannot make the run about memory instead of depth.
const TIGHT: Limits = Limits {
    max_extracted_bytes: 256 * 1024,
    max_members: 8,
    max_compression_ratio: 50,
    max_buffer_bytes: 64 * 1024,
    max_scanned_bytes: 256 * 1024,
    max_recursion: 2,
};

/// Wrap `inner` in `depth` copies of `open`/`close`.
fn nest(open: &[u8], close: &[u8], inner: &[u8], depth: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(open.len() * depth * 2 + inner.len());
    for _ in 0..depth {
        out.extend_from_slice(open);
    }
    out.extend_from_slice(inner);
    for _ in 0..depth {
        out.extend_from_slice(close);
    }
    out
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    // Two bytes choose the depth, so the mutator can walk it rather than having
    // to build the nesting itself. Capped where a healthy parser is already far
    // past any legitimate document and an unhealthy one has long since died.
    let depth = usize::from(u16::from_le_bytes([data[0], data[1]])) % 20_000;
    let shape = data[2] % 4;
    let payload = &data[3..];

    let body = match shape {
        // PDF arrays and dictionaries: the recursive-descent object parser.
        0 => nest(b"[", b"]", payload, depth),
        1 => nest(b"<<", b">>", payload, depth),
        // A PDF wrapper, so the object parser is reached through the real
        // entry point rather than a fragment.
        2 => {
            let mut v = b"%PDF-1.7\n1 0 obj\n".to_vec();
            v.extend_from_slice(&nest(b"[", b"]", payload, depth));
            v.extend_from_slice(b"\nendobj\ntrailer<</Root 1 0 R>>\n%%EOF");
            v
        }
        // XDP wraps XML around a PDF, so the markup walk and the object parser
        // are both reachable from one nested document.
        _ => nest(b"<a>", b"</a>", payload, depth),
    };

    for fmt in [Format::Pdf, Format::Xdp] {
        let mut budget = Budget::new(TIGHT);
        let _ = extract(fmt, &body, &mut budget);
    }
});
