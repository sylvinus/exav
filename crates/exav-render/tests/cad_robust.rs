//! Damaged and hostile DXF: every input returns, quickly, without a panic,
//! holding no more than its limits allow.

#[path = "cad_common/mod.rs"]
mod common;

use std::time::{Duration, Instant};

use exav_render::cad::{read_dxf, read_dxf_with, EntityKind, Error, Limits, WarningKind};

fn samples() -> [Vec<u8>; 3] {
    [
        "ascii/R2018/all.dxf",
        "binary/R2018/all.dxf",
        "ascii/R12/all.dxf",
    ]
    .map(|p| common::fixture(p).expect(p))
}

/// A DXF file of the given ENTITIES section body, as text.
fn dxf(entities: &str) -> Vec<u8> {
    format!("0\nSECTION\n2\nENTITIES\n{entities}0\nENDSEC\n0\nEOF\n").into_bytes()
}

fn quick<T>(what: &str, f: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let out = f();
    let took = start.elapsed();
    assert!(took < Duration::from_secs(5), "{what} took {took:?}");
    out
}

#[test]
fn every_truncation_reads_or_fails_cleanly() {
    for data in samples() {
        let step = (data.len() / 400).max(1);
        let mut cut = 0;
        while cut < data.len() {
            let _ = quick("truncated", || read_dxf(&data[..cut]));
            cut += step;
        }
    }
}

#[test]
fn a_truncated_file_says_so() {
    let [all, binary, _] = samples();
    for data in [all, binary] {
        let d = read_dxf(&data[..data.len() / 2]).expect("half a drawing still reads");
        assert!(
            d.warnings.iter().any(|w| w.kind == WarningKind::Truncated),
            "{:?}",
            d.warnings
        );
        // What was before the cut is there.
        assert!(!d.layers.is_empty());
    }
}

#[test]
fn a_whole_file_has_no_warning() {
    for data in samples() {
        let d = read_dxf(&data).expect("reads");
        assert!(d.warnings.is_empty(), "{:?}", d.warnings);
    }
}

#[test]
fn bit_flips_never_panic() {
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for data in samples() {
        for _ in 0..150 {
            let mut b = data.to_vec();
            for _ in 0..8 {
                let r = next();
                let i = (r as usize) % b.len();
                b[i] ^= 1 << (r >> 61);
            }
            let _ = quick("flipped", || read_dxf(&b));
        }
    }
}

#[test]
fn counts_the_file_cannot_back_allocate_nothing() {
    // Counts in the billions, followed by nothing.
    let cases = [
        "0\nLWPOLYLINE\n8\n0\n90\n2147483647\n70\n1\n",
        "0\nHATCH\n8\n0\n91\n2000000000\n92\n2\n93\n2000000000\n",
        "0\nHATCH\n8\n0\n91\n1\n92\n0\n93\n2000000000\n72\n4\n95\n2000000000\n96\n2000000000\n",
        "0\nHATCH\n8\n0\n78\n2000000000\n53\n0\n79\n2000000000\n",
        "0\nSPLINE\n8\n0\n72\n2000000000\n73\n2000000000\n",
        "0\nMLINE\n8\n0\n72\n2000000000\n73\n2000000000\n",
        "0\nINSERT\n2\nX\n70\n32767\n71\n32767\n",
    ];
    for c in cases {
        let d = quick(c, || read_dxf(&dxf(c))).expect(c);
        assert!(d.model_space().is_some());
    }
}

#[test]
fn binary_chunks_and_strings_cannot_run_past_the_end() {
    let mut b = b"AutoCAD Binary DXF\r\n\x1a\0".to_vec();
    b.extend_from_slice(&0i16.to_le_bytes());
    b.extend_from_slice(b"SECTION\0");
    b.extend_from_slice(&2i16.to_le_bytes());
    b.extend_from_slice(b"ENTITIES\0");
    b.extend_from_slice(&0i16.to_le_bytes());
    b.extend_from_slice(b"LINE\0");
    // A chunk claiming 255 bytes with 3 left, then a string with no NUL.
    let mut chunk = b.clone();
    chunk.extend_from_slice(&310i16.to_le_bytes());
    chunk.extend_from_slice(&[255, 1, 2, 3]);
    let d = read_dxf(&chunk).expect("partial");
    assert!(d.warnings.iter().any(|w| w.kind == WarningKind::Truncated));
    let mut text = b;
    text.extend_from_slice(&8i16.to_le_bytes());
    text.extend_from_slice(b"no terminator");
    let d = read_dxf(&text).expect("partial");
    assert!(d.warnings.iter().any(|w| w.kind == WarningKind::Truncated));
}

#[test]
fn endless_sections_and_records_end_with_the_input() {
    let many_sections = "0\nSECTION\n2\nFOO\n".repeat(50_000);
    let d = quick("sections", || read_dxf(many_sections.as_bytes())).expect("reads");
    assert!(d.model_space().is_some());

    let many_points = "0\nPOINT\n8\n0\n10\n1\n20\n2\n".repeat(20_000);
    let d = quick("points", || read_dxf(&dxf(&many_points))).expect("reads");
    assert_eq!(d.model_space().map(|b| b.entities.len()), Some(20_000));

    // Sequences that never close.
    let open = "0\nPOLYLINE\n8\n0\n".to_string() + &"0\nVERTEX\n10\n1\n20\n1\n".repeat(10_000);
    let d = quick("vertices", || read_dxf(&dxf(&open))).expect("reads");
    let Some(EntityKind::Polyline(p)) = d
        .model_space()
        .and_then(|b| b.entities.first())
        .map(|e| &e.kind)
    else {
        panic!("no polyline");
    };
    assert_eq!(p.vertices.len(), 10_000);
}

#[test]
fn limits_bound_what_is_kept() {
    let limits = Limits {
        max_entities: 10,
        max_items: 5,
        max_string_bytes: 8,
        ..Limits::default()
    };
    let points = "0\nPOINT\n8\n0\n".repeat(50);
    let d = read_dxf_with(&dxf(&points), &limits).expect("reads");
    assert_eq!(d.model_space().map(|b| b.entities.len()), Some(10));
    assert!(d
        .warnings
        .iter()
        .any(|w| w.kind == WarningKind::LimitReached));

    let lw = "0\nLWPOLYLINE\n8\n0\n".to_string() + &"10\n1\n20\n2\n".repeat(100);
    let d = read_dxf_with(&dxf(&lw), &limits).expect("reads");
    let Some(EntityKind::LwPolyline(p)) = d
        .model_space()
        .and_then(|b| b.entities.first())
        .map(|e| &e.kind)
    else {
        panic!("no polyline");
    };
    assert_eq!(p.vertices.len(), 5);

    let text = "0\nTEXT\n8\n0\n1\nabcdefghijklmnopqrstuvwxyz\n";
    let d = read_dxf_with(&dxf(text), &limits).expect("reads");
    let Some(EntityKind::Text(t)) = d
        .model_space()
        .and_then(|b| b.entities.first())
        .map(|e| &e.kind)
    else {
        panic!("no text");
    };
    assert_eq!(t.value, "abcdefgh");

    // MTEXT chunks are joined within the limit too.
    let mtext = "0\nMTEXT\n8\n0\n3\nabcdef\n3\nghijkl\n1\nmnop\n";
    let d = read_dxf_with(&dxf(mtext), &limits).expect("reads");
    let Some(EntityKind::MText(m)) = d
        .model_space()
        .and_then(|b| b.entities.first())
        .map(|e| &e.kind)
    else {
        panic!("no mtext");
    };
    assert_eq!(m.text, "abcdefgh");
}

#[test]
fn warnings_are_capped() {
    let limits = Limits {
        max_warnings: 3,
        ..Limits::default()
    };
    let strays = "0\nSEQEND\n".repeat(100);
    let d = read_dxf_with(&dxf(&strays), &limits).expect("reads");
    assert_eq!(d.warnings.len(), 3);
    assert_eq!(d.warnings_dropped, 97);
}

#[test]
fn not_a_dxf_is_an_error() {
    assert_eq!(read_dxf(b"").err(), Some(Error::NotDxf));
    assert_eq!(read_dxf(b"%PDF-1.7").err(), Some(Error::NotDxf));
    assert_eq!(read_dxf(b"AC1032\0\0").err(), Some(Error::NotDxf));
}
