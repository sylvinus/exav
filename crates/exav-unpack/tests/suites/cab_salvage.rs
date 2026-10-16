//! A cabinet cut or damaged inside a CFDATA block keeps what that block
//! decoded before the cut or the damage.
//!
//! A damaged block is reported (the compressed bytes after the damage were
//! present and never decoded); one cut by the end of the file is not (nothing
//! is hidden: the rest is absent).

use exav_unpack::{extract, Budget, Entry, Format, Limits};
use std::io::{Cursor, Write};

/// Text that deflates well, so a block holds a long run of it.
fn text(n: usize) -> Vec<u8> {
    (0..n as u32)
        .flat_map(|i| format!("line {} of the file {}\n", i % 977, i / 3).into_bytes())
        .take(n)
        .collect()
}

fn mszip_cab(data: &[u8]) -> Vec<u8> {
    let mut builder = cab::CabinetBuilder::new();
    builder
        .add_folder(cab::CompressionType::MsZip)
        .add_file("data.bin");
    let mut w = builder.build(Cursor::new(Vec::new())).unwrap();
    while let Some(mut f) = w.next_file().unwrap() {
        f.write_all(data).unwrap();
    }
    w.finish().unwrap().into_inner()
}

/// The offset of the first CFDATA record of a one-folder cabinet.
fn first_block(cab: &[u8]) -> usize {
    u32::from_le_bytes(cab[36..40].try_into().unwrap()) as usize
}

fn entries(cab: &[u8]) -> Vec<Entry> {
    extract(Format::Cab, &cab, &mut Budget::new(Limits::default())).unwrap()
}

#[test]
fn a_block_whose_deflate_stream_ends_early_keeps_what_it_decoded_and_is_reported() {
    let data = text(20_000);
    let mut cab = mszip_cab(&data);
    let at = first_block(&cab);
    let cb = u16::from_le_bytes([cab[at + 4], cab[at + 5]]);
    assert!(cb > 200);
    // The record claims fewer compressed bytes than the stream needs.
    cab[at + 4..at + 6].copy_from_slice(&(cb / 2).to_le_bytes());
    let e = entries(&cab);
    assert_eq!(e.len(), 1);
    assert!(e[0].unsupported.is_some(), "a damaged block came out whole");
    assert!(
        e[0].data.len() > 1000 && data.starts_with(&e[0].data),
        "the part of the block decoded before the damage is lost: {} bytes",
        e[0].data.len()
    );
}

#[test]
fn a_block_damaged_inside_its_deflate_stream_keeps_what_came_before() {
    let data = text(20_000);
    let cab = mszip_cab(&data);
    let at = first_block(&cab);
    // A reserved block type, some way into the first block's stream. The
    // bits before it decode; which byte does it is found by trying.
    let end = at + 8 + u16::from_le_bytes([cab[at + 4], cab[at + 5]]) as usize;
    let mut kept = 0;
    for k in (at + 40..end - 8).step_by(13) {
        let mut bad = cab.clone();
        bad[k] = 0xff;
        bad[k + 1] = 0xff;
        let e = entries(&bad);
        if e.len() == 1 && e[0].unsupported.is_some() && e[0].data.len() > 100 {
            // The start of the block is the file's own, up to the damage.
            assert!(e[0].data.starts_with(&data[..100]));
            kept += 1;
        }
    }
    assert!(kept > 0, "no damaged block kept a decoded prefix");
}

#[test]
fn a_cabinet_cut_inside_a_block_keeps_what_the_block_decoded() {
    let data = text(20_000);
    let cab = mszip_cab(&data);
    let at = first_block(&cab);
    let cb = u16::from_le_bytes([cab[at + 4], cab[at + 5]]) as usize;
    let cut = &cab[..at + 8 + cb / 2];
    let e = extract(Format::Cab, &cut, &mut Budget::new(Limits::default()));
    let e = e.expect("a cut cabinet is still walked");
    assert_eq!(e.len(), 1);
    assert!(
        e[0].data.len() > 1000 && data.starts_with(&e[0].data),
        "the part of the block present is lost: {} bytes",
        e[0].data.len()
    );
    // The rest of the block is absent, not hidden: not a damaged member.
    assert!(e[0].unsupported.is_none(), "{:?}", e[0].unsupported);
}

#[test]
fn a_whole_cabinet_still_decodes_to_the_file() {
    let data = text(150_000);
    let cab = mszip_cab(&data);
    let e = entries(&cab);
    assert_eq!(e.len(), 1);
    assert!(e[0].unsupported.is_none());
    assert_eq!(e[0].data, data);
}

#[test]
fn a_second_block_damaged_keeps_the_first_whole_and_part_of_the_second() {
    let data = text(150_000);
    let mut cab = mszip_cab(&data);
    let mut at = first_block(&cab);
    at += 8 + u16::from_le_bytes([cab[at + 4], cab[at + 5]]) as usize;
    let cb = u16::from_le_bytes([cab[at + 4], cab[at + 5]]);
    let first = 32768usize;
    cab[at + 4..at + 6].copy_from_slice(&(cb / 2).to_le_bytes());
    let e = entries(&cab);
    assert!(e[0].unsupported.is_some());
    assert!(
        e[0].data.len() > first + 1000 && data.starts_with(&e[0].data),
        "{} bytes",
        e[0].data.len()
    );
}
