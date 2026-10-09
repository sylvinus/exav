//! Header fields at their extremes.
//!
//! A container's own numbers (offsets, counts, sizes) are the attacker's. A
//! sum or product of them that is not checked panics in builds with overflow
//! checks, which `walk` turns into a "decoder panicked" error, and wraps in the
//! WebAssembly builds, where it can defeat the bounds check next to it. Each
//! test here takes a valid container, sets one field at a time to a value near
//! the top of its range, and requires that no run ends in a panic.

use super::extract_each;
use exav_unpack::{Budget, Entry, Format, Limits};
use std::ops::Range;

const U64S: [u64; 7] = [
    u64::MAX,
    u64::MAX - 15,
    1 << 63,
    1 << 62,
    1 << 55,
    i64::MAX as u64,
    (1 << 44) - 1,
];
const U32S: [u32; 3] = [u32::MAX, 1 << 31, i32::MAX as u32];

/// Whether the walk of `blob` ended in a panic inside the decoder.
fn panicked(fmt: Format, blob: &[u8]) -> bool {
    let mut limits = Limits::default();
    limits.max_buffer_bytes = 8 * 1024 * 1024;
    limits.max_extracted_bytes = 16 * 1024 * 1024;
    let mut budget = Budget::new(limits);
    match extract_each(fmt, blob, &mut budget, &mut |_: Entry, _: &mut Budget| {
        None::<()>
    }) {
        Err(e) => e.reason.contains("panicked"),
        Ok(_) => false,
    }
}

/// Sets every aligned 4- and 8-byte field, and every byte, inside `regions` to
/// the values above, one at a time, and returns the changes that panicked the
/// decoder as `"offset width value"`.
pub fn sweep(fmt: Format, blob: &[u8], regions: &[Range<usize>]) -> Vec<String> {
    assert!(!panicked(fmt, blob), "the unmodified input already panics");
    let mut work = blob.to_vec();
    let mut bad = Vec::new();
    let mut try_set = |work: &mut Vec<u8>, at: usize, bytes: &[u8], what: String| {
        let saved = work[at..at + bytes.len()].to_vec();
        work[at..at + bytes.len()].copy_from_slice(bytes);
        if panicked(fmt, work) {
            bad.push(what);
        }
        work[at..at + bytes.len()].copy_from_slice(&saved);
    };
    for r in regions {
        let end = r.end.min(blob.len());
        for at in (r.start..end).step_by(4) {
            if at + 4 <= end {
                for v in U32S {
                    for bytes in [v.to_le_bytes(), v.to_be_bytes()] {
                        try_set(&mut work, at, &bytes, format!("{at:#x} u32 {v:#x}"));
                    }
                }
            }
            // Every 4 bytes, not 8: a record inside a resource need not sit on
            // an 8-byte boundary of the file.
            if at + 8 <= end {
                for v in U64S {
                    for bytes in [v.to_le_bytes(), v.to_be_bytes()] {
                        try_set(&mut work, at, &bytes, format!("{at:#x} u64 {v:#x}"));
                    }
                }
            }
        }
        for at in r.start..end.min(r.start + 1024) {
            for v in [0x80u8, 0xFF] {
                try_set(&mut work, at, &[v], format!("{at:#x} u8 {v:#x}"));
            }
        }
    }
    bad
}

/// The first `len` bytes of up to `cap` evenly spread 512-byte sectors that are
/// not all zero: where a container keeps its headers and tables.
fn sectors(blob: &[u8], cap: usize, len: usize) -> Vec<Range<usize>> {
    let live: Vec<usize> = (0..blob.len() / 512)
        .map(|i| i * 512)
        .filter(|&s| blob[s..s + 512].iter().any(|&b| b != 0))
        .collect();
    if cap == 0 {
        return Vec::new();
    }
    let step = live.len().div_ceil(cap).max(1);
    live.into_iter().step_by(step).map(|s| s..s + len).collect()
}

#[cfg(feature = "diskimage")]
mod disk {
    use super::*;
    use crate::suites::diskimage::fixture;

    #[test]
    fn qcow2_fields_at_their_extremes() {
        let blob = fixture("compressed.qcow2");
        none(sweep(Format::Qcow2, &blob, &sectors(&blob, 24, 128)));
    }

    #[test]
    fn sparse_vmdk_fields_at_their_extremes() {
        let blob = fixture("sparse.vmdk");
        none(sweep(Format::Vmdk, &blob, &sectors(&blob, 24, 128)));
    }

    #[test]
    fn streamoptimized_vmdk_fields_at_their_extremes() {
        let blob = fixture("streamoptimized.vmdk");
        none(sweep(Format::Vmdk, &blob, &sectors(&blob, 24, 128)));
    }

    #[test]
    fn vhdx_fields_at_their_extremes() {
        let blob = fixture("dynamic.vhdx.gz");
        none(sweep(Format::Vhdx, &blob, &sectors(&blob, 24, 128)));
    }
}

#[cfg(feature = "vhd")]
#[test]
fn dynamic_vhd_fields_at_their_extremes() {
    use crate::suites::vhd::{dyn_header, footer};
    let block_size: u32 = 1024;
    let mut blob = footer(3, 512, block_size as u64 * 2);
    blob.extend_from_slice(&dyn_header(512 + 1024, 2, block_size));
    blob.extend_from_slice(&u32::MAX.to_be_bytes());
    blob.extend_from_slice(&5u32.to_be_bytes());
    blob.resize(5 * 512, 0);
    blob.extend_from_slice(&vec![0u8; 512 + block_size as usize]);
    blob.extend_from_slice(&footer(3, 512, block_size as u64 * 2));
    none(sweep(Format::Vhd, &blob, &[0..512, 512..1536, 1536..1600]));
}

#[cfg(feature = "ntfs")]
#[test]
fn ntfs_fields_at_their_extremes() {
    let blob = crate::suites::ntfs::fixture();
    // The boot sector, and every file record (1 KiB, "FILE") up to a few.
    let mut regions: Vec<Range<usize>> = Vec::new();
    regions.push(0..512);
    regions.extend(
        (0..blob.len().saturating_sub(4))
            .step_by(1024)
            .filter(|&at| &blob[at..at + 4] == b"FILE")
            .take(10)
            .map(|at| at..at + 512),
    );
    none(sweep(Format::Ntfs, &blob, &regions));
}

#[cfg(feature = "wim")]
#[test]
fn wim_fields_at_their_extremes() {
    let blob = crate::suites::wim::fixture("w_none.wim");
    // All of it: the directory entries are in the metadata resource, wherever
    // the writer put it.
    let whole = Range {
        start: 0,
        end: blob.len(),
    };
    none(sweep(Format::Wim, &blob, &[whole]));
}

/// One sample of each other container format, small, from the fixtures.
#[test]
fn other_containers_fields_at_their_extremes() {
    let samples: &[(Format, &str)] = &[
        (Format::Arc, "arc/sample.arc"),
        (Format::Arc, "arc/stored.arc"),
        (Format::Lz4, "lz4/one.lz4"),
        (Format::Lz4, "lz4/one_legacy.lz4"),
        (Format::Lz4, "lz4/one_sized.lz4"),
        (Format::Lz4, "lz4/two_frames.lz4"),
        (Format::Arj, "sample.arj"),
        (Format::Egg, "egg/directories.egg"),
        (Format::Egg, "egg/lzma_simple.egg"),
        (Format::Egg, "egg/globalencrypt.egg"),
        (Format::Upx, "upx_nrv2d.upx"),
        (Format::Upx, "upx_lzma.upx"),
        (Format::Ole, "ole/malformed_dir_order.ole"),
        (Format::Rar, "rar4/solid_x86.rar"),
        (Format::Rar, "rar4/two_windows.rar"),
        (Format::Rar, "rar5/hardlink.rar"),
        (Format::Rar, "rar_solid/solid_rar4.rar"),
        (Format::Zoo, "zoo/default.zoo"),
        (Format::Alz, "alz/defaults.alz"),
        (Format::Cab, "cab/mszip_lzx_qtm.cab"),
        (Format::Chm, "chm/benign-lzx.chm"),
        (Format::SevenZip, "7z/copy.7z"),
        (Format::SevenZip, "7z/aes_lzma2.7z"),
        (Format::Zip, "encrypted/zip_aes256_deflate.zip"),
        (Format::Xz, "xz/simple.xz"),
        (Format::Lzw, "lzw/repetitive.b16.Z"),
        (Format::IshieldZ, "ishieldz/demo.z"),
        (Format::Hwp3, "hwp3/tika_testHWP_3.0.hwp"),
        (Format::Iso, "iso_short_record.iso"),
        (Format::Lha, "lha_delharc_overflow_min.lha"),
        (Format::Pdf, "pdf/empty_aesv2_r4.pdf"),
        (Format::Pdf, "pdf/empty_rc4_r3.pdf"),
        (Format::Pdf, "pdf/qpdf_actions_aes128.pdf"),
    ];
    let mut bad = Vec::new();
    for &(fmt, path) in samples {
        // To run one sample alone: EXTREME_ONLY=lz4/one.lz4
        if std::env::var("EXTREME_ONLY").is_ok_and(|only| !path.contains(&only)) {
            continue;
        }
        let p = format!("{}/tests/fixtures/{path}", env!("CARGO_MANIFEST_DIR"));
        let blob = exav_unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"));
        if blob.len() > 200_000 {
            continue;
        }
        // A RAR is decoded with a large window on every run: its headers only.
        let (head, tail_len, nsectors) = if matches!(fmt, Format::Rar) {
            (160, 64, 0)
        } else {
            (1024, 512, 12)
        };
        let tail = blob.len().saturating_sub(tail_len);
        let mut regions = vec![
            Range {
                start: 0,
                end: blob.len().min(head),
            },
            Range {
                start: tail,
                end: blob.len(),
            },
        ];
        regions.extend(sectors(&blob, nsectors, 64));
        bad.extend(
            sweep(fmt, &blob, &regions)
                .into_iter()
                .map(|w| format!("{path} {w}")),
        );
    }
    none(bad);
}

/// A skippable frame ahead of a real one, whose size field is the skip: on a
/// 32-bit `usize` the position after a large skip saturates, and the next
/// bound check adds to it.
#[test]
fn lz4_with_a_skippable_frame_fields_at_their_extremes() {
    let p = format!("{}/tests/fixtures/lz4/one.lz4", env!("CARGO_MANIFEST_DIR"));
    let frame = exav_unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"));
    let mut blob = Vec::new();
    blob.extend_from_slice(&0x184D_2A50u32.to_le_bytes());
    blob.extend_from_slice(&4u32.to_le_bytes());
    blob.extend_from_slice(&[0; 4]);
    blob.extend_from_slice(&frame);
    none(sweep(Format::Lz4, &blob, &[Range { start: 0, end: 24 }]));
}

/// Fails with the first few changes in `bad`.
pub fn none(bad: Vec<String>) {
    assert!(
        bad.is_empty(),
        "{} field values panic the decoder, first: {:?}",
        bad.len(),
        &bad[..bad.len().min(12)]
    );
}
