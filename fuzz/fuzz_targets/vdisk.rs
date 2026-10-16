#![no_main]
//! Virtual disks and the filesystems read in place, on hostile bytes: QCOW2,
//! VMDK, VHD and VHDX through their tables and compressed units, and NTFS, FAT
//! and partition tables through the volume walker. The budgets are small, so an
//! image of more than a few KiB declares a disk over the buffer limit and is
//! walked in place rather than read into one member.
//!
//! The first byte picks the format (above the list: all of them); the rest is the
//! image. Each is walked twice, from memory and through a block cache of tiny
//! blocks, and the two must agree on what they find: a read that depends on
//! where the cache's blocks fall is a bug. No member held whole may pass the
//! buffer limit.
//!
//! Seeds: `scripts/fuzz-seeds.sh` (`fuzz/seeds/vdisk`, and the disk fixtures of
//! at most 64 KiB).
use exav_fuzz_support::extreme;
use exav_unpack::source::BlockCache;
use exav_unpack::{walk, Budget, ByteSource, Format, LimitHit, Limits, Member};
use libfuzzer_sys::fuzz_target;
use std::io::{Cursor, Read};

libfuzzer_sys::fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    if extreme::set_extreme_field(data, size, seed) {
        size
    } else {
        libfuzzer_sys::fuzzer_mutate(data, size, max_size)
    }
});

const FORMATS: [Format; 7] = [
    Format::Qcow2,
    Format::Vmdk,
    Format::Vhd,
    Format::Vhdx,
    Format::Ntfs,
    Format::Fat,
    Format::Partition,
];

const BUFFER: u64 = 64 * 1024;

fn limits() -> Limits {
    let mut l = Limits::default();
    l.max_buffer_bytes = BUFFER;
    l.max_extracted_bytes = 1024 * 1024;
    l.max_scanned_bytes = 4 * 1024 * 1024;
    l.max_members = 400;
    l.max_recursion = 2;
    l
}

/// What a walk found: each member's name, size and whether it was reported, and
/// how the walk ended.
type Found = (Vec<(String, usize, bool)>, Result<(), LimitHit>);

fn found(fmt: Format, src: &dyn ByteSource) -> Found {
    let mut budget = Budget::new(limits());
    let mut out = Vec::new();
    let end = walk(fmt, src, &mut budget, &mut |meta, content, _| {
        let n = match content {
            None => 0,
            Some(Member::Bytes(b)) => {
                assert!(
                    b.len() as u64 <= BUFFER,
                    "{}: a member held whole passes the buffer limit",
                    meta.name
                );
                b.len()
            }
            Some(Member::Stream(r)) => {
                let mut n = 0;
                let mut buf = [0u8; 8192];
                // A stream is bounded by the scan budget it is read under.
                while let Ok(k) = r.read(&mut buf) {
                    if k == 0 {
                        break;
                    }
                    n += k;
                }
                n
            }
        };
        out.push((meta.name.clone(), n, meta.unsupported.is_some()));
        None::<()>
    });
    // A panic is let through only where a read of the filesystem crate is
    // wrapped to lose that read alone; one that reaches the walk's boundary
    // ends the volume, and is a finding.
    if let Err(hit) = &end {
        assert!(!hit.reason.contains("panicked"), "{fmt:?}: {}", hit.reason);
    }
    (out, end.map(|_| ()))
}

fuzz_target!(|data: &[u8]| {
    exav_fuzz_support::panics::tolerate_inside(exav_fuzz_support::panics::CONTAINED);
    let Some((&pick, image)) = data.split_first() else {
        return;
    };
    let pick = usize::from(pick);
    let all: &[Format] = &FORMATS;
    let one = [FORMATS[pick % FORMATS.len()]];
    let formats: &[Format] = if pick < FORMATS.len() { &one } else { all };
    for &fmt in formats {
        let mem = found(fmt, &image);
        let cached = BlockCache::with_sizes(Cursor::new(image.to_vec()), 512, 8 * 1024).unwrap();
        let via_cache = found(fmt, &cached);
        // The same members, in the same order; the same end, or both ended in an
        // error (its text names offsets the cache does not change, but not what
        // a block boundary does).
        assert_eq!(mem.0, via_cache.0, "{fmt:?}: the cache changed what was found");
        assert_eq!(
            mem.1.is_err(),
            via_cache.1.is_err(),
            "{fmt:?}: the cache changed how the walk ended"
        );
    }
});
