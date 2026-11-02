#![no_main]
//! Filesystem images on hostile bytes: ext2/3/4, exFAT, SquashFS, cramfs, romfs
//! and EROFS, each walked in place over a `Read + Seek`, and a partitioned disk
//! holding any of them (a volume over the buffer limit is walked where it lies,
//! under the name of its partition). With them the three archives that are read
//! where they lie on a seekable source rather than held: 7z, WIM and xar. The
//! budgets are small, so the declared sizes of an image, a directory or a file
//! of a few KiB are over them.
//!
//! The first byte picks the format (above the list: all of them); the rest is the
//! image. Each is walked twice, from memory and through a block cache of tiny
//! blocks, and the two must find the same members and end the same way: a read
//! that depends on where the cache's blocks fall is a bug. A third walk, again
//! from memory, must find the same as the first: nothing may depend on what an
//! earlier walk left behind. No member held whole may pass the buffer limit, and
//! no walk may end as a decoder that panicked.
//!
//! Seeds: `fuzz/seeds/fsimage` (small images of each, made by the script in that
//! directory, and the same behind a partition table), via `scripts/fuzz-seeds.sh`.
use exav_fuzz_support::extreme;
use exav_unpack::source::BlockCache;
use exav_unpack::{Budget, ByteSource, Format, LimitHit, Limits, Member, walk};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

libfuzzer_sys::fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    if extreme::set_extreme_field(data, size, seed) {
        size
    } else {
        libfuzzer_sys::fuzzer_mutate(data, size, max_size)
    }
});

const FORMATS: [Format; 10] = [
    Format::Ext,
    Format::Exfat,
    Format::Squashfs,
    Format::Cramfs,
    Format::Romfs,
    Format::Erofs,
    Format::Partition,
    Format::SevenZip,
    Format::Wim,
    Format::Xar,
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
    if let Err(hit) = &end {
        // Error texts may echo input bytes, so match the walk's own wording.
        assert!(
            !hit.reason.ends_with(" decoder panicked on malformed input"),
            "{fmt:?}: {}",
            hit.reason
        );
    }
    (out, end.map(|_| ()))
}

fuzz_target!(|data: &[u8]| {
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
        assert_eq!(
            mem.0, via_cache.0,
            "{fmt:?}: the cache changed what was found"
        );
        assert_eq!(
            mem.1.is_err(),
            via_cache.1.is_err(),
            "{fmt:?}: the cache changed how the walk ended"
        );
        let again = found(fmt, &image);
        assert_eq!(mem.0, again.0, "{fmt:?}: a second walk found something else");
    }
});
