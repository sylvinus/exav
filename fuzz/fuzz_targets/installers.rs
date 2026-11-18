#![no_main]
//! AppleSingle and AppleDouble, InstallShield InstallScript cabinets (`ISc(`)
//! and Inno Setup installers, walked on hostile bytes: headers and descriptor
//! tables, file records, deflated chunks, obfuscated data, and what is
//! reported rather than read. The budgets are small, so the declared counts
//! and sizes of a file of a few KiB are over them.
//!
//! The first byte picks the format (above the list: all of them); the rest is
//! the file. Each is walked from memory and through a block cache of tiny
//! blocks, which must find the same members and end the same way, and a
//! second walk from memory must find what the first did. No walk may end as a
//! decoder that panicked.
//!
//! Seeds: `fuzz/seeds/installers` (written by the script in that directory),
//! via `scripts/fuzz-seeds.sh`.
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

const FORMATS: [Format; 3] = [Format::AppleSingle, Format::IshieldCab, Format::Inno];

fn limits() -> Limits {
    let mut l = Limits::default();
    l.max_buffer_bytes = 64 * 1024;
    l.max_extracted_bytes = 1024 * 1024;
    l.max_scanned_bytes = 4 * 1024 * 1024;
    l.max_members = 400;
    l.max_recursion = 2;
    l
}

/// Each member's name, size and whether it was reported, and how the walk
/// ended.
type Found = (Vec<(String, usize, bool)>, Result<(), LimitHit>);

fn found(fmt: Format, src: &dyn ByteSource) -> Found {
    let mut budget = Budget::new(limits());
    let mut out = Vec::new();
    let end = walk(fmt, src, &mut budget, &mut |meta, content, _| {
        let n = match content {
            None => 0,
            Some(Member::Bytes(b)) => b.len(),
            Some(Member::Stream(r)) => {
                let mut n = 0;
                let mut buf = [0u8; 8192];
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
        assert!(
            !hit.reason.ends_with(" decoder panicked on malformed input"),
            "{fmt:?}: {}",
            hit.reason
        );
    }
    (out, end.map(|_| ()))
}

fuzz_target!(|data: &[u8]| {
    let Some((&pick, file)) = data.split_first() else {
        return;
    };
    let pick = usize::from(pick);
    let one = [FORMATS[pick % FORMATS.len()]];
    let formats: &[Format] = if pick < FORMATS.len() { &one } else { &FORMATS };
    for &fmt in formats {
        let mem = found(fmt, &file);
        let cached = BlockCache::with_sizes(Cursor::new(file.to_vec()), 512, 8 * 1024).unwrap();
        let via_cache = found(fmt, &cached);
        assert_eq!(
            mem.0, via_cache.0,
            "{fmt:?}: the cache changed what was found"
        );
        assert_eq!(
            mem.1.is_err(),
            via_cache.1.is_err(),
            "{fmt:?}: the cache changed how the walk ended"
        );
        let again = found(fmt, &file);
        assert_eq!(
            mem.0, again.0,
            "{fmt:?}: a second walk found something else"
        );
    }
});
