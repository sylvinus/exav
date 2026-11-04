#![no_main]
//! RAR4 and RAR5 through `walk`, the path the scanner takes: headers read
//! from the source, members decoded as they are read (LZ, PPMd, filters,
//! solid groups), the CRC checked at the end of each. Each archive is walked
//! from memory and through a block cache of 512-byte blocks, reading members
//! a few bytes at a time: the two must find the same members with the same
//! bytes and end the same way.
use exav_unpack::source::BlockCache;
use exav_unpack::{Budget, ByteSource, Format, Limits, Member, walk};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

type Seen = (String, Vec<u8>, Option<&'static str>, Option<String>);

fn members(src: &dyn ByteSource, step: usize) -> (Vec<Seen>, Result<(), String>) {
    let mut limits = Limits::default();
    limits.max_buffer_bytes = 1 << 20;
    limits.max_scanned_bytes = 8 << 20;
    limits.max_extracted_bytes = 8 << 20;
    limits.max_members = 64;
    let mut budget = Budget::new(limits);
    let mut seen = Vec::new();
    let r = walk(Format::Rar, src, &mut budget, &mut |m, c, _| {
        let mut data = Vec::new();
        let mut err = None;
        match c {
            Some(Member::Bytes(d)) => data = d,
            Some(Member::Stream(r)) => {
                let mut buf = vec![0u8; step];
                loop {
                    match r.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => data.extend_from_slice(&buf[..n]),
                        Err(e) => {
                            err = Some(e.to_string());
                            break;
                        }
                    }
                }
            }
            None => {}
        }
        seen.push((m.name.clone(), data, m.unsupported, err));
        None::<()>
    });
    (seen, r.map(|_| ()).map_err(|e| e.reason))
}

fuzz_target!(|data: &[u8]| {
    let step = 1 + data.first().map_or(0, |&b| b as usize % 13);
    let (mem, mem_end) = members(&data, 4096);
    let Ok(cache) = BlockCache::with_sizes(Cursor::new(data.to_vec()), 512, 4096) else {
        return;
    };
    let (cached, cached_end) = members(&cache, step);
    assert_eq!(mem, cached, "memory and block cache disagree");
    assert_eq!(mem_end, cached_end);
});
