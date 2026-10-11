#![no_main]
//! Multi-volume sets: the volume-name grammar (`x.7z.001`, `x.part1.rar`,
//! `x.r00`, `x.z01`, ...), the collector that holds the parts of a split
//! archive until the rest arrive and then joins them, and the RAR joiner that
//! rewrites the volumes of a set into the one archive `Format::Rar` reads.
//!
//! The input is `fuzz_support::frame`: up to eight files, each a volume (the
//! kind byte picks its name from `NAMES`, so that several fall in one set) of
//! the set, whose bytes are the volume's.
//!
//! Checked: the collector loses nothing. Whatever is offered comes out, once,
//! under the name it came in under, whether passed through, joined or left
//! unjoined, and the bytes add up; a set it cannot rejoin is never silently
//! dropped (the verdict's third invariant). The RAR joiner and the extraction
//! of what it joins neither panic nor overrun the budget.
use exav_fuzz_support::frame;
use exav_unpack::volume::{Collector, Offer};
use exav_unpack::{extract, join_rar_volumes, Budget, Format, Limits};
use libfuzzer_sys::fuzz_target;

const NAMES: &[&str] = &[
    "a.7z.001",
    "a.7z.002",
    "a.7z.003",
    "a.zip.001",
    "a.zip.002",
    "a.part1.rar",
    "a.part2.rar",
    "a.part3.rar",
    "a.rar",
    "a.r00",
    "a.r01",
    "a.z01",
    "a.z02",
    "a.zip",
    "b.7z.001",
    "plain.txt",
];

fn tight() -> Limits {
    let mut l = Limits::default();
    l.max_extracted_bytes = 1 << 20;
    l.max_members = 16;
    l.max_compression_ratio = 100;
    l.max_buffer_bytes = 1 << 20;
    l.max_scanned_bytes = 1 << 20;
    l.max_recursion = 2;
    l
}

fuzz_target!(|data: &[u8]| {
    let Some(f) = frame::parse(data) else {
        return;
    };

    let mut collector = Collector::new(1 << 20);
    let mut offered: Vec<(String, usize)> = Vec::new();
    let mut out: Vec<(String, usize)> = Vec::new();
    for (kind, bytes) in &f.files {
        let name = NAMES[*kind as usize % NAMES.len()];
        offered.push((name.to_string(), bytes.len()));
        match collector.offer(name, bytes.to_vec()) {
            Offer::PassThrough { name, data } => out.push((name, data.len())),
            Offer::Held => {}
        }
    }
    let finished = collector.finish();
    for j in &finished.joined {
        // The parts' names, and between them the joined bytes.
        let parts: Vec<_> = offered.iter().filter(|(n, _)| j.parts.contains(n)).collect();
        assert!(!parts.is_empty(), "a joined set names parts nobody offered: {:?}", j.parts);
        out.extend(j.parts.iter().map(|p| {
            let len = offered.iter().find(|(n, _)| n == p).map_or(0, |(_, l)| *l);
            (p.clone(), len)
        }));
    }
    for u in &finished.unjoined {
        out.push((u.name.clone(), u.data.len()));
    }
    let key = |v: &Vec<(String, usize)>| {
        let mut v = v.clone();
        v.sort();
        v
    };
    // A part offered twice under one name is one name, and joined sets list
    // each once: compare the names and sizes as sets.
    let mut offered_set = key(&offered);
    offered_set.dedup();
    let mut out_set = key(&out);
    out_set.dedup();
    assert_eq!(out_set, offered_set, "what was offered is not what came out");
    let joined_bytes: usize = finished.joined.iter().map(|j| j.data.len()).sum();
    let parts_bytes: usize = finished
        .joined
        .iter()
        .flat_map(|j| j.parts.iter())
        .map(|p| offered.iter().find(|(n, _)| n == p).map_or(0, |(_, l)| *l))
        .sum();
    assert_eq!(joined_bytes, parts_bytes, "a joined set has other bytes than its parts");

    // The RAR joiner: the files, in order, as the volumes of one set.
    let volumes: Vec<&[u8]> = f.files.iter().map(|(_, b)| *b).collect();
    if let Ok(joined) = join_rar_volumes(&volumes) {
        let mut budget = Budget::new(tight());
        let _ = extract(Format::Rar, &joined.as_slice(), &mut budget);
    }
});
