//! `EP`, `Sn`, `SL` and `SEn` offsets on ELF (`Target:6`) and Mach-O
//! (`Target:9`) files.
//!
//! Until a layout was read from their headers these offsets matched nothing
//! there: a signature anchored at an ELF's entry point was in the database, the
//! file was that ELF, and the scan said `OK`.
//!
//! The expectations are clamscan 1.4.3's, measured one signature at a time on
//! a gcc-built ELF and on hand-built Mach-O files, each offset with a control
//! (the same bytes at an offset wrong by three, which must not fire):
//!
//! * ELF `EP`: the entry point's file offset, through the loadable segment
//!   whose memory image holds it, the `.bss` part included; nothing past it,
//!   nothing for another file type.
//! * ELF and Mach-O `Sn`: section `n`'s file offset, counted from the null
//!   section 0 (ELF) or over the segments in load order (Mach-O); `SL` the last.
//! * `SEn`: the match starts inside section `n`, its end included.
//! * Mach-O `EP`: never resolved (`LC_MAIN` and `LC_UNIXTHREAD`, both widths).

use exav_core::{analyze, loader, ScanOptions, Verdict};

/// 64 bytes of distinct content for a section: `seed` and the position.
fn block(seed: u8) -> Vec<u8> {
    (0..64u32)
        .map(|j| ((u32::from(seed) * 61 + j * 7 + 13) % 251 + 1) as u8)
        .collect()
}

fn put(v: &mut Vec<u8>, at: usize, bytes: &[u8]) {
    if v.len() < at + bytes.len() {
        v.resize(at + bytes.len(), 0);
    }
    v[at..at + bytes.len()].copy_from_slice(bytes);
}

/// Bytes of an integer field of `width` bytes in the file's order.
fn int(v: u64, width: usize, be: bool) -> Vec<u8> {
    let mut b = v.to_le_bytes()[..width].to_vec();
    if be {
        b.reverse();
    }
    b
}

/// An ELF with a null section, `.text`, `.rodata`, `.data` and a `.bss`:
/// two loadable segments, the second at a virtual address that is not its file
/// offset plus the first's, and with memory past its bytes. Returns the file,
/// and the file offsets of the sections' contents.
fn elf(wide: bool, be: bool, entry: u64) -> Vec<u8> {
    let w = if wide { 8 } else { 4 };
    let (ehsize, phsize, shsize) = if wide { (64, 56, 64) } else { (52, 32, 40) };
    let mut f = vec![0u8; 0x600];
    put(&mut f, 0, b"\x7fELF");
    f[4] = if wide { 2 } else { 1 };
    f[5] = if be { 2 } else { 1 };
    f[6] = 1;
    let mut at = 16;
    for (v, n) in [(2u64, 2), (62, 2), (1, 4)] {
        put(&mut f, at, &int(v, n, be));
        at += n;
    }
    let (phoff, shoff) = (ehsize as u64, 0x400u64);
    for v in [entry, phoff, shoff] {
        put(&mut f, at, &int(v, w, be));
        at += w;
    }
    put(&mut f, at, &int(0, 4, be)); // e_flags
    at += 4;
    for v in [ehsize as u64, phsize as u64, 2, shsize as u64, 5, 0] {
        put(&mut f, at, &int(v, 2, be));
        at += 2;
    }
    // Program headers: (type, offset, vaddr, filesz, memsz).
    let segments = [
        (1u64, 0u64, 0x10000u64, 0x300u64, 0x300u64),
        (1, 0x300, 0x30000, 0x40, 0x80),
    ];
    for (i, (kind, offset, vaddr, filesz, memsz)) in segments.iter().enumerate() {
        let p = ehsize + i * phsize;
        put(&mut f, p, &int(*kind, 4, be));
        if wide {
            for (off, v) in [
                (8, offset),
                (16, vaddr),
                (24, vaddr),
                (32, filesz),
                (40, memsz),
            ] {
                put(&mut f, p + off, &int(*v, 8, be));
            }
        } else {
            for (off, v) in [
                (4, offset),
                (8, vaddr),
                (12, vaddr),
                (16, filesz),
                (20, memsz),
            ] {
                put(&mut f, p + off, &int(*v, 4, be));
            }
        }
    }
    // Section contents, then the section headers: (type, offset, size).
    for (i, off) in [0x200usize, 0x240, 0x300].iter().enumerate() {
        put(&mut f, *off, &block(i as u8));
    }
    // What follows `.rodata`, which is not in it, and what the file holds
    // where the `.bss` would be, so that a wrong offset reads other bytes.
    put(&mut f, 0x280, &block(9)[..32]);
    put(&mut f, 0x340, &block(7));
    let sections = [
        (0u64, 0u64, 0u64),
        (1, 0x200, 0x40),
        (1, 0x240, 0x40),
        (1, 0x300, 0x40),
        (8, 0x340, 0x40),
    ];
    for (i, (kind, offset, size)) in sections.iter().enumerate() {
        let s = shoff as usize + i * shsize;
        put(&mut f, s + 4, &int(*kind, 4, be));
        let (off_at, size_at) = if wide { (24, 32) } else { (16, 20) };
        put(&mut f, s + off_at, &int(*offset, w, be));
        put(&mut f, s + size_at, &int(*size, w, be));
    }
    f
}

/// A Mach-O with `__text` and `__cstring` in `__TEXT`, `__data` in `__DATA`,
/// and an `LC_MAIN` whose entry is at 0x210.
fn macho(wide: bool, be: bool) -> Vec<u8> {
    let (seg_cmd, seg_head, sect_len, sect_fields) = if wide {
        (0x19u64, 72usize, 80usize, 8usize)
    } else {
        (0x1, 56, 68, 4)
    };
    let sections = [
        ("__text", "__TEXT", 0x200u64),
        ("__cstring", "__TEXT", 0x240),
        ("__data", "__DATA", 0x280),
    ];
    let mut cmds = Vec::new();
    for (segname, group) in [("__TEXT", &sections[..2]), ("__DATA", &sections[2..])] {
        let size = seg_head + group.len() * sect_len;
        let mut c = vec![0u8; size];
        put(&mut c, 0, &int(seg_cmd, 4, be));
        put(&mut c, 4, &int(size as u64, 4, be));
        put(&mut c, 8, segname.as_bytes());
        let nsects_at = if wide { 64 } else { 48 };
        put(&mut c, nsects_at, &int(group.len() as u64, 4, be));
        for (i, (name, seg, offset)) in group.iter().enumerate() {
            let s = seg_head + i * sect_len;
            put(&mut c, s, name.as_bytes());
            put(&mut c, s + 16, seg.as_bytes());
            put(
                &mut c,
                s + 32,
                &int(0x1_0000_0000 + offset, sect_fields, be),
            );
            put(&mut c, s + 32 + sect_fields, &int(0x40, sect_fields, be));
            put(&mut c, s + 32 + 2 * sect_fields, &int(*offset, 4, be));
        }
        cmds.extend(c);
    }
    let mut main = vec![0u8; 24];
    put(&mut main, 0, &int(0x8000_0028, 4, be));
    put(&mut main, 4, &int(24, 4, be));
    put(&mut main, 8, &int(0x210, 8, be));
    cmds.extend(main);
    let header = if wide { 32 } else { 28 };
    let mut f = vec![0u8; 0x300];
    let magic: [u8; 4] = match (wide, be) {
        (true, false) => [0xCF, 0xFA, 0xED, 0xFE],
        (false, false) => [0xCE, 0xFA, 0xED, 0xFE],
        (true, true) => [0xFE, 0xED, 0xFA, 0xCF],
        (false, true) => [0xFE, 0xED, 0xFA, 0xCE],
    };
    put(&mut f, 0, &magic);
    put(&mut f, 4, &int(if wide { 0x0100_000c } else { 7 }, 4, be));
    put(&mut f, 12, &int(2, 4, be));
    put(&mut f, 16, &int(3, 4, be));
    put(&mut f, 20, &int(cmds.len() as u64, 4, be));
    put(&mut f, header, &cmds);
    for (i, (_, _, offset)) in sections.iter().enumerate() {
        put(&mut f, *offset as usize, &block(i as u8));
    }
    f
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The names of the signatures among `lines` (`name:target:offset:bytes`)
/// that fire on `file`, all of them listed.
fn fired(file: &[u8], lines: &[(&str, &str, &str, &[u8])]) -> Vec<String> {
    let mut found = Vec::new();
    // One signature a database: a first-match scan would stop at the first.
    for (name, target, offset, bytes) in lines {
        let mut b = loader::Builder::new();
        b.add_named_bytes(
            "t.ndb",
            format!("{name}:{target}:{offset}:{}\n", hex(bytes)).as_bytes(),
            true,
        );
        let Ok(db) = b.build() else {
            continue;
        };
        if matches!(
            analyze(&db, file, &ScanOptions::default()).verdict,
            Verdict::Infected { .. }
        ) {
            found.push((*name).to_string());
        }
    }
    found
}

fn names(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| (*s).to_string()).collect()
}

#[test]
fn an_elf_resolves_its_entry_point_and_its_sections_in_every_class_and_order() {
    for (wide, be) in [(true, false), (false, false), (true, true), (false, true)] {
        let f = elf(wide, be, 0x10210);
        let at = |o: usize| f[o..o + 12].to_vec();
        let got = fired(
            &f,
            &[
                ("EP", "6", "EP+0", &at(0x210)),
                ("EPwrong", "6", "EP+3", &at(0x210)),
                ("EPelsewhere", "6", "EP+0", &at(0x200)),
                ("S0", "6", "S0+0", &at(0)),
                ("S1", "6", "S1+0", &at(0x200)),
                ("S1wrong", "6", "S1+3", &at(0x200)),
                ("S2", "6", "S2+0", &at(0x240)),
                ("S3", "6", "S3+0", &at(0x300)),
                ("S3wrong", "6", "S3+3", &at(0x300)),
                ("S4", "6", "S4+0", &at(0x340)),
                ("S5none", "6", "S5+0", &at(0x200)),
                ("SL", "6", "SL+0", &at(0x340)),
                ("SLwrong", "6", "SL+3", &at(0x340)),
                // Another file type's target.
                ("EPasPe", "1", "EP+0", &at(0x210)),
            ],
        );
        assert_eq!(
            got,
            names(&["EP", "S0", "S1", "S2", "S3", "S4", "SL"]),
            "wide {wide} big-endian {be}"
        );
    }
}

#[test]
fn an_elf_entry_point_is_found_through_the_segment_that_maps_it() {
    // In the second segment, whose address is not its offset plus the first's.
    let f = elf(true, false, 0x30010);
    let sig = |o: usize| f[o..o + 12].to_vec();
    assert_eq!(
        fired(
            &f,
            &[
                ("EP", "6", "EP+0", &sig(0x310)),
                ("EPasAddr", "6", "EP+0", &sig(0x10)),
                ("EPwrong", "6", "EP+3", &sig(0x310))
            ]
        ),
        names(&["EP"])
    );
    // In the memory past the segment's bytes, which has an offset all the same.
    let f = elf(true, false, 0x30050);
    assert_eq!(
        fired(&f, &[("EP", "6", "EP+0", &f[0x350..0x35c])]),
        names(&["EP"])
    );
    // Past the segment's memory, in none.
    let f = elf(true, false, 0x30080);
    assert_eq!(
        fired(
            &f,
            &[
                ("EP", "6", "EP+0", &f[0x380..0x38c]),
                ("EP0", "6", "EP+0", &f[0..12])
            ]
        ),
        Vec::<String>::new()
    );
}

#[test]
fn se_means_a_start_inside_the_section_its_end_included() {
    let f = elf(true, false, 0x10210);
    // `.rodata` is 0x240..0x280.
    let got = fired(
        &f,
        &[
            ("inside", "6", "SE2", &f[0x244..0x24a]),
            ("first", "6", "SE2", &f[0x240..0x246]),
            ("lastByteRunningOut", "6", "SE2", &f[0x27e..0x286]),
            ("atTheEnd", "6", "SE2", &f[0x280..0x288]),
            ("inTheNextOne", "6", "SE2", &f[0x304..0x30a]),
            ("inThePrevious", "6", "SE2", &f[0x204..0x20a]),
        ],
    );
    assert_eq!(
        got,
        names(&["inside", "first", "lastByteRunningOut", "atTheEnd"])
    );
}

#[test]
fn a_macho_resolves_its_sections_in_load_order_and_never_its_entry_point() {
    for (wide, be) in [(true, false), (false, false), (true, true), (false, true)] {
        let f = macho(wide, be);
        let at = |o: usize| f[o..o + 8].to_vec();
        let got = fired(
            &f,
            &[
                ("S0", "9", "S0+0", &at(0x200)),
                ("S0wrong", "9", "S0+3", &at(0x200)),
                ("S1", "9", "S1+0", &at(0x240)),
                ("S2", "9", "S2+0", &at(0x280)),
                ("S3none", "9", "S3+0", &at(0x280)),
                ("SL", "9", "SL+0", &at(0x280)),
                ("SLwrong", "9", "SL+3", &at(0x280)),
                ("SE1", "9", "SE1", &f[0x244..0x24a]),
                ("SE1elsewhere", "9", "SE1", &f[0x284..0x28a]),
                ("EP", "9", "EP+0", &at(0x210)),
            ],
        );
        assert_eq!(
            got,
            names(&["S0", "S1", "S2", "SL", "SE1"]),
            "wide {wide} big-endian {be}"
        );
    }
}

#[test]
fn headers_that_lie_give_no_layout_and_no_panic() {
    let elf = elf(true, false, 0x10210);
    let macho = macho(true, false);
    for file in [&elf, &macho] {
        // Every field at its extremes, 4 bytes at a time, and the file cut short.
        for at in (0..file.len().min(0x120)).step_by(4) {
            for v in [0xFFFF_FFFFu32, 0x8000_0000, 0x7FFF_FFFF, 0] {
                let mut f = file.clone();
                f[at..at + 4].copy_from_slice(&v.to_le_bytes());
                let _ = fired(
                    &f,
                    &[
                        ("S1", "6", "S1+0", &[1, 2, 3, 4]),
                        ("S1m", "9", "S1+0", &[1, 2, 3, 4]),
                        ("EP", "6", "EP+0", &[1, 2, 3, 4]),
                    ],
                );
            }
        }
        for cut in (0..file.len()).step_by(37) {
            let _ = fired(
                &file[..cut],
                &[
                    ("SL", "6", "SL+0", &[1, 2, 3, 4]),
                    ("SLm", "9", "SL+0", &[1, 2, 3, 4]),
                ],
            );
        }
    }
}
