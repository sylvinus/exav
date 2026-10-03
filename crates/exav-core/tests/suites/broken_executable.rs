//! `Heuristics.Broken.Executable` judges the headers a loader maps, not the
//! data they point at.
//!
//! Every expectation below was checked against clamscan 1.5.4
//! (`--alert-broken`) on these exact bytes. The rules were found the same way,
//! by mutating one header field at a time; the corpus check behind them is 4,134
//! PE, ELF and Mach-O files extracted from archives, where exav and clamscan
//! now agree on all of them.
//!
//! Before, any file goblin could not parse in full was "broken": a DLL with a
//! non-UTF-8 export name, a resource directory pointing nowhere, an Android
//! `.so` with junk section headers. Meanwhile PEs whose alignment or section
//! layout no loader accepts parsed fine and passed.

use exav_core::{analyze, loader, ScanOptions, Scanner, Verdict};

fn empty_db() -> Scanner {
    let mut l = loader::Builder::new();
    l.add_named_bytes("t.ndb", b"Zzz.Never:0:*:deadbeefdeadbeef\n", true);
    l.build().expect("build database")
}

fn broken(db: &Scanner, blob: &[u8]) -> bool {
    let mut opts = ScanOptions::default();
    opts.alert_broken = true;
    opts.clamav_compat = true;
    match analyze(db, blob, &opts).verdict {
        Verdict::Infected { signature, .. } => {
            assert_eq!(signature, "Heuristics.Broken.Executable");
            true
        }
        _ => false,
    }
}

fn check(cases: Vec<(&str, Vec<u8>, bool)>) {
    let db = empty_db();
    let wrong: Vec<String> = cases
        .iter()
        .filter(|(_, blob, want)| broken(&db, blob) != *want)
        .map(|(name, _, want)| format!("{name}: expected broken={want}"))
        .collect();
    assert!(
        wrong.is_empty(),
        "{} of {} wrong:\n{}",
        wrong.len(),
        cases.len(),
        wrong.join("\n")
    );
}

fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

// ---------------------------------------------------------------------- PE

#[derive(Clone, Copy)]
struct Sec {
    vs: u32,
    va: u32,
    rs: u32,
    rp: u32,
}

const fn sec(vs: u32, va: u32, rs: u32, rp: u32) -> Sec {
    Sec { vs, va, rs, rp }
}

/// A two-section image laid out the way a linker would: headers in the first
/// 0x200 bytes, `.text` and `.data` at 0x200 and 0x400 in the file and at
/// 0x1000 and 0x2000 in memory. Each case changes what it needs.
#[derive(Clone)]
struct Pe {
    pe64: bool,
    nsec: Option<u16>,
    optsz: Option<u16>,
    magic: Option<u16>,
    subsystem: u16,
    ep: u32,
    salign: u32,
    falign: u32,
    soh: u32,
    nrva: u32,
    dirs: Vec<(usize, u32, u32)>,
    secs: Vec<Sec>,
    len: Option<usize>,
}

impl Default for Pe {
    fn default() -> Self {
        Pe {
            pe64: false,
            nsec: None,
            optsz: None,
            magic: None,
            subsystem: 2,
            ep: 0x1000,
            salign: 0x1000,
            falign: 0x200,
            soh: 0x200,
            nrva: 16,
            dirs: Vec::new(),
            secs: vec![
                sec(0x200, 0x1000, 0x200, 0x200),
                sec(0x200, 0x2000, 0x200, 0x400),
            ],
            len: None,
        }
    }
}

impl Pe {
    fn build(&self) -> Vec<u8> {
        let fixed: usize = if self.pe64 { 112 } else { 96 };
        let optsz = self.optsz.map_or(fixed + 128, usize::from);
        let nsec = self.nsec.unwrap_or(self.secs.len() as u16);
        let opt = 0x80 + 24;
        let table = opt + optsz;
        let body = table + self.secs.len() * 40;
        let data_end = self
            .secs
            .iter()
            .filter(|s| s.rp < 0x10000)
            .map(|s| (s.rp + s.rs) as usize);
        let mut b = vec![0u8; data_end.max().unwrap_or(0).max(body).max(0x600)];
        b[..2].copy_from_slice(b"MZ");
        put32(&mut b, 0x3c, 0x80);
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        put16(&mut b, 0x84, if self.pe64 { 0x8664 } else { 0x14c });
        put16(&mut b, 0x86, nsec);
        put16(&mut b, 0x94, optsz as u16);
        put16(&mut b, 0x96, 0x0102);
        // Optional header fields that stay in place across both widths, then
        // the data directories.
        let mut o = vec![0u8; fixed + 128];
        put16(
            &mut o,
            0,
            self.magic.unwrap_or(if self.pe64 { 0x20b } else { 0x10b }),
        );
        put32(&mut o, 16, self.ep);
        put32(&mut o, 32, self.salign);
        put32(&mut o, 36, self.falign);
        put32(&mut o, 56, 0x3000);
        put32(&mut o, 60, self.soh);
        put16(&mut o, 68, self.subsystem);
        put32(&mut o, fixed - 4, self.nrva);
        for &(i, rva, size) in &self.dirs {
            put32(&mut o, fixed + i * 8, rva);
            put32(&mut o, fixed + i * 8 + 4, size);
        }
        o.resize(optsz, 0);
        b[opt..table].copy_from_slice(&o);
        for (i, s) in self.secs.iter().enumerate() {
            let at = table + i * 40;
            b[at..at + 5].copy_from_slice(b".sect");
            put32(&mut b, at + 8, s.vs);
            put32(&mut b, at + 12, s.va);
            put32(&mut b, at + 16, s.rs);
            put32(&mut b, at + 20, s.rp);
        }
        b[0x200] = 0xc3;
        if let Some(len) = self.len {
            b.resize(len, 0);
        }
        b
    }
}

fn pe(f: impl FnOnce(&mut Pe)) -> Vec<u8> {
    let mut p = Pe::default();
    f(&mut p);
    p.build()
}

#[test]
fn pe_rules() {
    let many: Vec<Sec> = std::iter::once(sec(0x200, 0x2000, 0x200, 0x2000))
        .chain((1..1000).map(|i| sec(0x1000, 0x1000 * (i + 2), 0, 0)))
        .collect();
    check(vec![
        ("PE32", pe(|_| {}), false),
        ("PE32+", pe(|p| p.pe64 = true), false),
        // What a loader does not need to map the image.
        (
            "import directory pointing nowhere",
            pe(|p| p.dirs = vec![(1, 0x7fff0000, 0x100)]),
            false,
        ),
        (
            "resource directory pointing nowhere",
            pe(|p| p.dirs = vec![(2, 0x7fff0000, 0x100)]),
            false,
        ),
        (
            "relocations pointing nowhere",
            pe(|p| p.dirs = vec![(5, 0x7fff0000, 0x100)]),
            false,
        ),
        (
            "CLR header pointing nowhere",
            pe(|p| p.dirs = vec![(14, 0x7fff0000, 0x100)]),
            false,
        ),
        (
            "unknown optional-header magic",
            pe(|p| p.magic = Some(0x999)),
            false,
        ),
        (
            "NumberOfRvaAndSizes above 16",
            pe(|p| p.nrva = 0x100),
            false,
        ),
        (
            "raw data running past EOF",
            pe(|p| p.secs[1].rs = 0x10000),
            false,
        ),
        (
            "last section starting past EOF",
            pe(|p| p.secs[1].rp = 0x10000),
            false,
        ),
        (
            "empty section starting past EOF",
            pe(|p| (p.secs[1].rp, p.secs[1].rs) = (0x10000, 0)),
            false,
        ),
        ("entry point 0", pe(|p| p.ep = 0), false),
        ("entry point in the headers", pe(|p| p.ep = 0x10), false),
        (
            "entry point in raw-size padding",
            pe(|p| (p.ep, p.secs[0].rs) = (0x1180, 0x150)),
            false,
        ),
        ("FileAlignment 0x600", pe(|p| p.falign = 0x600), false),
        (
            "1000 sections",
            pe(|p| (p.soh, p.ep, p.secs) = (0x2000, 0x2000, many.clone())),
            false,
        ),
        (
            "cut inside the COFF header",
            pe(|p| p.len = Some(0x8a)),
            false,
        ),
        (
            "cut inside the data directories",
            pe(|p| p.len = Some(0x80 + 24 + 100)),
            false,
        ),
        (
            "native driver with 0x80 alignment",
            pe(|p| {
                (p.subsystem, p.salign, p.falign, p.soh, p.ep) = (1, 0x80, 0x80, 0x200, 0x200);
                p.secs = vec![
                    sec(0x200, 0x200, 0x200, 0x200),
                    sec(0x200, 0x400, 0x200, 0x400),
                ];
            }),
            false,
        ),
        (
            "native with FileAlignment 0",
            pe(|p| (p.subsystem, p.falign) = (1, 0)),
            false,
        ),
        // What it does.
        ("no sections", pe(|p| p.nsec = Some(0)), true),
        (
            "optional header without its data directories",
            pe(|p| p.optsz = Some(0x60)),
            true,
        ),
        (
            "optional header below its fixed part",
            pe(|p| (p.optsz, p.nrva) = (Some(95), 0)),
            true,
        ),
        (
            "PE32+ with a PE32-sized optional header",
            pe(|p| (p.pe64, p.optsz) = (true, Some(224))),
            true,
        ),
        (
            "cut inside the fixed optional header",
            pe(|p| p.len = Some(0x80 + 24 + 50)),
            true,
        ),
        (
            "section table cut short",
            pe(|p| p.len = Some(0x80 + 24 + 224 + 60)),
            true,
        ),
        ("FileAlignment 0", pe(|p| p.falign = 0), true),
        ("FileAlignment 0x100", pe(|p| p.falign = 0x100), true),
        ("FileAlignment 0x300", pe(|p| p.falign = 0x300), true),
        ("SectionAlignment 0x800", pe(|p| p.salign = 0x800), true),
        (
            "native with SectionAlignment 0",
            pe(|p| (p.subsystem, p.salign) = (1, 0)),
            true,
        ),
        (
            "first section not right after the headers",
            pe(|p| p.secs[0].va = 0x2000),
            true,
        ),
        ("gap between sections", pe(|p| p.secs[1].va = 0x3000), true),
        ("overlapping sections", pe(|p| p.secs[1].va = 0x1000), true),
        ("entry point outside the image", pe(|p| p.ep = 0x8000), true),
        (
            "entry point past the raw data",
            pe(|p| (p.ep, p.secs[0].vs) = (0x1400, 0x800)),
            true,
        ),
        (
            "entry point in raw data past EOF",
            pe(|p| p.secs[0].rp = 0x10000),
            true,
        ),
        (
            "only section starting past EOF",
            pe(|p| (p.nsec, p.ep, p.secs[0].rp) = (Some(1), 0x10, 0x10000)),
            true,
        ),
        // A section whose raw data starts past EOF leaves the layout, so the
        // one after it is misplaced: the shape of every such file in the corpus.
        (
            "middle section starting past EOF",
            pe(|p| {
                p.secs = vec![
                    sec(0x200, 0x1000, 0x200, 0x200),
                    sec(0x800, 0x2000, 0x200, 0x10000),
                    sec(0x200, 0x3000, 0x200, 0x400),
                ]
            }),
            true,
        ),
    ]);
}

// --------------------------------------------------------------------- ELF

/// One `PT_LOAD` over the whole file, `.text` and `.shstrtab` sections.
#[derive(Clone)]
struct Elf {
    wide: bool,
    be: bool,
    class: Option<u8>,
    data: Option<u8>,
    entry: Option<u64>,
    phoff: Option<u64>,
    phentsize: Option<u16>,
    phnum: u16,
    shoff: Option<u64>,
    shentsize: Option<u16>,
    shnum: u16,
    ptype: u32,
    memsz: Option<u64>,
    text_off: Option<u64>,
    len: Option<usize>,
}

impl Default for Elf {
    fn default() -> Self {
        Elf {
            wide: true,
            be: false,
            class: None,
            data: None,
            entry: None,
            phoff: None,
            phentsize: None,
            phnum: 1,
            shoff: None,
            shentsize: None,
            shnum: 3,
            ptype: 1,
            memsz: None,
            text_off: None,
            len: None,
        }
    }
}

impl Elf {
    fn build(&self) -> Vec<u8> {
        let (eh, ph, sh) = if self.wide {
            (64, 56, 64)
        } else {
            (52, 32, 40)
        };
        let base = 0x40_0000u64;
        let code = eh + ph;
        let shstr = b"\0.text\0.shstrtab\0";
        let table = (code + 16 + shstr.len() + 7) & !7;
        let total = table + 3 * sh;
        let mut b = vec![0u8; total];
        let w = |b: &mut Vec<u8>, at: usize, v: u64, n: usize| {
            let bytes = if self.be {
                v.to_be_bytes()
            } else {
                v.to_le_bytes()
            };
            let bytes = if self.be {
                &bytes[8 - n..]
            } else {
                &bytes[..n]
            };
            b[at..at + n].copy_from_slice(bytes);
        };
        let word = if self.wide { 8 } else { 4 };
        b[..4].copy_from_slice(b"\x7fELF");
        b[4] = self.class.unwrap_or(if self.wide { 2 } else { 1 });
        b[5] = self.data.unwrap_or(if self.be { 2 } else { 1 });
        b[6] = 1;
        w(&mut b, 16, 2, 2); // EXEC
        w(&mut b, 18, if self.wide { 0x3e } else { 3 }, 2);
        w(&mut b, 20, 1, 4);
        w(&mut b, 24, self.entry.unwrap_or(base + code as u64), word);
        w(&mut b, 24 + word, self.phoff.unwrap_or(eh as u64), word);
        w(
            &mut b,
            24 + 2 * word,
            self.shoff.unwrap_or(table as u64),
            word,
        );
        let f = 28 + 3 * word; // e_ehsize
        w(&mut b, f, eh as u64, 2);
        w(
            &mut b,
            f + 2,
            u64::from(self.phentsize.unwrap_or(ph as u16)),
            2,
        );
        w(&mut b, f + 4, u64::from(self.phnum), 2);
        w(
            &mut b,
            f + 6,
            u64::from(self.shentsize.unwrap_or(sh as u16)),
            2,
        );
        w(&mut b, f + 8, u64::from(self.shnum), 2);
        w(&mut b, f + 10, 2, 2);
        let memsz = self.memsz.unwrap_or(total as u64);
        if self.wide {
            w(&mut b, eh, u64::from(self.ptype), 4);
            w(&mut b, eh + 4, 5, 4);
            w(&mut b, eh + 16, base, 8);
            w(&mut b, eh + 24, base, 8);
            w(&mut b, eh + 32, total as u64, 8);
            w(&mut b, eh + 40, memsz, 8);
        } else {
            w(&mut b, eh, u64::from(self.ptype), 4);
            w(&mut b, eh + 8, base, 4);
            w(&mut b, eh + 12, base, 4);
            w(&mut b, eh + 16, total as u64, 4);
            w(&mut b, eh + 20, memsz, 4);
            w(&mut b, eh + 24, 5, 4);
        }
        b[code] = 0xc3;
        b[code + 16..code + 16 + shstr.len()].copy_from_slice(shstr);
        // Section headers: null, .text, .shstrtab. Name, type, then the file
        // offset and size at their width-dependent places.
        let (off_at, size_at) = if self.wide { (24, 32) } else { (16, 20) };
        for (i, (name, kind, off, size)) in [
            (1u64, 1u64, self.text_off.unwrap_or(code as u64), 16u64),
            (7, 3, (code + 16) as u64, shstr.len() as u64),
        ]
        .into_iter()
        .enumerate()
        {
            let at = table + (i + 1) * sh;
            w(&mut b, at, name, 4);
            w(&mut b, at + 4, kind, 4);
            w(&mut b, at + off_at, off, word);
            w(&mut b, at + size_at, size, word);
        }
        if let Some(len) = self.len {
            b.truncate(len);
        }
        b
    }
}

#[test]
fn elf_rules() {
    let mut cases = Vec::new();
    for (wide, be) in [(true, false), (true, true), (false, false), (false, true)] {
        let t = format!(
            "ELF{}{}",
            if wide { 64 } else { 32 },
            if be { "BE" } else { "LE" }
        );
        let elf = |f: &dyn Fn(&mut Elf)| {
            let mut e = Elf {
                wide,
                be,
                ..Elf::default()
            };
            f(&mut e);
            e.build()
        };
        let (eh, sh) = if wide { (64, 64) } else { (52, 40) };
        for (what, blob, want) in [
            ("base", elf(&|_| {}), false),
            // Section contents and segment data are not the loader's concern.
            (
                "section data past EOF",
                elf(&|e| e.text_off = Some(0x10_0000)),
                false,
            ),
            (
                "header shorter than its own size",
                elf(&|e| e.len = Some(eh - 10)),
                false,
            ),
            ("memsz below filesz", elf(&|e| e.memsz = Some(0x100)), false),
            ("entry point 0", elf(&|e| e.entry = Some(0)), false),
            (
                "entry point in a non-LOAD segment",
                elf(&|e| e.ptype = 4),
                false,
            ),
            (
                "no program headers, entry anywhere",
                elf(&|e| (e.phnum, e.entry) = (0, Some(0x10))),
                false,
            ),
            (
                "no sections, table offset past EOF",
                elf(&|e| (e.shnum, e.shoff) = (0, Some(0x10_0000))),
                false,
            ),
            // The tables the loader and the section walk read.
            ("class 3", elf(&|e| e.class = Some(3)), true),
            (
                "program header table past EOF",
                elf(&|e| e.phoff = Some(0x10_0000)),
                true,
            ),
            (
                "program header entry size wrong",
                elf(&|e| e.phentsize = Some(24)),
                true,
            ),
            ("129 program headers", elf(&|e| e.phnum = 129), true),
            (
                "section header table past EOF",
                elf(&|e| e.shoff = Some(0x10_0000)),
                true,
            ),
            (
                "section header entry size wrong",
                elf(&|e| e.shentsize = Some(sh - 8)),
                true,
            ),
            (
                "entry point outside every segment",
                elf(&|e| e.entry = Some(0x10)),
                true,
            ),
            (
                "entry point at the end of its segment",
                elf(&|e| (e.memsz, e.entry) = (Some(0x100), Some(0x40_0100))),
                true,
            ),
            (
                "cut inside the program headers",
                elf(&|e| e.len = Some(eh + 10)),
                true,
            ),
            (
                "cut inside the section headers",
                {
                    let b = elf(&|_| {});
                    b[..b.len() - 10].to_vec()
                },
                true,
            ),
        ] {
            cases.push((format!("{t}: {what}"), blob, want));
        }
        // EI_DATA other than 1 reads the file as big-endian.
        cases.push((format!("{t}: EI_DATA 0"), elf(&|e| e.data = Some(0)), !be));
    }
    check(
        cases
            .iter()
            .map(|(n, b, w)| (n.as_str(), b.clone(), *w))
            .collect(),
    );
}

// ------------------------------------------------------------------ Mach-O

/// A `__TEXT` segment with one section, then `LC_MAIN` (or `LC_UNIXTHREAD`).
fn macho(wide: bool, be: bool, cpu: Option<u32>, thread: bool) -> Vec<u8> {
    let w32 = |v: u32| if be { v.to_be_bytes() } else { v.to_le_bytes() };
    let w64 = |v: u64| if be { v.to_be_bytes() } else { v.to_le_bytes() };
    let mut seg = Vec::new();
    seg.extend(w32(if wide { 0x19 } else { 0x1 }));
    seg.extend(w32(if wide { 72 + 80 } else { 56 + 68 }));
    seg.extend(*b"__TEXT\0\0\0\0\0\0\0\0\0\0");
    if wide {
        for v in [0x1_0000_0000u64, 0x1000, 0, 0x1000] {
            seg.extend(w64(v));
        }
    } else {
        for v in [0x1000u32, 0x1000, 0, 0x1000] {
            seg.extend(w32(v));
        }
    }
    for v in [5u32, 5, 1, 0] {
        seg.extend(w32(v)); // maxprot, initprot, nsects, flags
    }
    seg.extend(*b"__text\0\0\0\0\0\0\0\0\0\0__TEXT\0\0\0\0\0\0\0\0\0\0");
    seg.resize(if wide { 72 + 80 } else { 56 + 68 }, 0);
    let mut cmd = Vec::new();
    if thread {
        cmd.extend(w32(0x5));
        cmd.extend(w32(16 + 64));
        cmd.extend(w32(1));
        cmd.extend(w32(16));
        cmd.resize(16 + 64, 0);
    } else {
        cmd.extend(w32(0x8000_0028));
        cmd.extend(w32(24));
        cmd.extend(w64(0x800));
        cmd.extend(w64(0));
    }
    let mut b = Vec::new();
    b.extend(w32(if wide { 0xfeed_facf } else { 0xfeed_face }));
    b.extend(w32(cpu.unwrap_or(if wide { 0x0100_0007 } else { 7 })));
    b.extend(w32(3));
    b.extend(w32(2));
    b.extend(w32(2));
    b.extend(w32((seg.len() + cmd.len()) as u32));
    b.extend(w32(0x85));
    if wide {
        b.extend(w32(0));
    }
    b.extend(seg);
    b.extend(cmd);
    b.resize(0x1000, 0);
    b[0x800] = 0xc3;
    b
}

#[test]
fn macho_rules() {
    let mut cases = Vec::new();
    for (wide, be) in [(true, false), (true, true), (false, false), (false, true)] {
        let t = format!(
            "Mach-O{}{}",
            if wide { 64 } else { 32 },
            if be { "BE" } else { "LE" }
        );
        let hs = if wide { 32 } else { 28 };
        let seg = if wide { 72 + 80 } else { 56 + 68 };
        let put = |b: &mut Vec<u8>, at: usize, v: u32| {
            b[at..at + 4].copy_from_slice(&if be { v.to_be_bytes() } else { v.to_le_bytes() })
        };
        let base = macho(wide, be, None, false);
        let with = |at: usize, v: u32| {
            let mut b = base.clone();
            put(&mut b, at, v);
            b
        };
        let i386 = macho(wide, be, Some(7), true);
        let x86_64 = macho(wide, be, Some(0x0100_0007), true);
        let ppc = macho(wide, be, Some(18), true);
        for (what, blob, want) in [
            ("base", base.clone(), false),
            ("header cut short", base[..20].to_vec(), false),
            ("sizeofcmds wrong", with(20, 0x10_0000), false),
            ("segment cmdsize 0", with(hs + 4, 0), false),
            ("segment cmdsize past EOF", with(hs + 4, 0x10000), false),
            (
                "x86_64 thread state cut short",
                x86_64[..hs + seg + 12].to_vec(),
                false,
            ),
            ("i386 thread state whole", i386.clone(), false),
            ("no load commands", with(16, 0), true),
            (
                "more load commands than the file holds",
                with(16, 1000),
                true,
            ),
            ("segment cut short", base[..hs + 30].to_vec(), true),
            (
                "nsects past EOF",
                with(hs + if wide { 64 } else { 48 }, 100_000),
                true,
            ),
            (
                "LC_MAIN cmdsize past EOF, then a command",
                {
                    let mut b = with(16, 3);
                    put(&mut b, hs + seg + 4, 0x10000);
                    b
                },
                true,
            ),
            (
                "i386 thread state cut short",
                i386[..hs + seg + 16 + 4].to_vec(),
                true,
            ),
            (
                "PPC thread state cut short",
                ppc[..hs + seg + 16 + 4].to_vec(),
                true,
            ),
        ] {
            cases.push((format!("{t}: {what}"), blob, want));
        }
    }
    check(
        cases
            .iter()
            .map(|(n, b, w)| (n.as_str(), b.clone(), *w))
            .collect(),
    );
}
