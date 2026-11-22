//! An ELF image written by the tests of the `elf` module, of either class and
//! byte order. It holds a `PT_LOAD` over the whole file, a `PT_DYNAMIC` with a
//! hash table and `DT_SYMTAB`, three dynamic symbols in a `SHT_DYNSYM` section
//! and a `.symtab` of two. The options change what the header or the tables
//! say.
#![allow(dead_code)]

/// Where the section header table is, for `Image::section_headers`.
#[derive(Clone, Copy, PartialEq)]
pub enum SectionHeaders {
    Present,
    /// `e_shoff` and `e_shnum` are 0.
    Absent,
    /// `e_shoff` is past the end of the file.
    PastEnd,
    /// `e_shoff` is past the end of the file and `e_shnum` is 0.
    PastEndNoCount,
}

pub struct Image {
    pub wide: bool,
    pub big: bool,
    pub osabi: u8,
    pub e_type: u16,
    pub machine: u16,
    pub entry: u64,
    /// The address of the start of the file, which the one `PT_LOAD` maps.
    pub base: u64,
    /// Added to the address of the sections that are loaded, so that a segment
    /// and a section do not hold the same addresses.
    pub section_shift: u64,
    pub dt_symtab: bool,
    /// The one bucket of the `DT_HASH` table. In a table of 64-bit words (as
    /// on s390x) a non-zero value would make the count of symbols huge.
    pub hash_bucket: u32,
    pub section_headers: SectionHeaders,
    pub e_phoff_zero: bool,
    pub e_phnum: Option<u16>,
    pub e_shnum: Option<u16>,
    pub e_shstrndx: u16,
    /// A second `PT_DYNAMIC`, over the first two entries only.
    pub second_dynamic: bool,
    /// A second `SHT_SYMTAB`, which holds the dynamic symbols.
    pub second_symtab: bool,
    /// An `sh_entsize` of 0 for the first `SHT_SYMTAB`.
    pub symtab_entsize_zero: bool,
    /// A section of type 0x80000000, a dynamic entry of tag 0x80000000 (before
    /// the end) and a segment of type 0x80000001.
    pub high_types: bool,
    /// A `SHT_NOBITS` section of 16 bytes at the address of the file offset
    /// 0x40 (with the shift of the sections).
    pub nobits: bool,
}

impl Image {
    pub fn new(wide: bool, big: bool) -> Image {
        Image {
            wide,
            big,
            osabi: 0,
            e_type: 3,
            machine: 62,
            entry: 0,
            base: 0x1000,
            section_shift: 0,
            dt_symtab: true,
            hash_bucket: 0,
            section_headers: SectionHeaders::Present,
            e_phoff_zero: false,
            e_phnum: None,
            e_shnum: None,
            e_shstrndx: 5,
            second_dynamic: false,
            second_symtab: false,
            symtab_entsize_zero: false,
            high_types: false,
            nobits: false,
        }
    }

    /// The virtual address of the file offset `off`.
    pub fn va(&self, off: usize) -> u64 {
        self.base + off as u64
    }

    pub fn bytes(&self) -> Vec<u8> {
        self.build().0
    }

    /// The image, and where its tables are.
    pub fn build(&self) -> (Vec<u8>, Layout) {
        let new = || Writer {
            big: self.big,
            wide: self.wide,
            bytes: Vec::new(),
        };
        let (e, p, sh, d) = if self.wide {
            (64, 56, 64, 16)
        } else {
            (52, 32, 40, 8)
        };
        // A symbol of `[name, value, size, info, other, shndx]`.
        let sym = |w: &mut Writer, [name, value, size, info, other, shndx]: [u64; 6]| {
            w.u32(name);
            if self.wide {
                w.bytes.extend([info as u8, other as u8]);
                w.u16(shndx);
                w.words(&[value, size]);
            } else {
                w.words(&[value, size]);
                w.bytes.extend([info as u8, other as u8]);
                w.u16(shndx);
            }
        };
        let dynstr = b"\0alpha\0beta\0gamma\0";
        let strtab = b"\0main\0";
        let shstrtab = b"\0.dynsym\0.dynstr\0.symtab\0.strtab\0.shstrtab\0.high\0.symtab2\0";
        let mut dynsym = new();
        sym(&mut dynsym, [0, 0, 0, 0, 0, 0]);
        sym(&mut dynsym, [1, 0x1234, 8, 0x12, 1, 5]);
        sym(&mut dynsym, [7, 0x20, 4, 0x21, 3, 0xfff1]);
        // The high bits of `st_other` are not the visibility.
        sym(&mut dynsym, [12, 0, 0, 0x10, 0xfe, 0]);
        let mut symtab = new();
        sym(&mut symtab, [0, 0, 0, 0, 0, 0]);
        sym(&mut symtab, [1, 0x1000, 16, 0x12, 0, 1]);
        // One bucket, four chain entries.
        let mut hash = new();
        hash.u32s(&[1, 4, u64::from(self.hash_bucket), 0, 0, 0, 0]);

        let n_ph = 2 + usize::from(self.second_dynamic) + usize::from(self.high_types);
        let n_dyn = 3 + usize::from(self.dt_symtab) + usize::from(self.high_types) + 2;
        let mut at = e + n_ph * p;
        let mut place = |len: usize| {
            at += len;
            at - len
        };
        let off_dynstr = place(dynstr.len());
        let off_dynsym = place(dynsym.bytes.len());
        let off_hash = place(hash.bytes.len());
        let off_dyn = place(n_dyn * d);
        let off_symtab = place(symtab.bytes.len());
        let off_strtab = place(strtab.len());
        let off_shstr = place(shstrtab.len());
        let off_sh = place(0);
        let n_sh = 6
            + usize::from(self.high_types)
            + usize::from(self.second_symtab)
            + usize::from(self.nobits);
        let total = off_sh + n_sh * sh;
        let layout = Layout {
            dynsym: off_dynsym,
            dynstr: off_dynstr,
            symtab: off_symtab,
            total,
        };

        let (shoff, shnum) = match self.section_headers {
            SectionHeaders::Present => (off_sh, n_sh),
            SectionHeaders::Absent => (0, 0),
            SectionHeaders::PastEnd => (total + 8, n_sh),
            SectionHeaders::PastEndNoCount => (total + 8, 0),
        };
        let mut out = new();
        out.bytes.extend(b"\x7fELF");
        out.bytes.extend([
            if self.wide { 2 } else { 1 },
            if self.big { 2 } else { 1 },
            1,
            self.osabi,
        ]);
        out.bytes.resize(16, 0);
        out.u16(u64::from(self.e_type));
        out.u16(u64::from(self.machine));
        out.u32(1);
        out.words(&[
            self.entry,
            if self.e_phoff_zero { 0 } else { e as u64 },
            shoff as u64,
        ]);
        out.u32(0);
        let phnum = self.e_phnum.map_or(n_ph as u64, u64::from);
        let shnum = self.e_shnum.map_or(shnum as u64, u64::from);
        for v in [e as u64, p as u64, phnum, sh as u64, shnum] {
            out.u16(v);
        }
        out.u16(u64::from(self.e_shstrndx));

        let phdr = |out: &mut Writer, kind: u64, flags: u64, off: usize, size: usize| {
            out.u32(kind);
            if self.wide {
                out.u32(flags);
            }
            let va = self.va(off);
            out.words(&[off as u64, va, va, size as u64, size as u64]);
            if !self.wide {
                out.u32(flags);
            }
            out.word(8);
        };
        phdr(&mut out, 1, 5, 0, total);
        phdr(&mut out, 2, 6, off_dyn, n_dyn * d);
        if self.second_dynamic {
            phdr(&mut out, 2, 6, off_dyn, 2 * d);
        }
        if self.high_types {
            phdr(&mut out, 0x8000_0001, 4, off_dyn, d);
        }
        out.bytes.extend(dynstr);
        out.bytes.extend(&dynsym.bytes);
        out.bytes.extend(&hash.bytes);
        let mut dynamic = vec![
            (4, self.va(off_hash)),
            (5, self.va(off_dynstr)),
            (10, dynstr.len() as u64),
        ];
        if self.dt_symtab {
            dynamic.push((6, self.va(off_dynsym)));
        }
        if self.high_types {
            dynamic.push((0x8000_0000, 9));
        }
        // The end, and an entry after it.
        dynamic.push((0, 0));
        dynamic.push((1, 7));
        for (tag, val) in dynamic {
            out.words(&[tag, val]);
        }
        out.bytes.extend(&symtab.bytes);
        out.bytes.extend(strtab);
        out.bytes.extend(shstrtab);
        // A section header of `[name, type, flags, offset, size, link, entsize]`;
        // a section with the flag 2 is loaded.
        let shdr = |out: &mut Writer, [name, kind, flags, at, size, link, entsize]: [u64; 7]| {
            let addr = if flags == 2 {
                self.va(at as usize) + self.section_shift
            } else {
                0
            };
            out.u32s(&[name, kind]);
            out.words(&[flags, addr, at, size]);
            out.u32s(&[link, 0]);
            out.words(&[8, entsize]);
        };
        let symbol = if self.wide { 24 } else { 16 };
        let entsize = if self.symtab_entsize_zero { 0 } else { symbol };
        let (dynsym_len, symtab_len) = (dynsym.bytes.len() as u64, symtab.bytes.len() as u64);
        let (dynsym_at, dynstr_at, symtab_at) =
            (off_dynsym as u64, off_dynstr as u64, off_symtab as u64);
        shdr(&mut out, [0, 0, 0, 0, 0, 0, 0]);
        shdr(&mut out, [1, 11, 2, dynsym_at, dynsym_len, 2, symbol]);
        shdr(&mut out, [9, 3, 2, dynstr_at, dynstr.len() as u64, 0, 0]);
        shdr(&mut out, [17, 2, 0, symtab_at, symtab_len, 4, entsize]);
        let (strtab_at, shstr_at) = (off_strtab as u64, off_shstr as u64);
        let (strtab_len, shstr_len) = (strtab.len() as u64, shstrtab.len() as u64);
        shdr(&mut out, [25, 3, 0, strtab_at, strtab_len, 0, 0]);
        shdr(&mut out, [33, 3, 0, shstr_at, shstr_len, 0, 0]);
        if self.high_types {
            shdr(&mut out, [43, 0x8000_0000, 0, 0, 0, 0, 0]);
        }
        if self.second_symtab {
            shdr(&mut out, [49, 2, 0, dynsym_at, dynsym_len, 2, symbol]);
        }
        if self.nobits {
            shdr(&mut out, [43, 8, 2, 0x40, 16, 0, 0]);
        }
        assert_eq!(out.bytes.len(), total);
        (out.bytes, layout)
    }
}

/// A symbol of a table written by [`symbol_elf`].
pub struct Sym {
    pub name: Vec<u8>,
    pub info: u8,
    pub other: u8,
    pub shndx: u16,
}

impl Sym {
    /// A symbol with every field given.
    pub fn new(name: &[u8], info: u8, other: u8, shndx: u16) -> Sym {
        Sym {
            name: name.to_vec(),
            info,
            other,
            shndx,
        }
    }

    /// A global function of default visibility the file does not define.
    pub fn import(name: &str) -> Sym {
        Sym::new(name.as_bytes(), 0x12, 0, 0)
    }

    /// A global function of default visibility the file defines.
    pub fn func(name: &str) -> Sym {
        Sym::new(name.as_bytes(), 0x12, 0, 1)
    }
}

/// A 64-bit little-endian ELF whose only content is a `SHT_DYNSYM` section
/// and a `SHT_SYMTAB` section, each with the null symbol first and then
/// `symbols`; a table that is `None` has no section.
pub fn symbol_elf(dynsym: Option<&[Sym]>, symtab: Option<&[Sym]>) -> Vec<u8> {
    let mut body = Vec::new();
    // `(name offset, type, offset, size, link)` of each section after the null one.
    let mut sections: Vec<(u32, u32, usize, usize, u32)> = Vec::new();
    let mut shstrtab = b"\0".to_vec();
    let mut name = |s: &[u8]| {
        shstrtab.extend(s);
        shstrtab.push(0);
        (shstrtab.len() - s.len() - 1) as u32
    };
    for (kind, table, names) in [
        (11, dynsym, (".dynsym", ".dynstr")),
        (2, symtab, (".symtab", ".strtab")),
    ] {
        let Some(table) = table else { continue };
        let mut strings = vec![0u8];
        let mut records = vec![0u8; 24];
        for s in table {
            records.extend((strings.len() as u32).to_le_bytes());
            records.extend([s.info, s.other]);
            records.extend(s.shndx.to_le_bytes());
            records.extend([0u8; 16]);
            strings.extend(&s.name);
            strings.push(0);
        }
        let link = sections.len() as u32 + 2;
        sections.push((
            name(names.0.as_bytes()),
            kind,
            64 + body.len(),
            records.len(),
            link,
        ));
        body.extend(&records);
        sections.push((
            name(names.1.as_bytes()),
            3,
            64 + body.len(),
            strings.len(),
            0,
        ));
        body.extend(&strings);
    }
    let shstr_name = name(b".shstrtab");
    sections.push((shstr_name, 3, 64 + body.len(), shstrtab.len(), 0));
    body.extend(&shstrtab);

    let shoff = 64 + body.len();
    let shnum = sections.len() + 1;
    let mut out = b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0".to_vec();
    out.extend(3u16.to_le_bytes()); // ET_DYN
    out.extend(62u16.to_le_bytes()); // EM_X86_64
    out.extend(1u32.to_le_bytes());
    out.extend([0u8; 8]); // e_entry
    out.extend([0u8; 8]); // e_phoff
    out.extend((shoff as u64).to_le_bytes());
    out.extend(0u32.to_le_bytes());
    for v in [64u16, 56, 0, 64, shnum as u16, shnum as u16 - 1] {
        out.extend(v.to_le_bytes());
    }
    out.extend(&body);
    out.extend([0u8; 64]);
    for (name, kind, offset, size, link) in sections {
        out.extend(name.to_le_bytes());
        out.extend(kind.to_le_bytes());
        out.extend([0u8; 16]); // flags, address
        out.extend((offset as u64).to_le_bytes());
        out.extend((size as u64).to_le_bytes());
        out.extend(link.to_le_bytes());
        out.extend(0u32.to_le_bytes());
        out.extend(8u64.to_le_bytes());
        out.extend(24u64.to_le_bytes());
    }
    out
}

/// Every constant of the `elf` module of yara-x, with its value.
pub const CONSTANTS: &[(&str, i64)] = &[
    ("ET_NONE", 0),
    ("ET_REL", 1),
    ("ET_EXEC", 2),
    ("ET_DYN", 3),
    ("ET_CORE", 4),
    ("ET_LOPROC", 0xff00),
    ("ET_HIPROC", 255),
    ("EM_NONE", 0),
    ("EM_M32", 1),
    ("EM_SPARC", 2),
    ("EM_386", 3),
    ("EM_68K", 4),
    ("EM_88K", 5),
    ("EM_IAMCU", 6),
    ("EM_860", 7),
    ("EM_MIPS", 8),
    ("EM_S370", 9),
    ("EM_MIPS_RS3_LE", 10),
    ("EM_PARISC", 15),
    ("EM_SPARC32PLUS", 18),
    ("EM_PPC", 20),
    ("EM_PPC64", 21),
    ("EM_S390", 22),
    ("EM_MCORE", 39),
    ("EM_RCE", 39),
    ("EM_ARM", 40),
    ("EM_SH", 42),
    ("EM_SPARCV9", 43),
    ("EM_X86_64", 62),
    ("EM_ARC_COMPACT", 93),
    ("EM_AARCH64", 183),
    ("EM_BPF", 247),
    ("EM_LOONGARCH", 0x102),
    ("OSABI_NONE", 0),
    ("OSABI_HPUX", 1),
    ("OSABI_NETBSD", 2),
    ("OSABI_LINUX", 3),
    ("OSABI_GNU_HURD", 4),
    ("OSABI_SOLARIS", 6),
    ("OSABI_AIX", 7),
    ("OSABI_IRIX", 8),
    ("OSABI_FREE_BSD", 9),
    ("OSABI_TRU64", 10),
    ("OSABI_MODESTO", 11),
    ("OSABI_OPENBSD", 12),
    ("OSABI_OPENVMS", 13),
    ("OSABI_NSK", 14),
    ("OSABI_AROS", 15),
    ("OSABI_FENIXOS", 16),
    ("OSABI_CLOUDABI", 17),
    ("OSABI_OPENVOS", 18),
    ("OSABI_ARM_AEABI", 64),
    ("OSABI_ARM", 97),
    ("OSABI_STANDALONE", 255),
    ("SHT_NULL", 0),
    ("SHT_PROGBITS", 1),
    ("SHT_SYMTAB", 2),
    ("SHT_STRTAB", 3),
    ("SHT_RELA", 4),
    ("SHT_HASH", 5),
    ("SHT_DYNAMIC", 6),
    ("SHT_NOTE", 7),
    ("SHT_NOBITS", 8),
    ("SHT_REL", 9),
    ("SHT_SHLIB", 10),
    ("SHT_DYNSYM", 11),
    ("SHT_INIT_ARRAY", 14),
    ("SHT_FINI_ARRAY", 15),
    ("PT_NULL", 0),
    ("PT_LOAD", 1),
    ("PT_DYNAMIC", 2),
    ("PT_INTERP", 3),
    ("PT_NOTE", 4),
    ("PT_SHLIB", 5),
    ("PT_PHDR", 6),
    ("PT_TLS", 7),
    ("PT_GNU_EH_FRAME", 0x6474e550),
    ("PT_GNU_STACK", 0x6474e551),
    ("PT_GNU_RELRO", 0x6474e552),
    ("PT_GNU_PROPERTY", 0x6474e553),
    ("PF_X", 1),
    ("PF_W", 2),
    ("PF_R", 4),
    ("STT_NOTYPE", 0),
    ("STT_OBJECT", 1),
    ("STT_FUNC", 2),
    ("STT_SECTION", 3),
    ("STT_FILE", 4),
    ("STT_COMMON", 5),
    ("STT_TLS", 6),
    ("STB_LOCAL", 0),
    ("STB_GLOBAL", 1),
    ("STB_WEAK", 2),
    ("STV_DEFAULT", 0),
    ("STV_INTERNAL", 1),
    ("STV_HIDDEN", 2),
    ("STV_PROTECTED", 3),
    ("DT_NULL", 0),
    ("DT_NEEDED", 1),
    ("DT_PLTRELSZ", 2),
    ("DT_PLTGOT", 3),
    ("DT_HASH", 4),
    ("DT_STRTAB", 5),
    ("DT_SYMTAB", 6),
    ("DT_RELA", 7),
    ("DT_RELASZ", 8),
    ("DT_RELAENT", 9),
    ("DT_STRSZ", 10),
    ("DT_SYMENT", 11),
    ("DT_INIT", 12),
    ("DT_FINI", 13),
    ("DT_SONAME", 14),
    ("DT_RPATH", 15),
    ("DT_SYMBOLIC", 16),
    ("DT_REL", 17),
    ("DT_RELSZ", 18),
    ("DT_RELENT", 19),
    ("DT_PLTREL", 20),
    ("DT_DEBUG", 21),
    ("DT_TEXTREL", 22),
    ("DT_JMPREL", 23),
    ("DT_BIND_NOW", 24),
    ("DT_INIT_ARRAY", 25),
    ("DT_FINI_ARRAY", 26),
    ("DT_INIT_ARRAYSZ", 27),
    ("DT_FINI_ARRAYSZ", 28),
    ("DT_RUNPATH", 29),
    ("DT_FLAGS", 30),
    ("DT_ENCODING", 32),
    ("DT_LOOS", 0x6000000d),
    ("DT_HIOS", 0x6ffff000),
    ("DT_VALRNGLO", 0x6ffffd00),
    ("DT_VALRNGHI", 0x6ffffdff),
    ("DT_ADDRRNGLO", 0x6ffffe00),
    ("DT_ADDRRNGHI", 0x6ffffeff),
    ("DT_VERSYM", 0x6ffffff0),
    ("DT_RELACOUNT", 0x6ffffff9),
    ("DT_RELCOUNT", 0x6ffffffa),
    ("DT_FLAGS_1", 0x6ffffffb),
    ("DT_VERDEF", 0x6ffffffc),
    ("DT_VERDEFNUM", 0x6ffffffd),
    ("DT_VERNEED", 0x6ffffffe),
    ("DT_VERNEEDNUM", 0x6fffffff),
    ("DT_LOPROC", 0x70000000),
    ("DT_HIPROC", 0x7fffffff),
];

/// File offsets of the tables of an image.
pub struct Layout {
    pub dynsym: usize,
    pub dynstr: usize,
    pub symtab: usize,
    pub total: usize,
}

/// Numbers of an image, in its byte order and class.
struct Writer {
    big: bool,
    wide: bool,
    bytes: Vec<u8>,
}

impl Writer {
    fn num(&mut self, size: usize, v: u64) {
        if self.big {
            self.bytes.extend(&v.to_be_bytes()[8 - size..]);
        } else {
            self.bytes.extend(&v.to_le_bytes()[..size]);
        }
    }

    fn u16(&mut self, v: u64) {
        self.num(2, v);
    }

    fn u32(&mut self, v: u64) {
        self.num(4, v);
    }

    fn u32s(&mut self, vs: &[u64]) {
        vs.iter().for_each(|&v| self.u32(v));
    }

    /// An address, an offset or a size: 8 bytes in a 64-bit file, else 4.
    fn word(&mut self, v: u64) {
        self.num(if self.wide { 8 } else { 4 }, v);
    }

    fn words(&mut self, vs: &[u64]) {
        vs.iter().for_each(|&v| self.word(v));
    }
}
