//! PE structural analysis: per-section entropy, packer/high-entropy
//! detection, suspicious-import heuristics, and imphash. Requires the
//! whole (bounded) file in memory, so it runs only on objects within the
//! deep-analysis size cap.

use goblin::pe::PE;
use md5::{Digest, Md5};

use crate::byte_source::ByteSource;
use crate::hexsig::encode_hex;

/// A PE's headers and section table, read without its data directories.
///
/// What signatures, section hashes, icons and bytecode read, and bounded: the
/// section headers must fit in the file. A full parse also walks imports,
/// exports, resources and the certificate table, and refuses the whole file
/// over one malformed entry in any of them (a certificate table sized past
/// the end of the file, say); its permissive mode instead keeps going through
/// them, and a malformed import table took it to gigabytes.
pub(crate) struct Headers<'a> {
    pub header: goblin::pe::header::Header<'a>,
    pub sections: Vec<goblin::pe::section_table::SectionTable>,
}

/// [`Headers`] of `data`, `None` if they do not parse.
pub(crate) fn headers(data: &[u8]) -> Option<Headers<'_>> {
    use goblin::pe::header::{Header, SIZEOF_COFF_HEADER, SIZEOF_PE_MAGIC};
    let header = Header::parse(data).ok()?;
    let mut at = (header.dos_header.pe_pointer as usize)
        .checked_add(SIZEOF_PE_MAGIC + SIZEOF_COFF_HEADER)?
        .checked_add(usize::from(header.coff_header.size_of_optional_header))?;
    let sections = header.coff_header.sections(data, &mut at).ok()?;
    Some(Headers { header, sections })
}

/// Structural facts extracted from a PE file.
pub struct PeInfo {
    pub is_64: bool,
    pub section_count: usize,
    /// (name, entropy) per section, entropy in bits/byte 0..=8.
    pub sections: Vec<(String, f64)>,
    /// Max section entropy (packing indicator).
    pub max_entropy: f64,
    /// Mandiant-style import hash (md5 of ordered "dll.func"), or empty.
    pub imphash: String,
    pub import_count: usize,
    /// Names of imports considered security-relevant.
    pub suspicious_imports: Vec<String>,
}

/// Imports frequently abused by malware (injection, download-exec, etc.).
const SUSPICIOUS: &[&str] = &[
    "virtualalloc",
    "virtualallocex",
    "virtualprotect",
    "writeprocessmemory",
    "readprocessmemory",
    "createremotethread",
    "createremotethreadex",
    "ntunmapviewofsection",
    "queueuserapc",
    "setthreadcontext",
    "getthreadcontext",
    "loadlibrarya",
    "loadlibraryw",
    "getprocaddress",
    "winexec",
    "shellexecutea",
    "shellexecutew",
    "createprocessa",
    "createprocessw",
    "urldownloadtofilea",
    "urldownloadtofilew",
    "internetopenurla",
    "wininet",
    "cryptencrypt",
    "cryptdecrypt",
    "isdebuggerpresent",
    "checkremotedebuggerpresent",
];

/// Parse a PE and extract structural features. Returns `None` if the bytes
/// are not a parseable PE.
pub fn analyze(data: &[u8]) -> Option<PeInfo> {
    let pe = PE::parse(data).ok()?;

    let mut sections = Vec::with_capacity(pe.sections.len());
    let mut max_entropy = 0.0f64;
    for s in &pe.sections {
        let name = s.name().map(|n| n.to_string()).unwrap_or_else(|_| {
            s.real_name
                .clone()
                .unwrap_or_else(|| "<unnamed>".to_string())
        });
        let start = s.pointer_to_raw_data as usize;
        let len = s.size_of_raw_data as usize;
        let entropy = match data.get(start..start.saturating_add(len)) {
            Some(slice) if !slice.is_empty() => shannon_entropy(slice),
            _ => 0.0,
        };
        if entropy > max_entropy {
            max_entropy = entropy;
        }
        sections.push((name, entropy));
    }

    // imphash: md5 of comma-joined lowercase "dll_without_ext.func" in
    // import-table order (Mandiant definition).
    let mut imp_parts: Vec<String> = Vec::new();
    let mut suspicious = Vec::new();
    for imp in &pe.imports {
        let dll = imp
            .dll
            .rsplit_once('.')
            .map(|(stem, _)| stem)
            .unwrap_or(imp.dll)
            .to_ascii_lowercase();
        // Imports by ordinal contribute "dll.ord<n>" (the imphash/Mandiant
        // convention), not the function name; goblin renders an ordinal
        // import's name as "ORDINAL <n>". Dropping these (or hashing the
        // rendered string) would change the imphash and miss `.imp` sigs.
        if imp.name.starts_with("ORDINAL ") {
            imp_parts.push(format!("{dll}.ord{}", imp.ordinal));
            continue;
        }
        let func = imp.name.to_ascii_lowercase();
        if !func.is_empty() {
            imp_parts.push(format!("{dll}.{func}"));
            if SUSPICIOUS.contains(&func.as_str()) {
                suspicious.push(imp.name.to_string());
            }
        }
    }
    let imphash = if imp_parts.is_empty() {
        String::new()
    } else {
        encode_hex(&Md5::digest(imp_parts.join(",").as_bytes()))
    };

    Some(PeInfo {
        is_64: pe.is_64,
        section_count: pe.sections.len(),
        max_entropy,
        sections,
        imphash,
        import_count: pe.imports.len(),
        suspicious_imports: suspicious,
    })
}

/// Shannon entropy (bits per byte) of a buffer.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    entropy_of_counts(&counts, data.len())
}

/// [`shannon_entropy`] of `len` bytes, from how many times each value occurs.
pub(crate) fn entropy_of_counts(counts: &[u64; 256], len: usize) -> f64 {
    if len == 0 {
        return 0.0;
    }
    let len = len as f64;
    let mut h = 0.0f64;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}

impl PeInfo {
    /// True if any section's entropy suggests packing/encryption.
    pub fn looks_packed(&self) -> bool {
        self.max_entropy >= 7.2
    }
}

/// PE layout needed to resolve `EP`/section-relative signature offsets.
#[derive(Debug, Clone, Default)]
pub struct PeLayout {
    /// File offset of the entry point (translated from its RVA), if known.
    pub entry: Option<u64>,
    /// File offset (PointerToRawData) of each section, in order.
    pub section_rawptrs: Vec<u64>,
    /// SizeOfRawData of each section, in the same order: the section's extent
    /// in *file* space, which is what an `SEn:` offset is measured against.
    pub section_rawsizes: Vec<u64>,
    /// File offsets of the `VS_VERSION_INFO` string keys, the anchor set a
    /// `VI:` offset matches against. Empty for a PE with no version resource.
    pub version_info: Vec<u64>,
}

/// Whether a file that *claims* to be an executable describes a layout no
/// loader could map: ClamAV's `Heuristics.Broken.Executable`, reported under
/// `--alert-broken`.
///
/// The signal is the contradiction: something typed as a PE, ELF or Mach-O by
/// its magic, whose headers then do not hold together. Only the headers a
/// loader reads to map the image are judged. What they point at (imports,
/// resources, debug data, signatures, section names) is malformed routinely in
/// software that runs, and a full parse that fails on any of it made this the
/// largest false-positive class exav had: DLLs with a non-UTF-8 export name,
/// resource directories pointing nowhere, Android libraries with junk section
/// headers.
///
/// Each condition was measured against clamscan 1.5.4 on headers mutated one
/// field at a time; see `tests/suites/broken_executable.rs`.
///
/// Deliberately narrow: it only answers for input that already carries an
/// executable magic, so an arbitrary file can never be "a broken executable".
pub fn looks_broken(data: &[u8]) -> bool {
    looks_broken_in(&data)
}

/// [`looks_broken`] over an object that need not be held in memory.
pub(crate) fn looks_broken_in(src: &dyn ByteSource) -> bool {
    let head = src.window(0, 4);
    if head.starts_with(b"MZ") {
        pe_broken(src)
    } else if head.starts_with(b"\x7fELF") {
        elf_broken(src)
    } else {
        macho_broken(src)
    }
}

/// Header fields read through one cached window, so a walk over many small
/// records does not cost a read of the object per field.
struct Fields<'a> {
    src: &'a dyn ByteSource,
    at: usize,
    buf: std::borrow::Cow<'a, [u8]>,
    be: bool,
}

impl<'a> Fields<'a> {
    fn new(src: &'a dyn ByteSource) -> Self {
        Fields {
            src,
            at: 0,
            buf: std::borrow::Cow::Borrowed(&[]),
            be: false,
        }
    }

    /// `len` bytes at `off`, or `None` when the object ends first.
    fn get(&mut self, off: u64, len: usize) -> Option<&[u8]> {
        let off = usize::try_from(off).ok()?;
        let end = off.checked_add(len)?;
        if end > self.src.len() {
            return None;
        }
        if off < self.at || end > self.at + self.buf.len() {
            self.at = off;
            self.buf = self.src.window(off, len.max(64 * 1024));
        }
        self.buf.get(off - self.at..end - self.at)
    }

    fn u16(&mut self, off: u64) -> Option<u16> {
        let be = self.be;
        self.get(off, 2).map(|b| read_uint(b, be) as u16)
    }

    fn u32(&mut self, off: u64) -> Option<u32> {
        let be = self.be;
        self.get(off, 4).map(|b| read_uint(b, be) as u32)
    }

    /// A 4- or 8-byte field, by the file's class.
    fn word(&mut self, off: u64, wide: bool) -> Option<u64> {
        let be = self.be;
        self.get(off, if wide { 8 } else { 4 }).map(|b| read_uint(b, be))
    }
}

/// An unsigned integer of up to 8 bytes in the given byte order.
fn read_uint(b: &[u8], be: bool) -> u64 {
    let fold = |v: u64, &x: &u8| (v << 8) | u64::from(x);
    if be {
        b.iter().fold(0, fold)
    } else {
        b.iter().rev().fold(0, fold)
    }
}

/// `x` rounded up to a multiple of `a`, or `x` itself when `a` is 0.
fn round_up(x: u64, a: u64) -> u64 {
    if a == 0 {
        x
    } else {
        x.div_ceil(a) * a
    }
}

fn pe_broken(src: &dyn ByteSource) -> bool {
    let mut f = Fields::new(src);
    let n = src.len() as u64;
    // No PE header is a DOS program, and a COFF header cut short is too little
    // to judge: neither describes a layout.
    let Some(e) = f.u32(0x3c).map(u64::from) else {
        return false;
    };
    let Some(coff) = f.get(e, 24) else {
        return false;
    };
    if coff[..4] != *b"PE\0\0" {
        return false;
    }
    let nsec = u64::from(u16::from_le_bytes([coff[6], coff[7]]));
    let optsz = u64::from(u16::from_le_bytes([coff[20], coff[21]]));
    let opt = e + 24;
    // Any magic but PE32+ is read as PE32.
    let fixed = if f.u16(opt) == Some(0x20b) { 112 } else { 96 };
    if optsz < fixed {
        return true;
    }
    let Some(h) = f.get(opt, fixed as usize) else {
        return true;
    };
    let le32 = |at: usize| u64::from(u32::from_le_bytes([h[at], h[at + 1], h[at + 2], h[at + 3]]));
    let (entry, salign, falign, headers) = (le32(16), le32(32), le32(36), le32(60));
    let native = u16::from_le_bytes([h[68], h[69]]) == 1;
    let dirs = le32(fixed as usize - 4).min(16) * 8;
    if optsz < fixed + dirs {
        return true;
    }
    // The data directories cut short: incomplete rather than wrong.
    if opt + fixed + dirs > n {
        return false;
    }
    if nsec == 0 {
        return true;
    }
    // Drivers (the native subsystem) may use any alignment.
    let aligned = falign != 0 && falign % 0x200 == 0 && salign != 0 && salign % 0x1000 == 0;
    if salign == 0 || !(native || aligned) {
        return true;
    }
    let Some(table) = f.get(opt + optsz, (nsec * 40) as usize) else {
        return true;
    };
    // (VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData). A
    // section whose raw data starts at or past the end of the file is left out
    // of the layout, as though the table did not list it.
    let sections = || {
        table
            .as_chunks::<40>()
            .0
            .iter()
            .map(|s| {
                let at = |i: usize| u64::from(u32::from_le_bytes([s[i], s[i + 1], s[i + 2], s[i + 3]]));
                (at(8), at(12), at(16), at(20))
            })
            .filter(|&(_, _, raw_size, raw_ptr)| raw_size == 0 || raw_ptr < n)
    };
    let Some((_, first, _, _)) = sections().next() else {
        return true;
    };
    // Laid out in memory right after the headers, each section where the one
    // before it ends.
    if first != round_up(headers, salign) {
        return true;
    }
    let mut end = first;
    for (vsize, va, raw_size, _) in sections() {
        if va != end {
            return true;
        }
        end = va + round_up(if vsize != 0 { vsize } else { raw_size }, salign);
    }
    // The entry point has to land on bytes the file holds.
    if entry < first {
        return entry >= n;
    }
    let Some((_, va, _, raw_ptr)) = sections().find(|&(_, va, raw_size, _)| {
        entry >= va && entry - va < round_up(raw_size, falign)
    }) else {
        return true;
    };
    let raw_start = raw_ptr.checked_div(falign).map_or(raw_ptr, |q| q * falign);
    raw_start + (entry - va) >= n
}

fn elf_broken(src: &dyn ByteSource) -> bool {
    let mut f = Fields::new(src);
    let Some(ident) = f.get(0, 16) else {
        return false;
    };
    let wide = match ident[4] {
        1 => false,
        2 => true,
        _ => return true,
    };
    // Anything but little-endian is read as big-endian.
    f.be = ident[5] != 1;
    let (header, ph_size, sh_size) = if wide { (64, 56, 64) } else { (52, 32, 40) };
    // A header cut short is too little to judge.
    if f.get(0, header).is_none() {
        return false;
    }
    let w = if wide { 8 } else { 4 };
    let (Some(entry), Some(phoff), Some(shoff)) =
        (f.word(24, wide), f.word(24 + w, wide), f.word(24 + 2 * w, wide))
    else {
        return false;
    };
    let fields = 28 + 3 * w; // e_ehsize, then the table geometry
    let geometry = [2, 4, 6, 8].map(|i| f.u16(fields + i).map(u64::from));
    let [Some(ph_entsize), Some(phnum), Some(sh_entsize), Some(shnum)] = geometry else {
        return false;
    };
    if phnum > 0 {
        if phnum > 128 || ph_entsize != ph_size {
            return true;
        }
        if f.get(phoff, (phnum * ph_size) as usize).is_none() {
            return true;
        }
        // Inside some segment's memory image, whatever its type. 0 is no entry.
        let (vaddr_at, memsz_at) = if wide { (16, 40) } else { (8, 20) };
        let mapped = (0..phnum).any(|i| {
            let p = phoff + i * ph_size;
            let (Some(vaddr), Some(memsz)) = (f.word(p + vaddr_at, wide), f.word(p + memsz_at, wide)) else {
                return false;
            };
            entry >= vaddr && entry - vaddr < memsz
        });
        if entry != 0 && !mapped {
            return true;
        }
    }
    // A zero entry size is a stripped section table, which is reported under
    // its own name (see `elf_section_headers_stripped`).
    if sh_entsize == 0 {
        return false;
    }
    sh_entsize != sh_size || (shnum > 0 && f.get(shoff, (shnum * sh_size) as usize).is_none())
}

fn macho_broken(src: &dyn ByteSource) -> bool {
    let mut f = Fields::new(src);
    let n = src.len() as u64;
    // Thin images only: the universal ("fat") magic is a container, and a Java
    // class shares its bytes.
    let Some(magic) = f.get(0, 4) else {
        return false;
    };
    let (wide, be) = match magic {
        [0xCE, 0xFA, 0xED, 0xFE] => (false, false),
        [0xCF, 0xFA, 0xED, 0xFE] => (true, false),
        [0xFE, 0xED, 0xFA, 0xCE] => (false, true),
        [0xFE, 0xED, 0xFA, 0xCF] => (true, true),
        _ => return false,
    };
    f.be = be;
    let header: u64 = if wide { 32 } else { 28 };
    if n < header {
        return false;
    }
    let (Some(cpu), Some(ncmds)) = (f.u32(4), f.u32(16).map(u64::from)) else {
        return false;
    };
    // Every command moves the walk at least 8 bytes on, so more than the file
    // can hold is a read past its end. This also bounds the walk.
    if ncmds == 0 || ncmds * 8 > n - header {
        return true;
    }
    let (segment, segment_size, section_size) = if wide { (0x19, 72, 80) } else { (0x1, 56, 68) };
    // Thread state is read in full on these CPUs (i386, PowerPC, PowerPC 64),
    // and skipped on the others.
    let thread_state = match cpu {
        7 => Some(64),
        18 => Some(160),
        0x0100_0012 => Some(312),
        _ => None,
    };
    let mut at = header;
    for _ in 0..ncmds {
        let (Some(cmd), Some(size)) = (f.u32(at), f.u32(at + 4)) else {
            return true;
        };
        if cmd == segment {
            // A segment is read by its structure, whatever its cmdsize says.
            let Some(nsects) = f.u32(at + segment_size - 8) else {
                return true;
            };
            at += segment_size + u64::from(nsects) * section_size;
            if at > n {
                return true;
            }
            continue;
        }
        if matches!(cmd, 0x4 | 0x5) {
            // LC_THREAD, LC_UNIXTHREAD: flavor, count, then the registers.
            if thread_state.is_some_and(|len| at + 16 + len > n) {
                return true;
            }
        }
        at += u64::from(size).max(8);
    }
    false
}

/// Extract [`PeLayout`] from a PE. `None` if `data` is not a parseable PE.
pub fn layout(data: &[u8]) -> Option<PeLayout> {
    let pe = headers(data)?;
    let mut section_rawptrs = Vec::with_capacity(pe.sections.len());
    let mut section_rawsizes = Vec::with_capacity(pe.sections.len());
    let entry_rva = pe
        .header
        .optional_header
        .map_or(0, |o| u64::from(o.standard_fields.address_of_entry_point));
    let mut entry = None;
    for s in &pe.sections {
        let va = s.virtual_address as u64;
        let vsize = (s.virtual_size as u64).max(s.size_of_raw_data as u64);
        let ptr = s.pointer_to_raw_data as u64;
        section_rawptrs.push(ptr);
        section_rawsizes.push(s.size_of_raw_data as u64);
        if entry.is_none() && entry_rva >= va && entry_rva < va.saturating_add(vsize) {
            entry = Some(ptr + (entry_rva - va));
        }
    }
    Some(PeLayout {
        entry,
        section_rawptrs,
        section_rawsizes,
        version_info: crate::icon::version_info_anchors(data),
    })
}

/// One PE section in the shape the bytecode PE APIs expect
/// (`cli_exe_section`).
///
/// The name and layout are the interface a `.cbc` program is compiled against,
/// so an interpreter has to match them exactly. Both are established the same
/// way as the rest of that ABI here: from the field accesses real programs
/// make, not from any engine source.
#[derive(Debug, Clone, Copy, Default)]
pub struct BcPeSection {
    pub rva: u32,
    pub vsz: u32,
    pub raw: u32,
    pub rsz: u32,
    pub chr: u32,
}

/// PE header/section info needed by the bytecode `get_pe_section` and
/// `pe_rawaddr` APIs.
#[derive(Debug, Clone, Default)]
pub struct BcPe {
    pub sections: Vec<BcPeSection>,
    /// `SizeOfHeaders`: RVAs below this map directly to file offsets.
    pub hdr_size: u32,
    /// Byte image of `cli_pe_hook_data` (the `__clambc_pedata` global).
    pub pedata: Vec<u8>,
}

/// Size of the `cli_pe_hook_data` struct image (the bytecode-compiler view,
/// with both opt32/opt64 headers and their data directories inlined).
///
/// Fixed by the ABI rather than chosen: a program reads its fields at compiled
/// offsets, so the image has to be exactly this long. Derived from the accesses
/// real programs make, as with the rest of the layout.
const PEDATA_SIZE: usize = 648;

impl BcPe {
    /// Translate an RVA to a raw file offset.
    /// `None` if the RVA falls outside the header and every section.
    pub fn rawaddr(&self, rva: u32, file_size: usize) -> Option<u32> {
        if rva < self.hdr_size {
            return if (rva as usize) >= file_size {
                None
            } else {
                Some(rva)
            };
        }
        for s in self.sections.iter().rev() {
            if s.rsz != 0 && s.rva <= rva && s.rsz > rva - s.rva {
                return Some((rva - s.rva) + s.raw);
            }
        }
        None
    }
}

/// Extract [`BcPe`] from a PE image. `None` if `data` is not a parseable PE.
pub fn bytecode_pe(data: &[u8]) -> Option<BcPe> {
    let pe = headers(data)?;
    let hdr_size = pe
        .header
        .optional_header
        .map(|o| o.windows_fields.size_of_headers)
        .unwrap_or(0);
    let sections: Vec<BcPeSection> = pe
        .sections
        .iter()
        .map(|s| BcPeSection {
            rva: s.virtual_address,
            vsz: s.virtual_size,
            raw: s.pointer_to_raw_data,
            rsz: s.size_of_raw_data,
            chr: s.characteristics,
        })
        .collect();
    let mut bc = BcPe {
        sections,
        hdr_size,
        pedata: Vec::new(),
    };
    bc.pedata = build_pedata(&pe.header, &bc, data.len());
    Some(bc)
}

/// Build the `cli_pe_hook_data` byte image the way the bytecode compiler lays
/// it out (offsets verified against the field accesses real programs make).
fn build_pedata(header: &goblin::pe::header::Header, bc: &BcPe, file_size: usize) -> Vec<u8> {
    let mut b = vec![0u8; PEDATA_SIZE];
    let put16 =
        |b: &mut [u8], off: usize, v: u16| b[off..off + 2].copy_from_slice(&v.to_le_bytes());
    let put32 =
        |b: &mut [u8], off: usize, v: u32| b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    let put64 =
        |b: &mut [u8], off: usize, v: u64| b[off..off + 8].copy_from_slice(&v.to_le_bytes());

    let coff = &header.coff_header;
    let e_lfanew = header.dos_header.pe_pointer;
    put32(&mut b, 0, e_lfanew); // offset
    put16(&mut b, 8, coff.number_of_sections); // nsections

    // file_hdr @12: Magic "PE\0\0", then the COFF header fields.
    b[12..16].copy_from_slice(b"PE\0\0");
    put16(&mut b, 16, coff.machine);
    put16(&mut b, 18, coff.number_of_sections);
    put32(&mut b, 20, coff.time_date_stamp);
    put32(&mut b, 24, coff.pointer_to_symbol_table);
    put32(&mut b, 28, coff.number_of_symbol_table);
    put16(&mut b, 32, coff.size_of_optional_header);
    put16(&mut b, 34, coff.characteristics);

    if let Some(oh) = header.optional_header {
        let s = &oh.standard_fields;
        let w = &oh.windows_fields;
        let ep = s.address_of_entry_point;
        put32(&mut b, 4, bc.rawaddr(ep, file_size).unwrap_or(0)); // ep as file offset
                                                                  // The compiler's struct inlines DataDirectory[16] into each opt header,
                                                                  // so opt32 spans 36..260 and opt64 spans 264..504.
        if s.magic == 0x20b {
            let base = 264;
            put16(&mut b, base, s.magic);
            put32(&mut b, base + 16, ep);
            put64(&mut b, base + 24, w.image_base);
            put32(&mut b, base + 32, w.section_alignment);
            put32(&mut b, base + 36, w.file_alignment);
            put32(&mut b, base + 56, w.size_of_image);
            put32(&mut b, base + 60, w.size_of_headers);
            put16(&mut b, base + 68, w.subsystem);
            put32(&mut b, base + 108, w.number_of_rva_and_sizes);
            put_dirs(&mut b, 376, &oh); // opt64 data dirs
        } else {
            let base = 36;
            put16(&mut b, base, s.magic);
            put32(&mut b, base + 16, ep);
            put32(&mut b, base + 28, w.image_base as u32);
            put32(&mut b, base + 32, w.section_alignment);
            put32(&mut b, base + 36, w.file_alignment);
            put32(&mut b, base + 56, w.size_of_image);
            put32(&mut b, base + 60, w.size_of_headers);
            put16(&mut b, base + 68, w.subsystem);
            put32(&mut b, base + 92, w.number_of_rva_and_sizes);
            put_dirs(&mut b, 132, &oh); // opt32 data dirs
        }
        put_dirs(&mut b, 504, &oh); // merged dirs[16]
    }

    put32(&mut b, 632, e_lfanew); // e_lfanew
    put32(&mut b, 644, bc.hdr_size); // hdr_size
    b
}

/// The raw array, not `dirs()`: that skips absent entries, so enumerating it
/// shifts the slots, and it panics on the reserved 16th entry.
fn put_dirs(b: &mut [u8], base: usize, oh: &goblin::pe::optional_header::OptionalHeader) {
    for (i, dd) in oh.data_directories.data_directories.iter().enumerate().take(16) {
        let Some((_, dd)) = dd else { continue };
        let off = base + i * 8;
        b[off..off + 4].copy_from_slice(&dd.virtual_address.to_le_bytes());
        b[off + 4..off + 8].copy_from_slice(&dd.size.to_le_bytes());
    }
}

/// Maximum embedded PE images to carve from one buffer (bounds work on inputs
/// crafted with many `MZ` markers).
const MAX_EMBEDDED_PE: usize = 16;

/// Most archive candidates carved from one buffer.
const MAX_EMBEDDED_ARCHIVES: usize = 32;

/// What carving finds embedded at a non-zero offset in an object: validated
/// PE, ELF and Mach-O images, and archive candidates found by their magic, each
/// in ascending order and within its cap.
#[derive(Default)]
pub(crate) struct Embedded {
    pub(crate) pe: Vec<usize>,
    pub(crate) elf: Vec<usize>,
    pub(crate) macho: Vec<usize>,
    pub(crate) archives: Vec<usize>,
}

/// The magics carving looks for, and what each marks.
#[derive(Clone, Copy)]
enum Magic {
    Pe,
    Elf,
    /// A thin Mach-O, big-endian or not.
    MachoThin(bool),
    MachoFat,
    Archive,
}

const CARVE_MAGICS: [(&[u8], Magic); 14] = [
    (b"MZ", Magic::Pe),
    (b"\x7fELF", Magic::Elf),
    (&[0xCE, 0xFA, 0xED, 0xFE], Magic::MachoThin(false)), // MH_MAGIC    (32-bit), LE host
    (&[0xCF, 0xFA, 0xED, 0xFE], Magic::MachoThin(false)), // MH_MAGIC_64 (64-bit), LE host
    (&[0xFE, 0xED, 0xFA, 0xCE], Magic::MachoThin(true)),  // MH_CIGAM    (32-bit), BE host
    (&[0xFE, 0xED, 0xFA, 0xCF], Magic::MachoThin(true)),  // MH_CIGAM_64 (64-bit), BE host
    (b"\xCA\xFE\xBA\xBE", Magic::MachoFat),
    (b"PK\x03\x04", Magic::Archive),         // ZIP / OOXML / APK / JAR
    (b"\x1f\x8b\x08", Magic::Archive),       // GZIP
    (b"BZh", Magic::Archive),                // BZIP2
    (b"\xfd7zXZ\x00", Magic::Archive),       // XZ
    (b"7z\xbc\xaf\x27\x1c", Magic::Archive), // 7-Zip
    (b"Rar!\x1a\x07", Magic::Archive),       // RAR
    (b"MSCF", Magic::Archive),               // CAB
];

/// Everything carving looks for in `data`, found in one read of it, a window
/// at a time: the image at offset 0 is the object's own, and each candidate
/// is validated as it is met. A kind stops being looked for at its cap.
pub(crate) fn embedded_in(data: &dyn ByteSource) -> Embedded {
    let mut carving = Carving::new();
    let len = data.len();
    let mut at = 0;
    while at < len && !carving.full() {
        let w = data.window(at, (len - at).min(crate::byte_source::CHUNK));
        if w.is_empty() {
            break;
        }
        let last = at + w.len() >= len;
        let owned = if last { w.len() } else { w.len().saturating_sub(Carving::OVERLAP).max(1) };
        carving.feed(data, at, &w, owned);
        if last {
            break;
        }
        at += owned;
    }
    carving.found
}

/// The search [`embedded_in`] makes, fed a window at a time by a read of the
/// object that serves other searches too.
pub(crate) struct Carving {
    finders: Vec<memchr::memmem::Finder<'static>>,
    hits: Vec<(usize, Magic)>,
    pub(crate) found: Embedded,
}

impl Carving {
    /// Bytes each window must run into the next, so a magic across the seam
    /// is seen whole.
    pub(crate) const OVERLAP: usize = {
        let mut longest = 0;
        let mut i = 0;
        while i < CARVE_MAGICS.len() {
            if CARVE_MAGICS[i].0.len() > longest {
                longest = CARVE_MAGICS[i].0.len();
            }
            i += 1;
        }
        longest - 1
    };

    pub(crate) fn new() -> Self {
        Carving {
            finders: CARVE_MAGICS.iter().map(|(m, _)| memchr::memmem::Finder::new(m)).collect(),
            hits: Vec::new(),
            found: Embedded::default(),
        }
    }

    /// Whether every kind is at its cap, so the rest of the object has
    /// nothing more to add.
    pub(crate) fn full(&self) -> bool {
        let f = &self.found;
        f.pe.len() >= MAX_EMBEDDED_PE
            && f.elf.len() >= MAX_EMBEDDED_PE
            && f.macho.len() >= MAX_EMBEDDED_PE
            && f.archives.len() >= MAX_EMBEDDED_ARCHIVES
    }

    /// Search the window `w` at `at` in `data` for the magics that start in
    /// its first `owned` bytes; those after start in the next window, which
    /// sees them whole. Candidates are validated against `data`.
    pub(crate) fn feed(&mut self, data: &dyn ByteSource, at: usize, w: &[u8], owned: usize) {
        let found = &mut self.found;
        let hits = &mut self.hits;
        hits.clear();
        for (f, (_, kind)) in self.finders.iter().zip(CARVE_MAGICS) {
            hits.extend(f.find_iter(w).take_while(|&p| p < owned).map(|p| (at + p, kind)));
        }
        hits.sort_unstable_by_key(|&(off, _)| off);
        for &(off, kind) in hits.iter() {
            if off == 0 {
                continue; // the object's own image or archive
            }
            let (list, cap, ok) = match kind {
                Magic::Pe => (&mut found.pe, MAX_EMBEDDED_PE, pe_at(data, off)),
                Magic::Elf => (&mut found.elf, MAX_EMBEDDED_PE, elf_at(data, off)),
                Magic::MachoThin(be) => (&mut found.macho, MAX_EMBEDDED_PE, macho_thin_at(data, off, be)),
                Magic::MachoFat => (&mut found.macho, MAX_EMBEDDED_PE, macho_fat_at(data, off)),
                Magic::Archive => (&mut found.archives, MAX_EMBEDDED_ARCHIVES, true),
            };
            if ok && list.len() < cap {
                list.push(off);
            }
        }
    }
}

/// An `MZ` at `off` whose `e_lfanew` points to a sane `PE\0\0` header.
fn pe_at(data: &dyn ByteSource, off: usize) -> bool {
    if off + 0x40 > data.len() {
        return false;
    }
    let Some(e_lfanew) = le_u32_at(data, off + 0x3c) else {
        return false;
    };
    let e_lfanew = e_lfanew as usize;
    // e_lfanew is relative to the MZ; the PE header must be in-bounds.
    let Some(pe) = off.checked_add(e_lfanew) else {
        return false;
    };
    if e_lfanew < 0x40 || pe + 4 > data.len() {
        return false;
    }
    data.window(pe, 4)[..] == *b"PE\0\0" && valid_pe_coff(data, pe)
}

/// A validated ELF identification header at `off`: class, data and version,
/// and a plausible `e_type`.
fn elf_at(data: &dyn ByteSource, off: usize) -> bool {
    let h = data.window(off, 18);
    if h.len() != 18 {
        return false;
    }
    let class = h[4]; // EI_CLASS: 1=32-bit, 2=64-bit
    let endian = h[5]; // EI_DATA: 1=LE, 2=BE
    let version = h[6]; // EI_VERSION: 1
    if !matches!(class, 1 | 2) || !matches!(endian, 1 | 2) || version != 1 {
        return false;
    }
    // e_type at offset 16 (2 bytes, endianness per EI_DATA): REL/EXEC/DYN/CORE.
    let etype = if endian == 1 {
        u16::from_le_bytes([h[16], h[17]])
    } else {
        u16::from_be_bytes([h[16], h[17]])
    };
    matches!(etype, 1..=4)
}

fn rd_u32(h: &[u8], o: usize, be: bool) -> u32 {
    let b = [h[o], h[o + 1], h[o + 2], h[o + 3]];
    if be {
        u32::from_be_bytes(b)
    } else {
        u32::from_le_bytes(b)
    }
}

/// A thin Mach-O header at `off` with a sane `filetype` and `ncmds`.
fn macho_thin_at(data: &dyn ByteSource, off: usize, be: bool) -> bool {
    let h = data.window(off, 28);
    if h.len() != 28 {
        return false;
    }
    let filetype = rd_u32(&h, 12, be); // MH_OBJECT..MH_KEXT_BUNDLE
    let ncmds = rd_u32(&h, 16, be);
    (1..=11).contains(&filetype) && (1..=10_000).contains(&ncmds)
}

/// A fat Mach-O header at `off`: a sane arch count and a real `cputype`
/// first, which a Java `.class` (the same magic) does not have.
fn macho_fat_at(data: &dyn ByteSource, off: usize) -> bool {
    let h = data.window(off, 28);
    if h.len() != 28 {
        return false;
    }
    let nfat = rd_u32(&h, 4, true);
    let cputype0 = rd_u32(&h, 8, true);
    (1..=64).contains(&nfat) && is_macho_cputype(cputype0)
}

/// Offsets of PE images embedded at a **non-zero** offset (an `MZ` whose
/// `e_lfanew` points to a `PE\0\0` header within bounds). File-infectors and
/// droppers append/embed executables this way; scanning them is needed to match
/// signatures (incl. section hashes) the same way ClamAV does.
/// The image at offset 0, if any, is handled by the normal scan and skipped.
pub fn embedded_pe_offsets(data: &[u8]) -> Vec<usize> {
    embedded_pe_offsets_in(&data)
}

/// [`embedded_pe_offsets`] over an object that need not be held in memory.
pub(crate) fn embedded_pe_offsets_in(data: &dyn ByteSource) -> Vec<usize> {
    embedded_in(data).pe
}

/// The little-endian `u32` at `at`, if the object holds it.
fn le_u32_at(data: &dyn ByteSource, at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.window(at, 4)[..].try_into().ok()?))
}

/// A carved `MZ…PE\0\0` region is treated as a scannable embedded PE only when
/// its COFF + optional header pass basic structural sanity. Without this, any
/// bytes in a compressed/encrypted stream that merely contain the `MZ` and
/// `PE\0\0` markers get carved and scanned as a bogus PE, where a short
/// entry-point-anchored signature can false-positive on the garbage, since
/// [`layout`] still computes an "entry" from the junk section table. ClamAV
/// gates embedded-PE extraction the same way. `pe` is the offset of `PE\0\0`.
fn valid_pe_coff(data: &dyn ByteSource, pe: usize) -> bool {
    // 20-byte COFF header after `PE\0\0`, then the optional-header magic.
    if pe + 26 > data.len() {
        return false;
    }
    let h = data.window(pe, 26);
    if h.len() != 26 {
        return false;
    }
    let rd16 = |o: usize| u16::from_le_bytes([h[o], h[o + 1]]);
    let machine = rd16(4);
    let n_sections = rd16(6);
    let opt_size = rd16(20);
    let magic = rd16(24);
    // Machine must be set, section count within the PE-spec maximum (96), an
    // optional header must be present, and its magic must be PE32 (0x10b) or
    // PE32+ (0x20b). Random data clears all four only vanishingly rarely.
    machine != 0 && (1..=96).contains(&n_sections) && opt_size != 0 && matches!(magic, 0x10b | 0x20b)
}

/// Offsets of ELF images embedded at a **non-zero** offset (a validated
/// `\x7fELF` identification header). Linux file-infectors and droppers append or
/// embed ELF payloads the same way Windows ones embed PE; carving them lets the
/// engine re-type the payload as ELF so `Target:6` and ELF-specific signatures
/// match at the embedded offset. Validated (class/data/version + a plausible
/// `e_type`) so a coincidental `\x7fELF` byte run is not carved. The image at
/// offset 0, if any, is handled by the normal scan and skipped.
pub fn embedded_elf_offsets(data: &[u8]) -> Vec<usize> {
    embedded_elf_offsets_in(&data)
}

/// [`embedded_elf_offsets`] over an object that need not be held in memory.
pub(crate) fn embedded_elf_offsets_in(data: &dyn ByteSource) -> Vec<usize> {
    embedded_in(data).elf
}

/// A Mach-O `cputype` we accept when validating a fat/universal header (used to
/// tell a real fat Mach-O from a Java `.class`, which shares the `CA FE BA BE`
/// magic). x86/x86_64/arm/arm64/arm64_32/ppc/ppc64.
fn is_macho_cputype(ct: u32) -> bool {
    matches!(
        ct,
        7 | 0x0100_0007 | 12 | 0x0100_000C | 0x0200_000C | 18 | 0x0100_0012
    )
}

/// Offsets of Mach-O images embedded at a **non-zero** offset. macOS malware is
/// commonly carried inside cross-platform droppers/archives; carving lets the
/// engine re-type the payload so Mach-O signatures match at the embedded offset.
/// Handles thin images (32/64-bit, both byte orders) and fat/universal images,
/// each validated (thin: a sane `filetype` + `ncmds`; fat: `nfat_arch` range and
/// a real `cputype` for the first arch) so a coincidental magic byte run (in
/// particular a Java `.class`, which also begins `CA FE BA BE`) is not carved.
/// The image at offset 0, if any, is handled by the normal scan and skipped.
pub fn embedded_macho_offsets(data: &[u8]) -> Vec<usize> {
    embedded_macho_offsets_in(&data)
}

/// [`embedded_macho_offsets`] over an object that need not be held in memory.
pub(crate) fn embedded_macho_offsets_in(data: &dyn ByteSource) -> Vec<usize> {
    embedded_in(data).macho
}

/// Offsets (> 0) where a supported container's magic appears: an archive
/// appended to or embedded in another file: SFX stubs, PE overlays (data after
/// the last section), and droppers that staple a ZIP/CAB/7z/RAR/GZIP/XZ onto a
/// carrier. The normal scan only types the buffer at offset 0, so these embedded
/// containers are invisible without carving. Candidates are validated by the
/// caller (via the extractor's `detect`) before extraction, so a coincidental
/// magic byte-run isn't treated as a real archive. Bounded to keep a buffer full
/// of magic-like bytes from blowing up the work.
pub fn embedded_archive_offsets(data: &[u8]) -> Vec<usize> {
    embedded_archive_offsets_in(&data)
}

/// [`embedded_archive_offsets`] over an object that need not be held in memory.
pub(crate) fn embedded_archive_offsets_in(data: &dyn ByteSource) -> Vec<usize> {
    embedded_in(data).archives
}

/// `(raw_size, section_bytes)` for each PE section, for `.mdb`/`.msb`
/// section-hash matching. The caller computes whatever digests it needs (so
/// SHA can be skipped when no `.msb` signatures are loaded). Empty if `data`
/// is not a parseable PE.
pub fn section_slices(data: &[u8]) -> Vec<(u64, &[u8])> {
    let Some(pe) = headers(data) else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(pe.sections.len());
    for s in &pe.sections {
        let start = s.pointer_to_raw_data as usize;
        let len = s.size_of_raw_data as usize;
        if len == 0 || start >= data.len() {
            continue;
        }
        // Clamp to the bytes actually present rather than dropping the section:
        // overlay-trimmed / truncated PEs declare a raw size that overruns EOF,
        // and dropping them would lose section-hash detections. The size key is
        // the declared raw size; the hash is over the available bytes.
        let end = start.saturating_add(len).min(data.len());
        out.push((len as u64, &data[start..end]));
    }
    out
}

/// Whether an ELF's section-header table has been stripped: `e_shentsize` is
/// zero, so the table cannot be walked at all.
///
/// This is NOT breakage. Section headers are optional for execution: the program
/// headers are what the loader reads, and these binaries run. It is, however,
/// deliberate: no toolchain emits a zero entry size, and it is a standard
/// anti-analysis step (86 of 87 such files in the corpus were UPX-packed with the
/// section table blanked afterwards). So it is worth reporting, under a name that
/// says what was actually found.
///
/// Deliberately narrow, and measured: over 1,120 corpus ELFs this separates
/// cleanly from the neighbouring conditions: 87 files have a zeroed entry size,
/// 173 have `e_shnum == 0` with a canonical entry size (an ordinary way to say
/// "no sections", not flagged), and 21 have a section table running past EOF
/// (genuine breakage, caught by [`looks_broken`], as is a nonzero entry size
/// of the wrong length).
pub fn elf_section_headers_stripped(data: &[u8]) -> bool {
    elf_section_headers_stripped_in(&data)
}

/// [`elf_section_headers_stripped`] over an object that need not be held in
/// memory.
pub(crate) fn elf_section_headers_stripped_in(src: &dyn ByteSource) -> bool {
    let h = src.window(0, 64);
    if !h.starts_with(b"\x7fELF") {
        return false;
    }
    // `e_shentsize`, placed by the class. Zero reads the same in either byte
    // order.
    let off = match h.get(4) {
        Some(1) => 46,
        Some(2) => 58,
        _ => return false,
    };
    h.get(off..off + 2) == Some(&[0, 0][..])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One read finds what looking for each magic at every offset finds:
    /// every validated image and archive candidate, in order and within its
    /// cap, whatever window seam it straddles, in memory and read through a
    /// cache of small blocks.
    #[test]
    fn one_read_finds_every_embedded_candidate() {
        use crate::byte_source::{BlockCache, CHUNK};
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut data: Vec<u8> = (0..7 * CHUNK + 77)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                b"abcdefgh"[(state % 8) as usize]
            })
            .collect();
        let mut put = |at: usize, bytes: &[u8]| data[at..at + bytes.len()].copy_from_slice(bytes);
        let mut elf = b"\x7fELF\x02\x01\x01".to_vec();
        elf.resize(16, 0);
        elf.extend_from_slice(&2u16.to_le_bytes());
        let mut pe = b"MZ".to_vec();
        pe.resize(0x3c, 0);
        pe.extend_from_slice(&0x40u32.to_le_bytes());
        pe.extend_from_slice(b"PE\0\0\x4c\x01\x03\0");
        pe.resize(0x40 + 20, 0);
        pe.extend_from_slice(&0xe0u16.to_le_bytes());
        pe.extend_from_slice(&[0, 0, 0x0b, 0x01]);
        let mut thin = vec![0xCF, 0xFA, 0xED, 0xFE];
        thin.resize(12, 0);
        thin.extend_from_slice(&2u32.to_le_bytes());
        thin.extend_from_slice(&5u32.to_le_bytes());
        thin.resize(28, 0);
        let mut fat = b"\xCA\xFE\xBA\xBE".to_vec();
        fat.extend_from_slice(&2u32.to_be_bytes());
        fat.extend_from_slice(&7u32.to_be_bytes());
        fat.resize(28, 0);
        put(0, &pe);
        for seam in 1..7 {
            let at = seam * CHUNK;
            put(at - 3, [&elf, &pe, &thin, &fat, &elf, &pe][seam - 1]);
            put(at - 700, b"Rar!\x1a\x07");
            put(at + 900, b"\xfd7zXZ\x00");
        }
        for k in 0..40 {
            put(100 + k * 90, b"PK\x03\x04");
        }
        // Every candidate, one offset at a time, and the cap of its kind.
        let mut want = Embedded::default();
        for off in 1..data.len() {
            for (magic, kind) in CARVE_MAGICS {
                if !data[off..].starts_with(magic) {
                    continue;
                }
                let d: &dyn ByteSource = &&data[..];
                let (list, cap, ok) = match kind {
                    Magic::Pe => (&mut want.pe, MAX_EMBEDDED_PE, pe_at(d, off)),
                    Magic::Elf => (&mut want.elf, MAX_EMBEDDED_PE, elf_at(d, off)),
                    Magic::MachoThin(be) => (&mut want.macho, MAX_EMBEDDED_PE, macho_thin_at(d, off, be)),
                    Magic::MachoFat => (&mut want.macho, MAX_EMBEDDED_PE, macho_fat_at(d, off)),
                    Magic::Archive => (&mut want.archives, MAX_EMBEDDED_ARCHIVES, true),
                };
                if ok && list.len() < cap {
                    list.push(off);
                }
            }
        }
        assert_eq!((want.pe.len(), want.elf.len(), want.macho.len()), (2, 2, 2));
        assert_eq!(want.archives.len(), MAX_EMBEDDED_ARCHIVES);
        let src = BlockCache::with_sizes(std::io::Cursor::new(data.clone()), 512, 4096).unwrap();
        let slice: &[u8] = &data;
        for hay in [&slice as &dyn ByteSource, &src] {
            let got = embedded_in(hay);
            assert_eq!(got.pe, want.pe);
            assert_eq!(got.elf, want.elf);
            assert_eq!(got.macho, want.macho);
            assert_eq!(got.archives, want.archives);
        }
    }

    #[test]
    fn embedded_macho_carved_and_java_rejected() {
        // A 64-bit LE Mach-O executable header (MH_MAGIC_64 = CF FA ED FE) at a
        // non-zero offset.
        let mut macho = vec![0u8; 0x40];
        macho[..4].copy_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]);
        macho[12..16].copy_from_slice(&2u32.to_le_bytes()); // filetype = MH_EXECUTE
        macho[16..20].copy_from_slice(&20u32.to_le_bytes()); // ncmds
        let mut blob = vec![0x90u8; 200];
        blob.extend_from_slice(&macho);
        assert_eq!(embedded_macho_offsets(&blob), vec![200]);

        // A Java class file shares the fat magic CA FE BA BE but has a large
        // pseudo-`nfat_arch` / non-Mach-O cputype, so it must NOT be carved.
        let mut java = vec![0x11u8; 64];
        java[..4].copy_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
        java[4..8].copy_from_slice(&0x0000_0034u32.to_be_bytes()); // minor/major = Java 8
        let mut jblob = vec![0u8; 100];
        jblob.extend_from_slice(&java);
        assert!(embedded_macho_offsets(&jblob).is_empty());
    }

    #[test]
    fn embedded_elf_carved_and_validated() {
        // A 64-bit LE ELF executable header embedded after some prefix bytes.
        let mut elf = vec![0u8; 64];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2; // class 64
        elf[5] = 1; // little-endian
        elf[6] = 1; // version
        elf[16..18].copy_from_slice(&2u16.to_le_bytes()); // e_type = EXEC
        let mut buf = vec![0xAA; 100];
        buf.extend_from_slice(&elf);
        assert_eq!(embedded_elf_offsets(&buf), vec![100]);
        // A bare `\x7fELF` with a junk identification header must NOT be carved.
        let mut junk = vec![0xAA; 50];
        junk.extend_from_slice(b"\x7fELF\xff\xff\xff and random text after");
        assert!(embedded_elf_offsets(&junk).is_empty());
        // An ELF at offset 0 is left to the normal scan (not re-carved).
        assert!(embedded_elf_offsets(&elf).is_empty());
    }

    #[test]
    fn embedded_pe_offsets_no_panic_on_tiny_input() {
        // Regression: `&data[1..]` panicked on an empty/sub-header buffer.
        for n in 0..0x41 {
            assert!(embedded_pe_offsets(&vec![b'M'; n]).is_empty() || n >= 0x40);
        }
        assert!(embedded_pe_offsets(b"").is_empty());
    }

    #[test]
    fn embedded_pe_carve_requires_valid_coff() {
        // A real minimal PE embedded after a prefix IS carved.
        let pe = minimal_pe(b"abcdefgh");
        let mut buf = vec![0xAAu8; 128];
        buf.extend_from_slice(&pe);
        assert_eq!(embedded_pe_offsets(&buf), vec![128]);

        // Regression (the Zbot FP family): `MZ` … `PE\0\0` followed by a junk
        // COFF header (zero machine, no optional header, bogus magic) must NOT be
        // carved, otherwise compressed/encrypted bytes that merely contain those
        // markers get scanned as a bogus PE, where a short entry-point-anchored
        // signature false-positives on the garbage.
        let mut junk = vec![0u8; 0x80];
        junk[0] = b'M';
        junk[1] = b'Z';
        junk[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes()); // e_lfanew -> 0x40
        junk[0x40..0x44].copy_from_slice(b"PE\0\0"); // COFF beyond is all zero
        let mut buf2 = vec![0xAAu8; 64];
        buf2.extend_from_slice(&junk);
        assert!(embedded_pe_offsets(&buf2).is_empty());
    }

    /// Build a minimal PE32+ with one `.text` section holding `section`.
    fn minimal_pe(section: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; 0x200];
        v[0] = b'M';
        v[1] = b'Z';
        v[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes()); // e_lfanew
        v[0x40..0x44].copy_from_slice(b"PE\0\0");
        let coff = 0x44;
        v[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // x86-64
        v[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes()); // 1 section
        v[coff + 16..coff + 18].copy_from_slice(&0xF0u16.to_le_bytes()); // opt hdr size
        v[coff + 18..coff + 20].copy_from_slice(&0x0022u16.to_le_bytes()); // characteristics
        let opt = 0x58;
        v[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+
        v[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry RVA
        v[opt + 20..opt + 24].copy_from_slice(&0x1000u32.to_le_bytes()); // base of code
        v[opt + 24..opt + 32].copy_from_slice(&0x140000000u64.to_le_bytes()); // image base
        v[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // section align
        v[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes()); // file align
        v[opt + 56..opt + 60].copy_from_slice(&0x2000u32.to_le_bytes()); // size of image
        v[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes()); // size of headers
        v[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes()); // subsystem
        v[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes
        let sh = 0x148;
        v[sh..sh + 5].copy_from_slice(b".text");
        v[sh + 8..sh + 12].copy_from_slice(&(section.len() as u32).to_le_bytes()); // virtual size
        v[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // virtual address
        v[sh + 16..sh + 20].copy_from_slice(&(section.len() as u32).to_le_bytes()); // raw size
        v[sh + 20..sh + 24].copy_from_slice(&0x200u32.to_le_bytes()); // ptr to raw data
        v[sh + 36..sh + 40].copy_from_slice(&0x60000020u32.to_le_bytes()); // characteristics
        v.extend_from_slice(section); // raw section data at 0x200
        v
    }

    #[test]
    fn section_hashes_of_minimal_pe() {
        let body = b"some .text section bytes";
        let pe = minimal_pe(body);
        let slices = section_slices(&pe);
        assert_eq!(slices.len(), 1, "expected one section");
        assert_eq!(slices[0].0, body.len() as u64);
        assert_eq!(slices[0].1, body);
        assert_eq!(
            encode_hex(&Md5::digest(slices[0].1)),
            encode_hex(&Md5::digest(body))
        );
    }

    #[test]
    fn section_hashes_non_pe_is_empty() {
        assert!(section_slices(b"not a pe").is_empty());
    }

    #[test]
    fn layout_of_minimal_pe() {
        let pe = minimal_pe(b"abcdefgh");
        let l = layout(&pe).unwrap();
        assert_eq!(l.section_rawptrs, vec![0x200]);
        // entry RVA 0x1000 falls in the section at VA 0x1000 / file 0x200.
        assert_eq!(l.entry, Some(0x200));
    }

    #[test]
    fn entropy_bounds() {
        assert_eq!(shannon_entropy(&[0u8; 1000]), 0.0); // all same byte
        let mut all = Vec::new();
        for b in 0..=255u8 {
            all.extend(std::iter::repeat_n(b, 16));
        }
        let h = shannon_entropy(&all);
        assert!(h > 7.9 && h <= 8.0, "uniform bytes ~8 bits, got {h}");
    }

    #[test]
    fn non_pe_returns_none() {
        assert!(analyze(b"not a pe file at all").is_none());
    }

    #[test]
    fn bytecode_pe_sections_and_rawaddr() {
        let pe = minimal_pe(b"abcdefgh");
        let bc = bytecode_pe(&pe).unwrap();
        assert_eq!(bc.sections.len(), 1);
        let s = bc.sections[0];
        assert_eq!((s.rva, s.raw), (0x1000, 0x200));
        // RVA inside the section maps to its raw offset.
        assert_eq!(bc.rawaddr(0x1000, pe.len()), Some(0x200));
        assert_eq!(bc.rawaddr(0x1004, pe.len()), Some(0x204));
        // An RVA in no section and past the header is unmapped.
        assert_eq!(bc.rawaddr(0x9_0000, pe.len()), None);
    }

    #[test]
    fn pedata_image_key_fields() {
        let pe = minimal_pe(b"abcdefgh");
        let bc = bytecode_pe(&pe).unwrap();
        let pd = &bc.pedata;
        let rd16 = |o: usize| u16::from_le_bytes([pd[o], pd[o + 1]]);
        let rd32 = |o: usize| u32::from_le_bytes([pd[o], pd[o + 1], pd[o + 2], pd[o + 3]]);
        assert_eq!(rd16(8), 1); // nsections
        assert_eq!(rd32(632), 0x40); // e_lfanew
        assert_eq!(rd16(264), 0x20b); // opt64 Magic (PE32+)
        assert_eq!(rd32(280), 0x1000); // opt64 AddressOfEntryPoint
        assert_eq!(rd32(644), 0x200); // hdr_size (SizeOfHeaders)
    }

    /// Each data directory lands in its own slot, whichever are absent, and
    /// the reserved 16th one (which goblin's `dirs()` panics on) is copied too.
    #[test]
    fn pedata_data_directories_keep_their_index() {
        let set_dir = |pe: &mut Vec<u8>, i: usize, rva: u32, size: u32| {
            let at = 0x58 + 112 + i * 8;
            pe[at..at + 4].copy_from_slice(&rva.to_le_bytes());
            pe[at + 4..at + 8].copy_from_slice(&size.to_le_bytes());
        };
        let mut pe = minimal_pe(b"abcdefgh");
        set_dir(&mut pe, 8, 0x1004, 4); // GlobalPtr, not parsed by goblin
        set_dir(&mut pe, 15, 0x1008, 8); // reserved
        let bc = bytecode_pe(&pe).expect("parses");
        let pd = &bc.pedata;
        let rd32 = |o: usize| u32::from_le_bytes([pd[o], pd[o + 1], pd[o + 2], pd[o + 3]]);
        for base in [376, 504] {
            assert_eq!(rd32(base), 0, "slot 0 stays empty");
            assert_eq!((rd32(base + 64), rd32(base + 68)), (0x1004, 4));
            assert_eq!((rd32(base + 120), rd32(base + 124)), (0x1008, 8));
        }
    }

    /// From a live DLL in an MSI: a certificate table sized past the end of the
    /// file fails goblin's full parse. Its bytecode PE data was missing, so
    /// every bytecode program reading it left the scan `LIMITS-EXCEEDED`, and
    /// its section hashes were never computed. None of them reads a directory.
    #[test]
    fn a_malformed_certificate_table_leaves_the_pe_readable() {
        let body = b"abcdefgh";
        let mut pe = minimal_pe(body);
        let at = 0x58 + 112 + 4 * 8; // the certificate table's directory entry
        pe[at..at + 4].copy_from_slice(&0x200u32.to_le_bytes());
        pe[at + 4..at + 8].copy_from_slice(&2_409_852_894u32.to_le_bytes());
        assert!(PE::parse(&pe).is_err(), "the full parse refuses it");
        assert_eq!(bytecode_pe(&pe).expect("parses").sections.len(), 1);
        assert_eq!(section_slices(&pe), vec![(body.len() as u64, &body[..])]);
        assert_eq!(layout(&pe).expect("parses").entry, Some(0x200));
    }

    /// Noise with embedded images and archive magics planted at `spots`, some
    /// valid and some a byte off.
    fn carrier(len: usize, spots: &[usize]) -> Vec<u8> {
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut d: Vec<u8> = (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                b"MZPE\x7fELF\xca\xfe\xba\xbe\x00\x01\x02 x"[(state % 16) as usize]
            })
            .collect();
        for (k, &at) in spots.iter().enumerate() {
            let mut img = vec![0u8; 0x80];
            match k % 5 {
                0 => {
                    img[..2].copy_from_slice(b"MZ");
                    img[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
                    img[0x40..0x44].copy_from_slice(b"PE\0\0");
                    img[0x44..0x46].copy_from_slice(&0x14cu16.to_le_bytes());
                    img[0x46..0x48].copy_from_slice(&(1 + k as u16 % 3).to_le_bytes());
                    img[0x54..0x56].copy_from_slice(&0xe0u16.to_le_bytes());
                    img[0x58..0x5a].copy_from_slice(&0x10bu16.to_le_bytes());
                }
                1 => img[..18].copy_from_slice(b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0\x02\0"),
                2 => img[..20].copy_from_slice(b"\xcf\xfa\xed\xfe\x07\0\0\x01\x03\0\0\0\x02\0\0\0\x05\0\0\0"),
                3 => img[..12].copy_from_slice(b"\xca\xfe\xba\xbe\0\0\0\x02\0\0\0\x07"),
                _ => img[..4].copy_from_slice(if k % 2 == 0 { b"PK\x03\x04" } else { b"MSCF" }),
            }
            let at = at.min(len - img.len());
            d[at..at + img.len()].copy_from_slice(&img);
        }
        d
    }

    #[test]
    fn carving_offsets_are_the_same_read_in_blocks() {
        use crate::byte_source::{BlockCache, CHUNK};
        // Each kind straddling a chunk seam at several splits, and some
        // images whose headers run past the end.
        let mut spots = Vec::new();
        for k in 0..60 {
            spots.push((k + 1) * CHUNK - (k * 7) % 0x60);
        }
        let d = carrier(62 * CHUNK, &spots);
        let cache = BlockCache::with_sizes(std::io::Cursor::new(d.clone()), 509, 8 * 509).unwrap();
        for (name, f) in [
            ("pe", embedded_pe_offsets_in as fn(&dyn ByteSource) -> Vec<usize>),
            ("elf", embedded_elf_offsets_in),
            ("macho", embedded_macho_offsets_in),
            ("archive", embedded_archive_offsets_in),
        ] {
            let want = f(&d);
            assert!(!want.is_empty(), "{name}: nothing planted was found");
            assert_eq!(f(&cache), want, "{name}");
        }
        // The tail of the object cut through a header.
        for cut in [d.len() - 20, d.len() - 1] {
            let short = &d[..cut];
            let cache = BlockCache::with_sizes(std::io::Cursor::new(short.to_vec()), 509, 8 * 509).unwrap();
            assert_eq!(embedded_pe_offsets_in(&cache), embedded_pe_offsets(short));
            assert_eq!(embedded_elf_offsets_in(&cache), embedded_elf_offsets(short));
        }
    }
}
