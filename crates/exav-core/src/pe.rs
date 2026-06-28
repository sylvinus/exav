//! PE structural analysis: per-section entropy, packer/high-entropy
//! detection, suspicious-import heuristics, and imphash. Requires the
//! whole (bounded) file in memory, so it runs only on objects within the
//! deep-analysis size cap.

use goblin::pe::PE;
use md5::{Digest, Md5};

use crate::hexsig::encode_hex;

/// Structural facts extracted from a PE file.
pub struct PeInfo {
    pub is_64: bool,
    pub section_count: usize,
    /// (name, entropy) per section, entropy in bits/byte [0,8].
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
        // convention), not the function name — goblin renders an ordinal
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
    let len = data.len() as f64;
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
}

/// Extract [`PeLayout`] from a PE. `None` if `data` is not a parseable PE.
pub fn layout(data: &[u8]) -> Option<PeLayout> {
    let pe = PE::parse(data).ok()?;
    let mut section_rawptrs = Vec::with_capacity(pe.sections.len());
    let entry_rva = pe.entry as u64;
    let mut entry = None;
    for s in &pe.sections {
        let va = s.virtual_address as u64;
        let vsize = (s.virtual_size as u64).max(s.size_of_raw_data as u64);
        let ptr = s.pointer_to_raw_data as u64;
        section_rawptrs.push(ptr);
        if entry.is_none() && entry_rva >= va && entry_rva < va.saturating_add(vsize) {
            entry = Some(ptr + (entry_rva - va));
        }
    }
    Some(PeLayout {
        entry,
        section_rawptrs,
    })
}

/// One PE section in the shape the bytecode PE APIs expect
/// (`cli_exe_section`).
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
    /// `SizeOfHeaders` — RVAs below this map directly to file offsets.
    pub hdr_size: u32,
    /// Byte image of `cli_pe_hook_data` (the `__clambc_pedata` global).
    pub pedata: Vec<u8>,
}

/// Size of the `cli_pe_hook_data` struct image (the bytecode-compiler view,
/// with both opt32/opt64 headers and their data directories inlined).
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
    let pe = PE::parse(data).ok()?;
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
    bc.pedata = build_pedata(&pe, &bc, data.len());
    Some(bc)
}

/// Build the `cli_pe_hook_data` byte image the way the bytecode compiler lays
/// it out (offsets verified against the field accesses real programs make).
fn build_pedata(pe: &PE, bc: &BcPe, file_size: usize) -> Vec<u8> {
    let mut b = vec![0u8; PEDATA_SIZE];
    let put16 =
        |b: &mut [u8], off: usize, v: u16| b[off..off + 2].copy_from_slice(&v.to_le_bytes());
    let put32 =
        |b: &mut [u8], off: usize, v: u32| b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    let put64 =
        |b: &mut [u8], off: usize, v: u64| b[off..off + 8].copy_from_slice(&v.to_le_bytes());

    let coff = &pe.header.coff_header;
    let e_lfanew = pe.header.dos_header.pe_pointer;
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

    if let Some(oh) = pe.header.optional_header {
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

fn put_dirs(b: &mut [u8], base: usize, oh: &goblin::pe::optional_header::OptionalHeader) {
    for (i, dd) in oh.data_directories.dirs().enumerate().take(16) {
        let off = base + i * 8;
        // `dd` is (index, &DataDirectory); write VirtualAddress + Size.
        b[off..off + 4].copy_from_slice(&dd.1.virtual_address.to_le_bytes());
        b[off + 4..off + 8].copy_from_slice(&dd.1.size.to_le_bytes());
    }
}

/// Maximum embedded PE images to carve from one buffer (bounds work on inputs
/// crafted with many `MZ` markers).
const MAX_EMBEDDED_PE: usize = 16;

/// Offsets of PE images embedded at a **non-zero** offset (an `MZ` whose
/// `e_lfanew` points to a `PE\0\0` header within bounds). File-infectors and
/// droppers append/embed executables this way; scanning them is needed to match
/// signatures (incl. section hashes) the same way the reference engine does.
/// The image at offset 0, if any, is handled by the normal scan and skipped.
pub fn embedded_pe_offsets(data: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    // Need at least an MZ + e_lfanew header; also keeps `&data[from..]` (from=1)
    // from panicking on an empty/tiny buffer.
    if data.len() < 0x40 {
        return out;
    }
    let mut from = 1usize; // skip a top-level image at offset 0
    while out.len() < MAX_EMBEDDED_PE {
        let Some(rel) = memchr::memmem::find(&data[from..], b"MZ") else {
            break;
        };
        let off = from + rel;
        from = off + 1;
        if off + 0x40 > data.len() {
            break;
        }
        let e_lfanew = u32::from_le_bytes([
            data[off + 0x3c],
            data[off + 0x3d],
            data[off + 0x3e],
            data[off + 0x3f],
        ]) as usize;
        // e_lfanew is relative to the MZ; the PE header must be in-bounds.
        let Some(pe) = off.checked_add(e_lfanew) else {
            continue;
        };
        if e_lfanew < 0x40 || pe + 4 > data.len() {
            continue;
        }
        if &data[pe..pe + 4] == b"PE\0\0" {
            out.push(off);
        }
    }
    out
}

/// Offsets of ELF images embedded at a **non-zero** offset (a validated
/// `\x7fELF` identification header). Linux file-infectors and droppers append or
/// embed ELF payloads the same way Windows ones embed PE; carving them lets the
/// engine re-type the payload as ELF so `Target:6` and ELF-specific signatures
/// match at the embedded offset. Validated (class/data/version + a plausible
/// `e_type`) so a coincidental `\x7fELF` byte run is not carved. The image at
/// offset 0, if any, is handled by the normal scan and skipped.
pub fn embedded_elf_offsets(data: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    if data.len() < 0x14 {
        return out;
    }
    let mut from = 1usize; // skip a top-level image at offset 0
    while out.len() < MAX_EMBEDDED_PE {
        let Some(rel) = memchr::memmem::find(&data[from..], b"\x7fELF") else {
            break;
        };
        let off = from + rel;
        from = off + 1;
        if off + 18 > data.len() {
            break;
        }
        let class = data[off + 4]; // EI_CLASS: 1=32-bit, 2=64-bit
        let endian = data[off + 5]; // EI_DATA: 1=LE, 2=BE
        let version = data[off + 6]; // EI_VERSION: 1
        if !matches!(class, 1 | 2) || !matches!(endian, 1 | 2) || version != 1 {
            continue;
        }
        // e_type at offset 16 (2 bytes, endianness per EI_DATA): REL/EXEC/DYN/CORE.
        let etype = if endian == 1 {
            u16::from_le_bytes([data[off + 16], data[off + 17]])
        } else {
            u16::from_be_bytes([data[off + 16], data[off + 17]])
        };
        if matches!(etype, 1..=4) {
            out.push(off);
        }
    }
    out
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
/// a real `cputype` for the first arch) so a coincidental magic byte run — in
/// particular a Java `.class`, which also begins `CA FE BA BE` — is not carved.
/// The image at offset 0, if any, is handled by the normal scan and skipped.
pub fn embedded_macho_offsets(data: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    if data.len() < 0x20 {
        return out;
    }
    // (magic bytes as stored on disk, is_big_endian)
    const THIN: [([u8; 4], bool); 4] = [
        ([0xCE, 0xFA, 0xED, 0xFE], false), // MH_MAGIC    (32-bit), LE host
        ([0xCF, 0xFA, 0xED, 0xFE], false), // MH_MAGIC_64 (64-bit), LE host
        ([0xFE, 0xED, 0xFA, 0xCE], true),  // MH_CIGAM    (32-bit), BE host
        ([0xFE, 0xED, 0xFA, 0xCF], true),  // MH_CIGAM_64 (64-bit), BE host
    ];
    let rd_u32 = |o: usize, be: bool| -> u32 {
        let b = [data[o], data[o + 1], data[o + 2], data[o + 3]];
        if be {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        }
    };
    for (magic, be) in THIN {
        let mut from = 1usize; // skip a top-level image at offset 0
        while out.len() < MAX_EMBEDDED_PE {
            let Some(rel) = memchr::memmem::find(&data[from..], &magic) else {
                break;
            };
            let off = from + rel;
            from = off + 1;
            if off + 28 > data.len() {
                break;
            }
            let filetype = rd_u32(off + 12, be); // MH_OBJECT..MH_KEXT_BUNDLE
            let ncmds = rd_u32(off + 16, be);
            if (1..=11).contains(&filetype) && (1..=10_000).contains(&ncmds) {
                out.push(off);
            }
        }
    }
    // Fat/universal: magic is always big-endian on disk (`CA FE BA BE`).
    let mut from = 1usize;
    while out.len() < MAX_EMBEDDED_PE {
        let Some(rel) = memchr::memmem::find(&data[from..], b"\xCA\xFE\xBA\xBE") else {
            break;
        };
        let off = from + rel;
        from = off + 1;
        if off + 28 > data.len() {
            break;
        }
        let nfat = u32::from_be_bytes([data[off + 4], data[off + 5], data[off + 6], data[off + 7]]);
        let cputype0 =
            u32::from_be_bytes([data[off + 8], data[off + 9], data[off + 10], data[off + 11]]);
        if (1..=64).contains(&nfat) && is_macho_cputype(cputype0) {
            out.push(off);
        }
    }
    out.sort_unstable();
    out.truncate(MAX_EMBEDDED_PE);
    out
}

/// `(raw_size, section_bytes)` for each PE section, for `.mdb`/`.msb`
/// section-hash matching. The caller computes whatever digests it needs (so
/// SHA can be skipped when no `.msb` signatures are loaded). Empty if `data`
/// is not a parseable PE.
pub fn section_slices(data: &[u8]) -> Vec<(u64, &[u8])> {
    let pe = match PE::parse(data) {
        Ok(p) => p,
        Err(_) => return Vec::new(),
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
