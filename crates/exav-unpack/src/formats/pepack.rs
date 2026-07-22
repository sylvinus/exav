//! PE runtime-packer unpacking.
//!
//! Many Windows malware families ship packed by a runtime packer that wraps the
//! original image in a small decompressor stub; the on-disk bytes are the packed
//! form, so signatures on the *original* code only match once the payload is
//! decompressed. UPX is handled separately (see `upx.rs`). This module covers
//! the next tier of common packers.
//!
//! Three routes, tried in that order:
//!
//! * **aPLib-compressed packers** — Petite 2.x, FSG 2.0 and NsPack wrap the
//!   original image in an [`aplib`] stream. For these we locate the compressed
//!   stream and decompress it, then **accept the result only if it reconstructs
//!   a valid PE image** (`MZ`/`PE\0\0`). That output-validity gate means we do
//!   not need packer-version-exact stub reverse-engineering to be *safe*: a
//!   wrong guess fails the gate and is discarded, never fed to the matcher as
//!   bogus data. When it passes, the recovered original PE is emitted for
//!   scanning. Cheapest route, so it is tried first.
//!
//! * **Everything else that looks packed** — Aspack, MEW, Upack, wwpack32,
//!   PeSpin, Yoda's Cryptor, and packers with no name at all. Their stubs are
//!   *run*, under the bounded x86 interpreter in `exav-pe-emu`, which captures
//!   the image the stub rebuilds. Whatever scheme a packer uses, it has to
//!   reconstruct the original program in memory before it can jump to it, and
//!   that is what this catches. The same output gate applies: a dump is emitted
//!   only if it reads back as a PE.
//!
//! * **Virtualizing protectors** — VMProtect, Themida, Enigma. Never emulated:
//!   the protected code was translated to a private bytecode at build time, so
//!   there is no original image in memory at any point to capture, and running
//!   the stub would spend the budget proving it. Reported instead.
//!
//! A packed file that survives all three is reported `unsupported` (→
//! `Unscannable`) rather than passed over: the packed bytes were scanned, the
//! image the stub would unfold was not, and a scanner that stays quiet about
//! that has produced a silent clean.
//!
//! `#![forbid(unsafe_code)]` (crate root): all PE parsing is bounds-checked and
//! returns `None`/empty rather than panicking on malformed input.

use crate::{Budget, Entry, LimitHit, Sink};

use super::aplib;
#[cfg(feature = "pe-emu")]
use exav_pe_emu as x86;

#[cfg(feature = "pe-emu")]
/// Run the emulator over `data` and summarise the outcome. Exposed (hidden) for
/// the `pepack_emu` example, which is how a stub that does not unpack gets
/// triaged: the summary names the instruction, export or fault that stopped it.
pub(crate) fn emulate_pe(
    data: &[u8],
    max_ticks: u64,
    trace: bool,
) -> (String, Vec<(String, Vec<u8>)>) {
    let limits = x86::run::EmuLimits {
        max_ticks,
        trace,
        ..Default::default()
    };
    let r = x86::run::unpack(data, &limits);
    let mut line = format!(
        "ticks={} dirty={}KiB stop={}",
        r.ticks,
        r.dirty_bytes / 1024,
        r.stop
    );
    if !r.missing_apis.is_empty() {
        line.push_str(&format!(" missing={:?}", r.missing_apis));
    }
    if !r.extra.is_empty() {
        line.push_str(&format!(" allocated_images={}", r.extra.len()));
    }
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    if let Some(u) = r.unpacked {
        line.push_str(&format!(
            " dump={}KiB oep={:#x} reached_oep={}",
            u.data.len() / 1024,
            u.oep_rva,
            u.reached_oep
        ));
        out.push(("unpacked".to_string(), u.data));
    }
    for (i, e) in r.extra.into_iter().enumerate() {
        out.push((format!("allocation-{i}"), e));
    }
    for c in &r.api_calls {
        line.push_str("\n  api  ");
        line.push_str(c);
    }
    for t in &r.tail {
        line.push_str("\n    ");
        line.push_str(t);
    }
    (line, out)
}

/// A parsed subset of a PE file — just what packer detection and stream location
/// need. All offsets are validated against `len` at parse time.
struct Pe<'a> {
    data: &'a [u8],
    /// Address of entry point (RVA).
    entry_rva: u32,
    sections: Vec<Section>,
    /// File alignment, and the import/CLR data directories: what the
    /// packed-shape heuristics read. Kept here rather than borrowed from the
    /// emulator's parser so that *detecting* a packed file — and reporting it —
    /// still works in a build with the emulator compiled out.
    file_align: u32,
    import_rva: u32,
    clr_rva: u32,
}

struct Section {
    name: [u8; 8],
    vaddr: u32,
    vsize: u32,
    raw_ptr: u32,
    raw_size: u32,
    characteristics: u32,
}

#[inline]
fn u16_le(d: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*d.get(o)?, *d.get(o + 1)?]))
}
#[inline]
fn u32_le(d: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *d.get(o)?,
        *d.get(o + 1)?,
        *d.get(o + 2)?,
        *d.get(o + 3)?,
    ]))
}

impl<'a> Pe<'a> {
    /// Parse the PE headers. Returns `None` if the bytes are not a well-formed
    /// PE (bad magic, headers out of bounds, absurd section count).
    fn parse(data: &'a [u8]) -> Option<Pe<'a>> {
        if data.len() < 0x40 || &data[..2] != b"MZ" {
            return None;
        }
        let e_lfanew = u32_le(data, 0x3C)? as usize;
        // COFF header: "PE\0\0" then 20 bytes. `checked_add` so a hostile
        // `e_lfanew` (e.g. 0xFFFFFFFF) can't overflow the range end on 32-bit
        // targets (wasm) before the bounds check.
        let coff = e_lfanew.checked_add(4)?;
        if data.get(e_lfanew..coff)? != b"PE\0\0" {
            return None;
        }
        let num_sections = u16_le(data, coff + 2)? as usize;
        let opt_size = u16_le(data, coff + 16)? as usize;
        if num_sections == 0 || num_sections > 96 {
            return None;
        }
        let opt = coff + 20;
        let magic = u16_le(data, opt)?;
        // AddressOfEntryPoint sits at the same offset (+16) in PE32 and PE32+.
        if magic != 0x10b && magic != 0x20b {
            return None;
        }
        let entry_rva = u32_le(data, opt + 16)?;
        let file_align = u32_le(data, opt + 36).unwrap_or(0x200);
        let num_dirs = u32_le(data, opt + 92).unwrap_or(0);
        let import_rva = if num_dirs >= 2 {
            u32_le(data, opt + 104).unwrap_or(0)
        } else {
            0
        };
        let clr_rva = if num_dirs >= 15 {
            u32_le(data, opt + 96 + 14 * 8).unwrap_or(0)
        } else {
            0
        };
        let sec_table = opt + opt_size;
        let mut sections = Vec::with_capacity(num_sections);
        for i in 0..num_sections {
            let s = sec_table + i * 40;
            let hdr = data.get(s..s + 40)?;
            let mut name = [0u8; 8];
            name.copy_from_slice(&hdr[..8]);
            sections.push(Section {
                name,
                vsize: u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]),
                vaddr: u32::from_le_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]),
                raw_size: u32::from_le_bytes([hdr[16], hdr[17], hdr[18], hdr[19]]),
                raw_ptr: u32::from_le_bytes([hdr[20], hdr[21], hdr[22], hdr[23]]),
                characteristics: u32::from_le_bytes([hdr[36], hdr[37], hdr[38], hdr[39]]),
            });
        }
        Some(Pe {
            data,
            entry_rva,
            sections,
            file_align,
            import_rva,
            clr_rva,
        })
    }

    /// Index of the section containing `rva`.
    fn section_of(&self, rva: u32) -> Option<usize> {
        self.sections.iter().position(|s| {
            let end = s.vaddr.saturating_add(s.vsize.max(s.raw_size).max(0x1000));
            rva >= s.vaddr && rva < end
        })
    }

    /// File offset for an RVA, if it lands inside a section's raw data.
    fn rva_to_off(&self, rva: u32) -> Option<usize> {
        for s in &self.sections {
            if rva >= s.vaddr && rva < s.vaddr.saturating_add(s.vsize.max(s.raw_size)) {
                let delta = rva - s.vaddr;
                if delta < s.raw_size {
                    // `checked_add`: `raw_ptr` and `delta` are both attacker-
                    // controlled u32s; their sum can overflow a 32-bit usize.
                    let Some(off) = (s.raw_ptr as usize).checked_add(delta as usize) else {
                        continue;
                    };
                    if off <= self.data.len() {
                        return Some(off);
                    }
                }
            }
        }
        None
    }
}

/// Recognised PE runtime packers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Packer {
    /// aPLib-compressed families we attempt to decompress.
    Nspack,
    Petite,
    Fsg,
    /// Detected but not decompressed (bespoke / emulation-required).
    Aspack,
    Mew,
    Upack,
    WwPack,
    PeSpin,
    Yoda,
    /// A UPX-sectioned image the real UPX path declined — normally because the
    /// `PackHeader` was stripped or patched, a routine anti-unpack move. Those
    /// files reached no unpacker at all and so scanned clean; here they are at
    /// least reported. Ordinary UPX still goes to `upx.rs`, which is tried
    /// first.
    UpxStripped,
    /// MPRESS (`.MPRESS1`/`.MPRESS2`). Its LZMA-variant stream has no
    /// reconstruct-and-verify path here, so it is reported rather than guessed
    /// at. Found by a clamd differential run: clamd unpacks MPRESS and matched
    /// `Win.Dropper.Darkkomet` / `Win.Packed.Brsecmon` inside, where exav
    /// returned OK.
    Mpress,
    /// Commercial **protectors** that virtualize code rather than merely
    /// compress it: the marked functions are translated into a bespoke bytecode
    /// at protect time and interpreted at runtime, so the original instructions
    /// are *destroyed*, not hidden. No engine unpacks these — not exav, not
    /// ClamAV, not a perfect emulator — because there is no moment at which the
    /// original code exists in memory to recover. They are the three most common
    /// packers in current samples, so staying silent about them is the one thing
    /// worse than not unpacking them.
    VmProtect,
    Themida,
    Enigma,
}

impl Packer {
    /// Whether this packer wraps the original image in an aPLib stream we try to
    /// decompress.
    fn is_aplib(self) -> bool {
        matches!(self, Packer::Nspack | Packer::Petite | Packer::Fsg)
    }

    /// Whether this is a virtualizing protector rather than a compressor. The
    /// distinction changes what exav can truthfully say: a compressor hides content
    /// that could in principle be recovered, a virtualizer leaves nothing to
    /// recover.
    fn is_virtualizer(self) -> bool {
        matches!(self, Packer::VmProtect | Packer::Themida | Packer::Enigma)
    }
}

/// Case-insensitive comparison of a section name against a marker, ignoring the
/// NUL padding a PE section name carries.
fn ieq(name: &[u8; 8], want: &[u8]) -> bool {
    let n: &[u8] = name.split(|&b| b == 0).next().unwrap_or(&[]);
    n.eq_ignore_ascii_case(want)
}

/// Identify the packer from section-name and entry-point signatures. Kept
/// conservative (strong markers only) to avoid mis-flagging ordinary PEs; a
/// miss just means the file is scanned raw, exactly as before.
fn identify(pe: &Pe) -> Option<Packer> {
    // Section-name markers — the most reliable signal for these packers.
    for s in &pe.sections {
        let n = &s.name;
        if starts_with(n, b"UPX0") || starts_with(n, b"UPX1") || starts_with(n, b".UPX") {
            return Some(Packer::UpxStripped);
        }
        if starts_with(n, b".MPRESS") {
            return Some(Packer::Mpress);
        }
        // Virtualizing protectors. Section names are the standard marker and are
        // matched case-insensitively for Themida, which ships them capitalised
        // (`Themida`), lowercase (`.themida`) and under its WinLicense branding
        // (`WinLicen`/`.winlice`) depending on build.
        if starts_with(n, b".vmp0") || starts_with(n, b".vmp1") || starts_with(n, b".vmp2") {
            return Some(Packer::VmProtect);
        }
        if ieq(n, b"themida") || ieq(n, b".themida") || ieq(n, b"winlicen") || ieq(n, b".winlice") {
            return Some(Packer::Themida);
        }
        if starts_with(n, b".enigma") {
            return Some(Packer::Enigma);
        }
        if starts_with(n, b".nsp") || eq8(n, b"nsp0\0\0\0\0") {
            return Some(Packer::Nspack);
        }
        if starts_with(n, b".aspack") || starts_with(n, b".adata") {
            return Some(Packer::Aspack);
        }
        if starts_with(n, b".petite") {
            return Some(Packer::Petite);
        }
        if starts_with(n, b"MEW") || starts_with(n, b".MEW") {
            return Some(Packer::Mew);
        }
        if starts_with(n, b".WWP") || starts_with(n, b".WWPACK") {
            return Some(Packer::WwPack);
        }
        if starts_with(n, b".taz") {
            return Some(Packer::PeSpin);
        }
        if starts_with(n, b".yP") || starts_with(n, b".y0da") {
            return Some(Packer::Yoda);
        }
        if starts_with(n, b".Upack") || starts_with(n, b".ByDwing") {
            return Some(Packer::Upack);
        }
    }
    // Entry-point signature for FSG (which strips section names). FSG 2.0 stubs
    // begin the decompressor with a distinctive load of the packed-source and
    // destination pointers. Match at the entry-point file offset only.
    if let Some(off) = pe.rva_to_off(pe.entry_rva) {
        if let Some(win) = pe.data.get(off..off + 2) {
            // `BE xx xx xx xx` (mov esi, imm32) is the canonical FSG 2.0 stub
            // opener; require it to sit right at the entry point.
            if win[0] == 0xBE && fsg_stub_plausible(pe, off) {
                return Some(Packer::Fsg);
            }
        }
    }
    None
}

/// Extra confirmation for the FSG entry-point heuristic: the stub is tiny and
/// the entry point lies in the last section (FSG relocates execution there).
/// Keeps the single-byte `BE` opcode from matching arbitrary PEs.
fn fsg_stub_plausible(pe: &Pe, ep_off: usize) -> bool {
    // The imm32 loaded by `mov esi, imm32` should be a plausible in-image VA.
    let Some(imm) = u32_le(pe.data, ep_off + 1) else {
        return false;
    };
    // A real FSG stub is short; the entry section's raw data is small.
    let ep_section = pe.sections.iter().find(|s| {
        let off = s.raw_ptr as usize;
        // `saturating_add`: `raw_ptr + raw_size` (both attacker-controlled u32s)
        // can overflow a 32-bit usize; a saturated end is a correct upper bound.
        ep_off >= off && ep_off < off.saturating_add(s.raw_size as usize)
    });
    match ep_section {
        Some(s) => imm != 0 && s.raw_size <= 0x400,
        None => false,
    }
}

#[inline]
fn starts_with(name: &[u8; 8], prefix: &[u8]) -> bool {
    name.len() >= prefix.len() && &name[..prefix.len()] == prefix
}
#[inline]
fn eq8(name: &[u8; 8], other: &[u8; 8]) -> bool {
    name == other
}

/// True if `data` is a PE this module should look at: either a named packer, or
/// an image whose shape says a runtime packer built it. Used by the scan path to
/// route the file here (in addition to the raw scan).
pub(crate) fn is_pepack(data: &[u8]) -> bool {
    // An image this emulator already produced must not be fed back into it. It
    // still carries the packer's section names — the names are evidence and are
    // not rewritten — so `identify` would recognise the packer a second time,
    // the second run would find nothing to unpack (the work is already done),
    // and the file would be reported UNSCANNABLE: a successful unpack downgraded
    // by the rescan of its own output.
    if is_memory_layout_dump(data) {
        return false;
    }
    if Pe::parse(data).and_then(|pe| identify(&pe)).is_some() {
        return true;
    }
    looks_packed(data)
}

/// Whether an image is laid out the way memory is rather than the way a file
/// is: every section's raw offset equal to its virtual address, and a file
/// alignment as coarse as the section alignment. That is what a dump looks
/// like — a linker writes 512-byte-aligned raw data at offsets that have
/// nothing to do with the virtual addresses.
fn is_memory_layout_dump(data: &[u8]) -> bool {
    let Some(pe) = Pe::parse(data) else {
        return false;
    };
    pe.file_align >= 0x1000
        && pe.sections.len() > 1
        && pe
            .sections
            .iter()
            .all(|s| s.raw_size == 0 || s.raw_ptr == s.vaddr)
}

/// Whether a PE looks like a runtime-packed image, for the files no named
/// packer matched.
///
/// This is what makes the emulator general rather than a list of packers: most
/// packers can be renamed, restubbed or stripped of their section names, but
/// none of them can hide the *shape* of a packed image. What they all share is
/// that the program on disk is not the program that runs — so the file carries
/// a section far larger in memory than on disk to unfold into, an entry point
/// in the last section rather than the first, an import table with a handful of
/// entries where a real program has hundreds, and an entry-point section marked
/// writable because the stub writes to itself.
///
/// No single signal decides it. Each one alone appears in honest software — a
/// large `.bss`, a small import table, a compressed resource — so they are
/// scored and a threshold applied. The two strongest describe where execution
/// starts, because that is what a packer cannot fake: its stub has to live with
/// the packed data and write over it, so the entry point ends up somewhere no
/// linker would put it.
///
/// Scored against the 23-packer sample set, ordinary programs land at 0-1 and
/// every packed sample at 2 or above.
///
/// A miss costs nothing (the file is scanned raw, as before); a false hit costs
/// an emulation that finds nothing and reports nothing.
fn looks_packed(data: &[u8]) -> bool {
    let Some(pe) = Pe::parse(data) else {
        return false;
    };
    let Some(ep_idx) = pe.section_of(pe.entry_rva) else {
        // An entry point outside every section is itself conclusive — no linker
        // produces that.
        return true;
    };
    let ep = &pe.sections[ep_idx];
    let mut score = 0;

    const WRITABLE: u32 = 0x8000_0000;
    if ep.characteristics & WRITABLE != 0 {
        score += 2;
    }
    if ep_idx != 0 {
        score += 2;
    }
    // A section whose name no toolchain emits, holding data no toolchain
    // produces: this is the packed payload, sitting in the section the packer
    // added for it. Entropy alone would flag a `.rsrc` full of PNGs, and an odd
    // name alone flags a linker nobody uses; together they are decisive.
    if pe.sections.iter().any(|s| {
        !is_standard_section(&s.name) && s.raw_size >= 0x1000 && section_entropy(s, data) >= 7.0
    }) {
        score += 2;
    }
    if section_entropy(ep, data) >= 7.0 {
        score += 1;
    }
    // A section name generated per build. Packers that add a section either use
    // a fixed marker (`UPX1`, `.aspack`) — matched by name elsewhere — or
    // randomise it to defeat exactly that, and a random name is as much of a
    // signature as a fixed one. Compilers do not emit `.OqvPZc8`.
    if pe
        .sections
        .iter()
        .any(|s| s.raw_size >= 0x1000 && looks_random_name(&s.name))
    {
        score += 2;
    }
    // A section reserving far more memory than it occupies on disk: the
    // destination the packed payload unfolds into.
    if pe.sections.iter().any(|s| {
        s.raw_size == 0 && s.vsize >= 0x1000
            || (s.raw_size > 0 && s.vsize as u64 >= s.raw_size as u64 * 4 && s.vsize >= 0x4000)
    }) {
        score += 1;
    }
    // Almost no imports. A packer resolves what it needs at run time, so the
    // static table holds only what the stub itself calls. A file with no import
    // directory at all is a different thing — a driver, a resource-only DLL —
    // and does not count: two weak signals should not be enough on their own.
    if pe.import_rva != 0 && import_count(&pe, data) <= 6 {
        score += 1;
    }

    // A managed assembly's entry point is a jump into the .NET runtime and its
    // payload is IL, so emulating it reaches nothing — but a *packed* .NET file
    // runs a native stub first and often keeps the original CLR header. Rather
    // than veto those (which lost every Exe32pack sample), the bar is raised:
    // an ordinary managed assembly cannot clear it, and a packed one does so on
    // its packer's own section.
    let bar = if pe.clr_rva != 0 { 4 } else { 2 };
    score >= bar
}

/// Section names any toolchain might emit. Anything else was added by whatever
/// processed the file after the linker.
fn is_standard_section(name: &[u8; 8]) -> bool {
    const KNOWN: &[&[u8]] = &[
        b".text",
        b".data",
        b".rdata",
        b".bss",
        b".idata",
        b".edata",
        b".pdata",
        b".xdata",
        b".rsrc",
        b".reloc",
        b".tls",
        b".crt",
        b".sdata",
        b".didat",
        b".didata",
        b".gfids",
        b".cormeta",
        b".debug",
        b".drectve",
        b".sxdata",
        b".textbss",
        b".itext",
        b".00cfg",
        b".giats",
        b".buildid",
        b".eh_fram",
        b".symtab",
        b".fptable",
        b".rodata",
        b".comment",
        b".note",
        b".init",
        b".fini",
        b"code",
        b"data",
        b"const",
        b"bss",
    ];
    let n: &[u8] = name.split(|&b| b == 0).next().unwrap_or(&[]);
    if n.is_empty() {
        return false;
    }
    // Long names are stored as `/NNN` offsets into the string table.
    if n[0] == b'/' {
        return true;
    }
    let lower: Vec<u8> = n.to_ascii_lowercase();
    KNOWN.iter().any(|k| lower.starts_with(k))
}

/// Whether a section name looks machine-generated rather than chosen: mixed
/// case, and a digit or a second case switch. Deliberately narrow — every
/// convention-following name a toolchain or a named packer uses is one case
/// (`.text`, `.MPRESS1`, `UPX0`, `.aspack`), so only a name that is neither
/// qualifies.
fn looks_random_name(name: &[u8; 8]) -> bool {
    let n: &[u8] = name.split(|&b| b == 0).next().unwrap_or(&[]);
    let n = n.strip_prefix(b".").unwrap_or(n);
    if n.len() < 5 {
        return false;
    }
    let upper = n.iter().filter(|c| c.is_ascii_uppercase()).count();
    let lower = n.iter().filter(|c| c.is_ascii_lowercase()).count();
    let digits = n.iter().filter(|c| c.is_ascii_digit()).count();
    if upper == 0 || lower == 0 {
        return false;
    }
    let switches = n
        .windows(2)
        .filter(|w| w[0].is_ascii_lowercase() && w[1].is_ascii_uppercase())
        .count();
    digits > 0 || switches >= 2
}

/// Shannon entropy of a section's raw bytes, over a bounded sample. Compressed
/// and encrypted data sits at 7.5-8.0; compiled code around 6.
fn section_entropy(s: &Section, data: &[u8]) -> f64 {
    const SAMPLE: usize = 64 << 10;
    let start = s.raw_ptr as usize;
    let end = start
        .saturating_add(s.raw_size as usize)
        .min(data.len())
        .min(start.saturating_add(SAMPLE));
    let Some(bytes) = data.get(start..end) else {
        return 0.0;
    };
    if bytes.len() < 256 {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let n = bytes.len() as f64;
    -counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            p * p.log2()
        })
        .sum::<f64>()
}

/// Number of imported functions declared in the file's import table, capped —
/// the question is only "few or many".
fn import_count(pe: &Pe, data: &[u8]) -> u32 {
    const CAP: u32 = 64;
    let dir_rva = pe.import_rva;
    if dir_rva == 0 {
        return 0;
    }
    let Some(dir_off) = rva_to_file_offset(pe, dir_rva) else {
        return 0;
    };
    let mut total = 0u32;
    for i in 0..32usize {
        let d = dir_off + i * 20;
        let Some(desc) = data.get(d..d + 20) else {
            break;
        };
        let orig = u32::from_le_bytes([desc[0], desc[1], desc[2], desc[3]]);
        let first = u32::from_le_bytes([desc[16], desc[17], desc[18], desc[19]]);
        if orig == 0 && first == 0 {
            break;
        }
        let thunks = if orig != 0 { orig } else { first };
        let Some(mut off) = rva_to_file_offset(pe, thunks) else {
            continue;
        };
        while let Some(v) = data.get(off..off + 4) {
            if u32::from_le_bytes([v[0], v[1], v[2], v[3]]) == 0 {
                break;
            }
            total += 1;
            if total >= CAP {
                return CAP;
            }
            off += 4;
        }
    }
    total
}

/// File offset for an RVA, through the section table.
fn rva_to_file_offset(pe: &Pe, rva: u32) -> Option<usize> {
    let idx = pe.section_of(rva)?;
    let s = &pe.sections[idx];
    let delta = rva.checked_sub(s.vaddr)?;
    if delta >= s.raw_size {
        return None;
    }
    (s.raw_ptr as usize).checked_add(delta as usize)
}

/// Maximum size we will decompress an inner PE to (guards crafted streams; the
/// budget cap further constrains this).
const MAX_INNER: usize = 128 << 20;

/// Attempt to recover and emit the original image from a packed PE. For
/// aPLib-family packers, locate the compressed stream at candidate offsets and
/// decompress, accepting only output that reconstructs a valid PE. Returns
/// `Ok(None)` when nothing could be safely recovered (the caller still scans the
/// raw bytes).
pub(crate) fn extract_pepack<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    let Some(pe) = Pe::parse(data) else {
        return Ok(None);
    };
    let identified = identify(&pe);

    // The aPLib families first: a static depack is exact and costs a
    // decompression, where emulation costs millions of instructions.
    let mut recovered = false;
    if let Some(packer) = identified.filter(|p| p.is_aplib()) {
        match aplib_unpack(&pe, data, budget, visit, packer)? {
            Recovered::Halt(r) => return Ok(Some(r)),
            Recovered::Emitted => recovered = true,
            Recovered::Nothing => {}
        }
    }

    // Then the emulator, for everything except the virtualizers — for those
    // there is no original image in memory at any point, so running the stub
    // would burn the budget to reconstruct something that does not exist.
    #[cfg(feature = "pe-emu")]
    if !recovered && !identified.is_some_and(Packer::is_virtualizer) {
        let label = identified.map(packer_name).unwrap_or("runtime");
        match emulated_unpack(data, budget, visit, label)? {
            Recovered::Halt(r) => return Ok(Some(r)),
            Recovered::Emitted => recovered = true,
            Recovered::Nothing => {}
        }
    }
    if recovered {
        return Ok(None);
    }

    let Some(packer) = identified else {
        // Nothing named it and the emulator recovered nothing: the file was
        // routed here on the generic packed-look heuristic, which is a guess.
        // Reporting it unsupported would turn every unusual-but-ordinary PE
        // into an UNSCANNABLE verdict, so it is simply scanned raw.
        return Ok(None);
    };
    {
        // Detected, but not an aPLib family — no verifiable unpack, and we
        // fabricate nothing. The caller still scans the raw (packed) bytes, so a
        // signature written against the stub still fires; what is NOT examined
        // is the original image the stub will unfold at runtime.
        //
        // That unexamined payload has to be surfaced. Returning `Ok(None)` here
        // let a packed dropper scan as a clean OK — which is the one outcome the
        // scanner must never produce for content that is present but unread.
        // Reported as `unsupported`, so the verdict becomes UNSCANNABLE and the
        // member metadata still feeds `.cdb` matching.
        budget.count_entry()?;
        // The two tiers need different wording, because they are different
        // situations and a scanner that blurs them misleads. A compressor hides
        // an original image that exists and could be recovered; a virtualizer
        // translated the code at protect time, so there is no original image
        // anywhere — every byte present *was* scanned, but signatures written
        // against native instructions cannot match bytecode for a bespoke VM.
        let reason = if packer.is_virtualizer() {
            "executable protected by a code virtualizer: the protected functions \
             were translated to a private bytecode when the file was built, so no \
             original code exists to recover and signatures written against \
             native code cannot match it"
        } else {
            "executable packed with a format exav cannot unpack; \
             the packed bytes were scanned but the original image was not"
        };
        let e = Entry::unsupported(
            format!("{}-packed image", packer_name(packer)),
            data.len() as u64,
            false,
            reason,
        );
        Ok(visit(e, budget))
    }
}

/// Locate and decompress the aPLib stream Petite/FSG2/NsPack wrap the original
/// image in, accepting the result only if it reconstructs a valid PE. That
/// output check is what makes brute-forcing the stream offset safe: a wrong
/// guess fails it and is discarded rather than handed to the matcher as data.
fn aplib_unpack<R>(
    pe: &Pe,
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
    packer: Packer,
) -> Result<Recovered<R>, LimitHit> {
    budget.count_entry()?;
    let cap = budget.reserve()?.min(MAX_INNER as u64) as usize;

    // Candidate stream starts, most-likely first: each section's raw data (the
    // packed payload lives in one of them), plus the byte after the entry-point
    // stub. Deduplicated, bounded.
    let mut candidates: Vec<usize> = Vec::new();
    for s in &pe.sections {
        let start = s.raw_ptr as usize;
        if start < data.len() {
            candidates.push(start);
        }
    }
    if let Some(ep) = pe.rva_to_off(pe.entry_rva) {
        candidates.push(ep);
    }
    candidates.sort_unstable();
    candidates.dedup();

    for &start in &candidates {
        let stream = &data[start..];
        if stream.len() < 8 {
            continue;
        }
        if let Some(out) = aplib::depack(stream, cap) {
            if looks_like_pe(&out) {
                budget.commit(out.len() as u64);
                let name = format!("{}-unpacked", packer_name(packer));
                return Ok(match visit(Entry::new(name, out), budget) {
                    Some(r) => Recovered::Halt(r),
                    None => Recovered::Emitted,
                });
            }
        }
    }
    Ok(Recovered::Nothing)
}

/// What an unpacking attempt did, distinguishing "produced nothing" from
/// "produced a member the sink kept going past". A sink that collects every
/// member returns `None` for each one, so without that distinction a successful
/// static unpack would be followed by a redundant emulation of the same file.
pub(crate) enum Recovered<R> {
    Nothing,
    Emitted,
    Halt(R),
}

/// Instruction budget for one stub. Runtime packers spend on the order of a
/// hundred instructions per byte they produce, so this is what bounds the size
/// of image the emulator can follow to completion — and what bounds the CPU a
/// hostile file can demand. At roughly 20M ticks a second it is a few seconds
/// in the worst case, and only for files that already look packed.
#[cfg(feature = "pe-emu")]
const MAX_EMU_TICKS: u64 = 120_000_000;

/// Ceiling on the emulator's address space, and on the dump it produces.
///
/// These are deliberately far below the per-member buffer budget. An emulation
/// costs *both* at once — the page table while the stub runs, and the dump
/// afterwards — and it happens per packed member, at every nesting level, on
/// top of everything the enclosing scan is already holding. Sized from what a
/// real unpack needs (an image, a stack, a scratch allocation) rather than from
/// what the budget would allow, because the budget was set for one buffer and
/// this is three.
#[cfg(feature = "pe-emu")]
const MAX_EMU_MEMORY: usize = 64 << 20;
#[cfg(feature = "pe-emu")]
const MAX_EMU_DUMP: usize = 32 << 20;

/// Run the stub and emit what it rebuilt.
///
/// Three grades of result, named differently because they are different claims:
///
/// * `-emulated` — the stub transferred control to the reconstructed image. The
///   unpack ran to completion and the dump is the original program.
/// * `-emulated-partial` — the run stopped early with a substantial part of the
///   image rewritten. Worth scanning (the decompressed payload is in there), but
///   not the same as "this is the original program".
/// * `-emulated-allocation-N` — a PE image found in memory the stub allocated,
///   which is where a loader that never rewrites its own image puts the payload.
#[cfg(feature = "pe-emu")]
pub(crate) fn emulated_unpack<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
    label: &str,
) -> Result<Recovered<R>, LimitHit> {
    budget.count_entry()?;
    let cap = budget.reserve()?.min(MAX_INNER as u64) as usize;
    let limits = x86::run::EmuLimits {
        max_ticks: MAX_EMU_TICKS,
        max_dump: cap.min(MAX_EMU_DUMP),
        max_pages: cap.min(MAX_EMU_MEMORY) / exav_pe_emu::PAGE_SIZE,
        ..Default::default()
    };
    let report = x86::run::unpack(data, &limits);

    // Payloads the stub built in memory it allocated. Emitted whether or not it
    // also rebuilt its own image: a loader that unfolds the original program
    // into fresh pages and runs it there leaves it *only* here, and nothing
    // else in the scan would ever see it.
    let mut emitted = false;
    for (i, extra) in report.extra.into_iter().enumerate() {
        if !looks_like_pe(&extra) {
            continue;
        }
        budget.count_entry()?;
        budget.commit(extra.len() as u64);
        emitted = true;
        let name = format!("{label}-emulated-allocation-{i}");
        if let Some(r) = visit(Entry::new(name, extra), budget) {
            return Ok(Recovered::Halt(r));
        }
    }

    let Some(unpacked) = report.unpacked else {
        return Ok(if emitted {
            Recovered::Emitted
        } else {
            Recovered::Nothing
        });
    };
    // The same output gate the static path uses: only a buffer that reads back
    // as a PE image is emitted. A run that ended mid-decompression leaves the
    // headers intact, so this passes for partial reconstructions too — what it
    // rejects is a dump whose headers the stub overwrote with something else,
    // where there is no way to tell code from rubble.
    if !looks_like_pe(&unpacked.data) {
        return Ok(if emitted {
            Recovered::Emitted
        } else {
            Recovered::Nothing
        });
    }
    let name = if unpacked.reached_oep {
        format!("{label}-emulated")
    } else {
        format!("{label}-emulated-partial")
    };
    budget.commit(unpacked.data.len() as u64);
    if let Some(r) = visit(Entry::new(name, unpacked.data), budget) {
        return Ok(Recovered::Halt(r));
    }
    Ok(Recovered::Emitted)
}

fn packer_name(p: Packer) -> &'static str {
    // The vendor's own capitalisation, and the single source of truth for it.
    // These strings reach the user twice — in the member name and, with
    // `--alert-packed`, inside `Heuristics.Packed.<name>` — and a gateway
    // filtering on an exact string needs the name the vendor uses. Spelling them
    // once here means the scanner never has to re-derive a display name, so the
    // two can't drift apart and a packer added below is reportable immediately.
    match p {
        Packer::Nspack => "NsPack",
        Packer::Petite => "Petite",
        Packer::Fsg => "FSG",
        Packer::Aspack => "ASPack",
        Packer::Mew => "MEW",
        Packer::Upack => "Upack",
        Packer::WwPack => "WWPack32",
        Packer::PeSpin => "PESpin",
        Packer::Yoda => "Yoda",
        Packer::Mpress => "MPRESS",
        Packer::UpxStripped => "UPX",
        Packer::VmProtect => "VMProtect",
        Packer::Themida => "Themida",
        Packer::Enigma => "Enigma",
    }
}

/// Output-validity gate: accept a decompressed buffer only if it reconstructs a
/// plausible PE image (`MZ` + reachable `PE\0\0`). This is what makes candidate
/// brute-forcing safe — random or wrongly-located depack output is rejected
/// here rather than handed to the matcher as data.
fn looks_like_pe(out: &[u8]) -> bool {
    if out.len() < 0x40 || &out[..2] != b"MZ" {
        return false;
    }
    let Some(e_lfanew) = u32_le(out, 0x3C) else {
        return false;
    };
    let e = e_lfanew as usize;
    // The PE signature must be present, in bounds, and followed by a sane
    // section count, so a stray "MZ..." payload cannot pass.
    //
    // What is *not* required is that it sit past the DOS header. The loader
    // only needs `e_lfanew` to point somewhere in the file, and packers exploit
    // that: MEW, BeRoEXEPacker and WinUpack all put the PE header at offset
    // 0xc or 0x10, overlapping the DOS header they no longer need. Demanding
    // 0x40 here — a rule of thumb, not a rule — silently rejected every image
    // recovered from those three, turning a working unpack into an
    // `UNSCANNABLE` report.
    let Some(e_end) = e.checked_add(24) else {
        return false;
    };
    if e < 4 || e_end > out.len() {
        return false;
    }
    if &out[e..e + 4] != b"PE\0\0" {
        return false;
    }
    match u16_le(out, e + 4 + 2) {
        Some(n) => n > 0 && n <= 96,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{extract, Format, Limits};

    /// Build a minimal but structurally valid PE with the given section names
    /// and one section carrying `body` as raw data. Used both as the packed
    /// outer PE (to drive detection) and as the inner original PE (to be
    /// recovered and validated).
    fn build_pe(section_names: &[&[u8]], body: &[u8], body_section: usize) -> Vec<u8> {
        let num = section_names.len().max(1);
        let e_lfanew = 0x80usize;
        let opt_size = 0xE0usize; // PE32 optional header size
        let sec_table = e_lfanew + 24 + opt_size;
        let headers_end = sec_table + num * 40;
        let raw_align = |x: usize| (x + 0x1FF) & !0x1FF;
        let body_raw = raw_align(headers_end.max(0x200));
        let total = body_raw + raw_align(body.len().max(1));
        let mut d = vec![0u8; total];
        d[..2].copy_from_slice(b"MZ");
        d[0x3C..0x40].copy_from_slice(&(e_lfanew as u32).to_le_bytes());
        d[e_lfanew..e_lfanew + 4].copy_from_slice(b"PE\0\0");
        let coff = e_lfanew + 4;
        d[coff..coff + 2].copy_from_slice(&0x14c_u16.to_le_bytes()); // i386
        d[coff + 2..coff + 4].copy_from_slice(&(num as u16).to_le_bytes());
        d[coff + 16..coff + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());
        let opt = coff + 20;
        d[opt..opt + 2].copy_from_slice(&0x10b_u16.to_le_bytes()); // PE32
        d[opt + 16..opt + 20].copy_from_slice(&0x1000_u32.to_le_bytes()); // entry RVA
        for i in 0..num {
            let s = sec_table + i * 40;
            let name = section_names.get(i).copied().unwrap_or(b".text");
            let n = name.len().min(8);
            d[s..s + n].copy_from_slice(&name[..n]);
            let (raw_ptr, raw_size, vsize) = if i == body_section {
                (body_raw as u32, body.len() as u32, body.len() as u32)
            } else {
                (body_raw as u32, 0u32, 0x1000u32)
            };
            d[s + 8..s + 12].copy_from_slice(&vsize.to_le_bytes());
            d[s + 12..s + 16].copy_from_slice(&((0x1000 * (i as u32 + 1)).to_le_bytes()));
            d[s + 16..s + 20].copy_from_slice(&raw_size.to_le_bytes());
            d[s + 20..s + 24].copy_from_slice(&raw_ptr.to_le_bytes());
        }
        if body_raw + body.len() <= d.len() {
            d[body_raw..body_raw + body.len()].copy_from_slice(body);
        }
        d
    }

    #[test]
    fn identifies_packers_by_section_name() {
        for (name, want) in [
            (&b".nsp0"[..], Packer::Nspack),
            (&b".aspack"[..], Packer::Aspack),
            (&b".petite"[..], Packer::Petite),
            (&b"MEW"[..], Packer::Mew),
            (&b".WWP32"[..], Packer::WwPack),
            (&b".y0da"[..], Packer::Yoda),
            (&b".Upack"[..], Packer::Upack),
        ] {
            let pe_bytes = build_pe(&[name], b"payload", 0);
            let pe = Pe::parse(&pe_bytes).expect("parse");
            assert_eq!(identify(&pe), Some(want), "section {name:?}");
            assert!(is_pepack(&pe_bytes));
        }
    }

    /// Build a PE shaped like a packed one: an empty destination section that
    /// only exists in memory, then a writable section holding the stub and its
    /// payload, with the entry point in the latter. The two do not overlap —
    /// the destination ends where the stub section begins — because a stub that
    /// decompresses over its own code stops being a test of anything.
    fn packed_pe(stub: &[u8], payload: &[u8]) -> Vec<u8> {
        const DEST_RVA: u32 = 0x1000;
        const DEST_VSIZE: u32 = 0xd000;
        const STUB_RVA: u32 = 0xe000;
        const PAYLOAD_OFF: usize = 0x1000; // within the stub section
        let pe_off = 0x80usize;
        let opt_size = 0xe0usize;
        let sec_table = pe_off + 24 + opt_size;
        let stub_raw = 0x400usize;
        let sec1_len = PAYLOAD_OFF + payload.len();
        let mut d = vec![0u8; stub_raw + sec1_len];
        d[..2].copy_from_slice(b"MZ");
        d[0x3c..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
        d[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
        let coff = pe_off + 4;
        d[coff..coff + 2].copy_from_slice(&0x14cu16.to_le_bytes());
        d[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes());
        d[coff + 16..coff + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());
        let opt = coff + 20;
        d[opt..opt + 2].copy_from_slice(&0x10bu16.to_le_bytes());
        d[opt + 16..opt + 20].copy_from_slice(&STUB_RVA.to_le_bytes()); // entry
        d[opt + 28..opt + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
        d[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        d[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
        d[opt + 56..opt + 60].copy_from_slice(&0x2_0000u32.to_le_bytes()); // SizeOfImage
        d[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes());
        // Section 0: the destination, reserved in memory and empty on disk.
        let s0 = sec_table;
        d[s0..s0 + 5].copy_from_slice(b".text");
        d[s0 + 8..s0 + 12].copy_from_slice(&DEST_VSIZE.to_le_bytes());
        d[s0 + 12..s0 + 16].copy_from_slice(&DEST_RVA.to_le_bytes());
        d[s0 + 36..s0 + 40].copy_from_slice(&0xe000_0020u32.to_le_bytes());
        // Section 1: stub + payload, writable, holding the entry point.
        let s1 = sec_table + 40;
        d[s1..s1 + 5].copy_from_slice(b".data");
        d[s1 + 8..s1 + 12].copy_from_slice(&(sec1_len as u32).to_le_bytes());
        d[s1 + 12..s1 + 16].copy_from_slice(&STUB_RVA.to_le_bytes());
        d[s1 + 16..s1 + 20].copy_from_slice(&(sec1_len as u32).to_le_bytes());
        d[s1 + 20..s1 + 24].copy_from_slice(&(stub_raw as u32).to_le_bytes());
        d[s1 + 36..s1 + 40].copy_from_slice(&0xe000_0060u32.to_le_bytes()); // rwx
        d[stub_raw..stub_raw + stub.len()].copy_from_slice(stub);
        d[stub_raw + PAYLOAD_OFF..stub_raw + PAYLOAD_OFF + payload.len()].copy_from_slice(payload);
        d
    }

    #[test]
    fn an_unnamed_packer_is_emulated_and_its_payload_recovered() {
        // Nothing here names a packer: no marker section, no known stub. The
        // file is routed to the emulator by its *shape* — entry point in a
        // writable section, an empty section reserved to unfold into, no
        // imports — and the payload comes back from running the stub.
        const MARKER: &[u8] = b"EXAV_EMULATED_PAYLOAD_MARKER";
        let mut plain = Vec::new();
        while plain.len() < 0xc000 {
            plain.extend_from_slice(MARKER);
        }
        let cipher: Vec<u8> = plain.iter().map(|b| b ^ 0x5a).collect();
        let len = cipher.len() as u32;

        // mov esi, 0x40f000 ; mov edi, 0x401000 ; mov ecx, len
        // lodsb ; xor al, 0x5a ; stosb ; loop -6 ; jmp 0x401000
        let mut stub: Vec<u8> = vec![0xbe];
        stub.extend_from_slice(&0x0040_f000u32.to_le_bytes());
        stub.push(0xbf);
        stub.extend_from_slice(&0x0040_1000u32.to_le_bytes());
        stub.push(0xb9);
        stub.extend_from_slice(&len.to_le_bytes());
        stub.extend_from_slice(&[0xac, 0x34, 0x5a, 0xaa, 0xe2, 0xfa]);
        let jmp_at = 0x0040_e000u32 + stub.len() as u32;
        let rel = 0x0040_1000u32.wrapping_sub(jmp_at + 5) as i32;
        stub.push(0xe9);
        stub.extend_from_slice(&rel.to_le_bytes());

        let file = packed_pe(&stub, &cipher);
        assert!(
            is_pepack(&file),
            "the shape alone must route the file to the unpacker"
        );

        let mut b = Budget::new(Limits {
            max_extracted_bytes: 1 << 30,
            max_buffer_bytes: 1 << 30,
            ..Default::default()
        });
        let entries = extract(Format::PePacked, &file, &mut b).unwrap();
        assert_eq!(entries.len(), 1, "one reconstructed image");
        let e = &entries[0];
        assert_eq!(e.name, "runtime-emulated", "named as an emulated unpack");
        assert!(
            e.data.windows(MARKER.len()).any(|w| w == MARKER),
            "the decrypted payload is in the dump"
        );
        assert!(
            !file.windows(MARKER.len()).any(|w| w == MARKER),
            "and it is not in the packed file, so only the emulation found it"
        );
    }

    #[test]
    fn a_virtualizer_is_reported_without_being_emulated() {
        // Running a virtualizer's stub cannot produce an original image — there
        // isn't one — so the budget is not spent trying. The file is reported,
        // as before, with no bytes invented.
        let outer = build_pe(&[b".vmp0", b".vmp1"], b"whatever", 0);
        let mut b = Budget::new(Limits::default());
        let entries = extract(Format::PePacked, &outer, &mut b).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].unsupported.is_some());
        assert!(entries[0].data.is_empty());
    }

    #[test]
    fn ordinary_pe_is_not_flagged() {
        let pe_bytes = build_pe(&[b".text", b".data"], b"nothing special", 0);
        assert!(
            !is_pepack(&pe_bytes),
            "clean PE must not be detected as packed"
        );
        let mut b = Budget::new(Limits::default());
        // And extraction yields no member (raw file scanned by the caller).
        let entries = extract(Format::PePacked, &pe_bytes, &mut b).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn non_pe_input_is_ignored() {
        let mut b = Budget::new(Limits::default());
        assert!(!is_pepack(b"\x7fELF not a PE"));
        assert!(extract(Format::PePacked, b"\x7fELF..", &mut b)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn end_to_end_aplib_family_unpack() {
        // Inner "original" PE carrying a detectable marker string.
        const MARKER: &[u8] = b"EXAV_PEPACK_INNER_MARKER";
        let mut inner_body = Vec::new();
        inner_body.extend_from_slice(MARKER);
        inner_body.extend_from_slice(&[0x90u8; 300]); // padding to give aPLib matches
        inner_body.extend_from_slice(MARKER);
        let inner = build_pe(&[b".text"], &inner_body, 0);

        // Pack it with the aPLib encoder and lay the stream into an NsPack-named
        // outer PE section — exactly the shape the extractor expects.
        let packed_stream = aplib::encoder::pack(&inner);
        let outer = build_pe(&[b".nsp0", b".nsp1"], &packed_stream, 1);

        assert!(is_pepack(&outer), "outer PE must be detected as packed");
        let mut b = Budget::new(Limits {
            max_extracted_bytes: 1 << 30,
            max_buffer_bytes: 1 << 30,
            max_compression_ratio: u64::MAX,
            ..Default::default()
        });
        let entries = extract(Format::PePacked, &outer, &mut b).unwrap();
        assert_eq!(entries.len(), 1, "recovered exactly one inner image");
        let rec = &entries[0].data;
        assert_eq!(rec, &inner, "recovered inner PE must be byte-exact");
        assert!(
            rec.windows(MARKER.len()).any(|w| w == MARKER),
            "marker recovered from inside the packed stream"
        );
    }

    #[test]
    fn detected_non_aplib_packer_is_reported_not_silently_dropped() {
        // ASPack is detected but not decompressed. Nothing may be *fabricated* —
        // the entry carries no data — but the file must not scan clean either:
        // the original image is present in the packed bytes and was not
        // examined, so it is surfaced as unsupported (→ UNSCANNABLE).
        //
        // The opposite contract — returning no entries — would let a packed
        // dropper report OK, which is how a differential run against clamd
        // surfaces a real miss on UPX- and MPRESS-packed samples.
        let outer = build_pe(&[b".aspack", b".adata"], b"whatever", 0);
        assert!(is_pepack(&outer));
        let mut b = Budget::new(Limits::default());
        let entries = extract(Format::PePacked, &outer, &mut b).unwrap();
        assert_eq!(entries.len(), 1, "the packed image must be surfaced");
        assert!(
            entries[0].unsupported.is_some(),
            "reported as unsupported, so the verdict is UNSCANNABLE"
        );
        assert!(
            entries[0].data.is_empty(),
            "no bytes are invented for a packer we cannot unfold"
        );
    }

    #[test]
    fn upx_sections_without_a_packheader_are_reported() {
        // Stripping the PackHeader is a routine anti-unpack move: `is_upx` then
        // declines, so before this the file reached no unpacker at all and
        // scanned clean despite advertising UPX in its section names.
        let outer = build_pe(&[b"UPX0", b"UPX1"], b"packed-payload", 0);
        assert!(is_pepack(&outer), "UPX sections must be recognised here");
        let mut b = Budget::new(Limits::default());
        let entries = extract(Format::PePacked, &outer, &mut b).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].unsupported.is_some());
    }

    #[test]
    fn malformed_pe_does_not_panic() {
        for junk in [&b"MZ"[..], b"MZ\x00\x00", b"MZ\xff\xff\xff\xff garbage"] {
            let _ = is_pepack(junk);
            let mut b = Budget::new(Limits::default());
            let _ = extract(Format::PePacked, junk, &mut b);
        }
    }

    #[test]
    fn extreme_e_lfanew_does_not_panic() {
        // Attacker sets e_lfanew = 0xFFFFFFFF: `e_lfanew + 4` in Pe::parse must
        // not overflow-panic on 32-bit targets; parse must reject cleanly.
        let mut d = vec![0u8; 0x40];
        d[..2].copy_from_slice(b"MZ");
        d[0x3C..0x40].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        assert!(Pe::parse(&d).is_none());
        assert!(!is_pepack(&d));
        let mut b = Budget::new(Limits::default());
        let _ = extract(Format::PePacked, &d, &mut b);
    }

    #[test]
    fn looks_like_pe_extreme_e_lfanew_does_not_panic() {
        // Depack output whose e_lfanew is u32::MAX: `e + 24` in looks_like_pe
        // must not overflow-panic on 32-bit targets; the buffer is rejected.
        let mut out = vec![0u8; 0x40];
        out[..2].copy_from_slice(b"MZ");
        out[0x3C..0x40].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        assert!(!looks_like_pe(&out));
    }

    #[test]
    fn extreme_section_offsets_do_not_panic() {
        // A section with raw_ptr/raw_size = u32::MAX exercises the u32+u32
        // offset arithmetic in rva_to_off and the FSG stub check; must not
        // overflow-panic on 32-bit targets.
        let mut d = build_pe(&[b".text"], b"x", 0);
        let sec_table = 0x80usize + 24 + 0xE0; // mirrors build_pe layout
        let s = sec_table;
        d[s + 16..s + 20].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // raw_size
        d[s + 20..s + 24].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // raw_ptr
        let _ = is_pepack(&d);
        let mut b = Budget::new(Limits::default());
        let _ = extract(Format::PePacked, &d, &mut b);
    }
}
