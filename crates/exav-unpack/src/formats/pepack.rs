//! PE runtime-packer unpacking.
//!
//! Many Windows malware families ship packed by a runtime packer that wraps the
//! original image in a small decompressor stub; the on-disk bytes are the packed
//! form, so signatures on the *original* code only match once the payload is
//! decompressed. UPX is handled separately (see `upx.rs`). This module covers
//! the next tier of common packers.
//!
//! Two routes:
//!
//! * **Everything that looks packed**: Petite, FSG, NsPack, Aspack, MEW, Upack,
//!   wwpack32, PeSpin, Yoda's Cryptor, and packers with no name at all. Their
//!   stubs are *run*, under the bounded x86 interpreter in `exav-pe-emu`, which
//!   captures the image the stub rebuilds. Whatever scheme a packer uses, it
//!   has to reconstruct the original program in memory before it can jump to
//!   it, and that is what this catches. A dump is emitted only if it reads back
//!   as a PE.
//!
//! * **Virtualizing protectors**: VMProtect, Themida, Enigma. Never emulated:
//!   the protected code was translated to a private bytecode at build time, so
//!   there is no original image in memory at any point to capture, and running
//!   the stub would spend the budget proving it. Reported instead.
//!
//! A packed file that survives both (or any, in a build without the `pe-emu`
//! feature) is reported `unsupported` (→ `Unscannable`) rather than passed
//! over: the packed bytes were scanned, the image the stub would unfold was
//! not, and a scanner that stays quiet about that has produced a silent clean.
//!
//! `#![forbid(unsafe_code)]` (crate root): all PE parsing is bounds-checked and
//! returns `None`/empty rather than panicking on malformed input.

#[cfg(feature = "pe-emu")]
use crate::LimitHit;
use crate::pe::{Headers, PE32, PE32_PLUS, Section};
use crate::source::ByteSource;
use crate::{Budget, Entry, Sink};

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
    let r = crate::profile::timed("emu", data.len() as u64, || x86::run::unpack(data, &limits));
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

/// A PE file as packer detection and stream location see it: its headers and
/// the import and CLR data directories the packed-shape heuristics read. Kept
/// here rather than borrowed from the emulator's parser so that *detecting* a
/// packed file (and reporting it) still works in a build with the emulator
/// compiled out.
struct Pe<'a> {
    data: &'a [u8],
    headers: Headers,
    import_rva: u32,
    clr_rva: u32,
}

#[cfg(feature = "pe-emu")]
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
    /// Parse the PE headers. Returns `None` if the bytes are not a PE that
    /// packer detection reads: PE32 or PE32+, with 1 to 96 sections all in
    /// the file.
    fn parse(data: &'a [u8]) -> Option<Pe<'a>> {
        let headers = Headers::read(&|off, len| ByteSource::window(data, off, len))?;
        if !(1..=96).contains(&headers.section_count)
            || headers.sections.len() != usize::from(headers.section_count)
            || (headers.magic != PE32 && headers.magic != PE32_PLUS)
        {
            return None;
        }
        let directory = |i: usize| headers.directories.get(i).map_or(0, |d| d.address);
        Some(Pe {
            data,
            import_rva: directory(1),
            clr_rva: directory(14),
            headers,
        })
    }

    /// File offset for an RVA, if it lands inside a section's raw data and
    /// the file has it.
    fn rva_to_off(&self, rva: u32) -> Option<usize> {
        self.headers
            .rva_to_offset(rva)
            .filter(|&off| off <= self.data.len())
    }
}

/// Recognised PE runtime packers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Packer {
    Nspack,
    Petite,
    Fsg,
    Aspack,
    Mew,
    Upack,
    WwPack,
    PeSpin,
    Yoda,
    /// A UPX-sectioned image the real UPX path declined, normally because the
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
    /// are *destroyed*, not hidden. No engine unpacks these (not exav, not
    /// ClamAV, not a perfect emulator), because there is no moment at which the
    /// original code exists in memory to recover. They are the three most common
    /// packers in current samples, so staying silent about them is the one thing
    /// worse than not unpacking them.
    VmProtect,
    Themida,
    Enigma,
}

impl Packer {
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
    // Section-name markers: the most reliable signal for these packers.
    for s in &pe.headers.sections {
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
    if let Some(off) = pe.rva_to_off(pe.headers.entry_point)
        && let Some(win) = crate::bytes::at(pe.data, off, 2)
    {
        // `BE xx xx xx xx` (mov esi, imm32) is the canonical FSG 2.0 stub
        // opener; require it to sit right at the entry point.
        if win[0] == 0xBE && fsg_stub_plausible(pe, off) {
            return Some(Packer::Fsg);
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
    let ep_section = pe.headers.sections.iter().find(|s| {
        let off = s.raw_pointer as usize;
        // `saturating_add`: `raw_pointer + raw_size` (both attacker-controlled u32s)
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
    // still carries the packer's section names (the names are evidence and are
    // not rewritten), so `identify` would recognise the packer a second time,
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
/// like: a linker writes 512-byte-aligned raw data at offsets that have
/// nothing to do with the virtual addresses.
fn is_memory_layout_dump(data: &[u8]) -> bool {
    let Some(pe) = Pe::parse(data) else {
        return false;
    };
    pe.headers.file_alignment >= 0x1000
        && pe.headers.sections.len() > 1
        && pe
            .headers
            .sections
            .iter()
            .all(|s| s.raw_size == 0 || s.raw_pointer == s.virtual_address)
}

/// Whether a PE looks like a runtime-packed image, for the files no named
/// packer matched.
///
/// This is what makes the emulator general rather than a list of packers: most
/// packers can be renamed, restubbed or stripped of their section names, but
/// none of them can hide the *shape* of a packed image. What they all share is
/// that the program on disk is not the program that runs, so the file carries
/// a section far larger in memory than on disk to unfold into, an entry point
/// in the last section rather than the first, an import table with a handful of
/// entries where a real program has hundreds, and an entry-point section marked
/// writable because the stub writes to itself.
///
/// No single signal decides it. Each one alone appears in honest software (a
/// large `.bss`, a small import table, a compressed resource), so they are
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
    let Some(ep_idx) = pe.headers.section_index(pe.headers.entry_point) else {
        // An entry point outside every section is itself conclusive: no linker
        // produces that.
        return true;
    };
    let ep = &pe.headers.sections[ep_idx];
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
    if pe.headers.sections.iter().any(|s| {
        !is_standard_section(&s.name) && s.raw_size >= 0x1000 && section_entropy(s, data) >= 7.0
    }) {
        score += 2;
    }
    if section_entropy(ep, data) >= 7.0 {
        score += 1;
    }
    // A section name generated per build. Packers that add a section either use
    // a fixed marker (`UPX1`, `.aspack`), matched by name elsewhere, or
    // randomise it to defeat exactly that, and a random name is as much of a
    // signature as a fixed one. Compilers do not emit `.OqvPZc8`.
    if pe
        .headers
        .sections
        .iter()
        .any(|s| s.raw_size >= 0x1000 && looks_random_name(&s.name))
    {
        score += 2;
    }
    // A section reserving far more memory than it occupies on disk: the
    // destination the packed payload unfolds into.
    if pe.headers.sections.iter().any(|s| {
        s.raw_size == 0 && s.virtual_size >= 0x1000
            || (s.raw_size > 0
                && s.virtual_size as u64 >= s.raw_size as u64 * 4
                && s.virtual_size >= 0x4000)
    }) {
        score += 1;
    }
    // Almost no imports. A packer resolves what it needs at run time, so the
    // static table holds only what the stub itself calls. A file with no import
    // directory at all is a different thing (a driver, a resource-only DLL)
    // and does not count: two weak signals should not be enough on their own.
    if pe.import_rva != 0 && import_count(&pe, data) <= 6 {
        score += 1;
    }

    // A managed assembly's entry point is a jump into the .NET runtime and its
    // payload is IL, so emulating it reaches nothing, but a *packed* .NET file
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
/// case, and a digit or a second case switch. Deliberately narrow: every
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
        .array_windows()
        .filter(|[a, b]| a.is_ascii_lowercase() && b.is_ascii_uppercase())
        .count();
    digits > 0 || switches >= 2
}

/// Shannon entropy of a section's raw bytes, over a bounded sample. Compressed
/// and encrypted data sits at 7.5-8.0; compiled code around 6.
fn section_entropy(s: &Section, data: &[u8]) -> f64 {
    const SAMPLE: usize = 64 << 10;
    let start = s.raw_pointer as usize;
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

/// Number of imported functions declared in the file's import table, capped:
/// the question is only "few or many".
fn import_count(pe: &Pe, data: &[u8]) -> u32 {
    const CAP: u32 = 64;
    let dir_rva = pe.import_rva;
    if dir_rva == 0 {
        return 0;
    }
    let Some(dir_off) = pe.rva_to_off(dir_rva) else {
        return 0;
    };
    let mut total = 0u32;
    for i in 0..32usize {
        let d = dir_off.saturating_add(i * 20);
        let Some(desc) = crate::bytes::at(data, d, 20) else {
            break;
        };
        let orig = u32::from_le_bytes([desc[0], desc[1], desc[2], desc[3]]);
        let first = u32::from_le_bytes([desc[16], desc[17], desc[18], desc[19]]);
        if orig == 0 && first == 0 {
            break;
        }
        let thunks = if orig != 0 { orig } else { first };
        let Some(mut off) = pe.rva_to_off(thunks) else {
            continue;
        };
        while let Some(v) = crate::bytes::at(data, off, 4) {
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

/// Maximum size of an unpacked PE (the budget cap further constrains this).
#[cfg(feature = "pe-emu")]
const MAX_INNER: usize = 128 << 20;

/// Attempt to recover and emit the original image from a packed PE, by running
/// its stub. Returns `Ok(None)` when nothing could be safely recovered (the
/// caller still scans the raw bytes).
pub(crate) fn extract_pepack(data: &[u8], budget: &mut Budget, visit: Sink) -> crate::Extracted {
    let Some(pe) = Pe::parse(data) else {
        return Ok(None);
    };
    let identified = identify(&pe);

    // The emulator, for everything except the virtualizers: for those
    // there is no original image in memory at any point, so running the stub
    // would burn the budget to reconstruct something that does not exist.
    #[cfg(feature = "pe-emu")]
    if !identified.is_some_and(Packer::is_virtualizer) {
        let label = identified.map(packer_name).unwrap_or("runtime");
        match emulated_unpack(data, budget, visit, label)? {
            Recovered::Halt(r) => return Ok(Some(r)),
            Recovered::Emitted => return Ok(None),
            Recovered::Nothing => {}
        }
    }

    let Some(packer) = identified else {
        // Nothing named it and the emulator recovered nothing: the file was
        // routed here on the generic packed-look heuristic, which is a guess.
        // Reporting it unsupported would turn every unusual-but-ordinary PE
        // into an UNSCANNABLE verdict, so it is simply scanned raw.
        return Ok(None);
    };
    {
        // Detected, but nothing recovered: no verifiable unpack, and we
        // fabricate nothing. The caller still scans the raw (packed) bytes, so a
        // signature written against the stub still fires; what is NOT examined
        // is the original image the stub will unfold at runtime.
        //
        // That unexamined payload has to be surfaced. Returning `Ok(None)` here
        // let a packed dropper scan as a clean OK, which is the one outcome the
        // scanner must never produce for content that is present but unread.
        // Reported as `unsupported`, so the verdict becomes UNSCANNABLE and the
        // member metadata still feeds `.cdb` matching.
        budget.count_entry()?;
        // The two tiers need different wording, because they are different
        // situations and a scanner that blurs them misleads. A compressor hides
        // an original image that exists and could be recovered; a virtualizer
        // translated the code at protect time, so there is no original image
        // anywhere: every byte present *was* scanned, but signatures written
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

/// What an unpacking attempt did, distinguishing "produced nothing" from
/// "produced a member the sink kept going past". A sink that collects every
/// member returns `None` for each one, so without that distinction a
/// successful unpack would be reported as if it had recovered nothing.
#[cfg(feature = "pe-emu")]
pub(crate) enum Recovered {
    Nothing,
    Emitted,
    Halt(crate::Stop),
}

/// Ceiling on the emulator's address space, and on the dump it produces.
///
/// These are deliberately far below the per-member buffer budget. An emulation
/// costs *both* at once (the page table while the stub runs, and the dump
/// afterwards), and it happens per packed member, at every nesting level, on
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
/// * `-emulated`: the stub transferred control to the reconstructed image. The
///   unpack ran to completion and the dump is the original program.
/// * `-emulated-partial`: the run stopped early with a substantial part of the
///   image rewritten. Worth scanning (the decompressed payload is in there), but
///   not the same as "this is the original program".
/// * `-emulated-allocation-N`: a PE image found in memory the stub allocated,
///   which is where a loader that never rewrites its own image puts the payload.
#[cfg(feature = "pe-emu")]
pub(crate) fn emulated_unpack(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink,
    label: &str,
) -> Result<Recovered, LimitHit> {
    budget.count_entry()?;
    let cap = budget.reserve()?.min(MAX_INNER as u64) as usize;
    let room = budget.pe_emulation_room();
    if room == 0 {
        return Err(budget.pe_emulation_exhausted());
    }
    let stub_steps = budget.limits.max_pe_stub_steps;
    let limits = x86::run::EmuLimits {
        max_ticks: stub_steps.min(room),
        max_idle_ticks: budget.limits.max_pe_idle_steps,
        max_dump: cap.min(MAX_EMU_DUMP),
        max_pages: cap.min(MAX_EMU_MEMORY) / exav_pe_emu::PAGE_SIZE,
        ..Default::default()
    };
    let report =
        crate::profile::timed("emu", data.len() as u64, || x86::run::unpack(data, &limits));
    budget.charge_pe_emulation(report.ticks);
    // Either budget ending the run leaves the image incomplete, and the scan
    // says so after the partial image is emitted. The scan-wide one is named
    // when it is the smaller, as it is then what ended the run.
    let cut_short = report.ticks >= limits.max_ticks;
    let ended = |budget: &Budget, done: Recovered| {
        if !cut_short {
            Ok(done)
        } else if room <= stub_steps {
            Err(budget.pe_emulation_exhausted())
        } else {
            Err(budget.pe_stub_exhausted())
        }
    };

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

    let fallback = if emitted {
        Recovered::Emitted
    } else {
        Recovered::Nothing
    };
    let Some(unpacked) = report.unpacked else {
        return ended(budget, fallback);
    };
    // The same output gate the static path uses: only a buffer that reads back
    // as a PE image is emitted. A run that ended mid-decompression leaves the
    // headers intact, so this passes for partial reconstructions too: what it
    // rejects is a dump whose headers the stub overwrote with something else,
    // where there is no way to tell code from rubble.
    if !looks_like_pe(&unpacked.data) {
        return ended(budget, fallback);
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
    ended(budget, Recovered::Emitted)
}

fn packer_name(p: Packer) -> &'static str {
    // The vendor's own capitalisation, and the single source of truth for it.
    // These strings reach the user twice (in the member name and, with
    // `--detect packed`, inside `Heuristics.Packed.<name>`), and a gateway
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

/// Output-validity gate: accept an unpacked buffer only if it reads back as a
/// plausible PE image (`MZ` + reachable `PE\0\0`): a dump whose headers the stub
/// overwrote is rejected here rather than handed to the matcher as data.
#[cfg(feature = "pe-emu")]
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
    // 0x40 here (a rule of thumb, not a rule) silently rejected every image
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
    use crate::{Format, Limits, extract};

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
    /// payload, with the entry point in the latter. The two do not overlap
    /// (the destination ends where the stub section begins) because a stub that
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
        // file is routed to the emulator by its *shape* (entry point in a
        // writable section, an empty section reserved to unfold into, no
        // imports), and the payload comes back from running the stub.
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
        // Running a virtualizer's stub cannot produce an original image (there
        // isn't one), so the budget is not spent trying. The file is reported,
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
        assert!(
            extract(Format::PePacked, b"\x7fELF..", &mut b)
                .unwrap()
                .is_empty()
        );
    }

    #[cfg(feature = "pe-emu")]
    #[test]
    fn a_named_packer_is_emulated_and_the_dump_carries_its_name() {
        // Petite, FSG and NsPack were once unpacked by a static decoder; their
        // stubs now run like any other, and the member is named after the
        // packer the section names identify.
        const MARKER: &[u8] = b"EXAV_NAMED_PACKER_MARKER";
        let mut plain = Vec::new();
        while plain.len() < 0xc000 {
            plain.extend_from_slice(MARKER);
        }
        let cipher: Vec<u8> = plain.iter().map(|b| b ^ 0x5a).collect();
        let mut stub: Vec<u8> = vec![0xbe];
        stub.extend_from_slice(&0x0040_f000u32.to_le_bytes());
        stub.push(0xbf);
        stub.extend_from_slice(&0x0040_1000u32.to_le_bytes());
        stub.push(0xb9);
        stub.extend_from_slice(&(cipher.len() as u32).to_le_bytes());
        stub.extend_from_slice(&[0xac, 0x34, 0x5a, 0xaa, 0xe2, 0xfa]);
        let jmp_at = 0x0040_e000u32 + stub.len() as u32;
        stub.push(0xe9);
        stub.extend_from_slice(&0x0040_1000u32.wrapping_sub(jmp_at + 5).to_le_bytes());

        let mut file = packed_pe(&stub, &cipher);
        let sec_table = 0x80 + 24 + 0xe0;
        file[sec_table..sec_table + 8].copy_from_slice(b".nsp0\0\0\0");
        file[sec_table + 40..sec_table + 48].copy_from_slice(b".nsp1\0\0\0");
        assert!(is_pepack(&file));

        let mut b = Budget::new(Limits {
            max_extracted_bytes: 1 << 30,
            max_buffer_bytes: 1 << 30,
            ..Default::default()
        });
        let entries = extract(Format::PePacked, &file, &mut b).unwrap();
        assert_eq!(entries.len(), 1, "one reconstructed image");
        assert_eq!(entries[0].name, "NsPack-emulated");
        assert!(entries[0].data.windows(MARKER.len()).any(|w| w == MARKER));
    }

    #[test]
    fn a_detected_packer_that_does_not_unpack_is_reported_not_silently_dropped() {
        // An ASPack-named file whose stub unpacks nothing. Nothing may be *fabricated*
        // (the entry carries no data), but the file must not scan clean either:
        // the original image is present in the packed bytes and was not
        // examined, so it is surfaced as unsupported (→ UNSCANNABLE).
        //
        // The opposite contract (returning no entries) would let a packed
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
            let _ = extract(Format::PePacked, &junk, &mut b);
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

    #[cfg(feature = "pe-emu")]
    #[test]
    fn looks_like_pe_extreme_e_lfanew_does_not_panic() {
        // Dump whose e_lfanew is u32::MAX: `e + 24` in looks_like_pe
        // must not overflow-panic on 32-bit targets; the buffer is rejected.
        let mut out = vec![0u8; 0x40];
        out[..2].copy_from_slice(b"MZ");
        out[0x3C..0x40].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        assert!(!looks_like_pe(&out));
    }

    /// Where `build_pe` puts the optional header and the section table.
    const OPT: usize = 0x80 + 24;
    const TABLE: usize = OPT + 0xe0;

    fn set32(d: &mut [u8], at: usize, v: u32) {
        d[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    /// A PE with one section at RVA 0x1000, `vsize` long in memory, `raw`
    /// bytes in the file, holding an import table at its start and its
    /// thunks (three imports) `thunks` bytes into the section.
    fn pe_with_imports(vsize: u32, raw: usize, thunks: usize) -> Vec<u8> {
        let mut body = vec![0u8; raw];
        let rva = (0x1000 + thunks as u32).to_le_bytes();
        body[..4].copy_from_slice(&rva);
        body[16..20].copy_from_slice(&rva);
        for i in 0..3 {
            body[thunks + i * 4..thunks + 4 + i * 4].copy_from_slice(&1u32.to_le_bytes());
        }
        let mut d = build_pe(&[b".text"], &body, 0);
        set32(&mut d, TABLE + 8, vsize);
        set32(&mut d, OPT + 92, 16);
        set32(&mut d, OPT + 96 + 8, 0x1000);
        d
    }

    /// An RVA past the virtual size is read from the file while it is in
    /// the page of the virtual size and in the raw data: an entry point
    /// there is read, one past the page is not.
    #[test]
    fn an_rva_past_the_virtual_size_is_mapped_to_the_end_of_its_page() {
        let mut body = vec![0u8; 0x200];
        // `mov esi, imm32` at RVA 0x1010.
        body[0x10..0x15].copy_from_slice(&[0xbe, 1, 2, 3, 4]);
        let mut d = build_pe(&[b".text"], &body, 0);
        set32(&mut d, TABLE + 8, 0x10);
        set32(&mut d, OPT + 16, 0x1010);
        let pe = Pe::parse(&d).unwrap();
        assert_eq!(identify(&pe), Some(Packer::Fsg));

        // The raw data goes on past the page: not mapped there.
        let mut d = build_pe(&[b".text"], &[0u8; 0x2000], 0);
        set32(&mut d, TABLE + 8, 0x10);
        let pe = Pe::parse(&d).unwrap();
        assert!(pe.rva_to_off(0x1fff).is_some());
        assert!(pe.rva_to_off(0x2000).is_none());
    }

    /// An entry point in the rest of the page of its section is in the
    /// section.
    #[test]
    fn a_section_reaches_to_the_end_of_its_page() {
        let mut d = build_pe(&[b".text"], &[0u8; 0x200], 0);
        set32(&mut d, TABLE + 8, 0x10);
        set32(&mut d, OPT + 16, 0x1100);
        assert!(!looks_packed(&d));
        // Past the page, no section has it.
        set32(&mut d, OPT + 16, 0x2000);
        assert!(looks_packed(&d));
    }

    fn imports(d: &[u8]) -> u32 {
        import_count(&Pe::parse(d).unwrap(), d)
    }

    /// The thunks of an import table are read while they are in the page of
    /// the virtual size of their section.
    #[test]
    fn imports_are_read_to_the_end_of_the_page_of_the_virtual_size() {
        assert_eq!(imports(&pe_with_imports(0x200, 0x200, 0x100)), 3);
        assert_eq!(imports(&pe_with_imports(0x20, 0x200, 0x100)), 3);
        assert_eq!(imports(&pe_with_imports(0x20, 0x2000, 0xf00)), 3);
        assert_eq!(imports(&pe_with_imports(0x20, 0x2000, 0x1100)), 0);
    }

    /// The loader maps the headers: an import table below the size of
    /// headers is read.
    #[test]
    fn an_import_table_in_the_headers_is_read() {
        let mut d = build_pe(&[b".text"], &[0u8; 0x100], 0);
        // The room between the section table, which ends at 0x1a0, and 0x200.
        set32(&mut d, 0x1a0, 0x1c8);
        set32(&mut d, 0x1a0 + 16, 0x1c8);
        for i in 0..3 {
            set32(&mut d, 0x1c8 + i * 4, 1);
        }
        set32(&mut d, OPT + 92, 16);
        set32(&mut d, OPT + 96 + 8, 0x1a0);
        assert_eq!(imports(&d), 0);
        set32(&mut d, OPT + 60, 0x200);
        assert_eq!(imports(&d), 3);
    }

    /// An RVA is read from the first section that maps it, which is not
    /// always the first that holds it.
    #[test]
    fn an_rva_is_read_from_the_first_section_that_maps_it() {
        // Two sections overlap: the first has no raw data, the second does.
        let mut body = vec![0u8; 0x100];
        body[..4].copy_from_slice(&0x1040u32.to_le_bytes());
        body[16..20].copy_from_slice(&0x1040u32.to_le_bytes());
        for i in 0..3 {
            body[0x40 + i * 4..0x44 + i * 4].copy_from_slice(&1u32.to_le_bytes());
        }
        let mut d = build_pe(&[b".a", b".b"], &body, 1);
        set32(&mut d, TABLE + 40 + 12, 0x1000);
        set32(&mut d, OPT + 92, 16);
        set32(&mut d, OPT + 96 + 8, 0x1000);
        assert_eq!(imports(&d), 3);
    }

    /// The data directories of a PE32+ are where PE32+ puts them.
    #[test]
    fn a_pe32_plus_has_its_directories_at_its_own_offset() {
        let mut d = pe_with_imports(0x200, 0x200, 0x100);
        set32(&mut d, OPT + 92, 0);
        set32(&mut d, OPT + 96 + 8, 0);
        d[OPT..OPT + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        set32(&mut d, OPT + 108, 16);
        set32(&mut d, OPT + 112 + 8, 0x1000);
        let pe = Pe::parse(&d).unwrap();
        assert_eq!(pe.import_rva, 0x1000);
        assert_eq!(imports(&d), 3);
    }

    /// A field past the end of the optional header is not read from the
    /// bytes that follow it, which are the section table.
    #[test]
    fn the_optional_header_ends_where_it_says() {
        let mut d = pe_with_imports(0x200, 0x200, 0x100);
        // 0x60 bytes: the directory count is the last field inside.
        d[OPT - 24 + 4 + 16..OPT - 24 + 4 + 18].copy_from_slice(&0x60u16.to_le_bytes());
        d.copy_within(TABLE..TABLE + 40, OPT + 0x60);
        let pe = Pe::parse(&d).unwrap();
        assert_eq!(pe.import_rva, 0);
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
