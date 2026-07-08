//! PE runtime-packer unpacking.
//!
//! Many Windows malware families ship packed by a runtime packer that wraps the
//! original image in a small decompressor stub; the on-disk bytes are the packed
//! form, so signatures on the *original* code only match once the payload is
//! decompressed. UPX is handled separately (see `upx.rs`). This module covers
//! the next tier of common packers.
//!
//! Two groups, handled differently:
//!
//! * **aPLib-compressed packers** — Petite 2.x, FSG 2.0 and NsPack wrap the
//!   original image in an [`aplib`] stream. For these we locate the compressed
//!   stream and decompress it, then **accept the result only if it reconstructs
//!   a valid PE image** (`MZ`/`PE\0\0`). That output-validity gate means we do
//!   not need packer-version-exact stub reverse-engineering to be *safe*: a
//!   wrong guess fails the gate and is discarded, never fed to the matcher as
//!   bogus data. When it passes, the recovered original PE is emitted for
//!   scanning.
//!
//! * **Protector/encryptor packers** — Aspack, MEW, Upack, wwpack32, PeSpin and
//!   Yoda's Cryptor use bespoke or emulation-defeating schemes. We *detect* them
//!   (so the packer identity is available and the aPLib path is skipped) but do
//!   not synthesise an unpacked image — decoding them correctly needs CPU
//!   emulation, and emitting a mis-decoded buffer would be worse than not
//!   trying. The raw file is still scanned by the caller regardless, so packer
//!   signatures continue to match; this module simply never fabricates data it
//!   cannot verify.
//!
//! `#![forbid(unsafe_code)]` (crate root): all PE parsing is bounds-checked and
//! returns `None`/empty rather than panicking on malformed input.

use crate::{Budget, Entry, LimitHit, Sink};

use super::aplib;

/// A parsed subset of a PE file — just what packer detection and stream location
/// need. All offsets are validated against `len` at parse time.
struct Pe<'a> {
    data: &'a [u8],
    /// Address of entry point (RVA).
    entry_rva: u32,
    sections: Vec<Section>,
}

struct Section {
    name: [u8; 8],
    vaddr: u32,
    vsize: u32,
    raw_ptr: u32,
    raw_size: u32,
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
            });
        }
        Some(Pe {
            data,
            entry_rva,
            sections,
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
}

impl Packer {
    /// Whether this packer wraps the original image in an aPLib stream we try to
    /// decompress.
    fn is_aplib(self) -> bool {
        matches!(self, Packer::Nspack | Packer::Petite | Packer::Fsg)
    }
}

/// Identify the packer from section-name and entry-point signatures. Kept
/// conservative (strong markers only) to avoid mis-flagging ordinary PEs; a
/// miss just means the file is scanned raw, exactly as before.
fn identify(pe: &Pe) -> Option<Packer> {
    // Section-name markers — the most reliable signal for these packers.
    for s in &pe.sections {
        let n = &s.name;
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

/// True if `data` is a PE packed by a runtime packer this module recognises.
/// Used by the scan path to route the file here (in addition to the raw scan).
pub(crate) fn is_pepack(data: &[u8]) -> bool {
    Pe::parse(data).and_then(|pe| identify(&pe)).is_some()
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
    let Some(packer) = identify(&pe) else {
        return Ok(None);
    };
    if !packer.is_aplib() {
        // Detected, but not an aPLib family — no verifiable unpack. The caller
        // scans the raw file; we fabricate nothing.
        return Ok(None);
    }

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
                return Ok(visit(Entry::new(name, out), budget));
            }
        }
    }
    Ok(None)
}

fn packer_name(p: Packer) -> &'static str {
    match p {
        Packer::Nspack => "nspack",
        Packer::Petite => "petite",
        Packer::Fsg => "fsg",
        Packer::Aspack => "aspack",
        Packer::Mew => "mew",
        Packer::Upack => "upack",
        Packer::WwPack => "wwpack32",
        Packer::PeSpin => "pespin",
        Packer::Yoda => "yoda",
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
    // Reject absurd e_lfanew; require the PE signature to be present and a sane
    // section count to follow, so a stray "MZ..." payload can't pass.
    // `checked_add` so a huge `e_lfanew` can't overflow on 32-bit targets.
    let Some(e_end) = e.checked_add(24) else {
        return false;
    };
    if e < 0x40 || e_end > out.len() {
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
            max_total_bytes: 1 << 30,
            max_entry_bytes: 1 << 30,
            max_ratio: u64::MAX,
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
    fn detected_non_aplib_packer_emits_nothing() {
        // Aspack is detected but not decompressed: no fabricated member.
        let outer = build_pe(&[b".aspack", b".adata"], b"whatever", 0);
        assert!(is_pepack(&outer));
        let mut b = Budget::new(Limits::default());
        let entries = extract(Format::PePacked, &outer, &mut b).unwrap();
        assert!(entries.is_empty());
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
