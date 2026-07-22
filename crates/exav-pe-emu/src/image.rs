//! Loading a PE into the emulator's address space, and dumping it back out.
//!
//! Loading follows what the Windows loader does to the parts a stub can
//! observe: headers at the image base, each section at its virtual address,
//! zero-fill where the virtual size exceeds the raw size. Nothing else — no
//! relocations (the emulator maps at the image's preferred base, so there are
//! none to apply), no import binding (the stub resolves its own), no TLS
//! callbacks.
//!
//! Dumping is the reverse, with one deliberate difference: the dump is written
//! in **memory layout**, with `PointerToRawData == VirtualAddress` and the file
//! alignment raised to the section alignment. That is what makes the dump a
//! valid PE that the scanner's own parser and every signature can read, without
//! having to reconstruct the packer's original section table. The imports still
//! point at the emulator's trap addresses, which is irrelevant for scanning: no
//! one runs this file, it is matched against.

use crate::mem::Mem;

pub struct Section {
    /// The eight raw name bytes. Used to tell a linker's section from one a
    /// packer added, which is one of the signals that routes a file here.
    pub name: [u8; 8],
    pub vaddr: u32,
    pub vsize: u32,
    pub raw_ptr: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

pub struct PeImage {
    pub base: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub entry_rva: u32,
    pub section_align: u32,
    /// File alignment. The loader rounds `PointerToRawData` *down* to this, and
    /// packers rely on it: NSPack points its entry section at an unaligned
    /// offset holding zeros, so a loader that takes the field literally
    /// executes nothing while Windows executes the code at the rounded-down
    /// offset.
    pub file_align: u32,
    /// Whether the image is a DLL. Its entry point is `DllMain`, which takes
    /// three arguments — a stub that reads them off an empty stack faults
    /// immediately.
    pub is_dll: bool,
    /// Import directory (RVA, size). A packed image imports the two or three
    /// functions its stub needs, and the *loader* — not the stub — fills those
    /// slots in. Emulating that binding is what lets the stub call them.
    pub import_dir: (u32, u32),
    /// CLR header directory (RVA, size). A managed assembly has no x86 stub to
    /// run — its "entry point" is a jump into `mscoree` — so there is nothing
    /// for the emulator to do with one.
    pub clr_dir: (u32, u32),
    pub sections: Vec<Section>,
    /// Offset of the section table within the file, so the dump can patch it.
    sec_table_off: usize,
    /// Offset of the PE signature.
    pe_off: usize,
}

fn u16_at(d: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*d.get(o)?, *d.get(o + 1)?]))
}
fn u32_at(d: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *d.get(o)?,
        *d.get(o + 1)?,
        *d.get(o + 2)?,
        *d.get(o + 3)?,
    ]))
}

impl PeImage {
    /// Parse a 32-bit PE. Returns `None` for anything the emulator cannot run:
    /// a non-PE, a PE32+ (the interpreter is 32-bit), or headers that do not
    /// fit the file.
    pub fn parse(data: &[u8]) -> Option<PeImage> {
        if data.len() < 0x40 || &data[..2] != b"MZ" {
            return None;
        }
        let pe_off = u32_at(data, 0x3c)? as usize;
        let coff = pe_off.checked_add(4)?;
        if data.get(pe_off..coff)? != b"PE\0\0" {
            return None;
        }
        let machine = u16_at(data, coff)?;
        let num_sections = u16_at(data, coff + 2)? as usize;
        let opt_size = u16_at(data, coff + 16)? as usize;
        let is_dll = u16_at(data, coff + 18)? & 0x2000 != 0;
        if machine != 0x14c || num_sections == 0 || num_sections > 96 {
            return None;
        }
        let opt = coff + 20;
        if u16_at(data, opt)? != 0x10b {
            return None; // PE32+ or ROM image
        }
        let entry_rva = u32_at(data, opt + 16)?;
        let base = u32_at(data, opt + 28)?;
        let section_align = u32_at(data, opt + 32)?.max(0x1000);
        let file_align = u32_at(data, opt + 36).unwrap_or(0x200);
        let size_of_image = u32_at(data, opt + 56)?;
        let size_of_headers = u32_at(data, opt + 60)?;
        let sec_table_off = opt + opt_size;
        let num_dirs = u32_at(data, opt + 92).unwrap_or(0);
        let import_dir = if num_dirs >= 2 {
            (
                u32_at(data, opt + 104).unwrap_or(0),
                u32_at(data, opt + 108).unwrap_or(0),
            )
        } else {
            (0, 0)
        };
        let clr_dir = if num_dirs >= 15 {
            (
                u32_at(data, opt + 96 + 14 * 8).unwrap_or(0),
                u32_at(data, opt + 96 + 14 * 8 + 4).unwrap_or(0),
            )
        } else {
            (0, 0)
        };

        let mut sections = Vec::with_capacity(num_sections);
        for i in 0..num_sections {
            let s = sec_table_off.checked_add(i * 40)?;
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
        // A `SizeOfImage` that does not cover the sections is common in packed
        // files; take the larger of the two so nothing is mapped short.
        let span = sections
            .iter()
            .map(|s| {
                s.vaddr
                    .saturating_add(s.vsize.max(s.raw_size))
                    .saturating_add(section_align - 1)
                    & !(section_align - 1)
            })
            .max()
            .unwrap_or(0);
        let size_of_image = size_of_image.max(span).max(0x1000);

        Some(PeImage {
            base,
            size_of_image,
            size_of_headers: size_of_headers.min(0x1000),
            entry_rva,
            section_align,
            file_align,
            is_dll,
            import_dir,
            clr_dir,
            sections,
            sec_table_off,
            pe_off,
        })
    }

    /// Index of the section containing `rva`.
    pub fn section_of(&self, rva: u32) -> Option<usize> {
        self.sections.iter().position(|s| {
            let end = s
                .vaddr
                .saturating_add(s.vsize.max(s.raw_size).max(self.section_align));
            rva >= s.vaddr && rva < end
        })
    }

    /// Map the image at its preferred base: headers, then every section with
    /// its raw bytes and the zero fill beyond them.
    pub fn map_into(&self, data: &[u8], mem: &mut Mem) -> Result<(), MapFailed> {
        mem.map(self.base, self.size_of_image)
            .map_err(|_| MapFailed)?;
        let hdr_len = (self.size_of_headers as usize).min(data.len());
        mem.write_bytes(self.base, &data[..hdr_len])
            .map_err(|_| MapFailed)?;
        for s in &self.sections {
            let vlen = s.vsize.max(s.raw_size);
            if vlen == 0 {
                continue;
            }
            let addr = self.base.wrapping_add(s.vaddr);
            mem.map(addr, vlen).map_err(|_| MapFailed)?;
            // What the loader reads, not what the field says. It rounds
            // `PointerToRawData` down to a **512-byte** boundary — the sector
            // size, not the declared file alignment — and packers rely on it
            // both ways: NSPack points its entry section at an unaligned offset
            // holding zeros (the code lives at the rounded-down offset), while
            // FSG declares a 4 KiB file alignment with a section at 0xe00 that
            // must *not* be rounded to 4 KiB. An image whose file alignment is
            // below 512 is mapped exactly as it lies.
            let start = if self.file_align >= 0x200 {
                (s.raw_ptr & !0x1ffu32) as usize
            } else {
                s.raw_ptr as usize
            };
            let end = start.saturating_add(s.raw_size as usize).min(data.len());
            if start < end {
                let bytes = &data[start..end];
                let take = bytes.len().min(vlen as usize);
                mem.write_bytes(addr, &bytes[..take])
                    .map_err(|_| MapFailed)?;
            }
        }
        // The image as loaded is the baseline: from here on, a dirty page means
        // the stub wrote it.
        mem.clear_dirty(self.base, self.size_of_image);
        mem.watch(self.base, self.size_of_image);
        Ok(())
    }

    /// End of the part of the image worth dumping: past the last section that
    /// carries data, rounded to the section alignment.
    fn content_end(&self) -> u32 {
        let mut end = self.size_of_headers.max(self.section_align);
        for s in &self.sections {
            let len = s.vsize.max(s.raw_size);
            end = end.max(align_up(s.vaddr.saturating_add(len), self.section_align));
        }
        end
    }

    /// Rebuild a PE file from the emulated memory, with `oep_rva` as the entry
    /// point. Sections are written at their virtual addresses, so the result is
    /// a memory-layout dump: the same shape a debugger's "dump process" gives.
    pub fn dump(&self, mem: &mut Mem, file: &[u8], oep_rva: u32, cap: usize) -> Option<Vec<u8>> {
        // Only the part of the image that holds content is written out. A
        // packed file routinely declares a `SizeOfImage` far larger than
        // anything it fills — the destination section is reserved at its
        // uncompressed size — and copying tens of megabytes of never-touched
        // zeros costs memory and buys the scanner nothing.
        let total = self.content_end().min(self.size_of_image) as usize;
        if total > cap || total < 0x40 {
            return None;
        }
        let mut out = mem.snapshot(self.base, total);
        let pe = self.pe_off;
        if out.len() < pe + 24 + 0xe0 {
            return None;
        }
        // A stub is free to overwrite its own headers once the loader is done
        // with them, and several do precisely so that a memory dump is not a
        // valid PE. The header bytes are not the payload, though: the *file*
        // still has them, and they parsed, so the dump takes them from there
        // rather than throwing away a reconstructed image over a wiped `MZ`.
        if out[..2] != *b"MZ" || out[pe..pe + 4] != *b"PE\0\0" {
            let hdr_len = (self.size_of_headers as usize)
                .min(file.len())
                .min(out.len());
            if hdr_len < pe + 24 + 0xe0 {
                return None;
            }
            out[..hdr_len].copy_from_slice(&file[..hdr_len]);
        }
        let opt = pe + 24;
        // File alignment := section alignment, so raw offsets equal RVAs.
        write_u32(&mut out, opt + 16, oep_rva); // AddressOfEntryPoint
        write_u32(&mut out, opt + 36, self.section_align); // FileAlignment
        write_u32(&mut out, opt + 56, self.size_of_image); // SizeOfImage
        write_u32(&mut out, opt + 60, self.section_align); // SizeOfHeaders
        for (i, s) in self.sections.iter().enumerate() {
            let off = self.sec_table_off + i * 40;
            if off + 40 > out.len() {
                break;
            }
            let vlen = align_up(s.vsize.max(s.raw_size), self.section_align);
            let vlen = vlen.min(self.size_of_image.saturating_sub(s.vaddr));
            write_u32(&mut out, off + 16, vlen); // SizeOfRawData
            write_u32(&mut out, off + 20, s.vaddr); // PointerToRawData
        }
        Some(out)
    }
}

fn write_u32(buf: &mut [u8], off: usize, v: u32) {
    if off + 4 <= buf.len() {
        buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
}

fn align_up(v: u32, align: u32) -> u32 {
    v.saturating_add(align - 1) & !(align - 1)
}

/// The image did not fit the emulator's page budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapFailed;

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal but real PE32: two sections, the second holding `body`.
    pub fn build_pe(names: &[&[u8]], body: &[u8], body_section: usize) -> Vec<u8> {
        let num = names.len().max(1);
        let pe_off = 0x80usize;
        let opt_size = 0xe0usize;
        let sec_table = pe_off + 24 + opt_size;
        let headers_end = sec_table + num * 40;
        let raw_align = |x: usize| (x + 0x1ff) & !0x1ff;
        let body_raw = raw_align(headers_end.max(0x200));
        let mut d = vec![0u8; body_raw + raw_align(body.len().max(1))];
        d[..2].copy_from_slice(b"MZ");
        d[0x3c..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
        d[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
        let coff = pe_off + 4;
        d[coff..coff + 2].copy_from_slice(&0x14cu16.to_le_bytes());
        d[coff + 2..coff + 4].copy_from_slice(&(num as u16).to_le_bytes());
        d[coff + 16..coff + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());
        let opt = coff + 20;
        d[opt..opt + 2].copy_from_slice(&0x10bu16.to_le_bytes());
        d[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry
        d[opt + 28..opt + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes()); // base
        d[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // sect align
        d[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes()); // file align
        d[opt + 56..opt + 60].copy_from_slice(&(0x1000u32 * (num as u32 + 1)).to_le_bytes());
        d[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes());
        for i in 0..num {
            let s = sec_table + i * 40;
            let name = names.get(i).copied().unwrap_or(b".text");
            let n = name.len().min(8);
            d[s..s + n].copy_from_slice(&name[..n]);
            let (rp, rs) = if i == body_section {
                (body_raw as u32, body.len() as u32)
            } else {
                (body_raw as u32, 0)
            };
            d[s + 8..s + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // vsize
            d[s + 12..s + 16].copy_from_slice(&(0x1000u32 * (i as u32 + 1)).to_le_bytes());
            d[s + 16..s + 20].copy_from_slice(&rs.to_le_bytes());
            d[s + 20..s + 24].copy_from_slice(&rp.to_le_bytes());
            d[s + 36..s + 40].copy_from_slice(&0xe000_0020u32.to_le_bytes());
        }
        d[body_raw..body_raw + body.len()].copy_from_slice(body);
        d
    }

    #[test]
    fn maps_sections_at_their_virtual_addresses() {
        let file = build_pe(&[b".text", b".data"], b"PAYLOAD", 1);
        let pe = PeImage::parse(&file).unwrap();
        let mut mem = Mem::new(256);
        pe.map_into(&file, &mut mem).unwrap();
        assert_eq!(&mem.snapshot(0x0040_2000, 7), b"PAYLOAD");
        assert_eq!(&mem.snapshot(0x0040_0000, 2), b"MZ", "headers are mapped");
        assert!(
            !mem.is_dirty(0x0040_2000),
            "loading the file does not count as the stub writing"
        );
    }

    #[test]
    fn rejects_what_the_interpreter_cannot_run() {
        assert!(PeImage::parse(b"not a pe").is_none());
        let mut file = build_pe(&[b".text"], b"x", 0);
        // Turn it into a PE32+: the emulator is 32-bit only.
        let opt = 0x80 + 24;
        file[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        assert!(PeImage::parse(&file).is_none());
    }

    #[test]
    fn a_dump_is_a_valid_pe_in_memory_layout() {
        let file = build_pe(&[b".text", b".data"], b"PAYLOAD", 1);
        let pe = PeImage::parse(&file).unwrap();
        let mut mem = Mem::new(256);
        pe.map_into(&file, &mut mem).unwrap();
        // Pretend the stub decompressed something into .text.
        mem.write_bytes(0x0040_1000, b"ORIGINAL CODE").unwrap();
        let dump = pe.dump(&mut mem, &file, 0x1000, 1 << 20).unwrap();

        let re = PeImage::parse(&dump).expect("the dump re-parses as a PE");
        assert_eq!(re.entry_rva, 0x1000);
        let text = &re.sections[0];
        assert_eq!(
            text.raw_ptr, text.vaddr,
            "raw offsets equal RVAs in a memory-layout dump"
        );
        let at = text.raw_ptr as usize;
        assert_eq!(&dump[at..at + 13], b"ORIGINAL CODE");
    }

    #[test]
    fn a_dump_larger_than_the_cap_is_refused() {
        let file = build_pe(&[b".text"], b"x", 0);
        let pe = PeImage::parse(&file).unwrap();
        let mut mem = Mem::new(256);
        pe.map_into(&file, &mut mem).unwrap();
        assert!(pe.dump(&mut mem, &file, 0x1000, 16).is_none());
    }
}
