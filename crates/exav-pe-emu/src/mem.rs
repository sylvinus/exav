//! Sparse 32-bit address space for the unpacking emulator.
//!
//! A packer stub runs against a flat 4 GiB address space of which it touches a
//! few megabytes: its own image, a stack, a scratch allocation or two. Backing
//! that with a page table rather than one big buffer is what keeps a hostile
//! `SizeOfImage` (up to 4 GiB) from being a memory bomb — pages are allocated
//! only when they are first touched, and the page count is capped.
//!
//! Two properties matter beyond plain load/store:
//!
//! * **Mapped-ness is enforced, protection is not.** An access to an unmapped
//!   page is a fault that stops emulation; a write to a page the PE marked
//!   read-only is allowed. Packers routinely rewrite their own code section
//!   after calling `VirtualProtect`, and enforcing page protection would only
//!   produce faults on files that run fine on Windows.
//! * **Every page remembers whether it was written.** That is the signal the
//!   unpacker uses to decide where the original image was reconstructed: a jump
//!   into a page the stub wrote is the classic tail transfer to the original
//!   entry point.

use std::collections::HashMap;

/// Page size of the emulated machine. x86 pages are 4 KiB, and packers align
/// their `VirtualAlloc` requests to it.
pub const PAGE_SIZE: usize = 0x1000;
const PAGE_SHIFT: u32 = 12;
const PAGE_MASK: u32 = PAGE_SIZE as u32 - 1;

/// An access that could not be serviced. Carries the address so the caller can
/// report where the stub went wrong (useful when triaging a packer that does
/// not unpack).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fault {
    pub addr: u32,
    pub write: bool,
}

pub type MemResult<T> = Result<T, Fault>;

struct Page {
    bytes: Box<[u8; PAGE_SIZE]>,
    /// Set on the first write. Never cleared: the question the unpacker asks is
    /// "did the stub produce these bytes", and an overwrite followed by a
    /// restore is still stub-produced.
    dirty: bool,
    /// Whether an instruction has been fetched from this page. A write to such
    /// a page is self-modifying code, and invalidates the decode cache.
    executed: bool,
}

/// The emulator's address space.
pub struct Mem {
    pages: Vec<Page>,
    /// Page number (`addr >> 12`) to slot in `pages`.
    index: HashMap<u32, u32>,
    /// Hard cap on resident pages; hitting it is a budget stop, not a fault.
    max_pages: usize,
    /// Single-entry lookup cache. Emulated code has extreme page locality (a
    /// decompression loop walks one source and one destination page for
    /// thousands of instructions), so this removes most hash lookups.
    cache_page: u32,
    cache_slot: u32,
    cached: bool,
    /// Page range whose writes are counted (the loaded image), and the count.
    /// Maintained as pages are first written so that "how much has the stub
    /// rebuilt so far" is a field read rather than a walk over the image.
    watch: Option<(u32, u32)>,
    watch_dirty: u32,
    /// Bumped when a page code has been fetched from is written to.
    code_gen: u64,
    /// Pages written for the first time, anywhere in the address space.
    dirty_pages: u32,
    /// Which pages have been written recently, as a 64-bit fingerprint
    /// (`1 << (page % 64)`). This is the emulator's measure of *progress*, and
    /// it is deliberately "how many different pages", not "how many bytes" or
    /// "how many new pages":
    ///
    /// * A stub still unpacking sweeps across its destination, so it lights up
    ///   many bits — including in a second pass over pages it has already
    ///   written, which relocation and import fixups do and which a
    ///   count-new-pages measure would read as no progress at all.
    /// * A stub spinning in an anti-emulation loop writes the same one or two
    ///   locations forever, so it lights up one or two bits however many bytes
    ///   it moves.
    recent_pages: u64,
}

impl Mem {
    pub fn new(max_pages: usize) -> Self {
        Self {
            pages: Vec::new(),
            index: HashMap::new(),
            max_pages,
            cache_page: 0,
            cache_slot: 0,
            cached: false,
            watch: None,
            watch_dirty: 0,
            code_gen: 0,
            dirty_pages: 0,
            recent_pages: 0,
        }
    }

    /// Count writes into `addr..addr+len` from now on. Called once the image is
    /// loaded, so the count means "pages the stub produced".
    pub fn watch(&mut self, addr: u32, len: u32) {
        self.watch = Some((addr >> PAGE_SHIFT, addr.saturating_add(len) >> PAGE_SHIFT));
        self.watch_dirty = 0;
    }

    /// Bytes of the watched range the stub has written so far.
    pub fn watched_dirty_bytes(&self) -> u64 {
        self.watch_dirty as u64 * PAGE_SIZE as u64
    }

    /// How many distinct pages (modulo 64) have been written since the last
    /// call, which also clears the window.
    #[inline]
    pub fn take_write_spread(&mut self) -> u32 {
        let n = self.recent_pages.count_ones();
        self.recent_pages = 0;
        n
    }

    /// Note a page becoming dirty, for the watched-range counter.
    #[inline]
    fn count_dirty(&mut self, page: u32) {
        self.dirty_pages += 1;
        if let Some((lo, hi)) = self.watch {
            if page >= lo && page < hi {
                self.watch_dirty += 1;
            }
        }
    }

    /// Generation counter for executable memory. It advances whenever a page an
    /// instruction has been fetched from is written, which is the only event
    /// that can make a decoded instruction stale.
    #[inline]
    pub fn code_generation(&self) -> u64 {
        self.code_gen
    }

    /// Whether an instruction has ever been fetched from the page holding
    /// `addr`. A jump into a page that was written but never executed is the
    /// tail transfer into freshly unpacked code — including for the packers
    /// that unpack *inside* the section their stub lives in, where no
    /// section-level rule can see it.
    #[inline]
    pub fn was_executed(&self, addr: u32) -> bool {
        match self.index.get(&(addr >> PAGE_SHIFT)) {
            Some(&slot) => self.pages[slot as usize].executed,
            None => false,
        }
    }

    /// Record that code was fetched from the page holding `addr`.
    #[inline]
    pub fn mark_executed(&mut self, addr: u32) {
        if let Some(slot) = self.slot(addr >> PAGE_SHIFT) {
            self.pages[slot as usize].executed = true;
        }
    }

    /// Whether another page may be allocated. The caller stops the emulation
    /// (rather than faulting) when this goes false, because running out of the
    /// page budget says nothing about the stub's correctness.
    pub fn at_capacity(&self) -> bool {
        self.pages.len() >= self.max_pages
    }

    #[inline]
    fn slot(&mut self, page: u32) -> Option<u32> {
        if self.cached && self.cache_page == page {
            return Some(self.cache_slot);
        }
        let slot = *self.index.get(&page)?;
        self.cache_page = page;
        self.cache_slot = slot;
        self.cached = true;
        Some(slot)
    }

    /// Map `len` bytes at `addr`, rounded out to whole pages. Already-mapped
    /// pages keep their contents (mapping a range twice is not an error: a PE
    /// with overlapping sections does exactly that).
    pub fn map(&mut self, addr: u32, len: u32) -> Result<(), MapError> {
        if len == 0 {
            return Ok(());
        }
        let first = addr >> PAGE_SHIFT;
        // Saturating: a section claiming to end past 4 GiB maps up to the top
        // page rather than wrapping to page 0.
        let last = addr.saturating_add(len - 1) >> PAGE_SHIFT;
        for page in first..=last {
            if self.index.contains_key(&page) {
                continue;
            }
            if self.pages.len() >= self.max_pages {
                return Err(MapError::OutOfPages);
            }
            self.pages.push(Page {
                bytes: Box::new([0u8; PAGE_SIZE]),
                dirty: false,
                executed: false,
            });
            self.index.insert(page, (self.pages.len() - 1) as u32);
        }
        Ok(())
    }

    /// Whether *any* page covering `addr..addr+len` is mapped. Used to place
    /// the synthetic system modules somewhere the image being emulated is not:
    /// an image is free to claim any base, including the one a real
    /// `kernel32.dll` occupies.
    pub fn any_mapped(&self, addr: u32, len: u32) -> bool {
        if len == 0 {
            return false;
        }
        let first = addr >> PAGE_SHIFT;
        let last = addr.saturating_add(len - 1) >> PAGE_SHIFT;
        (first..=last).any(|p| self.index.contains_key(&p))
    }

    /// Whether every page covering `addr..addr+len` is mapped.
    pub fn is_mapped(&self, addr: u32, len: u32) -> bool {
        if len == 0 {
            return true;
        }
        let first = addr >> PAGE_SHIFT;
        let last = addr.saturating_add(len - 1) >> PAGE_SHIFT;
        (first..=last).all(|p| self.index.contains_key(&p))
    }

    /// Whether the page holding `addr` has been written since it was mapped.
    pub fn is_dirty(&self, addr: u32) -> bool {
        match self.index.get(&(addr >> PAGE_SHIFT)) {
            Some(&slot) => self.pages[slot as usize].dirty,
            None => false,
        }
    }

    /// Mark the pages covering `addr..addr+len` clean. Used right after the
    /// initial image load so that "dirty" means "the stub wrote here", not "the
    /// loader put the file's own bytes here".
    pub fn clear_dirty(&mut self, addr: u32, len: u32) {
        if len == 0 {
            return;
        }
        let first = addr >> PAGE_SHIFT;
        let last = addr.saturating_add(len - 1) >> PAGE_SHIFT;
        for page in first..=last {
            if let Some(&slot) = self.index.get(&page) {
                self.pages[slot as usize].dirty = false;
            }
        }
    }

    #[inline]
    pub fn read_u8(&mut self, addr: u32) -> MemResult<u8> {
        let slot = self
            .slot(addr >> PAGE_SHIFT)
            .ok_or(Fault { addr, write: false })?;
        Ok(self.pages[slot as usize].bytes[(addr & PAGE_MASK) as usize])
    }

    #[inline]
    pub fn write_u8(&mut self, addr: u32, v: u8) -> MemResult<()> {
        let page = addr >> PAGE_SHIFT;
        let slot = self.slot(page).ok_or(Fault { addr, write: true })?;
        let p = &mut self.pages[slot as usize];
        p.bytes[(addr & PAGE_MASK) as usize] = v;
        let was = p.dirty;
        self.recent_pages |= 1u64 << (page & 63);
        p.dirty = true;
        if p.executed {
            self.code_gen += 1;
        }
        if !was {
            self.count_dirty(page);
        }
        Ok(())
    }

    #[inline]
    pub fn read_u16(&mut self, addr: u32) -> MemResult<u16> {
        let mut b = [0u8; 2];
        self.read_into(addr, &mut b)?;
        Ok(u16::from_le_bytes(b))
    }

    #[inline]
    pub fn read_u32(&mut self, addr: u32) -> MemResult<u32> {
        let mut b = [0u8; 4];
        self.read_into(addr, &mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    #[inline]
    pub fn write_u16(&mut self, addr: u32, v: u16) -> MemResult<()> {
        self.write_bytes(addr, &v.to_le_bytes())
    }

    #[inline]
    pub fn write_u32(&mut self, addr: u32, v: u32) -> MemResult<()> {
        self.write_bytes(addr, &v.to_le_bytes())
    }

    /// Read exactly `out.len()` bytes. Fast path when the range sits inside one
    /// page, which is the overwhelmingly common case.
    pub fn read_into(&mut self, addr: u32, out: &mut [u8]) -> MemResult<()> {
        let len = out.len() as u32;
        if len == 0 {
            return Ok(());
        }
        let off = (addr & PAGE_MASK) as usize;
        if off + out.len() <= PAGE_SIZE {
            let slot = self
                .slot(addr >> PAGE_SHIFT)
                .ok_or(Fault { addr, write: false })?;
            out.copy_from_slice(&self.pages[slot as usize].bytes[off..off + out.len()]);
            return Ok(());
        }
        for (i, b) in out.iter_mut().enumerate() {
            *b = self.read_u8(addr.wrapping_add(i as u32))?;
        }
        Ok(())
    }

    /// Write `src` at `addr`, marking the touched pages dirty.
    pub fn write_bytes(&mut self, addr: u32, src: &[u8]) -> MemResult<()> {
        if src.is_empty() {
            return Ok(());
        }
        let off = (addr & PAGE_MASK) as usize;
        if off + src.len() <= PAGE_SIZE {
            let page = addr >> PAGE_SHIFT;
            let slot = self.slot(page).ok_or(Fault { addr, write: true })?;
            let p = &mut self.pages[slot as usize];
            p.bytes[off..off + src.len()].copy_from_slice(src);
            let was = p.dirty;
            self.recent_pages |= 1u64 << (page & 63);
            p.dirty = true;
            if p.executed {
                self.code_gen += 1;
            }
            if !was {
                self.count_dirty(page);
            }
            return Ok(());
        }
        for (i, &b) in src.iter().enumerate() {
            self.write_u8(addr.wrapping_add(i as u32), b)?;
        }
        Ok(())
    }

    /// Read up to `out.len()` bytes for instruction fetch, stopping at the first
    /// unmapped page. Returns how many bytes were available: a decoder given a
    /// short buffer reports an incomplete instruction, which the emulator treats
    /// as running off the end of mapped code rather than as a hard fault.
    pub fn read_code(&mut self, addr: u32, out: &mut [u8]) -> usize {
        // Instruction fetch is the emulator's hottest path — once per executed
        // instruction — so it copies whole page runs rather than walking byte by
        // byte through the page lookup.
        let mut n = 0;
        while n < out.len() {
            let cur = addr.wrapping_add(n as u32);
            let off = (cur & PAGE_MASK) as usize;
            let Some(slot) = self.slot(cur >> PAGE_SHIFT) else {
                break;
            };
            let chunk = (PAGE_SIZE - off).min(out.len() - n);
            out[n..n + chunk].copy_from_slice(&self.pages[slot as usize].bytes[off..off + chunk]);
            n += chunk;
        }
        n
    }

    /// Copy out `addr..addr+len` as a flat buffer, substituting zeros for
    /// unmapped pages. Used to dump a reconstructed image: a hole in the middle
    /// of the image is a section the stub never touched, which on disk is a
    /// zero-filled section, not a reason to abandon the dump.
    pub fn snapshot(&mut self, addr: u32, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        let mut done = 0usize;
        while done < len {
            let cur = addr.wrapping_add(done as u32);
            let off = (cur & PAGE_MASK) as usize;
            let chunk = (PAGE_SIZE - off).min(len - done);
            if let Some(slot) = self.slot(cur >> PAGE_SHIFT) {
                out[done..done + chunk]
                    .copy_from_slice(&self.pages[slot as usize].bytes[off..off + chunk]);
            }
            done += chunk;
        }
        out
    }
}

/// Mapping failed because the page budget is exhausted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapError {
    OutOfPages,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unmapped_access_faults() {
        let mut m = Mem::new(16);
        assert!(m.read_u8(0x1000).is_err());
        m.map(0x1000, 4).unwrap();
        assert_eq!(m.read_u8(0x1000).unwrap(), 0);
        assert!(m.read_u8(0x2000).is_err());
    }

    #[test]
    fn writes_cross_page_boundaries() {
        let mut m = Mem::new(16);
        m.map(0x1000, 0x2000).unwrap();
        m.write_u32(0x1ffe, 0xdead_beef).unwrap();
        assert_eq!(m.read_u32(0x1ffe).unwrap(), 0xdead_beef);
        // The two low bytes landed on the first page, the two high bytes on the
        // second: the byte at the page boundary is the third of `ef be ad de`.
        assert_eq!(m.read_u8(0x2000).unwrap(), 0xad);
    }

    #[test]
    fn a_cross_page_write_that_runs_into_a_hole_faults() {
        let mut m = Mem::new(16);
        m.map(0x1000, PAGE_SIZE as u32).unwrap();
        // The first two bytes land on the mapped page, the last two do not.
        assert!(m.write_u32(0x1ffe, 0).is_err());
    }

    #[test]
    fn dirty_tracks_writes_only() {
        let mut m = Mem::new(16);
        m.map(0x1000, 0x1000).unwrap();
        assert!(!m.is_dirty(0x1000));
        m.read_u8(0x1000).unwrap();
        assert!(!m.is_dirty(0x1000), "reads do not dirty a page");
        m.write_u8(0x1010, 1).unwrap();
        assert!(m.is_dirty(0x1000));
        m.clear_dirty(0x1000, 0x1000);
        assert!(!m.is_dirty(0x1000));
    }

    #[test]
    fn page_budget_is_a_hard_cap() {
        let mut m = Mem::new(2);
        assert!(m.map(0x1000, 0x2000).is_ok());
        assert_eq!(m.map(0x8000, 0x1000), Err(MapError::OutOfPages));
        assert!(m.at_capacity());
    }

    #[test]
    fn snapshot_fills_holes_with_zeros() {
        let mut m = Mem::new(16);
        m.map(0x2000, 0x1000).unwrap();
        m.write_bytes(0x2000, b"abcd").unwrap();
        // 0x1000 is unmapped, 0x2000 is mapped: the hole comes back zeroed.
        let snap = m.snapshot(0x1000, 0x1004);
        assert!(snap[..0x1000].iter().all(|&b| b == 0));
        assert_eq!(&snap[0x1000..0x1004], b"abcd");
    }

    #[test]
    fn read_code_stops_at_the_first_unmapped_byte() {
        let mut m = Mem::new(16);
        m.map(0x1000, 0x1000).unwrap();
        m.write_bytes(0x1ffc, &[0x90, 0x90, 0x90, 0x90]).unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(m.read_code(0x1ffc, &mut buf), 4);
        assert_eq!(&buf[..4], &[0x90; 4]);
    }
}
