//! The partitions and filesystems of a disk, walked where they lie.
//!
//! A disk image is a `Read + Seek`; the filesystem readers (NTFS, FAT, and ext
//! for the one volume it holds) take one, so a file comes out of a disk
//! without the disk, or the volume around it, being held.
//!
//! A volume of at most the buffer limit is handed over whole, as a stream, as
//! a partition of a raw disk always was: its raw bytes are scanned and typed
//! one level down, which also reaches whatever it holds that is not a
//! filesystem exav reads. A larger one that is a filesystem exav reads is
//! walked in place. A larger one that is not is streamed when the disk is a
//! file ([`Mode::Raw`]), where those bytes are the input, and reported when
//! the disk is a virtual one ([`Mode::Virtual`]), where its size is only what
//! a header declares and reading it could be a long walk through zeros.

// Every sum and product on a header's number is checked or saturating here; a
// plain one fails the build, so the next edit cannot add the unchecked kind.
#![deny(clippy::arithmetic_side_effects)]
// Each build has the filesystems and the partition walker its features give it.
#![allow(dead_code, unused_imports, unused_variables)]

use std::io::{self, Read, Seek, SeekFrom};

use super::vol::{Emit, Found};
use crate::stream::{MemberMeta, Region, Visit, emit_entry, emit_stream};
use crate::{Budget, Entry, LimitHit};

/// A member that is only a report: `reason` about `size` bytes of `name`.
pub(crate) fn report<T>(
    name: &str,
    size: u64,
    reason: &'static str,
    budget: &mut Budget,
    visit: Visit<T>,
) -> Result<Option<T>, LimitHit> {
    report_enc(name, size, false, reason, budget, visit)
}

/// [`report`] of content that is encrypted.
pub(crate) fn report_enc<T>(
    name: &str,
    size: u64,
    encrypted: bool,
    reason: &'static str,
    budget: &mut Budget,
    visit: Visit<T>,
) -> Result<Option<T>, LimitHit> {
    budget.count_entry()?;
    emit_entry(
        Entry::unsupported(name.to_string(), size, encrypted, reason),
        budget,
        visit,
    )
}

/// What is read to tell a filesystem apart.
const HEAD: usize = 4096;

/// How far into a virtual disk the bytes before the first partition are
/// scanned: the boot code, where a bootkit lives.
const BOOT_AREA: u64 = 1024 * 1024;

/// What the disk is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Mode {
    /// A file's bytes: the disk was scanned as the object it is.
    Raw,
    /// A virtual disk's declared bytes.
    Virtual,
}

/// A filesystem that is read in place.
#[derive(Clone, Copy)]
enum Fs {
    #[cfg(feature = "ntfs")]
    Ntfs,
    #[cfg(feature = "fat")]
    Fat,
    #[cfg(feature = "ext")]
    Ext,
    #[cfg(feature = "exfat")]
    Exfat,
    #[cfg(feature = "squashfs")]
    Squashfs,
    #[cfg(feature = "cramfs")]
    Cramfs,
    #[cfg(feature = "romfs")]
    Romfs,
    #[cfg(feature = "erofs")]
    Erofs,
    #[cfg(feature = "dmg")]
    Hfs,
    #[cfg(feature = "dmg")]
    Apfs,
}

/// The filesystem a volume starting with `head` is. The order is `detect`'s.
fn sniff(head: &[u8]) -> Option<Fs> {
    #[cfg(feature = "dmg")]
    if super::apfs::is_apfs(head) {
        return Some(Fs::Apfs);
    }
    #[cfg(feature = "dmg")]
    if super::hfsplus::is_hfsplus(head) {
        return Some(Fs::Hfs);
    }
    #[cfg(feature = "ext")]
    if super::ext::is_ext(head) {
        return Some(Fs::Ext);
    }
    #[cfg(feature = "fat")]
    if super::fat::is_fat(head) {
        return Some(Fs::Fat);
    }
    #[cfg(feature = "exfat")]
    if super::exfat::is_exfat(head) {
        return Some(Fs::Exfat);
    }
    #[cfg(feature = "squashfs")]
    if super::squashfs::is_squashfs(head) {
        return Some(Fs::Squashfs);
    }
    #[cfg(feature = "cramfs")]
    if super::cramfs::is_cramfs(head) {
        return Some(Fs::Cramfs);
    }
    #[cfg(feature = "romfs")]
    if super::romfs::is_romfs(head) {
        return Some(Fs::Romfs);
    }
    #[cfg(feature = "erofs")]
    if super::erofs::is_erofs(head) {
        return Some(Fs::Erofs);
    }
    #[cfg(feature = "ntfs")]
    if super::sniff::is(head, crate::Format::Ntfs) {
        return Some(Fs::Ntfs);
    }
    let _ = head;
    None
}

/// `[start, start + len)` of a disk, as a disk of its own.
pub(crate) struct Window<'a, D> {
    disk: &'a mut D,
    start: u64,
    len: u64,
    pos: u64,
}

impl<'a, D> Window<'a, D> {
    pub(crate) fn new(disk: &'a mut D, start: u64, len: u64) -> Self {
        Window {
            disk,
            start,
            len,
            pos: 0,
        }
    }
}

impl<D: Read + Seek> Read for Window<'_, D> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.len.saturating_sub(self.pos);
        let want = usize::try_from(left).map_or(buf.len(), |l| l.min(buf.len()));
        if want == 0 {
            return Ok(0);
        }
        let at = self
            .start
            .checked_add(self.pos)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "offset overflow"))?;
        self.disk.seek(SeekFrom::Start(at))?;
        let n = self.disk.read(&mut buf[..want])?;
        self.pos = self.pos.saturating_add(n as u64);
        Ok(n)
    }
}

impl<D> Seek for Window<'_, D> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let pos = match to {
            SeekFrom::Start(p) => Some(p),
            SeekFrom::End(d) => self.len.checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek outside the volume"))?;
        self.pos = pos;
        Ok(pos)
    }
}

/// Run a filesystem walker, which hands each file to an [`Emit`], as a walk
/// handing members to `visit`, each name under `prefix`. A file read as it
/// goes is a streamed member.
pub(crate) fn entries<T>(
    budget: &mut Budget,
    visit: Visit<T>,
    prefix: &str,
    run: impl FnOnce(
        &mut Budget,
        Emit<Result<T, LimitHit>>,
    ) -> Result<Option<Result<T, LimitHit>>, LimitHit>,
) -> Result<Option<T>, LimitHit> {
    let under = |e: Entry| {
        if prefix.is_empty() {
            e
        } else {
            Entry {
                name: format!("{prefix}/{}", e.name),
                ..e
            }
        }
    };
    let mut emit = |found: Found<'_>, budget: &mut Budget| -> Option<Result<T, LimitHit>> {
        match found {
            Found::Held(e) => emit_entry(under(e), budget, &mut *visit).transpose(),
            Found::Read(e, reader) => {
                let e = under(e);
                let meta = MemberMeta {
                    name: e.name,
                    comp_size: e.comp_size,
                    size: Some(e.comp_size),
                    mtime: e.mtime,
                    mode: e.mode,
                    ..MemberMeta::default()
                };
                emit_stream(&meta, reader, budget, &mut *visit).transpose()
            }
        }
    };
    run(budget, &mut emit)?.transpose()
}

/// Walk the filesystem `fs` that fills `[start, start + len)` of `disk`, each
/// file's name under `prefix`.
fn walk_fs<D: Read + Seek, T>(
    fs: Fs,
    disk: &mut D,
    start: u64,
    len: u64,
    prefix: &str,
    budget: &mut Budget,
    visit: Visit<T>,
) -> Result<Option<T>, LimitHit> {
    let window = Window::new(disk, start, len);
    entries(budget, visit, prefix, |budget, sink| match fs {
        #[cfg(feature = "ntfs")]
        Fs::Ntfs => super::ntfs::walk_volume(window, len, budget, sink),
        #[cfg(feature = "fat")]
        Fs::Fat => super::fat::walk_volume(window, len, budget, sink),
        #[cfg(feature = "ext")]
        Fs::Ext => super::ext::walk_volume(window, len, budget, sink),
        #[cfg(feature = "exfat")]
        Fs::Exfat => super::exfat::walk_volume(window, len, budget, sink),
        #[cfg(feature = "squashfs")]
        Fs::Squashfs => super::squashfs::walk_volume(window, len, budget, sink),
        #[cfg(feature = "cramfs")]
        Fs::Cramfs => super::cramfs::walk_volume(window, len, budget, sink),
        #[cfg(feature = "romfs")]
        Fs::Romfs => super::romfs::walk_volume(window, len, budget, sink),
        #[cfg(feature = "erofs")]
        Fs::Erofs => super::erofs::walk_volume(window, len, budget, sink),
        #[cfg(feature = "dmg")]
        Fs::Hfs => super::hfsplus::walk_volume(window, budget, sink),
        #[cfg(feature = "dmg")]
        Fs::Apfs => super::apfs::walk_volume(window, budget, sink),
    })
}

/// Walk a disk image: the filesystem that starts it, or the volumes its
/// partition table lists. A disk that is neither is reported: its bytes were
/// not read.
pub(crate) fn walk_disk<D: Read + Seek, T>(
    disk: &mut D,
    mode: Mode,
    budget: &mut Budget,
    visit: Visit<T>,
) -> Result<Option<T>, LimitHit> {
    let len = disk
        .seek(SeekFrom::End(0))
        .map_err(|e| LimitHit::corrupt(format!("disk: {e}")))?;
    let head = crate::read_at(disk, 0, HEAD)?;
    if let Some(fs) = sniff(&head) {
        return walk_fs(fs, disk, 0, len, "", budget, visit);
    }
    #[cfg(feature = "partition")]
    {
        let regions = super::partition::stream_offsets(disk)?;
        if !regions.is_empty() {
            return walk_regions(disk, regions, mode, budget, visit);
        }
        // A table with nothing in it holds nothing.
        if super::partition::is_table(&head, len) {
            return Ok(None);
        }
    }
    let why = "the disk is larger than the buffer limit and is neither a filesystem nor a \
               partition table exav reads, so its bytes were not examined";
    report("<disk>", len, why, budget, visit)
}

/// Walk the volumes of a partitioned disk.
pub(crate) fn walk_regions<D: Read + Seek, T>(
    disk: &mut D,
    regions: Vec<Region>,
    mode: Mode,
    budget: &mut Budget,
    visit: Visit<T>,
) -> Result<Option<T>, LimitHit> {
    let cap = budget.limits().max_buffer_bytes;
    if mode == Mode::Virtual {
        let first = regions
            .iter()
            .filter_map(|r| match r {
                Region::Member(_, off, _) => Some(*off),
                Region::Unwalked(..) => None,
            })
            .min();
        let n = first.map_or(0, |f| f.min(BOOT_AREA).min(cap));
        if let Some(n) = usize::try_from(n).ok().filter(|&n| n > 0) {
            let boot = crate::read_at(disk, 0, n)?;
            budget.count_entry()?;
            let e = Entry::new("<boot-area>".to_string(), boot);
            if let Some(t) = emit_entry(e, budget, &mut *visit)? {
                return Ok(Some(t));
            }
        }
    }
    for region in regions {
        let (name, off, len) = match region {
            Region::Member(name, off, len) => (name, off, len),
            // A part of the table that was not walked arrives as it always did.
            Region::Unwalked(..) => {
                if let Some(t) = crate::stream::stream_stored(disk, budget, &mut *visit, [region])?
                {
                    return Ok(Some(t));
                }
                continue;
            }
        };
        let found = if len > cap {
            let head = crate::read_at(&mut Window::new(disk, off, len), 0, HEAD)?;
            match sniff(&head) {
                Some(fs) => walk_fs(fs, disk, off, len, &name, budget, &mut *visit)?,
                None if mode == Mode::Raw => stream_volume(disk, name, off, len, budget, visit)?,
                None => {
                    let why = "a volume larger than the buffer limit that is not a filesystem \
                               exav reads in place, so its bytes were not examined";
                    report(&name, len, why, budget, &mut *visit)?
                }
            }
        } else {
            stream_volume(disk, name, off, len, budget, &mut *visit)?
        };
        if found.is_some() {
            return Ok(found);
        }
    }
    Ok(None)
}

/// Hand the visitor the bytes of a volume as a stream.
fn stream_volume<D: Read + Seek, T>(
    disk: &mut D,
    name: String,
    off: u64,
    len: u64,
    budget: &mut Budget,
    visit: Visit<T>,
) -> Result<Option<T>, LimitHit> {
    crate::stream::stream_stored(disk, budget, visit, [Region::Member(name, off, len)])
}
