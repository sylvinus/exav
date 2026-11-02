//! Virtual disks read in place.
//!
//! VHD, VHDX, QCOW2 and VMDK declare a disk size that is not the file's. A
//! [`VDisk`] gives such a disk as a `Read + Seek` without holding it. The
//! container's tables are read from the source when a read first reaches a
//! unit (a cluster, block or grain), a stored unit is read straight from the
//! source, an unallocated one reads as zeros and costs nothing, and a
//! compressed one is decoded into a cache of at most [`CACHE_BYTES`] and
//! decoded again if it was evicted.
//!
//! [`walk`] hands the disk over in one of two ways. A disk that fits the buffer
//! limit is read into one member, as it always was, so its raw bytes are
//! scanned and typed one level down. A larger one is never held: its partitions
//! and filesystems are walked in place ([`super::volumes`]) and each file comes
//! out as a member.
//!
//! What the decoder does is bounded three ways. The tables are not held at all
//! (they are read from the source, which caches them), so a hostile table size
//! costs reads, not memory. The cache is a fixed size. And the bytes decoded
//! over the whole walk are counted against the scan budget, so an image that
//! makes the filesystem walker land on a different compressed unit for every
//! small read stops when the budget does.

// Every sum and product on a header's number is checked or saturating here; a
// plain one fails the build, so the next edit cannot add the unchecked kind.
#![deny(clippy::arithmetic_side_effects)]
// Each format uses a part of this module (VHD has no compressed units, QCOW2 and
// VMDK no big-endian tables); see `cap_prealloc` for why the feature lists are
// not spelled out.
#![allow(dead_code)]

use std::borrow::Cow;
use std::cell::Cell;
use std::collections::{BTreeMap, HashMap};
use std::io::{self, Read, Seek, SeekFrom};
use std::rc::Rc;

use super::volumes::{self, report};
use crate::source::ByteSource;
use crate::stream::Visit;
use crate::{Budget, Entry, LimitHit, LimitKind};

/// Decoded units kept.
pub(crate) const CACHE_BYTES: usize = 32 * 1024 * 1024;

/// The largest compressed unit a layout may declare: a unit is decoded whole
/// into the cache, which has to hold a few of them.
pub(crate) const MAX_PACKED_UNIT: u64 = (CACHE_BYTES / 2) as u64;

/// Carried by the error a read fails with when the disk has decoded its
/// allowance.
const OVER_ALLOWANCE: &str = "exav:virtual-disk-decode-allowance";

/// Where a unit of the disk is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Map {
    /// Not stored: reads as zeros.
    Zero,
    /// Stored as it reads, from this offset in the file, wholly inside it.
    Plain(u64),
    /// Compressed: `stored` bytes at `at`, fewer than the container says when
    /// the file ends first (`cut`).
    Packed { at: u64, stored: u64, cut: bool },
}

/// A compressed unit as far as it decoded.
pub(crate) struct Unpacked {
    pub(crate) data: Vec<u8>,
    /// Compressed bytes of the unit were left undecoded, or it decoded to more
    /// than the unit holds: what was read from it may not be the disk's.
    pub(crate) damaged: bool,
}

/// What a container format says of its disk.
pub(crate) trait Layout {
    /// The member the disk is handed over as, when it is handed over whole.
    fn name(&self) -> &'static str;

    /// The disk's size in bytes.
    fn size(&self) -> u64;

    /// Bytes per unit, never zero.
    fn unit(&self) -> u64;

    /// Where unit `idx` is. A unit whose table entry cannot be read, or whose
    /// stored bytes are not all in the file, is [`Map::Zero`]: the file is
    /// short, so those bytes are absent, not hidden.
    fn map(&self, idx: u64) -> Map;

    /// Decode unit `idx`, `out` bytes long, from its [`Map::Packed`] bytes.
    fn unpack(&self, _idx: u64, _at: u64, _stored: u64, _cut: bool, _out: usize) -> Unpacked {
        Unpacked {
            data: Vec::new(),
            damaged: true,
        }
    }

    /// What the walk found that the member alone would not say: a size and a
    /// reason for each, reported ahead of it.
    fn reports(&self, _health: &Health) -> Vec<(u64, &'static str)> {
        Vec::new()
    }

    /// Why the disk is not worth handing over: the reason replaces it.
    /// `whole`: every unit was read.
    fn unusable(&self, _health: &Health, _whole: bool) -> Option<&'static str> {
        None
    }
}

/// What reads of a disk found, shared with the walker that reads it.
pub(crate) struct Health {
    /// Compressed units decoded with a fault, counted per decode.
    undecodable: Cell<u64>,
    /// Compressed units that gave any bytes, damaged or not.
    produced: Cell<u64>,
    /// Bytes decoded so far, and the most the disk may decode.
    decoded: Cell<u64>,
    allowance: u64,
    over: Cell<bool>,
    /// The most the cache held at once.
    cache_peak: Cell<usize>,
}

impl Health {
    fn new(allowance: u64) -> Rc<Self> {
        Rc::new(Health {
            undecodable: Cell::new(0),
            produced: Cell::new(0),
            decoded: Cell::new(0),
            allowance,
            over: Cell::new(false),
            cache_peak: Cell::new(0),
        })
    }

    /// Units reached whose compressed bytes would not decode.
    pub(crate) fn undecodable(&self) -> u64 {
        self.undecodable.get()
    }

    /// Units that gave any bytes: a unit damaged part way still gave what
    /// decoded before the damage.
    pub(crate) fn produced(&self) -> u64 {
        self.produced.get()
    }

    /// Bytes decoded so far.
    pub(crate) fn decoded(&self) -> u64 {
        self.decoded.get()
    }

    /// The most bytes of decoded units the cache held at once.
    #[cfg(test)]
    pub(crate) fn cache_peak(&self) -> usize {
        self.cache_peak.get()
    }

    /// A read was refused for decoding more than the disk may.
    pub(crate) fn over_allowance(&self) -> bool {
        self.over.get()
    }

    fn charge(&self, n: u64) -> io::Result<()> {
        let total = self.decoded.get().saturating_add(n);
        if total > self.allowance {
            self.over.set(true);
            return Err(io::Error::other(OVER_ALLOWANCE));
        }
        self.decoded.set(total);
        Ok(())
    }
}

/// Decoded units by index, the least recently used evicted past `cap` bytes.
struct Cache {
    units: HashMap<u64, (Vec<u8>, u64)>,
    /// Tick of last use to unit.
    order: BTreeMap<u64, u64>,
    bytes: usize,
    tick: u64,
    cap: usize,
}

impl Cache {
    fn new(cap: usize) -> Self {
        Cache {
            units: HashMap::new(),
            order: BTreeMap::new(),
            bytes: 0,
            tick: 0,
            cap,
        }
    }

    /// Mark `idx` used. Whether it is held.
    fn touch(&mut self, idx: u64) -> bool {
        let Some((_, used)) = self.units.get_mut(&idx) else {
            return false;
        };
        self.order.remove(used);
        self.tick = self.tick.saturating_add(1);
        *used = self.tick;
        self.order.insert(self.tick, idx);
        true
    }

    fn get(&self, idx: u64) -> Option<&[u8]> {
        self.units.get(&idx).map(|(d, _)| d.as_slice())
    }

    fn put(&mut self, idx: u64, data: Vec<u8>) {
        while self.bytes.saturating_add(data.len()) > self.cap {
            let Some((_, old)) = self.order.pop_first() else {
                break;
            };
            if let Some((d, _)) = self.units.remove(&old) {
                self.bytes = self.bytes.saturating_sub(d.len());
            }
        }
        self.bytes = self.bytes.saturating_add(data.len());
        self.tick = self.tick.saturating_add(1);
        self.order.insert(self.tick, idx);
        if let Some((old, used)) = self.units.insert(idx, (data, self.tick)) {
            self.order.remove(&used);
            self.bytes = self.bytes.saturating_sub(old.len());
        }
    }
}

/// `len` bytes at `off` of `src`, or `None` when they are not all in it.
pub(crate) fn bytes_at(src: &dyn ByteSource, off: u64, len: usize) -> Option<Cow<'_, [u8]>> {
    let off = usize::try_from(off).ok()?;
    if off.checked_add(len)? > src.len() {
        return None;
    }
    let w = src.window(off, len);
    (w.len() == len).then_some(w)
}

/// A big-endian `u32` at `off`.
pub(crate) fn be32(src: &dyn ByteSource, off: u64) -> Option<u32> {
    let b = bytes_at(src, off, 4)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// A big-endian `u64` at `off`.
pub(crate) fn be64(src: &dyn ByteSource, off: u64) -> Option<u64> {
    let b = bytes_at(src, off, 8)?;
    Some(u64::from_be_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

/// A little-endian `u32` at `off`.
pub(crate) fn le32(src: &dyn ByteSource, off: u64) -> Option<u32> {
    let b = bytes_at(src, off, 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// A little-endian `u64` at `off`.
pub(crate) fn le64(src: &dyn ByteSource, off: u64) -> Option<u64> {
    let b = bytes_at(src, off, 8)?;
    Some(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

/// A virtual disk, as a `Read + Seek`.
pub(crate) struct VDisk<'a, L: Layout> {
    src: &'a dyn ByteSource,
    layout: L,
    pos: u64,
    health: Rc<Health>,
    cache: Cache,
    /// The unit the last read was in, so a filesystem reading it sector by
    /// sector looks it up once.
    last: Option<(u64, Map)>,
}

impl<'a, L: Layout> VDisk<'a, L> {
    /// A disk that may decode `allowance` bytes in all.
    pub(crate) fn new(src: &'a dyn ByteSource, layout: L, allowance: u64) -> Self {
        VDisk {
            src,
            layout,
            pos: 0,
            health: Health::new(allowance),
            cache: Cache::new(CACHE_BYTES),
            last: None,
        }
    }

    pub(crate) fn size(&self) -> u64 {
        self.layout.size()
    }

    pub(crate) fn health(&self) -> Rc<Health> {
        self.health.clone()
    }

    fn lookup(&mut self, idx: u64) -> Map {
        if let Some((i, m)) = self.last
            && i == idx
        {
            return m;
        }
        let m = self.layout.map(idx);
        self.last = Some((idx, m));
        m
    }

    /// Unit `idx` decoded, `out` bytes long when whole.
    fn unpacked(
        &mut self,
        idx: u64,
        (at, stored, cut): (u64, u64, bool),
        out: usize,
    ) -> io::Result<&[u8]> {
        if !self.cache.touch(idx) {
            self.health.charge(out as u64)?;
            let u = self.layout.unpack(idx, at, stored, cut, out);
            let h = &self.health;
            if u.damaged {
                h.undecodable.set(h.undecodable.get().saturating_add(1));
            }
            if !u.data.is_empty() {
                h.produced.set(h.produced.get().saturating_add(1));
            }
            self.cache.put(idx, u.data);
            let peak = self.health.cache_peak.get().max(self.cache.bytes);
            self.health.cache_peak.set(peak);
        }
        Ok(self.cache.get(idx).unwrap_or(&[]))
    }
}

impl<L: Layout> Read for VDisk<'_, L> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let size = self.layout.size();
        if buf.is_empty() || self.pos >= size {
            return Ok(0);
        }
        let unit = self.layout.unit().max(1);
        let idx = self.pos.checked_div(unit).unwrap_or(0);
        let into = self.pos.checked_rem(unit).unwrap_or(0);
        let unit_len = unit.min(size.saturating_sub(idx.saturating_mul(unit)));
        let room = unit_len.saturating_sub(into);
        let want = usize::try_from(room).map_or(buf.len(), |r| r.min(buf.len()));
        let buf = &mut buf[..want];
        match self.lookup(idx) {
            Map::Zero => buf.fill(0),
            Map::Plain(at) => {
                let from = at.saturating_add(into);
                let w = bytes_at(self.src, from, want).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        self.src
                            .read_error()
                            .unwrap_or_else(|| "the image ended inside a stored unit".into()),
                    )
                })?;
                buf.copy_from_slice(&w);
            }
            Map::Packed { at, stored, cut } => {
                let out = usize::try_from(unit_len).unwrap_or(usize::MAX);
                let skip = usize::try_from(into).unwrap_or(usize::MAX);
                let data = self.unpacked(idx, (at, stored, cut), out)?;
                let have = data.len().saturating_sub(skip).min(want);
                if let Some(s) = data.get(skip..skip.saturating_add(have)) {
                    buf[..have].copy_from_slice(s);
                }
                // A unit that decoded short reads as zeros past what decoded.
                buf[have..].fill(0);
            }
        }
        self.pos = self.pos.saturating_add(want as u64);
        Ok(want)
    }
}

impl<L: Layout> Seek for VDisk<'_, L> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let pos = match to {
            SeekFrom::Start(p) => Some(p),
            SeekFrom::End(d) => self.layout.size().checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek outside the disk"))?;
        self.pos = pos;
        Ok(pos)
    }
}

/// The stop for a disk that decoded more than its allowance.
fn over_allowance(name: &str) -> LimitHit {
    LimitHit::of_kind(
        LimitKind::MaxScanSize,
        format!("{name}: the bytes decoded to read the disk exceed the scan budget"),
    )
}

/// Hand `disk` to the visitor. See the module note for the two ways.
pub(crate) fn walk<L: Layout, T>(
    mut disk: VDisk<'_, L>,
    budget: &mut Budget,
    visit: Visit<T>,
) -> Result<Option<T>, LimitHit> {
    budget.count_entry()?;
    let cap = budget.reserve()?;
    let size = disk.size();
    let name = disk.layout.name();
    let health = disk.health();
    match usize::try_from(size) {
        Ok(n) if size <= cap => {
            let mut data = Vec::with_capacity(crate::cap_prealloc(n));
            if let Err(e) = (&mut disk).take(size).read_to_end(&mut data) {
                if health.over_allowance() {
                    return Err(over_allowance(name));
                }
                return Err(LimitHit::corrupt(format!("{name}: {e}")));
            }
            if let Some(why) = disk.layout.unusable(&health, true) {
                return report(name, size, why, budget, visit);
            }
            for (n, why) in disk.layout.reports(&health) {
                if let Some(t) = report(name, n, why, budget, &mut *visit)? {
                    return Ok(Some(t));
                }
            }
            budget.commit(data.len() as u64);
            crate::stream::emit_entry(Entry::new(name.to_string(), data), budget, visit)
        }
        _ => {
            let found = volumes::walk_disk(&mut disk, volumes::Mode::Virtual, budget, &mut *visit);
            budget.charge_scan(health.decoded())?;
            // A walk that failed because the disk ran out of what it may
            // decode failed for that, whatever it was reading.
            match found {
                Ok(Some(t)) => return Ok(Some(t)),
                Err(_) if health.over_allowance() => return Err(over_allowance(name)),
                Err(e) => return Err(e),
                Ok(None) if health.over_allowance() => return Err(over_allowance(name)),
                Ok(None) => {}
            }
            if let Some(why) = disk.layout.unusable(&health, false) {
                return report(name, size, why, budget, visit);
            }
            for (n, why) in disk.layout.reports(&health) {
                if let Some(t) = report(name, n, why, budget, &mut *visit)? {
                    return Ok(Some(t));
                }
            }
            Ok(None)
        }
    }
}

// The tests lay out their inputs by index arithmetic on small constants.
#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
pub(crate) mod tests {
    use super::*;

    /// A layout of `units` units of `unit` bytes where the test says what each is.
    pub(crate) struct Table<'a> {
        pub(crate) src: &'a [u8],
        pub(crate) unit: u64,
        pub(crate) size: u64,
        pub(crate) maps: Vec<Map>,
        pub(crate) decodes: Rc<Cell<u64>>,
    }

    impl Layout for Table<'_> {
        fn name(&self) -> &'static str {
            "test-disk"
        }
        fn size(&self) -> u64 {
            self.size
        }
        fn unit(&self) -> u64 {
            self.unit
        }
        fn map(&self, idx: u64) -> Map {
            usize::try_from(idx)
                .ok()
                .and_then(|i| self.maps.get(i).copied())
                .unwrap_or(Map::Zero)
        }
        /// The unit's stored bytes, backwards.
        fn unpack(&self, _idx: u64, at: u64, stored: u64, _cut: bool, out: usize) -> Unpacked {
            self.decodes.set(self.decodes.get() + 1);
            let at = at as usize;
            let mut d: Vec<u8> = self.src[at..at + stored as usize].to_vec();
            d.reverse();
            d.resize(out, 0);
            Unpacked {
                data: d,
                damaged: false,
            }
        }
    }

    fn read_all<L: Layout>(d: &mut VDisk<'_, L>) -> Vec<u8> {
        let mut out = Vec::new();
        d.seek(SeekFrom::Start(0)).unwrap();
        d.read_to_end(&mut out).unwrap();
        out
    }

    /// Four units of 8 bytes: stored, absent, compressed, stored past the end.
    fn disk_of<'a>(file: &'a [u8], decodes: &Rc<Cell<u64>>) -> Table<'a> {
        Table {
            src: file,
            unit: 8,
            size: 30,
            maps: vec![
                Map::Plain(0),
                Map::Zero,
                Map::Packed {
                    at: 8,
                    stored: 8,
                    cut: false,
                },
                Map::Plain(8),
            ],
            decodes: decodes.clone(),
        }
    }

    #[test]
    fn units_read_as_their_map_says_and_the_last_one_is_short() {
        let file: Vec<u8> = (1..=16).collect();
        let decodes = Rc::new(Cell::new(0));
        let mut d = VDisk::new(&file, disk_of(&file, &decodes), u64::MAX);
        let all = read_all(&mut d);
        let mut want = Vec::new();
        want.extend_from_slice(&file[..8]);
        want.extend_from_slice(&[0; 8]);
        want.extend(file[8..16].iter().rev());
        want.extend_from_slice(&file[8..14]);
        assert_eq!(all, want);
        assert_eq!(d.size(), 30);
    }

    #[test]
    fn reads_that_cross_units_and_seeks_agree_with_the_whole() {
        let file: Vec<u8> = (1..=16).collect();
        let decodes = Rc::new(Cell::new(0));
        let mut d = VDisk::new(&file, disk_of(&file, &decodes), u64::MAX);
        let all = read_all(&mut d);
        for (at, n) in [(0u64, 5usize), (6, 9), (15, 3), (23, 7), (29, 1)] {
            d.seek(SeekFrom::Start(at)).unwrap();
            let mut got = vec![0u8; n];
            d.read_exact(&mut got).unwrap();
            assert_eq!(got, all[at as usize..at as usize + n], "({at}, {n})");
        }
        // End and Current seeks; reading at the end is empty, past it too.
        assert_eq!(d.seek(SeekFrom::End(-2)).unwrap(), 28);
        assert_eq!(d.seek(SeekFrom::Current(-1)).unwrap(), 27);
        assert!(d.seek(SeekFrom::Current(-100)).is_err());
        d.seek(SeekFrom::Start(30)).unwrap();
        assert_eq!(d.read(&mut [0u8; 4]).unwrap(), 0);
        d.seek(SeekFrom::Start(u64::MAX)).unwrap();
        assert_eq!(d.read(&mut [0u8; 4]).unwrap(), 0);
        assert!(d.seek(SeekFrom::Current(1)).is_err());
    }

    /// Decoded units are kept while the cache has room for them.
    #[test]
    fn a_decoded_unit_is_decoded_once_while_it_is_cached() {
        let file: Vec<u8> = (1..=16).collect();
        let decodes = Rc::new(Cell::new(0));
        let mut d = VDisk::new(&file, disk_of(&file, &decodes), u64::MAX);
        for _ in 0..3 {
            d.seek(SeekFrom::Start(16)).unwrap();
            d.read_exact(&mut [0u8; 8]).unwrap();
        }
        assert_eq!(decodes.get(), 1);
        assert_eq!(d.health().produced(), 1);
    }

    #[test]
    fn cache_evicts_the_least_recently_used_and_decodes_again_to_the_same_bytes() {
        let mut c = Cache::new(20);
        c.put(1, vec![1; 8]);
        c.put(2, vec![2; 8]);
        assert!(c.touch(1));
        // 3 does not fit beside both: 2, the least recently used, goes.
        c.put(3, vec![3; 8]);
        assert!(c.get(1).is_some() && c.get(2).is_none() && c.get(3).is_some());
        assert!(c.bytes <= 20);
        // A unit put again replaces itself without double counting.
        c.put(3, vec![9; 4]);
        assert_eq!(c.get(3), Some(&[9u8; 4][..]));
        assert_eq!(c.bytes, 12);
        assert!(!c.touch(2));
    }

    /// Reading A, then enough other units to evict it, then A again gives A.
    #[test]
    fn a_unit_read_again_after_eviction_is_the_same() {
        // 64 packed units of 1 MiB, each its own pattern; a cache of 32 MiB
        // holds 32 of them.
        let unit = 1usize << 20;
        let file: Vec<u8> = (0..64u32 * 1024).map(|i| (i % 251) as u8).collect();
        let decodes = Rc::new(Cell::new(0));
        let maps: Vec<Map> = (0..64)
            .map(|i| Map::Packed {
                at: (i % 8) * 8192,
                stored: 8192,
                cut: false,
            })
            .collect();
        let layout = Table {
            src: &file,
            unit: unit as u64,
            size: 64 * unit as u64,
            maps,
            decodes: decodes.clone(),
        };
        let mut d = VDisk::new(&file, layout, u64::MAX);
        let read = |d: &mut VDisk<'_, Table<'_>>, at: u64| {
            d.seek(SeekFrom::Start(at)).unwrap();
            let mut b = vec![0u8; 8192];
            d.read_exact(&mut b).unwrap();
            b
        };
        let a = read(&mut d, 0);
        // Walk through 40 more units: A is evicted.
        for i in 1..41u64 {
            read(&mut d, i * unit as u64);
        }
        let before = decodes.get();
        assert_eq!(read(&mut d, 0), a);
        assert_eq!(decodes.get(), before + 1, "A was decoded again");
        assert!(d.health().cache_peak() <= CACHE_BYTES + 8192);
    }

    #[test]
    fn decoding_past_the_allowance_stops_the_read_and_says_so() {
        let file: Vec<u8> = (1..=16).collect();
        let decodes = Rc::new(Cell::new(0));
        let mut d = VDisk::new(&file, disk_of(&file, &decodes), 4);
        d.seek(SeekFrom::Start(16)).unwrap();
        let e = d.read_exact(&mut [0u8; 8]).unwrap_err();
        assert_eq!(e.to_string(), OVER_ALLOWANCE);
        assert!(d.health().over_allowance());
        assert_eq!(decodes.get(), 0, "nothing was decoded past the allowance");
    }

    /// A plain unit the source cannot deliver is an error, not zeros.
    #[test]
    fn a_stored_unit_the_source_lost_is_an_error() {
        let file: Vec<u8> = (1..=4).collect();
        let layout = Table {
            src: &file,
            unit: 8,
            size: 8,
            maps: vec![Map::Plain(0)],
            decodes: Rc::new(Cell::new(0)),
        };
        let mut d = VDisk::new(&file, layout, u64::MAX);
        let e = d.read_exact(&mut [0u8; 8]).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
    }
}
