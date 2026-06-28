//! ClamAV-compatible PE "IconGroup" perceptual icon matching.
//!
//! Implemented from the public PE resource-directory and BMP/DIB icon formats,
//! producing hashes in the `.idb` IconGroup format so IconGroup signatures
//! match.
//!
//! Pipeline (see the spec for the authoritative details):
//!
//! 1. Walk the PE resource directory; enumerate the FIRST `RT_GROUP_ICON`
//!    resource and the `RT_ICON` bitmaps it references.
//! 2. Decode each `RT_ICON` headerless DIB to a 32-bit ARGB buffer, applying
//!    the AND mask as alpha and blending over white.
//! 3. Reject icons that are out of range / not roughly square; normalise to a
//!    canonical side of 16/24/32.
//! 4. Compute the fixed-layout `icomtr` metric vector ("icon hash").
//! 5. Match a computed metric against `.idb` entries (group-gated, same side),
//!    producing a weighted confidence; a confident match fires the signature.
//!
//! Everything is panic-isolated: malformed/hostile input returns `None`, never
//! panics. All integer reads are bounds-checked.

use serde::{Deserialize, Serialize};

/// One sliding-window cell triple (the best/worst 3 non-overlapping cells of a
/// component): per-cell average value plus its (x,y) top-left coordinate.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
struct Triple {
    avg: [u32; 3],
    x: [u32; 3],
    y: [u32; 3],
}

/// The serialized `icomtr` metric vector for one icon, plus its canonical side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IconMetric {
    /// Canonical side length: 16, 24 or 32.
    side: u32,
    color: Triple,
    gray: Triple,
    bright: Triple,
    dark: Triple,
    edge: Triple,
    noedge: Triple,
    rsum: u32,
    gsum: u32,
    bsum: u32,
    ccount: u32,
}

impl IconMetric {
    /// `enginesize`: which per-side table this metric belongs to (0=16,1=24,2=32).
    fn enginesize(&self) -> usize {
        ((self.side >> 3) as usize).wrapping_sub(2)
    }

    /// Serialize to the 124-hex-nibble `.idb` blob form (including the 2-nibble
    /// side prefix). Used by tests and diagnostics.
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(124);
        push_hex(&mut s, self.side, 2);
        for t in [&self.color, &self.gray] {
            for i in 0..3 {
                push_hex(&mut s, t.avg[i], 3);
                push_hex(&mut s, t.x[i], 2);
                push_hex(&mut s, t.y[i], 2);
            }
        }
        for t in [&self.bright, &self.dark, &self.edge, &self.noedge] {
            for i in 0..3 {
                push_hex(&mut s, t.avg[i], 2);
                push_hex(&mut s, t.x[i], 2);
                push_hex(&mut s, t.y[i], 2);
            }
        }
        push_hex(&mut s, self.rsum, 2);
        push_hex(&mut s, self.gsum, 2);
        push_hex(&mut s, self.bsum, 2);
        push_hex(&mut s, self.ccount, 2);
        s
    }
}

fn push_hex(s: &mut String, v: u32, nibbles: usize) {
    // Lowercase, zero-padded to `nibbles`, low `nibbles` of `v`.
    let hex = b"0123456789abcdef";
    for shift in (0..nibbles).rev() {
        let nib = (v >> (4 * shift)) & 0xf;
        s.push(hex[nib as usize] as char);
    }
}

// ===========================================================================
// `.idb` parsing  (§6)
// ===========================================================================

/// One parsed `.idb` signature entry.
#[derive(Clone, Serialize, Deserialize, Debug)]
struct IdbEntry {
    name: String,
    /// Index into [`IconDb::groups0`] for this entry's IconGroup1 name.
    group0: u32,
    /// Index into [`IconDb::groups1`] for this entry's IconGroup2 name.
    group1: u32,
    /// The decoded metric, flattened for cheap serde (see [`MetricRepr`]).
    metric: MetricRepr,
}

/// A serde-friendly flattening of [`IconMetric`] (fixed-size arrays).
#[derive(Clone, Copy, Serialize, Deserialize, Debug)]
struct MetricRepr {
    side: u32,
    // 6 components × (avg[3], x[3], y[3]).
    comp: [[[u32; 3]; 3]; 6],
    spread: [u32; 4],
}

impl MetricRepr {
    fn from_metric(m: &IconMetric) -> Self {
        let pack = |t: &Triple| [t.avg, t.x, t.y];
        MetricRepr {
            side: m.side,
            comp: [
                pack(&m.color),
                pack(&m.gray),
                pack(&m.bright),
                pack(&m.dark),
                pack(&m.edge),
                pack(&m.noedge),
            ],
            spread: [m.rsum, m.gsum, m.bsum, m.ccount],
        }
    }
    fn to_metric(self) -> IconMetric {
        let unpack = |c: &[[u32; 3]; 3]| Triple {
            avg: c[0],
            x: c[1],
            y: c[2],
        };
        IconMetric {
            side: self.side,
            color: unpack(&self.comp[0]),
            gray: unpack(&self.comp[1]),
            bright: unpack(&self.comp[2]),
            dark: unpack(&self.comp[3]),
            edge: unpack(&self.comp[4]),
            noedge: unpack(&self.comp[5]),
            rsum: self.spread[0],
            gsum: self.spread[1],
            bsum: self.spread[2],
            ccount: self.spread[3],
        }
    }
}

/// The loaded `.idb` icon-signature database.
///
/// Entries are bucketed by `enginesize` (0=16, 1=24, 2=32) so the matcher only
/// compares an icon against same-side entries. The two group-name tables are
/// deduplicated; `.ldb` `IconGroup1/2` constraints reference them by name.
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct IconDb {
    /// Entries by side bucket: [16-side, 24-side, 32-side].
    buckets: [Vec<IdbEntry>; 3],
    /// Distinct IconGroup1 names, in first-seen order (index = group0).
    groups0: Vec<String>,
    /// Distinct IconGroup2 names, in first-seen order (index = group1).
    groups1: Vec<String>,
}

impl IconDb {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.buckets.iter().all(|b| b.is_empty())
    }

    pub fn len(&self) -> usize {
        self.buckets.iter().map(|b| b.len()).sum()
    }

    /// True when at least one group name exists in BOTH tables — ClamAV requires
    /// this before attempting any icon match.
    fn has_groups(&self) -> bool {
        !self.groups0.is_empty() && !self.groups1.is_empty()
    }

    fn intern(table: &mut Vec<String>, name: &str) -> u32 {
        if let Some(i) = table.iter().position(|g| g == name) {
            return i as u32;
        }
        table.push(name.to_string());
        (table.len() - 1) as u32
    }

    /// Parse `.idb` text and append its entries. Malformed lines are skipped.
    pub fn extend_from_text(&mut self, text: &str) {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Exactly 4 colon-separated tokens.
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() != 4 {
                continue;
            }
            let metric = match parse_hashblob(parts[3]) {
                Some(m) => m,
                None => continue,
            };
            let es = metric.enginesize();
            if es > 2 {
                continue;
            }
            let group0 = Self::intern(&mut self.groups0, parts[1]);
            let group1 = Self::intern(&mut self.groups1, parts[2]);
            // ClamAV rejects a DB with >256 distinct groups per side; mirror it
            // by refusing to register further entries beyond that bound.
            if self.groups0.len() > 256 || self.groups1.len() > 256 {
                continue;
            }
            self.buckets[es].push(IdbEntry {
                name: parts[0].to_string(),
                group0,
                group1,
                metric: MetricRepr::from_metric(&metric),
            });
        }
    }

    /// Resolve an `IconGroup1` constraint name to a set of group0 indices it
    /// selects (`"*"` selects all). Returns `None` if a literal name isn't
    /// present (the constraint can then never be satisfied).
    fn select0(&self, name: &str) -> Option<GroupSel> {
        Self::select(&self.groups0, name)
    }
    fn select1(&self, name: &str) -> Option<GroupSel> {
        Self::select(&self.groups1, name)
    }
    fn select(table: &[String], name: &str) -> Option<GroupSel> {
        if name == "*" {
            return Some(GroupSel::All);
        }
        // Case-sensitive, byte-exact strcmp; no hex decoding of names.
        table
            .iter()
            .position(|g| g == name)
            .map(|i| GroupSel::One(i as u32))
    }

    /// Run the icon matcher: does `metric` (a PE icon) match any `.idb` entry
    /// whose group1/group2 satisfy `grp1`/`grp2` (each `None` ⇒ `"*"`)?
    /// Returns the matching entry's signature name, or `None`.
    fn match_metric(
        &self,
        metric: &IconMetric,
        grp1: Option<&str>,
        grp2: Option<&str>,
    ) -> Option<String> {
        if !self.has_groups() {
            return None;
        }
        let sel0 = self.select0(grp1.unwrap_or("*"))?;
        let sel1 = self.select1(grp2.unwrap_or("*"))?;
        let es = metric.enginesize();
        if es > 2 {
            return None;
        }
        for e in &self.buckets[es] {
            if !sel0.contains(e.group0) || !sel1.contains(e.group1) {
                continue;
            }
            let cand = e.metric.to_metric();
            if matches(metric, &cand) {
                return Some(e.name.clone());
            }
        }
        None
    }

    /// Public entry point used by the engine: extract the PE's icon(s), hash
    /// each, and report the first confident match for the given group
    /// constraints. `icon_metrics` is the per-scan cache of computed metrics.
    pub fn match_pe(
        &self,
        icon_metrics: &[IconMetric],
        grp1: Option<&str>,
        grp2: Option<&str>,
    ) -> Option<String> {
        if !self.has_groups() {
            return None;
        }
        for m in icon_metrics {
            if let Some(name) = self.match_metric(m, grp1, grp2) {
                return Some(name);
            }
        }
        None
    }
}

/// A resolved group-name selection for one side of the IconGroup constraint.
#[derive(Clone, Copy)]
enum GroupSel {
    All,
    One(u32),
}
impl GroupSel {
    fn contains(self, idx: u32) -> bool {
        match self {
            GroupSel::All => true,
            GroupSel::One(i) => i == idx,
        }
    }
}

/// Parse a 124-nibble `.idb` hash blob into an [`IconMetric`]. Returns `None`
/// on any malformed field (wrong length, out-of-range coordinate, bad side).
fn parse_hashblob(blob: &str) -> Option<IconMetric> {
    let blob = blob.trim();
    if blob.len() != 124 || !blob.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let h: Vec<u32> = blob.bytes().map(hex_nibble).collect();
    let mut c = 0usize; // nibble cursor
    let take = |c: &mut usize, n: usize| -> u32 {
        let mut v = 0u32;
        for _ in 0..n {
            v = (v << 4) | h[*c];
            *c += 1;
        }
        v
    };

    let side = take(&mut c, 2);
    if side != 16 && side != 24 && side != 32 {
        return None;
    }
    let coord_max = side - side / 8; // 14 / 21 / 28

    let read_triple3 = |c: &mut usize| -> Option<Triple> {
        // color/gray: avg is 3 nibbles (≤4072), x/y are 2 nibbles (≤coord_max).
        let mut t = Triple::default();
        for i in 0..3 {
            t.avg[i] = take(c, 3);
            if t.avg[i] > 4072 {
                return None;
            }
            t.x[i] = take(c, 2);
            if t.x[i] > coord_max {
                return None;
            }
            t.y[i] = take(c, 2);
            if t.y[i] > coord_max {
                return None;
            }
        }
        Some(t)
    };
    let color = read_triple3(&mut c)?;
    let gray = read_triple3(&mut c)?;

    let read_triple2 = |c: &mut usize| -> Option<Triple> {
        // bright/dark/edge/noedge: avg 2 nibbles (no upper bound beyond 0xff),
        // x/y 2 nibbles (≤coord_max).
        let mut t = Triple::default();
        for i in 0..3 {
            t.avg[i] = take(c, 2);
            t.x[i] = take(c, 2);
            if t.x[i] > coord_max {
                return None;
            }
            t.y[i] = take(c, 2);
            if t.y[i] > coord_max {
                return None;
            }
        }
        Some(t)
    };
    let bright = read_triple2(&mut c)?;
    let dark = read_triple2(&mut c)?;
    let edge = read_triple2(&mut c)?;
    let noedge = read_triple2(&mut c)?;

    let rsum = take(&mut c, 2);
    let gsum = take(&mut c, 2);
    let bsum = take(&mut c, 2);
    let ccount = take(&mut c, 2);
    if rsum + gsum + bsum > 103 || ccount > 100 {
        return None;
    }

    Some(IconMetric {
        side,
        color,
        gray,
        bright,
        dark,
        edge,
        noedge,
        rsum,
        gsum,
        bsum,
        ccount,
    })
}

fn hex_nibble(b: u8) -> u32 {
    match b {
        b'0'..=b'9' => (b - b'0') as u32,
        b'a'..=b'f' => (b - b'a' + 10) as u32,
        b'A'..=b'F' => (b - b'A' + 10) as u32,
        _ => 0,
    }
}

// ===========================================================================
// PE resource walk  (§1)  →  list of RT_ICON byte slices
// ===========================================================================

/// Cap on declared icon entries parsed (ClamAV `maxiconspe`, default 100).
const MAX_ICONS: usize = 100;

/// Little-endian readers, all bounds-checked.
fn rd_u16(d: &[u8], off: usize) -> Option<u16> {
    d.get(off..off + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}
fn rd_u32(d: &[u8], off: usize) -> Option<u32> {
    d.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Minimal section-table RVA→file-offset mapper (ClamAV `cli_rawaddr`).
struct RvaMap {
    /// (rva, vsize, raw, rsize) per section.
    secs: Vec<(u32, u32, u32, u32)>,
    hdr_size: u32,
}

impl RvaMap {
    fn from_pe(pe: &goblin::pe::PE) -> Self {
        let hdr_size = pe
            .header
            .optional_header
            .map(|o| o.windows_fields.size_of_headers)
            .unwrap_or(0);
        let secs = pe
            .sections
            .iter()
            .map(|s| {
                (
                    s.virtual_address,
                    s.virtual_size.max(s.size_of_raw_data),
                    s.pointer_to_raw_data,
                    s.size_of_raw_data,
                )
            })
            .collect();
        RvaMap { secs, hdr_size }
    }

    /// Translate an RVA to a file offset, or `None` if it maps nowhere.
    fn raw(&self, rva: u32) -> Option<u32> {
        if rva < self.hdr_size {
            return Some(rva);
        }
        for &(va, vsz, raw, rsz) in &self.secs {
            // Use the raw size for the in-file extent (a section can be larger
            // virtually than on disk); fall back to vsize if rsz is 0.
            let extent = if rsz != 0 { rsz } else { vsz };
            if extent != 0 && rva >= va && rva - va < extent {
                return Some(raw.wrapping_add(rva - va));
            }
        }
        None
    }
}

/// Walk the PE resource directory and return the raw byte slices of the
/// `RT_ICON` resources referenced by the FIRST `RT_GROUP_ICON` group.
fn extract_icon_blobs(data: &[u8]) -> Vec<&[u8]> {
    extract_icon_blobs_inner(data).unwrap_or_default()
}

fn extract_icon_blobs_inner(data: &[u8]) -> Option<Vec<&[u8]>> {
    let pe = goblin::pe::PE::parse(data).ok()?;
    let oh = pe.header.optional_header?;
    let dd = oh.data_directories.get_resource_table()?;
    let res_rva = dd.virtual_address;
    if res_rva == 0 {
        return None;
    }
    let map = RvaMap::from_pe(&pe);
    let res_base = map.raw(res_rva)? as usize;
    // The resource subtree is addressed by offsets relative to `res_base`.

    // Find the FIRST RT_GROUP_ICON (type 14) leaf. We must enumerate all NAMEs
    // (named + id) under it, and at each name take the first LANG leaf.
    let grp_leaves = find_type_leaves(data, res_base, 14)?;

    let mut blobs: Vec<&[u8]> = Vec::new();
    let mut parsed = 0usize;
    // Process the first group only (ClamAV processes the first matching TYPE
    // node; the first leaf encountered carries the group). Iterate the group's
    // entries and resolve each referenced RT_ICON.
    for leaf_off in grp_leaves {
        // Each leaf_off is the offset (relative to res_base) of an
        // IMAGE_RESOURCE_DATA_ENTRY descriptor.
        let (grp_off, grp_size) = read_data_entry(data, &map, res_base, leaf_off)?;
        let grp = data.get(grp_off..grp_off + grp_size)?;
        // GRPICONDIR: u16 reserved, u16 type, u16 count.
        if grp.len() < 6 {
            continue;
        }
        let count = rd_u16(grp, 4)? as usize;
        let mut p = 6usize;
        for _ in 0..count {
            if parsed >= MAX_ICONS {
                return Some(blobs);
            }
            let ent = match grp.get(p..p + 14) {
                Some(e) => e,
                None => break,
            };
            let icon_id = rd_u16(ent, 12)? as u32;
            parsed += 1;
            // Resolve RT_ICON (type 3) with NAME == icon_id.
            if let Some(icon_leaf) = find_named_leaf(data, res_base, 3, icon_id) {
                if let Some((ioff, isize)) = read_data_entry(data, &map, res_base, icon_leaf) {
                    if let Some(blob) = data.get(ioff..ioff + isize) {
                        blobs.push(blob);
                    }
                }
            }
            p += 14;
        }
        // ClamAV processes only the first group's worth of entries via the first
        // matching type node; stop after the first group leaf.
        break;
    }
    Some(blobs)
}

/// A 16-byte resource directory node header: returns (named_count, id_count).
fn dir_counts(data: &[u8], abs_off: usize) -> Option<(usize, usize)> {
    let named = rd_u16(data, abs_off + 12)? as usize;
    let ids = rd_u16(data, abs_off + 14)? as usize;
    Some((named, ids))
}

/// Iterate the (8-byte) entries of a resource directory at absolute file offset
/// `abs_off`, invoking `f(entry_id_field, offset_field)` for each. Bounds-safe.
fn for_each_dir_entry<F: FnMut(u32, u32) -> bool>(
    data: &[u8],
    abs_off: usize,
    mut f: F,
) -> Option<()> {
    let (named, ids) = dir_counts(data, abs_off)?;
    let total = named.checked_add(ids)?;
    // Guard against absurd counts (hostile input).
    if total > 1 << 20 {
        return None;
    }
    let mut e = abs_off + 16;
    for _ in 0..total {
        let id = rd_u32(data, e)?;
        let offv = rd_u32(data, e + 4)?;
        if f(id, offv) {
            return Some(());
        }
        e += 8;
    }
    Some(())
}

/// Resolve the TYPE-level node for `by_type`, then collect, for each NAME under
/// it, the RVA of the first LANG-level data-entry leaf. Returns the leaf RVAs.
fn find_type_leaves(data: &[u8], res_base: usize, by_type: u32) -> Option<Vec<u32>> {
    // Level 1: TYPE. Only ID entries are scanned for types (per spec).
    let mut type_sub: Option<u32> = None;
    for_each_dir_entry(data, res_base, |id, offv| {
        // Named type entries are skipped; we want the ID entry == by_type, and
        // the first matching TYPE node only.
        if id & 0x8000_0000 == 0 && id == by_type && offv & 0x8000_0000 != 0 {
            type_sub = Some(offv & 0x7fff_ffff);
            return true; // stop after the first matching type
        }
        false
    })?;
    let type_sub = type_sub?;
    let name_dir = res_base + type_sub as usize;

    // Level 2: NAME. Iterate BOTH named and id entries; each must be a
    // subdirectory (LANG level). For each, take the first LANG data leaf.
    let mut leaves: Vec<u32> = Vec::new();
    for_each_dir_entry(data, name_dir, |_id, offv| {
        if offv & 0x8000_0000 != 0 {
            let lang_dir = res_base + (offv & 0x7fff_ffff) as usize;
            if let Some(rva) = first_lang_leaf(data, lang_dir) {
                leaves.push(rva);
            }
        }
        false
    })?;
    Some(leaves)
}

/// Resolve a specific (TYPE=`by_type`, NAME=`by_name`) data-entry leaf RVA.
fn find_named_leaf(data: &[u8], res_base: usize, by_type: u32, by_name: u32) -> Option<u32> {
    let mut type_sub: Option<u32> = None;
    for_each_dir_entry(data, res_base, |id, offv| {
        if id & 0x8000_0000 == 0 && id == by_type && offv & 0x8000_0000 != 0 {
            type_sub = Some(offv & 0x7fff_ffff);
            return true;
        }
        false
    })?;
    let name_dir = res_base + type_sub? as usize;

    let mut name_sub: Option<u32> = None;
    for_each_dir_entry(data, name_dir, |id, offv| {
        // ID name entry == by_name.
        if id & 0x8000_0000 == 0 && id == by_name && offv & 0x8000_0000 != 0 {
            name_sub = Some(offv & 0x7fff_ffff);
            return true;
        }
        false
    })?;
    let lang_dir = res_base + name_sub? as usize;
    first_lang_leaf(data, lang_dir)
}

/// At the LANG level: return the offset (relative to res_base) of the first
/// data-entry leaf (offset high bit clear).
fn first_lang_leaf(data: &[u8], lang_dir: usize) -> Option<u32> {
    let mut found: Option<u32> = None;
    for_each_dir_entry(data, lang_dir, |_id, offv| {
        if offv & 0x8000_0000 == 0 {
            // The data-entry descriptor sits at res_base + offv; its RVA is
            // res_rva + offv. We track the file offset directly: the leaf's
            // file offset is res_base + offv.
            found = Some(offv);
            return true;
        }
        false
    })?;
    found
}

/// Read an IMAGE_RESOURCE_DATA_ENTRY at `res_base + leaf_off`: first dword is the
/// content RVA, second is the size. Returns (file_offset, size) of the content.
fn read_data_entry(
    data: &[u8],
    map: &RvaMap,
    res_base: usize,
    leaf_off: u32,
) -> Option<(usize, usize)> {
    let desc = res_base.checked_add(leaf_off as usize)?;
    let content_rva = rd_u32(data, desc)?;
    let size = rd_u32(data, desc + 4)? as usize;
    let off = map.raw(content_rva)? as usize;
    // Bound the size to the remaining file.
    let avail = data.len().checked_sub(off)?;
    Some((off, size.min(avail)))
}

// ===========================================================================
// DIB decode  (§2)  →  ARGB buffer, white-blended
// ===========================================================================

/// A decoded, normalised icon: a `side × side` ARGB pixel buffer (0xAARRGGBB
/// conceptually; per ClamAV byte convention low byte = blue).
struct DecodedIcon {
    width: usize,
    height: usize,
    pixels: Vec<u32>,
    scalemode: u8,
}

/// Decode one RT_ICON DIB blob. Returns `None` to skip (PNG icon, out of range,
/// malformed). Tolerant of the DIB quirks real PE icons exhibit.
fn parse_icon(blob: &[u8]) -> Option<DecodedIcon> {
    if blob.len() < 40 {
        return None;
    }
    let bi_size = rd_u32(blob, 0)? as usize;
    if bi_size < 40 {
        return None;
    }
    let bi_width = rd_u32(blob, 4)? as i64;
    let bi_height = rd_u32(blob, 8)? as i64;
    let depth = rd_u16(blob, 14)? as u32;

    let width = bi_width;
    let height = bi_height / 2;
    if width <= 0 || height <= 0 {
        return None;
    }
    let width = width as usize;
    let height = height as usize;

    // Dimension gate.
    if width > 256 || height > 256 || width < 16 || height < 16 {
        return None;
    }
    if width < height * 3 / 4 || height < width * 3 / 4 {
        return None;
    }

    // Scale-mode selection.
    let scalemode: u8 = if width == height {
        if width == 16 || width == 24 || width == 32 {
            0
        } else if width % 32 == 0 || width % 24 == 0 {
            1
        } else {
            2
        }
    } else {
        2
    };

    // Cursor advances past the (possibly v4/v5) header.
    let mut cur = bi_size;

    // Palette / depth handling.
    let palette: Vec<u32> = match depth {
        0 => return None, // PNG/JPEG compressed icon: skip.
        1 | 4 | 8 => {
            let n = 1usize << depth;
            let pal_bytes = blob.get(cur..cur + n * 4)?;
            let mut pal = Vec::with_capacity(n);
            for i in 0..n {
                pal.push(rd_u32(pal_bytes, i * 4)?);
            }
            cur += n * 4;
            pal
        }
        16 | 24 | 32 => Vec::new(),
        _ => return None,
    };

    // Line sizes (4-byte row alignment).
    let scanlinesz =
        4 * (width * (depth as usize) / 32) + 4 * (((width * (depth as usize)) % 32 != 0) as usize);
    let andlinesz_base = 4 * (width / 32) + 4 * ((width % 32 != 0) as usize);

    let npix = width * height;
    let mut pixels = vec![0u32; npix];
    let mut special_32_is_32: u32 = 0;

    // Decode the XOR (color) bitmap, bottom-up → output top-down.
    for y in 0..height {
        let out_row = height - 1 - y;
        let row = blob.get(cur..cur + scanlinesz)?;
        match depth {
            1 | 4 | 8 => {
                for x in 0..width {
                    let bit_off = x * depth as usize;
                    let byte_idx = bit_off / 8;
                    let in_byte = bit_off % 8;
                    let b = *row.get(byte_idx)? as u32;
                    let idx = match depth {
                        1 => (b >> (7 - in_byte)) & 0x1,
                        4 => (b >> (4 - in_byte)) & 0xf,
                        8 => b,
                        _ => unreachable!(),
                    };
                    let px = *palette.get(idx as usize)?;
                    pixels[out_row * width + x] = px & 0x00ff_ffff;
                }
            }
            16 => {
                for x in 0..width {
                    let b0 = *row.get(x * 2)? as u32;
                    let b1 = *row.get(x * 2 + 1)? as u32;
                    let bb = b0 & 0x1f;
                    let gg = (b0 >> 5) | ((b1 & 0x3) << 3);
                    let rr = b1 & 0xfc;
                    let blue = (bb << 3) | (bb >> 2);
                    let green = ((gg << 3) | (gg >> 2)) << 11;
                    let red = ((rr << 3) | (rr >> 2)) << 17;
                    // Compose the pixel from the 5/6/5 channels: pixel = r | g | b.
                    let pixel = red | green | blue;
                    pixels[out_row * width + x] = pixel;
                }
            }
            24 => {
                for x in 0..width {
                    let b0 = *row.get(x * 3)? as u32;
                    let b1 = *row.get(x * 3 + 1)? as u32;
                    let b2 = *row.get(x * 3 + 2)? as u32;
                    let pixel = b0 | (b1 << 8) | (b2 << 16);
                    pixels[out_row * width + x] = pixel;
                }
            }
            32 => {
                for x in 0..width {
                    let b0 = *row.get(x * 4)? as u32;
                    let b1 = *row.get(x * 4 + 1)? as u32;
                    let b2 = *row.get(x * 4 + 2)? as u32;
                    let b3 = *row.get(x * 4 + 3)? as u32;
                    let pixel = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
                    special_32_is_32 |= b3;
                    pixels[out_row * width + x] = pixel;
                }
            }
            _ => return None,
        }
        cur += scanlinesz;
    }

    // AND-MASK / alpha.
    let depth_low = depth & 0x1f; // 0 for depth 32
    if depth == 32 && special_32_is_32 == 0 {
        // Declared 32bpp but no alpha bit ever set: treat as 24-bit and read a
        // separate AND mask.
        let andlinesz = andlinesz_base;
        if !apply_and_mask(blob, &mut cur, &mut pixels, width, height, andlinesz) {
            // Mask unreadable: force full opacity.
            for p in pixels.iter_mut() {
                *p |= 0xff00_0000;
            }
        }
    } else if depth_low != 0 {
        // depths 1/4/8/16/24: AND mask immediately follows.
        let andlinesz = andlinesz_base;
        apply_and_mask(blob, &mut cur, &mut pixels, width, height, andlinesz);
    } else {
        // True 32-bpp icon: source alpha used as-is (AND-mask loop skipped).
    }

    // Alpha blend over white.
    for p in pixels.iter_mut() {
        let a = (*p >> 24) & 0xff;
        let r = (*p >> 16) & 0xff;
        let g = (*p >> 8) & 0xff;
        let b = *p & 0xff;
        let rp = 0xff - a + a * r / 0xff;
        let gp = 0xff - a + a * g / 0xff;
        let bp = 0xff - a + a * b / 0xff;
        *p = 0xff00_0000 | (rp << 16) | (gp << 8) | bp;
    }

    Some(DecodedIcon {
        width,
        height,
        pixels,
        scalemode,
    })
}

/// Apply the AND (1-bpp transparency) mask: bit 1 = transparent, bit 0 = opaque.
/// Opaque pixels get alpha 0xff. Returns false if the mask can't be fully read.
fn apply_and_mask(
    blob: &[u8],
    cur: &mut usize,
    pixels: &mut [u32],
    width: usize,
    height: usize,
    andlinesz: usize,
) -> bool {
    for y in 0..height {
        let out_row = height - 1 - y;
        let row = match blob.get(*cur..*cur + andlinesz) {
            Some(r) => r,
            None => return false,
        };
        for x in 0..width {
            let byte_idx = x / 8;
            let bit = 7 - (x % 8);
            let mask_bit = match row.get(byte_idx) {
                Some(&b) => (b >> bit) & 1,
                None => return false,
            };
            if mask_bit == 0 {
                pixels[out_row * width + x] |= 0xff00_0000;
            }
        }
        *cur += andlinesz;
    }
    true
}

// ===========================================================================
// Scaling / normalization  (§4)
// ===========================================================================

/// Normalise a decoded icon to side ∈ {16,24,32}. Returns (side, pixels).
fn normalize(icon: DecodedIcon) -> Option<(usize, Vec<u32>)> {
    let DecodedIcon {
        mut width,
        mut height,
        mut pixels,
        scalemode,
    } = icon;
    match scalemode {
        0 => Some((width, pixels)),
        1 => {
            // FAST 50%: while width > 32, halve by averaging 2×2 blocks.
            while width > 32 {
                let nw = width / 2;
                let nh = height / 2;
                let mut out = vec![0u32; nw * nh];
                for y in 0..nh {
                    for x in 0..nw {
                        let c1 = pixels[(2 * y) * width + 2 * x];
                        let c2 = pixels[(2 * y) * width + 2 * x + 1];
                        let c3 = pixels[(2 * y + 1) * width + 2 * x];
                        let c4 = pixels[(2 * y + 1) * width + 2 * x + 1];
                        let h1 = avg2(c1, c2);
                        let h2 = avg2(c3, c4);
                        out[y * nw + x] = avg2(h1, h2);
                    }
                }
                pixels = out;
                width = nw;
                height = nh;
            }
            Some((width, pixels))
        }
        _ => {
            // SLOW up/down: choose newsize by nearest of {32,24,16}.
            let w = width as i64;
            let h = height as i64;
            let d = |a: i64, b: i64| (w - a).abs() + (h - b).abs();
            let newsize: usize = if d(32, 32) < d(24, 24) {
                32
            } else if d(24, 24) < d(16, 16) {
                24
            } else {
                16
            };
            let scalex = width as f64 / newsize as f64;
            let scaley = height as f64 / newsize as f64;
            let mut out = vec![0u32; newsize * newsize];
            for y in 0..newsize {
                // Y truncates (no +0.5).
                let oldy = (y as f64 * scaley).floor() as usize;
                let row_base = oldy * width;
                for x in 0..newsize {
                    // X rounds (+0.5).
                    let oldx = (x as f64 * scalex + 0.5).floor() as usize;
                    let src = (row_base + oldx).min(pixels.len().saturating_sub(1));
                    out[y * newsize + x] = pixels[src];
                }
            }
            Some((newsize, out))
        }
    }
}

/// Per-channel average of two ARGB words without carry across channels.
fn avg2(c1: u32, c2: u32) -> u32 {
    (((c1 ^ c2) & 0xfefe_fefe) >> 1).wrapping_add(c1 & c2)
}

// ===========================================================================
// The icon hash / metric  (§5)
// ===========================================================================

/// Compute the [`IconMetric`] for a normalised `side × side` ARGB buffer.
fn get_metrics(side: usize, pixels: &[u32]) -> Option<IconMetric> {
    if side != 16 && side != 24 && side != 32 {
        return None;
    }
    if pixels.len() != side * side {
        return None;
    }
    let ksize = side / 4;

    // --- 5.1/5.2: per-window color & light sums + color presence over pixels.
    // Window sums over ksize×ksize for color (sqrt(s²v)) and light (v).
    let mut colsum = vec![0u32; (side - ksize + 1) * (side - ksize + 1)];
    let mut lightsum = vec![0u32; (side - ksize + 1) * (side - ksize + 1)];
    let wspan = side - ksize + 1;

    // Precompute per-pixel hsv-derived c (sqrt(s²v)) and v.
    let mut csqv = vec![0u32; side * side];
    let mut vval = vec![0u32; side * side];
    let mut rsum: u64 = 0;
    let mut gsum: u64 = 0;
    let mut bsum: u64 = 0;
    let mut ccount: u64 = 0;
    for i in 0..side * side {
        let c = pixels[i];
        let r = (c >> 16) & 0xff;
        let g = (c >> 8) & 0xff;
        let b = c & 0xff;
        let mn = r.min(g).min(b);
        let mx = r.max(g).max(b);
        let v = mx;
        let delta = mx - mn;
        let s = if delta == 0 { 0 } else { 255 * delta / mx };
        let cq = ((s * s * v) as f64).sqrt() as u32;
        csqv[i] = cq;
        vval[i] = v;
        if s > 85 && v > 85 {
            // delta != 0 guaranteed (s>85).
            ccount += 1;
            rsum += 100 - 100 * (g as i64 - b as i64).unsigned_abs() / delta as u64;
            gsum += 100 - 100 * (r as i64 - b as i64).unsigned_abs() / delta as u64;
            bsum += 100 - 100 * (r as i64 - g as i64).unsigned_abs() / delta as u64;
        }
    }
    // Window sums (plain double loop; identical totals to a running sum).
    for wy in 0..wspan {
        for wx in 0..wspan {
            let mut cs = 0u32;
            let mut ls = 0u32;
            for dy in 0..ksize {
                for dx in 0..ksize {
                    let idx = (wy + dy) * side + (wx + dx);
                    cs += csqv[idx];
                    ls += vval[idx];
                }
            }
            colsum[wy * wspan + wx] = cs;
            lightsum[wy * wspan + wx] = ls;
        }
    }

    // Finalize color presence.
    let total = (side * side) as u64;
    let mut bwonly = false;
    let (rs, gs, bs, cc);
    if ccount * 100 / total > 5 {
        rs = (rsum / ccount) as u32;
        gs = (gsum / ccount) as u32;
        bs = (bsum / ccount) as u32;
        cc = (ccount * 100 / total) as u32;
    } else {
        rs = 0;
        gs = 0;
        bs = 0;
        cc = 0;
        bwonly = true;
    }

    // --- 5.3: top/bottom-3 non-overlapping cells over colsum & lightsum.
    let color = pick_extreme(&colsum, wspan, ksize, true, 3);
    let gray = pick_extreme(&colsum, wspan, ksize, false, 3);
    let bright = pick_extreme(&lightsum, wspan, ksize, true, 3);
    let dark = pick_extreme(&lightsum, wspan, ksize, false, 3);

    // --- 5.4: edge detection (Lab→Sobel→normalize→blur) → edge/noedge cells.
    let edge_field = edge_image(side, pixels);
    // Sliding window sum over the blurred edge image (blue channel).
    let mut edgesum = vec![0u32; wspan * wspan];
    for wy in 0..wspan {
        for wx in 0..wspan {
            let mut sum = 0u32;
            for dy in 0..ksize {
                for dx in 0..ksize {
                    sum += edge_field[(wy + dy) * side + (wx + dx)] & 0xff;
                }
            }
            edgesum[wy * wspan + wx] = sum;
        }
    }
    // bwonly: pick 6 of each (extra 3 reused into color/gray slots).
    let npick = if bwonly { 6 } else { 3 };
    let edge_full = pick_extreme(&edgesum, wspan, ksize, true, npick);
    let noedge_full = pick_extreme(&edgesum, wspan, ksize, false, npick);

    let k2 = (ksize * ksize) as u32;
    let mut color = div_triple(extract3(&color, 0), k2);
    let mut gray = div_triple(extract3(&gray, 0), k2);
    let bright = div_triple(extract3(&bright, 0), k2);
    let dark = div_triple(extract3(&dark, 0), k2);
    let edge = div_triple(extract3(&edge_full, 0), k2);
    let noedge = div_triple(extract3(&noedge_full, 0), k2);

    // --- 5.5: bwonly substitution.
    if bwonly {
        // color slots ← edge[3..6]; gray slots ← noedge AVG but EDGE x/y[3..6].
        let edge_extra = div_triple(extract3(&edge_full, 3), k2);
        let noedge_extra_avg = div_triple(extract3(&noedge_full, 3), k2);
        let edge_extra_coords = extract3(&edge_full, 3); // raw coords (x/y) reused
        for i in 0..3 {
            color.avg[i] = edge_extra.avg[i];
            color.x[i] = edge_extra.x[i];
            color.y[i] = edge_extra.y[i];
            gray.avg[i] = noedge_extra_avg.avg[i];
            // Quirk: gray x/y come from EDGE extra coords, not noedge.
            gray.x[i] = edge_extra_coords.x[i];
            gray.y[i] = edge_extra_coords.y[i];
        }
    }

    Some(IconMetric {
        side: side as u32,
        color,
        gray,
        bright,
        dark,
        edge,
        noedge,
        rsum: rs,
        gsum: gs,
        bsum: bs,
        ccount: cc,
    })
}

/// Divide every avg in a triple by `k2` (cells → per-pixel averages).
fn div_triple(mut t: Triple, k2: u32) -> Triple {
    for i in 0..3 {
        t.avg[i] /= k2;
    }
    t
}

/// Extract a 3-cell [`Triple`] starting at offset `base` (0 or 3) from a 6-slot
/// extreme-pick result.
fn extract3(full: &ExtremePick, base: usize) -> Triple {
    let mut t = Triple::default();
    for i in 0..3 {
        t.avg[i] = full.avg[base + i];
        t.x[i] = full.x[base + i];
        t.y[i] = full.y[base + i];
    }
    t
}

/// Result of [`pick_extreme`]: up to 6 chosen cells (avg + coords).
struct ExtremePick {
    avg: [u32; 6],
    x: [u32; 6],
    y: [u32; 6],
}

/// Pick the top-`n` (MAX) or bottom-`n` (MIN) non-overlapping ksize windows from
/// a `wspan × wspan` window-sum field. Ties go to the earliest scan (first
/// window achieving the extreme via strict `>`/`<`).
fn pick_extreme(field: &[u32], wspan: usize, ksize: usize, max: bool, n: usize) -> ExtremePick {
    let mut res = ExtremePick {
        avg: [0; 6],
        x: [0; 6],
        y: [0; 6],
    };
    // x scan range per spec: x in 0..side-1-ksize i.e. wx < wspan-1; y in
    // 0..side-ksize i.e. wy < wspan. We mirror that (note the asymmetric x).
    let xspan = wspan.saturating_sub(1);
    for i in 0..n {
        let mut best: Option<(u32, usize, usize)> = None; // (val, wx, wy)
        for wy in 0..wspan {
            for wx in 0..xspan {
                // Overlap test against previously chosen cells [0..i).
                let mut overlaps = false;
                for j in 0..i {
                    let cx = res.x[j] as usize;
                    let cy = res.y[j] as usize;
                    if wx + ksize > cx && wx < cx + ksize && wy + ksize > cy && wy < cy + ksize {
                        overlaps = true;
                        break;
                    }
                }
                if overlaps {
                    continue;
                }
                let val = field[wy * wspan + wx];
                let take = match best {
                    None => true,
                    Some((bv, _, _)) => {
                        if max {
                            val > bv
                        } else {
                            val < bv
                        }
                    }
                };
                if take {
                    best = Some((val, wx, wy));
                }
            }
        }
        if let Some((v, wx, wy)) = best {
            res.avg[i] = v;
            res.x[i] = wx as u32;
            res.y[i] = wy as u32;
        }
    }
    res
}

// --- Lab / Sobel / Gaussian (§5.4) -----------------------------------------

/// Reference Lab colour (mid-gray 0x7f7f7f), the distance origin for `labdiff`.
const REF_L: f64 = 53.192_777_691_077_21;
const REF_A: f64 = 0.0031420942181448197;
const REF_B: f64 = -0.006_207_587_784_401_447;

/// Perceptual distance of an ARGB pixel's colour from mid-gray (CIE Lab L2).
fn labdiff(c: u32) -> f64 {
    let r = ((c >> 16) & 0xff) as f64;
    let g = ((c >> 8) & 0xff) as f64;
    let b = (c & 0xff) as f64;
    let inv = |ch: f64| -> f64 {
        let mut t = ch / 255.0;
        if t > 0.04045 {
            t = ((t + 0.055) / 1.055).powf(2.4);
        } else {
            t /= 12.92;
        }
        t * 100.0
    };
    let r = inv(r);
    let g = inv(g);
    let b = inv(b);
    let mut x = r * 0.4124 + g * 0.3576 + b * 0.1805;
    let mut y = r * 0.2126 + g * 0.7152 + b * 0.0722;
    let mut z = r * 0.0193 + g * 0.1192 + b * 0.9505;
    x /= 95.047;
    y /= 100.0;
    z /= 108.883;
    let f = |t: f64| -> f64 {
        if t > 0.008856 {
            t.powf(1.0 / 3.0)
        } else {
            7.787 * t + 16.0 / 116.0
        }
    };
    let fx = f(x);
    let fy = f(y);
    let fz = f(z);
    let l = 116.0 * fy - 16.0;
    let a = 500.0 * (fx - fy);
    let bb = 200.0 * (fy - fz);
    let dl = REF_L - l;
    let da = REF_A - a;
    let db = REF_B - bb;
    (dl * dl + da * da + db * db).sqrt()
}

/// Build the blurred edge image: a `side × side` grayscale ARGB field whose blue
/// channel holds the (Sobel→normalize→black-border→Gaussian-blur) edge value.
fn edge_image(side: usize, pixels: &[u32]) -> Vec<u32> {
    // Lab distance field.
    let sobel_field: Vec<f64> = pixels.iter().map(|&c| labdiff(c)).collect();

    // Sobel magnitude (interior 1..side-2), tracking max.
    let mut mag = vec![0u32; side * side];
    let mut maxmag = 0u32;
    if side >= 3 {
        for y in 1..side - 1 {
            for x in 1..side - 1 {
                let s = |yy: usize, xx: usize| sobel_field[yy * side + xx];
                let gx = (s(y - 1, x - 1) + 2.0 * s(y, x - 1) + s(y + 1, x - 1))
                    - (s(y - 1, x + 1) + 2.0 * s(y, x + 1) + s(y + 1, x + 1));
                let gy = (s(y - 1, x - 1) + 2.0 * s(y - 1, x) + s(y - 1, x + 1))
                    - (s(y + 1, x - 1) + 2.0 * s(y + 1, x) + s(y + 1, x + 1));
                let m = (gx * gx + gy * gy).sqrt() as u32;
                mag[y * side + x] = m;
                if m > maxmag {
                    maxmag = m;
                }
            }
        }
    }

    // Normalize to 0..255 → gray pixel; border stays untouched, then forced black.
    let mut img = vec![0xff00_0000u32; side * side];
    #[allow(clippy::manual_checked_ops)]
    if maxmag > 0 {
        for y in 1..side - 1 {
            for x in 1..side - 1 {
                let cval = mag[y * side + x] * 255 / maxmag;
                img[y * side + x] = 0xff00_0000 | cval | (cval << 8) | (cval << 16);
            }
        }
    }
    // Force a black 1-pixel border.
    for x in 0..side {
        img[x] = 0xff00_0000;
        img[(side - 1) * side + x] = 0xff00_0000;
    }
    for y in 0..side {
        img[y * side] = 0xff00_0000;
        img[y * side + side - 1] = 0xff00_0000;
    }

    // Gaussian blur with separable {1,2,1}, edge-clamped (truncated kernel).
    // Horizontal pass: read blue channel, write into green channel.
    let kern = [1i64, 2, 1];
    for y in 0..side {
        for x in 0..side {
            let mut sum = 0i64;
            let mut wsum = 0i64;
            for (di, &w) in kern.iter().enumerate() {
                let disp = di as i64 - 1;
                let xi = x as i64 + disp;
                if xi >= 0 && (xi as usize) < side {
                    let blue = (img[y * side + xi as usize] & 0xff) as i64;
                    sum += w * blue;
                    wsum += w;
                }
            }
            let val = if wsum > 0 { (sum / wsum) as u32 } else { 0 };
            // Store into green channel (bits 8..15), preserving the rest.
            img[y * side + x] = (img[y * side + x] & 0xffff_00ff) | (val << 8);
        }
    }
    // Vertical pass: read green channel just written, write back as gray.
    let mut out = img.clone();
    for y in 0..side {
        for x in 0..side {
            let mut sum = 0i64;
            let mut wsum = 0i64;
            for (di, &w) in kern.iter().enumerate() {
                let disp = di as i64 - 1;
                let yi = y as i64 + disp;
                if yi >= 0 && (yi as usize) < side {
                    let green = ((img[yi as usize * side + x] >> 8) & 0xff) as i64;
                    sum += w * green;
                    wsum += w;
                }
            }
            let val = if wsum > 0 { (sum / wsum) as u32 } else { 0 };
            out[y * side + x] = 0xff00_0000 | val | (val << 8) | (val << 16);
        }
    }
    out
}

// ===========================================================================
// Matching  (§7)
// ===========================================================================

/// Whether PE icon metric `a` matches `.idb` entry metric `b` at or above the
/// size/B&W threshold.
fn matches(a: &IconMetric, b: &IconMetric) -> bool {
    if a.side != b.side {
        return false;
    }
    let side = a.side;
    let enginesize = (side >> 3).wrapping_sub(2);

    let both_bw = a.ccount == 0 && b.ccount == 0;
    if both_bw {
        // B&W path: 6-cell match over (edge ∪ color) and (noedge ∪ gray).
        let edge = matchbwpoint(side, &six(&a.edge, &a.color), &six(&b.edge, &b.color));
        let noedge = matchbwpoint(side, &six(&a.noedge, &a.gray), &six(&b.noedge, &b.gray));
        let bright = matchpoint(side, &a.bright, &b.bright, 255);
        let dark = matchpoint(side, &a.dark, &b.dark, 255);
        let confidence = (bright + dark + edge * 2 + noedge) / 6;
        return confidence >= 70;
    }

    // Color path.
    let edge = matchpoint(side, &a.edge, &b.edge, 255);
    let noedge = matchpoint(side, &a.noedge, &b.noedge, 255);
    let (color, gray) = if a.ccount != 0 && b.ccount != 0 {
        (
            matchpoint(side, &a.color, &b.color, 4072),
            matchpoint(side, &a.gray, &b.gray, 4072),
        )
    } else {
        (0, 0)
    };
    let bright = matchpoint(side, &a.bright, &b.bright, 255);
    let dark = matchpoint(side, &a.dark, &b.dark, 255);

    // Color-spread sub-score.
    let sub = |x: u32, y: u32| -> u32 {
        let d = (x as i64 - y as i64).unsigned_abs() as u32 * 10;
        100_u32.saturating_sub(d)
    };
    let reds = sub(a.rsum, b.rsum);
    let greens = sub(a.gsum, b.gsum);
    let blues = sub(a.bsum, b.bsum);
    let ccnt = sub(a.ccount, b.ccount);
    let colors = (reds + greens + blues + ccnt) / 4;

    let positivematch = 64 + 4 * (2u32.wrapping_sub(enginesize));
    let confidence = (color + (gray + bright + noedge) * 2 / 3 + dark + edge + colors) / 6;
    confidence >= positivematch
}

/// A 6-cell merge: cells [0..3) from `a`, [3..6) from `b` (used for B&W where
/// edge/color and noedge/gray are concatenated).
struct Six {
    x: [u32; 6],
    y: [u32; 6],
    avg: [u32; 6],
}
fn six(a: &Triple, b: &Triple) -> Six {
    let mut s = Six {
        x: [0; 6],
        y: [0; 6],
        avg: [0; 6],
    };
    for i in 0..3 {
        s.x[i] = a.x[i];
        s.y[i] = a.y[i];
        s.avg[i] = a.avg[i];
        s.x[i + 3] = b.x[i];
        s.y[i + 3] = b.y[i];
        s.avg[i + 3] = b.avg[i];
    }
    s
}

/// Per-component confidence (0..100): greedy best-aligned pairing of the 3 cells
/// of `a` against the 3 of `b` (position AND average must be close).
fn matchpoint(side: u32, a: &Triple, b: &Triple, max: u32) -> u32 {
    let ksize = side / 4;
    let dist_lim = ksize * 3 / 4;
    let avg_lim = max / 5;
    let mut total = 0u32;
    for i in 0..3 {
        let mut best = 0u32;
        for j in 0..3 {
            let dx = a.x[i] as i64 - b.x[j] as i64;
            let dy = a.y[i] as i64 - b.y[j] as i64;
            let dist = ((dx * dx + dy * dy) as f64).sqrt() as u32;
            let adiff = (a.avg[i] as i64 - b.avg[j] as i64).unsigned_abs() as u32;
            if dist > dist_lim || adiff > avg_lim {
                continue;
            }
            let score = 100 - dist * 60 / dist_lim.max(1);
            best = best.max(score);
        }
        total += best;
    }
    total / 3
}

/// B&W variant of [`matchpoint`] over 6×6 cells with fixed avg tolerance 51.
fn matchbwpoint(side: u32, a: &Six, b: &Six) -> u32 {
    let ksize = side / 4;
    let dist_lim = ksize * 3 / 4;
    let avg_lim = 255 / 5;
    let mut total = 0u32;
    for i in 0..6 {
        let mut best = 0u32;
        for j in 0..6 {
            let dx = a.x[i] as i64 - b.x[j] as i64;
            let dy = a.y[i] as i64 - b.y[j] as i64;
            let dist = ((dx * dx + dy * dy) as f64).sqrt() as u32;
            let adiff = (a.avg[i] as i64 - b.avg[j] as i64).unsigned_abs() as u32;
            if dist > dist_lim || adiff > avg_lim {
                continue;
            }
            let score = 100 - dist * 60 / dist_lim.max(1);
            best = best.max(score);
        }
        total += best;
    }
    total / 6
}

// ===========================================================================
// Top-level extraction entry point
// ===========================================================================

/// Compute the [`IconMetric`]s for all icons in the FIRST RT_GROUP_ICON of a PE.
/// Returns an empty vec if `data` is not a PE, has no icons, or all are skipped.
/// Never panics on hostile input.
pub fn pe_icon_metrics(data: &[u8]) -> Vec<IconMetric> {
    let blobs = extract_icon_blobs(data);
    let mut metrics = Vec::new();
    for blob in blobs {
        if let Some(icon) = parse_icon(blob) {
            if let Some((side, pixels)) = normalize(icon) {
                if let Some(m) = get_metrics(side, &pixels) {
                    metrics.push(m);
                }
            }
        }
    }
    metrics
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal 24-bpp solid-color square icon DIB (BITMAPINFOHEADER +
    /// XOR rows + AND mask), bottom-up, with the doubled height. `(r,g,b)`.
    fn make_dib(side: usize, r: u8, g: u8, b: u8) -> Vec<u8> {
        let mut v = Vec::new();
        // BITMAPINFOHEADER (40 bytes).
        v.extend_from_slice(&40u32.to_le_bytes()); // biSize
        v.extend_from_slice(&(side as u32).to_le_bytes()); // biWidth
        v.extend_from_slice(&((side * 2) as u32).to_le_bytes()); // biHeight (doubled)
        v.extend_from_slice(&1u16.to_le_bytes()); // planes
        v.extend_from_slice(&24u16.to_le_bytes()); // bitcount
        v.extend_from_slice(&0u32.to_le_bytes()); // compression
        v.extend_from_slice(&0u32.to_le_bytes()); // sizeimage
        v.extend_from_slice(&0u32.to_le_bytes()); // xppm
        v.extend_from_slice(&0u32.to_le_bytes()); // yppm
        v.extend_from_slice(&0u32.to_le_bytes()); // clrused
        v.extend_from_slice(&0u32.to_le_bytes()); // clrimportant
                                                  // XOR rows: 24bpp, row-aligned to 4 bytes. side*3 bytes, padded.
        let rowbytes = side * 3;
        let pad = (4 - rowbytes % 4) % 4;
        for _y in 0..side {
            for _x in 0..side {
                v.push(b);
                v.push(g);
                v.push(r);
            }
            v.resize(v.len() + pad, 0);
        }
        // AND mask: 1bpp, row-aligned to 4 bytes; all opaque (bits = 0).
        let androw = side.div_ceil(8);
        let andpad = (4 - androw % 4) % 4;
        let and_row_and_pad = androw + andpad;
        for _y in 0..side {
            v.resize(v.len() + and_row_and_pad, 0);
        }
        v
    }

    #[test]
    fn dib_decode_solid_white_blend() {
        // A 16x16 fully-opaque mid-gray icon.
        let dib = make_dib(16, 0x7f, 0x7f, 0x7f);
        let icon = parse_icon(&dib).expect("decode");
        assert_eq!(icon.width, 16);
        assert_eq!(icon.height, 16);
        assert_eq!(icon.scalemode, 0);
        // Every pixel should be opaque mid-gray (alpha forced opaque, blended).
        for &p in &icon.pixels {
            assert_eq!(p, 0xff7f_7f7f, "pixel {p:08x}");
        }
    }

    #[test]
    fn dib_rejects_png_and_out_of_range() {
        // depth 0 → PNG icon, skipped.
        let mut dib = make_dib(16, 0, 0, 0);
        dib[14] = 0; // bitcount low byte → 0
        dib[15] = 0;
        assert!(parse_icon(&dib).is_none());
        // Too small (8x8).
        let small = make_dib(8, 0, 0, 0);
        assert!(parse_icon(&small).is_none());
    }

    #[test]
    fn hash_deterministic_and_serializes() {
        let dib = make_dib(32, 0x7f, 0x7f, 0x7f);
        let icon = parse_icon(&dib).unwrap();
        let (side, px) = normalize(icon).unwrap();
        assert_eq!(side, 32);
        let m1 = get_metrics(side, &px).unwrap();
        let m2 = get_metrics(side, &px).unwrap();
        assert_eq!(m1, m2, "hash must be deterministic");
        let hex = m1.to_hex();
        assert_eq!(hex.len(), 124);
        assert!(hex.starts_with("20"), "side prefix 0x20: {hex}");
        // mid-gray: bright/dark avg = 127 = 0x7f.
        assert_eq!(m1.bright.avg[0], 127);
        assert_eq!(m1.dark.avg[0], 127);
        // bwonly: ccount == 0.
        assert_eq!(m1.ccount, 0);
        // Round-trips through the blob parser.
        let reparsed = parse_hashblob(&hex).unwrap();
        assert_eq!(reparsed, m1);
    }

    #[test]
    fn red_icon_color_spread() {
        // A 32x32 pure-red icon: ccount finalizes to 100, rsum=100, color high.
        let dib = make_dib(32, 0xff, 0x00, 0x00);
        let icon = parse_icon(&dib).unwrap();
        let (side, px) = normalize(icon).unwrap();
        let m = get_metrics(side, &px).unwrap();
        assert_eq!(m.ccount, 100);
        assert_eq!(m.rsum, 100);
        assert_eq!(m.gsum, 0);
        assert_eq!(m.bsum, 0);
        // colsum per pixel ≈ 4071 → color avg near max.
        assert!(m.color.avg[0] >= 4000, "color avg {}", m.color.avg[0]);
        // Validity: rsum+gsum+bsum ≤ 103.
        assert!(m.rsum + m.gsum + m.bsum <= 103);
    }

    #[test]
    fn idb_parse_and_self_match() {
        // Build a metric, serialize, and craft an .idb line, then load + match.
        let dib = make_dib(32, 0x20, 0x90, 0xd0);
        let icon = parse_icon(&dib).unwrap();
        let (side, px) = normalize(icon).unwrap();
        let m = get_metrics(side, &px).unwrap();
        let hex = m.to_hex();
        let line = format!("Test.Icon:MS:IE:{hex}\n");
        let mut db = IconDb::new();
        db.extend_from_text(&line);
        assert_eq!(db.len(), 1);
        // A metric matches itself with high confidence under the right group.
        let hit = db.match_metric(&m, Some("MS"), Some("IE"));
        assert_eq!(hit.as_deref(), Some("Test.Icon"));
        // Wildcards also match.
        assert!(db.match_metric(&m, None, None).is_some());
        // Wrong group name → no match.
        assert!(db.match_metric(&m, Some("NOPE"), Some("IE")).is_none());
    }

    #[test]
    fn different_icon_does_not_match() {
        let dib_a = make_dib(32, 0x20, 0x90, 0xd0); // colorful
        let dib_b = make_dib(32, 0xff, 0x00, 0x00); // pure red
        let ma = get_metrics(32, &normalize(parse_icon(&dib_a).unwrap()).unwrap().1).unwrap();
        let mb = get_metrics(32, &normalize(parse_icon(&dib_b).unwrap()).unwrap().1).unwrap();
        let mut db = IconDb::new();
        db.extend_from_text(&format!("A:G1:G2:{}\n", ma.to_hex()));
        // The red icon should not match the colorful entry confidently.
        // (Solid colors differ strongly in color-spread + color avg.)
        let hit = db.match_metric(&mb, Some("G1"), Some("G2"));
        assert!(hit.is_none(), "distinct solid icons must not match");
    }

    #[test]
    fn idb_rejects_malformed() {
        let mut db = IconDb::new();
        // Wrong token count.
        db.extend_from_text("only:three:tokens\n");
        // Bad hash length.
        db.extend_from_text("X:A:B:dead\n");
        // Bad side prefix (0xff).
        let mut bad = String::from("ff");
        bad.push_str(&"0".repeat(122));
        db.extend_from_text(&format!("Y:A:B:{bad}\n"));
        assert_eq!(db.len(), 0);
    }

    #[test]
    fn different_side_never_matches() {
        let m16 = get_metrics(
            16,
            &normalize(parse_icon(&make_dib(16, 0x10, 0x80, 0xc0)).unwrap())
                .unwrap()
                .1,
        )
        .unwrap();
        let m32 = get_metrics(
            32,
            &normalize(parse_icon(&make_dib(32, 0x10, 0x80, 0xc0)).unwrap())
                .unwrap()
                .1,
        )
        .unwrap();
        assert!(!matches(&m16, &m32));
    }
}
