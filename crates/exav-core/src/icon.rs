//! PE icon perceptual hashing and fuzzy matching (`.idb` support).
//!
//! This module computes a fixed "icon metric" over the icons embedded in a
//! Windows PE image and matches those metrics against a loaded `.idb`
//! signature database. The metric constants and formulas are an
//! interoperability contract: a hash computed here must be numerically
//! identical to the one third-party `.idb` authors computed, so the numbers
//! are fixed by that compatibility requirement.
//!
//! Re-derived clean-room to satisfy that contract, using public knowledge of
//! the PE/COFF resource format, the BMP/DIB + Windows ICON format, CIE-Lab
//! colour math, and Sobel/Gaussian image filters. No `unsafe`; every byte read
//! is bounds-checked and every arithmetic step avoids overflow so hostile or
//! truncated input can never panic.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// One window cell of a metric: a per-pixel average value and the top-left
/// coordinate of the window it was taken from.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug, Serialize, Deserialize)]
struct Cell {
    avg: u32,
    x: u32,
    y: u32,
}

/// The perceptual metric of a single icon. Opaque; two metrics are equal iff
/// every field matches exactly.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct IconMetric {
    side: u32,
    color: [Cell; 3],
    gray: [Cell; 3],
    bright: [Cell; 3],
    dark: [Cell; 3],
    edge: [Cell; 3],
    noedge: [Cell; 3],
    rsum: u32,
    gsum: u32,
    bsum: u32,
    ccount: u32,
}

/// One loaded `.idb` entry: a signature name, its two group-table indices, and
/// the parsed reference metric.
#[derive(Clone, Serialize, Deserialize)]
struct IconEntry {
    name: String,
    g1: usize,
    g2: usize,
    metric: IconMetric,
}

/// Per-`enginesize` bucket: two interned group-name tables plus the entries.
#[derive(Clone, Default, Serialize, Deserialize)]
struct IconBucket {
    group1: Vec<String>,
    group2: Vec<String>,
    entries: Vec<IconEntry>,
}

/// A loaded `.idb` PE-icon signature database, bucketed by icon side
/// (16/24/32 → enginesize 0/1/2). Serializable so it can be stored on disk.
#[derive(Clone, Serialize, Deserialize)]
pub struct IconDb {
    buckets: Vec<IconBucket>,
}

impl Default for IconDb {
    fn default() -> Self {
        Self::new()
    }
}

impl IconDb {
    /// A fresh, empty database with the three side buckets allocated.
    pub fn new() -> Self {
        IconDb {
            buckets: vec![
                IconBucket::default(),
                IconBucket::default(),
                IconBucket::default(),
            ],
        }
    }

    /// True iff no usable entries are loaded.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Number of loaded entries across all buckets.
    pub fn len(&self) -> usize {
        self.buckets.iter().map(|b| b.entries.len()).sum()
    }

    /// Parse `.idb` text (one `name:group1:group2:hashblob` entry per line,
    /// `#`-comments and blank lines skipped). Malformed lines and entries with
    /// an invalid hash blob are silently skipped.
    pub fn extend_from_text(&mut self, text: &str) {
        while self.buckets.len() < 3 {
            self.buckets.push(IconBucket::default());
        }
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() != 4 {
                continue;
            }
            let (name, g1, g2, blob) = (parts[0], parts[1], parts[2], parts[3]);
            let metric = match parse_blob(blob) {
                Some(m) => m,
                None => continue,
            };
            let es = match enginesize(metric.side) {
                Some(e) => e,
                None => continue,
            };
            let bucket = &mut self.buckets[es];
            let g1i = match intern(&mut bucket.group1, g1) {
                Some(i) => i,
                None => continue,
            };
            let g2i = match intern(&mut bucket.group2, g2) {
                Some(i) => i,
                None => continue,
            };
            bucket.entries.push(IconEntry {
                name: name.to_string(),
                g1: g1i,
                g2: g2i,
                metric,
            });
        }
    }

    /// Does any loaded entry — whose group names satisfy the optional `g1`/`g2`
    /// constraints (`None` ⇒ any) — match one of the per-scan PE icon metrics?
    /// Returns the matching entry's signature name.
    pub fn match_pe(
        &self,
        metrics: &[IconMetric],
        g1: Option<&str>,
        g2: Option<&str>,
    ) -> Option<String> {
        let g1 = g1.unwrap_or("*");
        let g2 = g2.unwrap_or("*");
        for m in metrics {
            let es = match enginesize(m.side) {
                Some(e) => e,
                None => continue,
            };
            let bucket = match self.buckets.get(es) {
                Some(b) => b,
                None => continue,
            };
            let sel1 = match resolve_selection(&bucket.group1, g1) {
                Some(s) => s,
                None => continue,
            };
            let sel2 = match resolve_selection(&bucket.group2, g2) {
                Some(s) => s,
                None => continue,
            };
            for e in &bucket.entries {
                if sel1.contains(e.g1) && sel2.contains(e.g2) && metric_matches(m, &e.metric) {
                    return Some(e.name.clone());
                }
            }
        }
        None
    }
}

/// Compute the metric of every icon in the first icon group of a PE image.
/// Returns an empty vector for non-PE input, images with no icons, or icons
/// that are skipped (malformed / unsupported size). Never panics.
pub fn pe_icon_metrics(data: &[u8]) -> Vec<IconMetric> {
    let mut out = Vec::new();
    for dib in pe_icon_dibs(data) {
        if let Some(m) = dib_to_metric(dib) {
            out.push(m);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Group-name interning and selection
// ---------------------------------------------------------------------------

fn enginesize(side: u32) -> Option<usize> {
    match side {
        16 => Some(0),
        24 => Some(1),
        32 => Some(2),
        _ => None,
    }
}

/// Intern a group name, returning its index. Returns `None` (declining to add)
/// once a table already holds 256 distinct names, which stops registering
/// further entries that would introduce a new name.
fn intern(table: &mut Vec<String>, name: &str) -> Option<usize> {
    if let Some(i) = table.iter().position(|s| s == name) {
        return Some(i);
    }
    if table.len() >= 256 {
        return None;
    }
    table.push(name.to_string());
    Some(table.len() - 1)
}

enum Selection {
    All,
    One(usize),
}

impl Selection {
    fn contains(&self, i: usize) -> bool {
        match self {
            Selection::All => true,
            Selection::One(x) => *x == i,
        }
    }
}

fn resolve_selection(table: &[String], name: &str) -> Option<Selection> {
    if name == "*" {
        return Some(Selection::All);
    }
    table.iter().position(|s| s == name).map(Selection::One)
}

// ---------------------------------------------------------------------------
// Little-endian readers
// ---------------------------------------------------------------------------

fn rd_u16(d: &[u8], off: usize) -> Option<u16> {
    let end = off.checked_add(2)?;
    let s = d.get(off..end)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn rd_u32(d: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let s = d.get(off..end)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

// ---------------------------------------------------------------------------
// PE resource walk (§3)
// ---------------------------------------------------------------------------

/// Section-table view used to map resource-content RVAs to file offsets.
struct SectionMap {
    size_of_headers: u32,
    /// (virtual_address, extent, pointer_to_raw_data)
    sections: Vec<(u32, u32, u32)>,
}

impl SectionMap {
    fn rva_to_off(&self, rva: u32) -> Option<usize> {
        if (rva as u64) < self.size_of_headers as u64 {
            return usize::try_from(rva).ok();
        }
        for &(va, extent, raw) in &self.sections {
            let start = va as u64;
            let end = start + extent as u64;
            if rva as u64 >= start && (rva as u64) < end {
                let off = raw as u64 + (rva as u64 - start);
                return usize::try_from(off).ok();
            }
        }
        None
    }
}

/// A bounded view over a PE's resource directory tree.
struct Resources<'a> {
    data: &'a [u8],
    /// File offset of the resource root (the resource-directory base).
    rbase: usize,
    map: SectionMap,
}

impl<'a> Resources<'a> {
    /// First ID-named subdirectory under `dir_abs` whose id equals `want`.
    fn find_id_subdir(&self, dir_abs: usize, want: u16) -> Option<usize> {
        let named = rd_u16(self.data, dir_abs.checked_add(12)?)? as usize;
        let ids = rd_u16(self.data, dir_abs.checked_add(14)?)? as usize;
        let total = named.checked_add(ids)?;
        for i in named..total {
            let e = dir_abs.checked_add(16)?.checked_add(i.checked_mul(8)?)?;
            let id_field = rd_u32(self.data, e)?;
            let off_field = rd_u32(self.data, e.checked_add(4)?)?;
            if id_field == want as u32 && off_field & 0x8000_0000 != 0 {
                return self.rbase.checked_add((off_field & 0x7fff_ffff) as usize);
            }
        }
        None
    }

    /// Walk the entries of the type-14 node and return the first group leaf
    /// (content offset, size) reachable through the first sub-entry.
    fn group_leaf(&self, dir_abs: usize, depth: u32) -> Option<(usize, usize)> {
        if depth > 16 {
            return None;
        }
        let named = rd_u16(self.data, dir_abs.checked_add(12)?)? as usize;
        let ids = rd_u16(self.data, dir_abs.checked_add(14)?)? as usize;
        let total = named.checked_add(ids)?;
        for i in 0..total {
            let e = dir_abs.checked_add(16)?.checked_add(i.checked_mul(8)?)?;
            let off_field = rd_u32(self.data, e.checked_add(4)?)?;
            if off_field & 0x8000_0000 != 0 {
                let sub = self.rbase.checked_add((off_field & 0x7fff_ffff) as usize)?;
                if let Some(leaf) = self.first_data_leaf(sub, depth + 1) {
                    return Some(leaf);
                }
            }
        }
        None
    }

    /// First data-entry leaf reachable from `dir_abs`, descending through the
    /// first sub-entry at each level. Returns (content file offset, size).
    fn first_data_leaf(&self, dir_abs: usize, depth: u32) -> Option<(usize, usize)> {
        if depth > 16 {
            return None;
        }
        let named = rd_u16(self.data, dir_abs.checked_add(12)?)? as usize;
        let ids = rd_u16(self.data, dir_abs.checked_add(14)?)? as usize;
        let total = named.checked_add(ids)?;
        for i in 0..total {
            let e = dir_abs.checked_add(16)?.checked_add(i.checked_mul(8)?)?;
            let off_field = rd_u32(self.data, e.checked_add(4)?)?;
            if off_field & 0x8000_0000 != 0 {
                let sub = self.rbase.checked_add((off_field & 0x7fff_ffff) as usize)?;
                if let Some(l) = self.first_data_leaf(sub, depth + 1) {
                    return Some(l);
                }
            } else {
                let leaf = self.rbase.checked_add(off_field as usize)?;
                let crva = rd_u32(self.data, leaf)?;
                let csize = rd_u32(self.data, leaf.checked_add(4)?)? as usize;
                let coff = self.map.rva_to_off(crva)?;
                return Some((coff, csize));
            }
        }
        None
    }

    /// Ordered list of RT_ICON DIB byte slices for the first icon group.
    fn collect_dibs(&self) -> Vec<&'a [u8]> {
        let mut out = Vec::new();
        let t14 = match self.find_id_subdir(self.rbase, 14) {
            Some(x) => x,
            None => return out,
        };
        let (goff, _gsize) = match self.group_leaf(t14, 0) {
            Some(x) => x,
            None => return out,
        };
        let count = match goff.checked_add(4).and_then(|o| rd_u16(self.data, o)) {
            Some(c) => c as usize,
            None => return out,
        };
        let t3 = self.find_id_subdir(self.rbase, 3);
        let n = count.min(100);
        for i in 0..n {
            let entry = match goff
                .checked_add(6)
                .and_then(|b| i.checked_mul(14).and_then(|o| b.checked_add(o)))
            {
                Some(e) => e,
                None => break,
            };
            let icon_id = match entry.checked_add(12).and_then(|o| rd_u16(self.data, o)) {
                Some(v) => v,
                None => continue,
            };
            let t3abs = match t3 {
                Some(a) => a,
                None => continue,
            };
            if let Some(namedir) = self.find_id_subdir(t3abs, icon_id) {
                if let Some((coff, csize)) = self.first_data_leaf(namedir, 0) {
                    let end = coff
                        .checked_add(csize)
                        .map(|e| e.min(self.data.len()))
                        .unwrap_or(self.data.len());
                    if let Some(slice) = self.data.get(coff..end) {
                        if !slice.is_empty() {
                            out.push(slice);
                        }
                    }
                }
            }
        }
        out
    }
}

/// File offsets of every `String` entry inside a PE's `VS_VERSION_INFO`
/// resource — the anchor set an `VI:` signature offset matches against.
///
/// A `VI:` pattern is anchored, not windowed: probed against two real binaries,
/// a pattern matches only when it begins exactly at the start of a version-info
/// key (`CompanyName`, `FileDescription`, …), never one byte either side and
/// never elsewhere in the resource. Every offset clamscan accepted was such a
/// key start.
///
/// clamscan accepts a *subset* of these — on one binary it took the first eight
/// of nine keys, on another six of nine, with no positional or uniqueness rule
/// that accounts for which. exav anchors on all of them deliberately. The set is
/// a superset, so no `VI:` signature that fires there fails to fire here, and
/// widening it cannot invent a match: the pattern still has to equal the bytes
/// at the anchor, and those bytes are a genuine version-info string either way.
pub fn version_info_anchors(data: &[u8]) -> Vec<u64> {
    /// The resource type id of `RT_VERSION`.
    const RT_VERSION: u16 = 16;
    /// Cap on entries walked, so a crafted resource cannot spin.
    const MAX_ENTRIES: usize = 256;

    let Some((res, rbase)) = resource_view(data) else {
        return Vec::new();
    };
    let Some(t16) = res.find_id_subdir(rbase, RT_VERSION) else {
        return Vec::new();
    };
    let Some((off, size)) = res.first_data_leaf(t16, 0) else {
        return Vec::new();
    };
    let end = match off.checked_add(size) {
        Some(e) if e <= data.len() => e,
        _ => data.len(),
    };
    let block = &data[off.min(data.len())..end];

    // Walk the block for `String` entries. Each is
    // `wLength|wValueLength|wType|szKey…`, 4-byte aligned, so a scan on the
    // alignment grid finds every one without needing to model the full nested
    // `StringFileInfo`/`StringTable` hierarchy — which packers routinely
    // malform anyway.
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 8 <= block.len() && out.len() < MAX_ENTRIES {
        let wlen = u16::from_le_bytes([block[i], block[i + 1]]) as usize;
        let wtype = u16::from_le_bytes([block[i + 4], block[i + 5]]);
        // A `String` entry is text-typed and its length must be sane and stay
        // inside the block.
        if wtype == 1 && wlen > 6 && i + wlen <= block.len() {
            let key = i + 6;
            // The key is a NUL-terminated UTF-16 run of printable ASCII — the
            // known version-info key names all are, and requiring it keeps the
            // grid scan from anchoring on arbitrary binary.
            let mut j = key;
            let mut chars = 0;
            while j + 1 < block.len() && block[j..j + 2] != [0, 0] {
                if block[j + 1] != 0 || !block[j].is_ascii_graphic() && block[j] != b' ' {
                    chars = 0;
                    break;
                }
                chars += 1;
                j += 2;
            }
            if chars >= 3 {
                out.push((off + key) as u64);
            }
        }
        i += 4;
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Shared setup for the resource-tree walkers: parse the PE, map the resource
/// directory to a file offset, and build the view over it.
fn resource_view(data: &[u8]) -> Option<(Resources<'_>, usize)> {
    let pe = goblin::pe::PE::parse(data).ok()?;
    let oh = pe.header.optional_header?;
    let rsrc = oh.data_directories.get_resource_table()?;
    if rsrc.virtual_address == 0 || rsrc.size == 0 {
        return None;
    }
    let mut sections = Vec::with_capacity(pe.sections.len());
    for s in &pe.sections {
        let extent = if s.size_of_raw_data != 0 {
            s.size_of_raw_data
        } else {
            s.virtual_size.max(s.size_of_raw_data)
        };
        sections.push((s.virtual_address, extent, s.pointer_to_raw_data));
    }
    let map = SectionMap {
        size_of_headers: oh.windows_fields.size_of_headers,
        sections,
    };
    let rbase = map.rva_to_off(rsrc.virtual_address)?;
    if rbase >= data.len() {
        return None;
    }
    Some((Resources { data, rbase, map }, rbase))
}

/// Parse a PE and return the DIB slices of its first icon group.
fn pe_icon_dibs(data: &[u8]) -> Vec<&[u8]> {
    let pe = match goblin::pe::PE::parse(data) {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };
    let oh = match pe.header.optional_header {
        Some(o) => o,
        None => return Vec::new(),
    };
    let rsrc = match oh.data_directories.get_resource_table() {
        Some(d) => d,
        None => return Vec::new(),
    };
    if rsrc.virtual_address == 0 || rsrc.size == 0 {
        return Vec::new();
    }
    let mut sections = Vec::with_capacity(pe.sections.len());
    for s in &pe.sections {
        let extent = if s.size_of_raw_data != 0 {
            s.size_of_raw_data
        } else {
            s.virtual_size.max(s.size_of_raw_data)
        };
        sections.push((s.virtual_address, extent, s.pointer_to_raw_data));
    }
    let map = SectionMap {
        size_of_headers: oh.windows_fields.size_of_headers,
        sections,
    };
    let rbase = match map.rva_to_off(rsrc.virtual_address) {
        Some(o) => o,
        None => return Vec::new(),
    };
    if rbase >= data.len() {
        return Vec::new();
    }
    Resources { data, rbase, map }.collect_dibs()
}

// ---------------------------------------------------------------------------
// DIB decode → ARGB blended over white (§4)
// ---------------------------------------------------------------------------

fn pal(palette: &[u32], idx: usize) -> u32 {
    palette.get(idx).copied().unwrap_or(0) & 0x00FF_FFFF
}

/// Decode one 16-bpp (5-6-5) pixel per the interoperability formula.
fn decode565(b0: u8, b1: u8) -> u32 {
    let bb = (b0 & 0x1f) as u32;
    let gg = ((b0 >> 5) | ((b1 & 3) << 3)) as u32;
    let rr = (b1 & 0xfc) as u32;
    let blue = (bb << 3) | (bb >> 2);
    let green = ((gg << 3) | (gg >> 2)) << 11;
    let red = ((rr << 3) | (rr >> 2)) << 17;
    red | green | blue
}

/// Apply a 1-bpp bottom-up AND mask: bit 0 ⇒ opaque (alpha 0xFF), bit 1 ⇒
/// transparent (leave alpha untouched). MSB-first within each byte.
fn apply_and_mask(
    pixels: &mut [u32],
    dib: &[u8],
    and_start: usize,
    width: usize,
    height: usize,
    andlinesz: usize,
) {
    for y in 0..height {
        let row = match y
            .checked_mul(andlinesz)
            .and_then(|o| and_start.checked_add(o))
        {
            Some(r) => r,
            None => return,
        };
        let out_row = (height - 1 - y) * width;
        for x in 0..width {
            let boff = match row.checked_add(x / 8) {
                Some(v) => v,
                None => continue,
            };
            if let Some(&byte) = dib.get(boff) {
                let bit = (byte >> (7 - (x % 8))) & 1;
                if bit == 0 {
                    pixels[out_row + x] |= 0xFF00_0000;
                }
            }
        }
    }
}

/// Decode a `BITMAPINFOHEADER` DIB to a top-down ARGB buffer blended over
/// white. Returns `(width, height, pixels, scalemode)` or `None` if the icon
/// is malformed / unsupported / outside the accepted size range.
fn decode_dib(dib: &[u8]) -> Option<(usize, usize, Vec<u32>, u32)> {
    if dib.len() < 40 {
        return None;
    }
    let bi_size = rd_u32(dib, 0)? as usize;
    if bi_size < 40 {
        return None;
    }
    let bi_width = rd_u32(dib, 4)? as i64;
    let bi_height = rd_u32(dib, 8)? as i64;
    let depth = rd_u16(dib, 14)? as usize;

    let width = bi_width;
    let height = bi_height / 2;
    if width <= 0 || height <= 0 {
        return None;
    }
    // Dimension gate.
    if !(16..=256).contains(&width) || !(16..=256).contains(&height) {
        return None;
    }
    if width < height * 3 / 4 || height < width * 3 / 4 {
        return None;
    }
    // Scale-mode selection from the original width/height.
    let scalemode = if width == height {
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
    let width = width as usize;
    let height = height as usize;

    // Palette.
    let mut cursor = bi_size;
    let mut palette: Vec<u32> = Vec::new();
    match depth {
        0 => return None,
        1 | 4 | 8 => {
            let count = 1usize << depth;
            for _ in 0..count {
                palette.push(rd_u32(dib, cursor)?);
                cursor = cursor.checked_add(4)?;
            }
        }
        16 | 24 | 32 => {}
        _ => return None,
    }
    let pixel_start = cursor;

    let scanlinesz =
        4 * (width * depth / 32) + if (width * depth).is_multiple_of(32) { 0 } else { 4 };
    let andlinesz = 4 * (width / 32) + if width.is_multiple_of(32) { 0 } else { 4 };

    let mut pixels = vec![0u32; width * height];
    let mut any_alpha = 0u32;
    for y in 0..height {
        let row = pixel_start.checked_add(y.checked_mul(scanlinesz)?)?;
        let out_row = (height - 1 - y) * width;
        for x in 0..width {
            let color = match depth {
                1 => {
                    let byte = *dib.get(row.checked_add(x / 8)?)?;
                    let bit = (byte >> (7 - (x % 8))) & 1;
                    pal(&palette, bit as usize)
                }
                4 => {
                    let byte = *dib.get(row.checked_add(x / 2)?)?;
                    let nib = if x % 2 == 0 { byte >> 4 } else { byte & 0x0f };
                    pal(&palette, nib as usize)
                }
                8 => {
                    let idx = *dib.get(row.checked_add(x)?)?;
                    pal(&palette, idx as usize)
                }
                16 => {
                    let b0 = *dib.get(row.checked_add(x * 2)?)?;
                    let b1 = *dib.get(row.checked_add(x * 2 + 1)?)?;
                    decode565(b0, b1)
                }
                24 => {
                    let b0 = *dib.get(row.checked_add(x * 3)?)? as u32;
                    let b1 = *dib.get(row.checked_add(x * 3 + 1)?)? as u32;
                    let b2 = *dib.get(row.checked_add(x * 3 + 2)?)? as u32;
                    b0 | (b1 << 8) | (b2 << 16)
                }
                32 => {
                    let b0 = *dib.get(row.checked_add(x * 4)?)? as u32;
                    let b1 = *dib.get(row.checked_add(x * 4 + 1)?)? as u32;
                    let b2 = *dib.get(row.checked_add(x * 4 + 2)?)? as u32;
                    let b3 = *dib.get(row.checked_add(x * 4 + 3)?)? as u32;
                    any_alpha |= b3;
                    b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
                }
                _ => return None,
            };
            pixels[out_row + x] = color;
        }
    }
    let xor_end = pixel_start.checked_add(height.checked_mul(scanlinesz)?)?;

    if depth == 32 && any_alpha == 0 {
        // Declared 32bpp but no alpha ever set: treat as 24-bit and read a
        // separate AND mask; if unreadable, force full opacity.
        let need = height.checked_mul(andlinesz)?;
        let readable = xor_end
            .checked_add(need)
            .map(|e| e <= dib.len())
            .unwrap_or(false);
        if readable {
            apply_and_mask(&mut pixels, dib, xor_end, width, height, andlinesz);
        } else {
            for p in pixels.iter_mut() {
                *p |= 0xFF00_0000;
            }
        }
    } else if depth & 0x1f != 0 {
        // 1/4/8/16/24: AND mask immediately follows the XOR bitmap.
        apply_and_mask(&mut pixels, dib, xor_end, width, height, andlinesz);
    }
    // True 32-bpp with some alpha bit set: source alpha is used as-is.

    // Blend over white.
    for p in pixels.iter_mut() {
        let a = (*p >> 24) & 0xff;
        let r = (*p >> 16) & 0xff;
        let g = (*p >> 8) & 0xff;
        let b = *p & 0xff;
        let nr = 255 - a + a * r / 255;
        let ng = 255 - a + a * g / 255;
        let nb = 255 - a + a * b / 255;
        *p = 0xFF00_0000 | (nr << 16) | (ng << 8) | nb;
    }
    Some((width, height, pixels, scalemode))
}

// ---------------------------------------------------------------------------
// Normalize to side ∈ {16,24,32} (§5)
// ---------------------------------------------------------------------------

/// Channel-wise average of two ARGB words without cross-channel carry.
fn avg2(c1: u32, c2: u32) -> u32 {
    (((c1 ^ c2) & 0xFEFE_FEFE) >> 1) + (c1 & c2)
}

fn normalize(w: usize, h: usize, pixels: Vec<u32>, mode: u32) -> (usize, Vec<u32>) {
    match mode {
        0 => (w, pixels),
        1 => {
            let mut width = w;
            let mut height = h;
            let mut buf = pixels;
            while width > 32 {
                let nw = width / 2;
                let nh = height / 2;
                let mut nb = vec![0u32; nw * nh];
                for y in 0..nh {
                    for x in 0..nw {
                        let c1 = buf[(2 * y) * width + 2 * x];
                        let c2 = buf[(2 * y) * width + 2 * x + 1];
                        let c3 = buf[(2 * y + 1) * width + 2 * x];
                        let c4 = buf[(2 * y + 1) * width + 2 * x + 1];
                        nb[y * nw + x] = avg2(avg2(c1, c2), avg2(c3, c4));
                    }
                }
                buf = nb;
                width = nw;
                height = nh;
            }
            (width, buf)
        }
        _ => {
            let d = |a: usize, b: usize| {
                (w as i64 - a as i64).abs() + (h as i64 - b as i64).abs()
            };
            let newsize = if d(32, 32) < d(24, 24) {
                32
            } else if d(24, 24) < d(16, 16) {
                24
            } else {
                16
            };
            let scalex = w as f64 / newsize as f64;
            let scaley = h as f64 / newsize as f64;
            let len = pixels.len();
            let mut buf = vec![0u32; newsize * newsize];
            for y in 0..newsize {
                for x in 0..newsize {
                    let oldy = (y as f64 * scaley).floor() as usize;
                    let oldx = (x as f64 * scalex + 0.5).floor() as usize;
                    let idx = (oldy * w + oldx).min(len.saturating_sub(1));
                    buf[y * newsize + x] = pixels[idx];
                }
            }
            (newsize, buf)
        }
    }
}

// ---------------------------------------------------------------------------
// Edge field: Lab distance → Sobel → normalize → border → Gaussian (§6.5)
// ---------------------------------------------------------------------------

fn srgb_lin(ch: u8) -> f64 {
    let t = ch as f64 / 255.0;
    let t = if t > 0.04045 {
        ((t + 0.055) / 1.055).powf(2.4)
    } else {
        t / 12.92
    };
    t * 100.0
}

fn lab_f(t: f64) -> f64 {
    if t > 0.008856 {
        t.cbrt()
    } else {
        7.787 * t + 16.0 / 116.0
    }
}

fn lab_distance(r: u8, g: u8, b: u8) -> f64 {
    const LREF: f64 = 53.19277769107721;
    const AREF: f64 = 0.0031420942181448197;
    const BREF: f64 = -0.006207587784401447;
    let rl = srgb_lin(r);
    let gl = srgb_lin(g);
    let bl = srgb_lin(b);
    let x = (rl * 0.4124 + gl * 0.3576 + bl * 0.1805) / 95.047;
    let y = (rl * 0.2126 + gl * 0.7152 + bl * 0.0722) / 100.0;
    let z = (rl * 0.0193 + gl * 0.1192 + bl * 0.9505) / 108.883;
    let fx = lab_f(x);
    let fy = lab_f(y);
    let fz = lab_f(z);
    let l = 116.0 * fy - 16.0;
    let a = 500.0 * (fx - fy);
    let bb = 200.0 * (fy - fz);
    ((LREF - l).powi(2) + (AREF - a).powi(2) + (BREF - bb).powi(2)).sqrt()
}

/// Build the blurred edge image whose blue channel carries the edge value.
fn edge_field(side: usize, pixels: &[u32]) -> Vec<u32> {
    let n = side * side;
    let mut lab = vec![0.0f64; n];
    for i in 0..n {
        let px = pixels[i];
        let r = ((px >> 16) & 0xff) as u8;
        let g = ((px >> 8) & 0xff) as u8;
        let b = (px & 0xff) as u8;
        lab[i] = lab_distance(r, g, b);
    }

    // Sobel magnitude on the interior.
    let mut mag = vec![0u32; n];
    let mut maxmag = 0u32;
    if side >= 3 {
        for y in 1..side - 1 {
            for x in 1..side - 1 {
                let tl = lab[(y - 1) * side + (x - 1)];
                let tc = lab[(y - 1) * side + x];
                let tr = lab[(y - 1) * side + (x + 1)];
                let ml = lab[y * side + (x - 1)];
                let mr = lab[y * side + (x + 1)];
                let bl = lab[(y + 1) * side + (x - 1)];
                let bc = lab[(y + 1) * side + x];
                let br = lab[(y + 1) * side + (x + 1)];
                let gx = -tl + tr - 2.0 * ml + 2.0 * mr - bl + br;
                let gy = -tl - 2.0 * tc - tr + bl + 2.0 * bc + br;
                let m = (gx * gx + gy * gy).sqrt().floor() as u32;
                mag[y * side + x] = m;
                if m > maxmag {
                    maxmag = m;
                }
            }
        }
    }

    // Normalize to a gray ARGB image; border stays black.
    let mut buf = vec![0xFF00_0000u32; n];
    if maxmag > 0 && side >= 3 {
        for y in 1..side - 1 {
            for x in 1..side - 1 {
                let v = mag[y * side + x] * 255 / maxmag;
                buf[y * side + x] = 0xFF00_0000 | (v << 16) | (v << 8) | v;
            }
        }
    }
    // Force a 1-pixel black border on all four edges.
    for x in 0..side {
        buf[x] = 0xFF00_0000;
        buf[(side - 1) * side + x] = 0xFF00_0000;
    }
    for y in 0..side {
        buf[y * side] = 0xFF00_0000;
        buf[y * side + side - 1] = 0xFF00_0000;
    }

    // Horizontal Gaussian {1,2,1}: read blue, write green (in place).
    for y in 0..side {
        for x in 0..side {
            let mut sum = 0u32;
            let mut w = 0u32;
            if x > 0 {
                sum += buf[y * side + x - 1] & 0xff;
                w += 1;
            }
            sum += (buf[y * side + x] & 0xff) * 2;
            w += 2;
            if x + 1 < side {
                sum += buf[y * side + x + 1] & 0xff;
                w += 1;
            }
            // The centre tap always contributes weight 2, so `w` is never 0.
            let g = sum / w;
            let idx = y * side + x;
            buf[idx] = (buf[idx] & !0x0000_FF00) | (g << 8);
        }
    }

    // Vertical Gaussian {1,2,1}: read green, write final gray pixel.
    let mut out = vec![0xFF00_0000u32; n];
    for y in 0..side {
        for x in 0..side {
            let mut sum = 0u32;
            let mut w = 0u32;
            if y > 0 {
                sum += (buf[(y - 1) * side + x] >> 8) & 0xff;
                w += 1;
            }
            sum += ((buf[y * side + x] >> 8) & 0xff) * 2;
            w += 2;
            if y + 1 < side {
                sum += (buf[(y + 1) * side + x] >> 8) & 0xff;
                w += 1;
            }
            // The centre tap always contributes weight 2, so `w` is never 0.
            let v = sum / w;
            out[y * side + x] = 0xFF00_0000 | (v << 16) | (v << 8) | v;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The metric (§6)
// ---------------------------------------------------------------------------

/// Greedily choose up to `n` non-overlapping extreme windows.
fn pick_extreme(field: &[u32], wspan: usize, ksize: usize, max: bool, n: usize) -> Vec<Cell> {
    let mut chosen: Vec<Cell> = Vec::with_capacity(n);
    for _ in 0..n {
        let mut best: Option<Cell> = None;
        for wy in 0..wspan {
            for wx in 0..wspan.saturating_sub(1) {
                let overlaps = chosen.iter().any(|c| {
                    let cx = c.x as usize;
                    let cy = c.y as usize;
                    wx + ksize > cx && wx < cx + ksize && wy + ksize > cy && wy < cy + ksize
                });
                if overlaps {
                    continue;
                }
                let val = field[wy * wspan + wx];
                let better = match best {
                    None => true,
                    Some(b) => {
                        if max {
                            val > b.avg
                        } else {
                            val < b.avg
                        }
                    }
                };
                if better {
                    best = Some(Cell {
                        avg: val,
                        x: wx as u32,
                        y: wy as u32,
                    });
                }
            }
        }
        match best {
            Some(c) => chosen.push(c),
            None => break,
        }
    }
    chosen
}

/// Take the first three cells, dividing each `avg` by `k2`.
fn triple_div(cells: &[Cell], k2: u32) -> [Cell; 3] {
    let mut out = [Cell::default(); 3];
    for (i, o) in out.iter_mut().enumerate() {
        if let Some(c) = cells.get(i) {
            *o = Cell {
                avg: c.avg / k2,
                x: c.x,
                y: c.y,
            };
        }
    }
    out
}

fn compute_metric(side: usize, pixels: &[u32]) -> Option<IconMetric> {
    if !matches!(side, 16 | 24 | 32) {
        return None;
    }
    let total = side * side;
    if pixels.len() != total {
        return None;
    }
    let ksize = side / 4;
    let wspan = side - ksize + 1;
    let k2 = (ksize * ksize) as u32;

    // Per-pixel quantities and colour presence.
    let mut csqv = vec![0u32; total];
    let mut vval = vec![0u32; total];
    let mut rsum = 0u64;
    let mut gsum = 0u64;
    let mut bsum = 0u64;
    let mut ccount = 0u64;
    for i in 0..total {
        let px = pixels[i];
        let r = (px >> 16) & 0xff;
        let g = (px >> 8) & 0xff;
        let b = px & 0xff;
        let mx = r.max(g).max(b);
        let mn = r.min(g).min(b);
        let v = mx;
        let delta = mx - mn;
        let s = if delta == 0 { 0 } else { 255 * delta / mx };
        csqv[i] = ((s * s * v) as f64).sqrt().floor() as u32;
        vval[i] = v;
        if s > 85 && v > 85 {
            ccount += 1;
            rsum += (100 - 100 * g.abs_diff(b) / delta) as u64;
            gsum += (100 - 100 * r.abs_diff(b) / delta) as u64;
            bsum += (100 - 100 * r.abs_diff(g) / delta) as u64;
        }
    }
    let (rs, gs, bs, cc, bwonly) = if ccount * 100 / total as u64 > 5 {
        (
            (rsum / ccount) as u32,
            (gsum / ccount) as u32,
            (bsum / ccount) as u32,
            (ccount * 100 / total as u64) as u32,
            false,
        )
    } else {
        (0, 0, 0, 0, true)
    };

    // Window sums.
    let mut colsum = vec![0u32; wspan * wspan];
    let mut lightsum = vec![0u32; wspan * wspan];
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

    let color_pick = pick_extreme(&colsum, wspan, ksize, true, 3);
    let gray_pick = pick_extreme(&colsum, wspan, ksize, false, 3);
    let bright_pick = pick_extreme(&lightsum, wspan, ksize, true, 3);
    let dark_pick = pick_extreme(&lightsum, wspan, ksize, false, 3);

    // Edge windows.
    let edgeimg = edge_field(side, pixels);
    let mut edgesum = vec![0u32; wspan * wspan];
    for wy in 0..wspan {
        for wx in 0..wspan {
            let mut es = 0u32;
            for dy in 0..ksize {
                for dx in 0..ksize {
                    let idx = (wy + dy) * side + (wx + dx);
                    es += edgeimg[idx] & 0xff;
                }
            }
            edgesum[wy * wspan + wx] = es;
        }
    }
    let npick = if bwonly { 6 } else { 3 };
    let edge_full = pick_extreme(&edgesum, wspan, ksize, true, npick);
    let noedge_full = pick_extreme(&edgesum, wspan, ksize, false, npick);

    let edge = triple_div(&edge_full, k2);
    let noedge = triple_div(&noedge_full, k2);

    let (color, gray) = if bwonly {
        // A low-colour icon reuses the extra edge/noedge cells for colour/gray.
        let mut color = [Cell::default(); 3];
        let mut gray = [Cell::default(); 3];
        for i in 0..3 {
            let ec = edge_full.get(3 + i).copied().unwrap_or_default();
            let nc = noedge_full.get(3 + i).copied().unwrap_or_default();
            color[i] = Cell {
                avg: ec.avg / k2,
                x: ec.x,
                y: ec.y,
            };
            // Interop: gray's coordinates are taken from the edge cells, not noedge.
            gray[i] = Cell {
                avg: nc.avg / k2,
                x: ec.x,
                y: ec.y,
            };
        }
        (color, gray)
    } else {
        (triple_div(&color_pick, k2), triple_div(&gray_pick, k2))
    };
    let bright = triple_div(&bright_pick, k2);
    let dark = triple_div(&dark_pick, k2);

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

/// Full per-icon pipeline: decode DIB → normalize → metric.
fn dib_to_metric(dib: &[u8]) -> Option<IconMetric> {
    let (w, h, pixels, mode) = decode_dib(dib)?;
    let (side, buf) = normalize(w, h, pixels, mode);
    compute_metric(side, &buf)
}

// ---------------------------------------------------------------------------
// 124-nibble hash blob (§7)
// ---------------------------------------------------------------------------

#[cfg(test)]
fn push_hex(s: &mut String, val: u32, nibbles: usize) {
    for i in (0..nibbles).rev() {
        let nib = (val >> (i * 4)) & 0xf;
        s.push(char::from_digit(nib, 16).unwrap_or('0'));
    }
}

/// Encode a metric as its 124-nibble lowercase hex blob (inverse of
/// [`parse_blob`]). Used by tests and diagnostics.
#[cfg(test)]
fn metric_to_hex(m: &IconMetric) -> String {
    let mut s = String::with_capacity(124);
    push_hex(&mut s, m.side, 2);
    for c in &m.color {
        push_hex(&mut s, c.avg, 3);
        push_hex(&mut s, c.x, 2);
        push_hex(&mut s, c.y, 2);
    }
    for c in &m.gray {
        push_hex(&mut s, c.avg, 3);
        push_hex(&mut s, c.x, 2);
        push_hex(&mut s, c.y, 2);
    }
    for grp in [&m.bright, &m.dark, &m.edge, &m.noedge] {
        for c in grp {
            push_hex(&mut s, c.avg, 2);
            push_hex(&mut s, c.x, 2);
            push_hex(&mut s, c.y, 2);
        }
    }
    push_hex(&mut s, m.rsum, 2);
    push_hex(&mut s, m.gsum, 2);
    push_hex(&mut s, m.bsum, 2);
    push_hex(&mut s, m.ccount, 2);
    s
}

fn hexval(b: &[u8], pos: usize, n: usize) -> Option<u32> {
    let mut v = 0u32;
    for i in 0..n {
        let c = *b.get(pos.checked_add(i)?)?;
        let d = (c as char).to_digit(16)?;
        v = v.checked_mul(16)?.checked_add(d)?;
    }
    Some(v)
}

fn take_field(b: &[u8], pos: &mut usize, n: usize) -> Option<u32> {
    let v = hexval(b, *pos, n)?;
    *pos += n;
    Some(v)
}

fn take_cells(
    b: &[u8],
    pos: &mut usize,
    coord_max: u32,
    avg_n: usize,
    avg_max: Option<u32>,
) -> Option<[Cell; 3]> {
    let mut cells = [Cell::default(); 3];
    for c in cells.iter_mut() {
        let avg = take_field(b, pos, avg_n)?;
        if let Some(mx) = avg_max {
            if avg > mx {
                return None;
            }
        }
        let x = take_field(b, pos, 2)?;
        if x > coord_max {
            return None;
        }
        let y = take_field(b, pos, 2)?;
        if y > coord_max {
            return None;
        }
        *c = Cell { avg, x, y };
    }
    Some(cells)
}

/// Parse a 124-nibble hash blob into a metric, rejecting (returning `None`) on
/// any wrong length, non-hex digit, or out-of-range field.
fn parse_blob(hex: &str) -> Option<IconMetric> {
    let b = hex.as_bytes();
    if b.len() != 124 {
        return None;
    }
    let mut pos = 0usize;
    let side = take_field(b, &mut pos, 2)?;
    if !matches!(side, 16 | 24 | 32) {
        return None;
    }
    let coord_max = side - side / 8;
    let color = take_cells(b, &mut pos, coord_max, 3, Some(4072))?;
    let gray = take_cells(b, &mut pos, coord_max, 3, Some(4072))?;
    let bright = take_cells(b, &mut pos, coord_max, 2, None)?;
    let dark = take_cells(b, &mut pos, coord_max, 2, None)?;
    let edge = take_cells(b, &mut pos, coord_max, 2, None)?;
    let noedge = take_cells(b, &mut pos, coord_max, 2, None)?;
    let rsum = take_field(b, &mut pos, 2)?;
    let gsum = take_field(b, &mut pos, 2)?;
    let bsum = take_field(b, &mut pos, 2)?;
    let ccount = take_field(b, &mut pos, 2)?;
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

// ---------------------------------------------------------------------------
// Matching (§8)
// ---------------------------------------------------------------------------

fn concat6(a: &[Cell; 3], c: &[Cell; 3]) -> [Cell; 6] {
    [a[0], a[1], a[2], c[0], c[1], c[2]]
}

fn cell_score(ca: &Cell, cb: &Cell, dist_lim: u32, avg_lim: u32) -> Option<u32> {
    let dx = ca.x as i64 - cb.x as i64;
    let dy = ca.y as i64 - cb.y as i64;
    let dist = ((dx * dx + dy * dy) as f64).sqrt().floor() as u32;
    let adiff = ca.avg.abs_diff(cb.avg);
    if dist > dist_lim || adiff > avg_lim {
        return None;
    }
    Some(100u32.saturating_sub(dist * 60 / dist_lim.max(1)))
}

fn matchpoint(side: u32, a: &[Cell; 3], b: &[Cell; 3], max: u32) -> u32 {
    let ksize = side / 4;
    let dist_lim = ksize * 3 / 4;
    let avg_lim = max / 5;
    let mut total = 0u32;
    for ca in a {
        let mut best = 0u32;
        for cb in b {
            if let Some(score) = cell_score(ca, cb, dist_lim, avg_lim) {
                if score > best {
                    best = score;
                }
            }
        }
        total += best;
    }
    total / 3
}

fn matchbwpoint(side: u32, a: &[Cell; 6], b: &[Cell; 6]) -> u32 {
    let ksize = side / 4;
    let dist_lim = ksize * 3 / 4;
    let avg_lim = 255 / 5;
    let mut total = 0u32;
    for ca in a {
        let mut best = 0u32;
        for cb in b {
            if let Some(score) = cell_score(ca, cb, dist_lim, avg_lim) {
                if score > best {
                    best = score;
                }
            }
        }
        total += best;
    }
    total / 6
}

/// Colour-spread sub-score: `100 - min(100, 10*|x-y|)`.
fn spread_sub(x: u32, y: u32) -> u32 {
    100u32.saturating_sub(10u32.saturating_mul(x.abs_diff(y)).min(100))
}

fn metric_matches(a: &IconMetric, b: &IconMetric) -> bool {
    let side = a.side;
    let es = (side >> 3).wrapping_sub(2);
    let both_bw = a.ccount == 0 && b.ccount == 0;
    if both_bw {
        let a_ec = concat6(&a.edge, &a.color);
        let b_ec = concat6(&b.edge, &b.color);
        let a_ng = concat6(&a.noedge, &a.gray);
        let b_ng = concat6(&b.noedge, &b.gray);
        let edge6 = matchbwpoint(side, &a_ec, &b_ec);
        let noedge6 = matchbwpoint(side, &a_ng, &b_ng);
        let bright = matchpoint(side, &a.bright, &b.bright, 255);
        let dark = matchpoint(side, &a.dark, &b.dark, 255);
        let confidence = (bright + dark + edge6 * 2 + noedge6) / 6;
        confidence >= 70
    } else {
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
        let colors = (spread_sub(a.rsum, b.rsum)
            + spread_sub(a.gsum, b.gsum)
            + spread_sub(a.bsum, b.bsum)
            + spread_sub(a.ccount, b.ccount))
            / 4;
        let positivematch = 64u32.wrapping_add(4u32.wrapping_mul(2u32.wrapping_sub(es)));
        let confidence =
            (color + (gray + bright + noedge) * 2 / 3 + dark + edge + colors) / 6;
        confidence >= positivematch
    }
}

// ---------------------------------------------------------------------------
// Tests (§9 oracle vectors)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn put_u16(v: &mut Vec<u8>, x: u16) {
        v.extend_from_slice(&x.to_le_bytes());
    }
    fn put_u32(v: &mut Vec<u8>, x: u32) {
        v.extend_from_slice(&x.to_le_bytes());
    }

    /// Build a synthetic solid-colour 24-bpp DIB (doubled height, 4-byte
    /// aligned BGR rows, all-opaque AND mask).
    fn build_dib(side: usize, r: u8, g: u8, b: u8) -> Vec<u8> {
        let mut v = Vec::new();
        // BITMAPINFOHEADER (40 bytes)
        put_u32(&mut v, 40); // bi_size
        put_u32(&mut v, side as u32); // width
        put_u32(&mut v, (side * 2) as u32); // height (doubled)
        put_u16(&mut v, 1); // planes
        put_u16(&mut v, 24); // bit-count
        put_u32(&mut v, 0); // compression
        put_u32(&mut v, 0); // image size
        put_u32(&mut v, 0); // x ppm
        put_u32(&mut v, 0); // y ppm
        put_u32(&mut v, 0); // colours used
        put_u32(&mut v, 0); // colours important

        let rowsz = (side * 3).div_ceil(4) * 4;
        for _y in 0..side {
            for _x in 0..side {
                v.push(b);
                v.push(g);
                v.push(r);
            }
            v.resize(v.len() + (rowsz - side * 3), 0); // row padding to 4 bytes
        }
        // AND mask: side rows, each 4 bytes (side ≤ 32), all zero (opaque).
        let andsz = 4 * (side / 32) + if !side.is_multiple_of(32) { 4 } else { 0 };
        v.resize(v.len() + side * andsz, 0);
        v
    }

    fn metric_of(side: usize, r: u8, g: u8, b: u8) -> IconMetric {
        dib_to_metric(&build_dib(side, r, g, b)).expect("metric")
    }

    #[test]
    fn midgray_determinism_and_roundtrip() {
        let m1 = metric_of(32, 0x7f, 0x7f, 0x7f);
        let m2 = metric_of(32, 0x7f, 0x7f, 0x7f);
        assert_eq!(m1, m2, "metric must be deterministic");

        let hex = metric_to_hex(&m1);
        assert_eq!(hex.len(), 124);
        assert!(hex.starts_with("20"), "side 32 → prefix 20, got {hex}");
        assert_eq!(m1.bright[0].avg, 127);
        assert_eq!(m1.dark[0].avg, 127);
        assert_eq!(m1.ccount, 0, "solid gray is bwonly");

        let parsed = parse_blob(&hex).expect("blob round-trips");
        assert_eq!(parsed, m1);
    }

    #[test]
    fn pure_red() {
        let m = metric_of(32, 0xff, 0x00, 0x00);
        assert_eq!(m.ccount, 100);
        assert_eq!(m.rsum, 100);
        assert_eq!(m.gsum, 0);
        assert_eq!(m.bsum, 0);
        assert!(m.color[0].avg >= 4000, "color avg {}", m.color[0].avg);
        assert!(m.rsum + m.gsum + m.bsum <= 103);
    }

    #[test]
    fn self_match() {
        let m = metric_of(32, 0x20, 0x90, 0xd0);
        let hex = metric_to_hex(&m);
        let mut db = IconDb::new();
        db.extend_from_text(&format!("Sig.Name:GRP1:GRP2:{hex}\n"));
        assert_eq!(db.len(), 1);
        assert!(!db.is_empty());

        assert_eq!(
            db.match_pe(&[m], None, None).as_deref(),
            Some("Sig.Name"),
            "wildcard self-match"
        );
        assert_eq!(
            db.match_pe(&[m], Some("GRP1"), Some("GRP2")).as_deref(),
            Some("Sig.Name"),
            "exact-group self-match"
        );
        assert_eq!(
            db.match_pe(&[m], Some("WRONG"), Some("GRP2")),
            None,
            "wrong group1 name must not match"
        );
    }

    #[test]
    fn distinct_icons_do_not_match() {
        let colorful = metric_of(32, 0x20, 0x90, 0xd0);
        let red = metric_of(32, 0xff, 0x00, 0x00);
        let mut db = IconDb::new();
        db.extend_from_text(&format!("Colorful:*:*:{}\n", metric_to_hex(&colorful)));
        assert_eq!(db.match_pe(&[red], None, None), None);
    }

    #[test]
    fn different_sides_do_not_match() {
        let m32 = metric_of(32, 0x20, 0x90, 0xd0);
        let m16 = metric_of(16, 0x20, 0x90, 0xd0);
        let mut db = IconDb::new();
        db.extend_from_text(&format!("Sized:*:*:{}\n", metric_to_hex(&m32)));
        assert_eq!(db.match_pe(&[m16], None, None), None);
    }

    #[test]
    fn parser_hardening_and_non_panic() {
        // Wrong length blob → entry not loaded.
        let mut db = IconDb::new();
        db.extend_from_text("Bad:G1:G2:abcd\n");
        assert_eq!(db.len(), 0);

        // Valid metric, but corrupt the side prefix to 0xff → rejected.
        let m = metric_of(32, 0xff, 0x00, 0x00);
        let mut bytes = metric_to_hex(&m).into_bytes();
        bytes[0] = b'f';
        bytes[1] = b'f';
        let bad = String::from_utf8(bytes).unwrap();
        db.extend_from_text(&format!("BadSide:G1:G2:{bad}\n"));
        assert_eq!(db.len(), 0);

        // Non-PE / truncated input never panics and yields no metrics.
        assert!(pe_icon_metrics(&[]).is_empty());
        assert!(pe_icon_metrics(b"not a pe at all").is_empty());
        assert!(pe_icon_metrics(&[0u8; 10]).is_empty());
        assert!(pe_icon_metrics(b"MZ").is_empty());
        let junk: Vec<u8> = (0..4096u32).map(|i| (i.wrapping_mul(37)) as u8).collect();
        assert!(pe_icon_metrics(&junk).is_empty());

        // Fuzzy junk DIBs must be skipped, never panic.
        for len in [0usize, 1, 39, 40, 41, 200] {
            let junk: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
            let _ = dib_to_metric(&junk);
        }
    }
}
