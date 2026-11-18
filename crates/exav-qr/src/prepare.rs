// Vendored from rqrr 0.11.0 (https://github.com/WanzenBug/rqrr), src/prepare.rs,
// a port of quirc. License: (MIT OR Apache-2.0) AND ISC, see LICENSE-*.
// Copyright 2019 Moritz Wanzenböck; quirc: copyright 2010-2012 Daniel Beer.
// Changed: the lru crate's cache is a RegionCache of this file; the search
// counts its steps and its memory (`Meter`) and stops at a limit; the
// `ImageBuffer` impl for the `image` crate's grey images is removed; rustfmt.

use std::cmp;
use std::mem;

use crate::SkewedGridLocation;
use crate::identify::Point;
use crate::identify::grid::RefGridImage;
use crate::identify::match_capstones::CapStoneGroup;
use crate::limits::{Meter, SearchLimits, Stop};

/// How many regions are kept: one for each color a discarded pixel can have.
const CACHE_SIZE: usize = 251;

/// Ends the list of entries by use; not an index of the cache.
const NO_ENTRY: u8 = u8::MAX;
const _: () = assert!(CACHE_SIZE < NO_ENTRY as usize);

/// The regions by the index of their color, the least recently used first out.
/// The entries form a list by use, threaded through the arrays `newer` and
/// `older`, so that every operation takes constant time.
struct RegionCache {
    regions: [Option<ColoredRegion>; CACHE_SIZE],
    /// For an entry, the next one used more recently.
    newer: [u8; CACHE_SIZE],
    /// For an entry, the next one used less recently.
    older: [u8; CACHE_SIZE],
    newest: u8,
    oldest: u8,
    len: usize,
}

impl RegionCache {
    fn new() -> Self {
        RegionCache {
            regions: [None; CACHE_SIZE],
            newer: [NO_ENTRY; CACHE_SIZE],
            older: [NO_ENTRY; CACHE_SIZE],
            newest: NO_ENTRY,
            oldest: NO_ENTRY,
            len: 0,
        }
    }

    fn len(&self) -> usize {
        self.len
    }

    /// Takes the entry `i` out of the list by use.
    fn unlink(&mut self, i: usize) {
        let (newer, older) = (self.newer[i], self.older[i]);
        if newer == NO_ENTRY {
            self.newest = older;
        } else {
            self.older[usize::from(newer)] = older;
        }
        if older == NO_ENTRY {
            self.oldest = newer;
        } else {
            self.newer[usize::from(older)] = newer;
        }
    }

    /// Puts the entry `i` at the newest end of the list by use.
    fn link_newest(&mut self, i: usize) {
        self.older[i] = self.newest;
        self.newer[i] = NO_ENTRY;
        if self.newest == NO_ENTRY {
            self.oldest = i as u8;
        } else {
            self.newer[usize::from(self.newest)] = i as u8;
        }
        self.newest = i as u8;
    }

    /// The region at `index`, which becomes the most recently used.
    fn get(&mut self, index: u8) -> Option<ColoredRegion> {
        let i = usize::from(index);
        let region = (*self.regions.get(i)?)?;
        self.unlink(i);
        self.link_newest(i);
        Some(region)
    }

    /// Sets the region at `index` (below `CACHE_SIZE`) as the most recently used.
    fn put(&mut self, index: u8, region: ColoredRegion) {
        let i = usize::from(index);
        if self.regions[i].is_some() {
            self.unlink(i);
        } else {
            self.len += 1;
        }
        self.regions[i] = Some(region);
        self.link_newest(i);
    }

    /// Removes the least recently used region and returns it with its index.
    fn pop_lru(&mut self) -> Option<(u8, ColoredRegion)> {
        let index = self.oldest;
        if index == NO_ENTRY {
            return None;
        }
        let i = usize::from(index);
        self.unlink(i);
        self.len -= 1;
        Some((index, self.regions[i].take()?))
    }
}

impl Clone for RegionCache {
    /// The entries are put newest first, so the copy's order of use is the
    /// reverse of the original's, as it was with the lru crate: kept so that
    /// the search gives the same results.
    fn clone(&self) -> Self {
        let mut cache = RegionCache::new();
        let mut index = self.newest;
        while index != NO_ENTRY {
            let i = usize::from(index);
            if let Some(region) = self.regions[i] {
                cache.put(index, region);
            }
            index = self.older[i];
        }
        cache
    }
}

/// An black-and-white image that can be mutated on search for QR codes
///
/// During search for QR codes, some black zones will be recolored in
/// 'different' shades of black. This is done to speed up the search and
/// mitigate the impact of a huge zones.
pub struct PreparedImage<S> {
    buffer: S,
    cache: RegionCache,
    /// The limits of the search in this image and what it has spent.
    pub(crate) meter: Meter,
}

impl<S> Clone for PreparedImage<S>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        PreparedImage {
            buffer: self.buffer.clone(),
            cache: self.cache.clone(),
            meter: self.meter.clone(),
        }
    }
}

/// What [`PreparedImage::detect`] found.
pub struct Detection<'a, S> {
    /// The grids found, to decode.
    pub grids: Vec<crate::Grid<RefGridImage<'a, S>>>,
    /// Why the search ended before its end, if it did: the grids found
    /// before are in `grids`, but the image may hold more.
    pub stop: Option<Stop>,
    /// Finder patterns found.
    pub finder_patterns: usize,
    /// Groups of finder patterns tried as a grid.
    pub candidate_grids: usize,
}

pub trait ImageBuffer {
    fn width(&self) -> usize;
    fn height(&self) -> usize;

    fn get_pixel(&self, x: usize, y: usize) -> u8;
    fn set_pixel(&mut self, x: usize, y: usize, val: u8);
}

#[derive(Clone, Debug)]
pub struct BasicImageBuffer {
    w: usize,
    h: usize,
    pixels: Box<[u8]>,
}

impl ImageBuffer for BasicImageBuffer {
    fn width(&self) -> usize {
        self.w
    }

    fn height(&self) -> usize {
        self.h
    }

    fn get_pixel(&self, x: usize, y: usize) -> u8 {
        let w = self.width();
        self.pixels[(y * w) + x]
    }

    fn set_pixel(&mut self, x: usize, y: usize, val: u8) {
        let w = self.width();
        self.pixels[(y * w) + x] = val
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Row {
    pub left: usize,
    pub right: usize,
    pub y: usize,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PixelColor {
    White,
    Black,
    CapStone,
    Alignment,
    Tmp1,
    Discarded(u8),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ColoredRegion {
    Unclaimed {
        color: PixelColor,
        src_x: usize,
        src_y: usize,
        pixel_count: usize,
    },
    CapStone,
    Alignment,
    Tmp1,
}

impl From<u8> for PixelColor {
    fn from(x: u8) -> Self {
        match x {
            0 => PixelColor::White,
            1 => PixelColor::Black,
            2 => PixelColor::CapStone,
            3 => PixelColor::Alignment,
            4 => PixelColor::Tmp1,
            x => PixelColor::Discarded(x - 5),
        }
    }
}

impl From<PixelColor> for u8 {
    fn from(c: PixelColor) -> Self {
        match c {
            PixelColor::White => 0,
            PixelColor::Black => 1,
            PixelColor::CapStone => 2,
            PixelColor::Alignment => 3,
            PixelColor::Tmp1 => 4,
            PixelColor::Discarded(x) => x + 5,
        }
    }
}

impl PartialEq<u8> for PixelColor {
    fn eq(&self, other: &u8) -> bool {
        let rep: u8 = (*self).into();
        rep == *other
    }
}

pub trait AreaFiller {
    fn update(&mut self, row: Row);
}

impl<F> AreaFiller for F
where
    F: FnMut(Row),
{
    fn update(&mut self, row: Row) {
        self(row)
    }
}

struct AreaCounter(usize);

impl AreaFiller for AreaCounter {
    fn update(&mut self, row: Row) {
        self.0 += row.right - row.left + 1;
    }
}

impl<S> PreparedImage<S>
where
    S: ImageBuffer,
{
    pub fn prepare(buf: S) -> Self {
        Self::prepared(buf, Meter::unlimited())
    }

    /// Binarizes `buf` and starts the count of `meter`. When the meter stops
    /// the work, the image is left half done and its search finds nothing.
    fn prepared(mut buf: S, meter: Meter) -> Self {
        let w = buf.width();
        let h = buf.height();
        let row_bytes = (w as u64).saturating_mul(mem::size_of::<usize>() as u64);
        let mut row_average: Vec<usize> = Vec::new();
        if !meter.reserve(row_bytes) || row_average.try_reserve_exact(w).is_err() {
            meter.out_of_memory();
            return PreparedImage {
                buffer: buf,
                cache: RegionCache::new(),
                meter,
            };
        }
        row_average.resize(w, 0);
        let mut avg_v = 0;
        let mut avg_u = 0;

        let threshold_s = cmp::max(w / 8, 1);

        for y in 0..h {
            if !meter.charge(3 * w as u64) {
                break;
            }
            row_average.fill(0);

            for x in 0..w {
                let (v, u) = if y % 2 == 0 {
                    (w - 1 - x, x)
                } else {
                    (x, w - 1 - x)
                };
                avg_v = avg_v * (threshold_s - 1) / threshold_s + buf.get_pixel(v, y) as usize;
                avg_u = avg_u * (threshold_s - 1) / threshold_s + buf.get_pixel(u, y) as usize;
                row_average[v] += avg_v;
                row_average[u] += avg_u;
            }

            #[allow(clippy::needless_range_loop)]
            for x in 0..w {
                let fill = if (buf.get_pixel(x, y) as usize)
                    < row_average[x] * (100 - 5) / (200 * threshold_s)
                {
                    PixelColor::Black
                } else {
                    PixelColor::White
                };
                buf.set_pixel(x, y, fill.into());
            }
        }
        meter.release(row_bytes);

        PreparedImage {
            buffer: buf,
            cache: RegionCache::new(),
            meter,
        }
    }

    /// Group [CapStones](struct.CapStone.html) into [Grids](struct.Grid.html)
    /// that are likely QR codes
    ///
    /// Return a vector of Grids
    pub fn detect_grids<'a>(&'a mut self) -> Vec<crate::Grid<RefGridImage<'a, S>>>
    where
        S: Clone,
    {
        self.detect().grids
    }

    /// [`detect_grids`](Self::detect_grids), and why the search stopped before
    /// its end when a limit of the image's [`SearchLimits`] stopped it.
    pub fn detect<'a>(&'a mut self) -> Detection<'a, S>
    where
        S: Clone,
    {
        let mut res = Vec::new();
        let stones = crate::capstones_from_image(self);
        let groups = self.find_groupings(stones);
        let located_bytes = (mem::size_of::<SkewedGridLocation>()
            + mem::size_of::<crate::Grid<RefGridImage<'_, S>>>())
            as u64;
        let mut locations = Vec::new();
        for group in groups {
            if !self.meter.reserve(located_bytes) {
                break;
            }
            let location = SkewedGridLocation::from_group(self, group);
            if self.meter.is_stopped() {
                break;
            }
            locations.extend(location);
        }
        let stop = self.meter.outcome();
        let finder_patterns = self.meter.finder_patterns();
        let candidate_grids = self.meter.candidate_grids();
        for grid_location in locations {
            let bounds = [
                grid_location.c.map(0.0, 0.0),
                grid_location
                    .c
                    .map(grid_location.grid_size as f64 + 1.0, 0.0),
                grid_location.c.map(
                    grid_location.grid_size as f64 + 1.0,
                    grid_location.grid_size as f64 + 1.0,
                ),
                grid_location
                    .c
                    .map(0.0, grid_location.grid_size as f64 + 1.0),
            ];
            let grid = grid_location.into_grid_image(self);
            res.push(crate::Grid { grid, bounds });
        }

        Detection {
            grids: res,
            stop,
            finder_patterns,
            candidate_grids,
        }
    }

    /// Find CapStones that form a grid
    ///
    /// By trying to match up the relative perspective of 3
    /// [CapStones](struct.CapStone.html) along with other criteria we can find the
    /// CapStones that corner the same QR code.
    ///
    /// The search ends, with the groups found so far, at a stop of the meter
    /// or at the cap on candidates.
    fn find_groupings(&mut self, capstones: Vec<crate::CapStone>) -> Vec<CapStoneGroup>
    where
        S: Clone,
    {
        // What a group found holds: itself and the indexes that mark its
        // finder patterns as used.
        let group_bytes = (mem::size_of::<CapStoneGroup>() + 3 * mem::size_of::<usize>()) as u64;
        let pair_bytes = mem::size_of::<(usize, usize)>() as u64;
        let mut used_capstones = Vec::new();
        let mut groups = Vec::new();
        'search: for idx in 0..capstones.len() {
            if !self.meter.charge(1 + used_capstones.len() as u64) {
                break;
            }
            if used_capstones.contains(&idx) {
                continue;
            }
            let Some(pairs) =
                crate::identify::find_and_rank_possible_neighbors(&capstones, idx, &self.meter)
            else {
                break;
            };
            let held = pairs.len() as u64 * pair_bytes;
            let mut ended = false;
            for pair in pairs {
                // The two lookups in the used capstones take their length.
                if !self.meter.charge(1 + 2 * used_capstones.len() as u64) {
                    ended = true;
                    break;
                }
                if used_capstones.contains(&pair.0) || used_capstones.contains(&pair.1) {
                    continue;
                }
                let group_under_test = CapStoneGroup(
                    capstones[pair.0].clone(),
                    capstones[idx].clone(),
                    capstones[pair.1].clone(),
                );
                if !self.meter.count_candidate_grid() {
                    ended = true;
                    break;
                }
                // Confirm that this group has the other requirements of a QR code.
                match self.group_makes_grid(&group_under_test) {
                    None => {
                        ended = true;
                        break;
                    }
                    Some(false) => continue,
                    Some(true) => {}
                }
                // This is a viable set, save this grouping
                if !self.meter.reserve(group_bytes) {
                    ended = true;
                    break;
                }
                groups.push(group_under_test);
                used_capstones.push(pair.0);
                used_capstones.push(idx);
                used_capstones.push(pair.1);
            }
            self.meter.release(held);
            if ended {
                break 'search;
            }
        }
        groups
    }

    /// Whether `group` makes a grid. A copy of the image is used to not
    /// contaminate the original on an incorrect set of CapStones. `None` when
    /// the search was stopped.
    fn group_makes_grid(&mut self, group: &CapStoneGroup) -> Option<bool>
    where
        S: Clone,
    {
        // The pixels count for a byte each, whatever the buffer holds.
        let bytes = (self.width() as u64)
            .saturating_mul(self.height() as u64)
            .saturating_add(mem::size_of::<RegionCache>() as u64);
        if !self.meter.charge(bytes) || !self.meter.reserve(bytes) {
            return None;
        }
        let mut copy = PreparedImage {
            buffer: self.buffer.clone(),
            cache: self.cache.clone(),
            // The copy counts into the meter of the image, which it returns.
            meter: mem::take(&mut self.meter),
        };
        let located = SkewedGridLocation::from_group(&mut copy, group.clone());
        self.meter = copy.meter;
        self.meter.release(bytes);
        (!self.meter.is_stopped()).then(|| located.is_some())
    }

    pub fn without_preparation(buf: S) -> Self {
        for y in 0..buf.height() {
            for x in 0..buf.width() {
                assert!(buf.get_pixel(x, y) < 2);
            }
        }

        PreparedImage {
            buffer: buf,
            cache: RegionCache::new(),
            meter: Meter::unlimited(),
        }
    }

    /// Return the width of the image
    pub fn width(&self) -> usize {
        self.buffer.width()
    }

    /// Return the height of the image
    pub fn height(&self) -> usize {
        self.buffer.height()
    }

    pub(crate) fn get_region(&mut self, (x, y): (usize, usize)) -> ColoredRegion {
        // A stopped search may have left a region half recolored: it reads no
        // more of them.
        if self.meter.is_stopped() {
            return ColoredRegion::CapStone;
        }
        let color: PixelColor = self.buffer.get_pixel(x, y).into();
        match color {
            PixelColor::Discarded(r) => self.cache.get(r).unwrap(),
            PixelColor::Black => {
                let cache_fill = self.cache.len();
                let reg_idx = if cache_fill == CACHE_SIZE {
                    let (c, reg) = self.cache.pop_lru().expect("fill is at capacity (251)");
                    #[allow(clippy::single_match)]
                    match reg {
                        ColoredRegion::Unclaimed {
                            src_x,
                            src_y,
                            color,
                            ..
                        } => {
                            let _ = self.flood_fill(
                                src_x,
                                src_y,
                                color.into(),
                                PixelColor::Black.into(),
                                |_| (),
                            );
                        }
                        _ => (),
                    }
                    c
                } else {
                    cache_fill as u8
                };
                let next_reg_color = PixelColor::Discarded(reg_idx);
                let counter = self.repaint_and_apply((x, y), next_reg_color, AreaCounter(0));
                if self.meter.is_stopped() {
                    return ColoredRegion::CapStone;
                }
                let new_reg = ColoredRegion::Unclaimed {
                    color: next_reg_color,
                    src_x: x,
                    src_y: y,
                    pixel_count: counter.0,
                };
                self.cache.put(reg_idx, new_reg);
                new_reg
            }
            PixelColor::Tmp1 => ColoredRegion::Tmp1,
            PixelColor::Alignment => ColoredRegion::Alignment,
            PixelColor::CapStone => ColoredRegion::CapStone,
            PixelColor::White => panic!("Tried to color white patch"),
        }
    }

    pub(crate) fn repaint_and_apply<F>(
        &mut self,
        (x, y): (usize, usize),
        target_color: PixelColor,
        fill: F,
    ) -> F
    where
        F: AreaFiller,
    {
        if self.meter.is_stopped() {
            return fill;
        }
        let src = self.buffer.get_pixel(x, y);
        if PixelColor::White == src || target_color == src {
            panic!("Cannot repaint with white or same color");
        }

        self.flood_fill(x, y, src, target_color.into(), fill)
    }

    pub fn get_pixel_at_point(&self, p: Point) -> PixelColor {
        let x = cmp::max(0, cmp::min((self.width() - 1) as i32, p.x));
        let y = cmp::max(0, cmp::min((self.height() - 1) as i32, p.y));
        self.buffer.get_pixel(x as usize, y as usize).into()
    }

    pub fn get_pixel_at(&self, x: usize, y: usize) -> PixelColor {
        self.buffer.get_pixel(x, y).into()
    }

    fn flood_fill<F>(&mut self, x: usize, y: usize, from: u8, to: u8, mut fill: F) -> F
    where
        F: AreaFiller,
    {
        assert_ne!(from, to);
        let w = self.width();
        let mut queue = Vec::new();
        queue.push((x, y));
        let mut queue_bytes = 0;

        while let Some((x, y)) = queue.pop() {
            if !self.meter.charge(1) {
                break;
            }
            // Bail early in case there is nothing to fill
            if self.buffer.get_pixel(x, y) == to || self.buffer.get_pixel(x, y) != from {
                continue;
            }

            let mut left = x;
            let mut right = x;

            while left > 0 && self.buffer.get_pixel(left - 1, y) == from {
                left -= 1;
            }
            while right < w - 1 && self.buffer.get_pixel(right + 1, y) == from {
                right += 1
            }
            // The run is read, filled and seeded from.
            if !self.meter.charge(3 * (right - left + 1) as u64) {
                break;
            }

            /* Fill the extent */
            for idx in left..=right {
                self.buffer.set_pixel(idx, y, to);
            }

            fill.update(Row { left, right, y });

            /* Seed new flood-fills */
            if y > 0 {
                let mut seeded_previous = false;
                for x in left..=right {
                    let p = self.buffer.get_pixel(x, y - 1);
                    if p == from {
                        if !seeded_previous {
                            queue.push((x, y - 1));
                        }
                        seeded_previous = true;
                    } else {
                        seeded_previous = false;
                    }
                }
            }
            if y < self.height() - 1 {
                let mut seeded_previous = false;
                for x in left..=right {
                    let p = self.buffer.get_pixel(x, y + 1);
                    if p == from {
                        if !seeded_previous {
                            queue.push((x, y + 1));
                        }
                        seeded_previous = true;
                    } else {
                        seeded_previous = false;
                    }
                }
            }

            // The queue counts by its capacity, once per run.
            let held = (queue.capacity() * mem::size_of::<(usize, usize)>()) as u64;
            if held > queue_bytes {
                if !self.meter.reserve(held - queue_bytes) {
                    break;
                }
                queue_bytes = held;
            }
        }
        self.meter.release(queue_bytes);
        fill
    }
}

impl PreparedImage<BasicImageBuffer> {
    /// Given a function with binary output, generate a searchable image
    ///
    /// If the given function returns `true` the matching pixel will be 'black'.
    pub fn prepare_from_bitmap<F>(w: usize, h: usize, mut fill: F) -> Self
    where
        F: FnMut(usize, usize) -> bool,
    {
        let capacity = w.checked_mul(h).expect("Image dimensions caused overflow");
        let mut pixels = Vec::with_capacity(capacity);

        for y in 0..h {
            for x in 0..w {
                let col = if fill(x, y) {
                    PixelColor::Black
                } else {
                    PixelColor::White
                };
                pixels.push(col.into())
            }
        }
        let pixels = pixels.into_boxed_slice();
        let buffer = BasicImageBuffer { w, h, pixels };
        PreparedImage::without_preparation(buffer)
    }

    /// Given a byte valued function, generate a searchable image
    ///
    /// The values returned by the function are interpreted as luminance. i.e. a
    /// value of 0 is black, 255 is white.
    pub fn prepare_from_greyscale<F>(w: usize, h: usize, mut fill: F) -> Self
    where
        F: FnMut(usize, usize) -> u8,
    {
        let capacity = w.checked_mul(h).expect("Image dimensions caused overflow");
        let mut data = Vec::with_capacity(capacity);
        for y in 0..h {
            for x in 0..w {
                data.push(fill(x, y));
            }
        }
        let pixels = data.into_boxed_slice();
        let buffer = BasicImageBuffer { w, h, pixels };
        PreparedImage::prepare(buffer)
    }

    /// [`prepare_from_greyscale`](Self::prepare_from_greyscale) for a search
    /// under `limits`, which the image keeps.
    ///
    /// `Err` when the image would pass `limits.max_bytes`, does not fit in
    /// memory (neither panics nor aborts), or the deadline came while it was
    /// read.
    pub fn prepare_from_greyscale_within<F>(
        w: usize,
        h: usize,
        mut fill: F,
        limits: SearchLimits,
    ) -> Result<Self, Stop>
    where
        F: FnMut(usize, usize) -> u8,
    {
        let meter = Meter::new(limits);
        let n = w.checked_mul(h).ok_or(Stop::Memory)?;
        if !meter.reserve(n as u64) {
            return Err(Stop::Memory);
        }
        let mut data = Vec::new();
        if data.try_reserve_exact(n).is_err() {
            return Err(Stop::Memory);
        }
        for y in 0..h {
            if !meter.charge(w as u64) {
                break;
            }
            for x in 0..w {
                data.push(fill(x, y));
            }
        }
        if let Some(stop) = meter.stopped() {
            return Err(stop);
        }
        // Whatever `fill` holds (the source of the pixels) is no longer needed.
        drop(fill);
        let buffer = BasicImageBuffer {
            w,
            h,
            pixels: data.into_boxed_slice(),
        };
        let image = PreparedImage::prepared(buffer, meter);
        match image.meter.stopped() {
            Some(stop) => Err(stop),
            None => Ok(image),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn img_from_array(array: [[u8; 3]; 3]) -> PreparedImage<BasicImageBuffer> {
        let mut pixels = Vec::new();
        for col in array.iter() {
            for item in col.iter() {
                if *item == 0 {
                    pixels.push(0)
                } else {
                    pixels.push(1)
                }
            }
        }
        let buffer = BasicImageBuffer {
            w: 3,
            h: 3,
            pixels: pixels.into_boxed_slice(),
        };

        PreparedImage {
            buffer,
            cache: RegionCache::new(),
            meter: Meter::unlimited(),
        }
    }

    /// A row of isolated black pixels, at the even `x`.
    fn dotted_row(dots: usize) -> PreparedImage<BasicImageBuffer> {
        let w = 2 * dots;
        let pixels = (0..w).map(|x| u8::from(x % 2 == 0)).collect();
        PreparedImage::without_preparation(BasicImageBuffer { w, h: 1, pixels })
    }

    #[test]
    fn test_region_cache_evicts_least_recently_used() {
        let mut img = dotted_row(CACHE_SIZE + 1);
        // The first CACHE_SIZE dots take the colors 0.., in order.
        for i in 0..CACHE_SIZE {
            img.get_region((2 * i, 0));
        }
        assert_eq!(img.get_pixel_at(2, 0), PixelColor::Discarded(1));
        // Reading the first dot's region makes the second dot's the oldest.
        img.get_region((0, 0));
        let mut copy = img.clone();

        // A dot past the cache takes the color of the evicted region, whose
        // dot is black again.
        let last = (2 * CACHE_SIZE, 0);
        img.get_region(last);
        assert_eq!(img.get_pixel_at(last.0, 0), PixelColor::Discarded(1));
        assert_eq!(img.get_pixel_at(2, 0), PixelColor::Black);
        assert_eq!(img.get_pixel_at(0, 0), PixelColor::Discarded(0));

        // The copy evicts in the reverse order of the original's.
        copy.get_region(last);
        assert_eq!(copy.get_pixel_at(last.0, 0), PixelColor::Discarded(0));
        assert_eq!(copy.get_pixel_at(0, 0), PixelColor::Black);
        assert_eq!(copy.get_pixel_at(2, 0), PixelColor::Discarded(1));
    }

    #[test]
    fn test_flood_fill_full() {
        let mut test_full = img_from_array([[1, 1, 1], [1, 1, 1], [1, 1, 1]]);

        test_full.flood_fill(0, 0, 1, 2, &mut |_| ());

        for x in 0..3 {
            for y in 0..3 {
                assert_eq!(test_full.get_pixel_at(x, y), 2);
            }
        }
    }

    #[test]
    fn test_flood_fill_single() {
        let mut test_single = img_from_array([[1, 0, 1], [0, 1, 0], [1, 0, 1]]);

        test_single.flood_fill(1, 1, 1, 2, &mut |_| ());

        for x in 0..3 {
            for y in 0..3 {
                if x == 1 && y == 1 {
                    assert_eq!(test_single.get_pixel_at(x, y), 2);
                } else {
                    let col = if (x + y) % 2 == 0 { 1 } else { 0 };
                    assert_eq!(test_single.get_pixel_at(x, y), col);
                }
            }
        }
    }

    #[test]
    fn test_flood_fill_ring() {
        let mut test_ring = img_from_array([[1, 1, 1], [1, 0, 1], [1, 1, 1]]);

        test_ring.flood_fill(0, 0, 1, 2, &mut |_| ());

        for x in 0..3 {
            for y in 0..3 {
                if x == 1 && y == 1 {
                    assert_eq!(test_ring.get_pixel_at(x, y), 0);
                } else {
                    assert_eq!(test_ring.get_pixel_at(x, y), 2);
                }
            }
        }
    }

    #[test]
    fn test_flood_fill_u() {
        let mut test_u = img_from_array([[1, 0, 1], [1, 0, 1], [1, 1, 1]]);

        test_u.flood_fill(0, 0, 1, 2, &mut |_| ());

        for x in 0..3 {
            for y in 0..3 {
                if x == 1 && (y == 0 || y == 1) {
                    assert_eq!(test_u.get_pixel_at(x, y), 0);
                } else {
                    assert_eq!(test_u.get_pixel_at(x, y), 2);
                }
            }
        }
    }

    #[test]
    fn test_flood_fill_empty() {
        let mut test_empty = img_from_array([[0, 0, 0], [0, 0, 0], [0, 0, 0]]);

        test_empty.flood_fill(1, 1, 1, 2, &mut |_| ());

        for x in 0..3 {
            for y in 0..3 {
                assert_eq!(test_empty.get_pixel_at(x, y), 0)
            }
        }
    }

    #[test]
    fn test_get_region() {
        let mut test_u = img_from_array([[1, 0, 1], [1, 0, 1], [1, 1, 1]]);

        let reg = test_u.get_region((0, 0));
        let (color, src_x, src_y, pixel_count) = match reg {
            ColoredRegion::Unclaimed {
                color,
                src_x,
                src_y,
                pixel_count,
            } => (color, src_x, src_y, pixel_count),
            x => panic!("Expected Region::Unclaimed, got {:?}", x),
        };
        assert_eq!(0, src_x);
        assert_eq!(0, src_y);
        assert_eq!(7, pixel_count);
        for x in 0..3 {
            for y in 0..3 {
                if x == 1 && (y == 0 || y == 1) {
                    assert_eq!(PixelColor::White, test_u.get_pixel_at(x, y));
                } else {
                    assert_eq!(color, test_u.get_pixel_at(x, y));
                }
            }
        }
    }

    /// Pixels per module in the drawings below: wide enough for the clock to
    /// be read before the scan of one has ended.
    const SCALE: usize = 12;

    /// Whether the module `(x, y)`, counted from the corner of a version 1
    /// code, is dark in its three finder patterns and its timing patterns.
    fn module_is_dark(x: usize, y: usize) -> bool {
        let finder = |x: usize, y: usize| {
            x < 7
                && y < 7
                && (matches!(x, 0 | 6)
                    || matches!(y, 0 | 6)
                    || ((2..5).contains(&x) && (2..5).contains(&y)))
        };
        let timing = |along: usize| (8..13).contains(&along) && along.is_multiple_of(2);
        finder(x, y)
            || (x >= 14 && finder(x - 14, y))
            || (y >= 14 && finder(x, y - 14))
            || (y == 6 && timing(x))
            || (x == 6 && timing(y))
    }

    /// A drawing, as `(width, height, grey)`, of codes without data whose
    /// corners are at `origins` in modules: a search finds the three finder
    /// patterns of each and a grid that no data fills.
    fn drawing(origins: &[(usize, usize)]) -> (usize, usize, Vec<u8>) {
        let (cols, rows) = origins.iter().fold((0, 0), |(c, r), &(x, y)| {
            (c.max(x + 21 + 8), r.max(y + 21 + 8))
        });
        let (w, h) = (cols * SCALE, rows * SCALE);
        let mut grey = vec![255; w * h];
        for (i, g) in grey.iter_mut().enumerate() {
            let (mx, my) = ((i % w) / SCALE, (i / w) / SCALE);
            let dark = origins.iter().any(|&(ox, oy)| {
                mx >= ox + 4 && my >= oy + 4 && module_is_dark(mx - ox - 4, my - oy - 4)
            });
            if dark {
                *g = 0;
            }
        }
        (w, h, grey)
    }

    /// The drawing of codes at `origins`, prepared under no limit; its meter is
    /// then replaced by one under `limits`.
    fn drawn(origins: &[(usize, usize)], limits: SearchLimits) -> PreparedImage<BasicImageBuffer> {
        let (w, h, grey) = drawing(origins);
        let mut img = PreparedImage::prepare_from_greyscale(w, h, |x, y| grey[y * w + x]);
        img.meter = Meter::new(limits);
        img
    }

    #[test]
    fn a_search_past_its_deadline_returns_what_it_has_and_says_so() {
        let mut whole = drawn(&[(0, 0)], SearchLimits::default());
        let found = whole.detect();
        assert_eq!((found.stop, found.finder_patterns), (None, 3));
        assert_eq!(found.grids.len(), 1);

        // The clock is first read after the scan has passed the finder
        // patterns of the top, and not reached those at the bottom.
        let late = SearchLimits {
            deadline: Some(std::time::Instant::now()),
            ..SearchLimits::default()
        };
        let mut img = drawn(&[(0, 0)], late);
        let found = img.detect();
        assert_eq!(found.stop, Some(Stop::Deadline));
        assert!(found.finder_patterns < 3);
        assert!(found.grids.is_empty());
    }

    #[test]
    fn finder_patterns_past_the_cap_end_their_search_and_the_rest_is_still_read() {
        let two_codes = [(0, 0), (40, 0)];
        let mut img = drawn(&two_codes, SearchLimits::default());
        assert_eq!(img.detect().finder_patterns, 6);

        let cap = SearchLimits {
            max_finder_patterns: Some(5),
            ..SearchLimits::default()
        };
        let mut img = drawn(&two_codes, cap);
        let found = img.detect();
        assert_eq!(found.stop, Some(Stop::FinderPatterns));
        assert_eq!(found.finder_patterns, 5);
        // The first code has its three patterns among the five.
        assert_eq!(found.grids.len(), 1);
    }

    #[test]
    fn candidate_grids_past_the_cap_end_their_trials_and_the_found_are_still_read() {
        let two_codes = [(0, 0), (40, 0)];
        let mut img = drawn(&two_codes, SearchLimits::default());
        let found = img.detect();
        assert_eq!((found.stop, found.candidate_grids), (None, 2));
        assert_eq!(found.grids.len(), 2);

        let cap = SearchLimits {
            max_candidate_grids: Some(1),
            ..SearchLimits::default()
        };
        let mut img = drawn(&two_codes, cap);
        let found = img.detect();
        assert_eq!(found.stop, Some(Stop::CandidateGrids));
        assert_eq!(found.candidate_grids, 1);
        assert_eq!(found.grids.len(), 1);
    }

    #[test]
    fn a_search_over_its_memory_budget_is_refused() {
        let (w, h, grey) = drawing(&[(0, 0)]);
        let within = |max_bytes: u64| {
            let limits = SearchLimits {
                max_bytes: Some(max_bytes),
                ..SearchLimits::default()
            };
            PreparedImage::prepare_from_greyscale_within(w, h, |x, y| grey[y * w + x], limits)
        };
        let pixels = (w * h) as u64;
        let rows = 8 * w as u64;
        // The grey image does not fit.
        assert_eq!(within(pixels - 1).err(), Some(Stop::Memory));
        // The sums of a row of it do not fit.
        assert_eq!(within(pixels + rows - 1).err(), Some(Stop::Memory));
        // Both fit, a few thousand bytes of finder patterns too, but not the
        // copy of the image that the trial of a candidate grid is made on.
        let mut img = within(pixels + rows + 4096).unwrap();
        let found = img.detect();
        assert_eq!(found.stop, Some(Stop::Memory));
        assert_eq!((found.finder_patterns, found.candidate_grids), (3, 1));
        assert!(found.grids.is_empty());
        // With room for the copy, the code is found.
        let mut img = within(2 * pixels + rows + 65536).unwrap();
        let found = img.detect();
        assert_eq!((found.stop, found.grids.len()), (None, 1));
    }
}
