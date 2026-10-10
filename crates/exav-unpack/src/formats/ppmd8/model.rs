//! PPMd8 (var.I rev.1) model, ported from `ppmd-rust` 1.5.0 (CC0-1.0 OR MIT-0)
//! `internal/ppmd8.rs` and `internal/ppmd8/decoder.rs`, and generalised over
//! the [`RangeDec`] trait as the PPMd7 model in `formats/ppmd7` is. Not derived
//! from UnRAR.
//!
//! # 100% safe-Rust arena
//!
//! Upstream addresses the sub-allocator through raw pointers into one heap
//! allocation. Here it is a `Vec<u8>` arena addressed by `u32` byte offsets,
//! read and written through the bounds-checked little-endian `rd_*`/`wr_*`
//! accessors. An out-of-range access sets `corrupt` and reads `0`, and
//! [`Ppmd8::decode_symbol`] then returns [`SYM_ERROR`]. Offset arithmetic
//! wraps, every walk over a list, a context's states or a suffix chain is
//! bounded, and every table index is checked, so no input can make the model
//! panic or loop forever. The arena layout is upstream's, so decoding is
//! byte-exact with it.

use super::RestoreMethod;
use crate::formats::ppmd7::common::*;
use crate::formats::ppmd7::{RangeDec, TaggedOffset, SYM_END, SYM_ERROR};

// Context (12 bytes):
//   num_stats:u8 @0 (symbol count - 1)  flags:u8 @1
//   @2: summ_freq:u16 | single state { symbol:u8 @2, freq:u8 @3 }
//   @4: stats:u32     | single state successor (u16 @4, u16 @6)
//   suffix:u32 @8
// Node (12 bytes, a free block):
//   stamp:u32 @0  next:u32 @4  nu:u32 @8
const CTX_NUM_STATS: u32 = 0;
const CTX_FLAGS: u32 = 1;
const CTX_SUMM_FREQ: u32 = 2;
const CTX_STATS: u32 = 4;
const CTX_SUFFIX: u32 = 8;
/// The single state of a binary context overlays bytes 2..8.
const CTX_SINGLE_STATE: u32 = 2;

const NODE_STAMP: u32 = 0;
const NODE_NEXT: u32 = 4;
const NODE_NU: u32 = 8;

const EMPTY_NODE: u32 = u32::MAX;
const FLAG_RESCALED: u8 = 1 << 2;
const FLAG_PREV_HIGH: u8 = 1 << 4;

/// Upstream sizes its successor stack `PPMD8_MAX_ORDER + 1`.
const PS_LEN: usize = super::PPMD8_MAX_ORDER as usize + 1;
/// Bound on suffix-chain walks. A valid chain is at most `max_order` (<= 16)
/// links long.
const CHAIN_LIMIT: u32 = 64;
/// Bound on the cut-off passes of one model restore (see `restore_model`).
const CUT_OFF_PASS_LIMIT: u32 = 64;

/// Where a list walk writes the link it unhooks: a list head or a node's
/// `next` field.
#[derive(Copy, Clone)]
enum Link {
    Local,
    FreeList(usize),
    Node(u32),
}

/// The PPMd8 model, generic over the range decoder. Every context, state and
/// node "pointer" is a `u32` byte offset into `arena`.
pub(crate) struct Ppmd8<RC: RangeDec> {
    min_context: u32,
    max_context: u32,
    found_state: u32,
    order_fall: u32,
    init_esc: u32,
    prev_success: u32,
    max_order: u32,
    restore_method: RestoreMethod,
    run_length: i32,
    init_rl: i32,
    size: u32,
    glue_count: u32,
    align_offset: u32,
    lo_unit: u32,
    hi_unit: u32,
    text: u32,
    units_start: u32,
    index2units: [u8; 40],
    units2index: [u8; 128],
    free_list: [TaggedOffset; PPMD_NUM_INDEXES as usize],
    stamps: [u32; PPMD_NUM_INDEXES as usize],
    ns2bs_index: [u8; 256],
    ns2index: [u8; 260],
    dummy_see: See,
    see: [[See; 32]; 24],
    bin_summ: [[u16; 64]; 25],
    arena: Vec<u8>,
    corrupt: bool,
    rc: RC,
    /// How often `restore_model` restarted, and cut the model off.
    #[cfg(test)]
    pub(crate) restores: (u32, u32),
    /// The most cut-off passes one restore took.
    #[cfg(test)]
    pub(crate) max_cut_off_passes: u32,
}

impl<RC: RangeDec> Ppmd8<RC> {
    /// The model over `rc` (already initialised), `order` in
    /// `PPMD8_MIN_ORDER..=PPMD8_MAX_ORDER` and `mem_size` in
    /// `PPMD8_MIN_MEM_SIZE..=PPMD8_MAX_MEM_SIZE`. `None` if a parameter is out
    /// of range or the arena cannot be allocated.
    pub(crate) fn new(
        rc: RC,
        order: u32,
        mem_size: u32,
        restore_method: RestoreMethod,
    ) -> Option<Self> {
        if !(super::PPMD8_MIN_ORDER..=super::PPMD8_MAX_ORDER).contains(&order)
            || !(super::PPMD8_MIN_MEM_SIZE..=super::PPMD8_MAX_MEM_SIZE).contains(&mem_size)
        {
            return None;
        }

        let mut units2index = [0u8; 128];
        let mut index2units = [0u8; 40];
        let mut k = 0usize;
        for i in 0..PPMD_NUM_INDEXES {
            let step = if i >= 12 { 4 } else { (i >> 2) + 1 };
            for _ in 0..step {
                units2index[k] = i as u8;
                k += 1;
            }
            index2units[i as usize] = k as u8;
        }

        let mut ns2bs_index = [0u8; 256];
        ns2bs_index[0] = 0;
        ns2bs_index[1] = 2;
        ns2bs_index[2..11].fill(4);
        ns2bs_index[11..256].fill(6);

        let mut ns2index = [0u8; 260];
        for (i, v) in ns2index.iter_mut().enumerate().take(5) {
            *v = i as u8;
        }
        let mut m = 5u32;
        let mut k = 1u32;
        for v in ns2index.iter_mut().skip(5) {
            *v = m as u8;
            k -= 1;
            if k == 0 {
                m += 1;
                k = m - 4;
            }
        }

        let align_offset = (4u32.wrapping_sub(mem_size)) & 3;
        let total_size = (align_offset as usize).checked_add(mem_size as usize)?;
        let mut arena: Vec<u8> = Vec::new();
        arena.try_reserve_exact(total_size).ok()?;
        arena.resize(total_size, 0u8);

        let mut ppmd = Self {
            min_context: 0,
            max_context: 0,
            found_state: 0,
            order_fall: 0,
            init_esc: 0,
            prev_success: 0,
            max_order: order,
            restore_method,
            run_length: 0,
            init_rl: 0,
            size: mem_size,
            glue_count: 0,
            align_offset,
            lo_unit: 0,
            hi_unit: 0,
            text: 0,
            units_start: 0,
            index2units,
            units2index,
            free_list: [TaggedOffset::null(); PPMD_NUM_INDEXES as usize],
            stamps: [0; PPMD_NUM_INDEXES as usize],
            ns2bs_index,
            ns2index,
            dummy_see: See::default(),
            see: [[See::default(); 32]; 24],
            bin_summ: [[0; 64]; 25],
            arena,
            corrupt: false,
            rc,
            #[cfg(test)]
            restores: (0, 0),
            #[cfg(test)]
            max_cut_off_passes: 0,
        };
        ppmd.restart_model();
        Some(ppmd)
    }

    /// True once the range decoder has read past the end of its input.
    pub(crate) fn out_of_data(&self) -> bool {
        self.rc.out_of_data()
    }

    // ---- bounds-checked little-endian arena accessors --------------------

    fn rd_u8(&mut self, off: u32) -> u8 {
        match self.arena.get(off as usize) {
            Some(&b) => b,
            None => {
                self.corrupt = true;
                0
            }
        }
    }

    fn rd_u16(&mut self, off: u32) -> u16 {
        let o = off as usize;
        match o.checked_add(2).and_then(|end| self.arena.get(o..end)) {
            Some(s) => u16::from_le_bytes([s[0], s[1]]),
            None => {
                self.corrupt = true;
                0
            }
        }
    }

    fn rd_u32(&mut self, off: u32) -> u32 {
        let o = off as usize;
        match o.checked_add(4).and_then(|end| self.arena.get(o..end)) {
            Some(s) => u32::from_le_bytes([s[0], s[1], s[2], s[3]]),
            None => {
                self.corrupt = true;
                0
            }
        }
    }

    fn wr_u8(&mut self, off: u32, v: u8) {
        match self.arena.get_mut(off as usize) {
            Some(b) => *b = v,
            None => self.corrupt = true,
        }
    }

    fn wr_u16(&mut self, off: u32, v: u16) {
        let o = off as usize;
        match o.checked_add(2).and_then(|end| self.arena.get_mut(o..end)) {
            Some(s) => s.copy_from_slice(&v.to_le_bytes()),
            None => self.corrupt = true,
        }
    }

    fn wr_u32(&mut self, off: u32, v: u32) {
        let o = off as usize;
        match o.checked_add(4).and_then(|end| self.arena.get_mut(o..end)) {
            Some(s) => s.copy_from_slice(&v.to_le_bytes()),
            None => self.corrupt = true,
        }
    }

    /// `memmove` of `len` bytes from `src` to `dst` within the arena.
    fn arena_copy(&mut self, dst: u32, src: u32, len: u32) {
        let (d, s, l) = (dst as usize, src as usize, len as usize);
        let fits = |start: usize| start.checked_add(l).is_some_and(|e| e <= self.arena.len());
        if !fits(d) || !fits(s) {
            self.corrupt = true;
            return;
        }
        self.arena.copy_within(s..s + l, d);
    }

    // ---- typed field accessors -------------------------------------------

    fn state_symbol(&mut self, s: u32) -> u8 {
        self.rd_u8(s.wrapping_add(ST_SYMBOL))
    }
    fn set_state_symbol(&mut self, s: u32, v: u8) {
        self.wr_u8(s.wrapping_add(ST_SYMBOL), v)
    }
    fn state_freq(&mut self, s: u32) -> u8 {
        self.rd_u8(s.wrapping_add(ST_FREQ))
    }
    fn set_state_freq(&mut self, s: u32, v: u8) {
        self.wr_u8(s.wrapping_add(ST_FREQ), v)
    }
    fn state_successor(&mut self, s: u32) -> TaggedOffset {
        let lo = self.rd_u16(s.wrapping_add(ST_SUCC0)) as u32;
        let hi = self.rd_u16(s.wrapping_add(ST_SUCC1)) as u32;
        TaggedOffset::from_raw(lo | (hi << 16))
    }
    fn set_state_successor(&mut self, s: u32, v: TaggedOffset) {
        let raw = v.as_raw();
        self.wr_u16(s.wrapping_add(ST_SUCC0), raw as u16);
        self.wr_u16(s.wrapping_add(ST_SUCC1), (raw >> 16) as u16);
    }
    fn copy_state(&mut self, dst: u32, src: u32) {
        self.arena_copy(dst, src, STATE_SIZE);
    }
    fn swap_states(&mut self, a: u32, b: u32) {
        let mut ta = [0u8; STATE_SIZE as usize];
        let mut tb = [0u8; STATE_SIZE as usize];
        for j in 0..STATE_SIZE {
            ta[j as usize] = self.rd_u8(a.wrapping_add(j));
            tb[j as usize] = self.rd_u8(b.wrapping_add(j));
        }
        for j in 0..STATE_SIZE {
            self.wr_u8(a.wrapping_add(j), tb[j as usize]);
            self.wr_u8(b.wrapping_add(j), ta[j as usize]);
        }
    }
    fn read_state(&mut self, s: u32) -> [u8; STATE_SIZE as usize] {
        let mut t = [0u8; STATE_SIZE as usize];
        for j in 0..STATE_SIZE {
            t[j as usize] = self.rd_u8(s.wrapping_add(j));
        }
        t
    }
    fn write_state(&mut self, s: u32, t: [u8; STATE_SIZE as usize]) {
        for j in 0..STATE_SIZE {
            self.wr_u8(s.wrapping_add(j), t[j as usize]);
        }
    }

    fn ctx_num_stats(&mut self, c: u32) -> u8 {
        self.rd_u8(c.wrapping_add(CTX_NUM_STATS))
    }
    fn set_ctx_num_stats(&mut self, c: u32, v: u8) {
        self.wr_u8(c.wrapping_add(CTX_NUM_STATS), v)
    }
    fn ctx_flags(&mut self, c: u32) -> u8 {
        self.rd_u8(c.wrapping_add(CTX_FLAGS))
    }
    fn set_ctx_flags(&mut self, c: u32, v: u8) {
        self.wr_u8(c.wrapping_add(CTX_FLAGS), v)
    }
    fn ctx_summ_freq(&mut self, c: u32) -> u16 {
        self.rd_u16(c.wrapping_add(CTX_SUMM_FREQ))
    }
    fn set_ctx_summ_freq(&mut self, c: u32, v: u16) {
        self.wr_u16(c.wrapping_add(CTX_SUMM_FREQ), v)
    }
    fn ctx_stats(&mut self, c: u32) -> u32 {
        self.rd_u32(c.wrapping_add(CTX_STATS))
    }
    fn set_ctx_stats(&mut self, c: u32, v: u32) {
        self.wr_u32(c.wrapping_add(CTX_STATS), v)
    }
    fn ctx_suffix(&mut self, c: u32) -> TaggedOffset {
        TaggedOffset::from_raw(self.rd_u32(c.wrapping_add(CTX_SUFFIX)))
    }
    fn set_ctx_suffix(&mut self, c: u32, v: TaggedOffset) {
        self.wr_u32(c.wrapping_add(CTX_SUFFIX), v.as_raw())
    }
    fn single_state(c: u32) -> u32 {
        c.wrapping_add(CTX_SINGLE_STATE)
    }

    /// A successor in the units area is a context; below it, it points into
    /// the text area (a "raw" successor).
    fn is_real_context(&self, v: TaggedOffset) -> bool {
        v.get_offset() >= self.units_start
    }

    /// The state for `sym` among context `c`'s states. A miss means the model
    /// is inconsistent.
    fn find_state(&mut self, c: u32, sym: u8) -> Option<u32> {
        let mut s = self.ctx_stats(c);
        let n = self.ctx_num_stats(c) as u32 + 1;
        for _ in 0..n {
            if self.state_symbol(s) == sym {
                return Some(s);
            }
            s = s.wrapping_add(STATE_SIZE);
        }
        self.corrupt = true;
        None
    }

    /// `units2index[nu - 1]`, for `nu` in 1..=128.
    fn u2i(&mut self, nu: u32) -> u32 {
        match nu
            .checked_sub(1)
            .and_then(|i| self.units2index.get(i as usize))
        {
            Some(&i) => i as u32,
            None => {
                self.corrupt = true;
                0
            }
        }
    }

    fn i2u(&self, index: u32) -> u32 {
        self.index2units
            .get(index as usize)
            .map_or(0, |&u| u as u32)
    }

    /// Upper bound on the nodes any list can hold.
    fn max_nodes(&self) -> usize {
        self.arena.len() / UNIT_SIZE as usize + 1
    }

    fn set_link(&mut self, link: Link, local: &mut TaggedOffset, v: TaggedOffset) {
        match link {
            Link::Local => *local = v,
            Link::FreeList(i) => self.free_list[i] = v,
            Link::Node(off) => self.wr_u32(off, v.as_raw()),
        }
    }

    // ---- sub-allocator ----------------------------------------------------

    fn insert_node(&mut self, node: u32, index: u32) {
        let i = index as usize;
        if i >= self.free_list.len() {
            self.corrupt = true;
            return;
        }
        self.wr_u32(node.wrapping_add(NODE_STAMP), EMPTY_NODE);
        let head = self.free_list[i].as_raw();
        self.wr_u32(node.wrapping_add(NODE_NEXT), head);
        let nu = self.i2u(index);
        self.wr_u32(node.wrapping_add(NODE_NU), nu);
        self.free_list[i] = TaggedOffset::from_raw(node);
        self.stamps[i] = self.stamps[i].wrapping_add(1);
    }

    /// Pops list `index`, which the caller has checked is not empty.
    fn remove_node(&mut self, index: u32) -> u32 {
        let i = index as usize;
        let node = self.free_list[i].as_raw();
        let next = self.rd_u32(node.wrapping_add(NODE_NEXT));
        self.free_list[i] = TaggedOffset::from_raw(next);
        self.stamps[i] = self.stamps[i].wrapping_sub(1);
        node
    }

    fn split_block(&mut self, ptr: u32, old_index: u32, new_index: u32) {
        let nu = self.i2u(old_index).wrapping_sub(self.i2u(new_index));
        let ptr = ptr.wrapping_add(self.i2u(new_index).wrapping_mul(UNIT_SIZE));
        let mut index = self.u2i(nu);
        if self.i2u(index) != nu {
            index = index.wrapping_sub(1);
            let k = self.i2u(index);
            self.insert_node(
                ptr.wrapping_add(k.wrapping_mul(UNIT_SIZE)),
                nu.wrapping_sub(k).wrapping_sub(1),
            );
        }
        self.insert_node(ptr, index);
    }

    fn glue_free_blocks(&mut self) {
        self.glue_count = 1 << 13;
        self.stamps = [0; PPMD_NUM_INDEXES as usize];
        // Guard node at lo_unit.
        if self.lo_unit != self.hi_unit {
            self.wr_u32(self.lo_unit.wrapping_add(NODE_STAMP), 0);
        }
        let head = self.glue_blocks();
        self.fill_list(head);
    }

    /// Chains every free block into one list, merging each with the free
    /// blocks that follow it in memory. Returns the list head.
    fn glue_blocks(&mut self) -> TaggedOffset {
        let mut head = TaggedOffset::null();
        let mut prev = Link::Local;
        let mut budget = self.max_nodes();
        for i in 0..PPMD_NUM_INDEXES as usize {
            let mut next = self.free_list[i];
            self.free_list[i] = TaggedOffset::null();
            while next.is_not_null() {
                if budget == 0 {
                    self.corrupt = true;
                    return TaggedOffset::null();
                }
                budget -= 1;
                let node = next.as_raw();
                let mut nu = self.rd_u32(node.wrapping_add(NODE_NU));
                self.set_link(prev, &mut head, next);
                next = TaggedOffset::from_raw(self.rd_u32(node.wrapping_add(NODE_NEXT)));
                if nu != 0 {
                    prev = Link::Node(node.wrapping_add(NODE_NEXT));
                    loop {
                        let node2 = node.wrapping_add(nu.wrapping_mul(UNIT_SIZE));
                        if self.rd_u32(node2.wrapping_add(NODE_STAMP)) != EMPTY_NODE {
                            break;
                        }
                        let nu2 = self.rd_u32(node2.wrapping_add(NODE_NU));
                        if nu2 == 0 || self.corrupt {
                            // Would not advance: only a damaged arena has this.
                            self.corrupt = true;
                            return TaggedOffset::null();
                        }
                        nu = nu.wrapping_add(nu2);
                        self.wr_u32(node.wrapping_add(NODE_NU), nu);
                        self.wr_u32(node2.wrapping_add(NODE_NU), 0);
                    }
                }
            }
        }
        self.set_link(prev, &mut head, TaggedOffset::null());
        head
    }

    /// Splits the glued blocks back into the per-size free lists.
    fn fill_list(&mut self, mut n: TaggedOffset) {
        let mut budget = self.max_nodes();
        while n.is_not_null() {
            if budget == 0 || self.corrupt {
                self.corrupt = true;
                return;
            }
            budget -= 1;
            let mut node = n.as_raw();
            let mut nu = self.rd_u32(node.wrapping_add(NODE_NU));
            n = TaggedOffset::from_raw(self.rd_u32(node.wrapping_add(NODE_NEXT)));
            if nu == 0 {
                continue;
            }
            if nu as usize > self.max_nodes() {
                self.corrupt = true;
                return;
            }
            while nu > 128 {
                self.insert_node(node, PPMD_NUM_INDEXES - 1);
                nu -= 128;
                node = node.wrapping_add(128 * UNIT_SIZE);
            }
            let mut index = self.u2i(nu);
            if self.i2u(index) != nu {
                index = index.wrapping_sub(1);
                let k = self.i2u(index);
                self.insert_node(
                    node.wrapping_add(k.wrapping_mul(UNIT_SIZE)),
                    nu.wrapping_sub(k).wrapping_sub(1),
                );
            }
            self.insert_node(node, index);
        }
    }

    fn alloc_units_rare(&mut self, index: u32) -> Option<u32> {
        if index >= PPMD_NUM_INDEXES {
            self.corrupt = true;
            return None;
        }
        if self.glue_count == 0 {
            self.glue_free_blocks();
            if self.free_list[index as usize].is_not_null() {
                return Some(self.remove_node(index));
            }
        }
        let mut i = index;
        loop {
            i += 1;
            if i == PPMD_NUM_INDEXES {
                let num_bytes = self.i2u(index) * UNIT_SIZE;
                let us = self.units_start;
                self.glue_count = self.glue_count.wrapping_sub(1);
                return if us.wrapping_sub(self.text) > num_bytes {
                    self.units_start = us.wrapping_sub(num_bytes);
                    Some(self.units_start)
                } else {
                    None
                };
            }
            if self.free_list[i as usize].is_not_null() {
                break;
            }
        }
        let block = self.remove_node(i);
        self.split_block(block, i, index);
        Some(block)
    }

    fn alloc_units(&mut self, index: u32) -> Option<u32> {
        if index >= PPMD_NUM_INDEXES {
            self.corrupt = true;
            return None;
        }
        if self.free_list[index as usize].is_not_null() {
            return Some(self.remove_node(index));
        }
        let num_bytes = self.i2u(index) * UNIT_SIZE;
        let lo = self.lo_unit;
        if self.hi_unit.wrapping_sub(lo) >= num_bytes {
            self.lo_unit = lo.wrapping_add(num_bytes);
            return Some(lo);
        }
        self.alloc_units_rare(index)
    }

    fn shrink_units(&mut self, old_ptr: u32, old_nu: u32, new_nu: u32) -> u32 {
        let i0 = self.u2i(old_nu);
        let i1 = self.u2i(new_nu);
        if i0 == i1 {
            return old_ptr;
        }
        if self.free_list[i1 as usize].is_not_null() {
            let ptr = self.remove_node(i1);
            self.arena_copy(ptr, old_ptr, new_nu.wrapping_mul(UNIT_SIZE));
            self.insert_node(old_ptr, i0);
            return ptr;
        }
        self.split_block(old_ptr, i0, i1);
        old_ptr
    }

    fn free_units(&mut self, ptr: u32, nu: u32) {
        let index = self.u2i(nu);
        self.insert_node(ptr, index);
    }

    fn special_free_unit(&mut self, ptr: u32) {
        if ptr != self.units_start {
            self.insert_node(ptr, 0);
        } else {
            self.units_start = self.units_start.wrapping_add(UNIT_SIZE);
        }
    }

    /// Returns the free blocks at the bottom of the units area to the text
    /// area.
    fn expand_text_area(&mut self) {
        let mut count = [0u32; PPMD_NUM_INDEXES as usize];
        if self.lo_unit != self.hi_unit {
            self.wr_u32(self.lo_unit.wrapping_add(NODE_STAMP), 0);
        }

        let mut node = self.units_start;
        while self.rd_u32(node.wrapping_add(NODE_STAMP)) == EMPTY_NODE {
            let nu = self.rd_u32(node.wrapping_add(NODE_NU));
            self.wr_u32(node.wrapping_add(NODE_STAMP), 0);
            let i = self.u2i(nu);
            if nu == 0 || self.corrupt {
                self.corrupt = true;
                return;
            }
            count[i as usize] = count[i as usize].wrapping_add(1);
            node = node.wrapping_add(nu.wrapping_mul(UNIT_SIZE));
        }
        self.units_start = node;

        for (i, &removed) in count.iter().enumerate() {
            let mut cnt = removed;
            if cnt == 0 {
                continue;
            }
            let mut prev = Link::FreeList(i);
            let mut n = self.free_list[i];
            self.stamps[i] = self.stamps[i].wrapping_sub(cnt);
            let mut budget = self.max_nodes();
            let mut unused = TaggedOffset::null();
            loop {
                if n.is_null() || budget == 0 {
                    self.corrupt = true;
                    return;
                }
                budget -= 1;
                let node = n.as_raw();
                n = TaggedOffset::from_raw(self.rd_u32(node.wrapping_add(NODE_NEXT)));
                if self.rd_u32(node.wrapping_add(NODE_STAMP)) != 0 {
                    prev = Link::Node(node.wrapping_add(NODE_NEXT));
                    continue;
                }
                self.set_link(prev, &mut unused, n);
                cnt -= 1;
                if cnt == 0 {
                    break;
                }
            }
        }
    }

    fn restart_model(&mut self) {
        self.free_list = [TaggedOffset::null(); PPMD_NUM_INDEXES as usize];
        self.stamps = [0; PPMD_NUM_INDEXES as usize];

        self.text = self.align_offset;
        self.hi_unit = self.text + self.size;
        self.units_start = self.hi_unit - (self.size / 8 / UNIT_SIZE * 7 * UNIT_SIZE);
        self.lo_unit = self.units_start;
        self.glue_count = 0;

        self.order_fall = self.max_order;
        self.init_rl = -(self.max_order.min(12) as i32) - 1;
        self.run_length = self.init_rl;
        self.prev_success = 0;

        self.hi_unit -= UNIT_SIZE;
        let mc = self.hi_unit;
        let s = self.lo_unit;
        self.lo_unit += (256 / 2) * UNIT_SIZE;
        self.min_context = mc;
        self.max_context = mc;
        self.found_state = s;

        self.set_ctx_flags(mc, 0);
        self.set_ctx_num_stats(mc, 255);
        self.set_ctx_summ_freq(mc, 256 + 1);
        self.set_ctx_stats(mc, s);
        self.set_ctx_suffix(mc, TaggedOffset::null());

        for i in 0..256u32 {
            let st = s + i * STATE_SIZE;
            self.set_state_symbol(st, i as u8);
            self.set_state_freq(st, 1);
            self.set_state_successor(st, TaggedOffset::null());
        }

        let mut i = 0u32;
        for m in 0..25 {
            while self.ns2index[i as usize] as usize == m {
                i += 1;
            }
            for (k, &esc) in K_INIT_BIN_ESC.iter().enumerate() {
                let val = PPMD_BIN_SCALE - (esc as u32) / (i + 1);
                for r in (0..64).step_by(8) {
                    self.bin_summ[m][k + r] = val as u16;
                }
            }
        }

        let mut i = 0u32;
        for m in 0..24 {
            while self.ns2index[(i + 3) as usize] as usize == m + 3 {
                i += 1;
            }
            let summ = (2 * i + 5) << (PPMD_PERIOD_BITS - 4);
            for see in self.see[m].iter_mut() {
                see.summ = summ as u16;
                see.shift = (PPMD_PERIOD_BITS - 4) as u8;
                see.count = 7;
            }
        }

        self.dummy_see.summ = 0;
        self.dummy_see.shift = PPMD_PERIOD_BITS as u8;
        self.dummy_see.count = 64;
    }

    /// After symbols were removed from `ctx`: shrinks its block and rescales
    /// its frequencies, raising the escape frequency by what was removed.
    fn refresh(&mut self, ctx: u32, old_nu: u32, mut scale: u32) {
        let num_stats = self.ctx_num_stats(ctx) as u32;
        if num_stats == 0 {
            self.corrupt = true;
            return;
        }
        let states = self.ctx_stats(ctx);
        let mut s = self.shrink_units(states, old_nu, (num_stats + 2) >> 1);
        self.set_ctx_stats(ctx, s);

        let summ = self.ctx_summ_freq(ctx) as u32;
        scale |= (summ >= 1 << 15) as u32;

        let mut flags = Self::hi_bits_prepare(self.state_symbol(s) as u32);
        let mut freq = self.state_freq(s) as u32;
        let mut esc_freq = summ.wrapping_sub(freq);
        freq = (freq + scale) >> scale;
        let mut sum_freq = freq;
        self.set_state_freq(s, freq as u8);

        for _ in 0..num_stats {
            s = s.wrapping_add(STATE_SIZE);
            let mut freq = self.state_freq(s) as u32;
            esc_freq = esc_freq.wrapping_sub(freq);
            freq = (freq + scale) >> scale;
            sum_freq += freq;
            self.set_state_freq(s, freq as u8);
            flags |= Self::hi_bits_prepare(self.state_symbol(s) as u32);
        }

        self.set_ctx_summ_freq(
            ctx,
            sum_freq.wrapping_add(esc_freq.wrapping_add(scale) >> scale) as u16,
        );
        let kept =
            self.ctx_flags(ctx) as u32 & (FLAG_PREV_HIGH as u32 + FLAG_RESCALED as u32 * scale);
        self.set_ctx_flags(ctx, (kept + Self::hi_bits_convert_3(flags)) as u8);
    }

    /// Cuts the model down when memory runs out (restore method "cut off"):
    /// drops successors past `max_order`, raw successors and empty contexts,
    /// and moves a state block that sits near `units_start` up. Returns `ctx`,
    /// or null if `ctx` was freed.
    fn cut_off(&mut self, ctx: u32, order: u32) -> TaggedOffset {
        if self.corrupt {
            return TaggedOffset::null();
        }
        let mut ns = self.ctx_num_stats(ctx) as i32;

        if ns == 0 {
            let single = Self::single_state(ctx);
            let mut successor = self.state_successor(single);
            if self.is_real_context(successor) {
                if order < self.max_order {
                    successor = self.cut_off(successor.get_offset(), order + 1);
                } else {
                    successor = TaggedOffset::null();
                }
                self.set_state_successor(single, successor);
                if successor.is_not_null() || order <= 9 {
                    return TaggedOffset::from_raw(ctx);
                }
            }
            self.special_free_unit(ctx);
            return TaggedOffset::null();
        }

        let nu = (ns as u32 + 2) >> 1;
        let index = self.u2i(nu);
        let mut stats = self.ctx_stats(ctx);

        if stats.wrapping_sub(self.units_start) <= (1 << 14)
            && stats <= self.free_list[index as usize].get_offset()
        {
            let ptr = self.remove_node(index);
            self.set_ctx_stats(ctx, ptr);
            self.arena_copy(ptr, stats, nu * UNIT_SIZE);
            if stats != self.units_start {
                self.insert_node(stats, index);
            } else {
                self.units_start = self.units_start.wrapping_add(self.i2u(index) * UNIT_SIZE);
            }
            stats = ptr;
        }

        // Upstream walks `s` from the last state down to `stats`.
        for k in (0..=ns as u32).rev() {
            let s = stats.wrapping_add(k * STATE_SIZE);
            let successor = self.state_successor(s);
            if !self.is_real_context(successor) {
                let s2 = stats.wrapping_add(ns as u32 * STATE_SIZE);
                ns -= 1;
                if order != 0 {
                    if s != s2 {
                        self.copy_state(s, s2);
                    }
                } else {
                    self.swap_states(s, s2);
                    self.set_state_successor(s2, TaggedOffset::null());
                }
            } else if order < self.max_order {
                let cut = self.cut_off(successor.get_offset(), order + 1);
                self.set_state_successor(s, cut);
            } else {
                self.set_state_successor(s, TaggedOffset::null());
            }
        }

        if ns != self.ctx_num_stats(ctx) as i32 && order != 0 {
            if ns < 0 {
                self.free_units(stats, nu);
                self.special_free_unit(ctx);
                return TaggedOffset::null();
            }
            self.set_ctx_num_stats(ctx, ns as u8);
            if ns == 0 {
                let sym = self.state_symbol(stats);
                let flags =
                    (self.ctx_flags(ctx) & FLAG_PREV_HIGH) as u32 + Self::hi_bits_flag3(sym as u32);
                self.set_ctx_flags(ctx, flags as u8);
                let single = Self::single_state(ctx);
                self.set_state_symbol(single, sym);
                let freq = ((self.state_freq(stats) as u32 + 11) >> 3) as u8;
                self.set_state_freq(single, freq);
                let succ = self.state_successor(stats);
                self.set_state_successor(single, succ);
                self.free_units(stats, nu);
            } else {
                let scale = (self.ctx_summ_freq(ctx) as u32 > 16 * ns as u32) as u32;
                self.refresh(ctx, nu, scale);
            }
        }

        TaggedOffset::from_raw(ctx)
    }

    fn get_used_memory(&self) -> u32 {
        let mut v = 0u32;
        for i in 0..PPMD_NUM_INDEXES as usize {
            v = v.wrapping_add(self.stamps[i].wrapping_mul(self.index2units[i] as u32));
        }
        self.size
            .wrapping_sub(self.hi_unit.wrapping_sub(self.lo_unit))
            .wrapping_sub(self.units_start.wrapping_sub(self.text))
            .wrapping_sub(v.wrapping_mul(UNIT_SIZE))
    }

    /// Recovers from a failed context allocation, by the restore method.
    fn restore_model(&mut self, ctx_error: u32) {
        self.text = self.align_offset;

        // Roll back the symbol added to each context in
        // [max_context, ctx_error).
        let mut c = self.max_context;
        let mut steps = 0;
        while c != ctx_error {
            steps += 1;
            if steps > CHAIN_LIMIT || self.corrupt {
                self.corrupt = true;
                return;
            }
            let ns = self.ctx_num_stats(c).wrapping_sub(1);
            self.set_ctx_num_stats(c, ns);
            if ns == 0 {
                let s = self.ctx_stats(c);
                let sym = self.state_symbol(s);
                let flags =
                    (self.ctx_flags(c) & FLAG_PREV_HIGH) as u32 + Self::hi_bits_flag3(sym as u32);
                self.set_ctx_flags(c, flags as u8);
                let single = Self::single_state(c);
                self.set_state_symbol(single, sym);
                let freq = ((self.state_freq(s) as u32 + 11) >> 3) as u8;
                self.set_state_freq(single, freq);
                let succ = self.state_successor(s);
                self.set_state_successor(single, succ);
                self.special_free_unit(s);
            } else {
                self.refresh(c, (ns as u32 + 3) >> 1, 0);
            }
            c = self.ctx_suffix(c).get_offset();
        }

        // Raise the escape frequency of [ctx_error, min_context).
        let mut steps = 0;
        while c != self.min_context {
            steps += 1;
            if steps > CHAIN_LIMIT || self.corrupt {
                self.corrupt = true;
                return;
            }
            let ns = self.ctx_num_stats(c) as u32;
            if ns == 0 {
                let single = Self::single_state(c);
                let freq = ((self.state_freq(single) as u32 + 1) >> 1) as u8;
                self.set_state_freq(single, freq);
            } else {
                let summ = self.ctx_summ_freq(c).wrapping_add(4);
                self.set_ctx_summ_freq(c, summ);
                if summ as u32 > 128 + 4 * ns {
                    self.refresh(c, (ns + 2) >> 1, 1);
                }
            }
            c = self.ctx_suffix(c).get_offset();
        }

        if self.restore_method == RestoreMethod::Restart || self.get_used_memory() < self.size >> 1
        {
            #[cfg(test)]
            {
                self.restores.0 += 1;
            }
            self.restart_model();
        } else {
            #[cfg(test)]
            {
                self.restores.1 += 1;
            }
            let mut steps = 0;
            while self.ctx_suffix(self.max_context).is_not_null() {
                steps += 1;
                if steps > CHAIN_LIMIT {
                    self.corrupt = true;
                    return;
                }
                self.max_context = self.ctx_suffix(self.max_context).get_offset();
            }
            // Upstream loops until a quarter of the memory is free. A model
            // whose cut-off tree (binary contexts up to order 9 are kept)
            // fills more than that never gets there, and upstream then loops
            // forever, its encoder included (a 2 KiB model does it). The
            // reference cut-off streams in the tests take at most two passes.
            let mut passes = 0;
            loop {
                self.cut_off(self.max_context, 0);
                self.expand_text_area();
                if self.corrupt || self.get_used_memory() <= 3 * (self.size >> 2) {
                    break;
                }
                passes += 1;
                if passes >= CUT_OFF_PASS_LIMIT {
                    self.corrupt = true;
                    return;
                }
            }
            #[cfg(test)]
            {
                self.max_cut_off_passes = self.max_cut_off_passes.max(passes + 1);
            }
            self.glue_count = 0;
            self.order_fall = self.max_order;
        }
        self.min_context = self.max_context;
    }

    fn create_successors(&mut self, skip: bool, s1: &mut Option<u32>, mut c: u32) -> Option<u32> {
        let up_branch = self.state_successor(self.found_state);
        let mut num_ps = 0usize;
        let mut ps = [0u32; PS_LEN];

        if !skip {
            ps[num_ps] = self.found_state;
            num_ps += 1;
        }

        while self.ctx_suffix(c).is_not_null() {
            c = self.ctx_suffix(c).get_offset();
            let s;
            if let Some(state) = s1.take() {
                s = state;
            } else if self.ctx_num_stats(c) != 0 {
                let sym = self.state_symbol(self.found_state);
                s = self.find_state(c, sym)?;
                let freq = self.state_freq(s);
                if freq < MAX_FREQ - 9 {
                    self.set_state_freq(s, freq + 1);
                    let summ = self.ctx_summ_freq(c).wrapping_add(1);
                    self.set_ctx_summ_freq(c, summ);
                }
            } else {
                s = Self::single_state(c);
                let suffix = self.ctx_suffix(c).get_offset();
                let suffix_binary = self.ctx_num_stats(suffix) == 0;
                let freq = self.state_freq(s);
                let bump = (suffix_binary && freq < 24) as u8;
                self.set_state_freq(s, freq.wrapping_add(bump));
            }

            let successor = self.state_successor(s);
            if successor != up_branch {
                c = successor.get_offset();
                if num_ps == 0 {
                    return Some(c);
                }
                break;
            }
            if num_ps >= PS_LEN {
                self.corrupt = true;
                return None;
            }
            ps[num_ps] = s;
            num_ps += 1;
        }

        let new_sym = self.rd_u8(up_branch.get_offset());
        let up_branch = TaggedOffset::from_bytes_offset(up_branch.get_offset().wrapping_add(1));

        let fsym = self.state_symbol(self.found_state);
        let flags = (Self::hi_bits_flag4(fsym as u32) + Self::hi_bits_flag3(new_sym as u32)) as u8;

        let new_freq = if self.ctx_num_stats(c) == 0 {
            self.state_freq(Self::single_state(c))
        } else {
            let s = self.find_state(c, new_sym)?;
            let cf = (self.state_freq(s) as u32).wrapping_sub(1);
            let s0 = (self.ctx_summ_freq(c) as u32)
                .wrapping_sub(self.ctx_num_stats(c) as u32)
                .wrapping_sub(cf);
            let add = if cf.wrapping_mul(2) <= s0 {
                (cf.wrapping_mul(5) > s0) as u32
            } else {
                let num = cf.wrapping_add(s0.wrapping_mul(2)).wrapping_sub(3);
                let Some(q) = num.checked_div(s0) else {
                    self.corrupt = true;
                    return None;
                };
                q
            };
            (add as u8).wrapping_add(1)
        };

        loop {
            let c1 = if self.hi_unit != self.lo_unit {
                self.hi_unit = self.hi_unit.wrapping_sub(UNIT_SIZE);
                self.hi_unit
            } else if self.free_list[0].is_not_null() {
                self.remove_node(0)
            } else {
                self.alloc_units_rare(0)?
            };
            self.set_ctx_flags(c1, flags);
            self.set_ctx_num_stats(c1, 0);
            let single = Self::single_state(c1);
            self.set_state_symbol(single, new_sym);
            self.set_state_freq(single, new_freq);
            self.set_state_successor(single, up_branch);
            self.set_ctx_suffix(c1, TaggedOffset::from_raw(c));
            if num_ps == 0 {
                self.corrupt = true;
                return None;
            }
            num_ps -= 1;
            self.set_state_successor(ps[num_ps], TaggedOffset::from_raw(c1));
            c = c1;
            if num_ps == 0 {
                break;
            }
        }
        Some(c)
    }

    fn reduce_order(&mut self, mut s1: Option<u32>, mut c: u32) -> Option<u32> {
        let c1 = c;
        let up_branch = TaggedOffset::from_bytes_offset(self.text);
        let fs = self.found_state;
        self.set_state_successor(fs, up_branch);
        self.order_fall += 1;

        let mut s;
        let mut steps = 0;
        loop {
            steps += 1;
            if steps > CHAIN_LIMIT || self.corrupt {
                self.corrupt = true;
                return None;
            }
            if let Some(state) = s1.take() {
                c = self.ctx_suffix(c).get_offset();
                s = state;
            } else {
                if self.ctx_suffix(c).is_null() {
                    return Some(c);
                }
                c = self.ctx_suffix(c).get_offset();
                if self.ctx_num_stats(c) != 0 {
                    let sym = self.state_symbol(self.found_state);
                    s = self.find_state(c, sym)?;
                    let freq = self.state_freq(s);
                    if freq < MAX_FREQ - 9 {
                        self.set_state_freq(s, freq + 2);
                        let summ = self.ctx_summ_freq(c).wrapping_add(2);
                        self.set_ctx_summ_freq(c, summ);
                    }
                } else {
                    s = Self::single_state(c);
                    let freq = self.state_freq(s);
                    self.set_state_freq(s, freq + (freq < 32) as u8);
                }
            }
            if self.state_successor(s).is_not_null() {
                break;
            }
            self.set_state_successor(s, up_branch);
            self.order_fall += 1;
        }

        if self.state_successor(s).get_offset() <= up_branch.get_offset() {
            let s2 = self.found_state;
            self.found_state = s;
            let successor = match self.create_successors(false, &mut None, c) {
                None => TaggedOffset::null(),
                Some(successor) => TaggedOffset::from_raw(successor),
            };
            self.set_state_successor(s, successor);
            self.found_state = s2;
        }

        let successor = self.state_successor(s);
        if self.order_fall == 1 && c1 == self.max_context {
            let fs = self.found_state;
            self.set_state_successor(fs, successor);
            self.text = self.text.wrapping_sub(1);
        }
        if successor.is_null() {
            return None;
        }
        Some(successor.get_offset())
    }

    fn update_model(&mut self) {
        let fs = self.found_state;
        let mut min_successor = self.state_successor(fs);
        let f_freq = self.state_freq(fs) as u32;
        let f_symbol = self.state_symbol(fs);
        let mut s: Option<u32> = None;

        let mc_suffix = self.ctx_suffix(self.min_context);
        if f_freq < (MAX_FREQ / 4) as u32 && mc_suffix.is_not_null() {
            // Update the frequency in the suffix context.
            let c = mc_suffix.get_offset();
            if self.ctx_num_stats(c) == 0 {
                let state = Self::single_state(c);
                let freq = self.state_freq(state);
                if freq < 32 {
                    self.set_state_freq(state, freq + 1);
                }
                s = Some(state);
            } else {
                let first = self.ctx_stats(c);
                let Some(mut state) = self.find_state(c, f_symbol) else {
                    return;
                };
                if state != first {
                    let prev = state.wrapping_sub(STATE_SIZE);
                    if self.state_freq(state) >= self.state_freq(prev) {
                        self.swap_states(state, prev);
                        state = prev;
                    }
                }
                let freq = self.state_freq(state);
                if freq < MAX_FREQ - 9 {
                    self.set_state_freq(state, freq + 2);
                    let summ = self.ctx_summ_freq(c).wrapping_add(2);
                    self.set_ctx_summ_freq(c, summ);
                }
                s = Some(state);
            }
        }

        let mut c = self.max_context;
        if self.order_fall == 0 && min_successor.is_not_null() {
            match self.create_successors(true, &mut s, self.min_context) {
                None => {
                    self.set_state_successor(fs, TaggedOffset::null());
                    self.restore_model(c);
                }
                Some(cs) => {
                    self.set_state_successor(fs, TaggedOffset::from_raw(cs));
                    self.max_context = cs;
                    self.min_context = cs;
                }
            }
            return;
        }

        let text = self.text;
        self.wr_u8(text, f_symbol);
        self.text = text.wrapping_add(1);
        if self.text >= self.units_start {
            self.restore_model(c);
            return;
        }
        let mut max_successor = TaggedOffset::from_bytes_offset(self.text);

        if min_successor.is_null() {
            let Some(cs) = self.reduce_order(s, self.min_context) else {
                self.restore_model(c);
                return;
            };
            min_successor = TaggedOffset::from_raw(cs);
        } else if !self.is_real_context(min_successor) {
            let Some(cs) = self.create_successors(false, &mut s, self.min_context) else {
                self.restore_model(c);
                return;
            };
            min_successor = TaggedOffset::from_raw(cs);
        }

        self.order_fall = self.order_fall.wrapping_sub(1);
        if self.order_fall == 0 {
            max_successor = min_successor;
            self.text = self
                .text
                .wrapping_sub((self.max_context != self.min_context) as u32);
        }

        let flag = Self::hi_bits_flag3(f_symbol as u32) as u8;
        let ns = self.ctx_num_stats(self.min_context) as u32;
        let s0 = (self.ctx_summ_freq(self.min_context) as u32)
            .wrapping_sub(ns)
            .wrapping_sub(f_freq);

        let mut steps = 0;
        while c != self.min_context {
            steps += 1;
            if steps > CHAIN_LIMIT || self.corrupt {
                self.corrupt = true;
                return;
            }
            let mut sum;
            let ns1 = self.ctx_num_stats(c) as u32;
            if ns1 != 0 {
                if ns1 & 1 != 0 {
                    // Grow the state block by one unit.
                    let old_nu = (ns1 + 1) >> 1;
                    let i = self.u2i(old_nu);
                    let Some(&next_i) = self.units2index.get(old_nu as usize) else {
                        self.corrupt = true;
                        return;
                    };
                    if i != next_i as u32 {
                        let Some(ptr) = self.alloc_units(i + 1) else {
                            self.restore_model(c);
                            return;
                        };
                        let old_ptr = self.ctx_stats(c);
                        self.arena_copy(ptr, old_ptr, old_nu * UNIT_SIZE);
                        self.insert_node(old_ptr, i);
                        self.set_ctx_stats(c, ptr);
                    }
                }
                sum = self.ctx_summ_freq(c) as u32;
                sum = sum.wrapping_add((3 * ns1 + 1 < ns) as u32);
            } else {
                let Some(st) = self.alloc_units(0) else {
                    self.restore_model(c);
                    return;
                };
                let single = Self::single_state(c);
                let mut freq = self.state_freq(single) as u32;
                let sym = self.state_symbol(single);
                let succ = self.state_successor(single);
                self.set_state_symbol(st, sym);
                self.set_state_successor(st, succ);
                self.set_ctx_stats(c, st);
                if freq < (MAX_FREQ / 4 - 1) as u32 {
                    freq <<= 1;
                } else {
                    freq = (MAX_FREQ - 4) as u32;
                }
                self.set_state_freq(st, freq as u8);
                sum = freq
                    .wrapping_add(self.init_esc)
                    .wrapping_add((ns > 2) as u32);
            }

            let st = self.ctx_stats(c).wrapping_add((ns1 + 1) * STATE_SIZE);
            let mut cf = 2u32.wrapping_mul(sum.wrapping_add(6)).wrapping_mul(f_freq);
            let sf = s0.wrapping_add(sum);
            self.set_state_symbol(st, f_symbol);
            self.set_ctx_num_stats(c, (ns1 + 1) as u8);
            self.set_state_successor(st, max_successor);
            let flags = self.ctx_flags(c) | flag;
            self.set_ctx_flags(c, flags);
            if cf < sf.wrapping_mul(6) {
                cf = 1 + (cf > sf) as u32 + (cf >= sf.wrapping_mul(4)) as u32;
                sum = sum.wrapping_add(4);
            } else {
                cf = 4
                    + (cf > sf.wrapping_mul(9)) as u32
                    + (cf > sf.wrapping_mul(12)) as u32
                    + (cf > sf.wrapping_mul(15)) as u32;
                sum = sum.wrapping_add(cf);
            }
            self.set_ctx_summ_freq(c, sum as u16);
            self.set_state_freq(st, cf as u8);
            c = self.ctx_suffix(c).get_offset();
        }

        self.min_context = min_successor.get_offset();
        self.max_context = self.min_context;
    }

    fn rescale(&mut self) {
        let mc = self.min_context;
        let stats = self.ctx_stats(mc);
        let num_stats = self.ctx_num_stats(mc) as u32;
        let mut s = self.found_state;

        // Move the found state to the front.
        if s != stats {
            let dist = s.wrapping_sub(stats);
            if !dist.is_multiple_of(STATE_SIZE) || dist / STATE_SIZE > num_stats {
                self.corrupt = true;
                return;
            }
            let tmp = self.read_state(s);
            while s != stats {
                self.copy_state(s, s - STATE_SIZE);
                s -= STATE_SIZE;
            }
            self.write_state(s, tmp);
        }

        let mut sum_freq = self.state_freq(s) as u32;
        let mut esc_freq = (self.ctx_summ_freq(mc) as u32).wrapping_sub(sum_freq);
        let adder = (self.order_fall != 0) as u32;
        sum_freq = (sum_freq + 4 + adder) >> 1;
        self.set_state_freq(s, sum_freq as u8);

        for _ in 0..num_stats {
            s = s.wrapping_add(STATE_SIZE);
            let mut freq = self.state_freq(s) as u32;
            esc_freq = esc_freq.wrapping_sub(freq);
            freq = (freq + adder) >> 1;
            sum_freq += freq;
            self.set_state_freq(s, freq as u8);
            if freq > self.state_freq(s.wrapping_sub(STATE_SIZE)) as u32 {
                // Keep the states sorted by frequency.
                let tmp = self.read_state(s);
                let mut s1 = s;
                loop {
                    self.copy_state(s1, s1.wrapping_sub(STATE_SIZE));
                    s1 = s1.wrapping_sub(STATE_SIZE);
                    if s1 == stats || freq <= self.state_freq(s1.wrapping_sub(STATE_SIZE)) as u32 {
                        break;
                    }
                }
                self.write_state(s1, tmp);
            }
        }

        if self.state_freq(s) == 0 {
            // Drop the states whose frequency fell to zero.
            let mut i = 0u32;
            loop {
                i += 1;
                s = s.wrapping_sub(STATE_SIZE);
                if self.state_freq(s) != 0 {
                    break;
                }
                if i > num_stats {
                    self.corrupt = true;
                    return;
                }
            }
            esc_freq = esc_freq.wrapping_add(i);
            let num_stats_new = num_stats.wrapping_sub(i);
            self.set_ctx_num_stats(mc, num_stats_new as u8);
            let n0 = (num_stats + 2) >> 1;

            if num_stats_new == 0 {
                if esc_freq == 0 {
                    self.corrupt = true;
                    return;
                }
                let freq = (2 * self.state_freq(stats) as u32)
                    .div_ceil(esc_freq)
                    .min((MAX_FREQ / 3) as u32);
                let sym = self.state_symbol(stats);
                let flags =
                    (self.ctx_flags(mc) & FLAG_PREV_HIGH) as u32 + Self::hi_bits_flag3(sym as u32);
                self.set_ctx_flags(mc, flags as u8);
                let single = Self::single_state(mc);
                self.copy_state(single, stats);
                self.set_state_freq(single, freq as u8);
                self.found_state = single;
                let index = self.u2i(n0);
                self.insert_node(stats, index);
                return;
            }

            let n1 = (num_stats_new + 2) >> 1;
            if n0 != n1 {
                let shrunk = self.shrink_units(stats, n0, n1);
                self.set_ctx_stats(mc, shrunk);
            }
        }

        let summ = sum_freq.wrapping_add(esc_freq).wrapping_sub(esc_freq >> 1);
        self.set_ctx_summ_freq(mc, summ as u16);
        let flags = self.ctx_flags(mc) | FLAG_RESCALED;
        self.set_ctx_flags(mc, flags);
        self.found_state = self.ctx_stats(mc);
    }

    fn make_esc_freq(&mut self, num_masked: u32, esc_freq: &mut u32) -> SeeSource {
        let num_stats = self.ctx_num_stats(self.min_context) as u32;
        if num_stats == 0xFF {
            *esc_freq = 1;
            return SeeSource::Dummy;
        }
        let Some((i, k)) = self.calculate_see_table_hash(num_masked, num_stats) else {
            *esc_freq = 1;
            return SeeSource::Dummy;
        };
        let see = &mut self.see[i][k];
        let summ = see.summ as u32;
        let r = summ >> see.shift;
        see.summ = (summ - r) as u16;
        *esc_freq = r + (r == 0) as u32;
        SeeSource::Table(i, k)
    }

    fn calculate_see_table_hash(
        &mut self,
        num_masked: u32,
        num_stats: u32,
    ) -> Option<(usize, usize)> {
        let mc = self.min_context;
        let base = (self.ns2index[(num_stats + 2) as usize] as usize).checked_sub(3);
        let suffix = self.ctx_suffix(mc).get_offset();
        let suffix_num_stats = self.ctx_num_stats(suffix) as u32;
        let summ_freq = self.ctx_summ_freq(mc) as u32;

        let freq_distribution_hash = (summ_freq > 11 * (num_stats + 1)) as usize;
        let context_hierarchy_hash =
            2 * ((2 * num_stats) < (suffix_num_stats + num_masked)) as usize;
        let symbol_characteristics_hash = self.ctx_flags(mc) as usize;
        let hash = freq_distribution_hash + context_hierarchy_hash + symbol_characteristics_hash;

        match base {
            Some(b) if b < self.see.len() && hash < self.see[0].len() => Some((b, hash)),
            _ => {
                self.corrupt = true;
                None
            }
        }
    }

    fn get_see(&mut self, see_source: SeeSource) -> &mut See {
        match see_source {
            SeeSource::Dummy => &mut self.dummy_see,
            SeeSource::Table(i, k) => &mut self.see[i][k],
        }
    }

    fn next_context(&mut self) {
        let successor = self.state_successor(self.found_state);
        if self.order_fall == 0 && self.is_real_context(successor) {
            self.min_context = successor.get_offset();
            self.max_context = self.min_context;
        } else {
            self.update_model();
        }
    }

    fn update1(&mut self) {
        let mut s = self.found_state;
        let freq = self.state_freq(s) as u32 + 4;
        let summ = self.ctx_summ_freq(self.min_context).wrapping_add(4);
        self.set_ctx_summ_freq(self.min_context, summ);
        self.set_state_freq(s, freq as u8);
        let prev = s.wrapping_sub(STATE_SIZE);
        if freq > self.state_freq(prev) as u32 {
            self.swap_states(s, prev);
            s = prev;
            self.found_state = s;
            if freq > MAX_FREQ as u32 {
                self.rescale();
            }
        }
        self.next_context();
    }

    fn update1_0(&mut self) {
        let s = self.found_state;
        let mc = self.min_context;
        let freq = self.state_freq(s) as u32;
        let summ_freq = self.ctx_summ_freq(mc) as u32;
        // `>=` here, where PPMd7 has `>`.
        self.prev_success = (2 * freq >= summ_freq) as u32;
        self.run_length = self.run_length.wrapping_add(self.prev_success as i32);
        self.set_ctx_summ_freq(mc, summ_freq.wrapping_add(4) as u16);
        let freq = freq + 4;
        self.set_state_freq(s, freq as u8);
        if freq > MAX_FREQ as u32 {
            self.rescale();
        }
        self.next_context();
    }

    fn update2(&mut self) {
        let s = self.found_state;
        let freq = self.state_freq(s) as u32 + 4;
        self.run_length = self.init_rl;
        let summ = self.ctx_summ_freq(self.min_context).wrapping_add(4);
        self.set_ctx_summ_freq(self.min_context, summ);
        self.set_state_freq(s, freq as u8);
        if freq > MAX_FREQ as u32 {
            self.rescale();
        }
        self.update_model();
    }

    fn update_bin(&mut self, s: u32) -> u8 {
        let freq = self.state_freq(s);
        let sym = self.state_symbol(s);
        self.found_state = s;
        self.prev_success = 1;
        self.run_length = self.run_length.wrapping_add(1);
        self.set_state_freq(s, freq.wrapping_add((freq < 196) as u8));
        self.next_context();
        sym
    }

    /// Masks the symbol of `s` and every state from `s2` up to `s`, in pairs
    /// as upstream does.
    fn mask_symbols(&mut self, char_mask: &mut [u8; 256], s: u32, mut s2: u32) {
        let sym = self.state_symbol(s) as usize;
        char_mask[sym] = 0;
        for _ in 0..128 {
            let sym0 = self.state_symbol(s2) as usize;
            let sym1 = self.state_symbol(s2.wrapping_add(STATE_SIZE)) as usize;
            s2 = s2.wrapping_add(2 * STATE_SIZE);
            char_mask[sym0] = 0;
            char_mask[sym1] = 0;
            if s2 >= s {
                return;
            }
        }
        self.corrupt = true;
    }

    const fn hi_bits_prepare(flag: u32) -> u32 {
        flag + 0xC0
    }
    const fn hi_bits_convert_3(flag: u32) -> u32 {
        (flag >> (8 - 3)) & (1 << 3)
    }
    const fn hi_bits_convert_4(flag: u32) -> u32 {
        (flag >> (8 - 4)) & (1 << 4)
    }
    const fn hi_bits_flag3(symbol: u32) -> u32 {
        Self::hi_bits_convert_3(Self::hi_bits_prepare(symbol))
    }
    const fn hi_bits_flag4(symbol: u32) -> u32 {
        Self::hi_bits_convert_4(Self::hi_bits_prepare(symbol))
    }

    /// The `bin_summ` cell of the current binary context, as indices so the
    /// caller can then borrow the range decoder.
    fn get_bin_summ(&mut self) -> Option<(usize, usize)> {
        let mc = self.min_context;
        let freq = self.state_freq(Self::single_state(mc)) as usize;
        let suffix = self.ctx_suffix(mc).get_offset();
        let suffix_num_stats = self.ctx_num_stats(suffix) as usize;
        let flags = self.ctx_flags(mc) as u32;
        let row = freq
            .checked_sub(1)
            .map(|f| self.ns2index[f] as usize)
            .filter(|&r| r < self.bin_summ.len());
        let col = self
            .prev_success
            .wrapping_add((self.run_length as u32 >> 26) & 0x20)
            .wrapping_add(self.ns2bs_index[suffix_num_stats] as u32)
            .wrapping_add(flags) as usize;
        match row {
            Some(r) if col < self.bin_summ[0].len() => Some((r, col)),
            _ => {
                self.corrupt = true;
                None
            }
        }
    }

    /// `sum` capped at the current range, as upstream's `correct_sum_range`:
    /// keeps the range decoder's division well-defined.
    fn correct_sum_range(&self, sum: u32) -> u32 {
        sum.min(self.rc.range())
    }

    /// Decodes the next symbol: a byte in `0..=255`, [`SYM_END`] for the end
    /// marker, or [`SYM_ERROR`] on an inconsistent stream, a damaged model or
    /// input that ran out.
    pub(crate) fn decode_symbol(&mut self) -> i32 {
        if self.rc.out_of_data() || self.corrupt {
            return SYM_ERROR;
        }
        let mut char_mask: [u8; 256];
        let mc = self.min_context;

        if self.ctx_num_stats(mc) != 0 {
            let mut s = self.ctx_stats(mc);
            let summ_freq = self.ctx_summ_freq(mc) as u32;
            let summ_freq = self.correct_sum_range(summ_freq);
            if summ_freq == 0 {
                return SYM_ERROR;
            }
            let mut count = self.rc.get_threshold(summ_freq);
            let hi_cnt = count;

            let freq = self.state_freq(s) as u32;
            count = count.wrapping_sub(freq);
            if (count as i32) < 0 {
                self.rc.decode(0, freq);
                self.found_state = s;
                let sym = self.state_symbol(s);
                self.update1_0();
                return self.finish_symbol(sym);
            }

            self.prev_success = 0;
            let num_stats = self.ctx_num_stats(mc);
            for _ in 0..num_stats {
                s = s.wrapping_add(STATE_SIZE);
                let freq = self.state_freq(s) as u32;
                count = count.wrapping_sub(freq);
                if (count as i32) < 0 {
                    self.rc
                        .decode(hi_cnt.wrapping_sub(count).wrapping_sub(freq), freq);
                    self.found_state = s;
                    let sym = self.state_symbol(s);
                    self.update1();
                    return self.finish_symbol(sym);
                }
            }

            if hi_cnt >= summ_freq {
                return SYM_ERROR;
            }
            let hi_cnt = hi_cnt.wrapping_sub(count);
            self.rc.decode(hi_cnt, summ_freq.wrapping_sub(hi_cnt));

            char_mask = [u8::MAX; 256];
            let s2 = self.ctx_stats(mc);
            self.mask_symbols(&mut char_mask, s, s2);
        } else {
            let s = Self::single_state(mc);
            let Some((r, c)) = self.get_bin_summ() else {
                return SYM_ERROR;
            };
            let pr = self.bin_summ[r][c] as u32;
            let bit = self.rc.decode_bit(pr);
            let pr = ppmd_update_prob_1(pr);
            if bit == 0 {
                self.bin_summ[r][c] = (pr + (1 << PPMD_INT_BITS)) as u16;
                let sym = self.update_bin(s);
                return self.finish_symbol(sym);
            }
            self.bin_summ[r][c] = pr as u16;
            let Some(&esc) = K_EXP_ESCAPE.get((pr >> 10) as usize) else {
                return SYM_ERROR;
            };
            self.init_esc = esc as u32;

            char_mask = [u8::MAX; 256];
            let sym = self.state_symbol(s) as usize;
            char_mask[sym] = 0;
            self.prev_success = 0;
        }

        // Each escape moves at least one context up the suffix chain.
        let mut steps = 0;
        loop {
            if self.rc.out_of_data() || self.corrupt {
                return SYM_ERROR;
            }
            let mut mc = self.min_context;
            let num_masked = self.ctx_num_stats(mc) as u32;

            loop {
                steps += 1;
                if steps > CHAIN_LIMIT {
                    return SYM_ERROR;
                }
                self.order_fall += 1;
                let suffix = self.ctx_suffix(mc);
                if suffix.is_null() {
                    return SYM_END;
                }
                mc = suffix.get_offset();
                if self.ctx_num_stats(mc) as u32 != num_masked {
                    break;
                }
            }

            let num_stats = self.ctx_num_stats(mc) as u32;
            if num_stats == 0 {
                return SYM_ERROR;
            }
            let mut s = self.ctx_stats(mc);
            let num = num_stats + 1;
            let odd = num & 1;
            let mut hi_cnt = self.state_freq(s) as u32
                & char_mask[self.state_symbol(s) as usize] as u32
                & 0u32.wrapping_sub(odd);
            s = s.wrapping_add(odd * STATE_SIZE);
            self.min_context = mc;

            for _ in 0..num / 2 {
                let sym0 = self.state_symbol(s) as usize;
                let sym1 = self.state_symbol(s.wrapping_add(STATE_SIZE)) as usize;
                hi_cnt += (self.state_freq(s) & char_mask[sym0]) as u32;
                hi_cnt += (self.state_freq(s.wrapping_add(STATE_SIZE)) & char_mask[sym1]) as u32;
                s = s.wrapping_add(2 * STATE_SIZE);
            }

            let mut freq_sum = 0;
            let see_source = self.make_esc_freq(num_masked, &mut freq_sum);
            freq_sum += hi_cnt;
            let freq_sum2 = self.correct_sum_range(freq_sum);
            if freq_sum2 == 0 {
                return SYM_ERROR;
            }

            let mut count = self.rc.get_threshold(freq_sum2);

            if count < hi_cnt {
                s = self.ctx_stats(self.min_context);
                let hi_cnt = count;
                let mut found = false;
                for _ in 0..num {
                    let f = self.state_freq(s) & char_mask[self.state_symbol(s) as usize];
                    count = count.wrapping_sub(f as u32);
                    s = s.wrapping_add(STATE_SIZE);
                    if (count as i32) < 0 {
                        found = true;
                        break;
                    }
                }
                if !found {
                    return SYM_ERROR;
                }
                s = s.wrapping_sub(STATE_SIZE);
                let freq = self.state_freq(s) as u32;
                self.rc
                    .decode(hi_cnt.wrapping_sub(count).wrapping_sub(freq), freq);

                self.get_see(see_source).update();
                self.found_state = s;
                let sym = self.state_symbol(s);
                self.update2();
                return self.finish_symbol(sym);
            }

            if count >= freq_sum2 {
                return SYM_ERROR;
            }

            self.rc.decode(hi_cnt, freq_sum2 - hi_cnt);
            // Upstream adds the uncapped sum; `summ` may wrap.
            let see = self.get_see(see_source);
            see.summ = (see.summ as u32).wrapping_add(freq_sum) as u16;

            s = self.ctx_stats(self.min_context);
            for _ in 0..num {
                let sym = self.state_symbol(s) as usize;
                char_mask[sym] = 0;
                s = s.wrapping_add(STATE_SIZE);
            }
        }
    }

    /// `sym`, unless the model went out of bounds while updating.
    fn finish_symbol(&self, sym: u8) -> i32 {
        if self.corrupt {
            SYM_ERROR
        } else {
            sym as i32
        }
    }
}
