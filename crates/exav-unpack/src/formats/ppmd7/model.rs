//! PPMd7 (var.H) model, vendored from `ppmd-rust` 1.4.0 (CC0-1.0 OR MIT-0) and
//! generalised over the [`RangeDec`] trait so it can be driven by either the 7z
//! or the RAR range coder. The model logic (suballocator, context tree, SEE,
//! rescale, update) is unchanged from upstream; only `decode_symbol` is
//! rewritten to use the trait's three range-coder operations instead of the
//! upstream 7z-specific range/code field accesses. Not derived from UnRAR.
//!
//! # 100% safe-Rust arena
//!
//! Upstream `ppmd-rust` (like the C original) addresses the PPMd sub-allocator
//! through raw pointers into a single heap allocation. This port replaces that
//! with a **bounds-checked `Vec<u8>` arena** addressed by `u32` byte offsets
//! ([`TaggedOffset`]). Every node field is read/written through the
//! little-endian `rd_*` / `wr_*` accessors below, which validate the offset
//! against the arena length; an out-of-range access (only reachable on
//! malformed input) sets the `corrupt` flag and yields `0`, and the symbol
//! decoder turns `corrupt` into [`SYM_ERROR`] instead of panicking. The
//! in-arena byte layout is identical to the previous `#[repr(C, packed)]`
//! structs, so the decode is byte-exact with the pointer version.
#![allow(clippy::all)]

use super::tagged_offset::TaggedOffset;
use super::{RangeDec, SYM_END, SYM_ERROR};

// ---- shared PPMd constants (from ppmd-rust internal.rs) -------------------

const PPMD_INT_BITS: u32 = 7;
const PPMD_PERIOD_BITS: u32 = 7;
const PPMD_BIN_SCALE: u32 = 1 << (PPMD_INT_BITS + PPMD_PERIOD_BITS);

const fn ppmd_get_mean_spec(summ: u32, shift: u32, round: u32) -> u32 {
    (summ + (1 << (shift - round))) >> shift
}
const fn ppmd_get_mean(summ: u32) -> u32 {
    ppmd_get_mean_spec(summ, PPMD_PERIOD_BITS, 2)
}
const fn ppmd_update_prob_1(prob: u32) -> u32 {
    prob - ppmd_get_mean(prob)
}

const PPMD_N1: u32 = 4;
const PPMD_N2: u32 = 4;
const PPMD_N3: u32 = 4;
const PPMD_N4: u32 = (128 + 3 - PPMD_N1 - 2 * PPMD_N2 - 3 * PPMD_N3) / 4;
const PPMD_NUM_INDEXES: u32 = PPMD_N1 + PPMD_N2 + PPMD_N3 + PPMD_N4;

enum SeeSource {
    Dummy,
    Table(usize, usize),
}

#[derive(Copy, Clone, Default)]
struct See {
    summ: u16,
    shift: u8,
    count: u8,
}

impl See {
    fn update(&mut self) {
        if (self.shift as i32) < 7 && {
            self.count = self.count.wrapping_sub(1);
            self.count as i32 == 0
        } {
            self.summ = ((self.summ as i32) << 1) as u16;
            let fresh = self.shift;
            self.shift = self.shift.wrapping_add(1);
            self.count = (3 << fresh as i32) as u8;
        }
    }
}

// ---- arena node byte layout ----------------------------------------------
//
// These mirror the previous `#[repr(C, packed)]` structs byte-for-byte. All
// fields are little-endian (the previous code ran on LE targets and stored
// native-endian; the round-trip and gold-CRC tests pin the exact bytes).
//
// State (6 bytes):
//   symbol:u8 @0  freq:u8 @1  successor_0:u16 @2  successor_1:u16 @4
// Context (12 bytes):
//   num_stats:u16 @0
//   union2 @2: summ_freq:u16  | state2{ symbol:u8 @2, freq:u8 @3 }
//   union4 @4: stats:u32      | state4{ successor_0:u16 @4, successor_1:u16 @6 }
//   suffix:u32 @8
// Node (12 bytes):
//   stamp:u16 @0  nu:u16 @2  next:u32 @4  prev:u32 @8
//   (NodeUnion overlays next_ref:u32 @0, i.e. stamp+nu)

const STATE_SIZE: u32 = 6;

const ST_SYMBOL: u32 = 0;
const ST_FREQ: u32 = 1;
const ST_SUCC0: u32 = 2;
const ST_SUCC1: u32 = 4;

const CTX_NUM_STATS: u32 = 0;
const CTX_SUMM_FREQ: u32 = 2; // union2 as summ_freq
const CTX_STATE2_SYMBOL: u32 = 2; // union2.state2.symbol
const CTX_STATE2_FREQ: u32 = 3; // union2.state2.freq
const CTX_STATS: u32 = 4; // union4 as stats (u32)
const CTX_STATE4_SUCC0: u32 = 4; // union4.state4.successor_0
const CTX_STATE4_SUCC1: u32 = 6; // union4.state4.successor_1
const CTX_SUFFIX: u32 = 8;

/// Single-state lives in the Context's `union2`/`union4` overlay; its `State`
/// view starts at the union2 byte offset (`+2`) within the context.
const CTX_SINGLE_STATE: u32 = 2;

const NODE_STAMP: u32 = 0;
const NODE_NU: u32 = 2;
const NODE_NEXT: u32 = 4;
#[allow(dead_code)]
const NODE_PREV: u32 = 8;
const NODE_NEXT_REF: u32 = 0; // NodeUnion.next_ref overlays stamp+nu

// ---- model constants (from ppmd-rust ppmd7.rs) ----------------------------

const MAX_FREQ: u8 = 124;
const UNIT_SIZE: u32 = 12;
const EMPTY_NODE: u16 = 0;

static K_EXP_ESCAPE: [u8; 16] = [25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2];
static K_INIT_BIN_ESC: [u16; 8] = [
    0x3CDD, 0x1F3F, 0x59BF, 0x48F3, 0x64A1, 0x5ABC, 0x6632, 0x6051,
];

/// The PPMd7 (var.H) model, generic over the range decoder.
///
/// Node "pointers" are `u32` byte offsets into `arena`. `min_context`,
/// `max_context`, `found_state`, `lo_unit`, `hi_unit`, `text` and `units_start`
/// are all such offsets (relative to the start of `arena`, which corresponds to
/// the upstream `base_memory_ptr`).
pub(crate) struct Ppmd7<RC: RangeDec> {
    min_context: u32,
    max_context: u32,
    found_state: u32,
    order_fall: u32,
    init_esc: u32,
    prev_success: u32,
    max_order: u32,
    hi_bits_flag: u32,
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
    free_list: [TaggedOffset; 38],
    ns2bs_index: [u8; 256],
    ns2index: [u8; 256],
    exp_escape: [u8; 16],
    dummy_see: See,
    see: [[See; 16]; 25],
    bin_summ: [[u16; 64]; 128],
    /// The byte arena (sub-allocator backing store). Indexed by `u32` offset.
    arena: Vec<u8>,
    /// Set if any node access ever went out of the arena bounds (only possible
    /// on malformed input). Surfaced as a decode error.
    corrupt: bool,
    rc: RC,
}

impl<RC: RangeDec> Ppmd7<RC> {
    /// Construct the model with `rc` already initialised, `order` in
    /// [PPMD7_MIN_ORDER, PPMD7_MAX_ORDER] and `mem_size` bytes of arena. Returns
    /// `None` on allocation failure.
    pub(crate) fn new(rc: RC, order: u32, mem_size: u32) -> Option<Self> {
        let mut units2index = [0u8; 128];
        let mut index2units = [0u8; 40];

        let mut k = 0;
        for i in 0..PPMD_NUM_INDEXES {
            let step: u32 = if i >= 12 { 4 } else { (i >> 2) + 1 };
            for _ in 0..step {
                units2index[k as usize] = i as u8;
                k += 1;
            }
            index2units[i as usize] = k as u8;
        }

        let mut ns2bs_index = [0u8; 256];
        ns2bs_index[0] = 0;
        ns2bs_index[1] = 2;
        ns2bs_index[2..11].fill(4);
        ns2bs_index[11..256].fill(6);

        let mut ns2index = [0u8; 256];
        for i in 0..3 {
            ns2index[i as usize] = i as u8;
        }
        let mut m = 3;
        let mut k = 1;
        for i in 3..256 {
            ns2index[i as usize] = m as u8;
            k -= 1;
            if k == 0 {
                m += 1;
                k = m - 2;
            }
        }

        let align_offset = (4u32.wrapping_sub(mem_size)) & 3;
        let total_size = (align_offset + mem_size) as usize;
        if total_size == 0 {
            return None;
        }
        // Bounds-checked byte arena. Zero-initialised, matching `alloc_zeroed`.
        // `try_reserve` keeps allocation failure non-panicking.
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
            hi_bits_flag: 0,
            run_length: 0,
            init_rl: 0,
            size: mem_size,
            glue_count: 0,
            align_offset,
            lo_unit: 0,
            hi_unit: 0,
            text: 0,
            units_start: 0,
            units2index,
            index2units,
            ns2bs_index,
            ns2index,
            exp_escape: K_EXP_ESCAPE,
            dummy_see: See::default(),
            see: [[See::default(); 16]; 25],
            free_list: [TaggedOffset::null(); PPMD_NUM_INDEXES as usize],
            bin_summ: [[0; 64]; 128],
            arena,
            corrupt: false,
            rc,
        };

        ppmd.restart_model();
        Some(ppmd)
    }

    // ---- bounds-checked little-endian arena accessors --------------------
    //
    // All node-field reads/writes go through these. An out-of-range access
    // (only reachable on malformed input that drives an offset past the arena)
    // sets `corrupt` and yields 0 / is a no-op, so the decoder can never panic
    // with an index-out-of-bounds and never reads/writes foreign memory.

    #[inline(always)]
    fn rd_u8(&mut self, off: u32) -> u8 {
        match self.arena.get(off as usize) {
            Some(&b) => b,
            None => {
                self.corrupt = true;
                0
            }
        }
    }

    #[inline(always)]
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

    #[inline(always)]
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

    #[inline(always)]
    fn wr_u8(&mut self, off: u32, v: u8) {
        match self.arena.get_mut(off as usize) {
            Some(b) => *b = v,
            None => self.corrupt = true,
        }
    }

    #[inline(always)]
    fn wr_u16(&mut self, off: u32, v: u16) {
        let o = off as usize;
        match self.arena.get_mut(o..o + 2) {
            Some(s) => s.copy_from_slice(&v.to_le_bytes()),
            None => self.corrupt = true,
        }
    }

    #[inline(always)]
    fn wr_u32(&mut self, off: u32, v: u32) {
        let o = off as usize;
        match self.arena.get_mut(o..o + 4) {
            Some(s) => s.copy_from_slice(&v.to_le_bytes()),
            None => self.corrupt = true,
        }
    }

    /// Copy `len` bytes within the arena, `src..src+len` -> `dst..dst+len`.
    /// Out-of-range is a no-op that flags corruption.
    #[inline]
    fn arena_copy(&mut self, dst: u32, src: u32, len: u32) {
        let (d, s, l) = (dst as usize, src as usize, len as usize);
        if d.checked_add(l).map_or(true, |e| e > self.arena.len())
            || s.checked_add(l).map_or(true, |e| e > self.arena.len())
        {
            self.corrupt = true;
            return;
        }
        self.arena.copy_within(s..s + l, d);
    }

    // ---- typed node field accessors --------------------------------------

    #[inline(always)]
    fn state_symbol(&mut self, s: u32) -> u8 {
        self.rd_u8(s + ST_SYMBOL)
    }
    #[inline(always)]
    fn set_state_symbol(&mut self, s: u32, v: u8) {
        self.wr_u8(s + ST_SYMBOL, v)
    }
    #[inline(always)]
    fn state_freq(&mut self, s: u32) -> u8 {
        self.rd_u8(s + ST_FREQ)
    }
    #[inline(always)]
    fn set_state_freq(&mut self, s: u32, v: u8) {
        self.wr_u8(s + ST_FREQ, v)
    }
    #[inline(always)]
    fn state_successor(&mut self, s: u32) -> TaggedOffset {
        let lo = self.rd_u16(s + ST_SUCC0) as u32;
        let hi = self.rd_u16(s + ST_SUCC1) as u32;
        TaggedOffset::from_raw(lo + (hi << 16))
    }
    #[inline(always)]
    fn set_state_successor(&mut self, s: u32, v: TaggedOffset) {
        let raw = v.as_raw();
        self.wr_u16(s + ST_SUCC0, raw as u16);
        self.wr_u16(s + ST_SUCC1, (raw >> 16) as u16);
    }

    /// Copy a whole 6-byte State node `src` -> `dst`.
    #[inline(always)]
    fn copy_state(&mut self, dst: u32, src: u32) {
        self.arena_copy(dst, src, STATE_SIZE);
    }

    #[inline(always)]
    fn ctx_num_stats(&mut self, c: u32) -> u16 {
        self.rd_u16(c + CTX_NUM_STATS)
    }
    #[inline(always)]
    fn set_ctx_num_stats(&mut self, c: u32, v: u16) {
        self.wr_u16(c + CTX_NUM_STATS, v)
    }
    #[inline(always)]
    fn ctx_summ_freq(&mut self, c: u32) -> u16 {
        self.rd_u16(c + CTX_SUMM_FREQ)
    }
    #[inline(always)]
    fn set_ctx_summ_freq(&mut self, c: u32, v: u16) {
        self.wr_u16(c + CTX_SUMM_FREQ, v)
    }
    #[inline(always)]
    fn ctx_state2_symbol(&mut self, c: u32) -> u8 {
        self.rd_u8(c + CTX_STATE2_SYMBOL)
    }
    #[inline(always)]
    fn ctx_state2_freq(&mut self, c: u32) -> u8 {
        self.rd_u8(c + CTX_STATE2_FREQ)
    }
    #[inline(always)]
    fn ctx_stats(&mut self, c: u32) -> TaggedOffset {
        TaggedOffset::from_raw(self.rd_u32(c + CTX_STATS))
    }
    #[inline(always)]
    fn set_ctx_stats(&mut self, c: u32, v: TaggedOffset) {
        self.wr_u32(c + CTX_STATS, v.as_raw())
    }
    /// `union4.state4.get_successor()` — overlay of the single-state successor.
    #[inline(always)]
    fn ctx_state4_successor(&mut self, c: u32) -> TaggedOffset {
        let lo = self.rd_u16(c + CTX_STATE4_SUCC0) as u32;
        let hi = self.rd_u16(c + CTX_STATE4_SUCC1) as u32;
        TaggedOffset::from_raw(lo + (hi << 16))
    }
    #[inline(always)]
    fn ctx_suffix(&mut self, c: u32) -> TaggedOffset {
        TaggedOffset::from_raw(self.rd_u32(c + CTX_SUFFIX))
    }
    #[inline(always)]
    fn set_ctx_suffix(&mut self, c: u32, v: TaggedOffset) {
        self.wr_u32(c + CTX_SUFFIX, v.as_raw())
    }

    // ---- sub-allocator ----------------------------------------------------

    fn insert_node(&mut self, node: u32, indx: u32) {
        // node viewed as a NodeUnion: write its next_ref (u32 @0) to the
        // current free-list head, then push `node` as the new head.
        let head = self.free_list[indx as usize];
        self.wr_u32(node + NODE_NEXT_REF, head.as_raw());
        self.free_list[indx as usize] = TaggedOffset::from_raw(node);
    }

    fn remove_node(&mut self, indx: u32) -> u32 {
        let node = self.free_list[indx as usize].as_raw();
        let next = self.rd_u32(node + NODE_NEXT_REF);
        self.free_list[indx as usize] = TaggedOffset::from_raw(next);
        node
    }

    fn split_block(&mut self, ptr: u32, old_index: u32, new_index: u32) {
        let nu = (self.index2units[old_index as usize] as u32)
            - (self.index2units[new_index as usize] as u32);
        let ptr = ptr + self.index2units[new_index as usize] as u32 * UNIT_SIZE;
        let mut i = self.units2index[(nu as usize) - 1] as u32;
        if self.index2units[i as usize] as u32 != nu {
            i -= 1;
            let k = self.index2units[i as usize] as u32;
            self.insert_node(ptr + k * UNIT_SIZE, nu - k - 1);
        }
        self.insert_node(ptr, i);
    }

    fn glue_free_blocks(&mut self) {
        let mut n = TaggedOffset::null();
        self.glue_count = 255;
        if self.lo_unit != self.hi_unit {
            self.wr_u16(self.lo_unit + NODE_STAMP, 1);
        }
        let mut i = 0;
        while i < PPMD_NUM_INDEXES {
            let nu = self.index2units[i as usize] as u16;
            let mut next = self.free_list[i as usize];
            self.free_list[i as usize] = TaggedOffset::null();
            while next.is_not_null() {
                let node = next.as_raw();
                // un = node as NodeUnion. tmp = next; next = un.next_ref;
                let tmp = next;
                next = TaggedOffset::from_raw(self.rd_u32(node + NODE_NEXT_REF));
                self.wr_u16(node + NODE_STAMP, EMPTY_NODE);
                self.wr_u16(node + NODE_NU, nu);
                self.wr_u32(node + NODE_NEXT, n.as_raw());
                n = tmp;
            }
            i += 1;
        }
        let mut head = n;
        self.glue_blocks(n, &mut head);
        self.fill_list(head);
    }

    fn glue_blocks(&mut self, mut n: TaggedOffset, head: &mut TaggedOffset) {
        // `prev` is the location (a node offset + field offset, or the `head`
        // local) whose `next` pointer we'll rewrite. We track it as an enum so
        // the assignment `*prev = n` is well-defined in safe code.
        enum Prev {
            Head,
            NodeNext(u32),
        }
        let mut prev = Prev::Head;
        while n.is_not_null() {
            let node = n.as_raw();
            let mut nu = self.rd_u16(node + NODE_NU) as u32;
            n = TaggedOffset::from_raw(self.rd_u32(node + NODE_NEXT));
            if nu == 0 {
                match prev {
                    Prev::Head => *head = n,
                    Prev::NodeNext(off) => self.wr_u32(off, n.as_raw()),
                }
            } else {
                prev = Prev::NodeNext(node + NODE_NEXT);
                loop {
                    let node2 = node + nu * UNIT_SIZE;
                    let node2_nu = self.rd_u16(node2 + NODE_NU) as u32;
                    nu += node2_nu;
                    let node2_stamp = self.rd_u16(node2 + NODE_STAMP);
                    if node2_stamp != EMPTY_NODE || nu >= 0x10000 {
                        break;
                    }
                    self.wr_u16(node + NODE_NU, nu as u16);
                    self.wr_u16(node2 + NODE_NU, 0);
                }
            }
        }
    }

    fn fill_list(&mut self, head: TaggedOffset) {
        let mut n = head;
        while n.is_not_null() {
            let mut node = n.as_raw();
            let mut nu = self.rd_u16(node + NODE_NU) as u32;
            n = TaggedOffset::from_raw(self.rd_u32(node + NODE_NEXT));
            if nu == 0 {
                continue;
            }
            while nu > 128 {
                self.insert_node(node, PPMD_NUM_INDEXES - 1);
                nu -= 128;
                node += 128 * UNIT_SIZE;
            }
            let mut index = self.units2index[(nu as usize) - 1] as u32;
            if self.index2units[index as usize] as u32 != nu {
                index -= 1;
                let k = self.index2units[index as usize] as u32;
                self.insert_node(node + k * UNIT_SIZE, nu - k - 1);
            }
            self.insert_node(node, index);
        }
    }

    #[inline(never)]
    fn alloc_units_rare(&mut self, index: u32) -> Option<u32> {
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
                let num_bytes = self.index2units[index as usize] as u32 * UNIT_SIZE;
                let us = self.units_start;
                self.glue_count -= 1;
                return if us - self.text > num_bytes {
                    self.units_start = us - num_bytes;
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
        if self.free_list[index as usize].is_not_null() {
            return Some(self.remove_node(index));
        }
        let num_bytes = self.index2units[index as usize] as u32 * UNIT_SIZE;
        let lo = self.lo_unit;
        if self.hi_unit - lo >= num_bytes {
            self.lo_unit = lo + num_bytes;
            return Some(lo);
        }
        self.alloc_units_rare(index)
    }

    #[inline(never)]
    fn restart_model(&mut self) {
        self.free_list = [TaggedOffset::null(); 38];
        self.text = self.align_offset;
        self.hi_unit = self.text + self.size;
        self.units_start = self.hi_unit - (self.size / 8 / UNIT_SIZE * 7 * UNIT_SIZE);
        self.lo_unit = self.units_start;
        self.glue_count = 0;

        self.order_fall = self.max_order;
        self.init_rl = -(if self.max_order < 12 {
            self.max_order as i32
        } else {
            12
        }) - 1;
        self.run_length = self.init_rl;
        self.prev_success = 0;

        self.hi_unit -= UNIT_SIZE;
        let mc = self.hi_unit;
        let s = self.lo_unit;
        self.lo_unit += (256 / 2) * UNIT_SIZE;
        self.min_context = mc;
        self.max_context = mc;
        self.found_state = s;

        self.set_ctx_num_stats(mc, 256);
        self.set_ctx_summ_freq(mc, (256 + 1) as u16);
        self.set_ctx_stats(mc, TaggedOffset::from_raw(s));
        self.set_ctx_suffix(mc, TaggedOffset::null());

        for i in 0..256u32 {
            let st = s + i * STATE_SIZE;
            self.set_state_symbol(st, i as u8);
            self.set_state_freq(st, 1);
            self.set_state_successor(st, TaggedOffset::null());
        }

        (0..128).for_each(|i| {
            (0..8).for_each(|k| {
                let val = PPMD_BIN_SCALE - (K_INIT_BIN_ESC[k] as u32) / (i as u32 + 2);
                (0..64).step_by(8).for_each(|m| {
                    self.bin_summ[i][k + m] = val as u16;
                });
            });
        });

        (0..25).for_each(|i| {
            let summ = (5 * i as u32 + 10) << (PPMD_PERIOD_BITS - 4);
            (0..16).for_each(|k| {
                let s = &mut self.see[i][k];
                s.summ = summ as u16;
                s.shift = (PPMD_PERIOD_BITS - 4) as u8;
                s.count = 4;
            });
        });

        self.dummy_see.summ = 0;
        self.dummy_see.shift = PPMD_PERIOD_BITS as u8;
        self.dummy_see.count = 64;
    }

    #[inline(never)]
    fn create_successors(&mut self) -> Option<u32> {
        let mut c = self.min_context;
        let up_branch = self.state_successor(self.found_state);
        let mut num_ps = 0usize;
        let mut ps: [u32; 64] = [0; 64];

        if self.order_fall != 0 {
            ps[num_ps] = self.found_state;
            num_ps += 1;
        }

        while self.ctx_suffix(c).is_not_null() {
            let mut s;
            c = self.ctx_suffix(c).get_offset();
            if self.ctx_num_stats(c) != 1 {
                let sym = self.state_symbol(self.found_state);
                s = self.get_multi_state_stats(c);
                // Valid input holds `sym` within the context's `num_stats`
                // states; corrupt input may not — bound the scan so `s` can't run
                // off the arena and overflow the u32 offset.
                let ns = self.ctx_num_stats(c) as usize;
                let mut steps = 0usize;
                while self.state_symbol(s) != sym {
                    s += STATE_SIZE;
                    steps += 1;
                    if steps >= ns {
                        self.corrupt = true;
                        return None;
                    }
                }
            } else {
                s = self.get_single_state(c);
            }
            let successor = self.state_successor(s);
            if successor != up_branch {
                c = successor.get_offset();
                if num_ps == 0 {
                    return Some(c);
                }
                break;
            } else {
                if num_ps >= ps.len() {
                    // Valid suffix chains are <= max_order (<= 64) deep; a corrupt
                    // or cyclic chain must not overrun the fixed `ps` array.
                    self.corrupt = true;
                    return None;
                }
                ps[num_ps] = s;
                num_ps += 1;
            }
        }

        let new_sym = self.rd_u8(up_branch.get_offset());
        let new_offset = up_branch.get_offset() + 1;
        let up_branch = TaggedOffset::from_bytes_offset(new_offset);

        let new_freq = if self.ctx_num_stats(c) == 1 {
            self.state_freq(self.get_single_state(c))
        } else {
            let mut s = self.get_multi_state_stats(c);
            let ns = self.ctx_num_stats(c) as usize;
            let mut steps = 0usize;
            while self.state_symbol(s) != new_sym {
                s += STATE_SIZE;
                steps += 1;
                if steps >= ns {
                    self.corrupt = true;
                    return None;
                }
            }
            // saturating: valid input keeps freq >= 1 and summ_freq >= num_stats + cf.
            let cf = (self.state_freq(s) as u32).saturating_sub(1);
            let s0 = (self.ctx_summ_freq(c) as u32)
                .saturating_sub(self.ctx_num_stats(c) as u32)
                .saturating_sub(cf);
            1 + (if 2 * cf <= s0 {
                (5 * cf > s0) as u32
            } else {
                ((2 * cf + s0 - 1) / (2 * s0)) + 1
            }) as u8
        };

        loop {
            let c1: u32 = if self.hi_unit != self.lo_unit {
                self.hi_unit -= UNIT_SIZE;
                self.hi_unit
            } else if self.free_list[0].is_not_null() {
                self.remove_node(0)
            } else {
                self.alloc_units_rare(0)?
            };
            self.set_ctx_num_stats(c1, 1);
            let state = self.get_single_state(c1);
            self.set_state_symbol(state, new_sym);
            self.set_state_freq(state, new_freq);
            self.set_state_successor(state, up_branch);
            self.set_ctx_suffix(c1, TaggedOffset::from_raw(c));
            num_ps -= 1;
            let successor = ps[num_ps];
            self.set_state_successor(successor, TaggedOffset::from_raw(c1));
            c = c1;
            if num_ps == 0 {
                break;
            }
        }
        Some(c)
    }

    #[inline(never)]
    fn update_model(&mut self) {
        let mut c: u32;
        let mc = self.min_context;

        if self.state_freq(self.found_state) < MAX_FREQ / 4 && self.ctx_suffix(mc).is_not_null() {
            c = self.ctx_suffix(mc).get_offset();
            if self.ctx_num_stats(c) == 1 {
                let s = self.get_single_state(c);
                if self.state_freq(s) < 32 {
                    let f = self.state_freq(s);
                    self.set_state_freq(s, f + 1);
                }
            } else {
                let mut s = self.get_multi_state_stats(c);
                let sym = self.state_symbol(self.found_state);
                if self.state_symbol(s) != sym {
                    let ns = self.ctx_num_stats(c) as usize;
                    let mut steps = 0usize;
                    while self.state_symbol(s) != sym {
                        s += STATE_SIZE;
                        steps += 1;
                        if steps >= ns {
                            self.corrupt = true;
                            return;
                        }
                    }
                    if self.state_freq(s) >= self.state_freq(s - STATE_SIZE) {
                        self.swap_states(s);
                        s -= STATE_SIZE;
                    }
                }
                if self.state_freq(s) < MAX_FREQ - 9 {
                    let f = self.state_freq(s);
                    self.set_state_freq(s, f + 2);
                    let sf = self.ctx_summ_freq(c);
                    self.set_ctx_summ_freq(c, sf + 2);
                }
            }
        }

        if self.order_fall == 0 {
            match self.create_successors() {
                None => {
                    self.restart_model();
                    return;
                }
                Some(mc) => {
                    self.min_context = mc;
                    self.max_context = mc;
                }
            }
            let fs = self.found_state;
            self.set_state_successor(fs, TaggedOffset::from_raw(self.min_context));
            return;
        }

        let sym = self.state_symbol(self.found_state);
        self.wr_u8(self.text, sym);
        self.text += 1;
        if self.text >= self.units_start {
            self.restart_model();
            return;
        }
        let mut max_successor = TaggedOffset::from_raw(self.text);
        let mut min_successor = self.state_successor(self.found_state);

        if min_successor.is_null() {
            self.set_state_successor(self.found_state, max_successor);
            min_successor = TaggedOffset::from_raw(self.min_context);
        } else {
            if min_successor.get_offset() <= max_successor.get_offset() {
                match self.create_successors() {
                    None => {
                        self.restart_model();
                        return;
                    }
                    Some(context) => {
                        min_successor = TaggedOffset::from_raw(context);
                    }
                }
            }
            self.order_fall -= 1;
            if self.order_fall == 0 {
                max_successor = min_successor;
                self.text -= (self.max_context != self.min_context) as u32;
            }
        }

        let mc = self.min_context;
        c = self.max_context;
        self.min_context = min_successor.get_offset();
        self.max_context = self.min_context;
        if c == mc {
            return;
        }

        let ns = self.ctx_num_stats(mc) as u32;
        let s0 = (self.ctx_summ_freq(mc) as u32) - ns - ((self.state_freq(self.found_state) as u32) - 1);

        while c != mc {
            let mut sum;
            let ns1 = self.ctx_num_stats(c) as u32;
            if ns1 != 1 {
                if ns1 & 1 == 0 {
                    let old_nu = ns1 >> 1;
                    let i = self.units2index[(old_nu as usize) - 1] as u32;
                    if i != self.units2index[old_nu as usize] as u32 {
                        let Some(ptr) = self.alloc_units(i + 1) else {
                            self.restart_model();
                            return;
                        };
                        let old_ptr = self.get_multi_state_stats(c);
                        self.arena_copy(ptr, old_ptr, old_nu * UNIT_SIZE);
                        self.insert_node(old_ptr, i);
                        self.set_ctx_stats(c, TaggedOffset::from_raw(ptr));
                    }
                }
                sum = self.ctx_summ_freq(c) as u32;
                sum += ((2 * (ns1) < ns) as u32)
                    + 2 * ((4 * (ns1) <= ns) as u32 & (sum <= (8 * (ns1))) as u32);
            } else {
                let Some(s_ptr) = self.alloc_units(0) else {
                    self.restart_model();
                    return;
                };
                let s = s_ptr;
                let mut freq = self.ctx_state2_freq(c) as u32;
                let sym = self.ctx_state2_symbol(c);
                self.set_state_symbol(s, sym);
                let succ = self.ctx_state4_successor(c);
                self.set_state_successor(s, succ);
                self.set_ctx_stats(c, TaggedOffset::from_raw(s));
                if freq < (MAX_FREQ / 4 - 1) as u32 {
                    freq <<= 1;
                } else {
                    freq = (MAX_FREQ - 4) as u32;
                }
                self.set_state_freq(s, freq as u8);
                sum = freq + self.init_esc + ((ns > 3) as u32);
            }

            let s = self.get_multi_state_stats(c) + ns1 * STATE_SIZE;
            let mut cf = 2 * (sum + 6) * self.state_freq(self.found_state) as u32;
            let sf = s0 + sum;
            let fsym = self.state_symbol(self.found_state);
            self.set_state_symbol(s, fsym);
            self.set_ctx_num_stats(c, (ns1 + 1) as u16);
            self.set_state_successor(s, max_successor);
            if cf < 6 * sf {
                cf = 1 + ((cf > sf) as u32) + ((cf >= 4 * sf) as u32);
                sum += 3;
            } else {
                cf = 4
                    + ((cf >= 9 * sf) as u32)
                    + ((cf >= 12 * sf) as u32)
                    + ((cf >= 15 * sf) as u32);
                sum += cf;
            }
            self.set_ctx_summ_freq(c, sum as u16);
            self.set_state_freq(s, cf as u8);
            c = self.ctx_suffix(c).get_offset();
        }
    }

    /// Swap State node `s` with the node before it (`s-STATE_SIZE`).
    fn swap_states(&mut self, s: u32) {
        let a = s;
        let b = s - STATE_SIZE;
        // Swap two 6-byte State records via a temporary.
        let mut tmp = [0u8; STATE_SIZE as usize];
        for j in 0..STATE_SIZE {
            tmp[j as usize] = self.rd_u8(a + j);
        }
        for j in 0..STATE_SIZE {
            let v = self.rd_u8(b + j);
            self.wr_u8(a + j, v);
        }
        for j in 0..STATE_SIZE {
            self.wr_u8(b + j, tmp[j as usize]);
        }
    }

    #[inline(never)]
    fn rescale(&mut self) {
        let stats = self.get_multi_state_stats(self.min_context);
        let mut s = self.found_state;
        if s != stats {
            // Shift the found_state record down to the front (insertion move).
            let mut tmp = [0u8; STATE_SIZE as usize];
            for j in 0..STATE_SIZE {
                tmp[j as usize] = self.rd_u8(s + j);
            }
            while s != stats {
                self.copy_state(s, s - STATE_SIZE);
                s -= STATE_SIZE;
            }
            for j in 0..STATE_SIZE {
                self.wr_u8(s + j, tmp[j as usize]);
            }
        }

        let mut sum_freq = self.state_freq(s) as u32;
        let mut esc_freq = (self.ctx_summ_freq(self.min_context) as u32) - sum_freq;
        let adder = (self.order_fall != 0) as u32;
        sum_freq = (sum_freq + 4 + adder) >> 1;
        let mut i = (self.ctx_num_stats(self.min_context) as u32) - 1;
        self.set_state_freq(s, sum_freq as u8);

        for _ in 0..i {
            s += STATE_SIZE;
            let mut freq = self.state_freq(s) as u32;
            esc_freq -= freq;
            freq = (freq + adder) >> 1;
            sum_freq += freq;
            self.set_state_freq(s, freq as u8);
            if freq > self.state_freq(s - STATE_SIZE) as u32 {
                // Bubble the record up while its freq exceeds the predecessor.
                let mut tmp = [0u8; STATE_SIZE as usize];
                for j in 0..STATE_SIZE {
                    tmp[j as usize] = self.rd_u8(s + j);
                }
                let mut s1 = s;
                loop {
                    self.copy_state(s1, s1 - STATE_SIZE);
                    s1 -= STATE_SIZE;
                    if !(s1 != stats && freq > self.state_freq(s1 - STATE_SIZE) as u32) {
                        break;
                    }
                }
                for j in 0..STATE_SIZE {
                    self.wr_u8(s1 + j, tmp[j as usize]);
                }
            }
        }

        if self.state_freq(s) as i32 == 0 {
            i = 0;
            while self.state_freq(s) == 0 {
                i += 1;
                s -= STATE_SIZE;
            }
            esc_freq += i;
            let mc = self.min_context;
            let num_stats = self.ctx_num_stats(mc) as u32;
            let num_stats_new = num_stats.wrapping_sub(i);
            self.set_ctx_num_stats(mc, num_stats_new as u16);
            let n0 = (num_stats + 1) >> 1;

            if num_stats_new == 1 {
                let mut freq = self.state_freq(stats) as u32;
                loop {
                    esc_freq >>= 1;
                    freq = (freq + 1) >> 1;
                    if esc_freq <= 1 {
                        break;
                    }
                }
                s = self.get_single_state(mc);
                self.copy_state(s, stats);
                self.set_state_freq(s, freq as u8);
                self.found_state = s;
                self.insert_node(stats, self.units2index[(n0 as usize) - 1] as u32);
                return;
            }

            let n1 = (num_stats_new + 1) >> 1;
            if n0 != n1 {
                let i0 = self.units2index[(n0 as usize) - 1] as u32;
                let i1 = self.units2index[(n1 as usize) - 1] as u32;
                if i0 != i1 {
                    if self.free_list[i1 as usize].is_not_null() {
                        let ptr = self.remove_node(i1);
                        self.set_ctx_stats(self.min_context, TaggedOffset::from_raw(ptr));
                        self.arena_copy(ptr, stats, n1 * UNIT_SIZE);
                        self.insert_node(stats, i0);
                    } else {
                        self.split_block(stats, i0, i1);
                    }
                }
            }
        }

        let new_summ = (sum_freq + esc_freq - (esc_freq >> 1)) as u16;
        self.set_ctx_summ_freq(self.min_context, new_summ);
        self.found_state = self.get_multi_state_stats(self.min_context);
    }

    fn make_esc_freq(&mut self, num_masked: u32, esc_freq: &mut u32) -> SeeSource {
        let num_stats = self.ctx_num_stats(self.min_context) as u32;
        if num_stats != 256 {
            let (base_context_idx, see_table_hash) =
                self.calculate_see_table_hash(num_masked, num_stats);
            let see = &mut self.see[base_context_idx][see_table_hash];
            let summ = see.summ as u32;
            let r = summ >> see.shift as i32;
            see.summ = (summ - r) as u16;
            *esc_freq = r + (r == 0) as u32;
            SeeSource::Table(base_context_idx, see_table_hash)
        } else {
            *esc_freq = 1;
            SeeSource::Dummy
        }
    }

    fn get_see(&mut self, see_source: SeeSource) -> &mut See {
        match see_source {
            SeeSource::Dummy => &mut self.dummy_see,
            SeeSource::Table(i, k) => &mut self.see[i][k],
        }
    }

    fn calculate_see_table_hash(&mut self, num_masked: u32, num_stats: u32) -> (usize, usize) {
        // Valid input keeps num_masked < num_stats <= ns2index.len(); corrupt input
        // can break this, underflowing `non_masked`/the `-1` or overrunning ns2index.
        if num_masked >= num_stats || num_stats as usize > self.ns2index.len() {
            self.corrupt = true;
            return (0, 0);
        }
        let non_masked = num_stats - num_masked;
        let base_context_idx = self.ns2index[(non_masked as usize) - 1] as usize;
        let suffix_context = self.ctx_suffix(self.min_context).get_offset();
        let suffix_num_stats = self.ctx_num_stats(suffix_context) as u32;
        let summ_freq = self.ctx_summ_freq(self.min_context) as u32;
        let context_hierarchy_hash =
            (non_masked < suffix_num_stats.saturating_sub(num_stats)) as usize;
        let freq_distribution_hash = 2 * (summ_freq < (11 * num_stats)) as usize;
        let symbol_masking_ratio_hash = 4 * (num_masked > non_masked) as usize;
        let symbol_characteristics_hash = self.hi_bits_flag as usize;
        let see_table_hash = context_hierarchy_hash
            + freq_distribution_hash
            + symbol_masking_ratio_hash
            + symbol_characteristics_hash;
        (base_context_idx, see_table_hash)
    }

    fn next_context(&mut self) {
        let successor = self.state_successor(self.found_state);
        // "real context": successor offset lands in the unit area (>= units_start),
        // not the text buffer area.
        if self.order_fall == 0 && successor.get_offset() >= self.units_start {
            let c = successor.get_offset();
            self.min_context = c;
            self.max_context = c;
        } else {
            self.update_model();
        }
    }

    fn update1(&mut self) {
        let mut s = self.found_state;
        let freq = self.state_freq(s) as u32 + 4;
        let sf = self.ctx_summ_freq(self.min_context);
        self.set_ctx_summ_freq(self.min_context, sf + 4);
        self.set_state_freq(s, freq as u8);
        if freq > self.state_freq(s - STATE_SIZE) as u32 {
            self.swap_states(s);
            s -= STATE_SIZE;
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
        let mut freq = self.state_freq(s) as u32;
        let summ_freq = self.ctx_summ_freq(mc) as u32;
        self.prev_success = ((2 * freq) > summ_freq) as u32;
        self.run_length += self.prev_success as i32;
        self.set_ctx_summ_freq(mc, (summ_freq + 4) as u16);
        freq += 4;
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
        let sf = self.ctx_summ_freq(self.min_context);
        self.set_ctx_summ_freq(self.min_context, sf + 4);
        self.set_state_freq(s, freq as u8);
        if freq > MAX_FREQ as u32 {
            self.rescale();
        }
        self.update_model();
    }

    fn update_bin(&mut self, s: u32) {
        let freq = self.state_freq(s) as u32;
        self.found_state = s;
        self.prev_success = 1;
        self.run_length += 1;
        let nf = self.state_freq(s) + ((freq < 128) as u32) as u8;
        self.set_state_freq(s, nf);
        self.next_context();
    }

    fn mask_symbols(&mut self, char_mask: &mut [u8; 256], s: u32, mut s2: u32) {
        let sym = self.state_symbol(s) as usize;
        char_mask[sym] = 0;
        while s2 < s {
            let sym0 = self.state_symbol(s2) as usize;
            let sym1 = self.state_symbol(s2 + STATE_SIZE) as usize;
            s2 += 2 * STATE_SIZE;
            char_mask[sym0] = 0;
            char_mask[sym1] = 0;
        }
    }

    const fn hi_bits_flag3(symbol: u32) -> u32 {
        (symbol + 0xC0) >> (8 - 3) & (1 << 3)
    }
    const fn hi_bits_flag4(symbol: u32) -> u32 {
        (symbol + 0xC0) >> (8 - 4) & (1 << 4)
    }

    /// Returns `(freq_bin_idx, context_idx)` indexing the relevant `bin_summ`
    /// cell, so the binary-context decode can call `self.rc.decode_bit`
    /// afterwards without a conflicting borrow of `self`.
    fn get_bin_summ(&mut self) -> (usize, usize) {
        let state = self.get_single_state(self.min_context);
        let hi_bits_flag3 = Self::hi_bits_flag3(self.state_symbol(self.found_state) as u32);
        let symbol = self.state_symbol(state) as u32;
        let hi_bits_flag4 = Self::hi_bits_flag4(symbol);
        self.hi_bits_flag = hi_bits_flag3;
        let freq_bin_idx = self.state_freq(state) as usize;
        let suffix = self.ctx_suffix(self.min_context).get_offset();
        let num_stats = self.ctx_num_stats(suffix) as usize;
        // Valid streams keep freq in 1..=128 and num_stats in 1..=ns2bs_index.len();
        // corrupt input can violate either, underflowing the `-1`s or overrunning
        // `ns2bs_index`/`bin_summ`. Guard so the indices stay in range, flag corrupt.
        if freq_bin_idx == 0 || num_stats == 0 || num_stats > self.ns2bs_index.len() {
            self.corrupt = true;
            return (0, 0);
        }
        let context_idx = (self.prev_success
            + ((self.run_length as u32 >> 26) & 0x20)
            + self.ns2bs_index[num_stats - 1] as u32
            + hi_bits_flag4
            + hi_bits_flag3) as usize;
        let bi = freq_bin_idx - 1;
        if bi >= self.bin_summ.len() || context_idx >= self.bin_summ[0].len() {
            self.corrupt = true;
            return (0, 0);
        }
        (bi, context_idx)
    }

    /// Offset of a context's single state (the union2/union4 overlay at `+2`).
    #[inline(always)]
    fn get_single_state(&self, context: u32) -> u32 {
        context + CTX_SINGLE_STATE
    }

    #[inline(always)]
    fn get_multi_state_stats(&mut self, context: u32) -> u32 {
        self.ctx_stats(context).get_offset()
    }

    /// Replace the range decoder while preserving all model state. RAR3 uses
    /// this for a "solid continuation" PPMd block (escape→new-table without the
    /// 0x20 reset flag): `PpmdRAR_RangeDec_Init` re-initialises the range coder
    /// over the bytes that follow, but the context tree / SEE / suballocator are
    /// carried over unchanged.
    pub(crate) fn replace_rc(&mut self, rc: RC) {
        self.rc = rc;
    }

    /// Input bytes consumed by the range decoder so far.
    pub(crate) fn rc_bytes_consumed(&self) -> usize {
        self.rc.bytes_consumed()
    }

    /// Decode the next symbol. Returns a byte in `0..=255`, [`SYM_END`] for the
    /// model end marker, or [`SYM_ERROR`] on an inconsistency. This is the
    /// range-coder-agnostic rewrite of ppmd-rust's `decode_symbol`: it uses only
    /// [`RangeDec::get_threshold`], [`RangeDec::decode`] and
    /// [`RangeDec::decode_bit`].
    pub(crate) fn decode_symbol(&mut self) -> i32 {
        // Bail out early on truncated input or a prior arena-bounds violation
        // rather than spinning.
        if self.rc.out_of_data() || self.corrupt {
            return if self.corrupt { SYM_ERROR } else { SYM_END };
        }
        let mut char_mask: [u8; 256];

        if self.ctx_num_stats(self.min_context) != 1 {
            let mut s = self.get_multi_state_stats(self.min_context);
            let summ_freq = self.ctx_summ_freq(self.min_context) as u32;
            let mut count = self.rc.get_threshold(summ_freq);
            let hi_cnt = count;

            count = count.wrapping_sub(self.state_freq(s) as u32);
            if (count as i32) < 0 {
                let freq = self.state_freq(s) as u32;
                self.rc.decode(0, freq);
                self.found_state = s;
                let sym = self.state_symbol(s);
                self.update1_0();
                return self.finish_symbol(sym as i32);
            }

            self.prev_success = 0;
            let num_stats = self.ctx_num_stats(self.min_context);
            for _ in 1..num_stats {
                s += STATE_SIZE;
                count = count.wrapping_sub(self.state_freq(s) as u32);
                if (count as i32) < 0 {
                    let freq = self.state_freq(s) as u32;
                    self.rc
                        .decode(hi_cnt.wrapping_sub(count).wrapping_sub(freq), freq);
                    self.found_state = s;
                    let sym = self.state_symbol(s);
                    self.update1();
                    return self.finish_symbol(sym as i32);
                }
            }

            if hi_cnt >= summ_freq {
                return SYM_ERROR;
            }

            let hi_cnt = hi_cnt.wrapping_sub(count);
            self.rc.decode(hi_cnt, summ_freq.wrapping_sub(hi_cnt));

            self.hi_bits_flag = Self::hi_bits_flag3(self.state_symbol(self.found_state) as u32);
            char_mask = [u8::MAX; 256];
            let s2 = self.get_multi_state_stats(self.min_context);
            self.mask_symbols(&mut char_mask, s, s2);
        } else {
            let s = self.get_single_state(self.min_context);
            let (bi, ci) = self.get_bin_summ();
            let mut pr: u32 = self.bin_summ[bi][ci] as u32;

            if self.rc.decode_bit(pr) == 0 {
                pr = ppmd_update_prob_1(pr);
                self.bin_summ[bi][ci] = (pr + (1 << PPMD_INT_BITS)) as u16;
                let sym = self.state_symbol(s);
                self.update_bin(s);
                return self.finish_symbol(sym as i32);
            }

            pr = ppmd_update_prob_1(pr);
            self.bin_summ[bi][ci] = pr as u16;
            self.init_esc = self.exp_escape[(pr >> 10) as usize] as u32;

            char_mask = [u8::MAX; 256];
            let symbol = self.state_symbol(self.get_single_state(self.min_context)) as usize;
            char_mask[symbol] = 0;
            self.prev_success = 0;
        }

        loop {
            if self.rc.out_of_data() || self.corrupt {
                return if self.corrupt { SYM_ERROR } else { SYM_END };
            }
            let mut mc = self.min_context;
            let num_masked = self.ctx_num_stats(mc) as u32;

            while self.ctx_num_stats(mc) as u32 == num_masked {
                self.order_fall += 1;
                if self.ctx_suffix(mc).is_null() {
                    return SYM_END;
                }
                mc = self.ctx_suffix(mc).get_offset();
            }

            let mut s = self.get_multi_state_stats(mc);
            let mut num = self.ctx_num_stats(mc) as u32;
            let mut num2 = num / 2;
            num &= 1;
            let mut hi_cnt = self.state_freq(s) as u32
                & char_mask[self.state_symbol(s) as usize] as u32
                & (0u32.wrapping_sub(num));
            s += num * STATE_SIZE;
            self.min_context = mc;

            while num2 != 0 {
                let sym0_0 = self.state_symbol(s) as usize;
                let sym1_0 = self.state_symbol(s + STATE_SIZE) as usize;
                s += 2 * STATE_SIZE;
                hi_cnt += (self.state_freq(s - 2 * STATE_SIZE) & char_mask[sym0_0]) as u32;
                hi_cnt += (self.state_freq(s - STATE_SIZE) & char_mask[sym1_0]) as u32;
                num2 -= 1;
            }

            let mut freq_sum = 0;
            let see_source = self.make_esc_freq(num_masked, &mut freq_sum);
            freq_sum += hi_cnt;

            let mut count = self.rc.get_threshold(freq_sum);

            if count < hi_cnt {
                s = self.get_multi_state_stats(self.min_context);
                hi_cnt = count;
                // Bound by num_stats: valid input drives `count` negative within the
                // context's states; corrupt input might not, so cap the walk.
                let ns = self.ctx_num_stats(self.min_context) as usize;
                let mut steps = 0usize;
                loop {
                    let f = self.state_freq(s) as u32;
                    let m = char_mask[self.state_symbol(s) as usize] as u32;
                    count = count.wrapping_sub(f & m);
                    s += STATE_SIZE;
                    steps += 1;
                    if (count as i32) < 0 {
                        break;
                    }
                    if steps >= ns {
                        self.corrupt = true;
                        break;
                    }
                }
                s -= STATE_SIZE;
                let freq = self.state_freq(s) as u32;
                self.rc
                    .decode(hi_cnt.wrapping_sub(count).wrapping_sub(freq), freq);

                let see = self.get_see(see_source);
                see.update();
                self.found_state = s;
                let sym = self.state_symbol(s);
                self.update2();
                return self.finish_symbol(sym as i32);
            }

            if count >= freq_sum {
                return SYM_ERROR;
            }

            self.rc.decode(hi_cnt, freq_sum - hi_cnt);
            let see = self.get_see(see_source);
            see.summ = see.summ.wrapping_add(freq_sum as u16);

            s = self.get_multi_state_stats(self.min_context);
            let s2 = s + self.ctx_num_stats(self.min_context) as u32 * STATE_SIZE;
            while s < s2 {
                let sym = self.state_symbol(s) as usize;
                char_mask[sym] = 0;
                s += STATE_SIZE;
            }
        }
    }

    /// Convert a decoded symbol to its result, downgrading to [`SYM_ERROR`] if
    /// an arena-bounds violation was observed while updating the model.
    #[inline(always)]
    fn finish_symbol(&self, sym: i32) -> i32 {
        if self.corrupt {
            SYM_ERROR
        } else {
            sym
        }
    }
}
