//! Definitions shared by the PPMd7 (var.H) model in this module and the PPMd8
//! (var.I rev.1) model in `formats/ppmd8`, from `ppmd-rust` (CC0-1.0 OR MIT-0)
//! `internal.rs`, plus the constants both of its models define with the same
//! values. Not derived from UnRAR.

pub(crate) const PPMD_INT_BITS: u32 = 7;
pub(crate) const PPMD_PERIOD_BITS: u32 = 7;
pub(crate) const PPMD_BIN_SCALE: u32 = 1 << (PPMD_INT_BITS + PPMD_PERIOD_BITS);

const fn ppmd_get_mean_spec(summ: u32, shift: u32, round: u32) -> u32 {
    (summ + (1 << (shift - round))) >> shift
}
const fn ppmd_get_mean(summ: u32) -> u32 {
    ppmd_get_mean_spec(summ, PPMD_PERIOD_BITS, 2)
}
pub(crate) const fn ppmd_update_prob_1(prob: u32) -> u32 {
    prob - ppmd_get_mean(prob)
}

const PPMD_N1: u32 = 4;
const PPMD_N2: u32 = 4;
const PPMD_N3: u32 = 4;
const PPMD_N4: u32 = (128 + 3 - PPMD_N1 - 2 * PPMD_N2 - 3 * PPMD_N3) / 4;
pub(crate) const PPMD_NUM_INDEXES: u32 = PPMD_N1 + PPMD_N2 + PPMD_N3 + PPMD_N4;

pub(crate) const MAX_FREQ: u8 = 124;
pub(crate) const UNIT_SIZE: u32 = 12;

pub(crate) static K_EXP_ESCAPE: [u8; 16] = [25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2];
pub(crate) static K_INIT_BIN_ESC: [u16; 8] = [
    0x3CDD, 0x1F3F, 0x59BF, 0x48F3, 0x64A1, 0x5ABC, 0x6632, 0x6051,
];

pub(crate) enum SeeSource {
    Dummy,
    Table(usize, usize),
}

#[derive(Copy, Clone, Default)]
pub(crate) struct See {
    pub(crate) summ: u16,
    pub(crate) shift: u8,
    pub(crate) count: u8,
}

impl See {
    pub(crate) fn update(&mut self) {
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

// State record (6 bytes, little-endian), the same in both models:
//   symbol:u8 @0  freq:u8 @1  successor_0:u16 @2  successor_1:u16 @4
pub(crate) const STATE_SIZE: u32 = 6;
pub(crate) const ST_SYMBOL: u32 = 0;
pub(crate) const ST_FREQ: u32 = 1;
pub(crate) const ST_SUCC0: u32 = 2;
pub(crate) const ST_SUCC1: u32 = 4;
