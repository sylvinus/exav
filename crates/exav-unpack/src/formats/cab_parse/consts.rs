pub(crate) const FILE_SIGNATURE: u32 = 0x4643534d; // "MSCF" little-endian

pub(crate) const MAX_STRING_SIZE: usize = 255;

// Header flags:
pub(crate) const FLAG_PREV_CABINET: u16 = 0x1;
pub(crate) const FLAG_NEXT_CABINET: u16 = 0x2;
pub(crate) const FLAG_RESERVE_PRESENT: u16 = 0x4;

// File attributes:
pub(crate) const ATTR_NAME_IS_UTF: u16 = 0x80;
