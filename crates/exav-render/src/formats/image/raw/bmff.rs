//! The boxes of an ISO base media file (ISO/IEC 14496-12), read for what a
//! Canon CR3 keeps there that its embedded JPEGs lack: the Exif orientation.
//! It is the TIFF structure in the `CMT1` box of a `uuid` box of `moov`.

use std::cell::Cell;

use super::tiff;

/// Boxes read in one file, at every level together.
pub(super) const MAX_BOXES: usize = 256;
/// The shortest `ftyp` box: size, type, major brand and minor version.
const MIN_FTYP: u32 = 16;

/// An ISO base media file whose major brand is `crx `.
pub(super) fn is_cr3(data: &[u8]) -> bool {
    data.get(4..12) == Some(b"ftypcrx ")
        && data
            .first_chunk::<4>()
            .is_some_and(|s| u32::from_be_bytes(*s) >= MIN_FTYP)
}

/// The orientation (1 to 8) in the first `CMT1` box found in the `uuid`
/// boxes of `moov`.
pub(super) fn orientation(data: &[u8]) -> Option<u8> {
    let budget = Cell::new(MAX_BOXES);
    let moov = Boxes::new(data, &budget).find(|b| b.kind == *b"moov")?;
    for uuid in Boxes::new(moov.body, &budget).filter(|b| b.kind == *b"uuid") {
        // A `uuid` box names its type with 16 bytes before its content.
        let Some(content) = uuid.body.get(16..) else {
            continue;
        };
        if let Some(cmt1) = Boxes::new(content, &budget).find(|b| b.kind == *b"CMT1") {
            return tiff::orientation(cmt1.body);
        }
    }
    None
}

struct Item<'a> {
    kind: [u8; 4],
    /// What follows the size, the type and the 64-bit size when there is one.
    body: &'a [u8],
}

/// The boxes laid end to end in a slice. It ends at the first box that does
/// not fit the slice, or when the budget, shared with every other `Boxes`
/// of a file, is spent.
struct Boxes<'a> {
    rest: &'a [u8],
    budget: &'a Cell<usize>,
}

impl<'a> Boxes<'a> {
    fn new(data: &'a [u8], budget: &'a Cell<usize>) -> Self {
        Boxes { rest: data, budget }
    }

    fn read(&self) -> Option<(Item<'a>, usize)> {
        let head = self.rest.get(..8)?;
        let kind = [head[4], head[5], head[6], head[7]];
        let (header, size) = match u32::from_be_bytes([head[0], head[1], head[2], head[3]]) {
            // The box runs to the end of the enclosing one.
            0 => (8, self.rest.len()),
            // The size is the 64 bits that follow the type.
            1 => {
                let big = u64::from_be_bytes(self.rest.get(8..16)?.try_into().ok()?);
                (16, usize::try_from(big).ok()?)
            }
            n => (8, usize::try_from(n).ok()?),
        };
        let body = self.rest.get(header..size)?;
        Some((Item { kind, body }, size))
    }
}

impl<'a> Iterator for Boxes<'a> {
    type Item = Item<'a>;

    fn next(&mut self) -> Option<Item<'a>> {
        let step = match self.budget.get().checked_sub(1) {
            Some(left) => self.read().map(|(item, size)| (item, size, left)),
            None => None,
        };
        let Some((item, size, left)) = step else {
            self.rest = &[];
            return None;
        };
        self.budget.set(left);
        self.rest = &self.rest[size..];
        Some(item)
    }
}
