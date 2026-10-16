use crate::formats::office::sheets::error::{Error, Result};

/// Bounds on the work one conversion may do. A document past one of them is
/// refused with [`Error::TooLarge`] rather than partly converted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Limits {
    /// Bytes of input.
    pub max_input: u64,
    /// Cells written, empty styled cells included, over all sheets.
    pub max_cells: u64,
    /// Memory the workbook model and the output may take, as this module
    /// counts it: an estimate per cell and string, the bytes of each picture
    /// and decompressed part, and the XLSX written so far.
    pub max_memory: u64,
    /// Bytes of one decompressed part of an ODS or Numbers package.
    pub max_part: u64,
    /// Sheets (Numbers: tables).
    pub max_sheets: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_input: 256 << 20,
            max_cells: 4_000_000,
            max_memory: 1 << 30,
            max_part: 256 << 20,
            max_sheets: 4096,
        }
    }
}

impl Limits {
    /// Defaults with another cell bound.
    pub fn with_max_cells(mut self, n: u64) -> Self {
        self.max_cells = n;
        self
    }

    /// Defaults with another memory bound.
    pub fn with_max_memory(mut self, bytes: u64) -> Self {
        self.max_memory = bytes;
        self
    }
}

/// What a conversion has used of its [`Limits`].
pub(crate) struct Budget {
    pub limits: Limits,
    cells: u64,
    memory: u64,
}

/// What one cell costs in the model, beyond its strings.
pub(crate) const CELL_BYTES: u64 = 96;

impl Budget {
    pub fn new(limits: Limits) -> Self {
        Budget {
            limits,
            cells: 0,
            memory: 0,
        }
    }

    /// One more cell, and `extra` bytes of its own text.
    pub fn cell(&mut self, extra: usize) -> Result<()> {
        self.cells += 1;
        if self.cells > self.limits.max_cells {
            return Err(Error::TooLarge("cells"));
        }
        self.alloc(CELL_BYTES + extra as u64)
    }

    /// `bytes` more held in memory.
    pub fn alloc(&mut self, bytes: u64) -> Result<()> {
        self.memory = self.memory.saturating_add(bytes);
        if self.memory > self.limits.max_memory {
            return Err(Error::TooLarge("memory"));
        }
        Ok(())
    }

    /// Whether `n` more cells would still fit, without counting them.
    pub fn room_for_cells(&self, n: u64) -> bool {
        self.cells.saturating_add(n) <= self.limits.max_cells
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cells_and_memory_are_bounded() {
        let mut b = Budget::new(Limits::default().with_max_cells(2));
        assert!(b.cell(0).is_ok());
        assert!(b.cell(0).is_ok());
        assert_eq!(b.cell(0), Err(Error::TooLarge("cells")));
        let mut b = Budget::new(Limits::default().with_max_memory(1000));
        assert!(b.alloc(999).is_ok());
        assert_eq!(b.alloc(2), Err(Error::TooLarge("memory")));
    }
}
