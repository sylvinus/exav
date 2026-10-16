use crate::formats::office::docs::error::{Error, Result};

/// Bounds on the work one conversion may do. A document past one of them is
/// refused with [`Error::TooLarge`] rather than partly converted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Limits {
    /// Bytes of input.
    pub max_input: u64,
    /// Memory the model and the output may take, as this module counts it:
    /// an estimate per paragraph and cell, the bytes of text, each picture
    /// and decompressed part, and the DOCX written so far.
    pub max_memory: u64,
    /// Bytes of one decompressed part of a package or stream.
    pub max_part: u64,
    /// Paragraphs over the body, notes, headers and footers.
    pub max_paragraphs: u64,
    /// Table cells.
    pub max_cells: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_input: 512 << 20,
            max_memory: 1 << 30,
            max_part: 256 << 20,
            max_paragraphs: 5_000_000,
            max_cells: 2_000_000,
        }
    }
}

impl Limits {
    /// Defaults with another memory bound.
    pub fn with_max_memory(mut self, bytes: u64) -> Self {
        self.max_memory = bytes;
        self
    }

    /// Defaults with another paragraph bound.
    pub fn with_max_paragraphs(mut self, n: u64) -> Self {
        self.max_paragraphs = n;
        self
    }

    /// Defaults with another cell bound.
    pub fn with_max_cells(mut self, n: u64) -> Self {
        self.max_cells = n;
        self
    }
}

/// What a conversion has used of its [`Limits`].
pub(crate) struct Budget {
    pub limits: Limits,
    paragraphs: u64,
    cells: u64,
    memory: u64,
}

/// What one paragraph costs in the model, beyond its text.
pub(crate) const PARA_BYTES: u64 = 256;
/// What one table cell costs in the model, beyond its content.
pub(crate) const CELL_BYTES: u64 = 192;

impl Budget {
    pub fn new(limits: Limits) -> Self {
        Budget {
            limits,
            paragraphs: 0,
            cells: 0,
            memory: 0,
        }
    }

    /// One more paragraph, and `extra` bytes of its own text.
    pub fn paragraph(&mut self, extra: usize) -> Result<()> {
        self.paragraphs += 1;
        if self.paragraphs > self.limits.max_paragraphs {
            return Err(Error::TooLarge("paragraphs"));
        }
        self.alloc(PARA_BYTES + extra as u64)
    }

    /// One more table cell.
    pub fn cell(&mut self) -> Result<()> {
        self.cells += 1;
        if self.cells > self.limits.max_cells {
            return Err(Error::TooLarge("table cells"));
        }
        self.alloc(CELL_BYTES)
    }

    /// `bytes` more held in memory.
    pub fn alloc(&mut self, bytes: u64) -> Result<()> {
        self.memory = self.memory.saturating_add(bytes);
        if self.memory > self.limits.max_memory {
            return Err(Error::TooLarge("memory"));
        }
        Ok(())
    }

    pub fn used(&self) -> u64 {
        self.memory
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paragraphs_cells_and_memory_are_bounded() {
        let mut b = Budget::new(Limits::default().with_max_paragraphs(2));
        assert!(b.paragraph(0).is_ok());
        assert!(b.paragraph(0).is_ok());
        assert_eq!(b.paragraph(0), Err(Error::TooLarge("paragraphs")));
        let mut b = Budget::new(Limits::default().with_max_cells(1));
        assert!(b.cell().is_ok());
        assert_eq!(b.cell(), Err(Error::TooLarge("table cells")));
        let mut b = Budget::new(Limits::default().with_max_memory(1000));
        assert!(b.alloc(999).is_ok());
        assert_eq!(b.alloc(2), Err(Error::TooLarge("memory")));
    }
}
