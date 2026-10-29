use super::error::{Error, Result};
use super::model::{Shape, Sp};

/// Bounds on the work one conversion may do. A document past one of them is
/// refused with [`Error::TooLarge`] rather than partly converted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Limits {
    /// Bytes of input.
    pub max_input: u64,
    /// Memory the model and the output may take, as this module counts it:
    /// an estimate per shape and paragraph, the bytes of each picture and
    /// decompressed part, and the PPTX written so far.
    pub max_memory: u64,
    /// Bytes of one decompressed part of a package or stream.
    pub max_part: u64,
    /// Slides.
    pub max_slides: u32,
    /// Shapes over all slides, masters and layouts, group members included.
    pub max_shapes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_input: 512 << 20,
            max_memory: 1 << 30,
            max_part: 256 << 20,
            max_slides: 10_000,
            max_shapes: 1_000_000,
        }
    }
}

impl Limits {
    /// Defaults with another memory bound.
    pub fn with_max_memory(mut self, bytes: u64) -> Self {
        self.max_memory = bytes;
        self
    }

    /// Defaults with another shape bound.
    pub fn with_max_shapes(mut self, n: u64) -> Self {
        self.max_shapes = n;
        self
    }
}

/// What a conversion has used of its [`Limits`].
pub(crate) struct Budget {
    pub limits: Limits,
    shapes: u64,
    memory: u64,
    /// The slides to convert, by index; the others are counted only.
    wanted: std::ops::Range<usize>,
}

/// What one shape costs in the model, beyond its text and pictures: the shape
/// and the largest of what it holds.
pub(crate) const SHAPE_BYTES: u64 = (size_of::<Shape>() + size_of::<Sp>()) as u64;

impl Budget {
    pub fn new(limits: Limits) -> Self {
        Budget {
            limits,
            shapes: 0,
            memory: 0,
            wanted: 0..usize::MAX,
        }
    }

    /// Converts only the slides of `range`.
    pub fn only(mut self, range: std::ops::Range<usize>) -> Self {
        self.wanted = range;
        self
    }

    /// Whether slide `index` is converted.
    pub fn wants(&self, index: usize) -> bool {
        self.wanted.contains(&index)
    }

    /// One more shape, and `extra` bytes of its own text.
    pub fn shape(&mut self, extra: usize) -> Result<()> {
        self.shapes += 1;
        if self.shapes > self.limits.max_shapes {
            return Err(Error::TooLarge("shapes"));
        }
        self.alloc(SHAPE_BYTES + extra as u64)
    }

    /// `bytes` more held in memory.
    pub fn alloc(&mut self, bytes: u64) -> Result<()> {
        self.memory = self.memory.saturating_add(bytes);
        if self.memory > self.limits.max_memory {
            return Err(Error::TooLarge("memory"));
        }
        Ok(())
    }

    /// What `xml::parse` charges the memory of a tree to.
    pub fn tree(&mut self) -> impl FnMut(u64) -> bool + '_ {
        |bytes| self.alloc(bytes).is_ok()
    }

    /// One more slide, `count` being those read so far.
    pub fn slide(&self, count: usize) -> Result<()> {
        if count as u64 >= u64::from(self.limits.max_slides) {
            return Err(Error::TooLarge("slides"));
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
    fn shapes_and_memory_are_bounded() {
        let mut b = Budget::new(Limits::default().with_max_shapes(2));
        assert!(b.shape(0).is_ok());
        assert!(b.shape(0).is_ok());
        assert_eq!(b.shape(0), Err(Error::TooLarge("shapes")));
        let mut b = Budget::new(Limits::default().with_max_memory(1000));
        assert!(b.alloc(999).is_ok());
        assert_eq!(b.alloc(2), Err(Error::TooLarge("memory")));
    }
}
