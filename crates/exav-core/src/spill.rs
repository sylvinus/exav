//! Room outside memory for bytes a scan makes, when the host provides it.
//!
//! The library never writes to disk itself. A scan of an object too large to
//! hold makes views of it (its normalised text) and meets members too large to
//! hold, and those have to go somewhere they can be read back at any offset. A
//! host that allows that hands a [`Spill`] in [`crate::ScanOptions::spill`].
//! Without one, what would have needed it is reported as not fully scanned.
//!
//! The traits are those of [`exav_unpack::spill`], which also has a spill that
//! writes to a directory.

pub(crate) use exav_unpack::spill::Spilled;
pub use exav_unpack::spill::{Spill, SpillReader, SpillWriter};

use exav_unpack::spill::SpillBatch;

/// Collects the bytes of a normalised view for a spill file.
pub(crate) struct SpillOut {
    batch: SpillBatch,
    last: Option<u8>,
}

impl SpillOut {
    pub(crate) fn new(file: Box<dyn SpillWriter>) -> Self {
        SpillOut {
            batch: SpillBatch::new(file),
            last: None,
        }
    }

    /// What was written, to read back.
    pub(crate) fn finish(self, cache: (usize, usize)) -> Result<Spilled, String> {
        self.batch.finish(cache)
    }
}

impl crate::normalize::Out for SpillOut {
    #[inline]
    fn push(&mut self, b: u8) {
        self.batch.push(b);
        self.last = Some(b);
    }

    fn last(&self) -> Option<u8> {
        self.last
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::byte_source::ByteSource;
    use crate::normalize::Out;

    #[test]
    fn a_view_written_a_byte_at_a_time_reads_back_whole_and_knows_its_last_byte() {
        let spill = exav_unpack::spill::MemSpill::new();
        let mut out = SpillOut::new(spill.create().unwrap());
        assert_eq!(out.last(), None);
        let data: Vec<u8> = (0..3 * crate::byte_source::CHUNK + 1)
            .map(|i| i as u8)
            .collect();
        for &b in &data {
            out.push(b);
        }
        assert_eq!(out.last(), Some(data[data.len() - 1]));
        let back = out.finish((4096, 1 << 20)).unwrap();
        assert_eq!(back.window(0, back.len()), &data[..]);
    }
}
