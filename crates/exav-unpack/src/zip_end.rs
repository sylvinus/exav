//! The end-of-central-directory record of a ZIP, found at the end of a file.
//! Every reader of a ZIP's end in this crate takes its candidates from here,
//! so that they agree on which record is one.

/// An end-of-central-directory record found at the end of a file. The span
/// reads only where it is; the ZIP reader and the detection read its fields.
#[derive(Clone, Copy)]
#[cfg_attr(not(feature = "zip"), allow(dead_code))]
pub(crate) struct EndRecord {
    /// Where the record starts, from the start of the file.
    pub(crate) at: u64,
    pub(crate) entries: u16,
    /// Length of the central directory, which ends where the record starts.
    pub(crate) size: u32,
    /// Where the directory starts, as the record counts.
    pub(crate) offset: u32,
    /// Length of the comment after the record.
    pub(crate) comment: u16,
}

#[cfg_attr(not(feature = "zip"), allow(dead_code))]
impl EndRecord {
    pub(crate) const LEN: usize = 22;

    /// The record at the start of `bytes`, found `at` bytes into a file with
    /// `room` bytes from there to its end; `None` unless its comment ends
    /// within the file.
    pub(crate) fn parse(at: u64, bytes: &[u8], room: u64) -> Option<Self> {
        let b = bytes.get(..Self::LEN)?;
        if !b.starts_with(b"PK\x05\x06") {
            return None;
        }
        let record = EndRecord {
            at,
            entries: u16::from_le_bytes([b[10], b[11]]),
            size: u32::from_le_bytes([b[12], b[13], b[14], b[15]]),
            offset: u32::from_le_bytes([b[16], b[17], b[18], b[19]]),
            comment: u16::from_le_bytes([b[20], b[21]]),
        };
        (Self::LEN as u64 + u64::from(record.comment) <= room).then_some(record)
    }

    /// Whether its 16 and 32 bit fields describe a directory: some entries,
    /// and no field that defers to a ZIP64 end record.
    pub(crate) fn has_directory(&self) -> bool {
        self.entries != 0
            && self.entries != u16::MAX
            && self.size != u32::MAX
            && self.offset != u32::MAX
    }
}

/// The end records in `window`, the last bytes of a file whose first byte is
/// `base` bytes into it, the last one first. Only records whose comment ends
/// within the file: anything after a record's comment is not part of it.
pub(crate) fn end_records(window: &[u8], base: u64) -> impl Iterator<Item = EndRecord> + '_ {
    memchr::memmem::rfind_iter(window, b"PK\x05\x06").filter_map(move |p| {
        EndRecord::parse(base + p as u64, &window[p..], (window.len() - p) as u64)
    })
}
