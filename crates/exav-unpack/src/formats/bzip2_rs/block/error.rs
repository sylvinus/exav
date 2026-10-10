use std::error::Error as StdError;
use std::fmt::{self, Display, Formatter};
use std::io;

/// An error returned by the block decoder
///
/// At the moment it's not possible to find out what
/// error occurred other than through the `Display`
/// implementation, this will change in a future release.
#[derive(Debug, Clone, PartialEq)]
pub struct BlockError {
    reason: &'static str,
    truncated: bool,
    checksum: bool,
}

impl BlockError {
    #[inline(always)]
    pub(super) fn new(reason: &'static str) -> Self {
        Self {
            reason,
            truncated: false,
            checksum: false,
        }
    }

    /// The block's bits ran out before it was whole.
    #[inline(always)]
    pub(super) fn truncated(reason: &'static str) -> Self {
        Self {
            reason,
            truncated: true,
            checksum: false,
        }
    }

    /// The stream decoded in full and a block failed its CRC.
    pub(super) fn checksum(reason: &'static str) -> Self {
        Self {
            reason,
            truncated: false,
            checksum: true,
        }
    }

    pub(crate) fn is_truncated(&self) -> bool {
        self.truncated
    }
}

impl Display for BlockError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason)
    }
}

impl StdError for BlockError {}

impl From<BlockError> for io::Error {
    fn from(err: BlockError) -> io::Error {
        if err.checksum {
            return crate::checksum_mismatch("bzip2 block CRC");
        }
        io::Error::other(err)
    }
}
