//! LZMA-alone (`.lzma`, the format of LZMA Utils before xz): a 13-byte header
//! (the properties byte, the dictionary size, the uncompressed size or all ones
//! when unknown) and one LZMA stream, which ends at the size or at an end
//! marker. There is no checksum. `lzma_rust2` parses the header and decodes;
//! the sniff is in [`super::sniff`].
use std::io::Read;

use lzma_rust2::LzmaStream;

use super::lzma::SansIo;
use crate::source::{ByteSource, Reader};
use crate::stream::{stream_single, Visit};
use crate::{Budget, LimitHit};

/// Memory the decoder may take, in KiB: the dictionary the header asks for and
/// the probability tables. `lzma -9` asks for a 64 MiB dictionary.
const MEM_LIMIT_KIB: u32 = 128 * 1024;

pub(crate) fn walk<T>(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<T>,
) -> Result<Option<T>, LimitHit> {
    let mut source = Reader::new(src);
    stream_single(&mut source, budget, visit, "lzma-content", |r| {
        Ok(Box::new(SansIo::new(
            r,
            LzmaStream::new_mem_limit(MEM_LIMIT_KIB, None),
        )) as Box<dyn Read + '_>)
    })
}
