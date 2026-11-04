//! LZMA-alone (`.lzma`, the format of LZMA Utils before xz): a 13-byte header
//! (the properties byte, the dictionary size, the uncompressed size or all ones
//! when unknown) and one LZMA stream, which ends at the size or at an end
//! marker. There is no checksum. `lzma_rust2` parses the header and decodes;
//! the sniff is in [`super::sniff`].
use std::io::Read;

use lzma_rust2::{Action, LzmaStream, Status};

use super::lzma::SansIo;
use crate::source::{ByteSource, Reader};
use crate::stream::{Visit, stream_single};
use crate::{Budget, LimitHit};

/// Memory the decoder may take, in KiB: the dictionary the header asks for and
/// the probability tables. `lzma -9` asks for a 64 MiB dictionary.
const MEM_LIMIT_KIB: u32 = 128 * 1024;

/// Bytes after the header that [`starts_decodable`] decodes.
const TRIAL_INPUT: usize = 64;

/// Bytes of output after which [`starts_decodable`] stops.
const TRIAL_OUTPUT: usize = 64 * 1024;

/// Whether the start of `d`, which has the header of an LZMA-alone stream,
/// decodes. The header is a few conditions that data made of small numbers
/// meets (the tables and the string pool of an installer database do), and
/// such data soon makes the decoder ask for a match before any output exists,
/// which no stream does. A start that is cut short is taken for a stream.
///
/// The dictionary is taken as 1 MiB, more than the output the trial makes, so
/// the header cannot make it allocate more.
pub(crate) fn starts_decodable(d: &[u8]) -> bool {
    let mut input = d[..d.len().min(13 + TRIAL_INPUT)].to_vec();
    if input.len() >= 5 {
        input[1..5].copy_from_slice(&(1u32 << 20).to_le_bytes());
    }
    let mut stream = LzmaStream::new_mem_limit(MEM_LIMIT_KIB, None);
    let mut out = [0u8; 4096];
    let (mut at, mut made) = (0, 0);
    loop {
        match stream.process(&input[at..], &mut out, Action::Run) {
            Err(_) => return false,
            Ok(r) => {
                at += r.bytes_consumed;
                made += r.bytes_produced;
                if r.status == Status::StreamEnd
                    || made >= TRIAL_OUTPUT
                    || (r.bytes_consumed == 0 && r.bytes_produced == 0)
                {
                    return true;
                }
            }
        }
    }
}

pub(crate) fn walk(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<()>,
) -> Result<Option<()>, LimitHit> {
    let mut source = Reader::new(src);
    stream_single(&mut source, budget, visit, "lzma-content", &mut |r| {
        Ok(content_reader(r))
    })
}

/// The LZMA-alone stream read from `r`, decoded as it is read. A stream cut
/// short is damage here: the decoder keeps back the symbols of the last bytes
/// it has, which `xz -dc` writes.
pub(crate) fn content_reader<'a, R: Read + 'a>(r: R) -> Box<dyn Read + 'a> {
    Box::new(SansIo::new(r, LzmaStream::new_mem_limit(MEM_LIMIT_KIB, None)).cut_is_damage())
}
