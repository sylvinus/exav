use crate::*;
use std::io::{Cursor, Read};

/// Decompress a UDIF DMG into a raw disk image.
///
/// Uses `dmg_core::DmgReader` which handles all UDIF codecs (zlib, bzip2,
/// LZFSE, LZMA, ADC, raw) in pure Rust.
pub(crate) fn decompress_udif(data: &[u8]) -> Result<Vec<u8>, LimitHit> {
    if data.len() < 512 || &data[data.len() - 512..data.len() - 508] != b"koly" {
        return Ok(data.to_vec());
    }

    let mut reader = dmg::DmgReader::open(Cursor::new(data))
        .map_err(|e| LimitHit::corrupt(format!("UDIF parse: {e}")))?;

    let disk_size = reader.virtual_disk_size() as usize;
    let mut raw = Vec::with_capacity(disk_size);
    reader
        .read_to_end(&mut raw)
        .map_err(|e| LimitHit::corrupt(format!("UDIF decompress: {e}")))?;

    Ok(raw)
}
