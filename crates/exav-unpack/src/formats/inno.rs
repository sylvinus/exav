//! Inno Setup — recognised, not decoded.
//!
//! Inno Setup is one of the most widely used Windows installer builders, which
//! makes an `.exe` built with it a first-rank delivery container: the victim
//! double-clicks it and it writes and runs whatever it holds. Its payload is
//! LZMA-compressed in blocks appended to the stub, so the files inside show
//! nothing to a raw pattern scan.
//!
//! exav sees the installer as an SFX and carves the appended block, which is the
//! right shape — but that block is Inno's own chunked container, not a format
//! any extractor here reads. Emitted as an ordinary member it scanned clean,
//! which is exactly the failure this codebase refuses: a container full of
//! unexamined files reported as though it had been examined.
//!
//! This module does not add a decoder. It makes the gap **visible**, so an Inno
//! installer is reported `UNSCANNABLE` rather than clean — a coverage gap we
//! admit to instead of one we hide.
//!
//! Decoding it properly means the setup loader, the compressed header block, the
//! file-entry table and the per-file chunked LZMA streams, with the layout
//! changing across setup-data versions. The reference implementation
//! (`innoextract`) is GPL, so it can be used as an oracle but not as a source;
//! that is a from-scratch project, not an afternoon.

use crate::{Budget, Entry, LimitHit, Sink};

pub(crate) fn extract_inno<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    if !super::sniff::is(data, crate::Format::Inno) {
        return Ok(None);
    }
    budget.count_entry()?;
    Ok(visit(
        Entry::unsupported(
            "inno-setup-payload".to_string(),
            data.len() as u64,
            false,
            "Inno Setup installer: exav has no decoder, so the files it installs \
             were not examined",
        ),
        budget,
    ))
}
