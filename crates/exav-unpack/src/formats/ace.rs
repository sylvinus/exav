//! ACE — recognised, not decoded.
//!
//! WinRAR opens ACE archives, which is what makes the format matter: it is the
//! CVE-2018-20250 vector, where a path-traversal bug in WinRAR's ACE handler let
//! an archive write into the victim's Startup folder. An attacker has every
//! reason to reach for it, and a victim has WinRAR installed.
//!
//! exav has no ACE decoder, and this module does not pretend otherwise. What it
//! does is make the gap **visible**: without it an `.ace` is an unrecognised
//! blob, its compressed members show nothing to a raw scan, and the file comes
//! back clean. With it the file is reported `UNSCANNABLE` — coverage we do not
//! have, rather than coverage we falsely claim.
//!
//! Writing a decoder is blocked on validation rather than on effort: no ACE
//! compressor is still distributed, and the one obtainable sample (the
//! `TestData.ace` in Microsoft's RecursiveExtractor corpus) is rejected as
//! invalid by both `lsar` and `unace`. A decoder written against the format
//! description with nothing to check it produces plausible bytes when it is
//! wrong, which is worse than reporting the gap.

use crate::{Budget, Entry, Format, LimitHit, Sink};

fn is_ace(d: &[u8]) -> bool {
    super::sniff::is(d, Format::Ace)
}

pub(crate) fn extract_ace<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    if !is_ace(data) {
        return Ok(None);
    }
    budget.count_entry()?;
    Ok(visit(
        Entry::unsupported(
            "ace-archive".to_string(),
            data.len() as u64,
            false,
            "ACE archive: exav has no decoder, so its members were not examined",
        ),
        budget,
    ))
}
