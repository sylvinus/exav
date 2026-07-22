//! StuffIt / StuffIt X — recognised, not decoded.
//!
//! The Mac archive format. It matters for the same reason ACE does: the
//! *recipient* can open it. StuffIt Expander was bundled on macOS for years and
//! The Unarchiver still reads the format, so an attacker mailing a `.sit` has a
//! victim who can open it and a scanner that historically could not look inside.
//!
//! exav has no StuffIt decoder, and this module does not pretend otherwise. What
//! it does is make the gap **visible**. Without it a `.sit` was an unrecognised
//! blob: its members are compressed, a raw scan of the container matches
//! nothing, and the file came back **`OK`** — a clean verdict over content that
//! was never examined, which is the one outcome this scanner must never produce.
//! With it the file is reported `UNSCANNABLE`.
//!
//! A decoder is blocked on validation rather than effort, the same as ACE:
//! StuffIt's compression methods are undocumented, and the only reference
//! implementations are closed-source or GPL, so an implementation written from
//! observation has nothing trustworthy to check it against. A decoder that is
//! subtly wrong emits plausible bytes rather than errors.

use crate::{Budget, Entry, Format, LimitHit, Sink};

fn is_stuffit(d: &[u8]) -> bool {
    super::sniff::is(d, Format::StuffIt)
}

pub(crate) fn extract_stuffit<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    if !is_stuffit(data) {
        return Ok(None);
    }
    budget.count_entry()?;
    Ok(visit(
        Entry::unsupported(
            "stuffit-archive".to_string(),
            data.len() as u64,
            false,
            "StuffIt archive: exav has no decoder, so its members were not examined",
        ),
        budget,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // The magic itself is tested in `formats::sniff`, which owns it.

    #[test]
    fn a_recognised_archive_is_reported_never_clean() {
        let mut b = Budget::new(crate::Limits::default());
        let mut seen = Vec::new();
        let _ = extract_stuffit::<()>(b"SIT!padding here", &mut b, &mut |e, _| {
            seen.push(e);
            None
        });
        assert_eq!(seen.len(), 1);
        assert!(
            seen[0].unsupported.is_some(),
            "a StuffIt archive must surface as unscannable, not pass as clean"
        );
        assert!(seen[0].data.is_empty(), "nothing is invented for it");
    }
}
