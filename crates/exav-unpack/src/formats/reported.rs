//! Containers exav recognises but does not open.
//!
//! Recognition alone closes the worst hole. An unrecognised container gets a raw
//! pattern scan over compressed bytes, matches nothing, and comes back **`OK`**;
//! a recognised one reports `UNSCANNABLE` and the operator can see the gap. That
//! is a much cheaper fix than a decoder and it is why the gap list ranks it
//! first.
//!
//! One module rather than one per format: the bodies were identical, and the
//! only thing that differs is the name and the sentence explaining what went
//! unread. Sniffing lives in [`super::sniff`]; this is purely the reporting.
//!
//! # Why these are still here
//!
//! Two of them are blocked on licensing rather than on effort, and that is
//! worth writing down so nobody re-derives the search:
//!
//! * **lrzip** — the rzip long-range match stream has no published
//!   specification. It is defined only by lrzip's own GPL source, which exav
//!   must not read, and there is no permissively-licensed implementation in any
//!   language. Running the tool as an *oracle* is allowed, but inferring an
//!   exact bitstream from black-box behaviour is not something to attempt and
//!   then claim.
//! * **InstallShield `ISc(` cabinets** — likewise undocumented; the only
//!   implementation is the LGPL `unshield` **C project**. Not to be confused
//!   with the MIT `unshield` *crate*, which reads the older InstallShield `.z`
//!   archive — a different format, and one exav does open (`formats/ishield_z`).
//!
//! Both therefore stay recognised-and-reported, which is the honest answer:
//! `UNSCANNABLE` tells an operator there is a gap, where a decoder that guessed
//! would produce plausible bytes and a confident `OK`.

use crate::{Budget, Entry, Format, LimitHit, Sink};

/// How a recognised-but-unopened container reports: the member name, why its
/// contents went unread, and whether the reason is encryption (which reports as
/// `PASSWORD-PROTECTED` rather than merely undecodable, because the user can act
/// on it).
fn report_of(fmt: Format) -> Option<(&'static str, &'static str, bool)> {
    Some(match fmt {
        Format::Egg => (
            "egg-archive",
            "EGG archive: exav has no decoder, so its members were not examined",
            false,
        ),
        Format::IshieldMsi => (
            "ishield-msi",
            "InstallShield MSI installer: exav has no unpacker, so its embedded \
             database and payload were not examined",
            false,
        ),
        Format::IshieldCab => (
            "ishield-cab",
            "InstallShield InstallScript cabinet: exav has no unpacker, so its \
             members were not examined",
            false,
        ),
        Format::CryptFf => (
            "cryptff-payload",
            "CryptFF-encrypted file: exav cannot decrypt it, so its payload was \
             not examined",
            true,
        ),
        Format::Lrzip => (
            "lrzip-stream",
            "lrzip stream: exav has no decoder, so its contents were not examined",
            false,
        ),
        Format::AppleSingle => (
            "applesingle-container",
            "AppleSingle/AppleDouble container: exav has no reader, so the forks \
             inside it were not examined",
            false,
        ),
        _ => return None,
    })
}

/// Emit the one report for a recognised-but-unopened container.
///
/// Returns `Ok(None)` when `fmt` is not one of these or the bytes do not
/// actually sniff as it — the caller must not be able to conjure a report for a
/// file that is not the thing.
pub(crate) fn extract_reported<R>(
    fmt: Format,
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    let Some((name, reason, encrypted)) = report_of(fmt) else {
        return Ok(None);
    };
    if !super::sniff::is(data, fmt) {
        return Ok(None);
    }
    budget.count_entry()?;
    Ok(visit(
        Entry::unsupported(name.to_string(), data.len() as u64, encrypted, reason),
        budget,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Limits;

    /// One sample per format, shaped so [`super::super::sniff`] claims it.
    fn samples() -> Vec<(Format, Vec<u8>)> {
        let mut v: Vec<(Format, Vec<u8>)> = vec![
            (Format::Egg, b"EGGA\x01\x00padding".to_vec()),
            (
                Format::CryptFf,
                [
                    &[0xB6u8, 0xB9, 0xAC, 0xAE, 0xFE, 0xFF, 0xFF, 0xFF][..],
                    b"payload",
                ]
                .concat(),
            ),
            (Format::Lrzip, b"LRZI\x00\x06rest of the stream".to_vec()),
            (
                Format::AppleSingle,
                [&[0x00u8, 0x05, 0x16, 0x00][..], &[0; 32]].concat(),
            ),
            (Format::IshieldCab, [b"ISc(".as_slice(), &[0; 64]].concat()),
        ];
        // A format this module lists is one exav recognises and does not decode.
        // ext and ZOO are decoded (formats/ext.rs, formats/zoo.rs) and so belong
        // nowhere near here; `a_format_this_module_does_not_speak_for_is_declined`
        // is what keeps the list honest.
        // InstallShield MSI: the `InstallShield\0` tag, then a fixed 292-byte
        // gap, the `06` record marker, eight bytes of anything, and the trailing
        // marker (see `super::sniff`).
        let mut msi = b"InstallShield\0".to_vec();
        msi.extend(std::iter::repeat_n(0u8, 292));
        msi.extend([0x06, 0, 0, 0, 0, 0, 0, 0]);
        msi.extend([0xAA; 8]);
        msi.extend([0, 0, 0, 0, 1]);
        v.push((Format::IshieldMsi, msi));
        v
    }

    fn members(fmt: Format, blob: &[u8]) -> Vec<Entry> {
        let mut b = Budget::new(Limits::default());
        let mut seen = Vec::new();
        let _ = extract_reported(fmt, blob, &mut b, &mut |e: Entry, _: &mut Budget| {
            seen.push(e);
            None::<()>
        });
        seen
    }

    #[test]
    fn every_recognised_container_reports_exactly_once() {
        for (fmt, blob) in samples() {
            let seen = members(fmt, &blob);
            assert_eq!(seen.len(), 1, "{fmt:?}: expected one report, got {seen:?}");
            assert!(
                seen[0].unsupported.is_some(),
                "{fmt:?} must surface as unscannable, not pass as clean"
            );
            assert!(
                seen[0].data.is_empty(),
                "{fmt:?}: no content may be invented"
            );
        }
    }

    /// The sample for one format, looked up rather than indexed — a positional
    /// index silently tests the wrong format the moment the list is reordered.
    fn sample_for(fmt: Format) -> Vec<u8> {
        samples()
            .into_iter()
            .find(|(f, _)| *f == fmt)
            .unwrap_or_else(|| panic!("no sample for {fmt:?}"))
            .1
    }

    #[test]
    fn the_encrypted_ones_say_so() {
        // PASSWORD-PROTECTED is actionable by the user; UNSCANNABLE is not. The
        // distinction is the only reason both verdicts exist.
        let seen = members(Format::CryptFf, &sample_for(Format::CryptFf));
        assert!(seen[0].encrypted, "CryptFF is encrypted, and must say so");
        for fmt in [Format::Lrzip, Format::Egg, Format::IshieldCab] {
            let seen = members(fmt, &sample_for(fmt));
            assert!(
                !seen[0].encrypted,
                "{fmt:?} is not encrypted; reporting it as password-protected \
                 would send the user looking for a password that does not exist"
            );
        }
    }

    #[test]
    fn bytes_that_are_not_the_format_produce_nothing() {
        // Otherwise a caller passing the wrong `fmt` would manufacture a report
        // for an ordinary file, which is its own kind of lie.
        for (fmt, _) in samples() {
            let seen = members(fmt, b"just some ordinary text, not a container");
            assert!(seen.is_empty(), "{fmt:?} claimed a plain text file");
        }
    }

    #[test]
    fn a_format_this_module_does_not_speak_for_is_declined() {
        let seen = members(Format::Zip, b"PK\x03\x04whatever");
        assert!(seen.is_empty());
    }
}
