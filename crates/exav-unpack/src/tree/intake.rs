//! Taking a member's bytes from its reader: held in memory, read where they lie
//! in the container, or written to a spill, and how the read ended.

use std::io::{self, Read};

use super::{End, Reason, ReasonKind, Reasons};
use crate::Settled;
use crate::source::{ByteSource, Sub, read_capped};
use crate::spill::{Spill, Spilled, spill_stream};
use crate::{Budget, Member, MemberMeta, decode_error_hides_content, is_budget_overflow};

/// What a walk holds of a member in memory, and where the rest may go.
pub struct Hold<'a> {
    /// Bytes of a member that are held. A member over it is too large to hold.
    pub limit: u64,
    /// Where a member too large to hold may be written. `None`: nowhere.
    pub spill: Option<&'a dyn Spill>,
    /// Block size and capacity, in bytes, of the cache over a spilled member.
    pub cache: (usize, usize),
    /// What is done with a stream member too large to hold.
    pub large: Large,
}

/// What a walk does with a member decoded as it is read that is too large to
/// hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Large {
    /// Every one is written to the spill and read back, whatever it is, so
    /// that it has the same bytes to go to as a member held (the scanner).
    Source,
    /// Only a container is: it cannot be opened without seeking in it. Any
    /// other is handed over as a stream, read as it is decoded, so that what
    /// is held does not grow with it (a search). Whether it is a container is
    /// told from its first bytes as far as detection reaches (4 MiB and a
    /// little), which are read even when that is past the hold limit.
    StreamLeaves,
}

/// A member's bytes, once taken.
pub enum Body<'a> {
    /// Nothing to scan: the member was not decoded, or could not be read.
    None,
    Mem(Vec<u8>),
    /// Too large to hold, and written to the spill.
    Spilled(Spilled),
    /// Too large to hold, and not spilled: the first `Hold::limit` bytes,
    /// which are scanned before `reason` is reported.
    Prefix {
        data: Vec<u8>,
        reason: String,
    },
    /// Too large to hold, and a range of its container as it stands: read
    /// there, through the container's own reads.
    Range(Sub<'a>),
    /// Too large to hold, and not a container (so far as its start says): what
    /// was read of it. The rest of the stream is [`Intake::rest`]. `unchecked`
    /// says why it was not told for certain, when it was not.
    Stream {
        head: Vec<u8>,
        unchecked: Option<Reason>,
    },
}

impl Body<'_> {
    /// What the scan of the body showed was not there. A read error of a
    /// spilled or in-place body shows only once the bytes were read, so ask
    /// after the scan.
    pub fn unread(&self) -> Reasons {
        let mut reasons = Reasons::default();
        match self {
            Body::Spilled(spilled) => {
                if let Some(e) = spilled.read_error() {
                    add(
                        &mut reasons,
                        ReasonKind::ReadFailed,
                        format!("spilled member unreadable: {e}"),
                    );
                }
            }
            Body::Range(sub) => {
                if let Some(e) = sub.read_error() {
                    add(
                        &mut reasons,
                        ReasonKind::ReadFailed,
                        format!("member unreadable: {e}"),
                    );
                }
            }
            Body::None | Body::Mem(_) | Body::Prefix { .. } | Body::Stream { .. } => {}
        }
        reasons
    }
}

/// A member's bytes, how they end, and what could not be taken.
pub struct Intake<'a, 's> {
    pub body: Body<'a>,
    /// The stream a [`Body::Stream`] goes on in, after what was read of it.
    pub rest: Option<&'s mut dyn Read>,
    /// `Complete` unless the stream failed. A failed stream keeps what was
    /// decoded before the error in `body`, held or spilled, so a truncated
    /// gzip or tar does not hide the payload in its readable part. `body` is
    /// `None` when nothing decoded and the error hides content, and, with
    /// checksums verified, for any error.
    pub end: End,
    /// What was dropped while taking the member. `at` is empty: the caller
    /// knows the node.
    pub reasons: Reasons,
}

/// Why [`intake`] gives no bytes.
#[derive(Debug)]
pub enum Declined {
    /// The member is byte-identical to its container and is not to be walked.
    Same,
    /// The member ran past what the scan budget or its compression ratio
    /// allowed it, or the budget refused it read in place. The reader reports
    /// the limit itself once the member is left, whatever the visitor returns
    /// for it: there is nothing to scan. The walk ends with the scan budget's;
    /// it goes on with the member after one over the ratio.
    Stopped,
}

/// Take a member's bytes.
///
/// A member decoded whole is taken as it is. One read in place (a stored
/// member over the hold limit, checksums not verified) is a [`Body::Range`] of
/// the container, charged to the scan budget by its length. Any other stream
/// is read into memory up to `hold.limit`, else written to the spill with
/// what was already read first; with no spill, or if it fails, the prefix is
/// given as a [`Body::Prefix`].
pub fn intake<'a, 's>(
    meta: &MemberMeta,
    content: Option<Member<'s>>,
    hold: &Hold<'_>,
    budget: &mut Budget,
    container: &'a dyn ByteSource,
) -> Result<Intake<'a, 's>, Declined> {
    let verify = budget.should_verify_checksums();
    let range = range_member(container, meta, hold.limit, verify);
    let mut end = End::Complete;
    let mut reasons = Reasons::default();
    let mut rest = None;
    let body = match (content, range) {
        (None, _) => Body::None,
        (Some(Member::Bytes(data)), _) => Body::Mem(data),
        (Some(Member::Stream(_)), Some(sub)) => Body::Range(sub),
        (Some(Member::Stream(rdr)), None) => match hold.large {
            Large::Source => read_member(hold, rdr, verify, &mut reasons, &mut end)?,
            Large::StreamLeaves => {
                let (body, left) =
                    read_member_or_stream(hold, rdr, verify, &mut reasons, &mut end)?;
                rest = left;
                body
            }
        },
    };
    // A member byte-identical to its container, once walked, is found again
    // as the same format and yields itself, down to the recursion limit. That
    // spends the levels on one buffer and the content that needed them is
    // never reached. Its bytes are already scanned as the container, so
    // skipping it loses nothing. The guard is here, not in a reader, so that
    // it covers every format. The length test is false for nearly every real
    // member, so the comparison is rarely made.
    if is_fixed_point(&body, container) {
        return Err(Declined::Same);
    }
    // A range read in place is charged here, once taken: the walk counts only
    // what is read of the stream.
    if let Body::Range(sub) = &body
        && budget.charge_scan(sub.len() as u64).is_err()
    {
        return Err(Declined::Stopped);
    }
    // A range that runs past the end of the container is cut there, held or
    // read in place: the rest is absent, not hidden.
    if end.is_complete()
        && !matches!(body, Body::None)
        && let Some(why) = range_cut(meta, container.len())
    {
        end = End::Cut(why);
    }
    Ok(Intake {
        body,
        rest,
        end,
        reasons,
    })
}

/// Why a member declared as a range of its container ([`MemberMeta::range`])
/// is cut by the end of a container of `size` bytes; `None` when all of it is
/// there.
pub fn range_cut(meta: &MemberMeta, size: usize) -> Option<String> {
    let (off, len) = meta.range?;
    let held = (size as u64).saturating_sub(off).min(len);
    (held < len).then(|| {
        format!(
            "member '{}' is {len} bytes at {off}, past the end of its {size}-byte \
             container: only {held} bytes of it are in the container",
            super::quoted(&meta.name)
        )
    })
}

fn is_fixed_point(body: &Body<'_>, container: &dyn ByteSource) -> bool {
    match body {
        Body::Mem(data) => {
            data.len() == container.len() && *container.window(0, data.len()) == data[..]
        }
        // The range is clipped to the container, so one as long as the
        // container starts at its first byte.
        Body::Range(sub) => sub.len() == container.len(),
        Body::None | Body::Spilled(_) | Body::Prefix { .. } | Body::Stream { .. } => false,
    }
}

/// A member past the hold limit whose content is a range of its container,
/// read there: no copy, no spill. `None` for any other member, and when
/// checksums are verified, which takes reading the member's stream.
///
/// A range past what the build addresses is past the end of any container, so
/// the `Sub` is clipped to it, and the caller reports the shortfall against
/// the range the member declares.
fn range_member<'a>(
    container: &'a dyn ByteSource,
    meta: &MemberMeta,
    limit: u64,
    verify_checksums: bool,
) -> Option<Sub<'a>> {
    let (off, len) = meta.range?;
    if verify_checksums || len <= limit {
        return None;
    }
    let off = usize::try_from(off).unwrap_or(usize::MAX);
    let len = usize::try_from(len).unwrap_or(usize::MAX);
    Some(Sub::new(container, off, len))
}

fn add(reasons: &mut Reasons, kind: ReasonKind, text: String) {
    reasons.add(Reason {
        kind,
        text,
        at: String::new(),
    });
}

/// Note a member dropped for the error `e`: the content it hides is damage,
/// the rest is a member not taken.
fn drop_for(reasons: &mut Reasons, end: &End, what: &str, e: &io::Error) {
    let kind = match end {
        End::Damaged(_) => ReasonKind::Damaged,
        _ => ReasonKind::NotExtracted,
    };
    add(reasons, kind, format!("{what}: {e}"));
}

/// Read a member decoded as it is read: into memory up to the hold limit, else
/// to the spill, the prefix already read first.
///
/// A decode error keeps what was decoded before it, held or spilled, and `end`
/// says why the rest is missing.
fn read_member<'a>(
    hold: &Hold<'_>,
    rdr: &mut dyn Read,
    verify_checksums: bool,
    reasons: &mut Reasons,
    end: &mut End,
) -> Result<Body<'a>, Declined> {
    let cap = hold.limit;
    let keep = usize::try_from(cap).unwrap_or(usize::MAX);
    let mut buf = Vec::new();
    // One byte past the cap: reading exactly `cap` cannot tell a member that
    // just fits from one that does not.
    match read_capped(&mut *rdr, &mut buf, cap.saturating_add(1)) {
        Err(e) if is_budget_overflow(&e) => return Err(Declined::Stopped),
        // Nothing decoded before an error that hides nothing (the input ran
        // out inside the first block, say) is an empty prefix, not a failure.
        Err(e) if verify_checksums || (buf.is_empty() && decode_error_hides_content(&e)) => {
            *end = End::from_error(&e);
            drop_for(reasons, end, "member decode error", &e);
            return Ok(Body::None);
        }
        Err(e) => {
            buf.truncate(keep);
            *end = End::from_error(&e);
            return Ok(Body::Mem(buf));
        }
        Ok(_) if buf.len() as u64 <= cap => return Ok(Body::Mem(buf)),
        Ok(_) => {}
    }
    spill_rest(hold, buf, rdr, verify_checksums, reasons, end)
}

/// [`read_member`] for a walk that hands over a member too large to hold as a
/// stream when it is not a container ([`Large::StreamLeaves`]).
///
/// A member that fits is held. Past the cap, what has been read is looked at as
/// far as detection reaches: a container is written to the spill (it cannot be
/// opened without seeking in it), anything else is given as it stands with the
/// rest of the stream. A stream that was read to its end only to find it is
/// over the cap has all of it, and is told by it. Up to what detection reaches
/// is read whatever the cap, so that much may be held of a stream that is
/// handed over, and of one that failed.
fn read_member_or_stream<'a, 's>(
    hold: &Hold<'_>,
    rdr: &'s mut dyn Read,
    verify_checksums: bool,
    reasons: &mut Reasons,
    end: &mut End,
) -> Result<(Body<'a>, Option<&'s mut dyn Read>), Declined> {
    let cap = hold.limit;
    // One byte past the cap tells a member that fits from one that does not;
    // detection needs a start of its own length to say what it is.
    let reach = cap.saturating_add(1).max(crate::DETECT_HEAD as u64);
    let mut buf = Vec::new();
    match read_capped(&mut *rdr, &mut buf, reach) {
        Err(e) if is_budget_overflow(&e) => return Err(Declined::Stopped),
        Err(e) if verify_checksums || (buf.is_empty() && decode_error_hides_content(&e)) => {
            *end = End::from_error(&e);
            drop_for(reasons, end, "member decode error", &e);
            return Ok((Body::None, None));
        }
        // The stream cannot be read on: what was decoded is all there is.
        Err(e) => {
            *end = End::from_error(&e);
            return Ok((Body::Mem(buf), None));
        }
        Ok(_) if buf.len() as u64 <= cap => return Ok((Body::Mem(buf), None)),
        Ok(_) => {}
    }
    let whole = (buf.len() as u64) < reach;
    let settled = if whole {
        match crate::detect(&buf.as_slice()) {
            Some(format) => Settled::Is(format),
            None => Settled::Not,
        }
    } else {
        crate::detect_head(&buf)
    };
    if matches!(settled, Settled::Is(_)) {
        let body = spill_rest(hold, buf, rdr, verify_checksums, reasons, end)?;
        return Ok((body, None));
    }
    let unchecked = match settled {
        Settled::Unsettled => Some(Reason {
            kind: ReasonKind::NotChecked,
            text: format!(
                "a member over the {cap}-byte limit (--max-object-bytes) is read as it is \
                 decoded: whether it is a container that is recognised by its end, or a packed \
                 executable, was not checked"
            ),
            at: String::new(),
        }),
        // Whether an executable is packed is told from all of it, which is
        // over the cap: not checked, as for one read where it lies.
        _ if crate::executable_kind(&buf).is_some() => Some(super::engine::packer_not_checked(cap)),
        _ => None,
    };
    Ok((
        Body::Stream {
            head: buf,
            unchecked,
        },
        Some(rdr),
    ))
}

/// A member over the hold limit, of which `buf` is what was read and `rest`
/// the rest: written to the spill, or given as its prefix.
fn spill_rest<'a>(
    hold: &Hold<'_>,
    buf: Vec<u8>,
    rest: &mut dyn Read,
    verify_checksums: bool,
    reasons: &mut Reasons,
    end: &mut End,
) -> Result<Body<'a>, Declined> {
    let cap = hold.limit;
    let keep = usize::try_from(cap).unwrap_or(usize::MAX);
    // What was read is given though the rest cannot be kept. When only a
    // container is written to the spill, that is what this one is: its prefix
    // is not a file to look at, and its members are what was not examined.
    let left = match hold.large {
        Large::Source => format!("only its first {cap} bytes were examined"),
        Large::StreamLeaves => "it is a container, and its members were not examined".to_string(),
    };
    let not_spilled = |mut buf: Vec<u8>, why: &str| {
        buf.truncate(keep);
        Ok(Body::Prefix {
            data: buf,
            reason: format!(
                "a member is over the {cap}-byte limit (--max-object-bytes) and could not \
                 be spilled to disk ({why}): {left}"
            ),
        })
    };
    let Some(spill) = hold.spill else {
        return not_spilled(buf, "spilling to disk is off");
    };
    let spooled = spill_stream(
        spill,
        &mut io::Cursor::new(&buf[..]).chain(rest),
        hold.cache,
    );
    match spooled {
        Ok((_, Some(e))) if is_budget_overflow(&e) => Err(Declined::Stopped),
        Ok((_, Some(e))) if verify_checksums => {
            *end = End::from_error(&e);
            drop_for(reasons, end, "member stream error", &e);
            Ok(Body::None)
        }
        // A decode error keeps what was decoded before it, as for a held member.
        Ok((spilled, error)) => {
            if let Some(e) = &error {
                *end = End::from_error(e);
            }
            Ok(Body::Spilled(spilled))
        }
        Err(why) => not_spilled(buf, &why),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Limits;
    use crate::spill::{MemSpill, SpillReader, SpillWriter};
    use crate::stream::BudgetReader;
    use std::borrow::Cow;
    use std::cell::Cell;
    use std::io::{Cursor, ErrorKind, Seek, SeekFrom};

    /// A reader played by a closure.
    struct Played<F>(F);

    impl<F: FnMut(&mut [u8]) -> io::Result<usize>> Read for Played<F> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            (self.0)(buf)
        }
    }

    /// A reader that gives `data`, then fails with `err` on every call.
    fn failing_after(
        data: &[u8],
        err: fn() -> io::Error,
    ) -> Played<impl FnMut(&mut [u8]) -> io::Result<usize>> {
        let data = data.to_vec();
        let mut at = 0;
        Played(move |buf: &mut [u8]| {
            if at == data.len() {
                return Err(err());
            }
            let n = buf.len().min(data.len() - at);
            buf[..n].copy_from_slice(&data[at..at + n]);
            at += n;
            Ok(n)
        })
    }

    fn eof() -> io::Error {
        io::Error::from(ErrorKind::UnexpectedEof)
    }

    fn bad() -> io::Error {
        io::Error::new(ErrorKind::InvalidData, "bad block")
    }

    fn crc() -> io::Error {
        crate::checksum_mismatch("crc")
    }

    fn bytes(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    fn meta(name: &str) -> MemberMeta {
        MemberMeta {
            name: name.to_string(),
            ..MemberMeta::default()
        }
    }

    /// A member whose content is `len` bytes at `off` of its container.
    fn stored(name: &str, off: u64, len: u64) -> MemberMeta {
        MemberMeta {
            range: Some((off, len)),
            ..meta(name)
        }
    }

    fn hold<'a>(limit: u64, spill: Option<&'a dyn Spill>) -> Hold<'a> {
        Hold {
            limit,
            spill,
            cache: (16, 64),
            large: Large::Source,
        }
    }

    fn budget() -> Budget {
        Budget::new(Limits::default())
    }

    fn give<'a, 's>(
        meta: &MemberMeta,
        content: Option<Member<'s>>,
        hold: &Hold<'_>,
        budget: &mut Budget,
        container: &'a dyn ByteSource,
    ) -> Result<Intake<'a, 's>, Declined> {
        intake(meta, content, hold, budget, container)
    }

    /// The intake of `content` under a fresh budget.
    fn take<'a, 's>(
        meta: &MemberMeta,
        content: Option<Member<'s>>,
        hold: &Hold<'_>,
        container: &'a dyn ByteSource,
    ) -> Intake<'a, 's> {
        match give(meta, content, hold, &mut budget(), container) {
            Ok(intake) => intake,
            Err(declined) => panic!("declined: {declined:?}"),
        }
    }

    fn shape(body: &Body<'_>) -> &'static str {
        match body {
            Body::None => "none",
            Body::Mem(_) => "mem",
            Body::Spilled(_) => "spilled",
            Body::Prefix { .. } => "prefix",
            Body::Range(_) => "range",
            Body::Stream { .. } => "stream",
        }
    }

    /// The bytes of a body that holds them.
    fn contents(body: &Body<'_>) -> Vec<u8> {
        match body {
            Body::Mem(data) | Body::Prefix { data, .. } => data.clone(),
            Body::Spilled(s) => s.window(0, s.len()).into_owned(),
            Body::Range(s) => s.window(0, s.len()).into_owned(),
            Body::Stream { head, .. } => head.clone(),
            Body::None => panic!("no body"),
        }
    }

    fn texts(r: &Reasons) -> [Option<&str>; 3] {
        [&r.password, &r.limits, &r.unscannable].map(|x| x.as_ref().map(|r| r.text.as_str()))
    }

    #[test]
    fn a_member_decoded_whole_is_taken_as_it_is_whatever_its_size() {
        let data = bytes(10);
        let container = bytes(300);
        // Over the hold limit, and with a range over it: neither matters.
        let i = take(
            &stored("m", 0, 100),
            Some(Member::Bytes(data.clone())),
            &hold(4, None),
            &container,
        );
        assert_eq!(shape(&i.body), "mem");
        assert_eq!(contents(&i.body), data);
        assert!(i.end.is_complete() && i.reasons.is_empty());
    }

    #[test]
    fn no_content_is_no_body() {
        let container = bytes(300);
        let i = take(&stored("m", 0, 100), None, &hold(4, None), &container);
        assert_eq!(shape(&i.body), "none");
        assert!(i.end.is_complete() && i.reasons.is_empty());
    }

    #[test]
    fn a_stream_is_held_up_to_the_limit_and_spilled_past_it() {
        let container = bytes(300);
        let data = bytes(1000);
        let spill = MemSpill::new();
        for (limit, expected) in [(1000, "mem"), (999, "spilled")] {
            let mut rdr = Cursor::new(data.clone());
            let i = take(
                &meta("m"),
                Some(Member::Stream(&mut rdr)),
                &hold(limit, Some(&spill)),
                &container,
            );
            assert_eq!(shape(&i.body), expected, "limit {limit}");
            assert_eq!(contents(&i.body), data, "limit {limit}");
            assert!(i.end.is_complete() && i.reasons.is_empty());
        }
        assert_eq!(spill.made(), 1);
    }

    #[test]
    fn a_stream_past_the_limit_with_no_spill_is_a_prefix_and_says_why() {
        let data = bytes(100);
        let container = bytes(300);
        let mut rdr = Cursor::new(data.clone());
        let i = take(
            &meta("m"),
            Some(Member::Stream(&mut rdr)),
            &hold(8, None),
            &container,
        );
        let Body::Prefix {
            data: prefix,
            reason,
        } = i.body
        else {
            panic!("not a prefix");
        };
        assert_eq!(prefix, data[..8]);
        assert_eq!(
            reason,
            "a member is over the 8-byte limit (--max-object-bytes) and could not \
             be spilled to disk (spilling to disk is off): only its first 8 bytes \
             were examined"
        );
        assert!(i.end.is_complete() && i.reasons.is_empty());
    }

    #[test]
    fn a_spill_that_cannot_be_written_leaves_the_prefix_and_its_reason() {
        let data = bytes(100);
        let container = bytes(300);
        let spill = MemSpill::with_file_limit(10);
        let mut rdr = Cursor::new(data.clone());
        let i = take(
            &meta("m"),
            Some(Member::Stream(&mut rdr)),
            &hold(8, Some(&spill)),
            &container,
        );
        assert_eq!(spill.made(), 1);
        let Body::Prefix {
            data: prefix,
            reason,
        } = i.body
        else {
            panic!("not a prefix");
        };
        assert_eq!(prefix, data[..8]);
        assert!(
            reason.ends_with(
                "could not be spilled to disk (spill budget): only its first 8 bytes were examined"
            ),
            "{reason}"
        );
    }

    #[test]
    fn a_stream_past_what_the_budget_has_left_stops_the_walk() {
        let container = bytes(300);
        let spill = MemSpill::new();
        // Held: the overflow comes inside the first read. Spilled: past the limit.
        for (limit, spill) in [(100, None), (4, Some(&spill as &dyn Spill))] {
            let mut src = Cursor::new(bytes(50));
            let mut capped = BudgetReader::new(&mut src, 10);
            let taken = give(
                &meta("m"),
                Some(Member::Stream(&mut capped)),
                &hold(limit, spill),
                &mut budget(),
                &container,
            );
            assert!(matches!(taken, Err(Declined::Stopped)), "limit {limit}");
        }
    }

    #[test]
    fn a_stream_cut_short_keeps_what_was_decoded_and_ends_cut() {
        let container = bytes(300);
        // An empty prefix is a prefix, not a failure.
        for data in [bytes(5), Vec::new()] {
            let mut rdr = failing_after(&data, eof);
            let i = take(
                &meta("m"),
                Some(Member::Stream(&mut rdr)),
                &hold(100, None),
                &container,
            );
            assert_eq!(shape(&i.body), "mem");
            assert_eq!(contents(&i.body), data);
            assert!(matches!(i.end, End::Cut(_)), "{:?}", i.end);
            assert!(i.reasons.is_empty());
        }
    }

    #[test]
    fn a_checksum_mismatch_after_a_full_decode_ends_cut() {
        let container = bytes(300);
        for data in [bytes(5), Vec::new()] {
            let mut rdr = failing_after(&data, crc);
            let i = take(
                &meta("m"),
                Some(Member::Stream(&mut rdr)),
                &hold(100, None),
                &container,
            );
            assert_eq!(shape(&i.body), "mem");
            assert_eq!(contents(&i.body), data);
            assert!(matches!(i.end, End::Cut(_)), "{:?}", i.end);
            assert!(i.reasons.is_empty());
        }
    }

    #[test]
    fn damage_after_some_bytes_keeps_them_and_ends_damaged() {
        let data = bytes(5);
        let container = bytes(300);
        let mut rdr = failing_after(&data, bad);
        let i = take(
            &meta("m"),
            Some(Member::Stream(&mut rdr)),
            &hold(100, None),
            &container,
        );
        assert_eq!(shape(&i.body), "mem");
        assert_eq!(contents(&i.body), data);
        assert_eq!(i.end, End::Damaged("bad block".to_string()));
        assert!(i.reasons.is_empty());
    }

    #[test]
    fn damage_before_any_byte_drops_the_member_with_a_reason() {
        let container = bytes(300);
        let mut rdr = failing_after(&[], bad);
        let i = take(
            &meta("m"),
            Some(Member::Stream(&mut rdr)),
            &hold(100, None),
            &container,
        );
        assert_eq!(shape(&i.body), "none");
        assert_eq!(i.end, End::Damaged("bad block".to_string()));
        assert_eq!(
            texts(&i.reasons),
            [None, None, Some("member decode error: bad block")]
        );
        let reason = i.reasons.unscannable.unwrap();
        assert_eq!(reason.kind, ReasonKind::Damaged);
        assert_eq!(reason.at, "");
    }

    #[test]
    fn a_stream_that_fails_past_the_limit_is_spilled_up_to_the_error() {
        let container = bytes(300);
        let data = bytes(1000);
        let spill = MemSpill::new();
        let cases: [(fn() -> io::Error, bool); 3] = [(bad, true), (eof, false), (crc, false)];
        for (err, damaged) in cases {
            let mut rdr = failing_after(&data, err);
            let i = take(
                &meta("m"),
                Some(Member::Stream(&mut rdr)),
                &hold(8, Some(&spill)),
                &container,
            );
            assert_eq!(shape(&i.body), "spilled");
            assert_eq!(contents(&i.body), data);
            assert_eq!(matches!(i.end, End::Damaged(_)), damaged, "{:?}", i.end);
            assert!(!i.end.is_complete());
            assert!(i.reasons.is_empty());
        }
    }

    #[cfg(feature = "checksums")]
    #[test]
    fn with_checksums_verified_a_failing_stream_is_dropped_whole() {
        let container = bytes(300);
        let spill = MemSpill::new();
        let mut b = budget();
        b.set_verify_checksums(true);
        // Held, and spilled: a checksum mismatch hides nothing, and still drops it.
        for (data, limit, what) in [(bytes(5), 100, "decode"), (bytes(1000), 8, "stream")] {
            let mut rdr = failing_after(&data, crc);
            let Ok(i) = give(
                &meta("m"),
                Some(Member::Stream(&mut rdr)),
                &hold(limit, Some(&spill)),
                &mut b,
                &container,
            ) else {
                panic!("not read");
            };
            assert_eq!(shape(&i.body), "none", "{what}");
            assert!(matches!(i.end, End::Cut(_)), "{what}");
            let reason = i.reasons.unscannable.unwrap();
            assert_eq!(reason.kind, ReasonKind::NotExtracted);
            assert_eq!(
                reason.text,
                format!("member {what} error: {}", crc()),
                "{what}"
            );
        }
        // A stream that decodes is kept as it is.
        let data = bytes(1000);
        for limit in [2000, 8] {
            let mut rdr = Cursor::new(data.clone());
            let Ok(i) = give(
                &meta("m"),
                Some(Member::Stream(&mut rdr)),
                &hold(limit, Some(&spill)),
                &mut b,
                &container,
            ) else {
                panic!("not read");
            };
            assert_eq!(contents(&i.body), data);
            assert!(i.end.is_complete() && i.reasons.is_empty());
        }
    }

    #[cfg(feature = "checksums")]
    #[test]
    fn with_checksums_verified_a_stored_member_is_read_through_its_stream() {
        let container = bytes(100);
        let mut b = budget();
        b.set_verify_checksums(true);
        let spill = MemSpill::new();
        let mut rdr = Cursor::new(container[20..80].to_vec());
        let Ok(i) = give(
            &stored("m", 20, 60),
            Some(Member::Stream(&mut rdr)),
            &hold(40, Some(&spill)),
            &mut b,
            &container,
        ) else {
            panic!("not read");
        };
        assert_eq!(shape(&i.body), "spilled");
        assert_eq!(contents(&i.body), container[20..80]);
        assert_eq!(b.scanned, 0);
    }

    #[test]
    fn a_stored_member_over_the_limit_is_read_in_place_and_charged_by_its_length() {
        let container = bytes(100);
        let m = stored("m", 20, 60);
        let mut rdr = Played(|_: &mut [u8]| -> io::Result<usize> { panic!("the stream is read") });
        let mut b = budget();
        let Ok(i) = give(
            &m,
            Some(Member::Stream(&mut rdr)),
            &hold(40, None),
            &mut b,
            &container,
        ) else {
            panic!("not read");
        };
        assert_eq!(shape(&i.body), "range");
        assert_eq!(contents(&i.body), container[20..80]);
        assert_eq!(b.scanned, 60);
        assert!(i.end.is_complete() && i.reasons.is_empty());
        assert!(i.body.unread().is_empty());
    }

    #[test]
    fn a_stored_member_within_the_limit_is_read_from_its_stream() {
        let container = bytes(100);
        let mut rdr = Cursor::new(container[20..60].to_vec());
        let mut b = budget();
        let Ok(i) = give(
            &stored("m", 20, 40),
            Some(Member::Stream(&mut rdr)),
            &hold(40, None),
            &mut b,
            &container,
        ) else {
            panic!("not read");
        };
        assert_eq!(shape(&i.body), "mem");
        assert_eq!(contents(&i.body), container[20..60]);
        assert_eq!(b.scanned, 0);
    }

    #[test]
    fn the_scan_budget_refuses_a_member_read_in_place_by_its_length() {
        let container = bytes(100);
        for (max, refused) in [(59, true), (60, false)] {
            let mut b = Budget::new(Limits {
                max_scanned_bytes: max,
                ..Limits::default()
            });
            let mut rdr = Cursor::new(Vec::new());
            let taken = give(
                &stored("m", 20, 60),
                Some(Member::Stream(&mut rdr)),
                &hold(40, None),
                &mut b,
                &container,
            );
            match taken {
                Err(Declined::Stopped) => assert!(refused, "max {max}"),
                Ok(i) => {
                    assert!(!refused, "max {max}");
                    assert_eq!(shape(&i.body), "range");
                }
                _ => panic!("max {max}: neither"),
            }
        }
    }

    #[test]
    fn a_range_past_the_end_of_its_container_is_clipped_and_cut() {
        let container = bytes(100);
        // (offset, length, bytes in the container, how the cut is told)
        let cases = [
            (40, 60, 60, None),
            (
                80,
                60,
                20,
                Some(
                    "member 'm' is 60 bytes at 80, past the end of its 100-byte container: \
                     only 20 bytes of it are in the container",
                ),
            ),
            (
                150,
                60,
                0,
                Some(
                    "member 'm' is 60 bytes at 150, past the end of its 100-byte container: \
                     only 0 bytes of it are in the container",
                ),
            ),
        ];
        // Over the hold limit it is read where it lies; under it, its stream
        // (what the container has of it) is held. The same either way: the
        // node is cut, and nothing is unread.
        for (limit, want) in [(10, "range"), (1000, "mem")] {
            for (off, len, held, text) in cases {
                let m = stored("m", off, len);
                let start = (off as usize).min(container.len());
                let mut rdr = Cursor::new(container[start..start + held].to_vec());
                let i = take(
                    &m,
                    Some(Member::Stream(&mut rdr)),
                    &hold(limit, None),
                    &container,
                );
                assert_eq!(shape(&i.body), want, "at {off}");
                assert_eq!(contents(&i.body).len(), held, "{want} at {off}");
                match (&i.end, text) {
                    (End::Complete, None) => {}
                    (End::Cut(why), Some(text)) => assert_eq!(why, text, "{want} at {off}"),
                    (end, _) => panic!("{want} at {off}: {end:?}"),
                }
                assert!(i.body.unread().is_empty(), "{want} at {off}");
            }
        }
    }

    /// A range that does not fit the build's `usize` is past the end of its
    /// container: it reads nothing, it does not wrap to an offset that does.
    #[test]
    fn a_member_range_past_the_address_space_reads_nothing() {
        let container = vec![7u8; 100];
        let sub_of = |off: u64, len: u64| {
            range_member(&container, &stored("m", off, len), 8, false)
                .expect("a range over the limit")
                .len()
        };
        // 2^32 + 5 wraps to 5 on a 32-bit target.
        assert_eq!(sub_of((1 << 32) + 5, 20), 0);
        assert_eq!(sub_of(u64::MAX - 1, u64::MAX), 0);
        // A length that does not fit is the rest of the container.
        assert_eq!(sub_of(50, (1 << 32) + 20), 50);
        assert_eq!(sub_of(50, u64::MAX), 50);
        assert_eq!(sub_of(10, 20), 20);
    }

    #[test]
    fn a_member_identical_to_its_container_is_not_taken() {
        let container = bytes(300);
        let h = hold(1000, None);
        let mut b = budget();
        let mut same = |meta: &MemberMeta, content: Member<'_>, h: &Hold<'_>| {
            matches!(
                give(meta, Some(content), h, &mut b, &container),
                Err(Declined::Same)
            )
        };
        // By its bytes, decoded whole or read from a held stream.
        let m = meta("m");
        assert!(same(&m, Member::Bytes(container.clone()), &h));
        let mut rdr = Cursor::new(container.clone());
        assert!(same(&m, Member::Stream(&mut rdr), &h));
        // One byte different, or one longer.
        let mut other = container.clone();
        other[299] ^= 1;
        assert!(!same(&m, Member::Bytes(other), &h));
        let mut longer = container.clone();
        longer.push(0);
        assert!(!same(&m, Member::Bytes(longer), &h));
        // By its range: all of the container, or more of it than there is.
        let h = hold(100, None);
        for (off, len, expected) in [
            (0, 300, true),
            (0, 400, true),
            (0, 299, false),
            (1, 300, false),
        ] {
            let mut rdr = Cursor::new(Vec::new());
            let got = same(&stored("m", off, len), Member::Stream(&mut rdr), &h);
            assert_eq!(got, expected, "range {off}+{len}");
        }
        // A copy not taken is not charged; only the two ranges taken are.
        assert_eq!(b.scanned, 299 + 299);
    }

    #[test]
    fn a_read_error_of_an_in_place_or_spilled_body_shows_once_it_is_read() {
        // In place: the container fails when it is read.
        struct Broken(Cell<bool>);
        impl ByteSource for Broken {
            fn len(&self) -> usize {
                100
            }
            fn window(&self, _: usize, _: usize) -> Cow<'_, [u8]> {
                self.0.set(true);
                Cow::Borrowed(&[])
            }
            fn read_error(&self) -> Option<String> {
                self.0.get().then(|| "disk gone".to_string())
            }
            fn identity(&self) -> (usize, usize) {
                (0, 100)
            }
        }
        let container = Broken(Cell::new(false));
        let m = stored("m", 0, 60);
        let mut rdr = Cursor::new(Vec::new());
        let i = take(
            &m,
            Some(Member::Stream(&mut rdr)),
            &hold(10, None),
            &container,
        );
        assert_eq!(shape(&i.body), "range");
        assert!(i.body.unread().is_empty());
        let Body::Range(sub) = &i.body else {
            unreachable!()
        };
        sub.window(0, 10);
        let unread = i.body.unread();
        assert_eq!(
            texts(&unread),
            [None, None, Some("member unreadable: disk gone")]
        );
        assert_eq!(unread.unscannable.unwrap().kind, ReasonKind::ReadFailed);

        // Spilled: the spill file fails when it is read.
        struct Dead(u64);
        impl Read for Dead {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("disk gone"))
            }
        }
        impl Seek for Dead {
            fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
                Ok(match to {
                    SeekFrom::End(_) => self.0,
                    SeekFrom::Start(n) => n,
                    SeekFrom::Current(_) => 0,
                })
            }
        }
        struct DeadSpill;
        struct DeadWriter(u64);
        impl Spill for DeadSpill {
            fn create(&self) -> Result<Box<dyn SpillWriter>, String> {
                Ok(Box::new(DeadWriter(0)))
            }
        }
        impl SpillWriter for DeadWriter {
            fn write(&mut self, bytes: &[u8]) -> Result<(), String> {
                self.0 += bytes.len() as u64;
                Ok(())
            }
            fn finish(self: Box<Self>) -> Result<Box<dyn SpillReader>, String> {
                Ok(Box::new(Dead(self.0)))
            }
        }
        let m = meta("m");
        let container = bytes(300);
        let mut rdr = Cursor::new(bytes(100));
        let i = take(
            &m,
            Some(Member::Stream(&mut rdr)),
            &hold(10, Some(&DeadSpill)),
            &container,
        );
        assert_eq!(shape(&i.body), "spilled");
        assert!(i.body.unread().is_empty());
        let Body::Spilled(spilled) = &i.body else {
            unreachable!()
        };
        spilled.window(0, 10);
        let unread = i.body.unread();
        assert_eq!(
            texts(&unread),
            [
                None,
                None,
                Some("spilled member unreadable: read at 0 failed: disk gone")
            ]
        );
        assert_eq!(unread.unscannable.unwrap().kind, ReasonKind::ReadFailed);
    }

    /// A walk that hands over what is not a container as a stream.
    fn leaves<'a>(limit: u64, spill: Option<&'a dyn Spill>) -> Hold<'a> {
        Hold {
            large: Large::StreamLeaves,
            ..hold(limit, spill)
        }
    }

    /// The rest of the stream a body goes on in.
    fn rest_of(i: &mut Intake<'_, '_>) -> Vec<u8> {
        let mut out = Vec::new();
        i.rest
            .take()
            .expect("a stream goes on")
            .read_to_end(&mut out)
            .unwrap();
        out
    }

    #[test]
    fn a_stream_that_fits_is_held_whether_or_not_leaves_are_streamed() {
        let container = bytes(300);
        let mut rdr = Cursor::new(bytes(8));
        let i = take(
            &meta("m"),
            Some(Member::Stream(&mut rdr)),
            &leaves(8, None),
            &container,
        );
        assert_eq!(shape(&i.body), "mem");
        assert_eq!(contents(&i.body), bytes(8));
        assert!(i.rest.is_none());
    }

    #[test]
    fn a_stream_over_the_limit_read_to_its_end_and_no_container_is_given_whole() {
        let container = bytes(300);
        let text = b"plain text, line after line\n".repeat(10);
        let mut rdr = Cursor::new(text.clone());
        let mut i = take(
            &meta("m"),
            Some(Member::Stream(&mut rdr)),
            &leaves(8, None),
            &container,
        );
        let Body::Stream { head, unchecked } = &i.body else {
            panic!("not a stream: {}", shape(&i.body));
        };
        // All of it was read, to find it is over the limit, and it is known to
        // be no container: nothing is left to say.
        assert_eq!(head, &text);
        assert!(unchecked.is_none());
        assert!(rest_of(&mut i).is_empty());
        assert!(i.end.is_complete() && i.reasons.is_empty());
    }

    #[test]
    fn an_executable_stream_over_the_limit_read_to_its_end_says_its_packer_was_not_checked() {
        let container = bytes(300);
        let mut exe = b"MZ".to_vec();
        exe.resize(100, 0);
        let mut rdr = Cursor::new(exe.clone());
        let i = take(
            &meta("m"),
            Some(Member::Stream(&mut rdr)),
            &leaves(8, None),
            &container,
        );
        let Body::Stream { head, unchecked } = &i.body else {
            panic!("not a stream: {}", shape(&i.body));
        };
        assert_eq!(head, &exe);
        let why = unchecked.as_ref().expect("not checked");
        assert_eq!(
            (why.kind, why.text.as_str()),
            (
                ReasonKind::NotChecked,
                "an executable over the 8-byte limit: whether it is packed was not checked"
            )
        );
    }

    #[test]
    fn a_stream_longer_than_detection_reaches_is_given_by_its_start_and_what_was_not_checked() {
        let container = bytes(300);
        let total = crate::DETECT_HEAD + 5000;
        let mut rdr = Cursor::new(vec![b'a'; total]);
        let mut i = take(
            &meta("m"),
            Some(Member::Stream(&mut rdr)),
            &leaves(8, None),
            &container,
        );
        let Body::Stream { head, unchecked } = &i.body else {
            panic!("not a stream: {}", shape(&i.body));
        };
        assert_eq!(head.len(), crate::DETECT_HEAD);
        let why = unchecked.as_ref().expect("not checked");
        assert_eq!(why.kind, ReasonKind::NotChecked);
        assert!(
            why.text
                .starts_with("a member over the 8-byte limit (--max-object-bytes)")
                && why.text.ends_with("was not checked"),
            "{}",
            why.text
        );
        assert_eq!(rest_of(&mut i).len(), 5000);
    }

    /// An InstallShield installer is told by a marker found anywhere in the
    /// first 4 MiB, with a record after it: a stream is read that far before
    /// it is said to be no container, whatever its limit.
    #[test]
    fn a_stream_told_a_container_by_a_marker_deep_in_its_start_is_spilled() {
        let container = bytes(300);
        let tag = b"InstallShield\0";
        for (total, at) in [(200_000, 100_000), (5 << 20, 3 << 20)] {
            let mut data = vec![b' '; total];
            data[at..at + tag.len()].copy_from_slice(tag);
            let record = at + tag.len() + 292;
            data[record..record + 8].copy_from_slice(&[6, 0, 0, 0, 0, 0, 0, 0]);
            data[record + 16..record + 21].copy_from_slice(&[0, 0, 0, 0, 1]);
            assert_eq!(
                crate::detect(&data.as_slice()),
                Some(crate::Format::IshieldMsi),
                "the fixture is one: {total}"
            );
            let spill = MemSpill::new();
            let mut rdr = Cursor::new(data.clone());
            let i = take(
                &meta("m"),
                Some(Member::Stream(&mut rdr)),
                &leaves(8, Some(&spill)),
                &container,
            );
            assert_eq!(shape(&i.body), "spilled", "{total}");
            assert_eq!(contents(&i.body), data, "{total}");
        }
    }

    #[test]
    fn a_stream_over_the_limit_that_starts_as_a_container_is_spilled_or_given_as_its_prefix() {
        let container = bytes(300);
        // A ZIP's local header, then bytes: a container by its start. Both
        // when it ends in its start and when it is longer than that.
        for total in [200, crate::DETECT_HEAD + 5000] {
            let mut data = b"PK\x03\x04".to_vec();
            data.resize(total, 7);
            let spill = MemSpill::new();
            let mut rdr = Cursor::new(data.clone());
            let i = take(
                &meta("m"),
                Some(Member::Stream(&mut rdr)),
                &leaves(8, Some(&spill)),
                &container,
            );
            assert_eq!(shape(&i.body), "spilled", "{total}");
            assert_eq!(contents(&i.body), data, "{total}");
            assert!(i.rest.is_none());
            // With nowhere to write, the prefix and why.
            let mut rdr = Cursor::new(data.clone());
            let i = take(
                &meta("m"),
                Some(Member::Stream(&mut rdr)),
                &leaves(8, None),
                &container,
            );
            let Body::Prefix {
                data: prefix,
                reason,
            } = &i.body
            else {
                panic!("not a prefix: {}", shape(&i.body));
            };
            assert_eq!(prefix, &data[..8]);
            assert_eq!(
                reason,
                "a member is over the 8-byte limit (--max-object-bytes) and could not be \
                 spilled to disk (spilling to disk is off): it is a container, and its \
                 members were not examined"
            );
            assert!(i.rest.is_none());
        }
    }

    #[test]
    fn a_stream_that_fails_past_the_limit_is_held_as_far_as_it_decoded() {
        let container = bytes(300);
        // Failing after the limit and within what detection reaches: all of
        // what decoded is kept, not cut at the limit.
        let data = vec![b'a'; 50];
        let mut rdr = failing_after(&data, bad);
        let i = take(
            &meta("m"),
            Some(Member::Stream(&mut rdr)),
            &leaves(8, None),
            &container,
        );
        assert_eq!(shape(&i.body), "mem");
        assert_eq!(contents(&i.body), data);
        assert!(matches!(i.end, End::Damaged(_)), "{:?}", i.end);
        assert!(i.rest.is_none());
        // Within the limit, as for a member held.
        let mut rdr = failing_after(&data[..5], eof);
        let i = take(
            &meta("m"),
            Some(Member::Stream(&mut rdr)),
            &leaves(8, None),
            &container,
        );
        assert_eq!(contents(&i.body), &data[..5]);
        assert!(matches!(i.end, End::Cut(_)), "{:?}", i.end);
    }

    #[test]
    fn a_stream_of_which_nothing_decoded_is_no_body_whether_or_not_leaves_are_streamed() {
        let container = bytes(300);
        let mut rdr = failing_after(&[], bad);
        let i = take(
            &meta("m"),
            Some(Member::Stream(&mut rdr)),
            &leaves(8, None),
            &container,
        );
        assert_eq!(shape(&i.body), "none");
        assert!(matches!(i.end, End::Damaged(_)));
        assert_eq!(texts(&i.reasons)[2], Some("member decode error: bad block"));
    }

    #[test]
    fn a_stream_past_what_the_budget_has_left_stops_the_walk_when_leaves_are_streamed() {
        let container = bytes(300);
        let mut src = Cursor::new(bytes(50));
        let mut capped = BudgetReader::new(&mut src, 10);
        let taken = give(
            &meta("m"),
            Some(Member::Stream(&mut capped)),
            &leaves(4, None),
            &mut budget(),
            &container,
        );
        assert!(matches!(taken, Err(Declined::Stopped)));
    }
}
