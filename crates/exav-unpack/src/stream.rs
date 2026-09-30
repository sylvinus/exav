//! The walk over a container's members: [`walk`].
//!
//! Every format goes through it. A format whose decoder can produce a member
//! as it is read hands the visitor a [`Member::Stream`], so a member of any
//! size is never held here; the rest decode each member whole and hand it
//! over as [`Member::Bytes`]. A format whose parser needs the whole container
//! gets it from the source, without a copy when the container is in memory,
//! and is refused as over the buffer limit when it is larger. Bomb defenses
//! are enforced as bytes flow, through [`BudgetReader`].
//!
//! Any buffering of a streamed member (to run the checks that need it whole)
//! is the caller's decision, made in `exav-core`.

use crate::source::ByteSource;
use crate::{Budget, Format, LimitHit};
use std::io::{self, Read, Seek};

/// Sentinel wrapped in an `io::Error` when a member's decoded bytes exceed its
/// reserved budget. The extraction walk recognises it and converts it to a
/// [`LimitHit`] (→ `LimitsExceeded`), so a bomb is never a silent truncation.
const BUDGET_OVERFLOW: &str = "exav:member-budget-overflow";

/// A `Read` that yields at most `cap` bytes from `inner`, counting what it
/// delivers and refusing to deliver a single byte past the cap. When `inner`
/// still has data at the cap, the next `read` fails with `BUDGET_OVERFLOW`
/// rather than returning EOF — so an over-budget (bomb) member is reported, not
/// silently cut short and treated as fully scanned.
pub(crate) struct BudgetReader<'a> {
    inner: &'a mut dyn Read,
    cap: u64,
    count: u64,
    overflowed: bool,
    done: bool,
}

impl<'a> BudgetReader<'a> {
    fn new(inner: &'a mut dyn Read, cap: u64) -> Self {
        Self {
            inner,
            cap,
            count: 0,
            overflowed: false,
            done: false,
        }
    }

    /// Bytes actually delivered to the caller so far.
    #[cfg(test)]
    fn count(&self) -> u64 {
        self.count
    }
}

impl Read for BudgetReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.done {
            return Ok(0);
        }
        let room = self.cap - self.count;
        if room == 0 {
            // At the cap. Probe one byte: if the member has more, it is a bomb.
            let mut probe = [0u8; 1];
            match self.inner.read(&mut probe)? {
                0 => {
                    self.done = true;
                    Ok(0)
                }
                _ => {
                    self.overflowed = true;
                    self.done = true;
                    Err(io::Error::other(BUDGET_OVERFLOW))
                }
            }
        } else {
            let want = (buf.len() as u64).min(room) as usize;
            let n = self.inner.read(&mut buf[..want])?;
            self.count += n as u64;
            if n == 0 {
                self.done = true;
            }
            Ok(n)
        }
    }
}

/// Metadata for a member handed to a [`walk`] visitor.
#[derive(Debug, Clone)]
pub struct MemberMeta {
    pub name: String,
    /// Compressed size within the container (for `.cdb` matching), or the
    /// decompressed length when the extractor can't report it.
    pub comp_size: u64,
    /// The decoded size the container declares for the member, when it
    /// declares one: what an index lists without decoding anything. Declared,
    /// not measured, so a hostile container can make it anything.
    pub size: Option<u64>,
    pub encrypted: bool,
    /// `Some(reason)` when the member is recognised but its content can't be
    /// decoded, or not all of it (unsupported method, encryption with no
    /// matching password, damage part way). What was decoded, if anything,
    /// still comes with it.
    pub unsupported: Option<&'static str>,
}

/// A member's content.
pub enum Member<'a> {
    /// Decoded in full.
    Bytes(Vec<u8>),
    /// Decoded as it is read, up to what the scan budget has left. Reading
    /// past that fails with an error [`is_budget_overflow`] recognises.
    Stream(&'a mut dyn Read),
}

impl Member<'_> {
    /// The member's bytes, a streamed one read whole under the bound a member
    /// decoded whole has ([`Budget::reserve`]). The flag is set when decoding
    /// failed part way; the bytes before the failure are kept.
    pub fn into_bytes(
        self,
        meta: &MemberMeta,
        budget: &mut Budget,
    ) -> Result<(Vec<u8>, bool), LimitHit> {
        let reader = match self {
            Member::Bytes(data) => return Ok((data, false)),
            Member::Stream(reader) => reader,
        };
        let name = &meta.name;
        let cap = budget.reserve()?;
        let mut data = Vec::new();
        let partial = match reader.take(cap.saturating_add(1)).read_to_end(&mut data) {
            Ok(_) => false,
            Err(e) if is_budget_overflow(&e) => {
                return Err(LimitHit::new(format!("member '{name}': {e}")));
            }
            Err(e) if budget.should_verify_checksums() => {
                return Err(LimitHit::corrupt(format!("member '{name}': {e}")));
            }
            Err(e) => crate::decode_error_hides_content(&e),
        };
        if data.len() as u64 > cap {
            return Err(LimitHit::new(format!("member '{name}' exceeds budget")));
        }
        budget.commit(data.len() as u64);
        Ok((data, partial))
    }
}

/// Visitor for [`walk`]: each member's metadata and its content, `None` when
/// none could be produced. Returning `Some(T)` stops the walk; later members
/// are never touched.
pub type Visit<'a, T> =
    &'a mut dyn FnMut(&MemberMeta, Option<Member<'_>>, &mut Budget) -> Option<T>;

/// Walk the members of `src`, a container of format `fmt`, handing each to
/// `visit`. `Ok(Some(t))` when the visitor stopped the walk, `Err` when a
/// budget ran out or the container could not be read.
///
/// Every member is counted toward [`crate::Limits::max_members`], and its
/// decoded bytes are charged to the scan budget as they are produced.
///
/// Panic containment: some third-party decoders panic on crafted input instead
/// of returning an error. The whole dispatch runs inside `catch_unwind`, so a
/// panic becomes undecodable content rather than a crash. This crate is
/// `#![forbid(unsafe_code)]`, so there is no undefined behaviour to leak
/// across the boundary. What it does not contain: an allocation large enough
/// to abort, stack exhaustion, and a loop that neither allocates nor returns.
/// The daemon bounds those with process limits; a one-shot run and a library
/// embedding have no equivalent (see `SECURITY.md`).
pub fn walk<T>(
    fmt: Format,
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<T>,
) -> Result<Option<T>, LimitHit> {
    // A format the caller excluded at runtime is reported, not skipped: the
    // container is there, exav declined to open it, and the scan has to be
    // able to say so. Every walk, nested ones included, passes through here.
    if !budget.limits().allows(fmt) {
        let meta = MemberMeta {
            name: format!("{fmt:?}"),
            comp_size: src.len() as u64,
            size: None,
            encrypted: false,
            unsupported: Some("format excluded by the caller's allowed_formats"),
        };
        return Ok(visit(&meta, None, budget));
    }
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        dispatch(fmt, src, budget, visit)
    }));
    match caught {
        // A decoder that met a failed read sees it as the end of its input, so
        // a walk that finished may still have missed the rest of the container.
        Ok(Ok(None)) => match src.read_error() {
            Some(e) => Err(LimitHit::corrupt(format!("{fmt:?}: {e}"))),
            None => Ok(None),
        },
        Ok(r) => r,
        Err(_) => Err(LimitHit::corrupt(format!(
            "{fmt:?} decoder panicked on malformed input"
        ))),
    }
}

/// How far into a container the testing-faults marker is looked for.
#[cfg(feature = "testing-faults")]
const PROVOKE_REACH: usize = 64 * 1024 * 1024;

/// Format dispatch for [`walk`], inside its panic boundary. A format whose
/// members can come out as they are read has its own `walk` (7z's reads the
/// container whole, then streams its members); every other one is read whole
/// ([`whole`]).
// In a build with no streamed format, every format takes the last arm.
#[allow(unreachable_code, unused_variables)]
fn dispatch<T>(
    fmt: Format,
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<T>,
) -> Result<Option<T>, LimitHit> {
    // Fail on demand, to test the containment boundary rather than the
    // decoders. The marker is looked for anywhere in the container's first
    // bytes, so it can be carried inside a well-formed one.
    #[cfg(feature = "testing-faults")]
    crate::provoke(&src.window(0, PROVOKE_REACH));
    #[allow(unused_imports)]
    use crate::formats as f;
    type WalkFn<T> = fn(&dyn ByteSource, &mut Budget, Visit<T>) -> Result<Option<T>, LimitHit>;
    let walk: WalkFn<T> = match fmt {
        #[cfg(feature = "gzip")]
        Format::Gzip => f::gzip::walk,
        #[cfg(feature = "bzip2")]
        Format::Bzip2 => f::bzip2::walk,
        #[cfg(feature = "lzw")]
        Format::Lzw => f::lzw::walk,
        #[cfg(feature = "lz4")]
        Format::Lz4 => f::lz4::walk,
        #[cfg(feature = "xz")]
        Format::Xz => f::xz::walk,
        #[cfg(feature = "zstd")]
        Format::Zstd => f::zstd::walk,
        #[cfg(feature = "lzip")]
        Format::Lzip => f::lzip::walk,
        #[cfg(feature = "sevenz")]
        Format::SevenZip => f::sevenz::walk,
        #[cfg(feature = "cab")]
        Format::Cab => f::cab::walk,
        #[cfg(feature = "tar")]
        Format::Tar => f::tar::walk,
        #[cfg(feature = "zip")]
        Format::Zip => f::zip::walk,
        #[cfg(feature = "lha")]
        Format::Lha => f::lha::walk,
        #[cfg(feature = "ar")]
        Format::Ar => f::ar::walk,
        #[cfg(feature = "cpio")]
        Format::Cpio => f::cpio::walk,
        #[cfg(feature = "machofat")]
        Format::Machofat => f::machofat::walk,
        #[cfg(feature = "pyc")]
        Format::Pyc => f::pyc::walk,
        #[cfg(feature = "sfx")]
        Format::Sfx => f::sfx::walk,
        #[cfg(feature = "tnef")]
        Format::Tnef => f::tnef::walk,
        #[cfg(feature = "partition")]
        Format::Partition => f::partition::walk,
        #[cfg(feature = "iso")]
        Format::Iso => f::iso::walk,
        #[cfg(feature = "onenote")]
        Format::OneNote => f::onenote::walk,
        #[cfg(feature = "swf")]
        Format::Swf => f::swf::walk,
        #[cfg(feature = "dmg")]
        Format::Dmg => f::dmg::walk,
        #[cfg(feature = "szdd")]
        Format::Szdd => f::szdd::walk,
        _ => return whole(fmt, src, budget, visit),
    };
    walk(src, budget, visit)
}

/// The member of a single-stream compressor.
#[allow(dead_code)]
pub(crate) fn single_meta(
    name: &str,
    src: &dyn ByteSource,
    unsupported: Option<&'static str>,
) -> MemberMeta {
    MemberMeta {
        name: name.to_string(),
        comp_size: src.len() as u64,
        size: None,
        encrypted: false,
        unsupported,
    }
}

/// All of `src`, for a format whose parser needs the whole container: the
/// bytes themselves when they are in memory, else read into memory up to the
/// buffer limit.
pub(crate) fn read_whole<'a>(
    fmt: Format,
    src: &'a dyn ByteSource,
    budget: &Budget,
) -> Result<std::borrow::Cow<'a, [u8]>, LimitHit> {
    let max = budget.limits.max_buffer_bytes;
    match src.materialize(usize::try_from(max).unwrap_or(usize::MAX)) {
        Some(data) => Ok(data),
        None if src.len() as u64 > max => Err(LimitHit::new(format!(
            "{fmt:?} container is {} bytes, over the {max}-byte buffer limit \
             (--max-object-bytes), and its format is read whole: its members \
             were not scanned",
            src.len()
        ))),
        None => Err(LimitHit::corrupt(format!(
            "{fmt:?}: {}",
            src.read_error()
                .unwrap_or_else(|| "the source ended early".to_string())
        ))),
    }
}

/// A format whose parser needs the whole container and decodes each member
/// whole.
pub(crate) fn whole<T>(
    fmt: Format,
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<T>,
) -> Result<Option<T>, LimitHit> {
    let data = read_whole(fmt, src, budget)?;
    let stopped = crate::dispatch_extract(fmt, &data, budget, &mut |e: crate::Entry,
                                                                    budget: &mut Budget|
     -> Option<
        Result<T, LimitHit>,
    > {
        emit_entry(e, budget, visit).transpose()
    })?;
    stopped.transpose()
}

/// Hand the visitor a member an extractor decoded whole.
pub(crate) fn emit_entry<T>(
    e: crate::Entry,
    budget: &mut Budget,
    visit: Visit<T>,
) -> Result<Option<T>, LimitHit> {
    let meta = MemberMeta {
        name: e.name,
        comp_size: e.comp_size,
        size: e.unsupported.is_none().then_some(e.data.len() as u64),
        encrypted: e.encrypted,
        unsupported: e.unsupported,
    };
    // An unsupported member may still carry what was decoded of it.
    let content = (e.unsupported.is_none() || !e.data.is_empty()).then_some(e.data);
    emit_bytes(&meta, content, budget, visit)
}

/// Hand the visitor a member decoded whole. Its bytes are charged to the scan
/// budget, as a streamed member's are while it is read.
pub(crate) fn emit_bytes<T>(
    meta: &MemberMeta,
    content: Option<Vec<u8>>,
    budget: &mut Budget,
    visit: Visit<T>,
) -> Result<Option<T>, LimitHit> {
    if let Some(data) = &content {
        budget.charge_scan(data.len() as u64)?;
    }
    Ok(visit(meta, content.map(Member::Bytes), budget))
}

/// Shared driver for a single-member sequential compressor: seek to the start,
/// build a streaming `Read` decoder over the source via `mk`, and hand it to the
/// visitor under a [`BudgetReader`]. The decoder pulls compressed bytes on
/// demand, so a member decompressing to any size is never materialized here.
#[allow(dead_code)]
pub(crate) fn stream_single<R: Read + Seek, T>(
    source: &mut R,
    budget: &mut Budget,
    visit: Visit<T>,
    name: &str,
    mk: impl for<'a> FnOnce(&'a mut R) -> Result<Box<dyn Read + 'a>, LimitHit>,
) -> Result<Option<T>, LimitHit> {
    let comp_size = source
        .seek(io::SeekFrom::End(0))
        .and_then(|len| source.seek(io::SeekFrom::Start(0)).map(|_| len))
        .map_err(|e| LimitHit::corrupt(format!("{name} seek: {e}")))?;
    budget.count_entry()?;
    let mut dec = mk(source)?;
    let meta = MemberMeta {
        name: name.to_string(),
        comp_size,
        size: None,
        encrypted: false,
        unsupported: None,
    };
    emit_stream(&meta, &mut *dec, budget, visit)
}

/// The most a member `comp_size` bytes long in its container may decode to
/// before its ratio is a bomb's ([`crate::ratio_guard`]); `None` when its size
/// in the container is unknown.
fn ratio_cap(comp_size: u64, budget: &Budget) -> Option<u64> {
    if comp_size == 0 {
        return None;
    }
    let ratio = budget.limits.max_compression_ratio.saturating_add(1);
    Some(
        comp_size
            .saturating_mul(ratio)
            .saturating_sub(1)
            .max(crate::RATIO_FLOOR_BYTES - 1),
    )
}

/// Hand the visitor a member decoded as it is read, under a [`BudgetReader`],
/// mapping an over-budget overflow to a [`LimitHit`].
///
/// A streamed member is not held here, so it is bounded by the cumulative
/// *scan* budget ([`Budget::remaining_scan`] = `max_scanned_bytes − scanned`), a
/// processing limit, not by the per-member *buffer* cap (`max_buffer_bytes`)
/// that bounds what is held whole. What the visitor reads is charged against
/// the scan budget, so a container of many large members is still bounded
/// cumulatively.
pub(crate) fn emit_stream<T>(
    meta: &MemberMeta,
    inner: &mut dyn Read,
    budget: &mut Budget,
    visit: Visit<T>,
) -> Result<Option<T>, LimitHit> {
    let scan_cap = budget.remaining_scan();
    let ratio_cap = ratio_cap(meta.comp_size, budget);
    let cap = ratio_cap.map_or(scan_cap, |r| r.min(scan_cap));
    let mut br = BudgetReader::new(inner, cap);
    let out = visit(meta, Some(Member::Stream(&mut br)), budget);
    if br.overflowed {
        if ratio_cap.is_some_and(|r| r < scan_cap) {
            return Err(LimitHit::new(format!(
                "member '{}': compression ratio > {}",
                meta.name, budget.limits.max_compression_ratio
            )));
        }
        return Err(LimitHit::new(format!(
            "member '{}' exceeds scan budget {}",
            meta.name, budget.limits.max_scanned_bytes
        )));
    }
    budget.charge_scan(br.count)?;
    Ok(out)
}

/// A member stored as it stands in its container, `(name, offset, size)`, or
/// a part of the container the walk stopped short of (too many partitions,
/// too many ISO directories, a table it would not walk) and why.
#[allow(dead_code)]
pub(crate) enum Region {
    Member(String, u64, u64),
    Unwalked(String, &'static str),
}

impl From<(String, u64, u64)> for Region {
    fn from((name, offset, size): (String, u64, u64)) -> Self {
        Region::Member(name, offset, size)
    }
}

/// Emit pre-parsed stored (uncompressed) members by seeking to each and handing
/// the visitor a bounded window: the shared tail of every format whose members
/// are stored as they are (ar, cpio, machofat...). No member data is buffered.
// Dead only in a build with none of the STORED-OFFSET formats (ar, cpio,
// machofat, pyc, sfx, tnef, partition, iso, onenote); see
// `crate::cap_prealloc` for why the feature list is not spelled out.
#[allow(dead_code)]
pub(crate) fn stream_stored<R: Read + Seek, T>(
    source: &mut R,
    budget: &mut Budget,
    visit: Visit<T>,
    members: impl IntoIterator<Item = impl Into<Region>>,
) -> Result<Option<T>, LimitHit> {
    for region in members {
        budget.count_entry()?;
        let (name, offset, size) = match region.into() {
            Region::Member(name, offset, size) => (name, offset, size),
            // Content that was never enumerated arrives as UNSUPPORTED.
            // Emitting it as an ordinary empty member would make "we did not
            // look" indistinguishable from "we looked and it was empty", which
            // is the shape of a silent clean.
            Region::Unwalked(name, reason) => {
                let meta = MemberMeta {
                    name,
                    comp_size: 0,
                    size: None,
                    encrypted: false,
                    unsupported: Some(reason),
                };
                if let Some(t) = visit(&meta, None, budget) {
                    return Ok(Some(t));
                }
                continue;
            }
        };
        source
            .seek(io::SeekFrom::Start(offset))
            .map_err(|e| LimitHit::corrupt(format!("stored member seek: {e}")))?;
        let mut window = source.take(size);
        let meta = MemberMeta {
            name,
            comp_size: size,
            size: Some(size),
            encrypted: false,
            unsupported: None,
        };
        if let Some(t) = emit_stream(&meta, &mut window, budget, visit)? {
            return Ok(Some(t));
        }
    }
    Ok(None)
}

/// True if `err` is the [`BudgetReader`] over-budget sentinel (a bomb), as
/// opposed to a genuine I/O error from the underlying source. Callers running a
/// member reader (e.g. a streaming matcher in `exav-core`) use this to map the
/// stop to `LimitsExceeded` rather than a hard I/O failure.
pub fn is_budget_overflow(err: &io::Error) -> bool {
    err.get_ref().map(|e| e.to_string()) == Some(BUDGET_OVERFLOW.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Limits;
    use std::io::Cursor;

    /// Every member `(name, bytes)` a visitor reading each one whole sees in
    /// `blob`, leaving out those reported unsupported.
    ///
    /// Every test using it is behind a format feature, so it is dead in a build
    /// with none of them compiled in.
    #[allow(dead_code)]
    fn members(fmt: Format, blob: &[u8]) -> Vec<(String, Vec<u8>)> {
        members_with(fmt, blob, Budget::new(Limits::default()))
    }

    #[allow(dead_code)] // see `members`
    fn members_with(fmt: Format, blob: &[u8], mut budget: Budget) -> Vec<(String, Vec<u8>)> {
        let mut out: Vec<(String, Vec<u8>)> = Vec::new();
        let mut visit = |m: &MemberMeta, content: Option<Member<'_>>, _: &mut Budget| {
            if m.unsupported.is_some() {
                return None::<()>;
            }
            let data = match content {
                None => Vec::new(),
                Some(Member::Bytes(d)) => d,
                Some(Member::Stream(r)) => {
                    let mut d = Vec::new();
                    let _ = r.read_to_end(&mut d);
                    d
                }
            };
            out.push((m.name.clone(), data));
            None
        };
        let _ = walk(fmt, &blob, &mut budget, &mut visit);
        out
    }

    /// `blob`'s members are exactly `want`.
    #[allow(dead_code)] // see `members`
    fn assert_members(fmt: Format, blob: &[u8], want: &[(&str, &[u8])]) {
        let want: Vec<(String, Vec<u8>)> = want
            .iter()
            .map(|(n, d)| (n.to_string(), d.to_vec()))
            .collect();
        assert_eq!(members(fmt, blob), want, "{fmt:?}");
    }

    /// An LHA member compressed with a method there is no decoder for is
    /// reported, not skipped, and the walk goes on to the next one.
    #[cfg(feature = "lha")]
    #[test]
    fn an_lha_member_with_an_unknown_method_is_reported() {
        // Level-0 headers: size, checksum, method, sizes, time, attribute,
        // level, name, CRC-16 of the content.
        fn member(method: &[u8; 5], name: &[u8], body: &[u8]) -> Vec<u8> {
            let crc = body.iter().fold(0u16, |mut crc, &b| {
                crc ^= b as u16;
                for _ in 0..8 {
                    crc = if crc & 1 != 0 {
                        (crc >> 1) ^ 0xA001
                    } else {
                        crc >> 1
                    };
                }
                crc
            });
            let mut h = method.to_vec();
            h.extend_from_slice(&(body.len() as u32).to_le_bytes());
            h.extend_from_slice(&(body.len() as u32).to_le_bytes());
            h.extend_from_slice(&[0, 0, 0x21, 0x5a, 0x20, 0]);
            h.push(name.len() as u8);
            h.extend_from_slice(name);
            h.extend_from_slice(&crc.to_le_bytes());
            let sum = h.iter().fold(0u8, |s, &b| s.wrapping_add(b));
            [&[h.len() as u8, sum][..], &h, body].concat()
        }
        let blob = [
            member(b"-lh0-", b"a.txt", b"hello"),
            member(b"-lh9-", b"b.txt", b"12345"),
            vec![0],
        ]
        .concat();
        let mut seen = Vec::new();
        let mut budget = Budget::new(Limits::default());
        walk(
            Format::Lha,
            &blob.as_slice(),
            &mut budget,
            &mut |m, content, b| {
                let data = content.map(|c| c.into_bytes(m, b).unwrap().0);
                seen.push((m.name.clone(), m.unsupported.is_some(), data));
                None::<()>
            },
        )
        .unwrap();
        assert_eq!(
            seen,
            [
                ("a.txt".to_string(), false, Some(b"hello".to_vec())),
                ("b.txt".to_string(), true, None),
            ]
        );
    }

    /// A ZIP whose central directory will not parse is salvaged from its local
    /// headers, and each salvaged member counts once toward `max_members`.
    #[cfg(feature = "zip")]
    #[test]
    fn a_salvaged_zip_counts_each_member_once() {
        use std::io::Write;
        let mut buf = Cursor::new(Vec::new());
        {
            let mut zip = ::zip::ZipWriter::new(&mut buf);
            let opts = ::zip::write::SimpleFileOptions::default()
                .compression_method(::zip::CompressionMethod::Stored);
            for name in ["a.txt", "b.txt"] {
                zip.start_file(name, opts).unwrap();
                zip.write_all(b"member").unwrap();
            }
            zip.finish().unwrap();
        }
        let mut blob = buf.into_inner();
        // Point the end-of-central-directory record's directory offset past
        // the end of the file, so only the local headers remain usable.
        let eocd = blob.len() - 22;
        blob[eocd + 16..eocd + 20].copy_from_slice(&u32::MAX.to_le_bytes());

        let mut budget = Budget::new(Limits {
            max_members: 2,
            ..Limits::default()
        });
        let mut seen = 0;
        let mut visit = |_: &MemberMeta, _: Option<Member<'_>>, _: &mut Budget| -> Option<()> {
            seen += 1;
            None
        };
        let walked = walk(Format::Zip, &blob, &mut budget, &mut visit);
        assert!(walked.is_ok(), "{:?}", walked.err());
        assert_eq!(seen, 2);
    }

    /// A member whose local header and data are in the file but whose entry is
    /// missing from the central directory is still visited: the target extracts
    /// it, so the scan has to read it.
    #[cfg(feature = "zip")]
    #[test]
    fn a_member_hidden_from_the_central_directory_is_visited() {
        use std::io::Write;
        let zip_of = |name: &str, data: &[u8]| {
            let mut buf = Cursor::new(Vec::new());
            {
                let mut zip = ::zip::ZipWriter::new(&mut buf);
                let opts = ::zip::write::SimpleFileOptions::default()
                    .compression_method(::zip::CompressionMethod::Stored);
                zip.start_file(name, opts).unwrap();
                zip.write_all(data).unwrap();
                zip.finish().unwrap();
            }
            buf.into_inner()
        };
        let cd_offset = |z: &[u8]| {
            let eocd = z.len() - 22;
            u32::from_le_bytes(z[eocd + 16..eocd + 20].try_into().unwrap()) as usize
        };
        let listed = zip_of("listed.txt", b"listed");
        let hidden = zip_of("hidden.txt", b"hidden");
        // Splice `hidden.txt`'s local header and data in ahead of the listed
        // archive's central directory, and move the directory offset past it.
        let orphan = &hidden[..cd_offset(&hidden)];
        let cd = cd_offset(&listed);
        let mut blob = listed[..cd].to_vec();
        blob.extend_from_slice(orphan);
        blob.extend_from_slice(&listed[cd..]);
        let eocd = blob.len() - 22;
        blob[eocd + 16..eocd + 20].copy_from_slice(&((cd + orphan.len()) as u32).to_le_bytes());

        let names: Vec<String> = members(Format::Zip, &blob)
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert_eq!(names, ["listed.txt", "hidden.txt"]);
    }

    // A member at exactly the cap reads fully, with no overflow.
    #[test]
    fn budget_reader_delivers_up_to_cap() {
        let data = vec![b'A'; 1000];
        let mut src = Cursor::new(data);
        let mut br = BudgetReader::new(&mut src, 1000);
        let mut out = Vec::new();
        br.read_to_end(&mut out).unwrap();
        assert_eq!(out.len(), 1000);
        assert_eq!(br.count(), 1000);
        assert!(!br.overflowed);
    }

    #[cfg(feature = "ar")]
    #[test]
    fn ar_members() {
        let mut blob = Vec::new();
        blob.extend_from_slice(b"!<arch>\n");
        let member = |name: &str, data: &[u8], out: &mut Vec<u8>| {
            let mut hdr = [b' '; 60];
            hdr[..name.len()].copy_from_slice(name.as_bytes());
            let size = format!("{}", data.len());
            hdr[48..48 + size.len()].copy_from_slice(size.as_bytes());
            hdr[58] = b'`';
            hdr[59] = b'\n';
            out.extend_from_slice(&hdr);
            out.extend_from_slice(data);
            if data.len() % 2 == 1 {
                out.push(b'\n'); // pad to even
            }
        };
        member("a.txt/", b"abc", &mut blob); // odd → padded
        member("b.bin/", b"xy", &mut blob);
        assert_members(Format::Ar, &blob, &[("a.txt", b"abc"), ("b.bin", b"xy")]);
    }

    #[cfg(feature = "cpio")]
    #[test]
    fn cpio_newc_members() {
        // SVR4 "new ASCII" cpio: 110-byte hex header, header+name and data each
        // padded to 4 bytes.
        fn member(name: &str, data: &[u8], out: &mut Vec<u8>) {
            let name_z = format!("{name}\0");
            let mut h = Vec::new();
            h.extend_from_slice(b"070701");
            let f = |v: usize| format!("{v:08x}");
            // 13 fields: ino, mode, uid, gid, nlink, mtime, FILESIZE, devmajor,
            // devminor, rdevmajor, rdevminor, NAMESIZE, check.
            for field in [0, 0, 0, 0, 0, 0, data.len(), 0, 0, 0, 0, name_z.len(), 0] {
                h.extend_from_slice(f(field).as_bytes());
            }
            assert_eq!(h.len(), 110);
            out.extend_from_slice(&h);
            out.extend_from_slice(name_z.as_bytes());
            while !out.len().is_multiple_of(4) {
                out.push(0);
            }
            out.extend_from_slice(data);
            while !out.len().is_multiple_of(4) {
                out.push(0);
            }
        }
        let mut blob = Vec::new();
        member("dir/a.txt", b"hello world", &mut blob);
        member("b.bin", b"\x00\x01\x02\x03\x04", &mut blob);
        // Trailer.
        member("TRAILER!!!", b"", &mut blob);
        assert_members(
            Format::Cpio,
            &blob,
            &[
                ("dir/a.txt", b"hello world"),
                ("b.bin", b"\x00\x01\x02\x03\x04"),
            ],
        );
    }

    #[cfg(feature = "machofat")]
    #[test]
    fn machofat_members() {
        let mut blob = Vec::new();
        blob.extend_from_slice(&0xCAFE_BABEu32.to_be_bytes()); // FAT_MAGIC
        blob.extend_from_slice(&2u32.to_be_bytes()); // nfat_arch = 2
        let a0 = &b"ARCH-ZERO-DATA"[..];
        let a1 = &b"ARCH-ONE"[..];
        let a0_off = 48u32; // 8-byte header + 2 * 20-byte records
        let a1_off = a0_off + a0.len() as u32;
        for (off, data) in [(a0_off, a0), (a1_off, a1)] {
            blob.extend_from_slice(&0u32.to_be_bytes()); // cputype
            blob.extend_from_slice(&0u32.to_be_bytes()); // cpusubtype
            blob.extend_from_slice(&off.to_be_bytes());
            blob.extend_from_slice(&(data.len() as u32).to_be_bytes());
            blob.extend_from_slice(&0u32.to_be_bytes()); // align
        }
        blob.extend_from_slice(a0);
        blob.extend_from_slice(a1);
        assert_members(
            Format::Machofat,
            &blob,
            &[("macho-arch-0", a0), ("macho-arch-1", a1)],
        );
    }

    #[cfg(feature = "onenote")]
    #[test]
    fn onenote_members() {
        let mut blob = Vec::new();
        blob.extend_from_slice(&crate::formats::onenote::ONENOTE_HEADER_GUID);
        blob.extend_from_slice(&[0u8; 16]); // filler
        let fds = [
            0xE7, 0x16, 0xE3, 0xBD, 0x65, 0x26, 0x11, 0x45, 0xA4, 0xC4, 0x8D, 0x4D, 0x0B, 0x7A,
            0x9E, 0xAC,
        ];
        let payload = &b"MZ...embedded executable payload..."[..];
        blob.extend_from_slice(&fds);
        blob.extend_from_slice(&(payload.len() as u64).to_le_bytes()); // cbLength
        blob.extend_from_slice(&0u32.to_le_bytes()); // unused
        blob.extend_from_slice(&0u64.to_le_bytes()); // reserved
        blob.extend_from_slice(payload);
        assert_members(Format::OneNote, &blob, &[("onenote-embedded-0", payload)]);
    }

    #[cfg(feature = "szdd")]
    #[test]
    fn szdd_member() {
        let payload = &b"HELLO SZDD WORLD -- literal-encoded body for the equivalence test"[..];
        let mut blob = Vec::new();
        blob.extend_from_slice(b"SZDD\x88\xF0\x27\x33"); // magic
        blob.push(b'A'); // compression mode
        blob.push(0); // last-char
        blob.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // declared size
        for chunk in payload.chunks(8) {
            // Flag with a set bit per literal in this group (set bit = literal).
            let flag = ((1u16 << chunk.len()) - 1) as u8;
            blob.push(flag);
            blob.extend_from_slice(chunk);
        }
        assert_members(Format::Szdd, &blob, &[("expanded.bin", payload)]);
    }

    /// Every `compress` fixture, at both code widths, decodes to the file it
    /// was made from, and cut short to a prefix of it. The fixtures cross width
    /// changes and table resets, and are larger than a source chunk.
    #[cfg(feature = "lzw")]
    #[test]
    fn lzw_member_is_the_compressed_file() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/lzw");
        let mut seen = 0;
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let path = e.path().to_string_lossy().into_owned();
            let Some(stem) = path.split(".b1").next().filter(|_| path.contains(".Z")) else {
                continue;
            };
            // `read_fixture` unmasks `<path>.xor` itself.
            let blob = crate::read_fixture(path.trim_end_matches(".xor")).unwrap();
            let plain = crate::read_fixture(&format!("{stem}.txt")).unwrap();
            assert!(blob.starts_with(&[0x1f, 0x9d]), "{path}");
            assert!(blob.len() > 4 * crate::source::CHUNK || !path.contains("bigreset"));
            assert_members(Format::Lzw, &blob, &[("lzw-content", &plain)]);
            let cut = &members(Format::Lzw, &blob[..blob.len() * 2 / 3])[0].1;
            assert!(!cut.is_empty() && plain.starts_with(cut), "{path}");
            seen += 1;
        }
        assert_eq!(seen, 10);
    }

    /// A linked frame whose matches reach back tens of KiB into earlier blocks,
    /// across a skippable frame and into a legacy one, decodes to what its
    /// sequences say; cut short, to a prefix of that.
    #[cfg(feature = "lz4")]
    #[test]
    fn lz4_matches_reach_back_across_blocks_and_frames() {
        // One LZ4 length field: the nibble, then 255s and the remainder.
        fn len_field(n: usize, nibble: &mut u8, tail: &mut Vec<u8>) {
            if n < 15 {
                *nibble = n as u8;
                return;
            }
            *nibble = 15;
            let mut rest = n - 15;
            while rest >= 255 {
                tail.push(255);
                rest -= 255;
            }
            tail.push(rest as u8);
        }
        fn sequence(lits: &[u8], offset: u16, mlen: usize, out: &mut Vec<u8>) {
            let (mut hi, mut lo) = (0u8, 0u8);
            let (mut lit_tail, mut match_tail) = (Vec::new(), Vec::new());
            len_field(lits.len(), &mut hi, &mut lit_tail);
            len_field(mlen - 4, &mut lo, &mut match_tail);
            out.push(hi << 4 | lo);
            out.extend_from_slice(&lit_tail);
            out.extend_from_slice(lits);
            out.extend_from_slice(&offset.to_le_bytes());
            out.extend_from_slice(&match_tail);
        }
        let mut seed = 0x2545_f491_u32;
        let mut noise = |n: usize| -> Vec<u8> {
            (0..n)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 17;
                    seed ^= seed << 5;
                    seed as u8
                })
                .collect()
        };
        // What the sequences decode to, built alongside them.
        let mut want: Vec<u8> = Vec::new();
        let copy_back = |want: &mut Vec<u8>, offset: usize, len: usize| {
            for _ in 0..len {
                let b = want[want.len() - offset];
                want.push(b);
            }
        };
        let mut linked = vec![0x04, 0x22, 0x4D, 0x18, 0x40, 0x70, 0xDF];
        // A stored block first, so the matches after it have 70 KB behind them.
        let first = noise(70_000);
        linked.extend_from_slice(&(first.len() as u32 | 0x8000_0000).to_le_bytes());
        linked.extend_from_slice(&first);
        want.extend_from_slice(&first);
        for _ in 0..40 {
            let mut body = Vec::new();
            let lits = noise(1000);
            sequence(&lits, 60_000, 5000, &mut body);
            want.extend_from_slice(&lits);
            copy_back(&mut want, 60_000, 5000);
            // A block ends with literals only.
            let tail = noise(5);
            body.push(5 << 4);
            body.extend_from_slice(&tail);
            want.extend_from_slice(&tail);
            linked.extend_from_slice(&(body.len() as u32).to_le_bytes());
            linked.extend_from_slice(&body);
        }
        linked.extend_from_slice(&0u32.to_le_bytes());
        // A skippable frame, then a legacy one reaching back into the first.
        linked.extend_from_slice(&[0x5A, 0x2A, 0x4D, 0x18, 3, 0, 0, 0, 1, 2, 3]);
        linked.extend_from_slice(&[0x02, 0x21, 0x4C, 0x18]);
        let mut body = Vec::new();
        sequence(b"legacy", 65_535, 3000, &mut body);
        want.extend_from_slice(b"legacy");
        copy_back(&mut want, 65_535, 3000);
        body.push(1 << 4);
        body.push(b'!');
        want.push(b'!');
        linked.extend_from_slice(&(body.len() as u32).to_le_bytes());
        linked.extend_from_slice(&body);

        assert_members(Format::Lz4, &linked, &[("lz4-content", &want)]);
        let cut = &members(Format::Lz4, &linked[..linked.len() * 2 / 3])[0].1;
        assert!(!cut.is_empty() && want.starts_with(cut));
    }

    /// Every DMG fixture, HFS+ and APFS, plain, compressed and encrypted,
    /// yields its one file.
    #[cfg(feature = "dmg")]
    #[test]
    fn dmg_members() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/dmg");
        let mut seen = 0;
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let path = e.path().to_string_lossy().into_owned();
            if !path.ends_with(".dmg") {
                continue;
            }
            let blob = std::fs::read(&path).unwrap();
            let budget = Budget::with_passwords(Limits::default(), vec!["test123".to_string()]);
            let files = members_with(Format::Dmg, &blob, budget);
            seen += 1;
            if cfg!(not(feature = "decrypt")) && path.contains("encrypted") {
                assert!(files.is_empty(), "{path}");
                continue;
            }
            assert_eq!(
                files,
                [("/test.txt".to_string(), b"hello hfs+\n".to_vec())],
                "{path}"
            );
        }
        assert_eq!(seen, 7);
    }

    // Every codec decodes, including the solid multi-file case, where each file
    // is carved from one decompressed block by skip+take without buffering
    // the block.
    #[cfg(feature = "sevenz")]
    #[test]
    fn sevenz_codecs_decode() {
        for name in [
            "lzma2.7z",
            "lzma.7z",
            "copy.7z",
            "deflate.7z",
            "bzip2.7z",
            "lzma2_solid.7z",
        ] {
            let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/7z")
                .join(name);
            let files = members(Format::SevenZip, &std::fs::read(&p).unwrap());
            assert!(
                !files.is_empty() && files.iter().all(|(_, d)| !d.is_empty()),
                "{name}"
            );
        }
    }

    // No valid multi-file cab fixture ships (only fuzz cases), so we build a
    // minimal STORED (uncompressed) cab with files in one folder, exercising
    // FolderReader and the skip/window/offset logic in stream_cab.
    #[cfg(feature = "cab")]
    #[test]
    fn cab_stored_members() {
        fn build_stored_cab(files: &[(&str, &[u8])]) -> Vec<u8> {
            let folder_data: Vec<u8> = files.iter().flat_map(|(_, d)| d.iter().copied()).collect();
            let cffile_start = 36u32 + 8; // header + 1 CFFOLDER
            let mut cffile_len = 0u32;
            for (n, _) in files {
                cffile_len += 16 + n.len() as u32 + 1;
            }
            let cfdata_start = cffile_start + cffile_len;
            let mut out = Vec::new();
            out.extend_from_slice(b"MSCF");
            out.extend_from_slice(&0u32.to_le_bytes()); // reserved1
            out.extend_from_slice(&0u32.to_le_bytes()); // cbCabinet (unused by layout)
            out.extend_from_slice(&0u32.to_le_bytes()); // reserved2
            out.extend_from_slice(&cffile_start.to_le_bytes()); // coffFiles
            out.extend_from_slice(&0u32.to_le_bytes()); // reserved3
            out.push(3); // minor
            out.push(1); // major
            out.extend_from_slice(&1u16.to_le_bytes()); // cFolders
            out.extend_from_slice(&(files.len() as u16).to_le_bytes()); // cFiles
            out.extend_from_slice(&0u16.to_le_bytes()); // flags
            out.extend_from_slice(&0u16.to_le_bytes()); // setID
            out.extend_from_slice(&0u16.to_le_bytes()); // iCabinet
                                                        // CFFOLDER
            out.extend_from_slice(&cfdata_start.to_le_bytes()); // coffCabStart
            out.extend_from_slice(&1u16.to_le_bytes()); // cCFData
            out.extend_from_slice(&0u16.to_le_bytes()); // typeCompress = None (stored)
                                                        // CFFILE table
            let mut off = 0u32;
            for (n, d) in files {
                out.extend_from_slice(&(d.len() as u32).to_le_bytes()); // cbFile
                out.extend_from_slice(&off.to_le_bytes()); // uoffFolderStart
                out.extend_from_slice(&0u16.to_le_bytes()); // iFolder
                out.extend_from_slice(&0u16.to_le_bytes()); // date
                out.extend_from_slice(&0u16.to_le_bytes()); // time
                out.extend_from_slice(&0u16.to_le_bytes()); // attribs
                out.extend_from_slice(n.as_bytes());
                out.push(0);
                off += d.len() as u32;
            }
            // Single CFDATA block (stored): csum, cbData, cbUncomp, data.
            out.extend_from_slice(&0u32.to_le_bytes()); // checksum
            out.extend_from_slice(&(folder_data.len() as u16).to_le_bytes()); // cbData
            out.extend_from_slice(&(folder_data.len() as u16).to_le_bytes()); // cbUncomp
            out.extend_from_slice(&folder_data);
            out
        }
        let two: [(&str, &[u8]); 2] = [
            ("readme.txt", b"hello cab world"),
            ("data.bin", b"\x00\x01\x02\x03\x04\x05"),
        ];
        assert_members(Format::Cab, &build_stored_cab(&two), &two);
        // Three files in one folder with a gap-free layout also exercises the
        // per-file skip/window/offset bookkeeping.
        let three: [(&str, &[u8]); 3] = [("x", b"AAAA"), ("y", b"BBBBBBBB"), ("z", b"C")];
        assert_members(Format::Cab, &build_stored_cab(&three), &three);
    }

    // MSZIP cab (via the `cab` crate) with a multi-block folder: exercises the
    // FolderReader over a real compressed folder whose 2nd+ blocks reference the
    // previous block's window (the MSZIP dictionary-priming fix).
    #[cfg(feature = "cab")]
    #[test]
    fn cab_mszip_members() {
        let mut builder = cab::CabinetBuilder::new();
        let folder = builder.add_folder(cab::CompressionType::MsZip);
        folder.add_file("big.bin");
        folder.add_file("tail.txt");
        let mut blob = Vec::new();
        let mut writer = builder.build(std::io::Cursor::new(&mut blob)).unwrap();
        let big: Vec<u8> = (0..100_000u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 24) as u8)
            .collect();
        let bodies: [&[u8]; 2] = [&big, b"the trailing file"];
        let mut i = 0;
        while let Some(mut w) = writer.next_file().unwrap() {
            std::io::Write::write_all(&mut w, bodies[i]).unwrap();
            i += 1;
        }
        writer.finish().unwrap();
        assert_members(
            Format::Cab,
            &blob,
            &[("big.bin", &big), ("tail.txt", bodies[1])],
        );
    }

    // A member past the cap: never delivers a byte beyond `cap`, and the read
    // past the cap is a hard error (never a silent EOF), flagged as overflow.
    #[test]
    fn budget_reader_errors_past_cap() {
        let data = vec![b'B'; 5000];
        let mut src = Cursor::new(data);
        let mut br = BudgetReader::new(&mut src, 1000);
        let mut out = Vec::new();
        let err = br.read_to_end(&mut out).unwrap_err();
        assert!(is_budget_overflow(&err));
        assert_eq!(out.len(), 1000, "must not deliver a byte past the cap");
        assert!(br.overflowed);
    }
}
