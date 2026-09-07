//! Reader-based extraction: the low-level streaming API.
//!
//! Unlike [`crate::extract_each`] — which decodes each member fully into an
//! [`crate::Entry`]'s `Vec<u8>` — this API hands the caller a **reader** per
//! member. The member is decoded on demand as the caller reads it, so a member
//! of any size (multi-gigabyte) is never materialized in RAM. Bomb defenses are
//! enforced *as bytes flow* through [`BudgetReader`], not by pre-buffering.
//!
//! The source is `Read + Seek` and nothing here allocates a member-sized buffer;
//! any buffering a caller needs (e.g. to run a slice-based structural matcher on
//! a small member) is the caller's decision, made in `exav-core` — deliberately
//! as high up the stack as possible.

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
pub struct BudgetReader<'a> {
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
    pub fn count(&self) -> u64 {
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

/// Metadata for a member handed to a [`stream_members`] visitor. The member's
/// bytes are read separately via the reader argument (or absent for a member
/// whose content can't be produced — encrypted / undecodable).
pub struct MemberMeta {
    pub name: String,
    /// Compressed size within the container (for `.cdb` matching), or the
    /// decompressed length when the extractor can't report it.
    pub comp_size: u64,
    pub encrypted: bool,
    /// `Some(reason)` when the member is recognised but its content can't be
    /// decoded (unsupported method / encryption with no matching password). The
    /// reader argument to the visitor is then `None`.
    pub unsupported: Option<&'static str>,
}

/// Visitor for [`stream_members`]. Receives each member's metadata and, when its
/// content is decodable, a budgeted reader over the (on-demand decoded) bytes.
/// Returning `Some(T)` stops the walk immediately — later members are never
/// touched. The `Budget` is threaded for recursion / counting.
pub type StreamVisit<'a, T> =
    &'a mut dyn FnMut(&MemberMeta, Option<&mut dyn Read>, &mut Budget) -> Option<T>;

/// True for the formats [`stream_members`] can walk with each member's decoded
/// bytes produced on demand — no decompressed member is ever materialized
/// whole. Some arms (bzip2, xz, 7z among them) do buffer the COMPRESSED
/// container first, bounded by the peak-buffer limit; the win is on the output
/// side, where one stream can decompress to orders of magnitude more than the
/// file occupies. A decoding step that inherently needs a whole object — an
/// encrypted ZIP member's decryption needs the full ciphertext — is likewise
/// bounded by the peak-buffer limit.
pub fn is_streamable(fmt: Format) -> bool {
    match fmt {
        Format::Gzip | Format::Tar => true,
        // Same shape as gzip: one stream whose output can be orders of
        // magnitude larger than the file, so it must not be materialized.
        #[cfg(feature = "bzip2")]
        Format::Bzip2 => true,
        #[cfg(feature = "xz")]
        Format::Xz => true,
        #[cfg(feature = "sevenz")]
        Format::SevenZip => true,
        #[cfg(feature = "cab")]
        Format::Cab => true,
        #[cfg(feature = "zip")]
        Format::Zip => true,
        #[cfg(feature = "zstd")]
        Format::Zstd => true,
        #[cfg(feature = "lzip")]
        Format::Lzip => true,
        #[cfg(feature = "lha")]
        Format::Lha => true,
        #[cfg(feature = "ar")]
        Format::Ar => true,
        #[cfg(feature = "cpio")]
        Format::Cpio => true,
        #[cfg(feature = "machofat")]
        Format::Machofat => true,
        #[cfg(feature = "pyc")]
        Format::Pyc => true,
        #[cfg(feature = "sfx")]
        Format::Sfx => true,
        #[cfg(feature = "tnef")]
        Format::Tnef => true,
        #[cfg(feature = "partition")]
        Format::Partition => true,
        #[cfg(feature = "iso")]
        Format::Iso => true,
        #[cfg(feature = "onenote")]
        Format::OneNote => true,
        #[cfg(feature = "swf")]
        Format::Swf => true,
        #[cfg(feature = "szdd")]
        Format::Szdd => true,
        _ => false,
    }
}

/// Walk a container's members, handing each to `visit` as a reader that decodes
/// on demand. The container is read straight from the seekable `source`; no
/// member-sized buffer is ever allocated here. Only [`is_streamable`] formats
/// are supported — the caller checks first and routes other formats to the
/// buffered [`crate::extract_each`] path.
///
/// Bomb defenses: each member is counted (`count_entry`) and its decoded bytes
/// are capped by [`BudgetReader`] at the remaining scan budget; exceeding it ends
/// the walk with a [`LimitHit`].
///
/// Panic containment: some decoders (e.g. `delharc` for LHA) can panic on crafted
/// input. As in [`crate::extract_each`], the whole dispatch runs inside a
/// `catch_unwind` so a decoder panic becomes a clean `LimitHit` (→ `Unscannable`)
/// rather than aborting the process. This crate is `#![forbid(unsafe_code)]`, so
/// a panic is the only failure mode to contain.
pub fn stream_members<R: Read + Seek, T>(
    fmt: Format,
    source: R,
    budget: &mut Budget,
    visit: StreamVisit<T>,
) -> Result<Option<T>, LimitHit> {
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        dispatch_stream(fmt, source, budget, visit)
    }));
    match caught {
        Ok(r) => r,
        Err(_) => Err(LimitHit::corrupt(format!(
            "{fmt:?} streaming decoder panicked on malformed input"
        ))),
    }
}

/// Format dispatch for [`stream_members`]; kept separate so the panic-containment
/// boundary wraps every streaming decoder uniformly.
// Every arm of the match below is behind a format feature, so in a build with
// none of them the body is `match fmt {}` and no parameter is read.
#[allow(unused_variables, unused_mut)]
fn dispatch_stream<R: Read + Seek, T>(
    fmt: Format,
    mut source: R,
    budget: &mut Budget,
    visit: StreamVisit<T>,
) -> Result<Option<T>, LimitHit> {
    // Fail on demand, to test the boundary rather than the decoders — the
    // streaming half of the hook in `dispatch_extract`. The top-level scan
    // routes every natively-streaming container here, never through the
    // buffered dispatch, so a hook only there is unreachable from a real
    // `exav <file>` run. The source is a reader, not a slice, so the marker is
    // looked for in a bounded prefix of the raw container bytes; a marker
    // carried in a stored member or a header field near the start of a
    // well-formed container lands inside it.
    #[cfg(feature = "testing-faults")]
    {
        let mut prefix = vec![0u8; 64 * 1024];
        if source.seek(io::SeekFrom::Start(0)).is_ok() {
            let mut n = 0;
            while n < prefix.len() {
                match source.read(&mut prefix[n..]) {
                    Ok(0) => break,
                    Ok(k) => n += k,
                    Err(_) => break,
                }
            }
            prefix.truncate(n);
            // Each format arm seeks to where it needs to be; rewinding here
            // keeps the probe invisible to arms that read without seeking.
            let _ = source.seek(io::SeekFrom::Start(0));
            crate::provoke(&prefix);
        }
    }
    match fmt {
        #[cfg(feature = "gzip")]
        Format::Gzip => stream_gzip(&mut source, budget, visit),
        #[cfg(feature = "bzip2")]
        Format::Bzip2 => {
            // Same trade as 7z below: the COMPRESSED input is buffered (bounded
            // by the peak-buffer limit — it is the file on disk, not its
            // output), and the decompressed content then streams. That is the
            // win, since a `.bz2` decompresses to far more than it occupies.
            source
                .seek(io::SeekFrom::Start(0))
                .map_err(|e| LimitHit::corrupt(format!("bzip2: {e}")))?;
            let (buf, truncated) = crate::bounded_read(&mut source, budget.limits.max_buffer_bytes)
                .map_err(|e| LimitHit::corrupt(format!("bzip2: {e}")))?;
            if truncated {
                return Err(LimitHit::new(
                    "bzip2 container exceeds max-buffer".to_string(),
                ));
            }
            budget.count_entry()?;
            let mut dec =
                crate::formats::bzip2::content_reader(&buf, budget.limits.max_buffer_bytes)?;
            let meta = MemberMeta {
                name: "bzip2-content".to_string(),
                comp_size: buf.len() as u64,
                encrypted: false,
                unsupported: None,
            };
            visit_member(&meta, &mut dec, budget, visit)
        }
        #[cfg(feature = "xz")]
        Format::Xz => {
            source
                .seek(io::SeekFrom::Start(0))
                .map_err(|e| LimitHit::corrupt(format!("xz: {e}")))?;
            let (buf, truncated) = crate::bounded_read(&mut source, budget.limits.max_buffer_bytes)
                .map_err(|e| LimitHit::corrupt(format!("xz: {e}")))?;
            if truncated {
                return Err(LimitHit::new("xz container exceeds max-buffer".to_string()));
            }
            budget.count_entry()?;
            let mut dec = crate::formats::xz::content_reader(&buf);
            let meta = MemberMeta {
                name: "xz-content".to_string(),
                comp_size: buf.len() as u64,
                encrypted: false,
                unsupported: None,
            };
            visit_member(&meta, &mut dec, budget, visit)
        }
        #[cfg(feature = "sevenz")]
        Format::SevenZip => {
            // 7z's header is at the end (random access), so the *compressed*
            // container is buffered (bounded by the peak-buffer limit); each
            // member's *decompressed* solid-block output then streams — that is
            // the win, since a block can be far larger than the packed archive.
            source
                .seek(io::SeekFrom::Start(0))
                .map_err(|e| LimitHit::corrupt(format!("7z: {e}")))?;
            let (buf, truncated) = crate::bounded_read(&mut source, budget.limits.max_buffer_bytes)
                .map_err(|e| LimitHit::corrupt(format!("7z: {e}")))?;
            if truncated {
                return Err(LimitHit::new("7z container exceeds max-buffer".to_string()));
            }
            crate::formats::sevenz::stream_sevenz(&buf, budget, visit)
        }
        #[cfg(feature = "cab")]
        Format::Cab => crate::formats::stream_cab(&mut source, budget, visit),
        #[cfg(feature = "tar")]
        Format::Tar => stream_tar(&mut source, budget, visit),
        #[cfg(feature = "zip")]
        Format::Zip => stream_zip(source, budget, visit),
        #[cfg(feature = "zstd")]
        Format::Zstd => stream_single(&mut source, budget, visit, "zstd-content", |r| {
            ruzstd::decoding::StreamingDecoder::new(r)
                .map(|d| Box::new(d) as Box<dyn Read + '_>)
                .map_err(|e| LimitHit::corrupt(format!("zstd: {e}")))
        }),
        #[cfg(feature = "lzip")]
        Format::Lzip => stream_single(&mut source, budget, visit, "lzip-content", |r| {
            Ok(Box::new(lzma_rust2::LzipReader::new(r)) as Box<dyn Read + '_>)
        }),
        #[cfg(feature = "lha")]
        Format::Lha => stream_lha(&mut source, budget, visit),
        #[cfg(feature = "ar")]
        Format::Ar => {
            let members =
                crate::formats::ar::stream_offsets(&mut source, budget.limits.max_buffer_bytes)?;
            stream_stored(&mut source, budget, visit, &members)
        }
        #[cfg(feature = "cpio")]
        Format::Cpio => {
            let members = crate::formats::cpio::stream_offsets(&mut source)?;
            stream_stored(&mut source, budget, visit, &members)
        }
        #[cfg(feature = "machofat")]
        Format::Machofat => {
            let members = crate::formats::machofat::stream_offsets(&mut source)?;
            stream_stored(&mut source, budget, visit, &members)
        }
        #[cfg(feature = "pyc")]
        Format::Pyc => {
            let members = crate::formats::pyc::stream_offsets(&mut source)?;
            stream_stored(&mut source, budget, visit, &members)
        }
        #[cfg(feature = "sfx")]
        Format::Sfx => {
            let members =
                crate::formats::sfx::stream_offsets(&mut source, budget.limits.max_buffer_bytes)?;
            stream_stored(&mut source, budget, visit, &members)
        }
        #[cfg(feature = "tnef")]
        Format::Tnef => {
            let members =
                crate::formats::tnef::stream_offsets(&mut source, budget.limits.max_buffer_bytes)?;
            stream_stored(&mut source, budget, visit, &members)
        }
        #[cfg(feature = "partition")]
        Format::Partition => {
            let members = crate::formats::partition::stream_offsets(&mut source)?;
            stream_stored(&mut source, budget, visit, &members)
        }
        #[cfg(feature = "iso")]
        Format::Iso => {
            let members =
                crate::formats::iso::stream_offsets(&mut source, budget.limits.max_buffer_bytes)?;
            stream_stored(&mut source, budget, visit, &members)
        }
        #[cfg(feature = "onenote")]
        Format::OneNote => {
            let members = crate::formats::onenote::stream_offsets(
                &mut source,
                budget.limits.max_buffer_bytes,
            )?;
            stream_stored(&mut source, budget, visit, &members)
        }
        #[cfg(feature = "swf")]
        Format::Swf => stream_swf(&mut source, budget, visit),
        #[cfg(feature = "szdd")]
        Format::Szdd => stream_szdd(&mut source, budget, visit),
        _ => Err(LimitHit::corrupt(format!(
            "{fmt:?} is not stream-extractable"
        ))),
    }
}

/// Shared driver for a single-member sequential compressor: seek to the start,
/// build a streaming `Read` decoder over the source via `mk`, and hand it to the
/// visitor under a [`BudgetReader`]. The decoder pulls compressed bytes on
/// demand, so a member decompressing to any size is never materialized here.
#[allow(dead_code)]
fn stream_single<R: Read + Seek, T>(
    source: &mut R,
    budget: &mut Budget,
    visit: StreamVisit<T>,
    name: &str,
    mk: impl for<'a> FnOnce(&'a mut R) -> Result<Box<dyn Read + 'a>, LimitHit>,
) -> Result<Option<T>, LimitHit> {
    source
        .seek(io::SeekFrom::Start(0))
        .map_err(|e| LimitHit::corrupt(format!("{name} seek: {e}")))?;
    budget.count_entry()?;
    let mut dec = mk(source)?;
    let meta = MemberMeta {
        name: name.to_string(),
        comp_size: 0,
        encrypted: false,
        unsupported: None,
    };
    visit_member(&meta, &mut *dec, budget, visit)
}

/// Run one member's reader through the visitor under a [`BudgetReader`], mapping
/// an over-budget overflow to a [`LimitHit`].
///
/// A streamed member is **never retained**, so it is bounded by the cumulative
/// *scan* budget ([`Budget::remaining_scan`] = `max_scanned_bytes − scanned`), a
/// processing limit — not by the per-member *buffer* cap (`max_buffer_bytes`)
/// that governs buffered extraction. The caller (`exav-core::member_stream_scan`)
/// holds only a bounded prefix (`deep_analysis_max`) in RAM and streams the rest
/// through the constant-memory matcher, so a member far larger than the RAM
/// buffer is scanned in full without ever being materialized. Consumed bytes are
/// charged against the scan budget so a container of many large members is still
/// bounded cumulatively.
pub(crate) fn visit_member<T>(
    meta: &MemberMeta,
    inner: &mut dyn Read,
    budget: &mut Budget,
    visit: StreamVisit<T>,
) -> Result<Option<T>, LimitHit> {
    let cap = budget.remaining_scan();
    let mut br = BudgetReader::new(inner, cap);
    let out = visit(meta, Some(&mut br), budget);
    if br.overflowed {
        return Err(LimitHit::new(format!(
            "member '{}' exceeds scan budget {}",
            meta.name, budget.limits.max_scanned_bytes
        )));
    }
    budget.charge_scan(br.count)?;
    Ok(out)
}

#[cfg(feature = "gzip")]
fn stream_gzip<R: Read + Seek, T>(
    source: &mut R,
    budget: &mut Budget,
    visit: StreamVisit<T>,
) -> Result<Option<T>, LimitHit> {
    use flate2::read::MultiGzDecoder;
    source
        .seek(io::SeekFrom::Start(0))
        .map_err(|e| LimitHit::corrupt(format!("gzip seek: {e}")))?;
    budget.count_entry()?;
    let mut dec = MultiGzDecoder::new(source);
    let meta = MemberMeta {
        name: "gzip-content".to_string(),
        comp_size: 0,
        encrypted: false,
        unsupported: None,
    };
    visit_member(&meta, &mut dec, budget, visit)
}

/// Stream a ZIP member-by-member off a seekable source. Only the central
/// directory and the members actually scanned are read (a range-backed reader
/// fetches nothing more). A cleartext member is handed to the visitor as the
/// crate's decompressing reader — so a member decompressing to any size is
/// scanned without being materialized. An encrypted member must be decrypted
/// whole (decryption needs the full ciphertext), bounded by the peak-buffer
/// limit; that buffered plaintext is then presented as a reader.
#[cfg(feature = "zip")]
fn stream_zip<R: Read + Seek, T>(
    mut source: R,
    budget: &mut Budget,
    visit: StreamVisit<T>,
) -> Result<Option<T>, LimitHit> {
    // Borrow the source for the central-directory parse so it survives a parse
    // failure. A forged/corrupt central directory (bad CDFH offset in the EOCD,
    // etc.) makes the seekable member walk impossible — but the members' Local
    // File Headers are still in the file. Fall back to buffering (bounded by
    // `max-buffer`) and the local-header salvage the buffered extractor performs,
    // then present each recovered member to the streaming visitor, so a malformed
    // archive still gets its members scanned instead of being written off whole
    // (matching clamd). Without this fallback, such an archive is written off as
    // `LimitsExceeded`, masking the detection inside.
    let mut zip = match ::zip::ZipArchive::new(source.by_ref()) {
        Ok(z) => z,
        Err(_) => {
            source
                .seek(io::SeekFrom::Start(0))
                .map_err(|e| LimitHit::corrupt(format!("zip seek: {e}")))?;
            let max = budget.limits.max_buffer_bytes;
            let mut data = Vec::new();
            source
                .by_ref()
                .take(max.saturating_add(1))
                .read_to_end(&mut data)
                .map_err(|e| LimitHit::corrupt(format!("zip read: {e}")))?;
            if data.len() as u64 > max {
                return Err(LimitHit::corrupt(format!(
                    "corrupt zip exceeds max-buffer {max}"
                )));
            }
            // Collect salvaged members (local-header scan), then hand each to the
            // streaming visitor. Collecting first keeps the visitor's `Result`
            // error path clean (the buffered `Sink` can't propagate errors).
            let mut entries = Vec::new();
            crate::formats::zip::extract_zip::<std::convert::Infallible>(
                &data,
                budget,
                &mut |e, _| {
                    entries.push(e);
                    None
                },
            )?;
            for entry in entries {
                budget.count_entry()?;
                let meta = MemberMeta {
                    name: entry.name,
                    comp_size: entry.comp_size,
                    encrypted: entry.encrypted,
                    unsupported: entry.unsupported,
                };
                let hit = if entry.unsupported.is_some() {
                    visit(&meta, None, budget)
                } else {
                    let mut cur = io::Cursor::new(&entry.data[..]);
                    visit_member(&meta, &mut cur, budget, visit)?
                };
                if let Some(t) = hit {
                    return Ok(Some(t));
                }
            }
            return Ok(None);
        }
    };
    for i in 0..zip.len() {
        budget.count_entry()?;
        // Peek metadata with the RAW reader — it never invokes the crate
        // decryptor, so it succeeds for encrypted members too.
        // A member whose header will not parse costs only itself — see the same
        // guard in `formats::zip::extract_zip_from`. Abandoning the walk here
        // strands every later member: this pass drops them and the salvage pass
        // skips them as already covered, so a payload behind one bad directory
        // pointer is never scanned and the file reports unreadable, not infected.
        if let Err(e) = zip.by_index_raw(i).map(|_| ()) {
            let hit = crate::formats::zip::zip_entry_error(i, &e);
            if !hit.corrupt {
                return Err(hit);
            }
            let meta = MemberMeta {
                name: format!("zip entry {i}"),
                comp_size: 0,
                encrypted: false,
                unsupported: Some("ZIP member header will not parse"),
            };
            if let Some(t) = visit(&meta, None, budget) {
                return Ok(Some(t));
            }
            continue;
        }
        let (name, is_file, encrypted, comp) = {
            let f = zip
                .by_index_raw(i)
                .map_err(|e| crate::formats::zip::zip_entry_error(i, &e))?;
            (
                f.name().to_string(),
                f.is_file(),
                f.encrypted(),
                f.compressed_size(),
            )
        };
        // `is_file()` is false purely because the name ends in '/'. A JAR packer
        // buys exactly that: `kingDavid/9.class/` holds a real deflate-compressed
        // class that the JVM loads by name, while every ZIP tool discards it as a
        // folder. Skip only what carries nothing at all — a "directory" with
        // content is content. (The same guard lives in `formats/zip.rs`; this is
        // the streaming walker the top-level scan actually takes.)
        if !is_file && comp == 0 {
            continue; // directory — counted toward the file budget above, skipped
        }
        if encrypted {
            if let Some(t) = stream_zip_encrypted(&mut zip, i, name, comp, budget, visit)? {
                return Ok(Some(t));
            }
            continue;
        }
        // Cleartext member: stream the decompressing reader on demand.
        //
        // A codec the `zip` crate lacks fails here rather than in our own
        // decoder, so fall back to the raw bytes and decode them ourselves —
        // otherwise a member exav CAN decode (Deflate64, LZMA, bzip2, zstd, XZ)
        // is reported unsupported purely because of which walker reached it.
        // The buffered walker already does this; the top-level scan takes this
        // one, so a fix in only one of the two never reaches the scanner.
        // Probe first so the borrow of `zip` ends before the fallback needs it.
        let decodable = zip.by_index(i).is_ok();
        let mut file = match decodable {
            true => zip
                .by_index(i)
                .map_err(|e| crate::formats::zip::zip_entry_error(i, &e))?,
            false => {
                if let Some(t) = stream_zip_raw_decode(&mut zip, i, &name, comp, budget, visit)? {
                    return Ok(Some(t));
                }
                // Nothing we can decode either: surface it, never drop it.
                let meta = MemberMeta {
                    name,
                    comp_size: comp,
                    encrypted: false,
                    unsupported: Some("unsupported zip compression method"),
                };
                if let Some(t) = visit(&meta, None, budget) {
                    return Ok(Some(t));
                }
                continue;
            }
        };
        let meta = MemberMeta {
            name,
            comp_size: comp,
            encrypted: false,
            unsupported: None,
        };
        if let Some(t) = visit_member(&meta, &mut file, budget, visit)? {
            return Ok(Some(t));
        }
    }
    Ok(None)
}

/// Decode a member the `zip` crate refused, from its RAW bytes, using exav's own
/// codec set. Returns `Ok(None)` when we cannot decode it either.
#[cfg(feature = "zip")]
fn stream_zip_raw_decode<R: Read + Seek, T>(
    zip: &mut ::zip::ZipArchive<R>,
    i: usize,
    name: &str,
    comp: u64,
    budget: &mut Budget,
    visit: StreamVisit<T>,
) -> Result<Option<T>, LimitHit> {
    let cap = budget.limits.max_buffer_bytes;
    let (method, usz, raw) = {
        let Ok(f) = zip.by_index_raw(i) else {
            return Ok(None);
        };
        let method = crate::formats::zip::zip_method_code(&f.compression());
        let usz = f.size();
        let mut raw = Vec::new();
        if f.take(cap).read_to_end(&mut raw).is_err() {
            return Ok(None);
        }
        (method, usz, raw)
    };
    let Some((out, truncated)) = crate::formats::zip::decode_zip_raw(method, &raw, usz, cap) else {
        return Ok(None);
    };
    if truncated {
        return Ok(None);
    }
    budget.commit(out.len() as u64);
    let meta = MemberMeta {
        name: name.to_string(),
        comp_size: comp,
        encrypted: false,
        unsupported: None,
    };
    let mut cur = io::Cursor::new(out);
    Ok(visit(&meta, Some(&mut cur), budget))
}

/// Handle one encrypted ZIP member: try the password pool, present the decrypted
/// plaintext as a reader on success, else a metadata-only unsupported member so
/// the caller surfaces PasswordProtected without masking later members.
#[cfg(feature = "zip")]
fn stream_zip_encrypted<R: Read + Seek, T>(
    zip: &mut ::zip::ZipArchive<R>,
    i: usize,
    name: String,
    comp: u64,
    budget: &mut Budget,
    visit: StreamVisit<T>,
) -> Result<Option<T>, LimitHit> {
    let unsupported_meta = MemberMeta {
        name: name.clone(),
        comp_size: comp,
        encrypted: true,
        unsupported: Some("encrypted ZIP member"),
    };
    // Disprove the flag BEFORE any `decrypt` gating: the check decrypts nothing,
    // it proves by CRC-32 that these bytes were never ciphertext.
    let max_buffer = budget.limits.max_buffer_bytes;
    let (crc, enc) = {
        let mut f = zip
            .by_index_raw(i)
            .map_err(|e| crate::formats::zip::zip_entry_error(i, &e))?;
        let crc = f.crc32();
        match crate::formats::zip::read_encrypted_member(&mut f, max_buffer) {
            Ok(e) => (crc, e),
            Err(_) => return Ok(visit(&unsupported_meta, None, budget)),
        }
    };
    // The bit can lie — an APK packer sets it on every member because
    // Android's ZIP reader ignores it, buying a PASSWORD-PROTECTED report on
    // an archive the platform installs happily. A CRC-32 match over a plain
    // decode proves the bytes were never encrypted. (Same guard as the
    // buffered walker in `formats/zip.rs`; this is the path the top-level
    // scan takes, and a fix in only one of the two does not reach the
    // scanner.)
    if let Some(plain) = crate::formats::zip::cleartext_despite_flag(&enc, crc) {
        budget.commit(plain.len() as u64);
        let meta = MemberMeta {
            name,
            comp_size: comp,
            encrypted: false,
            unsupported: None,
        };
        let mut cur = io::Cursor::new(plain);
        return Ok(visit(&meta, Some(&mut cur), budget));
    }
    // Actually encrypted. Without the `decrypt` feature there is no cipher
    // stack compiled in, so report it — never decrypted, never silently clean.
    #[cfg(not(feature = "decrypt"))]
    {
        Ok(visit(&unsupported_meta, None, budget))
    }
    #[cfg(feature = "decrypt")]
    {
        match crate::formats::zip::decrypt_zip_member(&enc, crc, budget)? {
            Some(plain) => {
                budget.commit(plain.len() as u64);
                // Decrypted: the plaintext is scanned AND the member is still
                // reported as having been encrypted. Clearing the flag on success
                // is what made cracking a password erase the report of one.
                let meta = MemberMeta {
                    name,
                    comp_size: comp,
                    encrypted: true,
                    unsupported: None,
                };
                let mut cur = io::Cursor::new(plain);
                Ok(visit(&meta, Some(&mut cur), budget))
            }
            None => Ok(visit(&unsupported_meta, None, budget)),
        }
    }
}

/// Stream an LHA/LZH archive: `delharc`'s per-member decoder is already a
/// `Read`, so each member is handed to the visitor and decoded on demand rather
/// than drained into a `Vec`. Members with an unsupported compression method are
/// skipped (matching the buffered extractor), and directories are ignored.
#[cfg(feature = "lha")]
fn stream_lha<R: Read + Seek, T>(
    source: &mut R,
    budget: &mut Budget,
    visit: StreamVisit<T>,
) -> Result<Option<T>, LimitHit> {
    source
        .seek(io::SeekFrom::Start(0))
        .map_err(|e| LimitHit::corrupt(format!("lha seek: {e}")))?;
    let mut dec = delharc::LhaDecodeReader::new(&mut *source)
        .map_err(|e| LimitHit::new(format!("lha: {e}")))?;
    loop {
        let supported = !dec.header().is_directory() && dec.is_decoder_supported();
        if supported {
            let name = dec.header().parse_pathname_to_str();
            budget.count_entry()?;
            let meta = MemberMeta {
                name,
                comp_size: 0,
                encrypted: false,
                unsupported: None,
            };
            if let Some(t) = visit_member(&meta, &mut dec, budget, visit)? {
                return Ok(Some(t));
            }
        }
        match dec.next_file() {
            Ok(true) => {}
            Ok(false) => break,
            Err(e) => return Err(LimitHit::new(format!("lha: {e}"))),
        }
    }
    Ok(None)
}

/// Incremental SZDD (MS-Compress) LZSS decoder as a `Read`: the 4 KiB ring
/// window is driven byte-by-byte from the source and decompressed output is
/// produced on demand, so a large expanded file is scanned without ever being
/// buffered. Mirrors `formats::szdd`'s `lzss_decompress` exactly.
#[cfg(feature = "szdd")]
struct SzddReader<'a> {
    src: &'a mut dyn Read,
    window: [u8; 4096],
    wpos: usize,
    declared: u64,
    produced: u64,
    out: [u8; 18], // one token emits ≤ 18 bytes (backref len 3..18)
    out_len: usize,
    out_pos: usize,
    flags: u32,
    bits_left: u8,
    done: bool,
}

#[cfg(feature = "szdd")]
impl<'a> SzddReader<'a> {
    fn new(src: &'a mut dyn Read, declared: u64) -> Self {
        Self {
            src,
            window: [0x20u8; 4096],
            wpos: 4096 - 16,
            declared,
            produced: 0,
            out: [0u8; 18],
            out_len: 0,
            out_pos: 0,
            flags: 0,
            bits_left: 0,
            done: false,
        }
    }
    fn next_byte(&mut self) -> io::Result<Option<u8>> {
        let mut b = [0u8; 1];
        match self.src.read(&mut b)? {
            0 => Ok(None),
            _ => Ok(Some(b[0])),
        }
    }
    fn emit(&mut self, b: u8) {
        self.out[self.out_len] = b;
        self.out_len += 1;
        self.window[self.wpos] = b;
        self.wpos = (self.wpos + 1) & 4095;
        self.produced += 1;
    }
}

#[cfg(feature = "szdd")]
impl Read for SzddReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut w = 0;
        while w < buf.len() {
            if self.out_pos < self.out_len {
                buf[w] = self.out[self.out_pos];
                self.out_pos += 1;
                w += 1;
                continue;
            }
            if self.done || self.produced >= self.declared {
                break;
            }
            self.out_len = 0;
            self.out_pos = 0;
            if self.bits_left == 0 {
                match self.next_byte()? {
                    Some(f) => {
                        self.flags = f as u32;
                        self.bits_left = 8;
                    }
                    None => {
                        self.done = true;
                        break;
                    }
                }
            }
            let is_literal = (self.flags & 1) == 1;
            self.flags >>= 1;
            self.bits_left -= 1;
            if is_literal {
                match self.next_byte()? {
                    Some(b) => self.emit(b),
                    None => {
                        self.done = true;
                        break;
                    }
                }
            } else {
                let (b0, b1) = match (self.next_byte()?, self.next_byte()?) {
                    (Some(a), Some(b)) => (a, b),
                    _ => {
                        self.done = true;
                        break;
                    }
                };
                let mut mpos = (b0 as usize) | (((b1 as usize) & 0xF0) << 4);
                let len = ((b1 as usize) & 0x0F) + 3;
                for _ in 0..len {
                    if self.produced >= self.declared {
                        break;
                    }
                    let b = self.window[mpos & 4095];
                    self.emit(b);
                    mpos = mpos.wrapping_add(1);
                }
            }
        }
        Ok(w)
    }
}

/// Stream SZDD (`expanded.bin` via the incremental LZSS `Read` above). KWAJ — the
/// other MS-Compress variant, with several compression methods — is decoded by
/// the buffered extractor over a bounded read and its members re-emitted, since
/// it is not a single LZSS stream.
#[cfg(feature = "szdd")]
fn stream_szdd<R: Read + Seek, T>(
    source: &mut R,
    budget: &mut Budget,
    visit: StreamVisit<T>,
) -> Result<Option<T>, LimitHit> {
    const SZDD_MAGIC: &[u8; 8] = b"SZDD\x88\xF0\x27\x33";
    source
        .seek(io::SeekFrom::Start(0))
        .map_err(|e| LimitHit::corrupt(format!("szdd: {e}")))?;
    let mut hdr = [0u8; 14];
    let mut n = 0;
    while n < hdr.len() {
        match source.read(&mut hdr[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(_) => break,
        }
    }
    if n >= 8 && &hdr[0..8] == SZDD_MAGIC {
        if n < 14 {
            return Err(LimitHit::corrupt("szdd: truncated header".to_string()));
        }
        let declared = u32::from_le_bytes([hdr[10], hdr[11], hdr[12], hdr[13]]) as u64;
        budget.count_entry()?;
        source
            .seek(io::SeekFrom::Start(14))
            .map_err(|e| LimitHit::corrupt(format!("szdd: {e}")))?;
        let mut rdr = SzddReader::new(&mut *source, declared);
        let meta = MemberMeta {
            name: "expanded.bin".to_string(),
            comp_size: 0,
            encrypted: false,
            unsupported: None,
        };
        return visit_member(&meta, &mut rdr, budget, visit);
    }
    // KWAJ / other: buffered decode, bounded, members re-emitted.
    source
        .seek(io::SeekFrom::Start(0))
        .map_err(|e| LimitHit::corrupt(format!("szdd: {e}")))?;
    let (buf, truncated) = crate::bounded_read(&mut *source, budget.limits.max_buffer_bytes)
        .map_err(|e| LimitHit::corrupt(format!("szdd: {e}")))?;
    if truncated {
        return Err(LimitHit::new("szdd input exceeds max-buffer".to_string()));
    }
    for e in crate::extract(Format::Szdd, &buf, budget)? {
        let meta = MemberMeta {
            name: e.name,
            comp_size: e.comp_size,
            encrypted: e.encrypted,
            unsupported: e.unsupported,
        };
        let r = if e.unsupported.is_some() {
            visit(&meta, None, budget)
        } else {
            let mut cur = io::Cursor::new(e.data);
            visit(&meta, Some(&mut cur), budget)
        };
        if r.is_some() {
            return Ok(r);
        }
    }
    Ok(None)
}

/// Stream an SWF movie: `CWS` (zlib) / `ZWS` (LZMA) bodies decode through a `Read`
/// adapter, so a large decompressed movie is scanned without being buffered. The
/// rebuilt `FWS` header is chained ahead of the decoded body (matching
/// [`crate::formats::extract_swf`]). `FWS` (already uncompressed) yields no member
/// — its bytes are covered by the caller's raw-container scan.
#[cfg(feature = "swf")]
fn stream_swf<R: Read + Seek, T>(
    source: &mut R,
    budget: &mut Budget,
    visit: StreamVisit<T>,
) -> Result<Option<T>, LimitHit> {
    let total = source
        .seek(io::SeekFrom::End(0))
        .map_err(|e| LimitHit::corrupt(format!("swf: {e}")))?;
    source
        .seek(io::SeekFrom::Start(0))
        .map_err(|e| LimitHit::corrupt(format!("swf: {e}")))?;
    let mut hdr = [0u8; 17];
    let mut n = 0;
    while n < hdr.len() {
        match source.read(&mut hdr[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(_) => break,
        }
    }
    if n < 8 || (&hdr[0..3] != b"CWS" && &hdr[0..3] != b"ZWS") {
        return Ok(None); // FWS / non-SWF: covered by the raw-container scan
    }
    budget.count_entry()?;
    let mut fws = Vec::with_capacity(8);
    fws.extend_from_slice(b"FWS");
    fws.extend_from_slice(&hdr[3..8]);
    let meta = MemberMeta {
        name: "movie.swf".to_string(),
        comp_size: 0,
        encrypted: false,
        unsupported: None,
    };
    let unsupported = MemberMeta {
        name: "movie.swf".to_string(),
        comp_size: total.saturating_sub(8),
        encrypted: false,
        unsupported: Some("SWF LZMA decode unsupported"),
    };
    if &hdr[0..3] == b"CWS" {
        source
            .seek(io::SeekFrom::Start(8))
            .map_err(|e| LimitHit::corrupt(format!("swf: {e}")))?;
        let dec = flate2::read::ZlibDecoder::new(&mut *source);
        let mut reader = io::Cursor::new(fws).chain(dec);
        visit_member(&meta, &mut reader, budget, visit)
    } else {
        // ZWS / LZMA: 8 header + 4 comp-length + 5 LZMA props before the stream.
        if n < 17 {
            return Ok(visit(&unsupported, None, budget));
        }
        let file_length = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as u64;
        let want = file_length.saturating_sub(8);
        let props = hdr[12];
        let dict_size = swf_dict_size(
            u32::from_le_bytes([hdr[13], hdr[14], hdr[15], hdr[16]]),
            want,
            budget.limits.max_buffer_bytes,
        );
        source
            .seek(io::SeekFrom::Start(17))
            .map_err(|e| LimitHit::corrupt(format!("swf: {e}")))?;
        match lzma_rust2::LzmaReader::new_with_props(&mut *source, want, props, dict_size, None) {
            Ok(dec) => {
                let mut reader = io::Cursor::new(fws).chain(dec);
                visit_member(&meta, &mut reader, budget, visit)
            }
            Err(_) => Ok(visit(&unsupported, None, budget)),
        }
    }
}

/// Pick the LZMA dictionary size for a `ZWS` movie. Both `declared` (the props
/// header's dictionary field) and `want` (the movie header's own `FileLength`,
/// less the 8-byte header) are attacker-controlled, and the dictionary is
/// allocated up front — so `want` is no ceiling on its own: a movie declaring
/// 4 GiB would buy itself a 4 GiB dictionary. `max_buffer` is the real bound;
/// `want` only ever tightens it, since a dictionary larger than the bytes it
/// will be used to look back into cannot be consulted.
#[cfg(feature = "swf")]
fn swf_dict_size(declared: u32, want: u64, max_buffer: u64) -> u32 {
    crate::bounded_dict(declared, want.min(max_buffer))
}

/// Emit a set of pre-parsed stored (uncompressed) members `(name, offset, size)`
/// by seeking to each and handing the visitor a bounded window — the shared tail
/// of every STORED-OFFSET format (ar/cpio/machofat/…). No member data is ever
/// buffered here.
// Dead only in a build with none of the STORED-OFFSET formats (ar, cpio,
// machofat, pyc, sfx, tnef, partition, iso, onenote); see
// `crate::cap_prealloc` for why the feature list is not spelled out.
#[allow(dead_code)]
pub(crate) fn stream_stored<R: Read + Seek, T>(
    source: &mut R,
    budget: &mut Budget,
    visit: StreamVisit<T>,
    members: &[(String, u64, u64)],
) -> Result<Option<T>, LimitHit> {
    for (name, offset, size) in members {
        budget.count_entry()?;
        // A zero-length `<…>` region is a walker saying it stopped short — too
        // many partitions, too many ISO directories. It names content that was
        // never enumerated, so it has to arrive as UNSUPPORTED. Emitting it as
        // an ordinary empty member would make "we did not look" indistinguishable
        // from "we looked and it was empty", which is the shape of a silent
        // clean. The buffered walkers say this with `Entry::unsupported`; this
        // is the streamed half of the same statement.
        if *size == 0 && name.starts_with('<') && name.ends_with('>') {
            let meta = MemberMeta {
                name: name.clone(),
                comp_size: 0,
                encrypted: false,
                unsupported: Some("container walk stopped at its limit"),
            };
            if let Some(t) = visit(&meta, None, budget) {
                return Ok(Some(t));
            }
            continue;
        }
        source
            .seek(io::SeekFrom::Start(*offset))
            .map_err(|e| LimitHit::corrupt(format!("stored member seek: {e}")))?;
        let mut window = source.take(*size);
        let meta = MemberMeta {
            name: name.clone(),
            comp_size: *size,
            encrypted: false,
            unsupported: None,
        };
        if let Some(t) = visit_member(&meta, &mut window, budget, visit)? {
            return Ok(Some(t));
        }
    }
    Ok(None)
}

#[cfg(feature = "tar")]
fn stream_tar<R: Read + Seek, T>(
    source: &mut R,
    budget: &mut Budget,
    visit: StreamVisit<T>,
) -> Result<Option<T>, LimitHit> {
    // The SAME reader the buffered `extract` path uses. Two readers of one
    // format can disagree, and when the scan path holds the weaker one, a header
    // form it mishandles makes the scanner see nothing while `exav-unpack list`
    // shows every member — the diagnostic tool contradicting the defect. One
    // reader cannot disagree with itself.
    //
    // No cost to memory: `entries()` needs only `Read`, and each entry IS a
    // reader bounded to its member, so nothing is buffered.
    source
        .seek(io::SeekFrom::Start(0))
        .map_err(|e| LimitHit::corrupt(format!("tar seek: {e}")))?;
    let mut archive = ::tar::Archive::new(source);
    let entries = archive
        .entries()
        .map_err(|e| LimitHit::corrupt(format!("tar: {e}")))?;
    for entry in entries {
        budget.count_entry()?;
        let mut entry = match entry {
            Ok(e) => e,
            // A truncated archive: entries before the cut were already scanned,
            // and the missing tail is absent rather than hidden. exav scans for
            // malware, it is not an integrity validator — the buffered path makes
            // the same call for the same reason.
            Err(e) if crate::formats::tar::is_truncation(&e) => return Ok(None),
            Err(e) => return Err(LimitHit::corrupt(format!("tar entry: {e}"))),
        };
        let name = entry
            .path()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "tar-entry".to_string());
        let size = entry.size();
        let meta = MemberMeta {
            name,
            comp_size: size,
            encrypted: false,
            unsupported: None,
        };
        if let Some(t) = visit_member(&meta, &mut entry, budget, visit)? {
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

    /// Collect every member `(name, bytes)` the streaming API yields for `blob`.
    ///
    /// Every test using it is behind a format feature, so it is dead in a build
    /// with none of them compiled in.
    #[allow(dead_code)]
    fn streamed_members(fmt: Format, blob: &[u8]) -> Vec<(String, Vec<u8>)> {
        let mut budget = Budget::new(Limits::default());
        let mut out: Vec<(String, Vec<u8>)> = Vec::new();
        let mut visit = |m: &MemberMeta, r: Option<&mut dyn Read>, _b: &mut Budget| -> Option<()> {
            let mut data = Vec::new();
            if let Some(r) = r {
                let _ = r.read_to_end(&mut data);
            }
            out.push((m.name.clone(), data));
            None
        };
        let _ = stream_members(fmt, Cursor::new(blob.to_vec()), &mut budget, &mut visit);
        out
    }

    /// The streaming path must yield the same member `(name, bytes)` as the
    /// buffered [`crate::extract`] path — the correctness contract for every
    /// STORED-OFFSET conversion.
    #[allow(dead_code)] // see `streamed_members`
    fn assert_stream_matches_buffered(fmt: Format, blob: &[u8]) {
        let mut budget = Budget::new(Limits::default());
        let buffered: Vec<(String, Vec<u8>)> = crate::extract(fmt, blob, &mut budget)
            .unwrap()
            .into_iter()
            .filter(|e| e.unsupported.is_none())
            .map(|e| (e.name, e.data))
            .collect();
        let streamed = streamed_members(fmt, blob);
        assert_eq!(
            streamed, buffered,
            "{fmt:?}: streamed members differ from buffered"
        );
    }

    // A `ZWS` header carries two attacker-chosen sizes, and the LZMA dictionary
    // is allocated before a single byte is decoded. Neither may set that size.
    #[cfg(feature = "swf")]
    #[test]
    fn swf_dictionary_is_bounded_by_the_buffer_limit() {
        let max_buffer = Limits::default().max_buffer_bytes;
        // The sizes from a movie that asked for a 2.7 GiB dictionary by declaring
        // a ~4 GiB FileLength: neither number may be believed.
        assert_eq!(
            swf_dict_size(0xA1A1_C32B, 0xF04A_0957 - 8, max_buffer),
            max_buffer as u32,
            "a huge declared dictionary is clamped to the buffer limit"
        );
        // A movie small enough to be honest keeps its own (smaller) dictionary.
        assert_eq!(
            swf_dict_size(1 << 16, 1 << 20, max_buffer),
            1 << 16,
            "a dictionary under both bounds is used as-is"
        );
        // `want` still tightens: no point holding more history than output.
        assert_eq!(
            swf_dict_size(u32::MAX, 1 << 20, max_buffer),
            1 << 20,
            "the declared output bounds the dictionary when it is the smaller"
        );
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
    fn stream_ar_matches_buffered() {
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
        assert_stream_matches_buffered(Format::Ar, &blob);
    }

    #[cfg(feature = "cpio")]
    #[test]
    fn stream_cpio_newc_matches_buffered() {
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
        assert_stream_matches_buffered(Format::Cpio, &blob);
    }

    #[cfg(feature = "machofat")]
    #[test]
    fn stream_machofat_matches_buffered() {
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
        assert_stream_matches_buffered(Format::Machofat, &blob);
    }

    #[cfg(feature = "onenote")]
    #[test]
    fn stream_onenote_matches_buffered() {
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
        assert_stream_matches_buffered(Format::OneNote, &blob);
    }

    #[cfg(feature = "szdd")]
    #[test]
    fn stream_szdd_matches_buffered() {
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
        assert_stream_matches_buffered(Format::Szdd, &blob);
    }

    // 7z pattern-A streaming must yield exactly the same files (as a set) as the
    // buffered extractor — including the solid multi-file case, where each file is
    // carved from one decompressed block by skip+take without buffering the block.
    #[cfg(feature = "sevenz")]
    #[test]
    fn stream_sevenz_matches_buffered() {
        use std::collections::BTreeMap;
        fn as_map(v: Vec<(String, Vec<u8>)>) -> BTreeMap<String, Vec<u8>> {
            v.into_iter().collect()
        }
        for name in ["lzma2.7z", "lzma.7z", "copy.7z", "deflate.7z", "bzip2.7z"] {
            let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/7z")
                .join(name);
            let blob = std::fs::read(&p).unwrap();
            let mut budget = Budget::new(Limits::default());
            let buffered: Vec<(String, Vec<u8>)> =
                crate::extract(Format::SevenZip, &blob, &mut budget)
                    .unwrap()
                    .into_iter()
                    .filter(|e| e.unsupported.is_none())
                    .map(|e| (e.name, e.data))
                    .collect();
            let streamed = streamed_members(Format::SevenZip, &blob);
            assert_eq!(
                as_map(streamed),
                as_map(buffered),
                "{name}: streamed 7z files differ"
            );
        }
    }

    // Cab pattern-A streaming must yield the same files as the buffered
    // extractor. No valid multi-file cab fixture ships (only fuzz cases), so we
    // build a minimal STORED (uncompressed) cab with two files in one folder —
    // exercising FolderReader + the skip/window/offset logic in stream_cab.
    #[cfg(feature = "cab")]
    #[test]
    fn stream_cab_matches_buffered() {
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
        let blob = build_stored_cab(&[
            ("readme.txt", b"hello cab world"),
            ("data.bin", b"\x00\x01\x02\x03\x04\x05"),
        ]);
        assert_stream_matches_buffered(Format::Cab, &blob);
        // Two files in one folder with a gap-free layout also exercises the
        // per-file skip/window/offset bookkeeping.
        let three = build_stored_cab(&[("x", b"AAAA"), ("y", b"BBBBBBBB"), ("z", b"C")]);
        assert_stream_matches_buffered(Format::Cab, &three);
    }

    // MSZIP cab (via the `cab` crate) with a multi-block folder: exercises the
    // FolderReader over a real compressed folder whose 2nd+ blocks reference the
    // previous block's window (the MSZIP dictionary-priming fix).
    #[cfg(feature = "cab")]
    #[test]
    fn stream_cab_mszip_matches_buffered() {
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
        assert_stream_matches_buffered(Format::Cab, &blob);
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
