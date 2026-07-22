// `wasm_bindgen`'s expansion contains `unsafe`, so this crate cannot `forbid` it
// outright the way the rest of the workspace does. Denying it covers the code
// exav writes, which is where the guarantee is available to give: nothing
// hand-written here is unsafe, and the generated glue is the only exception.
#![deny(unsafe_code)]

//! WebAssembly bindings for `exav-unpack` — memory-safe, in-browser archive
//! extraction with no native/C dependencies.
//!
//! This module is SYNCHRONOUS throughout, and that is the design rather than an
//! omission. `exav_unpack::Archive` is `Read + Seek`; meeting it on its own
//! terms is what lets a browser build share exav's archive readers instead of
//! carrying a second set, and a second set is a second set of answers about the
//! same bytes. Reading a `File` synchronously needs `FileReaderSync`, which
//! exists only inside a Worker — so the `File` path runs in a Worker, and
//! `js/index.js` presents the async API a caller on the main thread uses.
//! Bytes already in memory need no Worker and take the same code through a
//! `Cursor`.
//!
//! From JavaScript, through the facade:
//!
//! ```js
//! import init, { Archive, unpack } from "exav-unpack-wasm";
//! await init();
//!
//! const archive = await Archive.open(file);
//! const members = archive.list();
//! const entry = await archive.extract(0);
//!
//! const entries = await unpack(bytes);
//! ```

mod source;

use exav_unpack::{Budget, Entry as UnpackEntry, Format, Limits};
use js_sys::{Array, Object, Reflect, Uint8Array};
use source::Src;
use wasm_bindgen::prelude::*;

/// Carry any error's message out to JS.
fn err<E: std::fmt::Display>(e: E) -> JsValue {
    JsValue::from_str(&e.to_string())
}

// ---------------------------------------------------------------------------
// Helpers: format names, limits, JS conversions
// ---------------------------------------------------------------------------

fn format_name(fmt: Format) -> String {
    format!("{fmt:?}")
}

/// Refuse a format the caller excluded.
///
/// `allowedFormats` is a per-call control — "open only these; anything else is
/// reported" — and it has to be checked on the way IN. `Limits::allows` is also
/// consulted during extraction, but an archive that was never allowed should
/// not open at all.
fn check_allowed(fmt: Format, limits: &Limits) -> Result<(), JsValue> {
    if limits.allows(fmt) {
        Ok(())
    } else {
        Err(JsValue::from_str(&format!(
            "{} is not in allowedFormats",
            format_name(fmt)
        )))
    }
}

/// One extracted member, as JS receives it.
///
/// `data` is a `Uint8Array` rather than a stream: an entry crosses the Worker
/// boundary by structured clone, which a `ReadableStream` does not survive
/// without being transferred. `js/index.js` wraps it into the stream the public
/// API promises, on whichever side the caller is.
fn entry_to_js(name: &str, data: &[u8], encrypted: bool, unsupported: &str) -> Result<JsValue, JsValue> {
    let obj = Object::new();
    Reflect::set(&obj, &"name".into(), &JsValue::from_str(name))?;
    Reflect::set(&obj, &"data".into(), &Uint8Array::from(data))?;
    Reflect::set(&obj, &"encrypted".into(), &JsValue::from_bool(encrypted))?;
    Reflect::set(
        &obj,
        &"unsupported".into(),
        &JsValue::from_str(unsupported),
    )?;
    Ok(obj.into())
}

fn unpack_entry_to_js(e: &UnpackEntry) -> Result<JsValue, JsValue> {
    #[cfg(feature = "testing-faults")]
    provoke(&e.name);
    entry_to_js(&e.name, &e.data, e.encrypted, e.unsupported.unwrap_or(""))
}

/// Fail the way a decoder can, for a member named to ask for it.
///
/// Every one of these is beyond Rust's reach on this target — `panic = "abort"`
/// means no unwind to catch, a failed allocation aborts rather than returning,
/// and an exhausted stack traps. That is precisely why they are worth firing on
/// purpose: the containment for them lives in JS, and containment that has never
/// been triggered is an assumption.
///
/// Sited here because both `extract` and `extractAll` produce entries through
/// this function, so one hook covers both.
#[cfg(feature = "testing-faults")]
fn provoke(name: &str) {
    match name {
        "__exav_panic__" => panic!("deliberate panic from the testing-faults feature"),
        "__exav_oom__" => {
            // Reserved, never written: the point is to exhaust the address
            // space, and writing would only make it slower. wasm32 tops out at
            // 4 GiB, so this ends quickly.
            let mut held: Vec<Vec<u8>> = Vec::new();
            loop {
                held.push(Vec::<u8>::with_capacity(256 * 1024 * 1024));
                std::hint::black_box(&held);
            }
        }
        "__exav_stack__" => {
            // Not tail-recursive, and the result is used, so it cannot be
            // optimised into a loop.
            fn deeper(n: u64) -> u64 {
                if n == 0 {
                    0
                } else {
                    1 + std::hint::black_box(deeper(n + 1))
                }
            }
            std::hint::black_box(deeper(1));
        }
        _ => {}
    }
}

/// A member that could not be produced, reported as a member rather than
/// dropped.
///
/// A limit reached part-way through is not "the archive ends here". Returning
/// the members extracted so far and saying nothing about the rest turns "I
/// stopped" into "there was no more", which is the one answer this crate must
/// never give.
fn limit_marker_to_js(why: &str) -> Result<JsValue, JsValue> {
    entry_to_js(&format!("<{why}>"), &[], false, why)
}

fn member_to_js(m: &exav_unpack::MemberInfo) -> Result<JsValue, JsValue> {
    let obj = Object::new();
    Reflect::set(&obj, &"name".into(), &JsValue::from_str(&m.name))?;
    Reflect::set(&obj, &"index".into(), &JsValue::from_f64(m.index as f64))?;
    Reflect::set(
        &obj,
        &"compressedSize".into(),
        &JsValue::from_f64(m.compressed_size as f64),
    )?;
    Reflect::set(
        &obj,
        &"uncompressedSize".into(),
        &JsValue::from_f64(m.uncompressed_size as f64),
    )?;
    Reflect::set(&obj, &"encrypted".into(), &JsValue::from_bool(m.encrypted))?;
    Ok(obj.into())
}

fn parse_passwords(passwords: &JsValue) -> Vec<String> {
    let Some(arr) = passwords.dyn_ref::<Array>() else {
        return Vec::new();
    };
    arr.iter().filter_map(|v| v.as_string()).collect()
}

/// Bounds for a browser, which are not the bounds for a server.
///
/// `Limits::default()` is sized for a scanner on a host with real memory: 1 GiB
/// of extraction, 256 MiB for one member. wasm32 caps the whole address space
/// at 4 GiB and a browser commonly allows far less, so those defaults let a
/// page ask for more than the tab can give. Running out is not an error the
/// caller sees — the module aborts and takes its instance with it, so the JS
/// side gets no verdict at all.
///
/// The two byte budgets are therefore cut to an eighth, 128 MiB and 32 MiB. The
/// rest of `Limits` is kept as it stands: member count, recursion depth and
/// compression ratio bound counts and shapes rather than bytes, so the address
/// space is not what constrains them. Raise any of them through the `limits`
/// argument if the page can afford it.
fn browser_limits() -> Limits {
    Limits {
        max_extracted_bytes: 128 * 1024 * 1024,
        max_buffer_bytes: 32 * 1024 * 1024,
        ..Limits::default()
    }
}

/// Read a `{ maxExtractedBytes, maxBufferBytes, maxMembers, maxRecursion,
/// maxCompressionRatio }` object from JS. Absent keys keep the browser default;
/// a caller sets only what it cares about.
fn limits_from_js(v: &JsValue) -> Limits {
    let mut l = browser_limits();
    if v.is_undefined() || v.is_null() {
        return l;
    }
    let num = |k: &str| -> Option<f64> {
        Reflect::get(v, &JsValue::from_str(k))
            .ok()
            .and_then(|x| x.as_f64())
            .filter(|n| *n >= 0.0 && n.is_finite())
    };
    if let Some(n) = num("maxExtractedBytes") {
        l.max_extracted_bytes = n as u64;
    }
    if let Some(n) = num("maxBufferBytes") {
        l.max_buffer_bytes = n as u64;
    }
    if let Some(n) = num("maxMembers") {
        l.max_members = n as u64;
    }
    if let Some(n) = num("maxRecursion") {
        l.max_recursion = n as u32;
    }
    if let Some(n) = num("maxCompressionRatio") {
        l.max_compression_ratio = n as u64;
    }
    // `allowedFormats: ["Zip", "Tar"]` — names as `detectFormat` reports them.
    // An unknown name is ignored rather than rejected: a page pinned to an
    // older module should not fail outright because it listed a format that
    // build does not have, and anything not listed is excluded anyway.
    if let Ok(v) = Reflect::get(v, &JsValue::from_str("allowedFormats")) {
        if let Some(arr) = v.dyn_ref::<Array>() {
            let mut set = std::collections::BTreeSet::new();
            for item in arr.iter() {
                if let Some(f) = item.as_string().and_then(|n| format_by_name(&n)) {
                    set.insert(f);
                }
            }
            l.allowed_formats = Some(set);
        }
    }
    l
}

/// Look a `Format` up by the name `format_name` prints, so the JS side names
/// formats the same way it reads them back.
fn format_by_name(name: &str) -> Option<Format> {
    Format::ALL
        .iter()
        .copied()
        .find(|f| format_name(*f).eq_ignore_ascii_case(name))
}

// ---------------------------------------------------------------------------
// Archive
// ---------------------------------------------------------------------------

/// An open archive.
///
/// Every method is synchronous. On the main thread this type is reached only
/// with bytes already in memory; for a `File` it lives inside a Worker and
/// `js/index.js` is what a page talks to.
#[wasm_bindgen]
pub struct Archive {
    inner: exav_unpack::Archive<Src>,
    limits: Limits,
    /// The members of an archive that carries no index, once walked.
    ///
    /// `exav_unpack::Archive::list` reports an index where the format has one.
    /// Where it does not, it reports an empty slice — and passing that straight
    /// out would tell a page the archive holds NOTHING, which is the one answer
    /// this crate must never give. So an archive without an index is walked
    /// once and held: its members are not knowable any other way, since finding
    /// them and extracting them are the same operation.
    ///
    /// Nothing here is decided per format. Whatever `exav_unpack` can index, it
    /// indexes, and this never runs for it.
    walked: Option<Walk>,
}

/// What one walk of a directory-less archive found, and why it stopped.
struct Walk {
    entries: Vec<UnpackEntry>,
    /// Set when a limit ended the walk early, so the caller is told the list is
    /// short rather than left to read it as complete.
    stopped: Option<String>,
}

#[wasm_bindgen]
impl Archive {
    /// Open from a `Uint8Array`, a `File`/`Blob` inside a Worker, or a
    /// caller-supplied `{ read(offset, length): Uint8Array, size: number }`.
    ///
    /// A supplied `read` is SYNCHRONOUS and returns bytes rather than a promise
    /// of them: the archive readers are `Read + Seek`, and there is nowhere in
    /// a `read` that returns bytes to await anything.
    ///
    /// `limits` is optional and bounds every extraction from this archive:
    /// `{ maxExtractedBytes, maxBufferBytes, maxMembers, maxRecursion,
    /// maxCompressionRatio, allowedFormats }`. Absent keys keep the browser
    /// default, which is an order of magnitude below the library's own — a tab
    /// has far less room than a server, and running out of it aborts the module
    /// rather than returning an error.
    #[wasm_bindgen(js_name = "open")]
    pub fn open(source: JsValue, limits: Option<JsValue>) -> Result<Archive, JsValue> {
        let limits = limits_from_js(&limits.unwrap_or(JsValue::UNDEFINED));
        let src = if let Some(bytes) = source.dyn_ref::<Uint8Array>() {
            Src::Memory(std::io::Cursor::new(bytes.to_vec()))
        } else if let Some(blob) = source.dyn_ref::<web_sys::Blob>() {
            // `File` is a `Blob`, so one branch covers both.
            Src::from_blob(blob.clone())?
        } else if let Some(obj) = source.dyn_ref::<Object>() {
            Src::from_js_reader(obj)?
        } else {
            return Err(JsValue::from_str(
                "expected a Uint8Array, a File/Blob inside a Worker, \
                 or a { read(offset, length), size } object",
            ));
        };

        let inner = exav_unpack::Archive::open(src).map_err(err)?;
        check_allowed(inner.format(), &limits)?;
        Ok(Archive {
            inner,
            limits,
            walked: None,
        })
    }

    /// Whether this archive carries an index that can be read without
    /// extracting anything.
    ///
    /// A capability, asked of the archive, rather than a list of formats kept
    /// here — as `exav_unpack` learns to index another format, this starts
    /// reporting it with no change on this side.
    fn is_indexed(&self) -> bool {
        !self.inner.list().is_empty()
    }

    /// Walk a directory-less archive once, and keep what it found.
    ///
    /// The walk is what extraction does, so doing it twice would decompress
    /// everything twice — and for a source that only reads forward, the second
    /// walk would find nothing at all.
    fn walk(&mut self, passwords: Vec<String>) -> &Walk {
        if self.walked.is_none() {
            let mut budget = Budget::with_passwords(self.limits.clone(), passwords);
            let mut entries = Vec::new();
            let mut stopped = None;
            loop {
                match self.inner.extract_next(&mut budget) {
                    Ok(Some(e)) => entries.push(e),
                    Ok(None) => break,
                    Err(hit) => {
                        stopped = Some(hit.to_string());
                        break;
                    }
                }
            }
            self.walked = Some(Walk { entries, stopped });
        }
        self.walked.as_ref().expect("just populated")
    }

    /// The detected format's name.
    pub fn format(&self) -> String {
        format_name(self.inner.format())
    }

    /// The members, as metadata.
    ///
    /// Where the archive carries an index — a ZIP's central directory, a tar's
    /// headers — this reads what `open` already parsed: no further I/O, and no
    /// member decompressed. Where it does not, the members are only knowable by
    /// walking, so the walk happens here and is kept.
    pub fn list(&mut self, passwords: Option<JsValue>) -> Result<Array, JsValue> {
        let out = Array::new();
        if self.is_indexed() {
            for m in self.inner.list() {
                out.push(&member_to_js(m)?);
            }
            return Ok(out);
        }
        let pw = passwords.map(|p| parse_passwords(&p)).unwrap_or_default();
        let walk = self.walk(pw);
        for (index, e) in walk.entries.iter().enumerate() {
            out.push(&member_to_js(&exav_unpack::MemberInfo {
                name: e.name.clone(),
                index,
                compressed_size: e.comp_size,
                uncompressed_size: e.data.len() as u64,
                encrypted: e.encrypted,
            })?);
        }
        if let Some(why) = walk.stopped.clone() {
            out.push(&limit_marker_to_js(&why)?);
        }
        Ok(out)
    }

    /// Extract one member by index.
    pub fn extract(&mut self, index: usize, passwords: Option<JsValue>) -> Result<JsValue, JsValue> {
        let pw = passwords.map(|p| parse_passwords(&p)).unwrap_or_default();
        if self.is_indexed() {
            let mut budget = Budget::with_passwords(self.limits.clone(), pw);
            let entry = self.inner.extract(index, &mut budget).map_err(err)?;
            return unpack_entry_to_js(&entry);
        }
        let walk = self.walk(pw);
        match walk.entries.get(index) {
            Some(e) => unpack_entry_to_js(e),
            None => Err(JsValue::from_str(&format!("index {index} out of bounds"))),
        }
    }

    /// Extract every member.
    ///
    /// One budget across the whole archive, so `maxMembers`,
    /// `maxExtractedBytes` and the compression-ratio guard bound the ARCHIVE
    /// rather than each member of it. A limit reached part-way is reported as a
    /// final member saying so, because a list that simply ends reads as an
    /// archive that simply ended.
    #[wasm_bindgen(js_name = "extractAll")]
    pub fn extract_all(&mut self, passwords: Option<JsValue>) -> Result<Array, JsValue> {
        let pw = passwords.map(|p| parse_passwords(&p)).unwrap_or_default();
        let out = Array::new();
        if !self.is_indexed() {
            let walk = self.walk(pw);
            for e in &walk.entries {
                out.push(&unpack_entry_to_js(e)?);
            }
            if let Some(why) = walk.stopped.clone() {
                out.push(&limit_marker_to_js(&why)?);
            }
            return Ok(out);
        }
        let mut budget = Budget::with_passwords(self.limits.clone(), pw);
        loop {
            match self.inner.extract_next(&mut budget) {
                Ok(Some(e)) => out.push(&unpack_entry_to_js(&e)?),
                Ok(None) => break,
                Err(hit) => {
                    out.push(&limit_marker_to_js(&hit.to_string())?);
                    break;
                }
            };
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Standalone functions
// ---------------------------------------------------------------------------

/// Detect the archive/container format from magic bytes.
#[wasm_bindgen(js_name = "detectFormat")]
pub fn detect_format(data: &[u8]) -> Option<String> {
    exav_unpack::detect(data).map(format_name)
}

/// Extract every member from bytes already in memory.
///
/// `limits` takes the same object as [`Archive::open`].
#[wasm_bindgen]
pub fn unpack(
    data: Uint8Array,
    passwords: Option<JsValue>,
    limits: Option<JsValue>,
) -> Result<Array, JsValue> {
    let mut archive = Archive::open(data.into(), limits)?;
    archive.extract_all(passwords)
}

/// Rejoin the **multi-volume archives** among a group of files handed over
/// together — a multi-file drop, a directory picker, a set of uploads.
///
/// A set like `big.7z.001`, `.002`, `.003` is one archive cut into pieces at
/// arbitrary byte offsets. Opened one file at a time, none of them is a
/// recognisable archive at all; only the whole set is. This is what turns the
/// group back into files [`Archive::open`] can take.
///
/// Input: an array of `{ name: string, data: Uint8Array }`.
///
/// Output: an array of `{ name, data: Uint8Array, parts: string[], incomplete }`
/// — one entry per set. `incomplete` is `null` for a set that rejoined, and
/// otherwise a string saying why it could not, with `data` holding the pieces
/// that were present. Those pieces are returned rather than dropped on purpose:
/// their bytes belong to an archive nothing can now read, and letting them
/// vanish is precisely the failure this crate exists to prevent.
///
/// Files that are not part of a set are simply absent from the result — the
/// caller already has them. Names are labels: nothing here resolves a path.
///
/// Format-aware volumes (RAR `.partN`, ZIP `.zNN`) are not rejoined here. Each
/// carries its own headers and a member's data resumes *past* the next volume's
/// header, so concatenating them yields garbage that still looks like an
/// archive — that join belongs to the format's decoder.
#[wasm_bindgen(js_name = "joinVolumes")]
pub fn join_volumes(files: &Array) -> Result<Array, JsValue> {
    // No cap of its own: the caller already holds every one of these buffers, so
    // holding them once more is what it asked for.
    let mut collector = exav_unpack::volume::Collector::new(u64::MAX);
    for f in files.iter() {
        let obj = f
            .dyn_ref::<Object>()
            .ok_or_else(|| JsValue::from_str("each file must be { name, data }"))?;
        let name = Reflect::get(obj, &"name".into())?
            .as_string()
            .ok_or_else(|| JsValue::from_str("`name` must be a string"))?;
        let data = Reflect::get(obj, &"data".into())?;
        let data = data
            .dyn_ref::<Uint8Array>()
            .ok_or_else(|| JsValue::from_str("`data` must be a Uint8Array"))?
            .to_vec();
        collector.offer(&name, data);
    }
    let held = collector.finish();
    let out = Array::new();
    for j in held.joined {
        let obj = Object::new();
        Reflect::set(&obj, &"name".into(), &JsValue::from_str(&j.name))?;
        Reflect::set(&obj, &"data".into(), &Uint8Array::from(j.data.as_slice()))?;
        let parts = Array::new();
        for p in &j.parts {
            parts.push(&JsValue::from_str(p));
        }
        Reflect::set(&obj, &"parts".into(), &parts)?;
        Reflect::set(&obj, &"incomplete".into(), &JsValue::NULL)?;
        out.push(&obj);
    }
    for u in held.unjoined {
        // A lone numbered file is not a set — plenty of ordinary files end in
        // `.001` — and the caller already has it.
        let Some(reason) = u.incomplete_set else {
            continue;
        };
        let obj = Object::new();
        Reflect::set(&obj, &"name".into(), &JsValue::from_str(&u.name))?;
        Reflect::set(&obj, &"data".into(), &Uint8Array::from(u.data.as_slice()))?;
        let parts = Array::new();
        parts.push(&JsValue::from_str(&u.name));
        Reflect::set(&obj, &"parts".into(), &parts)?;
        Reflect::set(&obj, &"incomplete".into(), &JsValue::from_str(reason))?;
        out.push(&obj);
    }
    Ok(out)
}

/// Whether a filename marks a file as one part of a **byte-split** archive
/// (`big.7z.001`). Names only: nothing is read, so this is cheap enough to run
/// over a whole directory listing before deciding what to load.
#[wasm_bindgen(js_name = "isVolumePart")]
pub fn is_volume_part(name: &str) -> bool {
    exav_unpack::volume::parse(name).is_some_and(|v| v.scheme.is_byte_split())
}
