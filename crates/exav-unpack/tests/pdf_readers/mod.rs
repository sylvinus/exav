//! One PDF through the two readings the scanner uses, and what differs.
//!
//! The members of a PDF (the streams signatures run on, the scripts and link
//! targets) come from exav-unpack's own reader, and its visible text from
//! hayro-syntax. Neither reading is asked for more than it exposes: exav-unpack
//! gives its members (`extract`), hayro its objects, their decoded streams and
//! its pages (`Pdf::objects`, `Stream::decoded`, `Pdf::pages`).
//!
//! What both give, and so what is compared:
//! - the streams found, by object and generation number, and their decoded
//!   bytes (hayro's image codecs are not run: they size buffers by what the
//!   image declares, and exav-unpack hands those streams on undecoded);
//! - the strings under `/JS` and `/JavaScript` (exav-unpack's `pdf-javascript`
//!   member) and under the link and launch keys, `/F` file specification names
//!   among them (`pdf-uris`);
//! - whether the file opens, and whether it is refused as encrypted.
//!
//! What neither gives: hayro lists the numbers of the streams and dictionaries
//! only, exav-unpack the numbers of the streams only, so the objects that are
//! neither are not compared; the page count and the fonts' text are hayro's
//! alone.
//!
//! Included by `suites/pdf_readers_diff.rs` and by the `pdf_readers` fuzz
//! target, so it uses the public API of both crates only.

use exav_unpack::{Budget, Format, Limits, walk};
use hayro_syntax::object::{MaybeRef, Object, ObjectIdentifier};
use hayro_syntax::xref::XRef;
use hayro_syntax::{Filter, LoadPdfError, Pdf};
use std::collections::{BTreeMap, BTreeSet};

/// Object number and generation.
pub type Id = (u32, u32);

/// Keys whose strings exav-unpack gathers as scripts, and as targets. Those are
/// exav-unpack's lists (`formats/pdf.rs`): a key added there shows up here as a
/// difference.
const SCRIPT_KEYS: &[&str] = &["JS", "JavaScript"];
const TARGET_KEYS: &[&str] = &["URI", "URL", "Launch", "F", "Win", "SubmitForm"];

/// Nesting followed in an object, as exav-unpack's walk follows it.
const DEPTH: u32 = 32;

/// A stream as exav-unpack hands it on.
#[derive(Debug, Clone)]
pub struct ExavStream {
    pub data: Vec<u8>,
    /// Flagged as not (fully) decoded.
    pub flagged: bool,
}

/// What exav-unpack's reader found.
#[derive(Debug, Default)]
pub struct Exav {
    /// The extraction ended without a limit (or with a value passed over for
    /// its depth). Without it nothing else is read.
    pub complete: bool,
    /// Every stream it emitted: an object defined twice is emitted twice.
    pub streams: BTreeMap<Id, Vec<ExavStream>>,
    /// Refused as encrypted (no password, or the empty one is wrong).
    pub refused: bool,
    pub scripts: BTreeSet<Vec<u8>>,
    pub targets: BTreeSet<Vec<u8>>,
}

/// How hayro opened the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opened {
    Yes,
    /// Not a PDF it can read, or one without pages.
    Invalid,
    /// Encrypted, and the empty password does not open it.
    Password,
    /// Not tried: exav-unpack ended on a limit, and the scanner gives hayro
    /// only a file that its own reader took whole.
    Skipped,
}

/// A stream as hayro reads it.
#[derive(Debug, Clone)]
pub struct HayroStream {
    /// `None` when hayro failed to decode it, or it holds an image codec.
    pub data: Option<Vec<u8>>,
    pub image: bool,
}

/// What hayro found.
#[derive(Debug)]
pub struct Hayro {
    pub opened: Opened,
    pub pages: usize,
    pub streams: BTreeMap<Id, HayroStream>,
    pub scripts: BTreeSet<Vec<u8>>,
    pub targets: BTreeSet<Vec<u8>>,
}

/// What kind of difference. The first group leaves something unscanned, or
/// shows the scan something the text does not have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// hayro opens the file and lists streams, exav-unpack emits none.
    OnlyHayroOpens,
    /// A stream hayro lists and exav-unpack does not emit.
    StreamOnlyHayro,
    /// A script string hayro reads and exav-unpack's member does not have.
    ScriptOnlyHayro,
    /// A link or launch string hayro reads and `pdf-uris` does not have.
    TargetOnlyHayro,
    /// Both decode a stream, to other bytes.
    DecodedDiffers,
    /// hayro decodes a stream that exav-unpack flags as not decoded.
    OnlyHayroDecodes,
    /// hayro cannot decode a stream that exav-unpack decodes.
    OnlyExavDecodes,
    /// exav-unpack opens streams in a file hayro does not open.
    OnlyExavOpens,
    /// A stream exav-unpack emits and hayro does not list: a superseded
    /// revision, an object nothing refers to, or another repair.
    StreamOnlyExav,
    ScriptOnlyExav,
    TargetOnlyExav,
    /// exav-unpack refuses the file as encrypted, hayro opens it.
    RefusedOnlyExav,
    /// hayro asks for a password, exav-unpack does not refuse the file.
    RefusedOnlyHayro,
}

impl Kind {
    /// The differences after which the scan misses what hayro sees.
    pub fn is_miss(self) -> bool {
        matches!(
            self,
            Kind::OnlyHayroOpens
                | Kind::StreamOnlyHayro
                | Kind::ScriptOnlyHayro
                | Kind::TargetOnlyHayro
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Difference {
    pub kind: Kind,
    pub detail: String,
}

/// Both readings of one file, and the differences.
#[derive(Debug)]
pub struct Comparison {
    pub exav: Exav,
    pub hayro: Hayro,
    pub differences: Vec<Difference>,
}

impl Comparison {
    /// The kinds that occur, once each.
    pub fn kinds(&self) -> BTreeSet<Kind> {
        self.differences.iter().map(|d| d.kind).collect()
    }

    /// Streams both found and decoded to compare their bytes.
    pub fn compared(&self) -> usize {
        self.hayro
            .streams
            .iter()
            .filter(|(id, s)| s.data.is_some() && self.exav.streams.contains_key(id))
            .count()
    }
}

fn lines(bytes: &[u8], into: &mut BTreeSet<Vec<u8>>) {
    for line in bytes.split(|&b| b == b'\n') {
        if !line.is_empty() {
            into.insert(line.to_vec());
        }
    }
}

pub fn read_exav(data: &[u8], limits: &Limits) -> Exav {
    let mut exav = Exav::default();
    let mut budget = Budget::new(limits.clone());
    let mut entries = Vec::new();
    let mut unread = false;
    let end = walk::<()>(
        Format::Pdf,
        &data,
        &mut budget,
        &mut |meta, content, budget| {
            let data = match content.map(|c| c.into_bytes(meta, budget)) {
                Some(Ok((data, _))) => data,
                Some(Err(_)) => {
                    unread = true;
                    Vec::new()
                }
                None => Vec::new(),
            };
            entries.push((meta.name.clone(), meta.unsupported.is_some(), data));
            None
        },
    );
    // The end a PDF gets for a value it passed over for its depth is not a
    // limit: the members it handed over are compared.
    if unread || end.is_err_and(|hit| !hit.is_corrupt()) {
        return exav;
    }
    exav.complete = true;
    for (name, flagged, data) in entries {
        match name.as_str() {
            "pdf-encrypted" => exav.refused = true,
            "pdf-javascript" => lines(&data, &mut exav.scripts),
            "pdf-uris" => lines(&data, &mut exav.targets),
            name => {
                let id = name.strip_prefix("pdf-obj-").and_then(|rest| {
                    let (number, generation) = rest.split_once('-')?;
                    Some((number.parse().ok()?, generation.parse().ok()?))
                });
                if let Some(id) = id {
                    exav.streams
                        .entry(id)
                        .or_default()
                        .push(ExavStream { flagged, data });
                }
            }
        }
    }
    exav
}

fn id_of(id: ObjectIdentifier) -> Id {
    (id.obj_number, u32::try_from(id.gen_number).unwrap_or(0))
}

/// The strings under the script and target keys of `object` and of what it
/// holds, as exav-unpack's harvest walks them. A key's value is followed when
/// it is a reference, as exav-unpack does for a string.
fn harvest(
    object: &Object<'_>,
    xref: &XRef,
    depth: u32,
    scripts: &mut BTreeSet<Vec<u8>>,
    targets: &mut BTreeSet<Vec<u8>>,
) {
    if depth > DEPTH {
        return;
    }
    let dict = match object {
        Object::Dict(d) => d,
        Object::Stream(s) => s.dict(),
        Object::Array(a) => {
            for item in a.raw_iter() {
                if let MaybeRef::NotRef(item) = item {
                    harvest(&item, xref, depth + 1, scripts, targets);
                }
            }
            return;
        }
        _ => return,
    };
    for (key, value) in dict.entries() {
        let key = String::from_utf8_lossy(&key).into_owned();
        let into = if SCRIPT_KEYS.contains(&key.as_str()) {
            Some(&mut *scripts)
        } else if TARGET_KEYS.contains(&key.as_str()) {
            Some(&mut *targets)
        } else {
            None
        };
        if let Some(into) = into {
            let found = match &value {
                MaybeRef::NotRef(o) => o.clone().into_string(),
                MaybeRef::Ref(r) => xref
                    .get::<Object<'_>>(ObjectIdentifier::new(r.obj_number, r.gen_number))
                    .and_then(Object::into_string),
            };
            if let Some(string) = found {
                lines(string.as_bytes(), into);
            }
        }
        if let MaybeRef::NotRef(value) = &value {
            harvest(value, xref, depth + 1, scripts, targets);
        }
    }
}

pub fn read_hayro(data: &[u8]) -> Hayro {
    let mut hayro = Hayro {
        opened: Opened::Yes,
        pages: 0,
        streams: BTreeMap::new(),
        scripts: BTreeSet::new(),
        targets: BTreeSet::new(),
    };
    let pdf = match Pdf::new(data.to_vec()) {
        Ok(pdf) => pdf,
        Err(e) => {
            hayro.opened = match e {
                LoadPdfError::Decryption(_) => Opened::Password,
                LoadPdfError::Invalid => Opened::Invalid,
            };
            return hayro;
        }
    };
    hayro.pages = pdf.pages().len();
    for object in pdf.objects() {
        harvest(
            &object,
            pdf.xref(),
            0,
            &mut hayro.scripts,
            &mut hayro.targets,
        );
        let Object::Stream(stream) = &object else {
            continue;
        };
        let id = id_of(stream.obj_id());
        if id.0 == 0 {
            continue;
        }
        // The image codecs size their buffers by what the image declares.
        let image = stream.filters().iter().any(|f| {
            matches!(
                f,
                Filter::CcittFaxDecode
                    | Filter::Jbig2Decode
                    | Filter::DctDecode
                    | Filter::JpxDecode
            )
        });
        let data = if image {
            None
        } else {
            stream.decoded().ok().map(|d| d.into_owned())
        };
        hayro.streams.insert(id, HayroStream { data, image });
    }
    hayro
}

fn difference(kind: Kind, detail: impl Into<String>) -> Difference {
    Difference {
        kind,
        detail: detail.into(),
    }
}

fn show(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(&bytes[..bytes.len().min(60)]).into_owned();
    format!("{text:?}")
}

/// Both readings of `data`, compared. `limits` bound exav-unpack's reader, and
/// so what hayro is given: a file that ends it on a limit is not given to hayro.
pub fn compare(data: &[u8], limits: &Limits) -> Comparison {
    let exav = read_exav(data, limits);
    let hayro = if exav.complete {
        read_hayro(data)
    } else {
        Hayro {
            opened: Opened::Skipped,
            pages: 0,
            streams: BTreeMap::new(),
            scripts: BTreeSet::new(),
            targets: BTreeSet::new(),
        }
    };
    let mut diffs = Vec::new();
    if exav.complete && hayro.opened != Opened::Skipped {
        match hayro.opened {
            Opened::Password if !exav.refused => {
                diffs.push(difference(
                    Kind::RefusedOnlyHayro,
                    "hayro asks for a password",
                ));
            }
            Opened::Yes if exav.refused => {
                diffs.push(difference(
                    Kind::RefusedOnlyExav,
                    "opens with the empty password",
                ));
            }
            _ => {}
        }
        if hayro.opened == Opened::Yes {
            if exav.streams.is_empty() && !hayro.streams.is_empty() {
                diffs.push(difference(
                    Kind::OnlyHayroOpens,
                    format!("{} streams", hayro.streams.len()),
                ));
            }
        } else if !exav.streams.is_empty() && hayro.opened == Opened::Invalid {
            diffs.push(difference(
                Kind::OnlyExavOpens,
                format!("{} streams", exav.streams.len()),
            ));
        }
        // The rest is compared only when hayro read the file, and exav-unpack
        // read it as one it can decrypt.
        if hayro.opened == Opened::Yes && !exav.refused {
            compare_streams(&exav, &hayro, &mut diffs);
            for (set, other, only_hayro, only_exav) in [
                (
                    &hayro.scripts,
                    &exav.scripts,
                    Kind::ScriptOnlyHayro,
                    Kind::ScriptOnlyExav,
                ),
                (
                    &hayro.targets,
                    &exav.targets,
                    Kind::TargetOnlyHayro,
                    Kind::TargetOnlyExav,
                ),
            ] {
                for s in set.difference(other) {
                    diffs.push(difference(only_hayro, show(s)));
                }
                for s in other.difference(set) {
                    diffs.push(difference(only_exav, show(s)));
                }
            }
        }
    }
    Comparison {
        exav,
        hayro,
        differences: diffs,
    }
}

fn compare_streams(exav: &Exav, hayro: &Hayro, diffs: &mut Vec<Difference>) {
    for (id, h) in &hayro.streams {
        let Some(emitted) = exav.streams.get(id) else {
            diffs.push(difference(
                Kind::StreamOnlyHayro,
                format!("{} {}", id.0, id.1),
            ));
            continue;
        };
        // An object defined twice is emitted twice, hayro lists the one its
        // cross-reference data names: it must match one of them.
        let Some(data) = &h.data else {
            continue;
        };
        if emitted.iter().any(|e| !e.flagged && &e.data == data) {
            continue;
        }
        let detail = format!("{} {}: hayro {} bytes", id.0, id.1, data.len());
        if emitted.iter().all(|e| e.flagged) {
            diffs.push(difference(Kind::OnlyHayroDecodes, detail));
        } else {
            diffs.push(difference(Kind::DecodedDiffers, detail));
        }
    }
    for (id, emitted) in &exav.streams {
        match hayro.streams.get(id) {
            None => diffs.push(difference(
                Kind::StreamOnlyExav,
                format!("{} {}", id.0, id.1),
            )),
            Some(h) if !h.image && h.data.is_none() && emitted.iter().any(|e| !e.flagged) => {
                diffs.push(difference(
                    Kind::OnlyExavDecodes,
                    format!("{} {}: hayro fails", id.0, id.1),
                ));
            }
            Some(_) => {}
        }
    }
}
