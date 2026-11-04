//! The sets of volumes among files that arrive together: which of them make a
//! set, how a set is read as the one file it was cut from, and why one cannot
//! be. The files are given by the caller as closures; nothing here opens a
//! path.

use std::collections::BTreeMap;
use std::io;

use super::{Collector, Offer, Scheme, ambiguous, group, parse};
use crate::source::ByteSource;

/// Gives a file, or its first bytes when the size is given, held in memory.
pub type Fetch<'a> = dyn FnMut(&str, Option<usize>) -> io::Result<Vec<u8>> + 'a;

/// Opens a file, given the number of parts of its set.
pub type Open<'a> = dyn FnMut(&str, usize) -> io::Result<Box<dyn ByteSource>> + 'a;

/// How the parts of a set are read.
pub enum Parts<'a> {
    /// A whole file or its first bytes, held in memory.
    Memory(&'a mut Fetch<'a>),
    /// A file read where it lies.
    Files(&'a mut Open<'a>),
}

impl Parts<'_> {
    /// The first `n` bytes of a file.
    #[cfg_attr(not(feature = "cab"), allow(dead_code))]
    fn head(&mut self, name: &str, n: usize) -> io::Result<Vec<u8>> {
        match self {
            Parts::Memory(fetch) => fetch(name, Some(n)),
            Parts::Files(open) => Ok(open(name, 1)?.window(0, n).into_owned()),
        }
    }

    /// A file, one of `of` parts of its set.
    fn open(&mut self, name: &str, of: usize) -> io::Result<Box<dyn ByteSource>> {
        match self {
            Parts::Memory(fetch) => Ok(Box::new(fetch(name, None)?)),
            Parts::Files(open) => open(name, of),
        }
    }

    /// Whether what `open` gives is held in memory.
    fn in_memory(&self) -> bool {
        matches!(self, Parts::Memory(_))
    }
}

/// How the volumes of a set carry the archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetKind {
    /// `x.part1.rar`, ... or `x.rar`, `x.r00`, ...
    Rar,
    /// `x.z01`, ..., `x.zip`.
    Zip,
    /// Cabinets whose headers name one another.
    Cab,
}

/// A set found among a list of names.
#[derive(Debug, Clone)]
pub struct SetPlan {
    /// The archive the parts make, named for the set.
    pub name: String,
    pub kind: SetKind,
    /// The names of the parts, in volume order.
    pub parts: Vec<String>,
    /// Why the set cannot be joined, when the names say so.
    pub broken: Option<&'static str>,
}

/// The sets of format-aware volumes among `names`: RAR, ZIP, and CAB (whose
/// headers, the first 64 KiB of each `.cab` read through `files`, name the
/// cabinet that follows). A name is a label, never a path.
#[cfg_attr(not(feature = "cab"), allow(unused_variables))]
pub fn plan(names: &[String], files: &mut Parts<'_>) -> Vec<SetPlan> {
    let mut sets: Vec<SetPlan> = Vec::new();
    let lower = |s: &str| s.to_ascii_lowercase();

    // RAR: the naming schemes say the order, and a gap says a part is missing.
    let rar: Vec<&str> = names
        .iter()
        .map(String::as_str)
        .filter(|n| {
            matches!(
                parse(n).map(|v| v.scheme),
                Some(Scheme::RarPart { .. } | Scheme::RarOld)
            )
        })
        .collect();
    for set in group(&rar) {
        let parts: Vec<&str> = set.iter().map(|&i| rar[i]).collect();
        let first = parse(parts[0]).expect("grouped by name");
        let contiguous = parts
            .iter()
            .enumerate()
            .all(|(i, p)| parse(p).is_some_and(|v| v.index == i));
        sets.push(SetPlan {
            name: format!("{}.rar", first.stem),
            kind: SetKind::Rar,
            parts: parts.iter().map(|p| (*p).to_string()).collect(),
            broken: (!contiguous).then_some("part of a multi-volume RAR set with a volume missing"),
        });
    }
    // Two names for one volume (`x.part1.rar`, `x.part01.rar`): not joined, and
    // every name of the set reported with the reason.
    for (set, why) in ambiguous(&rar) {
        let first = parse(rar[set[0]]).expect("grouped by name");
        sets.push(SetPlan {
            name: format!("{}.rar", first.stem),
            kind: SetKind::Rar,
            parts: set.iter().map(|&i| rar[i].to_string()).collect(),
            broken: Some(why),
        });
    }

    // ZIP: `x.z01` ... and the `x.zip` that comes last and holds the directory.
    let mut stems: Vec<String> = Vec::new();
    for n in names {
        if let Some(v) = parse(n).filter(|v| v.scheme == Scheme::ZipSplit)
            && !stems.iter().any(|s| s.eq_ignore_ascii_case(&v.stem))
        {
            stems.push(v.stem);
        }
    }
    for stem in stems {
        let mut numbered: Vec<(usize, &String)> = names
            .iter()
            .filter_map(|n| {
                parse(n)
                    .filter(|v| v.scheme == Scheme::ZipSplit && v.stem.eq_ignore_ascii_case(&stem))
                    .map(|v| (v.index, n))
            })
            .collect();
        numbered.sort();
        let last = names
            .iter()
            .find(|n| lower(n) == lower(&format!("{stem}.zip")));
        let contiguous = numbered.iter().enumerate().all(|(i, (idx, _))| *idx == i);
        let mut parts: Vec<String> = numbered.iter().map(|(_, n)| (*n).clone()).collect();
        let broken = match last {
            Some(l) => {
                parts.push(l.clone());
                (!contiguous).then_some("part of a multi-volume ZIP set with a volume missing")
            }
            None => Some(
                "part of a multi-volume ZIP set whose last volume, the `.zip`, was not present",
            ),
        };
        sets.push(SetPlan {
            name: format!("{stem}.zip"),
            kind: SetKind::Zip,
            parts,
            broken,
        });
    }

    // CAB: no naming scheme; each header names its neighbours.
    #[cfg(feature = "cab")]
    {
        let mut cabs: Vec<(String, crate::CabLinks)> = Vec::new();
        for n in names.iter().filter(|n| lower(n).ends_with(".cab")) {
            // The header, its reserved area and the two names fit in 64 KiB.
            if let Some(l) = files
                .head(n, 64 * 1024)
                .ok()
                .and_then(|h| crate::cab_links(&h))
            {
                cabs.push((n.clone(), l));
            }
        }
        let mut ids: Vec<u16> = cabs.iter().map(|(_, l)| l.set_id).collect();
        ids.sort_unstable();
        ids.dedup();
        for id in ids {
            let mut members: Vec<&(String, crate::CabLinks)> =
                cabs.iter().filter(|(_, l)| l.set_id == id).collect();
            members.sort_by_key(|(_, l)| l.index);
            // The header's name is a label: its last component, whatever separator.
            let leaf = |s: &str| lower(s.rsplit(['/', '\\']).next().unwrap_or(s));
            let chained = members.iter().enumerate().all(|(i, (name, l))| {
                usize::from(l.index) == i
                    && (i == 0) == l.prev.is_none()
                    && (i + 1 == members.len()) == l.next.is_none()
                    && l.next
                        .as_deref()
                        .is_none_or(|n| members.get(i + 1).is_some_and(|m| leaf(n) == lower(&m.0)))
                    && l.prev
                        .as_deref()
                        .is_none_or(|p| i > 0 && leaf(p) == lower(&members[i - 1].0))
                    && !name.is_empty()
            });
            sets.push(SetPlan {
                name: members[0].0.clone(),
                kind: SetKind::Cab,
                parts: members.iter().map(|(n, _)| n.clone()).collect(),
                broken: (!chained).then_some("part of a multi-volume CAB set whose cabinets do not follow one another as their headers say"),
            });
        }
    }
    sets
}

/// Read the parts of `set` as the one archive they were cut from.
///
/// What is held in memory is held up to `hold` bytes: every part fetched
/// whole, and the cabinets, which are joined in memory whatever they are read
/// through. The parts are counted in `held_total` as they are opened and taken
/// off it again when this returns, so each set of a caller starts from the
/// same count. `Err` is the reason the set was not read, as a caller reports
/// it.
pub fn join(
    set: &SetPlan,
    files: &mut Parts<'_>,
    hold: usize,
    held_total: &mut usize,
) -> Result<Box<dyn ByteSource>, String> {
    if let Some(reason) = set.broken {
        return Err(reason.to_string());
    }
    let held_in_memory = files.in_memory() || set.kind == SetKind::Cab;
    let mut sources: Vec<Box<dyn ByteSource>> = Vec::new();
    let mut held = 0usize;
    let mut lost = None;
    for part in &set.parts {
        match files.open(part, set.parts.len()) {
            Ok(src) => {
                if held_in_memory {
                    if held_total.saturating_add(src.len()) > hold {
                        lost = Some(
                            "part of a multi-volume set too large to hold for rejoining (--max-object-bytes)",
                        );
                        break;
                    }
                    *held_total += src.len();
                    held += src.len();
                }
                sources.push(src);
            }
            Err(_) => {
                lost = Some("part of a multi-volume set one of whose volumes could not be read");
                break;
            }
        }
    }
    *held_total = held_total.saturating_sub(held);
    if let Some(reason) = lost {
        return Err(reason.to_string());
    }
    let joined: Result<Box<dyn ByteSource>, String> = match set.kind {
        #[cfg(feature = "rar")]
        SetKind::Rar => {
            crate::span::RarSpan::new(sources, hold).map(|s| Box::new(s) as Box<dyn ByteSource>)
        }
        #[cfg(not(feature = "rar"))]
        SetKind::Rar => Err("this build reads no RAR".to_string()),
        SetKind::Zip => {
            crate::span::ZipSpan::new(sources).map(|s| Box::new(s) as Box<dyn ByteSource>)
        }
        #[cfg(feature = "cab")]
        SetKind::Cab => {
            let whole: Vec<_> = sources.iter().map(|s| s.window(0, s.len())).collect();
            let refs: Vec<&[u8]> = whole.iter().map(|w| &**w).collect();
            crate::join_cab_volumes(&refs).map(|j| Box::new(j) as Box<dyn ByteSource>)
        }
        #[cfg(not(feature = "cab"))]
        SetKind::Cab => Err("this build reads no CAB".to_string()),
    };
    joined.map_err(|e| format!("part of a multi-volume set that could not be rejoined: {e}"))
}

/// The set a byte-split part belongs to, as a set is named: `big.7z` for
/// `big.7z.001`. A name that does not parse as a volume is its own set.
pub fn set_name(part: &str) -> String {
    parse(part)
        .map(|v| match v.scheme {
            Scheme::NumberedSuffix { ref base_ext, .. } => {
                format!("{}.{}", v.stem, base_ext)
            }
            _ => v.stem.clone(),
        })
        .unwrap_or_else(|| part.to_string())
}

/// What a byte-split set, or a part of one, came to.
#[derive(Debug, Clone)]
pub enum State {
    /// The parts joined, in volume order.
    Joined(Vec<u8>),
    /// The set cannot be read: the reason, which the parts are not clean for.
    Unjoinable(&'static str),
}

/// One set of [`rejoin_byte_split`], or one part that is not in a set that
/// joined.
#[derive(Debug, Clone)]
pub struct Resolved {
    /// The name of the archive the parts belong to.
    pub set: String,
    /// The names it covers, in volume order.
    pub parts: Vec<String>,
    pub state: State,
}

/// Rejoin the byte-split sets (`x.7z.001`, `.002`, ...) among `names`. `fetch`
/// is called only for the names that parse as a part, and what is held is held
/// up to `max_held` bytes.
///
/// Byte-split naming records no part count, so a set missing its last part
/// still looks contiguous and would join into a truncated prefix: a part that
/// cannot be read, or is not held, makes its whole set [`State::Unjoinable`].
/// Joined sets come first, then the parts of sets that never completed, then
/// the parts that were read and not held.
pub fn rejoin_byte_split<F>(names: &[String], max_held: u64, mut fetch: F) -> Vec<Resolved>
where
    F: FnMut(&str) -> io::Result<Vec<u8>>,
{
    let mut collector = Collector::new(max_held);
    let mut any = false;
    // Sets that lost a part on the way in, and why. `Collector::finish` cannot
    // see these: it judges completeness from the indices it was given, and a
    // missing trailing index leaves no trace in them.
    let mut broken: BTreeMap<String, &'static str> = BTreeMap::new();
    // The parts the collector read and would not hold. It keeps no trace of
    // them, so a set none of whose parts it holds comes back with no entry.
    let mut passed: Vec<String> = Vec::new();
    // Parts group without regard to case, so a set is known by its lower-case
    // name here, whichever part's case it was joined under.
    fn set_key(name: &str) -> String {
        name.to_ascii_lowercase()
    }
    for name in names {
        if !parse(name).is_some_and(|v| v.scheme.is_byte_split()) {
            continue;
        }
        let Ok(data) = fetch(name) else {
            broken.insert(
                set_key(&set_name(name)),
                "part of a multi-volume set one of whose volumes could not be read",
            );
            continue;
        };
        any = true;
        // `PassThrough` means the collector declined to hold it: the held-bytes
        // cap, or a second part claiming an index another part already holds.
        if let Offer::PassThrough { name, .. } = collector.offer(name, data) {
            broken.insert(
                set_key(&set_name(&name)),
                "part of a multi-volume set that could not be reassembled whole",
            );
            passed.push(name);
        }
    }
    if !any {
        return Vec::new();
    }
    let held = collector.finish();
    let mut out = Vec::new();
    for j in held.joined {
        // A set with a hole gets the hole's verdict, not a verdict read off the
        // bytes that happened to arrive.
        let state = match broken.get(set_key(&j.name).as_str()) {
            Some(reason) => State::Unjoinable(reason),
            None => State::Joined(j.data),
        };
        out.push(Resolved {
            set: j.name,
            parts: j.parts,
            state,
        });
    }
    for u in held.unjoined {
        // A lone numbered file is not a set: plenty of ordinary files end in
        // `.001`. Unless a part of it was lost: one readable part of a set
        // whose other part could not be read is not a lone file.
        let set = set_name(&u.name);
        let Some(reason) = u
            .incomplete_set
            .or_else(|| broken.get(set_key(&set).as_str()).copied())
        else {
            continue;
        };
        out.push(Resolved {
            set,
            parts: vec![u.name],
            state: State::Unjoinable(reason),
        });
    }
    // A part that was read and not held belongs to a set that cannot be
    // rejoined: it is not a clean file because its own bytes scan clean.
    for name in passed {
        if out.iter().any(|r| r.parts.contains(&name)) {
            continue;
        }
        out.push(Resolved {
            set: set_name(&name),
            parts: vec![name],
            state: State::Unjoinable(
                "part of a multi-volume set that could not be reassembled whole",
            ),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// Files that are only their names, so no head is read.
    fn no_files() -> impl FnMut(&str, Option<usize>) -> io::Result<Vec<u8>> {
        |name, _| panic!("{name} was read")
    }

    fn planned(given: &[&str]) -> Vec<(String, SetKind, Vec<String>, Option<&'static str>)> {
        let mut fetch = no_files();
        plan(&names(given), &mut Parts::Memory(&mut fetch))
            .into_iter()
            .map(|s| (s.name, s.kind, s.parts, s.broken))
            .collect()
    }

    #[test]
    fn rar_volumes_are_a_set_in_volume_order_and_a_gap_breaks_it() {
        let got = planned(&["b.part2.rar", "x.txt", "b.part1.rar", "b.part3.rar"]);
        assert_eq!(
            got,
            vec![(
                "b.rar".to_string(),
                SetKind::Rar,
                names(&["b.part1.rar", "b.part2.rar", "b.part3.rar"]),
                None
            )]
        );
        // The old scheme: `x.rar` first, then `x.r00`.
        let got = planned(&["c.r00", "c.rar", "c.r01"]);
        assert_eq!(got[0].2, names(&["c.rar", "c.r00", "c.r01"]));
        assert_eq!(got[0].3, None);
        // A volume missing in the middle.
        let got = planned(&["d.part1.rar", "d.part3.rar"]);
        assert_eq!(got.len(), 1);
        assert_eq!(
            got[0].3,
            Some("part of a multi-volume RAR set with a volume missing")
        );
        // One volume alone is a file, not a set.
        assert!(planned(&["e.part1.rar", "f.part2.rar"]).is_empty());
    }

    #[test]
    fn two_names_for_one_rar_volume_make_a_set_that_is_not_joined() {
        let got = planned(&["g.part1.rar", "g.part01.rar", "g.part2.rar"]);
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].0, "g.rar");
        assert_eq!(got[0].1, SetKind::Rar);
        assert_eq!(got[0].2.len(), 3);
        assert_eq!(got[0].3, Some(super::super::TWO_NAMES_AT_ONE_INDEX));
    }

    #[test]
    fn zip_volumes_end_with_the_zip_and_a_missing_end_or_gap_breaks_the_set() {
        let got = planned(&["h.zip", "h.z02", "h.z01", "other.txt"]);
        assert_eq!(
            got,
            vec![(
                "h.zip".to_string(),
                SetKind::Zip,
                names(&["h.z01", "h.z02", "h.zip"]),
                None
            )]
        );
        // The case of the extension does not matter.
        let got = planned(&["i.Z01", "i.ZIP"]);
        assert_eq!(got[0].2, names(&["i.Z01", "i.ZIP"]));
        assert_eq!(got[0].3, None);
        // No `.zip`: the directory is missing.
        let got = planned(&["j.z01", "j.z02"]);
        assert_eq!(
            got[0].3,
            Some("part of a multi-volume ZIP set whose last volume, the `.zip`, was not present")
        );
        // `.z02` with no `.z01`.
        let got = planned(&["k.z02", "k.zip"]);
        assert_eq!(
            got[0].3,
            Some("part of a multi-volume ZIP set with a volume missing")
        );
        // Two sets, each its own.
        let got = planned(&["l.z01", "l.zip", "m.z01", "m.zip"]);
        assert_eq!(got.len(), 2);
    }

    #[test]
    fn names_that_are_no_volume_make_no_set() {
        assert!(planned(&["a.txt", "b.7z.001", "b.7z.002", "c.zip", "d.rar"]).is_empty());
    }

    /// A cabinet that is only its header: its place in a set.
    #[cfg(feature = "cab")]
    fn cabinet(set_id: u16, index: u16, prev: Option<&str>, next: Option<&str>) -> Vec<u8> {
        let flags = u16::from(prev.is_some()) | (u16::from(next.is_some()) << 1);
        let mut out = b"MSCF".to_vec();
        out.extend_from_slice(&[0; 12]);
        out.extend_from_slice(&36u32.to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&[3, 1]);
        for v in [0, 0, flags, set_id, index] {
            out.extend_from_slice(&u16::to_le_bytes(v));
        }
        for name in [prev, next].into_iter().flatten() {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b"\0disk\0");
        }
        out
    }

    #[cfg(feature = "cab")]
    fn planned_cabinets(
        files: &[(&str, Vec<u8>)],
    ) -> Vec<(String, Vec<String>, Option<&'static str>)> {
        let mut heads = Vec::new();
        let mut fetch = |name: &str, head: Option<usize>| -> io::Result<Vec<u8>> {
            heads.push((name.to_string(), head));
            files
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, d)| d.clone())
                .ok_or_else(|| io::Error::other("no such file"))
        };
        let given: Vec<String> = files.iter().map(|(n, _)| n.to_string()).collect();
        let got: Vec<_> = plan(&given, &mut Parts::Memory(&mut fetch))
            .into_iter()
            .map(|s| {
                assert_eq!(s.kind, SetKind::Cab);
                (s.name, s.parts, s.broken)
            })
            .collect();
        // Only a `.cab` is asked for its head, and for its first 64 KiB.
        let asked: Vec<_> = files
            .iter()
            .filter(|(n, _)| n.to_ascii_lowercase().ends_with(".cab"))
            .map(|(n, _)| (n.to_string(), Some(64 * 1024)))
            .collect();
        assert_eq!(heads, asked);
        got
    }

    /// Three cabinets of one set, by what their headers say.
    #[cfg(feature = "cab")]
    fn chain() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        (
            cabinet(5, 0, None, Some("two.cab")),
            cabinet(5, 1, Some("one.cab"), Some("three.cab")),
            cabinet(5, 2, Some("two.cab"), None),
        )
    }

    #[cfg(feature = "cab")]
    const NOT_CHAINED: &str = "part of a multi-volume CAB set whose cabinets do not follow one another as their headers say";

    #[cfg(feature = "cab")]
    #[test]
    fn cabinets_are_chained_in_index_order_by_the_names_their_headers_give() {
        let (one, two, three) = chain();
        // In any order, by index; the headers' names are labels (a path's last
        // component, either separator, any case).
        let got = planned_cabinets(&[
            ("three.cab", three.clone()),
            ("notes.txt", b"x".to_vec()),
            ("one.cab", one.clone()),
            ("TWO.CAB", two.clone()),
        ]);
        assert_eq!(
            got,
            vec![(
                "one.cab".to_string(),
                names(&["one.cab", "TWO.CAB", "three.cab"]),
                None
            )]
        );
        let two_dir = cabinet(5, 1, Some("d:\\x\\One.cab"), Some("/y/three.cab"));
        let got = planned_cabinets(&[("one.cab", one), ("two.cab", two_dir), ("three.cab", three)]);
        assert_eq!(got[0].2, None);
    }

    #[cfg(feature = "cab")]
    #[test]
    fn a_cabinet_that_names_another_than_its_neighbour_breaks_the_set() {
        let (one, ..) = chain();
        // Its header names another cabinet than the one given next.
        let zwei = cabinet(5, 1, Some("one.cab"), None);
        let got = planned_cabinets(&[("one.cab", one.clone()), ("zwei.cab", zwei)]);
        assert_eq!(got[0].2, Some(NOT_CHAINED));
        // Another than the one before it.
        let other_prev = cabinet(5, 1, Some("uno.cab"), None);
        let got = planned_cabinets(&[("one.cab", one), ("two.cab", other_prev)]);
        assert_eq!(got[0].2, Some(NOT_CHAINED));
    }

    #[cfg(feature = "cab")]
    #[test]
    fn a_cabinet_that_is_not_where_its_header_says_breaks_the_set() {
        let (one, two, three) = chain();
        // The third of a set of which the second is not there.
        let skipping = cabinet(5, 2, Some("one.cab"), None);
        let got = planned_cabinets(&[("one.cab", one.clone()), ("two.cab", skipping)]);
        assert_eq!(got[0].2, Some(NOT_CHAINED));
        // The last one is missing: the second still names a next.
        let got = planned_cabinets(&[("one.cab", one), ("two.cab", two.clone())]);
        assert_eq!(got[0].2, Some(NOT_CHAINED));
        // The first is missing: the second still names a previous.
        let got = planned_cabinets(&[("two.cab", two.clone()), ("three.cab", three.clone())]);
        assert_eq!(got[0].2, Some(NOT_CHAINED));
        // A first cabinet that names one before it.
        let first = cabinet(5, 0, Some("zero.cab"), Some("two.cab"));
        let got = planned_cabinets(&[("one.cab", first), ("two.cab", two), ("three.cab", three)]);
        assert_eq!(got[0].2, Some(NOT_CHAINED));
        // A middle one that names none after it.
        let (one, ..) = chain();
        let (middle, last) = (
            cabinet(5, 1, Some("one.cab"), None),
            cabinet(5, 2, Some("two.cab"), None),
        );
        let got = planned_cabinets(&[("one.cab", one), ("two.cab", middle), ("three.cab", last)]);
        assert_eq!(got[0].2, Some(NOT_CHAINED));
    }

    #[cfg(feature = "cab")]
    #[test]
    fn a_lone_cabinet_is_no_set_and_two_sets_are_told_apart_by_their_ids() {
        let (one, ..) = chain();
        // A cabinet on its own, and one that is not a cabinet, make no set.
        let alone = cabinet(9, 0, None, None);
        assert!(planned_cabinets(&[("a.cab", alone), ("b.cab", b"MSCF".to_vec())]).is_empty());
        let other = cabinet(6, 0, None, Some("y.cab"));
        let other2 = cabinet(6, 1, Some("x.cab"), None);
        let got = planned_cabinets(&[("one.cab", one), ("x.cab", other), ("y.cab", other2)]);
        assert_eq!(got.len(), 2, "{got:?}");
        assert_eq!(got[0].1, names(&["one.cab"]));
        assert_eq!(
            got[1],
            ("x.cab".to_string(), names(&["x.cab", "y.cab"]), None)
        );
    }

    fn memory_of<'a>(
        files: &'a [(&'a str, usize)],
        opened: &'a std::cell::RefCell<Vec<String>>,
    ) -> impl FnMut(&str, Option<usize>) -> io::Result<Vec<u8>> + 'a {
        move |name, head| {
            opened.borrow_mut().push(name.to_string());
            let (_, len) = files
                .iter()
                .find(|(n, _)| *n == name)
                .ok_or_else(|| io::Error::other("no such file"))?;
            Ok(vec![b'a'; head.map_or(*len, |h| h.min(*len))])
        }
    }

    fn set(kind: SetKind, parts: &[&str], broken: Option<&'static str>) -> SetPlan {
        SetPlan {
            name: "s".to_string(),
            kind,
            parts: names(parts),
            broken,
        }
    }

    #[test]
    fn a_broken_set_is_refused_with_its_reason_and_nothing_is_opened() {
        let opened = std::cell::RefCell::new(Vec::new());
        let mut fetch = memory_of(&[], &opened);
        let mut held = 0;
        let s = set(SetKind::Zip, &["a.z01", "a.zip"], Some("names say so"));
        let got = join(&s, &mut Parts::Memory(&mut fetch), 100, &mut held);
        assert_eq!(got.err().as_deref(), Some("names say so"));
        assert!(opened.borrow().is_empty());
    }

    #[test]
    fn parts_held_in_memory_are_counted_against_the_limit_and_given_back_with_the_set() {
        let files = [
            ("a.z01", 4),
            ("a.z02", 4),
            ("a.zip", 4),
            ("b.z01", 4),
            ("b.zip", 4),
        ];
        let opened = std::cell::RefCell::new(Vec::new());
        let mut fetch = memory_of(&files, &opened);
        let mut parts = Parts::Memory(&mut fetch);
        let mut held = 0;
        let big = set(SetKind::Zip, &["a.z01", "a.z02", "a.zip"], None);
        let why = join(&big, &mut parts, 10, &mut held).err().unwrap();
        assert_eq!(
            why,
            "part of a multi-volume set too large to hold for rejoining (--max-object-bytes)"
        );
        // Given back: a set after it that fits is held whole.
        assert_eq!(held, 0);
        let small = set(SetKind::Zip, &["b.z01", "b.zip"], None);
        let why = join(&small, &mut parts, 10, &mut held).err().unwrap();
        assert!(
            why.starts_with("part of a multi-volume set that could not be rejoined: "),
            "{why}"
        );
        assert_eq!(held, 0);
        // Exactly the limit is held; one byte over is not.
        assert!(
            join(&small, &mut parts, 8, &mut held)
                .err()
                .unwrap()
                .contains("could not be rejoined")
        );
        assert!(
            join(&small, &mut parts, 7, &mut held)
                .err()
                .unwrap()
                .contains("too large to hold")
        );
        // What other sets already hold counts too.
        held = 5;
        assert!(
            join(&small, &mut parts, 12, &mut held)
                .err()
                .unwrap()
                .contains("too large to hold")
        );
        assert_eq!(held, 5);
    }

    /// A source that has only a length.
    struct Sized(usize);

    impl ByteSource for Sized {
        fn len(&self) -> usize {
            self.0
        }

        fn window(&self, _: usize, _: usize) -> Cow<'_, [u8]> {
            Cow::Owned(Vec::new())
        }

        fn identity(&self) -> (usize, usize) {
            (0, self.0)
        }
    }

    #[test]
    fn parts_read_where_they_lie_are_not_held_so_not_counted() {
        let ofs = std::cell::RefCell::new(Vec::new());
        let mut open = |name: &str, of: usize| -> io::Result<Box<dyn ByteSource>> {
            ofs.borrow_mut().push((name.to_string(), of));
            Ok(Box::new(Sized(1 << 30)))
        };
        let mut held = 0;
        let s = set(SetKind::Zip, &["a.z01", "a.zip"], None);
        let why = join(&s, &mut Parts::Files(&mut open), 10, &mut held)
            .err()
            .unwrap();
        assert!(why.contains("could not be rejoined"), "{why}");
        assert_eq!(held, 0);
        // Each is opened as one of the parts of its set.
        assert_eq!(
            *ofs.borrow(),
            vec![("a.z01".to_string(), 2), ("a.zip".to_string(), 2)]
        );
    }

    #[test]
    fn a_part_that_cannot_be_opened_loses_the_set_and_the_ones_after_it_are_not_opened() {
        let mut asked = Vec::new();
        let mut open = |name: &str, _: usize| -> io::Result<Box<dyn ByteSource>> {
            asked.push(name.to_string());
            match name {
                "a.z02" => Err(io::Error::other("gone")),
                _ => Ok(Box::new(Sized(4))),
            }
        };
        let mut held = 0;
        let s = set(SetKind::Zip, &["a.z01", "a.z02", "a.zip"], None);
        let why = join(&s, &mut Parts::Files(&mut open), 100, &mut held)
            .err()
            .unwrap();
        assert_eq!(
            why,
            "part of a multi-volume set one of whose volumes could not be read"
        );
        assert_eq!(asked, names(&["a.z01", "a.z02"]));
    }

    #[cfg(feature = "cab")]
    #[test]
    fn cabinets_are_joined_in_memory_whatever_they_are_read_through() {
        let one = cabinet(5, 0, None, Some("two.cab"));
        let two = cabinet(5, 1, Some("one.cab"), None);
        let both = [("one.cab", one.clone()), ("two.cab", two.clone())];
        let mut open = |name: &str, _: usize| -> io::Result<Box<dyn ByteSource>> {
            let d = both.iter().find(|(n, _)| *n == name).unwrap().1.clone();
            Ok(Box::new(d))
        };
        let s = set(SetKind::Cab, &["one.cab", "two.cab"], None);
        // Read where they lie, but held while they are joined: the limit counts.
        let mut held = 0;
        let why = join(&s, &mut Parts::Files(&mut open), 10, &mut held)
            .err()
            .unwrap();
        assert!(why.contains("too large to hold"), "{why}");
        // Within it, the join is the one `join_cab_volumes` makes (these two
        // carry no folder, which it refuses).
        let refused = crate::join_cab_volumes(&[&one, &two]).unwrap_err();
        let why = join(&s, &mut Parts::Files(&mut open), 1000, &mut held)
            .err()
            .unwrap();
        assert_eq!(
            why,
            format!("part of a multi-volume set that could not be rejoined: {refused}")
        );
        assert_eq!(held, 0);
    }

    #[test]
    fn a_set_that_does_not_fit_together_says_what_does_not() {
        // Two ZIP parts that are not a spanned archive.
        let files = [("a.z01", 4), ("a.zip", 4)];
        let opened = std::cell::RefCell::new(Vec::new());
        let mut fetch = memory_of(&files, &opened);
        let mut held = 0;
        let s = set(SetKind::Zip, &["a.z01", "a.zip"], None);
        let why = join(&s, &mut Parts::Memory(&mut fetch), 100, &mut held)
            .err()
            .unwrap();
        assert!(
            why.starts_with("part of a multi-volume set that could not be rejoined: "),
            "{why}"
        );
        assert!(why.len() > "part of a multi-volume set that could not be rejoined: ".len());
    }

    fn rejoined(
        names: &[&str],
        max_held: u64,
        data: &[(&str, &[u8])],
    ) -> (Vec<Resolved>, Vec<String>) {
        let mut fetched = Vec::new();
        let got = rejoin_byte_split(&self::names(names), max_held, |n| {
            fetched.push(n.to_string());
            data.iter()
                .find(|(name, _)| *name == n)
                .map(|(_, d)| d.to_vec())
                .ok_or_else(|| io::Error::other("no such file"))
        });
        (got, fetched)
    }

    fn summary(got: &[Resolved]) -> Vec<(String, Vec<String>, String)> {
        got.iter()
            .map(|r| {
                let what = match &r.state {
                    State::Joined(d) => format!("joined {}", String::from_utf8_lossy(d)),
                    State::Unjoinable(why) => (*why).to_string(),
                };
                (r.set.clone(), r.parts.clone(), what)
            })
            .collect()
    }

    const HOLE: &str = "part of a multi-volume set one of whose volumes could not be read";
    const WHOLE: &str = "part of a multi-volume set that could not be reassembled whole";
    const HELD: &str =
        "part of a multi-volume set one of whose volumes could not be held for rejoining";

    #[test]
    fn a_byte_split_set_is_fetched_by_its_names_only_and_joined_in_volume_order() {
        let (got, fetched) = rejoined(
            &["z.7z.002", "notes.txt", "z.7z.001", "x.part1.rar"],
            100,
            &[("z.7z.001", b"ab"), ("z.7z.002", b"cd")],
        );
        assert_eq!(fetched, names(&["z.7z.002", "z.7z.001"]));
        assert_eq!(
            summary(&got),
            vec![(
                "z.7z".to_string(),
                names(&["z.7z.001", "z.7z.002"]),
                "joined abcd".to_string()
            )]
        );
        // Nothing to fetch, nothing to say.
        assert!(rejoined(&["a.txt", "b.rar"], 100, &[]).0.is_empty());
        // A lone numbered file is not a set.
        assert!(
            rejoined(&["l.log.001"], 100, &[("l.log.001", b"x")])
                .0
                .is_empty()
        );
    }

    #[test]
    fn a_part_that_cannot_be_read_takes_its_whole_set_with_it() {
        // The parts before it joined, and the set is reported all the same:
        // nothing in the names says a last part was there.
        let (got, _) = rejoined(
            &["z.7z.001", "z.7z.002", "z.7z.003"],
            100,
            &[("z.7z.001", b"ab"), ("z.7z.002", b"cd")],
        );
        assert_eq!(
            summary(&got),
            vec![(
                "z.7z".to_string(),
                names(&["z.7z.001", "z.7z.002"]),
                HOLE.to_string()
            )]
        );
        // A gap in the indices says more than the missing part does.
        let (got, _) = rejoined(
            &["w.7z.001", "w.7z.002", "w.7z.003"],
            100,
            &[("w.7z.001", b"ab"), ("w.7z.003", b"ef")],
        );
        let got = summary(&got);
        assert_eq!(got.len(), 2);
        assert!(
            got.iter()
                .all(|g| g.2.contains("incomplete multi-volume set"))
        );
        // The only part that could be read is no lone file: its other part
        // could not be.
        let (got, _) = rejoined(&["y.7z.001", "y.7z.002"], 100, &[("y.7z.001", b"ab")]);
        assert_eq!(
            summary(&got),
            vec![("y.7z".to_string(), names(&["y.7z.001"]), HOLE.to_string())]
        );
        // The set is known by its name whatever the case of its parts.
        let (got, _) = rejoined(
            &["Y.7Z.001", "y.7z.002", "y.7z.003"],
            100,
            &[("Y.7Z.001", b"ab"), ("y.7z.002", b"cd")],
        );
        assert_eq!(
            summary(&got),
            vec![(
                "Y.7z".to_string(),
                names(&["Y.7Z.001", "y.7z.002"]),
                HOLE.to_string()
            )]
        );
    }

    #[test]
    fn a_part_over_what_is_held_makes_the_set_unjoinable_and_is_listed_once() {
        // Three bytes held, the next two parts over the five that may be.
        let (got, _) = rejoined(
            &["p.7z.001", "p.7z.002", "p.7z.003"],
            5,
            &[
                ("p.7z.001", b"abc"),
                ("p.7z.002", b"def"),
                ("p.7z.003", b"ghi"),
            ],
        );
        assert_eq!(
            summary(&got),
            vec![
                ("p.7z".to_string(), names(&["p.7z.001"]), HELD.to_string()),
                ("p.7z".to_string(), names(&["p.7z.002"]), WHOLE.to_string()),
                ("p.7z".to_string(), names(&["p.7z.003"]), WHOLE.to_string()),
            ]
        );
        // One that is held is given back as a part of an unjoinable set; one
        // that was not held is listed by its own name, and not twice.
        assert_eq!(got.iter().map(|r| r.parts.len()).sum::<usize>(), 3);
        // A name given twice: the second is turned away for the index the
        // first holds, and the part is already listed.
        let (got, fetched) = rejoined(&["q.7z.001", "q.7z.001"], 100, &[("q.7z.001", b"ab")]);
        assert_eq!(fetched.len(), 2);
        assert_eq!(
            summary(&got),
            vec![("q.7z".to_string(), names(&["q.7z.001"]), HELD.to_string())]
        );
    }

    #[test]
    fn a_set_with_a_gap_is_reported_part_by_part() {
        let (got, _) = rejoined(
            &["g.7z.001", "g.7z.003"],
            100,
            &[("g.7z.001", b"a"), ("g.7z.003", b"c")],
        );
        let got = summary(&got);
        assert_eq!(got.len(), 2);
        for (set, _, why) in got {
            assert_eq!(set, "g.7z");
            assert!(why.contains("incomplete multi-volume set"), "{why}");
        }
    }

    #[test]
    fn joined_sets_come_before_the_parts_that_did_not_join() {
        let (got, _) = rejoined(
            &["b.7z.001", "a.7z.001", "a.7z.002"],
            100,
            &[("a.7z.001", b"1"), ("a.7z.002", b"2"), ("b.7z.001", b"x")],
        );
        // `b` is one file on its own: not a set, not listed.
        assert_eq!(
            summary(&got),
            vec![(
                "a.7z".to_string(),
                names(&["a.7z.001", "a.7z.002"]),
                "joined 12".to_string()
            )]
        );
        // The set that never completed was named first, and is listed last.
        let (got, _) = rejoined(
            &["d.7z.001", "d.7z.003", "a.7z.001", "a.7z.002"],
            100,
            &[
                ("a.7z.001", b"1"),
                ("a.7z.002", b"2"),
                ("d.7z.001", b"3"),
                ("d.7z.003", b"4"),
            ],
        );
        let sets: Vec<_> = got
            .iter()
            .map(|r| (r.set.as_str(), r.parts.len()))
            .collect();
        assert_eq!(sets, vec![("a.7z", 2), ("d.7z", 1), ("d.7z", 1)]);
        assert!(matches!(got[0].state, State::Joined(_)));
    }

    #[test]
    fn a_part_is_named_for_its_set() {
        assert_eq!(set_name("big.7z.001"), "big.7z");
        assert_eq!(set_name("a.b.zip.010"), "a.b.zip");
        assert_eq!(set_name("x.part2.rar"), "x");
        assert_eq!(set_name("x.z01"), "x");
        assert_eq!(set_name("plain.txt"), "plain.txt");
    }
}
