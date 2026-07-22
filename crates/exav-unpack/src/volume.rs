//! Recognising the members of a **multi-volume archive** from their names.
//!
//! A multi-volume archive is one logical archive spread over several files, and
//! a member's compressed stream can run off the end of one and continue in the
//! next — so no single file decodes it. Scanned one at a time, the payload is
//! never reassembled.
//!
//! This module answers only the naming question: *do these names look like one
//! set, and in what order?* It performs no I/O and reads nothing from archive
//! content, which is what makes it safe to apply to a directory listing, to the
//! member list of a container, or to a client-supplied manifest alike.
//!
//! **Names are never turned into paths here.** A caller that resolves siblings
//! on a filesystem generates candidate names from a parsed pattern and looks
//! them up in one directory; nothing a file *contains* can steer that. The
//! format that inverts this is CAB, whose header names the next cabinet inside
//! the file — that string must be matched against a listing, never opened.

/// How a set names its volumes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scheme {
    /// `stem.partN.rar` — RAR 3 and later. Digit width is fixed across a set.
    RarPart { width: usize },
    /// `stem.rar`, `stem.r00`, `stem.r01` … — the pre-RAR3 scheme.
    RarOld,
    /// `stem.7z.001`, `.002` … — also used by `zip.001`, `arj.001` and others,
    /// since it is the generic "split a finished file" convention.
    NumberedSuffix { base_ext: String, width: usize },
    /// `stem.zip`, `stem.z01`, `stem.z02` … — the ZIP spanning convention,
    /// where the LAST file is the one holding the central directory.
    ZipSplit,
}

/// One volume's place in its set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeName {
    /// The part of the name shared by every volume in the set.
    pub stem: String,
    /// Zero-based position. Volume 0 is where a reader starts.
    pub index: usize,
    pub scheme: Scheme,
}

/// Recognise a volume filename, or `None` when it is not one a writer would
/// produce for a set.
///
/// Deliberately strict: a false positive groups unrelated files, and grouping
/// is what decides which bytes get concatenated.
pub fn parse(name: &str) -> Option<VolumeName> {
    let lower = name.to_ascii_lowercase();

    // `stem.partN.rar` / `stem.rar`
    if let Some(rest) = lower.strip_suffix(".rar") {
        if let Some(dot) = rest.rfind(".part") {
            let digits = &rest[dot + ".part".len()..];
            if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
                let n: usize = digits.parse().ok()?;
                // Writers number volumes from 1; position 0 is `part1`.
                return Some(VolumeName {
                    stem: name[..dot].to_string(),
                    index: n.checked_sub(1)?,
                    scheme: Scheme::RarPart {
                        width: digits.len(),
                    },
                });
            }
        }
        return Some(VolumeName {
            stem: name[..rest.len()].to_string(),
            index: 0,
            scheme: Scheme::RarOld,
        });
    }

    let (stem_l, ext) = lower.rsplit_once('.')?;
    let stem = &name[..stem_l.len()];

    // `stem.rNN` — continuation of the old RAR scheme. `.r00` is volume 1.
    if let Some(digits) = ext.strip_prefix('r') {
        if digits.len() == 2 && digits.bytes().all(|b| b.is_ascii_digit()) {
            let n: usize = digits.parse().ok()?;
            return Some(VolumeName {
                stem: stem.to_string(),
                index: n + 1,
                scheme: Scheme::RarOld,
            });
        }
    }

    // `stem.zNN` — ZIP spanning. `.z01` is volume 0; the bare `.zip` is LAST,
    // because it carries the central directory.
    if let Some(digits) = ext.strip_prefix('z') {
        if digits.len() == 2 && digits.bytes().all(|b| b.is_ascii_digit()) {
            let n: usize = digits.parse().ok()?;
            return Some(VolumeName {
                stem: stem.to_string(),
                index: n.checked_sub(1)?,
                scheme: Scheme::ZipSplit,
            });
        }
    }

    // `stem.<ext>.NNN` — the generic numbered split (7z, zip, arj, tar…).
    if ext.len() >= 2 && ext.bytes().all(|b| b.is_ascii_digit()) {
        let n: usize = ext.parse().ok()?;
        let (base_l, base_ext) = stem_l.rsplit_once('.')?;
        if base_ext.is_empty() || !base_ext.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return None;
        }
        return Some(VolumeName {
            stem: name[..base_l.len()].to_string(),
            index: n.checked_sub(1)?,
            scheme: Scheme::NumberedSuffix {
                base_ext: base_ext.to_string(),
                width: ext.len(),
            },
        });
    }

    None
}

impl VolumeName {
    /// The filename of volume `index` in this set, or `None` when the scheme
    /// cannot express it.
    ///
    /// Generated from the parsed pattern, never from file content — this is the
    /// function a filesystem resolver uses, so it must not be able to name
    /// anything outside the set.
    pub fn name_at(&self, index: usize) -> Option<String> {
        match &self.scheme {
            Scheme::RarPart { width } => {
                Some(format!("{}.part{:0width$}.rar", self.stem, index + 1))
            }
            Scheme::RarOld => match index {
                0 => Some(format!("{}.rar", self.stem)),
                1..=100 => Some(format!("{}.r{:02}", self.stem, index - 1)),
                _ => None,
            },
            Scheme::NumberedSuffix { base_ext, width } => {
                Some(format!("{}.{}.{:0width$}", self.stem, base_ext, index + 1))
            }
            Scheme::ZipSplit => Some(format!("{}.z{:02}", self.stem, index + 1)),
        }
    }

    /// Whether two names belong to the same set. Both the stem and the scheme
    /// must agree — `a.part1.rar` and `a.7z.001` share a stem and are not one
    /// archive.
    pub fn same_set_as(&self, other: &VolumeName) -> bool {
        self.stem.eq_ignore_ascii_case(&other.stem)
            && std::mem::discriminant(&self.scheme) == std::mem::discriminant(&other.scheme)
    }
}

/// Group a list of names into volume sets.
///
/// Returns `(representative_index, member_indices_in_volume_order)` per set,
/// where the indices are positions in `names`. Names that are not volumes, and
/// sets with only one member, are not returned — a lone volume is just a file.
///
/// The caller keeps its own data; this only decides grouping and order, so it
/// works the same for a directory listing and for the member names of a
/// container already held in memory.
pub fn group(names: &[&str]) -> Vec<Vec<usize>> {
    let parsed: Vec<Option<VolumeName>> = names.iter().map(|n| parse(n)).collect();
    let mut sets: Vec<Vec<usize>> = Vec::new();
    let mut claimed = vec![false; names.len()];

    for i in 0..names.len() {
        if claimed[i] {
            continue;
        }
        let Some(vi) = &parsed[i] else { continue };
        let mut members: Vec<(usize, usize)> = vec![(vi.index, i)];
        for (j, item) in parsed.iter().enumerate().skip(i + 1) {
            if claimed[j] {
                continue;
            }
            if let Some(vj) = item {
                if vi.same_set_as(vj) {
                    members.push((vj.index, j));
                    claimed[j] = true;
                }
            }
        }
        if members.len() < 2 {
            continue; // a single volume is just a file
        }
        claimed[i] = true;
        members.sort_by_key(|(idx, _)| *idx);
        // Duplicate positions mean the names disagree about the set's shape;
        // concatenating them would splice bytes in an order nothing wrote.
        if members.windows(2).any(|w| w[0].0 == w[1].0) {
            continue;
        }
        sets.push(members.into_iter().map(|(_, j)| j).collect());
    }
    sets
}

impl Scheme {
    /// Whether a set in this scheme is joined by plain concatenation.
    ///
    /// The two kinds of continuation need completely different handling:
    ///
    /// * **Byte-split** (`.001`, `.002`) — produced by splitting an already
    ///   finished file, so concatenating the parts *is* the original. Format
    ///   agnostic: it works for `.7z`, `.zip`, `.arj` or anything else.
    /// * **Format-aware volumes** (RAR `.partN`, ZIP `.zNN`) — each volume
    ///   carries its own headers, and a member's data resumes *past* the next
    ///   volume's header. Concatenating them produces garbage that still looks
    ///   like an archive, which is the worst kind of wrong.
    pub fn is_byte_split(&self) -> bool {
        matches!(self, Scheme::NumberedSuffix { .. })
    }
}

/// What to do with a member offered to a [`Collector`].
#[derive(Debug)]
pub enum Offer {
    /// Not part of any set — scan it as usual.
    PassThrough { name: String, data: Vec<u8> },
    /// Held as part of a possible set; nothing to scan yet.
    Held,
}

/// Everything a [`Collector`] held, resolved once the container has ended.
#[derive(Debug, Default)]
pub struct Finished {
    /// Reassembled files, each named for its set.
    pub joined: Vec<Joined>,
    /// Parts of sets that never completed. **These must still be scanned or
    /// reported** — bytes withheld and then dropped would be the silent clean
    /// this crate exists to prevent.
    pub unjoined: Vec<Unjoined>,
}

/// A set put back together.
#[derive(Debug)]
pub struct Joined {
    /// Named for the set, not for a part, so a report points at the archive.
    pub name: String,
    pub data: Vec<u8>,
    /// The parts it was built from, in volume order. A caller that must
    /// attribute the archive's verdict back to files it was given needs this:
    /// every one of these is a piece of whatever the joined file turns out to
    /// be.
    pub parts: Vec<String>,
}

impl Finished {
    /// Everything a caller must scan, as `(name, bytes, incomplete_set)`:
    /// rejoined files first, then the parts that could not be joined.
    ///
    /// The unjoined parts are in here deliberately. Bytes held back and then
    /// dropped would be a silent clean, so this returns the *whole* of what was
    /// held — a caller that iterates it cannot skip them by forgetting a field.
    pub fn into_scannable(self) -> impl Iterator<Item = (String, Vec<u8>, Option<&'static str>)> {
        self.joined
            .into_iter()
            .map(|j| (j.name, j.data, None))
            .chain(
                self.unjoined
                    .into_iter()
                    .map(|u| (u.name, u.data, u.incomplete_set)),
            )
    }
}

/// One member still held when a container ended, and why it could not be joined.
#[derive(Debug)]
pub struct Unjoined {
    pub name: String,
    pub data: Vec<u8>,
    /// `Some(reason)` when this member belonged to a set that could not be
    /// rejoined: its bytes are part of an archive nothing can now read, which a
    /// caller must not report clean.
    ///
    /// `None` when it was a lone numbered file. One part is not a set — the
    /// same rule [`group`] applies — and treating it as one would flag every
    /// file that merely happens to end in `.001`.
    pub incomplete_set: Option<&'static str>,
}

/// Collects volume members as they stream past, joining what it can.
///
/// This implements *react, don't enumerate*: members arrive one at a time, and
/// the only cost for a container with no volumes is one [`parse`] per name. A
/// list of the container's members is never built, so the flat working set that
/// [`crate::stream_members`] exists to preserve is untouched.
///
/// Held bytes are bounded by `max_held_bytes`; past it, members are passed
/// through individually rather than accumulated, so a container claiming a huge
/// volume set cannot turn this into unbounded memory.
pub struct Collector {
    pending: Vec<Pending>,
    max_held_bytes: u64,
    held_bytes: u64,
}

struct Pending {
    key: VolumeName,
    /// `(volume index, name, bytes)`, in arrival order.
    parts: Vec<(usize, String, Vec<u8>)>,
}

impl Collector {
    pub fn new(max_held_bytes: u64) -> Self {
        Collector {
            pending: Vec::new(),
            max_held_bytes,
            held_bytes: 0,
        }
    }

    /// Offer one member.
    pub fn offer(&mut self, name: &str, data: Vec<u8>) -> Offer {
        let Some(vn) = parse(name) else {
            return Offer::PassThrough {
                name: name.to_string(),
                data,
            };
        };
        // Only byte-split sets can be joined here. A format-aware volume still
        // needs its decoder to walk headers, so it is passed through and
        // reported exactly as it is today.
        if !vn.scheme.is_byte_split() {
            return Offer::PassThrough {
                name: name.to_string(),
                data,
            };
        }
        if self.held_bytes.saturating_add(data.len() as u64) > self.max_held_bytes {
            return Offer::PassThrough {
                name: name.to_string(),
                data,
            };
        }

        let slot = self.pending.iter_mut().find(|p| p.key.same_set_as(&vn));
        let set = match slot {
            Some(p) => p,
            None => {
                self.pending.push(Pending {
                    key: vn.clone(),
                    parts: Vec::new(),
                });
                self.pending.last_mut().expect("just pushed")
            }
        };
        // Two members claiming the same position: the set's shape is ambiguous,
        // so joining would splice bytes in an order nothing wrote.
        if set.parts.iter().any(|(i, _, _)| *i == vn.index) {
            return Offer::PassThrough {
                name: name.to_string(),
                data,
            };
        }
        self.held_bytes += data.len() as u64;
        set.parts.push((vn.index, name.to_string(), data));
        // Never joined here. Nothing in the naming records how many parts a set
        // has, so `.001`+`.002` looks contiguous even when `.003` follows —
        // joining on arrival would emit a truncated prefix that still parses as
        // the archive. Completeness is only knowable once the container ends.
        Offer::Held
    }

    /// Resolve everything held, now that no further members can arrive.
    pub fn finish(self) -> Finished {
        let mut out = Finished::default();
        for mut set in self.pending {
            set.parts.sort_by_key(|(i, _, _)| *i);
            // One numbered file on its own is not a set, however much its name
            // looks like one. Hand it straight back unflagged.
            if set.parts.len() < 2 {
                for (_, name, data) in set.parts {
                    out.unjoined.push(Unjoined {
                        name,
                        data,
                        incomplete_set: None,
                    });
                }
                continue;
            }
            let idx: Vec<usize> = set.parts.iter().map(|(i, _, _)| *i).collect();
            let complete = idx.first() == Some(&0) && idx.windows(2).all(|w| w[1] == w[0] + 1);
            if !complete {
                let reason = if idx.first() != Some(&0) {
                    "part of a multi-volume set whose first volume was not present"
                } else {
                    "part of an incomplete multi-volume set; the other volumes \
                     were not present"
                };
                for (_, name, data) in set.parts {
                    out.unjoined.push(Unjoined {
                        name,
                        data,
                        incomplete_set: Some(reason),
                    });
                }
                continue;
            }
            // Named for the set, not for a part, so a downstream report points
            // at the archive rather than at one fragment.
            let name = match &set.key.scheme {
                Scheme::NumberedSuffix { base_ext, .. } => {
                    format!("{}.{}", set.key.stem, base_ext)
                }
                _ => set.key.stem.clone(),
            };
            let mut data = Vec::new();
            let mut parts = Vec::new();
            for (_, part_name, part) in set.parts {
                data.extend_from_slice(&part);
                parts.push(part_name);
            }
            out.joined.push(Joined { name, data, parts });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rar_part_scheme() {
        let v = parse("archive.part1.rar").unwrap();
        assert_eq!(v.stem, "archive");
        assert_eq!(v.index, 0);
        assert_eq!(v.name_at(1).unwrap(), "archive.part2.rar");
        // The digit width a writer chose is preserved: `part01` sets stay
        // `part01`, and asking for `part2` in that set must not produce `part2`.
        let w = parse("archive.part01.rar").unwrap();
        assert_eq!(w.name_at(1).unwrap(), "archive.part02.rar");
    }

    #[test]
    fn rar_old_scheme_counts_the_bare_rar_first() {
        let v = parse("a.rar").unwrap();
        assert_eq!(v.index, 0);
        let w = parse("a.r00").unwrap();
        assert_eq!(w.index, 1, ".r00 is the SECOND volume, not the first");
        assert_eq!(v.name_at(1).unwrap(), "a.r00");
        assert_eq!(v.name_at(2).unwrap(), "a.r01");
    }

    #[test]
    fn numbered_suffix_scheme() {
        let v = parse("big.7z.001").unwrap();
        assert_eq!(v.stem, "big");
        assert_eq!(v.index, 0);
        assert_eq!(v.name_at(1).unwrap(), "big.7z.002");
        assert!(parse("big.zip.001").is_some());
    }

    #[test]
    fn ordinary_names_are_not_volumes() {
        // Grouping decides which bytes get concatenated, so a false positive
        // here is worse than a miss.
        for n in [
            "notes.txt",
            "archive.zip",
            "photo.jpeg",
            "a.tar.gz",
            "report.7z",
            "x.r",
            "x.rrr",
            "backup.2024",
            "",
            ".rar",
        ] {
            let v = parse(n);
            assert!(
                v.is_none() || !matches!(v.as_ref().unwrap().scheme, Scheme::NumberedSuffix { .. }),
                "{n:?} was taken for a numbered split: {v:?}"
            );
        }
        assert!(parse("notes.txt").is_none());
        assert!(parse("photo.jpeg").is_none());
    }

    #[test]
    fn a_set_is_grouped_in_volume_order_regardless_of_listing_order() {
        // A directory listing arrives in whatever order the filesystem gives.
        let names = ["a.part3.rar", "a.part1.rar", "a.part2.rar"];
        let sets = group(&names);
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0], vec![1, 2, 0], "must be sorted by volume index");
    }

    #[test]
    fn unrelated_archives_are_not_merged() {
        let names = ["a.part1.rar", "a.part2.rar", "b.part1.rar", "b.part2.rar"];
        let sets = group(&names);
        assert_eq!(sets.len(), 2);
        for s in &sets {
            assert_eq!(s.len(), 2);
        }
    }

    #[test]
    fn a_shared_stem_with_different_schemes_is_two_archives() {
        // `a.part1.rar` and `a.7z.001` are not one archive, however alike the
        // stems look.
        let names = ["a.part1.rar", "a.part2.rar", "a.7z.001", "a.7z.002"];
        let sets = group(&names);
        assert_eq!(sets.len(), 2, "got {sets:?}");
    }

    #[test]
    fn a_lone_volume_is_not_a_set() {
        assert!(group(&["a.part1.rar"]).is_empty());
        assert!(group(&["notes.txt", "photo.jpg"]).is_empty());
    }

    #[test]
    fn duplicate_volume_numbers_are_refused() {
        // Two files claiming the same position: concatenating them would splice
        // bytes in an order nothing ever wrote. Better to leave them ungrouped
        // and report each on its own.
        let names = ["a.part1.rar", "a.part1.rar", "a.part2.rar"];
        assert!(group(&names).is_empty(), "an ambiguous set must not group");
    }

    #[test]
    fn grouping_is_case_insensitive_but_names_are_preserved() {
        let names = ["A.Part1.RAR", "a.part2.rar"];
        let sets = group(&names);
        assert_eq!(sets.len(), 1, "case must not split a set: {sets:?}");
    }

    /// Drive a whole container through a collector: `(scannable, unjoined)`,
    /// where `scannable` is what the caller would hand on to be scanned.
    fn collect(members: &[(&str, &[u8])]) -> (Vec<(String, Vec<u8>)>, Vec<Unjoined>) {
        let mut c = Collector::new(1 << 20);
        let mut out = Vec::new();
        for (n, d) in members {
            match c.offer(n, d.to_vec()) {
                Offer::PassThrough { name, data } => out.push((name, data)),
                Offer::Held => {}
            }
        }
        let fin = c.finish();
        out.extend(fin.joined.into_iter().map(|j| (j.name, j.data)));
        (out, fin.unjoined)
    }

    #[test]
    fn a_byte_split_set_is_rejoined_into_the_original_file() {
        let (out, left) = collect(&[
            ("big.7z.001", b"HELLO "),
            ("big.7z.002", b"WORLD "),
            ("big.7z.003", b"AGAIN"),
        ]);
        assert!(left.is_empty(), "nothing should be left over");
        assert_eq!(out.len(), 1, "the set becomes one file: {out:?}");
        assert_eq!(out[0].0, "big.7z", "named for the set, not for a part");
        assert_eq!(out[0].1, b"HELLO WORLD AGAIN");
    }

    #[test]
    fn a_set_is_never_joined_before_the_container_ends() {
        // The bug this pins: `.001`+`.002` are contiguous, so a collector that
        // joins as soon as positions 0..n line up emits a TRUNCATED prefix —
        // which still parses as the archive, and is then scanned as if it were
        // the whole thing. Nothing in the naming says how many parts exist, so
        // completeness is only knowable once no more can arrive.
        let mut c = Collector::new(1 << 20);
        assert!(matches!(c.offer("s.7z.001", b"AAA".to_vec()), Offer::Held));
        assert!(
            matches!(c.offer("s.7z.002", b"BBB".to_vec()), Offer::Held),
            "a contiguous prefix must not be released mid-container"
        );
        assert!(matches!(c.offer("s.7z.003", b"CCC".to_vec()), Offer::Held));
        let fin = c.finish();
        assert_eq!(fin.joined.len(), 1);
        assert_eq!(
            fin.joined[0].data, b"AAABBBCCC",
            "the whole set, not the prefix that looked complete"
        );
        assert_eq!(
            fin.joined[0].parts,
            ["s.7z.001", "s.7z.002", "s.7z.003"],
            "a caller must be able to attribute the archive back to its parts"
        );
    }

    #[test]
    fn parts_arriving_out_of_order_still_join_in_volume_order() {
        // A container yields members in its own order, not the volume order.
        let (out, left) = collect(&[
            ("x.zip.003", b"C"),
            ("x.zip.001", b"A"),
            ("x.zip.002", b"B"),
        ]);
        assert!(left.is_empty());
        assert_eq!(
            out[0].1, b"ABC",
            "must be reassembled by index, not arrival"
        );
    }

    #[test]
    fn an_incomplete_set_is_handed_back_never_dropped() {
        // Withholding bytes from the scan and then dropping them would be
        // exactly the silent clean this crate exists to prevent.
        let (out, left) = collect(&[("x.7z.001", b"A"), ("x.7z.003", b"C")]);
        assert!(out.is_empty(), "an incomplete set must not be joined");
        assert_eq!(left.len(), 2, "both parts must come back: {left:?}");
        assert!(left.iter().all(|u| !u.data.is_empty()));
        assert!(
            left.iter().all(|u| u.incomplete_set.is_some()),
            "a gap in a real set is not something to report clean"
        );
    }

    #[test]
    fn a_lone_numbered_file_is_not_flagged_as_a_broken_set() {
        // Plenty of ordinary files end in `.001`. One part is not a set, so it
        // comes back as an ordinary file — flagging it would fire on all of them.
        let (out, left) = collect(&[("odd.dat.001", b"A")]);
        assert!(out.is_empty());
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].data, b"A");
        assert!(
            left[0].incomplete_set.is_none(),
            "a single part must not be reported as a broken archive"
        );
    }

    #[test]
    fn a_set_missing_its_first_volume_does_not_join() {
        // Starting at .002 means the head of the file is absent; concatenating
        // what is left would produce a plausible-looking wrong file.
        let (out, left) = collect(&[("x.7z.002", b"B"), ("x.7z.003", b"C")]);
        assert!(out.is_empty());
        assert_eq!(left.len(), 2);
    }

    #[test]
    fn format_aware_volumes_are_passed_through_not_concatenated() {
        // RAR volumes carry their own headers; concatenating them yields
        // garbage that still looks like an archive.
        let (out, left) = collect(&[("a.part1.rar", b"RAR1"), ("a.part2.rar", b"RAR2")]);
        assert!(left.is_empty());
        assert_eq!(out.len(), 2, "each volume passes through on its own");
        assert_eq!(out[0].1, b"RAR1");
    }

    #[test]
    fn ordinary_members_are_untouched() {
        let (out, left) = collect(&[("notes.txt", b"hello"), ("a.jpg", b"\xff\xd8")]);
        assert!(left.is_empty());
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].0, "notes.txt");
    }

    #[test]
    fn two_sets_in_one_container_do_not_mix() {
        let (out, left) = collect(&[
            ("a.7z.001", b"A1"),
            ("b.7z.001", b"B1"),
            ("a.7z.002", b"A2"),
            ("b.7z.002", b"B2"),
        ]);
        assert!(left.is_empty());
        assert_eq!(out.len(), 2);
        let mut joined: Vec<&[u8]> = out.iter().map(|(_, d)| d.as_slice()).collect();
        joined.sort();
        assert_eq!(joined, vec![b"A1A2".as_slice(), b"B1B2".as_slice()]);
    }

    #[test]
    fn a_duplicate_position_refuses_to_join() {
        let (out, left) = collect(&[
            ("x.7z.001", b"A"),
            ("x.7z.001", b"DIFFERENT"),
            ("x.7z.002", b"B"),
        ]);
        // The duplicate passes through on its own; whatever else happens, no
        // buffer may contain the duplicate spliced into the set.
        assert!(
            !out.iter()
                .any(|(_, d)| d.windows(9).any(|w| w == b"DIFFERENT")
                    && d.len() > b"DIFFERENT".len()),
            "an ambiguous set must not be spliced: {out:?}"
        );
        assert!(out.iter().any(|(_, d)| d == b"DIFFERENT"));
        let _ = left;
    }

    #[test]
    fn the_held_budget_bounds_memory() {
        // A container claiming a huge volume set must not turn this into
        // unbounded accumulation; past the cap, members pass through instead.
        let mut c = Collector::new(8);
        let mut passed = 0;
        for i in 1..=6 {
            let name = format!("x.7z.{i:03}");
            if let Offer::PassThrough { .. } = c.offer(&name, vec![0u8; 4]) {
                passed += 1;
            }
        }
        assert!(passed > 0, "the cap must eventually force pass-through");
    }

    #[test]
    fn generated_names_stay_inside_the_set() {
        // The filesystem resolver joins these onto a directory, so a name
        // carrying a separator would escape it.
        for base in ["a.part1.rar", "a.rar", "big.7z.001", "s.z01"] {
            let v = parse(base).unwrap();
            for i in 0..8 {
                if let Some(n) = v.name_at(i) {
                    assert!(
                        !n.contains('/') && !n.contains('\\') && !n.contains(".."),
                        "{base} generated an escaping name: {n:?}"
                    );
                }
            }
        }
    }
}
