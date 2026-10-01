//! The bodies an offset pins to a few places in an object, checked there
//! rather than looked for everywhere.
//!
//! A subsignature written `0:000000` or `EP+0:0000...` can only match where
//! its offset says, but its anchor, a few zero bytes, occurs throughout any
//! executable: looked for by the sweep, it was most of the anchor hits of a
//! PE, each rejected by the offset check. Such a body is instead checked at
//! the starts its offset allows once the object's length and layout are
//! known: a table lookup of the bytes where its anchor would be, per group of
//! bodies sharing an offset, or for the few whose window is wide, a search of
//! that window for the anchor.

use crate::byte_source::ByteSource;
use crate::pe::PeLayout;

use super::{start_set, Body, Elem, Offset, OffsetKind, Prefix, StartSet, FOLD};

/// Widest window of starts a pinned body may have: past it the sweep's one
/// pass over the object costs less than the searches.
const MAX_WINDOW: u64 = 4096;

/// Widest window checked a start at a time; wider ones are searched.
const MAX_STEPPED: u64 = 64;

/// Bodies sharing one offset, keyed by where their anchor sits past a start
/// and its first two bytes, folded.
#[derive(serde::Serialize, serde::Deserialize)]
struct Group {
    offset: Offset,
    /// Every distinct distance from a start to an anchor, ascending. Derived,
    /// not stored.
    #[serde(skip)]
    dists: Vec<u32>,
    /// `(distance, key, body)`, sorted.
    entries: Vec<(u32, u16, u32)>,
}

/// The pinned bodies of an engine.
#[derive(Default, serde::Serialize, serde::Deserialize)]
pub(super) struct Pins {
    groups: Vec<Group>,
    /// Bodies whose window is too wide to step through: each searched for
    /// its anchor in it.
    wide: Vec<u32>,
    /// Whether any is case-insensitive, so verifying it reads the object
    /// lowercased. Derived, not stored.
    #[serde(skip)]
    nocase: bool,
}

/// Whether `body` is pinned, and where its anchor sits past its start.
fn pinned(body: &Body) -> Option<(u64, u32)> {
    let Offset::Constrained(k) = &body.offset else {
        return None;
    };
    let shift = match **k {
        OffsetKind::Abs { shift, .. }
        | OffsetKind::Eof { shift, .. }
        | OffsetKind::Ep { shift, .. }
        | OffsetKind::Sec { shift, .. }
        | OffsetKind::SecLast { shift, .. } => shift,
        OffsetKind::SecIn { .. } | OffsetKind::VersionInfo => return None,
    };
    let dist = match body.prefix {
        Prefix::Fixed { len, .. } => len,
        Prefix::Floating { .. } => 0,
        Prefix::Internal { .. } => return None,
    };
    (shift <= MAX_WINDOW).then_some((shift, dist))
}

/// The anchor of `body`, which [`pinned`] took.
fn anchor(body: &Body) -> &[u8] {
    match &body.elems.as_deref().unwrap_or_default()[body.prefix.anchor_idx() as usize] {
        Elem::Bytes(b) => b,
        _ => unreachable!("an anchor is a literal"),
    }
}

fn key(a: &[u8]) -> u16 {
    u16::from_le_bytes([FOLD[a[0] as usize], FOLD[a[1] as usize]])
}

impl Pins {
    /// Take the pinned bodies out of `bodies`' anchoring: `true` for each one
    /// taken, which the anchor index then leaves out. A
    /// pure literal gets its anchor back as its pattern, since nothing else
    /// will hold it.
    pub(super) fn take(bodies: &mut [Body], anchors: impl Fn(usize) -> Vec<u8>) -> (Pins, Vec<bool>) {
        let mut pins = Pins::default();
        let mut taken = vec![false; bodies.len()];
        let mut by_offset: std::collections::BTreeMap<Offset, usize> = Default::default();
        #[cfg(test)]
        if super::tests::NO_PINS.get() {
            return (pins, taken);
        }
        for (id, body) in bodies.iter_mut().enumerate() {
            let Some((shift, dist)) = pinned(body) else {
                continue;
            };
            if body.elems.is_none() {
                body.elems = Some(vec![Elem::Bytes(anchors(id))]);
                body.prefix = Prefix::Fixed { anchor_idx: 0, len: 0 };
            }
            taken[id] = true;
            if shift > MAX_STEPPED {
                pins.wide.push(id as u32);
                continue;
            }
            let g = *by_offset.entry(body.offset.clone()).or_insert_with(|| {
                pins.groups.push(Group {
                    offset: body.offset.clone(),
                    dists: Vec::new(),
                    entries: Vec::new(),
                });
                pins.groups.len() - 1
            });
            pins.groups[g].entries.push((dist, key(anchor(body)), id as u32));
        }
        pins.derive(bodies);
        (pins, taken)
    }

    /// What is derived from the stored pins and `bodies`.
    fn derive(&mut self, bodies: &[Body]) {
        for g in &mut self.groups {
            g.entries.sort_unstable();
            g.dists = g.entries.iter().map(|e| e.0).collect();
            g.dists.dedup();
        }
        let nocase = self.bodies().any(|b| bodies[b as usize].nocase);
        self.nocase = nocase;
    }

    /// Every pinned body.
    pub(super) fn bodies(&self) -> impl Iterator<Item = u32> + '_ {
        self.groups.iter().flat_map(|g| g.entries.iter().map(|e| e.2)).chain(self.wide.iter().copied())
    }

    pub(super) fn any_nocase(&self) -> bool {
        self.nocase
    }

    /// Pins as read from a database, checked against `bodies`: every stored
    /// body is one, pinned, with a literal anchor of two bytes or more, and
    /// stored where [`Self::take`] puts it.
    pub(super) fn load(mut self, bodies: &[Body]) -> Option<Pins> {
        let at = |b: u32| {
            let body = bodies.get(b as usize)?;
            let (shift, dist) = pinned(body)?;
            let a = body.elems.as_deref()?.get(body.prefix.anchor_idx() as usize)?;
            matches!(a, Elem::Bytes(a) if a.len() >= 2).then_some((body, shift, dist))
        };
        let grouped = self.groups.iter().all(|g| {
            g.entries.iter().all(|&(d, k, b)| {
                at(b).is_some_and(|(body, shift, dist)| {
                    shift <= MAX_STEPPED && dist == d && body.offset == g.offset && key(anchor(body)) == k
                })
            })
        });
        if !grouped || !self.wide.iter().all(|&b| at(b).is_some_and(|(_, shift, _)| shift > MAX_STEPPED)) {
            return None;
        }
        self.derive(bodies);
        Some(self)
    }

    /// Hand `f` every place a pinned body of `bodies` could match in `buf`,
    /// as `(body, anchor start)`, for the bodies `wanted` keeps: its anchor's
    /// first two bytes are there, or for a wide window, the whole anchor.
    /// `lower` is `buf` lowercased. `false` when `f` asks to stop.
    pub(super) fn visit<B: ByteSource + ?Sized, L: ByteSource + ?Sized>(
        &self,
        bodies: &[Body],
        buf: &B,
        lower: &L,
        layout: Option<&PeLayout>,
        wanted: &dyn Fn(&Body) -> bool,
        f: &mut dyn FnMut(usize, usize) -> bool,
    ) -> bool {
        let len = buf.len() as u64;
        for g in &self.groups {
            let Some(StartSet::Range(lo, hi)) = start_set(&g.offset, len, layout) else {
                continue;
            };
            for s in lo..=hi.min(len) {
                for &d in &g.dists {
                    let at = s + d as u64;
                    let w = buf.window(at as usize, 2);
                    if w.len() < 2 {
                        continue;
                    }
                    let k = key(&w);
                    let from = g.entries.partition_point(|e| (e.0, e.1) < (d, k));
                    for &(_, _, b) in g.entries[from..].iter().take_while(|e| (e.0, e.1) == (d, k)) {
                        if wanted(&bodies[b as usize]) && !f(b as usize, at as usize) {
                            return false;
                        }
                    }
                }
            }
        }
        for &b in &self.wide {
            let body = &bodies[b as usize];
            if !wanted(body) {
                continue;
            }
            let Some(StartSet::Range(lo, hi)) = start_set(&body.offset, len, layout) else {
                continue;
            };
            let dist = pinned(body).map_or(0, |(_, d)| d) as u64;
            let a = anchor(body);
            let from = lo.saturating_add(dist);
            let to = hi.saturating_add(dist).saturating_add(a.len() as u64).min(len);
            if from >= to {
                continue;
            }
            let (from_u, n) = (from as usize, (to - from) as usize);
            let (w, finder) = match body.nocase {
                true => (lower.window(from_u, n), memchr::memmem::Finder::new(&a.to_ascii_lowercase()).into_owned()),
                false => (buf.window(from_u, n), memchr::memmem::Finder::new(a).into_owned()),
            };
            // Every occurrence, overlapping ones included: in a run, each
            // start is a match of its own.
            let mut p = 0;
            while let Some(q) = finder.find(&w[p..]) {
                if !f(b as usize, from as usize + p + q) {
                    return false;
                }
                p += q + 1;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::super::EngineBuilder;
    use super::*;

    /// Pins read back are refused unless every entry is a pinned body, stored
    /// where [`Pins::take`] puts it.
    #[test]
    fn a_misplaced_pin_is_refused() {
        let mut b = EngineBuilder::new();
        b.add_ndb(
            "P.Abs:0:0:4d5a9000\nP.Ep:1:EP+2:e8000000\nP.Wide:0:10,500:70696e6e6564\nP.Any:0:*:616e79776865726521",
            false,
        );
        let e = b.build();
        let copy = || rmp_serde::from_slice::<Pins>(&rmp_serde::to_vec(&e.pins).unwrap()).unwrap();
        assert_eq!((copy().groups.len(), copy().wide.len()), (2, 1));
        assert!(copy().load(&e.bodies).is_some());
        let misplaced: [&dyn Fn(&mut Pins); 6] = [
            &|p: &mut Pins| p.groups[0].entries[0].0 += 1,
            &|p: &mut Pins| p.groups[0].entries[0].1 ^= 1,
            &|p: &mut Pins| p.groups[0].offset = p.groups[1].offset.clone(),
            &|p: &mut Pins| p.groups[0].entries[0].2 = 3,
            &|p: &mut Pins| p.wide.push(p.groups[0].entries[0].2),
            &|p: &mut Pins| {
                let w = p.wide.pop().unwrap();
                p.groups[0].entries.push((0, 0, w));
            },
        ];
        for (i, m) in misplaced.iter().enumerate() {
            let mut p = copy();
            m(&mut p);
            assert!(p.load(&e.bodies).is_none(), "misplacement {i}");
        }
    }
}
