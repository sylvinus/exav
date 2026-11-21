//! What a walk does with the byte-split sets (`x.7z.001`, `x.7z.002`, ...)
//! among the members of a container.
//!
//! A part is a fragment of a file that only exists once the set is rejoined,
//! so a part that is held is not scanned on its own: it waits for the end of
//! the container. A part that cannot be held, or came out cut short, would
//! leave a hole in the rejoined file, so the set it belongs to is reported
//! instead of joined without it.

use super::{Body, End, Reason, ReasonKind};
use crate::volume::{Collector, Offer};

/// The byte-split sets of one container, while its members are walked.
pub struct Sets {
    /// `None`: no member is taken for the part of a set.
    collector: Option<Collector>,
}

/// A set put back together, or a part that could not be, at the end of its
/// container.
pub struct Rejoined {
    /// The set for a rejoined file, the part for one that could not be joined.
    pub name: String,
    pub data: Vec<u8>,
    /// The parts it was made of, in volume order; the part itself for one
    /// that could not be joined.
    pub parts: Vec<String>,
    /// Why the set is not whole, when it is not: its parts are bytes of an
    /// archive nothing can read.
    pub incomplete: Option<Reason>,
    /// `data` is a buffer the set made, not the bytes of one part as it was
    /// read.
    pub joined: bool,
}

impl Sets {
    /// `on` says whether parts of a set are looked for; `hold` is the most
    /// bytes held for the rejoin, over all the parts of the container.
    pub fn new(on: bool, hold: u64) -> Sets {
        Sets {
            collector: on.then(|| Collector::new(hold)),
        }
    }

    /// Say what became of a member's bytes before they are scanned. A body
    /// that is too large to hold (spilled, a prefix, or read where it lies),
    /// that was held and failed to decode (it ends cut or damaged), or that
    /// there is none of (the member was not decoded, or nothing of it was:
    /// `nothing`), is lost to its set: the set would be joined with a hole in
    /// it. What there is of it is scanned where it is.
    ///
    /// Returns whether the body is a part cut short: scanned as far as it
    /// decoded, and never offered.
    pub fn lose(&mut self, name: &str, body: &Body<'_>, end: &End, nothing: bool) -> bool {
        let cut = matches!(body, Body::Mem(_)) && !end.is_complete();
        let unheld = cut
            || nothing
            || matches!(
                body,
                Body::None
                    | Body::Spilled(_)
                    | Body::Prefix { .. }
                    | Body::Range(_)
                    | Body::Stream { .. }
            );
        if unheld && let Some(collector) = &mut self.collector {
            collector.lose(name);
        }
        cut
    }

    /// Offer a body that was held. `None`: it is held as a part of a set,
    /// there is nothing to scan yet. `Some`: it is not, scan it as it is.
    pub fn offer(&mut self, name: &str, data: Vec<u8>) -> Option<Vec<u8>> {
        let Some(collector) = &mut self.collector else {
            return Some(data);
        };
        match collector.offer(name, data) {
            Offer::Held => None,
            Offer::PassThrough { data, .. } => Some(data),
        }
    }

    /// The container has ended: the sets that joined, then the parts that did
    /// not. Nothing in a part's name says how many parts a set has, so a set
    /// is judged only here: joining as the parts arrive would hand on a
    /// prefix that still parses as the archive.
    pub fn rejoined(self) -> impl Iterator<Item = Rejoined> {
        let done = self.collector.map(Collector::finish).unwrap_or_default();
        let joined = done.joined.into_iter().map(|j| Rejoined {
            name: j.name,
            data: j.data,
            parts: j.parts,
            incomplete: None,
            joined: true,
        });
        let unjoined = done.unjoined.into_iter().map(|u| Rejoined {
            parts: vec![u.name.clone()],
            name: u.name,
            data: u.data,
            incomplete: u.incomplete_set.map(|why| Reason {
                kind: ReasonKind::SetIncomplete,
                text: why.to_string(),
                at: String::new(),
            }),
            joined: false,
        });
        joined.chain(unjoined)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::Sub;
    use crate::spill::{MemSpill, spill_stream};

    const LOST: &str =
        "part of a multi-volume set one of whose volumes could not be held for rejoining";

    fn cut() -> End {
        End::Cut("end of input".to_string())
    }

    fn mem(data: &[u8]) -> Body<'static> {
        Body::Mem(data.to_vec())
    }

    /// Hold `name` as a complete body, as a member walk does.
    fn hold(sets: &mut Sets, name: &str, data: &[u8]) {
        let body = mem(data);
        assert!(!sets.lose(name, &body, &End::Complete, false));
        assert!(sets.offer(name, data.to_vec()).is_none(), "{name} held");
    }

    /// A rejoined file: name, bytes, and the kind and text of why its set is
    /// not whole.
    type Got = (String, Vec<u8>, Option<(ReasonKind, String)>);

    fn rejoined(sets: Sets) -> Vec<Got> {
        sets.rejoined()
            .map(|r| (r.name, r.data, r.incomplete.map(|i| (i.kind, i.text))))
            .collect()
    }

    #[test]
    fn the_parts_of_a_set_are_held_and_rejoined_at_the_end() {
        let mut sets = Sets::new(true, 1 << 20);
        hold(&mut sets, "x.7z.001", b"abc");
        hold(&mut sets, "x.7z.002", b"def");
        hold(&mut sets, "x.7z.003", b"g");
        assert_eq!(
            rejoined(sets),
            vec![("x.7z".to_string(), b"abcdefg".to_vec(), None)]
        );
    }

    #[test]
    fn a_rejoined_set_names_its_parts_and_a_part_that_did_not_join_names_itself() {
        let mut sets = Sets::new(true, 1 << 20);
        hold(&mut sets, "x.7z.001", b"a");
        hold(&mut sets, "x.7z.002", b"b");
        hold(&mut sets, "y.7z.001", b"c");
        hold(&mut sets, "y.7z.003", b"d");
        let got: Vec<_> = sets.rejoined().map(|r| (r.name, r.parts)).collect();
        let names = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            got,
            vec![
                ("x.7z".to_string(), names(&["x.7z.001", "x.7z.002"])),
                ("y.7z.001".to_string(), names(&["y.7z.001"])),
                ("y.7z.003".to_string(), names(&["y.7z.003"])),
            ]
        );
    }

    #[test]
    fn a_member_that_is_no_part_of_a_set_is_given_back_to_be_scanned() {
        let mut sets = Sets::new(true, 1 << 20);
        assert_eq!(sets.offer("a.txt", b"abc".to_vec()), Some(b"abc".to_vec()));
        // A format-aware volume is the decoder's, not a byte-split part.
        assert_eq!(
            sets.offer("a.part1.rar", b"r".to_vec()),
            Some(b"r".to_vec())
        );
        assert!(rejoined(sets).is_empty());
    }

    #[test]
    fn with_sets_off_nothing_is_held_lost_or_rejoined() {
        let mut sets = Sets::new(false, 1 << 20);
        assert_eq!(
            sets.offer("x.7z.001", b"abc".to_vec()),
            Some(b"abc".to_vec())
        );
        assert!(!sets.lose("x.7z.002", &Body::None, &End::Complete, false));
        assert!(sets.lose("x.7z.003", &mem(b"z"), &cut(), false));
        assert!(rejoined(sets).is_empty());
    }

    #[test]
    fn a_body_too_large_to_hold_loses_its_part_to_the_set() {
        let container = vec![0u8; 100];
        let spill = MemSpill::new();
        for what in ["spilled", "prefix"] {
            let body = match what {
                "spilled" => {
                    let (spilled, _) =
                        spill_stream(&spill, &mut &b"abc"[..], (4096, 1 << 20)).unwrap();
                    Body::Spilled(spilled)
                }
                _ => Body::Prefix {
                    data: b"ab".to_vec(),
                    reason: "over".to_string(),
                },
            };
            let mut sets = Sets::new(true, 1 << 20);
            hold(&mut sets, "x.7z.001", b"abc");
            assert!(
                !sets.lose("x.7z.002", &body, &End::Complete, false),
                "{what}"
            );
            assert_eq!(
                rejoined(sets),
                vec![(
                    "x.7z.001".to_string(),
                    b"abc".to_vec(),
                    Some((ReasonKind::SetIncomplete, LOST.to_string()))
                )],
                "{what}"
            );
        }
        // Read where it lies in its container.
        let mut sets = Sets::new(true, 1 << 20);
        hold(&mut sets, "x.7z.001", b"abc");
        let range = Body::Range(Sub::new(&container, 0, 50));
        assert!(!sets.lose("x.7z.002", &range, &End::Complete, false));
        assert_eq!(rejoined(sets).len(), 1);
    }

    #[test]
    fn a_held_part_that_ends_cut_or_damaged_is_lost_and_not_offered() {
        for end in [cut(), End::Damaged("bad block".to_string())] {
            let mut sets = Sets::new(true, 1 << 20);
            hold(&mut sets, "x.7z.001", b"abc");
            assert!(sets.lose("x.7z.002", &mem(b"de"), &end, false), "{end:?}");
            assert_eq!(
                rejoined(sets),
                vec![(
                    "x.7z.001".to_string(),
                    b"abc".to_vec(),
                    Some((ReasonKind::SetIncomplete, LOST.to_string()))
                )],
                "{end:?}"
            );
        }
    }

    #[test]
    fn a_part_without_a_body_is_not_offered_and_is_lost_to_its_set() {
        let mut sets = Sets::new(true, 1 << 20);
        hold(&mut sets, "x.7z.001", b"abc");
        // It is not a body cut short: nothing of it is scanned as one.
        assert!(!sets.lose("x.7z.002", &Body::None, &cut(), false));
        // The part held is not joined with a hole where this one was.
        assert_eq!(
            rejoined(sets),
            vec![(
                "x.7z.001".to_string(),
                b"abc".to_vec(),
                Some((ReasonKind::SetIncomplete, LOST.to_string()))
            )]
        );
    }

    #[test]
    fn a_part_of_which_nothing_decoded_is_lost_to_its_set() {
        let mut sets = Sets::new(true, 1 << 20);
        hold(&mut sets, "x.7z.001", b"abc");
        // An empty body, with the reason it is empty: `nothing`.
        assert!(!sets.lose("x.7z.002", &mem(b""), &End::Complete, true));
        assert_eq!(
            rejoined(sets),
            vec![(
                "x.7z.001".to_string(),
                b"abc".to_vec(),
                Some((ReasonKind::SetIncomplete, LOST.to_string()))
            )]
        );
        // An empty file that is a part on its own is a part like another.
        let mut sets = Sets::new(true, 1 << 20);
        hold(&mut sets, "x.7z.001", b"abc");
        hold(&mut sets, "x.7z.002", b"");
        assert_eq!(rejoined(sets).len(), 1);
    }

    #[test]
    fn a_numbered_file_on_its_own_with_no_body_is_no_set() {
        let mut sets = Sets::new(true, 1 << 20);
        sets.lose("y.bin.001", &Body::None, &End::Complete, false);
        assert!(rejoined(sets).is_empty());
    }

    #[test]
    fn a_numbered_file_on_its_own_is_not_a_set_whatever_became_of_it() {
        let mut sets = Sets::new(true, 1 << 20);
        let prefix = Body::Prefix {
            data: Vec::new(),
            reason: String::new(),
        };
        sets.lose("y.bin.001", &prefix, &End::Complete, false);
        assert!(rejoined(sets).is_empty());
    }

    #[test]
    fn a_part_over_what_is_held_loses_the_set() {
        let mut sets = Sets::new(true, 5);
        hold(&mut sets, "x.7z.001", b"abc");
        // Over the 5 bytes: given back to be scanned, and the set cannot join.
        assert_eq!(
            sets.offer("x.7z.002", b"defg".to_vec()),
            Some(b"defg".to_vec())
        );
        assert_eq!(
            rejoined(sets),
            vec![(
                "x.7z.001".to_string(),
                b"abc".to_vec(),
                Some((ReasonKind::SetIncomplete, LOST.to_string()))
            )]
        );
    }

    #[test]
    fn a_gap_in_the_volumes_says_so() {
        let mut sets = Sets::new(true, 1 << 20);
        hold(&mut sets, "x.7z.001", b"abc");
        hold(&mut sets, "x.7z.003", b"ghi");
        let got = rejoined(sets);
        assert_eq!(got.len(), 2);
        for (_, _, why) in got {
            let (kind, text) = why.expect("a gap is reported");
            assert_eq!(kind, ReasonKind::SetIncomplete);
            assert!(text.contains("incomplete multi-volume set"), "{text}");
        }
    }
}
