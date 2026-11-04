//! Why something was not fully examined, and how several reasons fold into
//! one report.

use super::{Path, PathStyle};
use crate::{LimitKind, MemberMeta};

/// What kind of reason it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReasonKind {
    /// Encrypted content that was not decrypted.
    Password,
    /// A format or method that is not decoded.
    Unsupported,
    /// Bytes that are present and could not be decoded.
    Damaged,
    /// A member that was not read, or not kept to be read.
    NotExtracted,
    /// A bound was reached.
    Limit(LimitKind),
    /// A read failed.
    ReadFailed,
    /// A format the settings leave out.
    FormatExcluded,
    /// A check that could not be made.
    NotChecked,
    /// A decoder or a consumer panicked.
    Panic,
    /// Part of a multi-volume set is missing.
    SetIncomplete,
}

/// Which of the three reports a reason falls under when a container ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasonClass {
    /// Actionable: the right password reads the content.
    Password,
    /// A bound was reached; the content may be fine.
    Limits,
    /// Everything else.
    Unscannable,
}

impl ReasonKind {
    /// A member not read, or not read whole, for its size.
    pub const OVER_SIZE: ReasonKind = ReasonKind::Limit(LimitKind::MaxFileSize);

    /// The kind for a bound that stopped an extraction. A stop for malformed
    /// content is damage, not a bound.
    pub fn from_limit(kind: LimitKind) -> ReasonKind {
        match kind {
            LimitKind::Corrupt => ReasonKind::Damaged,
            kind => ReasonKind::Limit(kind),
        }
    }

    pub fn class(self) -> ReasonClass {
        match self {
            ReasonKind::Password => ReasonClass::Password,
            ReasonKind::Limit(LimitKind::Corrupt) => ReasonClass::Unscannable,
            ReasonKind::Limit(_) => ReasonClass::Limits,
            _ => ReasonClass::Unscannable,
        }
    }
}

/// One reason, and where it arose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reason {
    pub kind: ReasonKind,
    pub text: String,
    /// The location of the node it arose at (see
    /// [`PathStyle::Located`](super::PathStyle::Located)).
    pub at: String,
}

impl Reason {
    /// Why a member's content could not be decoded, from what its reader says
    /// of it: `Password` for an encrypted member, the kind the reader gave
    /// (`MemberMeta::reason_kind`) for any other, `Damaged` if it gave none.
    /// `None` for a member with nothing to report. `at` is empty.
    pub fn of_member(meta: &MemberMeta) -> Option<Reason> {
        let text = meta.unsupported?;
        Some(Reason {
            kind: if meta.encrypted {
                ReasonKind::Password
            } else {
                meta.reason_kind.unwrap_or(ReasonKind::Damaged)
            },
            text: text.to_string(),
            at: String::new(),
        })
    }
}

/// The reasons found under a container, the first of each class: what its
/// report is made from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reasons {
    pub password: Option<Reason>,
    pub limits: Option<Reason>,
    pub unscannable: Option<Reason>,
    /// Every reason added, including those not kept for being second of
    /// their class.
    pub total: u64,
}

impl Reasons {
    /// The reasons that are kept: password protection, a bound, the rest, as
    /// far as there is one of each.
    pub fn kept(&self) -> impl Iterator<Item = &Reason> {
        [&self.password, &self.limits, &self.unscannable]
            .into_iter()
            .flatten()
    }

    /// Add one reason. It is kept if it is the first of its class.
    pub fn add(&mut self, reason: Reason) {
        self.total = self.total.saturating_add(1);
        let slot = match reason.kind.class() {
            ReasonClass::Password => &mut self.password,
            ReasonClass::Limits => &mut self.limits,
            ReasonClass::Unscannable => &mut self.unscannable,
        };
        slot.get_or_insert(reason);
    }

    /// [`Self::add`] for a reason that arose at `path`: a reason that is kept
    /// and has no location yet is given the path's. The path is written out
    /// only for a reason that is kept.
    pub fn add_at(&mut self, mut reason: Reason, path: &Path<'_>) {
        let kept = match reason.kind.class() {
            ReasonClass::Password => self.password.is_none(),
            ReasonClass::Limits => self.limits.is_none(),
            ReasonClass::Unscannable => self.unscannable.is_none(),
        };
        if kept && reason.at.is_empty() {
            reason.at = path.render(PathStyle::Located);
        }
        self.add(reason);
    }

    /// Add what was found under a member after what is here: for each class
    /// the earlier reason stays.
    pub fn merge(&mut self, later: Reasons) {
        self.total = self.total.saturating_add(later.total);
        for (mine, theirs) in [
            (&mut self.password, later.password),
            (&mut self.limits, later.limits),
            (&mut self.unscannable, later.unscannable),
        ] {
            if mine.is_none() {
                *mine = theirs;
            }
        }
    }

    /// [`Self::merge`] for what was found under `path`: a reason that is kept
    /// and has no location yet is given the path's.
    pub fn merge_at(&mut self, later: Reasons, path: &Path<'_>) {
        self.total = self.total.saturating_add(later.total);
        for (mine, theirs) in [
            (&mut self.password, later.password),
            (&mut self.limits, later.limits),
            (&mut self.unscannable, later.unscannable),
        ] {
            if mine.is_none()
                && let Some(mut reason) = theirs
            {
                if reason.at.is_empty() {
                    reason.at = path.render(PathStyle::Located);
                }
                *mine = Some(reason);
            }
        }
    }

    /// The reason a container reports: password over limits over
    /// unscannable.
    pub fn first(&self) -> Option<&Reason> {
        self.password
            .as_ref()
            .or(self.limits.as_ref())
            .or(self.unscannable.as_ref())
    }

    /// [`Self::first`], taken.
    pub fn into_first(self) -> Option<Reason> {
        self.password.or(self.limits).or(self.unscannable)
    }

    pub fn is_empty(&self) -> bool {
        self.total == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reason(kind: ReasonKind, text: &str) -> Reason {
        Reason {
            kind,
            text: text.to_string(),
            at: format!("at-{text}"),
        }
    }

    fn texts(r: &Reasons) -> [Option<&str>; 3] {
        [&r.password, &r.limits, &r.unscannable].map(|x| x.as_ref().map(|r| r.text.as_str()))
    }

    #[test]
    fn a_kind_belongs_to_one_class() {
        let table = [
            (ReasonKind::Password, ReasonClass::Password),
            (
                ReasonKind::Limit(LimitKind::MaxFileSize),
                ReasonClass::Limits,
            ),
            (
                ReasonKind::Limit(LimitKind::MaxRecursion),
                ReasonClass::Limits,
            ),
            (
                ReasonKind::Limit(LimitKind::Corrupt),
                ReasonClass::Unscannable,
            ),
            (ReasonKind::Unsupported, ReasonClass::Unscannable),
            (ReasonKind::Damaged, ReasonClass::Unscannable),
            (ReasonKind::NotExtracted, ReasonClass::Unscannable),
            (ReasonKind::ReadFailed, ReasonClass::Unscannable),
            (ReasonKind::FormatExcluded, ReasonClass::Unscannable),
            (ReasonKind::NotChecked, ReasonClass::Unscannable),
            (ReasonKind::Panic, ReasonClass::Unscannable),
            (ReasonKind::SetIncomplete, ReasonClass::Unscannable),
        ];
        for (kind, class) in table {
            assert_eq!(kind.class(), class, "{kind:?}");
        }
    }

    #[test]
    fn a_stop_for_malformed_content_is_damage_and_a_bound_is_a_limit() {
        assert_eq!(
            ReasonKind::from_limit(LimitKind::Corrupt),
            ReasonKind::Damaged
        );
        assert_eq!(
            ReasonKind::from_limit(LimitKind::MaxFiles),
            ReasonKind::Limit(LimitKind::MaxFiles)
        );
    }

    #[test]
    fn the_first_reason_of_each_class_is_kept() {
        let mut r = Reasons::default();
        assert!(r.is_empty() && r.first().is_none());
        r.add(reason(ReasonKind::Damaged, "damaged"));
        r.add(reason(ReasonKind::Unsupported, "unsupported"));
        r.add(reason(ReasonKind::Limit(LimitKind::MaxFileSize), "big"));
        r.add(reason(ReasonKind::Limit(LimitKind::MaxFiles), "many"));
        assert_eq!(texts(&r), [None, Some("big"), Some("damaged")]);
        assert_eq!(r.total, 4);
        assert!(!r.is_empty());
    }

    #[test]
    fn a_container_reports_password_over_limits_over_unscannable() {
        let mut r = Reasons::default();
        r.add(reason(ReasonKind::Damaged, "damaged"));
        assert_eq!(r.first().unwrap().text, "damaged");
        r.add(reason(ReasonKind::Limit(LimitKind::MaxScanSize), "limit"));
        assert_eq!(r.first().unwrap().text, "limit");
        r.add(reason(ReasonKind::Password, "password"));
        assert_eq!(r.first().unwrap().text, "password");
        assert_eq!(r.first().unwrap().at, "at-password");
    }

    #[test]
    fn a_container_takes_its_reason_whole() {
        assert!(Reasons::default().into_first().is_none());
        // Every subset of the three classes: the one `first` names, taken.
        for set in 1..8u8 {
            let mut r = Reasons::default();
            for (bit, kind) in [
                (1, ReasonKind::Damaged),
                (2, ReasonKind::Limit(LimitKind::MaxFiles)),
                (4, ReasonKind::Password),
            ] {
                if set & bit != 0 {
                    r.add(reason(kind, &format!("{kind:?}")));
                }
            }
            let named = r.first().cloned();
            assert_eq!(r.into_first(), named, "set {set}");
        }
    }

    #[test]
    fn a_member_reports_what_its_reader_could_not_decode() {
        let meta = |encrypted, unsupported| MemberMeta {
            encrypted,
            unsupported,
            ..MemberMeta::default()
        };
        let got = |m: &MemberMeta| Reason::of_member(m).map(|r| (r.kind, r.text, r.at));
        assert_eq!(
            got(&meta(true, Some("encrypted"))),
            Some((ReasonKind::Password, "encrypted".to_string(), String::new()))
        );
        // The reader says it is a method it does not decode.
        let method = MemberMeta {
            reason_kind: Some(ReasonKind::Unsupported),
            ..meta(false, Some("method 99"))
        };
        assert_eq!(
            got(&method),
            Some((
                ReasonKind::Unsupported,
                "method 99".to_string(),
                String::new()
            ))
        );
        // It says nothing: the member is damaged, or not read for another reason.
        assert_eq!(
            got(&meta(false, Some("will not parse"))),
            Some((
                ReasonKind::Damaged,
                "will not parse".to_string(),
                String::new()
            ))
        );
        // A password is a password's, whatever else the reader says.
        assert_eq!(
            got(&MemberMeta {
                reason_kind: Some(ReasonKind::Unsupported),
                ..meta(true, Some("encrypted"))
            })
            .map(|r| r.0),
            Some(ReasonKind::Password)
        );
        // Decrypted, or nothing wrong: nothing to report.
        assert_eq!(got(&meta(true, None)), None);
        assert_eq!(got(&meta(false, None)), None);
    }

    #[test]
    fn merging_keeps_the_earlier_reason_of_a_class_and_fills_the_rest() {
        let mut earlier = Reasons::default();
        earlier.add(reason(ReasonKind::Damaged, "first damaged"));
        earlier.add(reason(ReasonKind::Panic, "second damaged"));
        let mut later = Reasons::default();
        later.add(reason(ReasonKind::Damaged, "later damaged"));
        later.add(reason(ReasonKind::Password, "later password"));
        later.add(reason(
            ReasonKind::Limit(LimitKind::MaxFileSize),
            "later limit",
        ));
        earlier.merge(later.clone());
        assert_eq!(
            texts(&earlier),
            [
                Some("later password"),
                Some("later limit"),
                Some("first damaged")
            ]
        );
        assert_eq!(earlier.total, 5);
        // The other way round, the later one wins its class.
        later.merge(Reasons::default());
        assert_eq!(later.total, 3);
        let mut other = Reasons::default();
        other.add(reason(ReasonKind::Unsupported, "x"));
        other.merge(later);
        assert_eq!(
            texts(&other),
            [Some("later password"), Some("later limit"), Some("x")]
        );
    }

    fn bare(kind: ReasonKind, text: &str) -> Reason {
        Reason {
            kind,
            text: text.to_string(),
            at: String::new(),
        }
    }

    fn places(r: &Reasons) -> [Option<&str>; 3] {
        [&r.password, &r.limits, &r.unscannable].map(|x| x.as_ref().map(|r| r.at.as_str()))
    }

    #[test]
    fn a_reason_that_is_kept_is_given_the_location_it_arose_at() {
        use super::super::Name;
        let root = Path::root(Name::stored("top.zip"));
        let inner = root.child(Name::stored("a.zip"));
        let leaf = inner.child(Name::stored("b\nc"));
        let mut r = Reasons::default();
        r.add_at(bare(ReasonKind::Damaged, "first"), &leaf);
        // The second of its class is not kept, and not written out.
        r.add_at(bare(ReasonKind::Panic, "second"), &inner);
        r.add_at(bare(ReasonKind::Password, "pw"), &inner);
        // One that already says where it arose keeps that.
        let mut placed = bare(ReasonKind::Limit(LimitKind::MaxFiles), "limit");
        placed.at = "elsewhere".to_string();
        r.add_at(placed, &root);
        assert_eq!(
            places(&r),
            [Some("a.zip"), Some("elsewhere"), Some("a.zip/b_c")]
        );
        assert_eq!(r.total, 4);
        // The root has no location.
        let mut at_root = Reasons::default();
        at_root.add_at(bare(ReasonKind::Damaged, "x"), &root);
        assert_eq!(places(&at_root), [None, None, Some("")]);
    }

    #[test]
    fn what_is_merged_from_under_a_node_is_given_its_location_if_it_has_none() {
        use super::super::Name;
        let root = Path::root(Name::stored("top"));
        let node = root.child(Name::stored("in.zip"));
        let mut earlier = Reasons::default();
        earlier.add_at(bare(ReasonKind::Damaged, "mine"), &root);
        let mut later = Reasons::default();
        later.add(bare(ReasonKind::Panic, "not kept"));
        later.add(bare(ReasonKind::Password, "pw"));
        let mut placed = bare(ReasonKind::Limit(LimitKind::MaxFiles), "limit");
        placed.at = "deeper/still".to_string();
        later.add(placed);
        earlier.merge_at(later, &node);
        assert_eq!(
            places(&earlier),
            [Some("in.zip"), Some("deeper/still"), Some("")]
        );
        assert_eq!(earlier.total, 4);
        assert_eq!(texts(&earlier), [Some("pw"), Some("limit"), Some("mine")]);
    }
}
