//! What exav does about the things it finds, as opposed to what it looks for.
//!
//! Two questions an operator answers, each with one flag:
//!
//! * [`NotScannedPolicy`] — what becomes of an object exav could not fully
//!   examine. Blocked, reported as a detection, or delivered.
//! * [`Detectors`] — which heuristic detectors run at all, over and above the
//!   signature database.
//!
//! One flag each rather than a boolean per condition, for two reasons. A
//! boolean per condition cannot express "all of them" — a reader has to know
//! the whole set to switch it on. And "exav could not fully examine this" is one
//! condition with three possible outcomes, so spreading it over a family of
//! switches lets an operator ask for two of them at once and leaves the answer
//! to whichever the code reads first.

use std::fmt;
use std::sync::OnceLock;

use exav_core::{ScanReport, Verdict, VerdictCategory};

static CURRENT: OnceLock<NotScanned> = OnceLock::new();

/// Install the not-scanned policy, once, at startup.
///
/// Process-global, the way the spill settings are, because every surface asks
/// the same question about the same verdict and threading it through six call
/// sites would give six chances for one of them to answer differently.
pub(crate) fn configure(policy: NotScanned) {
    let _ = CURRENT.set(policy);
}

/// The policy in force, defaulting to `block` for any caller that never
/// configured one.
pub(crate) fn current() -> NotScanned {
    *CURRENT.get_or_init(NotScanned::default)
}

/// Apply the policy to a finished report, in place.
///
/// The single point where `pass` and `alert` take effect, so a not-scanned
/// object reaches an exit code, a `clamd` reply, a JSON record and a summary
/// counter having already been through it. Doing it per surface would be four
/// chances to forget one, and forgetting the CLI's would mean an object the
/// operator asked to pass still exiting 2.
///
/// `alert` is a no-op for the two conditions the engine renames itself
/// (`--not-scanned password-protected=alert` becomes
/// `Heuristics.Encrypted.*` upstream, under ClamAV's own names, which are
/// better than anything synthesised here). It reaches this function only for a
/// condition the engine has no heuristic for.
pub(crate) fn apply(report: &mut ScanReport, policy: NotScanned) {
    if report.verdict.category() != VerdictCategory::NotScanned {
        return;
    }
    let tag = report.verdict.status_tag();
    match policy.for_tag(tag) {
        NotScannedPolicy::Block => {}
        NotScannedPolicy::Pass => {
            // Loud, per object. A pass an operator configured is a risk they
            // accepted; a pass they cannot count is one they cannot review.
            eprintln!(
                "exav: passing an object that could not be fully examined ({tag}: {}) \
                 — --not-scanned says so",
                report.verdict.detail().unwrap_or_default()
            );
            report.verdict = Verdict::Clean;
        }
        NotScannedPolicy::Alert => {
            report.verdict = Verdict::Infected {
                signature: heuristic_name(tag),
                offset: 0,
                method: exav_core::Method::Heuristic,
            };
        }
    }
}

/// The detection name a not-scanned condition is reported under when the engine
/// has no heuristic of its own for it: `UNSCANNABLE` becomes
/// `Heuristics.Exav.Unscannable`.
///
/// `Heuristics.` is the prefix ClamAV puts on a policy finding rather than a
/// database entry, and `.Exav.` says which scanner synthesised it — so no
/// signature set can collide with it and no analyst can mistake it for a hit.
pub(crate) fn heuristic_name(tag: &str) -> String {
    let mut out = String::from("Heuristics.Exav.");
    for word in tag.split('-') {
        let mut chars = word.chars();
        if let Some(first) = chars.next() {
            out.push(first.to_ascii_uppercase());
            out.extend(chars.map(|c| c.to_ascii_lowercase()));
        }
    }
    out
}

/// What happens to an object exav could not fully examine.
///
/// The three answers are exhaustive and mutually exclusive, which is why this
/// is one setting rather than a set of switches: an object is stopped, or it is
/// called a detection, or it is delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum NotScannedPolicy {
    /// Stop it. The verdict stays `LIMITS-EXCEEDED` / `UNSCANNABLE` /
    /// `PASSWORD-PROTECTED` and every surface treats it as a failure: exit 2,
    /// a clamd `ERROR` reply, an ICAP block.
    #[default]
    Block,
    /// Call it a detection, named `Heuristics.*`. Exit 1, `FOUND`,
    /// `X-Infection-Found` — an ordinary hit as far as any client is concerned.
    Alert,
    /// Deliver it. Exit 0, `OK`, a `204`.
    ///
    /// Never silently: a passed object is logged wherever it happens, and on
    /// ICAP the response still carries `X-Exav-Verdict` saying what was skipped.
    Pass,
}

impl NotScannedPolicy {
    fn parse(s: &str) -> Result<Self, String> {
        match s {
            "block" => Ok(Self::Block),
            "alert" => Ok(Self::Alert),
            "pass" => Ok(Self::Pass),
            other => Err(format!(
                "unknown policy `{other}` (expected block, alert or pass)"
            )),
        }
    }
}

impl fmt::Display for NotScannedPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Block => "block",
            Self::Alert => "alert",
            Self::Pass => "pass",
        })
    }
}

/// The status tags a not-scanned verdict reports under — the values
/// [`Verdict::status_tag`](exav_core::Verdict::status_tag) returns for the
/// `NotScanned` category — paired with the name an operator writes.
///
/// The two spellings differ on purpose: the wire tag is shouted
/// (`PASSWORD-PROTECTED`) because it appears in a protocol reply, and the flag
/// value is not. `every_tag_is_nameable` keeps the list honest against the
/// engine, so a verdict added there cannot become unnameable here.
pub(crate) const TAGS: [(&str, &str); 3] = [
    ("limits-exceeded", "LIMITS-EXCEEDED"),
    ("unscannable", "UNSCANNABLE"),
    ("password-protected", "PASSWORD-PROTECTED"),
];

/// The policy for each not-scanned condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct NotScanned {
    /// One slot per entry of [`TAGS`], in that order.
    per_tag: [NotScannedPolicy; TAGS.len()],
}

impl NotScanned {
    /// Parse `--not-scanned`: one policy for everything (`pass`), or a
    /// comma-separated list of `tag=policy` pairs.
    ///
    /// A tag exav does not know is refused rather than ignored. A policy that
    /// parsed but named nothing would read as a setting that never fires — an
    /// operator believing they had opened a hole they had not, or closed one
    /// they had not, and finding out from traffic.
    pub(crate) fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if let Ok(uniform) = NotScannedPolicy::parse(s) {
            return Ok(Self {
                per_tag: [uniform; TAGS.len()],
            });
        }
        if !s.contains('=') {
            return Err(format!(
                "expected block, alert, pass, or a list like \
                 `password-protected=pass` (tags: {})",
                TAGS.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", ")
            ));
        }
        let mut out = Self::default();
        for item in s.split(',') {
            let item = item.trim();
            let (name, policy) = item
                .split_once('=')
                .ok_or_else(|| format!("`{item}` is not a `tag=policy` pair"))?;
            let idx = TAGS
                .iter()
                .position(|(n, _)| n.eq_ignore_ascii_case(name.trim()))
                .ok_or_else(|| {
                    format!(
                        "unknown verdict tag `{}` (tags: {})",
                        name.trim(),
                        TAGS.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", ")
                    )
                })?;
            out.per_tag[idx] = NotScannedPolicy::parse(policy.trim())?;
        }
        Ok(out)
    }

    /// The policy for a wire status tag (`UNSCANNABLE`, …). An unrecognised tag
    /// blocks, which is the answer that cannot turn a verdict into a pass by
    /// accident.
    pub(crate) fn for_tag(&self, tag: &str) -> NotScannedPolicy {
        TAGS.iter()
            .position(|(_, wire)| *wire == tag)
            .map(|i| self.per_tag[i])
            .unwrap_or(NotScannedPolicy::Block)
    }

    /// Whether any condition is set to `pass`, for the line a listener
    /// announces itself with — a deployment delivering what it could not
    /// examine should be legible from its logs alone.
    pub(crate) fn any_pass(&self) -> bool {
        self.per_tag.contains(&NotScannedPolicy::Pass)
    }

    /// Whether `password-protected` is reported as a detection, which the
    /// engine implements itself under ClamAV's `Heuristics.Encrypted.*` names.
    pub(crate) fn alerts_encrypted(&self) -> bool {
        self.for_tag("PASSWORD-PROTECTED") == NotScannedPolicy::Alert
    }

    /// Whether `limits-exceeded` is reported as a detection, which the engine
    /// implements itself under `Heuristics.Limits.Exceeded.*`.
    pub(crate) fn alerts_limits(&self) -> bool {
        self.for_tag("LIMITS-EXCEEDED") == NotScannedPolicy::Alert
    }
}

impl fmt::Display for NotScanned {
    /// Spelled the way it was asked for, so a log line can be pasted back onto
    /// a command line.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.per_tag.iter().all(|p| *p == self.per_tag[0]) {
            return write!(f, "{}", self.per_tag[0]);
        }
        let parts: Vec<String> = TAGS
            .iter()
            .zip(self.per_tag.iter())
            .map(|((name, _), p)| format!("{name}={p}"))
            .collect();
        f.write_str(&parts.join(","))
    }
}

/// A heuristic detector: something exav can look for beyond the signature
/// database, off unless asked for.
///
/// `pua` sits in this list even though it is applied at database load rather
/// than at scan time. From the command line it is the same kind of decision —
/// "also look for this" — and splitting it out as `--detect-pua` only meant one
/// more flag to find.
pub(crate) const DETECTORS: [&str; 8] = [
    "macros",
    "broken",
    "broken-media",
    "partition-intersection",
    "phishing",
    "packed",
    "pua",
    "heuristics",
];

/// Which heuristic detectors are switched on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Detectors {
    on: [bool; DETECTORS.len()],
}

impl Detectors {
    /// Parse `--detect`: `none`, `all`, or a comma-separated list of names.
    pub(crate) fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        match s {
            "none" | "" => Ok(Self::default()),
            "all" => Ok(Self {
                on: [true; DETECTORS.len()],
            }),
            list => {
                let mut out = Self::default();
                for item in list.split(',') {
                    let item = item.trim();
                    let idx = DETECTORS
                        .iter()
                        .position(|d| d.eq_ignore_ascii_case(item))
                        .ok_or_else(|| {
                            format!(
                                "unknown detector `{item}` (known: {}, plus `all` and `none`)",
                                DETECTORS.join(", ")
                            )
                        })?;
                    out.on[idx] = true;
                }
                Ok(out)
            }
        }
    }

    fn has(&self, name: &str) -> bool {
        DETECTORS
            .iter()
            .position(|d| *d == name)
            .map(|i| self.on[i])
            .unwrap_or(false)
    }

    pub(crate) fn macros(&self) -> bool {
        self.has("macros")
    }
    pub(crate) fn broken(&self) -> bool {
        self.has("broken")
    }
    pub(crate) fn broken_media(&self) -> bool {
        self.has("broken-media")
    }
    pub(crate) fn partition_intersection(&self) -> bool {
        self.has("partition-intersection")
    }
    pub(crate) fn phishing(&self) -> bool {
        self.has("phishing")
    }
    pub(crate) fn packed(&self) -> bool {
        self.has("packed")
    }
    pub(crate) fn pua(&self) -> bool {
        self.has("pua")
    }
    /// TLSH fuzzy matching and the ML scorer — one engine switch, so one name
    /// here. Splitting it into `fuzzy` and `ml` would be a promise the engine
    /// cannot keep: `ScanOptions::heuristics` gates both together.
    pub(crate) fn heuristics(&self) -> bool {
        self.has("heuristics")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocking_is_what_you_get_without_asking() {
        let p = NotScanned::default();
        for (_, wire) in TAGS {
            assert_eq!(p.for_tag(wire), NotScannedPolicy::Block, "{wire}");
        }
        assert!(!p.any_pass());
        assert_eq!(p.to_string(), "block");
    }

    #[test]
    fn one_word_sets_every_condition() {
        let p = NotScanned::parse("pass").unwrap();
        for (_, wire) in TAGS {
            assert_eq!(p.for_tag(wire), NotScannedPolicy::Pass, "{wire}");
        }
        assert!(p.any_pass());
        assert_eq!(p.to_string(), "pass");
    }

    #[test]
    fn conditions_can_be_set_apart() {
        let p = NotScanned::parse("password-protected=pass, limits-exceeded=alert").unwrap();
        assert_eq!(p.for_tag("PASSWORD-PROTECTED"), NotScannedPolicy::Pass);
        assert_eq!(p.for_tag("LIMITS-EXCEEDED"), NotScannedPolicy::Alert);
        // Unnamed conditions keep the safe answer rather than inheriting one.
        assert_eq!(p.for_tag("UNSCANNABLE"), NotScannedPolicy::Block);
        assert!(p.any_pass());
        assert!(p.alerts_limits() && !p.alerts_encrypted());
        assert_eq!(
            p.to_string(),
            "limits-exceeded=alert,unscannable=block,password-protected=pass"
        );
    }

    #[test]
    fn a_tag_the_engine_reports_but_nobody_named_still_blocks() {
        // The answer that cannot turn a verdict into a pass by accident.
        let p = NotScanned::parse("pass").unwrap();
        assert_eq!(p.for_tag("SOME-FUTURE-TAG"), NotScannedPolicy::Block);
    }

    #[test]
    fn misspellings_are_refused_rather_than_ignored() {
        for bad in [
            "passs",
            "password_protected=pass",
            "encrypted=pass",
            "password-protected=allow",
            "password-protected",
            "",
        ] {
            assert!(NotScanned::parse(bad).is_err(), "{bad:?} parsed");
        }
    }

    /// The tags an operator may name have to be the tags the engine reports, or
    /// naming one would never fire. Built from the engine's own verdicts rather
    /// than copied, so a verdict added there fails this test.
    #[test]
    fn every_tag_is_nameable() {
        use exav_core::{Verdict, VerdictCategory};
        let reason = || "reason".to_string();
        for v in [
            Verdict::Clean,
            Verdict::LimitsExceeded { reason: reason() },
            Verdict::Unscannable { reason: reason() },
            Verdict::PasswordProtected { reason: reason() },
        ] {
            if v.category() != VerdictCategory::NotScanned {
                continue;
            }
            let tag = v.status_tag();
            assert!(
                TAGS.iter().any(|(_, wire)| *wire == tag),
                "the engine reports `{tag}`, which no operator can name"
            );
        }
    }

    #[test]
    fn detectors_are_a_list_with_an_all() {
        assert_eq!(Detectors::parse("none").unwrap(), Detectors::default());
        let all = Detectors::parse("all").unwrap();
        assert!(all.macros() && all.phishing() && all.packed() && all.pua());

        let some = Detectors::parse("macros, phishing").unwrap();
        assert!(some.macros() && some.phishing());
        assert!(!some.broken() && !some.pua());

        for bad in ["macro", "encrypted", "exceeds-max", "macros,nope"] {
            assert!(Detectors::parse(bad).is_err(), "{bad:?} parsed");
        }
    }

    /// The two conditions ClamAV spells `--alert-encrypted` and
    /// `--alert-exceeds-max` belong to `--not-scanned`, because they answer
    /// "what does this verdict become", not "what should exav look for".
    /// Accepting them here would put one question under two flags.
    #[test]
    fn verdict_remapping_is_not_a_detector() {
        for not_a_detector in ["encrypted", "exceeds-max", "limits-exceeded"] {
            assert!(
                Detectors::parse(not_a_detector).is_err(),
                "{not_a_detector} belongs to --not-scanned"
            );
        }
    }
}
