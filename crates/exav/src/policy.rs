//! What exav does about the things it finds, as opposed to what it looks for.
//!
//! Two questions an operator answers, each with one flag:
//!
//! * [`PartialStatus`] — what becomes of an object exav could not fully
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

static CURRENT: OnceLock<PartialAs> = OnceLock::new();

/// Install the partial policy, once, at startup.
///
/// Process-global, the way the spill settings are, because every surface asks
/// the same question about the same verdict and threading it through six call
/// sites would give six chances for one of them to answer differently.
pub(crate) fn configure(policy: PartialAs) {
    let _ = CURRENT.set(policy);
}

/// The policy in force, defaulting to `block` for any caller that never
/// configured one.
pub(crate) fn current() -> PartialAs {
    *CURRENT.get_or_init(PartialAs::default)
}

/// Apply the policy to a finished report, in place.
///
/// The single point where `pass` and `alert` take effect, so a partial
/// object reaches an exit code, a `clamd` reply, a JSON record and a summary
/// counter having already been through it. Doing it per surface would be four
/// chances to forget one, and forgetting the CLI's would mean an object the
/// operator asked to pass still exiting 2.
///
/// `found` is a no-op for the conditions the engine names itself
/// (`--partial-as password-protected=found` becomes `Heuristics.Encrypted.*`
/// upstream, under ClamAV's own names, which are better than anything
/// synthesised here). It reaches this function only for a condition the engine
/// has no heuristic for.
///
/// `error` is not handled here at all: it changes no verdict, only which exit
/// code the verdict contributes. Rewriting the report would lose the category
/// the line still has to name.
pub(crate) fn apply(report: &mut ScanReport, policy: PartialAs) {
    if report.verdict.category() != VerdictCategory::Partial {
        return;
    }
    let tag = report.verdict.status_tag();
    match policy.for_tag(tag) {
        PartialStatus::Partial | PartialStatus::Error => {}
        PartialStatus::Ok => {
            // Loud, per object. A pass an operator configured is a risk they
            // accepted; a pass they cannot count is one they cannot review.
            eprintln!(
                "exav: reporting an object that could not be fully examined as OK ({tag}: {}) \
                 — --partial-as says so",
                report.verdict.detail().unwrap_or_default()
            );
            report.verdict = Verdict::Clean;
        }
        PartialStatus::Found => {
            report.verdict = Verdict::Infected {
                signature: heuristic_name(tag),
                offset: 0,
                method: exav_core::Method::Heuristic,
            };
        }
    }
}

/// The detection name a partial condition is reported under when the engine
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

/// Which status a partial verdict is reported as.
///
/// The values are the four statuses themselves, so the name of the value is the
/// name of the outcome — and, because status and exit code are 1:1, the value
/// also names the exit code it produces. Nothing to look up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum PartialStatus {
    /// Report it for what it is: `PARTIAL` under its category, exit `3`. On the
    /// clamd wire that is an `ERROR` reply, because the protocol's vocabulary is
    /// closed and a word it does not know is read as `OK` by real clients.
    #[default]
    Partial,
    /// Deliver it as clean: `OK`, exit `0`, an ICAP `204`.
    ///
    /// Never silently — a passed object is logged wherever it happens, and the
    /// ICAP response still carries the headers saying what was skipped.
    Ok,
    /// Call it a detection, named `Heuristics.*`: `FOUND`, exit `1`,
    /// `X-Infection-Found`. An ordinary hit as far as any client is concerned,
    /// and what ClamAV's `--alert-exceeds-max` / `--alert-encrypted` do.
    Found,
    /// Call it an operational failure: `ERROR`, exit `2`.
    ///
    /// For a caller that would rather not learn a fourth exit code, or that
    /// wants any unexaminable object to stop the pipeline as loudly as a broken
    /// scanner does. Identical to `partial` on every surface that has no exit
    /// code of its own — the clamd wire and ICAP.
    Error,
}

impl PartialStatus {
    fn parse(s: &str) -> Result<Self, String> {
        match s {
            "partial" => Ok(Self::Partial),
            "ok" => Ok(Self::Ok),
            "found" => Ok(Self::Found),
            "error" => Ok(Self::Error),
            other => Err(format!(
                "unknown status `{other}` (expected partial, ok, found or error)"
            )),
        }
    }
}

impl fmt::Display for PartialStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Partial => "partial",
            Self::Ok => "ok",
            Self::Found => "found",
            Self::Error => "error",
        })
    }
}

/// The status tags a partial verdict reports under — the values
/// [`Verdict::status_tag`](exav_core::Verdict::status_tag) returns for the
/// `PartialAs` category — paired with the name an operator writes.
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

/// The policy for each partial condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct PartialAs {
    /// One slot per entry of [`TAGS`], in that order.
    per_tag: [PartialStatus; TAGS.len()],
}

impl PartialAs {
    /// One status for every category — what a bare `--partial-as ok` means, and
    /// what `--clamav-compat` installs.
    pub(crate) fn uniform(status: PartialStatus) -> Self {
        Self {
            per_tag: [status; TAGS.len()],
        }
    }

    /// Parse `--partial-as`: one status for everything (`ok`), or a
    /// comma-separated list of `category=status` pairs
    /// (`password-protected=ok,limits-exceeded=found`).
    ///
    /// A category exav does not know is refused rather than ignored. A setting
    /// that parsed but named nothing would read as one that never fires — an
    /// operator believing they had opened a hole they had not, or closed one
    /// they had not, and finding out from traffic.
    pub(crate) fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if let Ok(uniform) = PartialStatus::parse(s) {
            return Ok(Self::uniform(uniform));
        }
        if !s.contains('=') {
            return Err(format!(
                "expected partial, ok, found, error, or a list like \
                 `password-protected=ok` (categories: {})",
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
            out.per_tag[idx] = PartialStatus::parse(policy.trim())?;
        }
        Ok(out)
    }

    /// The policy for a wire status tag (`UNSCANNABLE`, …). An unrecognised tag
    /// blocks, which is the answer that cannot turn a verdict into a pass by
    /// accident.
    pub(crate) fn for_tag(&self, tag: &str) -> PartialStatus {
        TAGS.iter()
            .position(|(_, wire)| *wire == tag)
            .map(|i| self.per_tag[i])
            .unwrap_or(PartialStatus::Partial)
    }

    /// Whether any condition is set to `pass`, for the line a listener
    /// announces itself with — a deployment delivering what it could not
    /// examine should be legible from its logs alone.
    ///
    /// Its one caller is the ICAP listener, so a build without `icap` — two of
    /// which the feature-flag reference offers as copy-paste examples — has
    /// nothing calling it. The tests below still do, but they are not compiled
    /// into the binary the warning is raised against.
    #[cfg_attr(not(feature = "icap"), allow(dead_code))]
    pub(crate) fn reports_any_as_ok(&self) -> bool {
        self.per_tag.contains(&PartialStatus::Ok)
    }

    /// Whether `password-protected` is reported as a detection, which the
    /// engine implements itself under ClamAV's `Heuristics.Encrypted.*` names.
    pub(crate) fn reports_encrypted_as_found(&self) -> bool {
        self.for_tag("PASSWORD-PROTECTED") == PartialStatus::Found
    }

    /// Whether `limits-exceeded` is reported as a detection, which the engine
    /// implements itself under `Heuristics.Limits.Exceeded.*`.
    pub(crate) fn reports_limits_as_found(&self) -> bool {
        self.for_tag("LIMITS-EXCEEDED") == PartialStatus::Found
    }
}

impl fmt::Display for PartialAs {
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

    /// Everything in `self` that is not also in `other`, for `--no-detect`.
    pub(crate) fn without(self, other: Self) -> Self {
        let mut out = self;
        for (o, drop) in out.on.iter_mut().zip(other.on.iter()) {
            *o &= !drop;
        }
        out
    }
}

/// An encoding exav recovers a payload from before scanning it.
///
/// Distinct from a detector, which decides whether something is *reported*, and
/// from an unpacker, which opens a container the file declares itself to be.
/// A decoder finds a payload that the carrier does not announce at all: a PE
/// base64'd into a script, a long hex run in a PowerShell dropper.
///
/// On by default, unlike [`DETECTORS`], because a carrier that hides its payload
/// is the ordinary case rather than the suspicious one, and a scan that skips it
/// reports clean on a file it never really read.
pub(crate) const DECODERS: [&str; 1] = ["base64"];

/// Which decoders are switched on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Decoders {
    on: [bool; DECODERS.len()],
}

impl Default for Decoders {
    fn default() -> Self {
        Self {
            on: [true; DECODERS.len()],
        }
    }
}

impl Decoders {
    /// Parse `--decode` / `--no-decode`: `none`, `all`, or a comma-separated
    /// list of names.
    pub(crate) fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        match s {
            "none" | "" => Ok(Self::none()),
            "all" => Ok(Self::default()),
            list => {
                let mut out = Self::none();
                for item in list.split(',') {
                    let item = item.trim();
                    let idx = DECODERS
                        .iter()
                        .position(|d| d.eq_ignore_ascii_case(item))
                        .ok_or_else(|| {
                            format!(
                                "unknown decoder `{item}` (known: {}, plus `all` and `none`)",
                                DECODERS.join(", ")
                            )
                        })?;
                    out.on[idx] = true;
                }
                Ok(out)
            }
        }
    }

    /// None of them.
    pub(crate) fn none() -> Self {
        Self {
            on: [false; DECODERS.len()],
        }
    }

    /// Everything in `self` that is not also in `other`, for `--no-decode`.
    pub(crate) fn without(self, other: Self) -> Self {
        let mut out = self;
        for (o, drop) in out.on.iter_mut().zip(other.on.iter()) {
            *o &= !drop;
        }
        out
    }

    /// Base64 runs long enough to hold an executable, and base64 assets embedded
    /// in markup.
    pub(crate) fn base64(&self) -> bool {
        DECODERS
            .iter()
            .position(|d| *d == "base64")
            .map(|i| self.on[i])
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocking_is_what_you_get_without_asking() {
        let p = PartialAs::default();
        for (_, wire) in TAGS {
            assert_eq!(p.for_tag(wire), PartialStatus::Partial, "{wire}");
        }
        assert!(!p.reports_any_as_ok());
        assert_eq!(p.to_string(), "partial");
    }

    #[test]
    fn one_word_sets_every_condition() {
        let p = PartialAs::parse("ok").unwrap();
        for (_, wire) in TAGS {
            assert_eq!(p.for_tag(wire), PartialStatus::Ok, "{wire}");
        }
        assert!(p.reports_any_as_ok());
        assert_eq!(p.to_string(), "ok");
    }

    #[test]
    fn conditions_can_be_set_apart() {
        let p = PartialAs::parse("password-protected=ok, limits-exceeded=found").unwrap();
        assert_eq!(p.for_tag("PASSWORD-PROTECTED"), PartialStatus::Ok);
        assert_eq!(p.for_tag("LIMITS-EXCEEDED"), PartialStatus::Found);
        // Unnamed conditions keep the safe answer rather than inheriting one.
        assert_eq!(p.for_tag("UNSCANNABLE"), PartialStatus::Partial);
        assert!(p.reports_any_as_ok());
        assert!(p.reports_limits_as_found() && !p.reports_encrypted_as_found());
        assert_eq!(
            p.to_string(),
            "limits-exceeded=found,unscannable=partial,password-protected=ok"
        );
    }

    #[test]
    fn a_tag_the_engine_reports_but_nobody_named_still_blocks() {
        // The answer that cannot turn a verdict into a pass by accident.
        let p = PartialAs::parse("ok").unwrap();
        assert_eq!(p.for_tag("SOME-FUTURE-TAG"), PartialStatus::Partial);
    }

    #[test]
    fn misspellings_are_refused_rather_than_ignored() {
        for bad in [
            "passs",
            "password_protected=ok",
            "encrypted=ok",
            "password-protected=allow",
            "password-protected",
            "",
        ] {
            assert!(PartialAs::parse(bad).is_err(), "{bad:?} parsed");
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
            if v.category() != VerdictCategory::Partial {
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
    /// `--alert-exceeds-max` belong to `--partial-as`, because they answer
    /// "what does this verdict become", not "what should exav look for".
    /// Accepting them here would put one question under two flags.
    #[test]
    fn verdict_remapping_is_not_a_detector() {
        for not_a_detector in ["encrypted", "exceeds-max", "limits-exceeded"] {
            assert!(
                Detectors::parse(not_a_detector).is_err(),
                "{not_a_detector} belongs to --partial-as"
            );
        }
    }
}
