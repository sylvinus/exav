//! Flags measuring the same kind of thing accept the same words.
//!
//! Names and documentation were reviewed repeatedly without anyone comparing the
//! *parsers*, and the surface drifted underneath: `--max-object-bytes` took
//! `45M` while `--icap-preview-bytes`, also a count of bytes, refused `4K`; five
//! duration flags disabled themselves with `0` and refused `off` while two did
//! the exact reverse. Every one of those reads as a bug in the flag someone
//! happens to try second.
//!
//! Reading a flag's declaration cannot catch this, because each one is locally
//! reasonable. Only running the whole family against the same values does.

use std::process::Command;

fn exav() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_exav"));
    c.env("EXAV_ALLOW_NO_DB", "1");
    c
}

/// Whether the *value parser* took this value.
///
/// A flag may still be refused later for needing a listener it was not given.
/// That is a different check, and it means the value itself parsed, which is
/// what is under test.
fn parses(flag: &str, value: &str) -> bool {
    let out = exav()
        .args([flag, value, "/etc/hosts"])
        .output()
        .expect("run exav");
    !String::from_utf8_lossy(&out.stderr).contains("invalid value")
}

/// Byte-valued flags all read the same size vocabulary.
///
/// Two of these carry a plain integer default (`4096`, `65536`) and once had a
/// plain integer parser to match, so `4K` was a parse error on them and fine on
/// every other flag measured in bytes. The field's width is not something the
/// person typing can see.
#[test]
fn every_byte_flag_takes_the_same_sizes() {
    const BYTE_FLAGS: &[&str] = &[
        "--max-input-bytes",
        "--max-extracted-bytes",
        "--max-object-bytes",
        "--max-matcher-bytes",
        "--max-process-bytes",
        "--max-spill-bytes",
        "--max-total-spill-bytes",
        "--spill-threshold-bytes",
        "--build-shard-bytes",
        "--icap-preview-bytes",
        "--icap-max-header-bytes",
    ];
    for flag in BYTE_FLAGS {
        for good in ["4096", "45K", "45M", "45G", "45m", "0", "off"] {
            assert!(parses(flag, good), "{flag} must accept `{good}`");
        }
        // `M` is binary here, so `MB` would be a 4.9% lie at that suffix and a
        // 7.4% one at `G`. Refusing it is the honest answer.
        //
        // `45 M` is accepted, by the way, and on every flag alike: the numeric
        // part is trimmed on purpose. Uniformly lenient is the property this
        // test is for, not strictness for its own sake.
        for bad in ["45MB", "45MiB", "banana", ""] {
            assert!(!parses(flag, bad), "{flag} must refuse `{bad}`");
        }
    }
}

/// Duration flags all disable themselves with the same word.
///
/// `off` reaches the disabled state on every one of them. `0` additionally works
/// wherever zero is a meaningful bound, and is refused on the two that describe a
/// recurring interval, where a zero-second period is a loop rather than "never".
/// That refusal explains itself; it is the one difference in this family and it
/// is not arbitrary.
#[test]
fn every_duration_flag_disables_with_off() {
    const BOUNDS: &[&str] = &[
        "--max-scan-secs",
        "--startup-wait-secs",
        "--update-interval-secs",
        "--icap-idle-secs",
        "--icap-options-ttl-secs",
    ];
    const PERIODS: &[&str] = &["--metrics-secs", "--slow-scan-secs"];

    for flag in BOUNDS.iter().chain(PERIODS) {
        assert!(
            parses(flag, "120"),
            "{flag} must accept a number of seconds"
        );
        assert!(parses(flag, "off"), "{flag} must accept `off`");
        assert!(!parses(flag, "45M"), "{flag} is seconds, not a size");
    }
    for flag in BOUNDS {
        assert!(parses(flag, "0"), "{flag}: `0` is a bound of zero");
    }
    for flag in PERIODS {
        assert!(
            !parses(flag, "0"),
            "{flag}: a zero-second period is a loop, not `off`"
        );
    }
}

/// Counting flags take counts, and nothing that looks like a size.
///
/// The separation is what lets a reader tell the families apart at a glance: a
/// suffix means bytes. `--max-members 10K` quietly meaning ten thousand members
/// would remove that signal from the whole surface.
#[test]
fn every_counting_flag_refuses_size_suffixes() {
    const COUNTS: &[&str] = &[
        "--max-members",
        "--max-unpack-depth",
        "--max-jobs-per-worker",
        "--icap-max-requests",
        "--alert-ssns",
        "--alert-credit-cards",
    ];
    for flag in COUNTS {
        for good in ["10", "0", "10000"] {
            assert!(parses(flag, good), "{flag} must accept `{good}`");
        }
        for bad in ["10K", "10M", "off", "banana"] {
            assert!(!parses(flag, bad), "{flag} must refuse `{bad}`");
        }
    }
}

/// The size error names what is accepted, not only what was refused.
///
/// `45MB` is the likeliest wrong thing to type, and an error that says no more
/// than "invalid size" leaves the reader to guess which of `MB`, `MiB`, `mb` or
/// `45` it wanted.
#[test]
fn a_bad_size_is_told_what_to_write_instead() {
    let out = exav()
        .args(["--max-object-bytes", "45MB", "/etc/hosts"])
        .output()
        .expect("run exav");
    let said = String::from_utf8_lossy(&out.stderr);
    for expected in ["45M", "off", "binary", "MiB"] {
        assert!(
            said.contains(expected),
            "the error should mention `{expected}`: {said}"
        );
    }
}
