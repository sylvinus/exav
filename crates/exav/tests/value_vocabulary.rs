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
/// what is under test. A flag the binary does not have fails the test rather
/// than passing it: an unknown flag is not an invalid value.
fn parses(flag: &str, value: &str) -> bool {
    let out = exav()
        .args([flag, value, "/etc/hosts"])
        .output()
        .expect("run exav");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !err.contains("unexpected argument"),
        "{flag} is not a flag: {err}"
    );
    !err.contains("invalid value")
}

/// Byte-valued flags all read the same size vocabulary.
///
/// Two of these carry a plain integer default (`4096`, `65536`) and once had a
/// plain integer parser to match, so `4K` was a parse error on them and fine on
/// every other flag measured in bytes. The field's width is not something the
/// person typing can see.
///
/// `0` and `off` are where they differ, on purpose: a limit takes both; a size
/// that is not a limit (`--spill-threshold-bytes`) takes `0` and refuses `off`;
/// `--icap-max-header-bytes` has a floor of `1K` and no `off`.
#[test]
fn every_byte_flag_takes_the_same_sizes() {
    const LIMITS: &[&str] = &[
        "--max-input-bytes",
        "--max-object-bytes",
        "--max-matcher-bytes",
        "--max-process-bytes",
        "--max-spill-bytes",
        "--max-total-spill-bytes",
        "--build-shard-bytes",
        "--icap-preview-bytes",
    ];
    const SIZES: &[&str] = &["--spill-threshold-bytes", "--icap-max-header-bytes"];
    for flag in LIMITS {
        for good in ["0", "off"] {
            assert!(parses(flag, good), "{flag} must accept `{good}`");
        }
    }
    assert!(parses("--spill-threshold-bytes", "0"));
    for flag in SIZES {
        assert!(!parses(flag, "off"), "{flag} is a size, with no `off`");
    }
    assert!(
        !parses("--icap-max-header-bytes", "0"),
        "below the 1K floor"
    );
    for flag in LIMITS.iter().chain(SIZES) {
        for good in ["4096", "45K", "45M", "45G", "45m"] {
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
/// `off` reaches the disabled state on every one that can be disabled. `0`
/// additionally works wherever zero is a meaningful bound, and is refused on the
/// ones that describe a recurring interval, where a zero-second period is a loop
/// rather than "never". `--icap-idle-secs` has neither: with no idle timeout a
/// client could hold a connection forever, and with a zero one no request
/// would get through.
#[test]
fn every_duration_flag_disables_with_off() {
    const BOUNDS: &[&str] = &[
        "--max-scan-secs",
        "--startup-wait-secs",
        "--icap-options-ttl-secs",
    ];
    const PERIODS: &[&str] = &[
        "--metrics-secs",
        "--slow-scan-secs",
        "--update-interval-secs",
    ];

    for flag in BOUNDS.iter().chain(PERIODS).chain(&["--icap-idle-secs"]) {
        assert!(
            parses(flag, "120"),
            "{flag} must accept a number of seconds"
        );
        assert!(!parses(flag, "45M"), "{flag} is seconds, not a size");
    }
    for flag in BOUNDS.iter().chain(PERIODS) {
        assert!(parses(flag, "off"), "{flag} must accept `off`");
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
    assert!(!parses("--icap-idle-secs", "off"));
    assert!(!parses("--icap-idle-secs", "0"));
}

/// Counting flags take counts, and nothing that looks like a size.
///
/// The separation is what lets a reader tell the families apart at a glance: a
/// suffix means bytes. `--max-members 10K` quietly meaning ten thousand members
/// would remove that signal from the whole surface.
///
/// A limit on a count takes `0` and `off` for no limit. The nesting depth has
/// no unlimited setting (each level costs stack), and a threshold of findings
/// at `0` would fire on every file, so those refuse both.
#[test]
fn every_counting_flag_refuses_size_suffixes() {
    const LIMITS: &[&str] = &[
        "--max-members",
        "--max-jobs-per-worker",
        "--icap-max-requests",
    ];
    const AT_LEAST_ONE: &[&str] = &["--max-unpack-depth", "--dlp-ssns", "--dlp-credit-cards"];
    for flag in LIMITS.iter().chain(AT_LEAST_ONE) {
        for good in ["10", "10000"] {
            assert!(parses(flag, good), "{flag} must accept `{good}`");
        }
        for bad in ["10K", "10M", "banana"] {
            assert!(!parses(flag, bad), "{flag} must refuse `{bad}`");
        }
    }
    for flag in LIMITS {
        for good in ["0", "off"] {
            assert!(parses(flag, good), "{flag} must accept `{good}`");
        }
    }
    for flag in AT_LEAST_ONE {
        for bad in ["0", "off"] {
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
