//! A decoder that dies must never look like a file that is clean.
//!
//! Two of the three ways a decoder can fail are outside Rust's reach.
//! `catch_unwind` catches unwinding and nothing else, so a panic is turned into
//! a reported limit — but a failed allocation aborts and an exhausted stack
//! faults, and both end the process where it stands. Nothing inside that process
//! gets to report anything.
//!
//! What a caller can still observe is the exit status, and that is the whole
//! contract here: a crash must not exit 0. A pipeline reading `$?` cannot tell a
//! successful scan of a harmless file from a scanner that died on a crafted one,
//! and treating the second as the first is exactly the outcome an archive built
//! this way is buying.
//!
//! Needs `--features testing-faults`, which is what lets a scanned file ask a
//! decoder to fail. Without it these skip rather than passing for free.

use std::process::Command;

#[path = "../src/tmpfile.rs"]
mod tmpfile;
use tmpfile::TempDir;

fn exav() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_exav"));
    // Not about what the signatures say — about whether the run survives at all.
    c.env("EXAV_ALLOW_NO_DB", "1");
    c
}

/// A stored ZIP holding one member whose CONTENT is `marker`.
///
/// A bare marker file would be recognised as no format at all and never reach a
/// decoder. Carrying it inside a well-formed container is what makes this a test
/// of the scan path rather than of the detector.
fn zip_containing(marker: &[u8]) -> Vec<u8> {
    let name = b"payload.bin";
    let crc = crc32(marker);
    let mut out = Vec::new();

    let mut local = Vec::new();
    local.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    local.extend_from_slice(&crc.to_le_bytes());
    local.extend_from_slice(&(marker.len() as u32).to_le_bytes());
    local.extend_from_slice(&(marker.len() as u32).to_le_bytes());
    local.extend_from_slice(&(name.len() as u16).to_le_bytes());
    local.extend_from_slice(&0u16.to_le_bytes());
    local.extend_from_slice(name);
    local.extend_from_slice(marker);
    let local_offset = out.len() as u32;
    out.extend_from_slice(&local);

    let cd_offset = out.len() as u32;
    let mut cd = Vec::new();
    cd.extend_from_slice(&[0x50, 0x4b, 0x01, 0x02, 20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    cd.extend_from_slice(&crc.to_le_bytes());
    cd.extend_from_slice(&(marker.len() as u32).to_le_bytes());
    cd.extend_from_slice(&(marker.len() as u32).to_le_bytes());
    cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
    cd.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    cd.extend_from_slice(&local_offset.to_le_bytes());
    cd.extend_from_slice(name);
    let cd_len = cd.len() as u32;
    out.extend_from_slice(&cd);

    out.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0, 1, 0, 1, 0]);
    out.extend_from_slice(&cd_len.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in bytes {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & (0u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}

/// Scan a container carrying `marker` and report what the process did.
fn scan_with(marker: &[u8]) -> (Option<i32>, String) {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("crafted.zip");
    std::fs::write(&path, zip_containing(marker)).expect("write");
    let out = exav().arg(&path).output().expect("run exav");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.code(), text)
}

/// Whether the BINARY under test can be made to fail on demand.
///
/// Not `cfg!(feature = "testing-faults")`: that asks whether this test crate was
/// compiled with the flag, and the thing being tested is a separate process. The
/// two can disagree — the feature has to travel `exav → exav-core →
/// exav-unpack` to reach a decoder, and if it does not arrive, the flag is on
/// here and the fault is absent there. Asking the binary itself is the only
/// question worth asking.
///
/// The probe uses the abort marker because its answer is unambiguous: with the
/// fault compiled in the process dies, and without it the container scans like
/// any other.
fn faults_available() -> bool {
    let (code, _) = scan_with(b"__exav_abort__");
    code != Some(0)
}

/// Skip when the whole build lacks the feature; fail when only the binary does.
/// A test crate carrying the flag while the binary scans the probe clean means
/// the feature no longer travels to a decoder the scan path uses — the exact
/// breakage that would otherwise turn both tests into silent no-ops.
fn faults_available_or_skip() -> bool {
    if faults_available() {
        return true;
    }
    if cfg!(feature = "testing-faults") {
        panic!(
            "built with testing-faults, yet the binary scanned the abort probe \
             clean: the fault hook is not reachable from the scan path"
        );
    }
    false
}

/// A panic IS containable, so this one must come back as a normal run that
/// reports the file rather than as a dead process.
#[test]
fn a_decoder_panic_is_reported_and_the_scanner_survives() {
    if !faults_available_or_skip() {
        return;
    }
    let (code, text) = scan_with(b"__exav_panic__");
    assert!(
        code.is_some(),
        "the scanner died on a panic `catch_unwind` should have contained: {text}"
    );
    assert_ne!(
        code,
        Some(0),
        "a contained panic was reported as a clean scan: {text}"
    );
}

/// An abort and an exhausted stack are NOT containable. The process ends, and
/// the only thing left to be right about is that it did not end successfully.
#[test]
fn an_uncontainable_crash_never_exits_zero() {
    if !faults_available_or_skip() {
        return;
    }
    for marker in [&b"__exav_abort__"[..], &b"__exav_stack__"[..]] {
        let (code, text) = scan_with(marker);
        // `None` is death by signal, which is a failure a caller can see.
        // `Some(0)` is the one answer that must never happen: it tells a
        // pipeline the file was scanned and found clean.
        assert_ne!(
            code,
            Some(0),
            "a crash on {} exited 0, which reads as a clean scan: {text}",
            String::from_utf8_lossy(marker)
        );
    }
}
