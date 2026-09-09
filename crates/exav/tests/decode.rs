//! `--decode` / `--no-decode`: recovering a payload the carrier does not
//! announce.
//!
//! An unpacker opens a container the file declares itself to be. A decoder finds
//! something the carrier says nothing about: a PE base64'd into a PowerShell
//! one-liner is, to every layer above, a text file. Signatures written against
//! the executable cannot match the encoded form, so a scan that skips the decode
//! reports `OK` on a file it never really read, which is the one answer exav is
//! built not to give.
//!
//! On by default for that reason, unlike `--detect`, and off under
//! `--clamav-compat` because stock ClamAV has no such reach and a differential
//! run would otherwise count it as a disagreement.

use std::process::Command;

#[path = "../src/tmpfile.rs"]
mod tmpfile;
use tmpfile::TempDir;

fn exav() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_exav"));
    // The built-in EICAR-only baseline; exav otherwise refuses to run with no
    // real database.
    c.env("EXAV_ALLOW_NO_DB", "1");
    c
}

/// Standard base64, written out here so the test needs no dependency the
/// published crate would otherwise carry for it.
fn b64_encode(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = u32::from_be_bytes([0, b[0], b[1], b[2]]);
        for i in 0..4 {
            if i <= c.len() {
                out.push(A[(n >> (18 - 6 * i) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A PE carrying the test string, base64'd into a script.
///
/// Three properties matter, and each was found by watching this test fail
/// without it. The payload must be a *real* PE, `MZ` plus an `e_lfanew` at 0x3c
/// pointing at `PE\0\0`, because the decoder rejects a bare `MZ` rather than
/// trial-decode every long base64 run it meets. The run must clear the decoder's
/// minimum length (~1400 characters), which is what keeps incidental runs from
/// costing anything. And the carrier has to be text, since the executable pass
/// only looks inside a text-ish buffer.
fn dropper() -> (TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = TempDir::new().unwrap();

    let mut pe = vec![0u8; 1200];
    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    pe[0x80..0x84].copy_from_slice(b"PE\0\0");
    let eicar = exav_core::unpack::eicar();
    pe[0x100..0x100 + eicar.len()].copy_from_slice(eicar);

    let b64 = b64_encode(&pe);
    assert!(
        b64.len() > 1400,
        "the run has to clear the decoder's minimum length, or this test passes \
         by never reaching the decoder: {} chars",
        b64.len()
    );

    let raw = dir.path().join("payload.exe");
    let carrier = dir.path().join("dropper.ps1");
    std::fs::write(&raw, &pe).unwrap();
    std::fs::write(
        &carrier,
        format!("$p = '{b64}'\n[Reflection.Assembly]::Load([Convert]::FromBase64String($p))\n"),
    )
    .unwrap();
    (dir, raw, carrier)
}

/// (exit code, stdout) of a scan of the carrier under `args`.
fn scan(args: &[&str], path: &std::path::Path) -> (i32, String) {
    let out = exav().args(args).arg(path).output().expect("run exav");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn a_payload_hidden_in_base64_is_found_by_default_and_only_skipped_when_asked() {
    let (_d, raw, carrier) = dropper();

    // The control. If the payload is not detected standing on its own, nothing
    // below is evidence about decoding.
    let (code, out) = scan(&[], &raw);
    assert_eq!(code, 1, "the payload itself must be detected: {out}");

    // Encoded, with decoding on: same detection, reached through the carrier.
    for args in [&[][..], &["--decode", "base64"], &["--decode", "all"]] {
        let (code, out) = scan(args, &carrier);
        assert_eq!(code, 1, "{args:?} must reach the encoded payload: {out}");
    }

    // Encoded, with decoding off: the carrier is a text file and nothing in it
    // matches. `OK` here is the honest answer to a question that was not asked.
    for args in [
        &["--no-decode", "base64"][..],
        &["--decode", "none"],
        &["--decode", "all", "--no-decode", "base64"],
        // The preset turns it off, which is the parity `--clamav-compat` exists
        // for.
        &["--clamav-compat"],
    ] {
        let (code, out) = scan(args, &carrier);
        assert_eq!(code, 0, "{args:?} must not decode: {out}");
    }

    // And the reason the flag takes a list rather than being a bare switch: an
    // explicit choice has to be able to beat the preset. Without this there is
    // no way back to full reach under `--clamav-compat`.
    let (code, out) = scan(&["--clamav-compat", "--decode", "base64"], &carrier);
    assert_eq!(
        code, 1,
        "an explicit --decode must win over the preset: {out}"
    );
}

/// A name that is not a decoder is refused, in both directions.
///
/// The list is what makes room for `hex` and `xor` later, and it is worth
/// nothing if a typo quietly selects nothing: `--no-decode base64x` would read
/// as "decoding is off" and leave it on.
#[test]
fn a_misspelled_decoder_is_refused_rather_than_ignored() {
    for flag in ["--decode", "--no-decode"] {
        let out = exav()
            .args([flag, "b64", "/dev/null"])
            .output()
            .expect("run exav");
        let said = String::from_utf8_lossy(&out.stderr);
        assert!(
            said.contains("unknown decoder `b64`"),
            "{flag} b64 must name the mistake: {said}"
        );
        assert!(said.contains("base64"), "and list what is known: {said}");
    }
}
