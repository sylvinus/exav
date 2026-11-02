#![no_main]
//! `scan_seekable` over a reader that behaves as a socket or a disk does: it
//! returns a few bytes a call, and it fails part way. Every input to the
//! scanner but a buffer in memory comes through this function, and an object
//! over `deep_analysis_max` is read through a block cache by offset instead of
//! being held, which is another set of code than `analyze`'s.
//!
//! The input is `[bits: u16 LE] [piece: u8] [fail: u8] [data]`: `bits` are
//! `options::scan_options`'s, `piece` the most bytes a read returns
//! (`1 + 37 * piece`: one byte a call is correct and slow), and `fail` where a
//! read begins to fail, as a fraction of the data in 256ths (0: never). A seed
//! is a file behind `00 00 08 00`.
//!
//! Checked, from the crate's own claims:
//!
//! * with no failure and the object held in memory, the answer is `analyze`'s;
//! * a reader that fails is an error, unless a detection was made in what was
//!   read, which a limit never outranks (invariant 1) and which `analyze` of
//!   the whole object then also finds: a scan that fails to read must not
//!   report what it did not see as clean (invariant 3);
//! * an object over `deep_analysis_max` that is read whole and found nothing
//!   is not `Clean`: the checks that parse an object whole did not run on it,
//!   and the report says so (the crate docs).
use std::io::{self, Cursor, Read, Seek, SeekFrom};

use exav_core::{Verdict, VerdictCategory, analyze, scan_seekable};
use libfuzzer_sys::fuzz_target;

#[path = "../db.rs"]
mod db;
#[path = "../options.rs"]
mod options;

struct Flaky {
    inner: Cursor<Vec<u8>>,
    piece: usize,
    fail_at: Option<u64>,
}

impl Read for Flaky {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.fail_at.is_some_and(|at| self.inner.position() >= at) {
            return Err(io::Error::other("injected read failure"));
        }
        let n = buf.len().min(self.piece);
        self.inner.read(&mut buf[..n])
    }
}

impl Seek for Flaky {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        self.inner.seek(to)
    }
}

fuzz_target!(|input: &[u8]| {
    exav_fuzz_support::panics::contained_panics();
    let [b0, b1, piece, fail, data @ ..] = input else {
        return;
    };
    let opts = options::scan_options(u16::from_le_bytes([*b0, *b1]));
    let len = data.len() as u64;
    let fail_at = (*fail != 0).then(|| len * u64::from(*fail) / 256);
    let reader = Flaky {
        inner: Cursor::new(data.to_vec()),
        piece: 1 + *piece as usize * 37,
        fail_at,
    };
    let answer = scan_seekable(db::scanner(), reader, len, &opts);

    match (fail_at, answer) {
        (None, Ok(report)) => {
            let held = len <= opts.deep_analysis_max && opts.max_scan_size.is_none_or(|m| len <= m);
            if held {
                let direct = analyze(db::scanner(), data, &opts);
                assert_eq!(
                    report.verdict, direct.verdict,
                    "a reader and a buffer got two answers"
                );
            } else if opts.max_scan_size.is_none_or(|m| len <= m) {
                assert_ne!(
                    report.verdict.category(),
                    VerdictCategory::Clean,
                    "an object read through the block cache, which skips the whole-object checks, is clean"
                );
            }
        }
        (None, Err(e)) => panic!("a reader that does not fail gave an error: {e}"),
        (Some(at), Ok(report)) => {
            // Reading stopped at `at`: only a detection can have been reached.
            if !matches!(report.verdict, Verdict::Infected { .. }) {
                panic!(
                    "a read failed at byte {at} of {len} and the scan went on to say {:?}",
                    report.verdict
                );
            }
            let whole = analyze(db::scanner(), data, &opts);
            assert_ne!(
                whole.verdict.category(),
                VerdictCategory::Clean,
                "a detection in the first {at} bytes, and the whole object is clean"
            );
        }
        (Some(_), Err(_)) => {}
    }
});
