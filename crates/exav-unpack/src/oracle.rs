//! Test support for the differential tests against a reference decoder built
//! from its own sources (`tests/oracle/build.sh`).
//!
//! Those tests are `#[ignore]`d: a run that did not ask for them lists them as
//! ignored, never as passed. Run on request, one whose oracle is not built
//! fails instead of skipping.

use std::io::{Read, Write};
use std::process::{Command, Stdio};

/// Runs the oracle named by the environment variable `var`, with `args`, over
/// `jobs` (a limit and an input each), and returns its status byte and output
/// for each. Panics when the variable is unset or the oracle fails.
pub(crate) fn run(var: &str, args: &[&str], jobs: &[(u32, Vec<u8>)]) -> Vec<(u8, Vec<u8>)> {
    let path = std::env::var(var).unwrap_or_else(|_| {
        panic!("{var} is not set: build the oracle with tests/oracle/build.sh and set it")
    });
    let mut child = Command::new(&path)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("cannot run {path}: {e}"));
    let mut stdin = child.stdin.take().unwrap();
    let mut request = Vec::new();
    for (limit, input) in jobs {
        request.extend_from_slice(&limit.to_le_bytes());
        request.extend_from_slice(&(input.len() as u32).to_le_bytes());
        request.extend_from_slice(input);
    }
    let writer = std::thread::spawn(move || stdin.write_all(&request));
    let mut reply = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut reply)
        .unwrap();
    let wrote = writer.join().unwrap();
    let status = child.wait().unwrap();
    assert!(status.success(), "{path} failed: {status} ({wrote:?})");
    let mut out = Vec::new();
    let mut at = 0;
    while at < reply.len() {
        let n = u32::from_le_bytes(reply[at + 1..at + 5].try_into().unwrap()) as usize;
        out.push((reply[at], reply[at + 5..at + 5 + n].to_vec()));
        at += 5 + n;
    }
    assert_eq!(out.len(), jobs.len(), "{path} answered fewer inputs");
    out
}

/// With `EXAV_DEBUG_ORACLE_DUMP` set to a directory, writes a stream that differs,
/// the reference's output for it and ours, to inspect it.
pub(crate) fn dump(name: &str, n: usize, input: &[u8], reference: &[u8], ours: &[u8]) {
    if let Ok(dir) = std::env::var("EXAV_DEBUG_ORACLE_DUMP") {
        for (ext, bytes) in [("in", input), ("ref", reference), ("ours", ours)] {
            let _ = std::fs::write(format!("{dir}/{name}{n}.{ext}"), bytes);
        }
    }
}

/// A xorshift generator, so a failure repeats from its seed.
pub(crate) struct Rng(pub(crate) u64);

impl Rng {
    pub(crate) fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    pub(crate) fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }

    /// `base` damaged one way: a bit flipped, a byte or a four-byte field
    /// set (to an extreme half the time), a cut, bytes inserted or removed, a
    /// piece repeated. `hot` is the length of the header region the
    /// fields are chosen from three times in four.
    pub(crate) fn damage(&mut self, base: &[u8], hot: usize) -> Vec<u8> {
        let mut v = base.to_vec();
        if v.is_empty() {
            return v;
        }
        let at = |r: &mut Rng, len: usize| match r.below(4) {
            0 => r.below(len),
            _ => r.below(len.min(hot.max(1))),
        };
        match self.below(8) {
            0 | 1 => {
                let i = at(self, v.len());
                v[i] ^= 1 << self.below(8);
            }
            2 => {
                let i = at(self, v.len());
                v[i] = self.next() as u8;
            }
            3 => {
                let i = at(self, v.len());
                let w = [0, 1, 0x7f, 0x80, 0xff, 0xfe][self.below(6)];
                v[i] = w;
            }
            4 => {
                let i = at(self, v.len());
                let w: u32 = match self.below(3) {
                    0 => [0, 1, 0xffff, 0x10000, 0x7fff_ffff, 0x8000_0000, u32::MAX][self.below(7)],
                    1 => self.next() as u32 & 0xfffff,
                    _ => self.next() as u32,
                };
                for (k, b) in w.to_le_bytes().iter().enumerate() {
                    if let Some(x) = v.get_mut(i + k) {
                        *x = *b;
                    }
                }
            }
            5 => {
                let cut = self.below(v.len());
                v.truncate(cut);
            }
            6 => {
                let i = at(self, v.len());
                let n = 1 + self.below(8);
                match self.below(2) {
                    0 => {
                        let end = (i + n).min(v.len());
                        v.drain(i..end);
                    }
                    _ => {
                        for _ in 0..n {
                            v.insert(i, self.next() as u8);
                        }
                    }
                }
            }
            _ => {
                let i = at(self, v.len());
                let n = 1 + self.below(32);
                let piece: Vec<u8> = v[i..(i + n).min(v.len())].to_vec();
                let j = self.below(v.len());
                v.splice(j..j, piece);
            }
        }
        if !v.is_empty() && self.below(5) == 0 {
            let i = at(self, v.len());
            v[i] ^= 1 << self.below(8);
        }
        v
    }
}
