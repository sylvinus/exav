//! A source that fails part way is reported, never read as a short file.
//!
//! The walk reads its container through a `ByteSource`, and for a network range
//! reader a failed read is an ordinary event. Taking it for end of file drops
//! every member past that point without a word.

use exav_unpack::source::BlockCache;
use exav_unpack::{walk, Budget, Format, Limits, Member};
use std::io::{self, Read, Seek, SeekFrom};

/// Seeks anywhere in `len` bytes; every read fails.
struct Unreadable {
    pos: u64,
    len: u64,
}

impl Read for Unreadable {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("link down"))
    }
}

impl Seek for Unreadable {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        self.pos = match to {
            SeekFrom::Start(p) => p,
            SeekFrom::End(d) => self.len.saturating_add_signed(d),
            SeekFrom::Current(d) => self.pos.saturating_add_signed(d),
        };
        Ok(self.pos)
    }
}

/// `data`, whose reads fail from byte `fail_at` on.
struct FailsFrom {
    data: Vec<u8>,
    pos: u64,
    fail_at: u64,
}

impl Read for FailsFrom {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.fail_at && self.pos < self.data.len() as u64 {
            return Err(io::Error::other("link down"));
        }
        let start = (self.pos as usize).min(self.data.len());
        let end = (start + buf.len())
            .min(self.data.len())
            .min(self.fail_at.max(self.pos) as usize);
        let n = end - start;
        buf[..n].copy_from_slice(&self.data[start..end]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for FailsFrom {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let len = self.data.len() as u64;
        self.pos = match to {
            SeekFrom::Start(p) => p,
            SeekFrom::End(d) => len.saturating_add_signed(d),
            SeekFrom::Current(d) => self.pos.saturating_add_signed(d),
        };
        Ok(self.pos)
    }
}

/// What a walk produced: each member's name, unsupported reason and bytes,
/// and whether anything said a read went wrong.
#[derive(PartialEq)]
struct Outcome {
    members: Vec<(String, Option<&'static str>, Vec<u8>)>,
    error: Option<String>,
}

fn outcome(fmt: Format, src: &dyn exav_unpack::source::ByteSource) -> Outcome {
    let mut members = Vec::new();
    let mut read_error = None;
    let mut visit = |m: &exav_unpack::MemberMeta, content: Option<Member<'_>>, _: &mut Budget| {
        let mut d = Vec::new();
        match content {
            Some(Member::Stream(r)) => {
                if let Err(e) = r.read_to_end(&mut d) {
                    read_error = Some(e.to_string());
                }
            }
            Some(Member::Bytes(b)) => d = b,
            None => {}
        }
        members.push((m.name.clone(), m.unsupported, d));
        None::<()>
    };
    let r = walk(fmt, src, &mut Budget::new(Limits::default()), &mut visit);
    let error = match r {
        Err(hit) => Some(hit.reason),
        Ok(_) => read_error,
    };
    Outcome { members, error }
}

fn fixtures(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            fixtures(&p, out);
        } else if !p.to_string_lossy().contains("real-malware")
            && p.metadata().is_ok_and(|m| m.len() <= 4 << 20)
        {
            out.push(p);
        }
    }
}

/// A source that fails part way through a real archive, at a tenth, half and
/// nine tenths of it: the walk yields what an intact walk yields, or says
/// something went wrong. Yielding less without a word is the failure.
#[test]
fn a_source_failing_part_way_is_reported_or_harmless() {
    let mut paths = Vec::new();
    fixtures(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures"),
        &mut paths,
    );
    paths.sort();
    let mut silent = Vec::new();
    let mut checked = 0;
    for path in paths {
        let data = std::fs::read(&path).unwrap();
        let Some(fmt) = exav_unpack::detect(&data) else {
            continue;
        };
        let intact = outcome(fmt, &BlockCache::new(io::Cursor::new(data.clone())).unwrap());
        if intact.error.is_some() || intact.members.is_empty() {
            continue;
        }
        checked += 1;
        for tenths in [1, 5, 9] {
            let fail_at = data.len() as u64 * tenths / 10;
            // Small blocks, so the blocks before the failure still read and
            // the walk gets part way.
            let src = BlockCache::with_sizes(
                FailsFrom {
                    data: data.clone(),
                    pos: 0,
                    fail_at,
                },
                512,
                64 << 20,
            )
            .unwrap();
            let failing = outcome(fmt, &src);
            let reported = failing.error.is_some()
                || failing
                    .members
                    .iter()
                    .any(|m| m.1.is_some() && !intact.members.iter().any(|i| i.0 == m.0 && i.1 == m.1));
            if failing != intact && !reported {
                silent.push(format!(
                    "{} ({fmt:?}), failing from {fail_at}: {} members, intact {}",
                    path.display(),
                    failing.members.len(),
                    intact.members.len()
                ));
            }
        }
    }
    assert!(checked > 30, "only {checked} fixtures were walked");
    assert!(
        silent.is_empty(),
        "read errors not reported:\n{}",
        silent.join("\n")
    );
}

#[test]
fn a_failing_source_is_reported_by_every_format() {
    let mut silent = Vec::new();
    for &fmt in Format::ALL {
        let mut budget = Budget::new(Limits::default());
        // A member's bytes are read by the visitor, which sees their errors.
        let mut visit = |_: &_, content: Option<Member<'_>>, _: &mut Budget| match content? {
            Member::Stream(r) => io::copy(r, &mut io::sink()).err().map(|e| e.to_string()),
            Member::Bytes(_) => None,
        };
        let src = BlockCache::new(Unreadable {
            pos: 0,
            len: 1 << 20,
        })
        .unwrap();
        match walk(fmt, &src, &mut budget, &mut visit) {
            Err(hit) if hit.reason.contains("link down") => {}
            Ok(Some(seen)) if seen.contains("link down") => {}
            other => silent.push(format!("{fmt:?}: {other:?}")),
        }
    }
    assert!(
        silent.is_empty(),
        "read errors not reported:\n{}",
        silent.join("\n")
    );
}
