//! CHM (Microsoft Compiled HTML Help) detection and extraction tests.
//!
//! * `benign-lzx.chm` is a **committed** fixture: a small, original CC0 /
//!   public-domain help page compiled to a genuine LZX-compressed CHM (built
//!   with `chmcmd`; see `tests/fixtures/chm/README.md`). It carries no payload
//!   and is the always-on oracle for the **LZX decode path**, the one piece of
//!   coverage that can't be synthesised (exav ships an LZX *decoder*, not an
//!   encoder).
//! * The `real-malware-*.chm` samples are real malware and are therefore
//!   **gitignored, not committed** (sha256 provenance in that dir's README).
//!   The tests read them at runtime and **skip when absent** (a fresh clone /
//!   CI), adding extra real-world hostile-input robustness for local runs.
//! * The walk tests at the end build CHM files whose LZX stream is made of
//!   "uncompressed" blocks, which the decoder reads like any other and which
//!   need no encoder. They check what the reader does with the frames, the
//!   reset intervals, the order of the files and the source it reads from.

use exav_unpack::source::BlockCache;
use exav_unpack::{Budget, ByteSource, Format, LimitHit, Limits, Member, detect, extract, walk};
use std::borrow::Cow;
use std::cell::Cell;
use std::io::Cursor;

/// The committed, benign LZX oracle. Must always be present.
const BENIGN_LZX: &str = "benign-lzx.chm";

/// Real-malware samples (gitignored; tests skip them when absent).
const REAL_SAMPLES: &[&str] = &["real-malware-lzx-1.chm", "real-malware-lzx-2.chm"];

fn read_fixture(name: &str) -> Option<Vec<u8>> {
    if REAL_SAMPLES.contains(&name) {
        return super::real_sample(&format!("chm/{name}"));
    }
    let p = format!("{}/tests/fixtures/chm/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&p).ok()
}

/// Always-on: the committed benign CHM is detected, and its LZX-compressed HTML
/// topic decodes byte-for-byte (proving the ITSF/ITSP + ResetTable + LZX path,
/// not just the raw directory). This is the real decode-correctness oracle.
#[test]
fn benign_lzx_detects_and_decodes() {
    let data = read_fixture(BENIGN_LZX).expect("benign-lzx.chm must be committed");
    assert_eq!(detect(&data), Some(Format::Chm));

    let mut budget = Budget::new(Limits::default());
    let entries = extract(Format::Chm, &data, &mut budget).expect("extract");
    let joined: Vec<u8> = entries
        .iter()
        .flat_map(|e| e.data.iter().copied())
        .collect();
    // The marker lives inside the LZX-compressed content section, so finding it
    // proves the LZX decompressor reconstructed the topic.
    assert!(
        joined.windows(11).any(|w| w == b"EXAV-LZX-OK"),
        "LZX-decoded marker not recovered"
    );
    assert!(
        joined.windows(5).any(|w| w.eq_ignore_ascii_case(b"<html")),
        "no decompressed HTML markup found"
    );
}

/// `multi-frame-lzx.chm` resets its LZX stream every two 32 KiB frames, and
/// `b.html` runs from the first frame into the second, which only decodes
/// with the state the first left. Each page comes out as `chmcmd` was given it.
#[test]
fn every_frame_of_a_reset_interval_decodes() {
    let data = read_fixture("multi-frame-lzx.chm").expect("multi-frame-lzx.chm must be committed");
    let mut budget = Budget::new(Limits::default());
    let entries = extract(Format::Chm, &data, &mut budget).expect("extract");
    for name in ["a", "b", "c"] {
        let mut page = String::from("<html><body>\n");
        for i in 0..2000u32 {
            page += &format!("<p>{name} {}</p>\n", i * 7919 % 10007);
        }
        page += "</body></html>\n";
        let path = format!("/{name}.html");
        let e = entries
            .iter()
            .find(|e| e.name == path)
            .unwrap_or_else(|| panic!("{path} missing"));
        assert!(e.unsupported.is_none(), "{path}: {:?}", e.unsupported);
        assert!(e.data == page.as_bytes(), "{path} differs from its source");
    }
}

/// The same file with its second frame out of reach: its reset-table entry
/// points past the compressed stream. `a.html` lies in the first frame alone
/// and still comes out whole; `b.html` and `c.html` cross the lost frame, so
/// each comes out as its source or is reported, never as a page with a hole.
#[test]
fn a_page_over_a_frame_that_fails_is_reported() {
    let mut data =
        read_fixture("multi-frame-lzx.chm").expect("multi-frame-lzx.chm must be committed");
    // The reset table: version 2, then the entry count, entry size and header
    // length, and the frame offsets from byte 0x28.
    let rt = data
        .windows(16)
        .position(|w| w[..4] == 2u32.to_le_bytes() && w[8..] == [8, 0, 0, 0, 0x28, 0, 0, 0])
        .expect("reset table");
    data[rt + 0x28 + 8..rt + 0x28 + 16].copy_from_slice(&u64::MAX.to_le_bytes());
    let mut budget = Budget::new(Limits::default());
    let entries = extract(Format::Chm, &data, &mut budget).expect("extract");
    let mut reported = 0;
    for name in ["a", "b", "c"] {
        let mut page = String::from("<html><body>\n");
        for i in 0..2000u32 {
            page += &format!("<p>{name} {}</p>\n", i * 7919 % 10007);
        }
        page += "</body></html>\n";
        let path = format!("/{name}.html");
        let e = entries
            .iter()
            .find(|e| e.name == path)
            .unwrap_or_else(|| panic!("{path} missing"));
        if e.unsupported.is_some() {
            reported += 1;
        } else {
            assert!(
                e.data == page.as_bytes(),
                "{path} differs from its source unreported"
            );
        }
    }
    let a = entries.iter().find(|e| e.name == "/a.html").unwrap();
    assert!(a.unsupported.is_none(), "a.html needs only the first frame");
    assert!(reported > 0, "the lost frame went unreported");
}

/// The benign CHM, and any locally-present real samples, extract into at least
/// one member and never panic. (Real samples add real-world-input robustness.)
#[test]
fn extracts_members_without_panicking() {
    let mut names: Vec<&str> = vec![BENIGN_LZX];
    names.extend_from_slice(REAL_SAMPLES);
    for name in names {
        let Some(data) = read_fixture(name) else {
            continue;
        };
        let mut budget = Budget::new(Limits::default());
        let entries =
            extract(Format::Chm, &data, &mut budget).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(!entries.is_empty(), "{name}: expected >=1 member, got none");
        // At least one member carries decoded bytes OR is flagged unsupported,
        // never a silent empty-but-clean member set.
        let progress = entries
            .iter()
            .any(|e| !e.data.is_empty() || e.unsupported.is_some());
        assert!(progress, "{name}: no decoded or unsupported members");
    }
}

/// A CHM cut to its first 64 bytes (directory gone) has files nobody listed:
/// it must be reported, never panic and never come back as an empty archive.
/// Exercised on the benign fixture plus any local real samples.
#[test]
fn truncated_head_is_reported() {
    let mut names: Vec<&str> = vec![BENIGN_LZX];
    names.extend_from_slice(REAL_SAMPLES);
    for name in names {
        let Some(data) = read_fixture(name) else {
            continue;
        };
        let head = &data[..64.min(data.len())];
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Chm, &head, &mut budget).unwrap();
        assert_eq!(entries.len(), 1, "{name}: {entries:?}");
        assert!(
            entries[0].unsupported.is_some(),
            "{name}: a truncated head is a clean archive"
        );
    }
}

#[test]
fn random_bytes_after_itsf_do_not_panic() {
    let mut blob = Vec::new();
    blob.extend_from_slice(b"ITSF");
    for i in 0..8192u32 {
        blob.push((i.wrapping_mul(2654435761) >> 11) as u8);
    }
    let mut budget = Budget::new(Limits::default());
    // Must not panic; the header is no valid one, which is reported.
    let entries = extract(Format::Chm, &blob, &mut budget).unwrap();
    assert!(!entries.is_empty() && entries.iter().all(|e| e.unsupported.is_some()));
}

// ---- walking a CHM from a source -------------------------------------------------

/// A member as a walk gave it.
#[derive(Debug)]
struct Got {
    name: String,
    data: Vec<u8>,
    /// What stopped the read of its stream, if something did.
    err: Option<String>,
    unsupported: Option<&'static str>,
    range: Option<(u64, u64)>,
    streamed: bool,
}

fn collect(src: &dyn ByteSource, limits: Limits) -> (Vec<Got>, Result<(), LimitHit>) {
    let mut budget = Budget::new(limits);
    let mut out = Vec::new();
    let end = walk(Format::Chm, src, &mut budget, &mut |meta, content, _| {
        let mut g = Got {
            name: meta.name.clone(),
            data: Vec::new(),
            err: None,
            unsupported: meta.unsupported,
            range: meta.range,
            streamed: false,
        };
        match content {
            Some(Member::Stream(r)) => {
                g.streamed = true;
                if let Err(e) = r.read_to_end(&mut g.data) {
                    g.err = Some(e.to_string());
                }
            }
            Some(Member::Bytes(b)) => g.data = b,
            #[allow(unreachable_patterns)]
            Some(_) => panic!("{}: an unexpected kind of member", meta.name),
            None => {}
        }
        out.push(g);
        None::<()>
    });
    (out, end.map(|_| ()))
}

fn limits_with_buffer(bytes: u64) -> Limits {
    let mut l = Limits::default();
    l.max_buffer_bytes = bytes;
    l
}

fn by_name<'a>(got: &'a [Got], name: &str) -> &'a Got {
    got.iter().find(|g| g.name == name).unwrap_or_else(|| {
        panic!(
            "no member {name}: {:?}",
            got.iter().map(|g| &g.name).collect::<Vec<_>>()
        )
    })
}

/// A source that counts the bytes it hands out.
struct Counted<'a> {
    data: &'a [u8],
    read: Cell<u64>,
}

impl ByteSource for Counted<'_> {
    fn len(&self) -> usize {
        self.data.len()
    }

    fn window(&self, off: usize, len: usize) -> Cow<'_, [u8]> {
        let w = <[u8] as ByteSource>::window(self.data, off, len);
        self.read.set(self.read.get() + w.len() as u64);
        w
    }

    fn identity(&self) -> (usize, usize) {
        (self as *const Self as usize, self.data.len())
    }
}

/// The LZX fixtures, a file larger than the buffer limit and read through a
/// cache that holds a few blocks: every member comes out as it does from
/// memory, the compressed ones decoded as they are read.
#[test]
fn a_chm_over_the_buffer_limit_is_read_from_its_source() {
    for name in [BENIGN_LZX, "multi-frame-lzx.chm"] {
        let data = read_fixture(name).unwrap();
        let mut budget = Budget::new(Limits::default());
        let want = extract(Format::Chm, &data, &mut budget).unwrap();

        let cache = BlockCache::with_sizes(Cursor::new(data.clone()), 256, 1024).unwrap();
        let (got, end) = collect(&cache, limits_with_buffer(4096));
        end.unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(
            data.len() > 4096,
            "{name} must be over the limit for this to test it"
        );
        assert_eq!(got.len(), want.len(), "{name}");
        for w in &want {
            let g = by_name(&got, &w.name);
            assert!(g.err.is_none() && g.unsupported.is_none(), "{name}: {g:?}");
            assert!(g.data == w.data, "{name}: {} differs", w.name);
        }
    }
    let data = read_fixture(BENIGN_LZX).unwrap();
    let cache = BlockCache::with_sizes(Cursor::new(data), 256, 1024).unwrap();
    let (got, _) = collect(&cache, limits_with_buffer(4096));
    assert!(
        got.iter()
            .any(|g| g.data.windows(11).any(|w| w == b"EXAV-LZX-OK")),
        "the marker in the compressed topic was not found"
    );
}

/// CHM files built here, their LZX stream a run of "uncompressed" blocks.
mod synth {
    pub const FRAME: usize = 0x8000;

    fn encint(mut v: u64) -> Vec<u8> {
        let mut out = vec![(v & 0x7f) as u8];
        v >>= 7;
        while v != 0 {
            out.push((v & 0x7f) as u8 | 0x80);
            v >>= 7;
        }
        out.reverse();
        out
    }

    /// Frame `i` of the decoded stream: text that names its frame, so a
    /// frame read from the wrong place shows.
    pub fn frame_text(i: usize) -> Vec<u8> {
        format!("frame {i:08} abcdefghijklmnopqrstuvwxyz0123456789 ")
            .into_bytes()
            .into_iter()
            .cycle()
            .take(FRAME)
            .collect()
    }

    /// The decoded stream of `frames` frames.
    pub fn stream(frames: usize) -> Vec<u8> {
        (0..frames).flat_map(frame_text).collect()
    }

    /// One frame as an LZX block of the "uncompressed" type. The first frame
    /// of a reset interval opens with the E8 bit. A `damaged` frame is cut in
    /// half: its block says it is a frame long and the decoder runs out of
    /// data in it.
    fn raw_frame(first: bool, damaged: bool, data: &[u8]) -> Vec<u8> {
        let (w0, w1): (u16, u16) = if first {
            (0x3000 | (FRAME >> 12) as u16, ((FRAME & 0xfff) << 4) as u16)
        } else {
            (0x6000 | (FRAME >> 11) as u16, ((FRAME & 0x7ff) << 5) as u16)
        };
        let mut out = Vec::new();
        out.extend_from_slice(&w0.to_le_bytes());
        out.extend_from_slice(&w1.to_le_bytes());
        for r in [1u32; 3] {
            out.extend_from_slice(&r.to_le_bytes());
        }
        out.extend_from_slice(data);
        if damaged {
            out.truncate(16 + data.len() / 2);
        }
        out
    }

    pub enum File<'a> {
        /// A file of section 0.
        Stored(&'a str, Vec<u8>),
        /// A range of the decoded stream: name, offset, length.
        Packed(&'a str, u64, u64),
    }

    pub struct Spec<'a> {
        pub frames: usize,
        /// Frames in a reset interval.
        pub interval: usize,
        /// Frames whose block is damaged.
        pub damaged: Vec<usize>,
        /// In the order the directory lists them.
        pub files: Vec<File<'a>>,
    }

    fn u32s(v: &[u32]) -> Vec<u8> {
        v.iter().flat_map(|x| x.to_le_bytes()).collect()
    }

    impl Spec<'_> {
        pub fn build(&self) -> Vec<u8> {
            let mut content = Vec::new();
            let mut offsets = Vec::new();
            for f in 0..self.frames {
                offsets.push(content.len() as u64);
                content.extend(raw_frame(
                    f % self.interval == 0,
                    self.damaged.contains(&f),
                    &frame_text(f),
                ));
            }
            let uncomp = (self.frames * FRAME) as u64;
            // ControlData: length in dwords, "LZXC", version 2, reset interval
            // and window in frames, cache.
            let control = u32s(&[6, 0x4358_5A4C, 2, self.interval as u32, 2, 2, 0]);
            let mut reset = u32s(&[2, self.frames as u32, 8, 0x28]);
            for v in [uncomp, content.len() as u64, FRAME as u64] {
                reset.extend_from_slice(&v.to_le_bytes());
            }
            for o in &offsets {
                reset.extend_from_slice(&o.to_le_bytes());
            }

            let mut sec0: Vec<u8> = Vec::new();
            let mut entries: Vec<(String, u64, u64, u64)> = Vec::new();
            let put = |sec0: &mut Vec<u8>, name: &str, blob: &[u8]| {
                let e = (name.to_string(), 0, sec0.len() as u64, blob.len() as u64);
                sec0.extend_from_slice(blob);
                e
            };
            for f in &self.files {
                match f {
                    File::Stored(name, blob) => entries.push(put(&mut sec0, name, blob)),
                    File::Packed(name, off, len) => {
                        entries.push((name.to_string(), 1, *off, *len));
                    }
                }
            }
            let prefix = "::DataSpace/Storage/MSCompressed/";
            let rt = format!(
                "{prefix}Transform/{{7FC28940-9D31-11D0-9B27-00A0C91E9C7C}}/InstanceData/ResetTable"
            );
            entries.push(put(&mut sec0, &format!("{prefix}ControlData"), &control));
            entries.push(put(&mut sec0, &rt, &reset));
            entries.push(put(&mut sec0, &format!("{prefix}Content"), &content));

            let chunk_size = 0x1000usize;
            let mut chunks: Vec<(Vec<u8>, u16)> = vec![(Vec::new(), 0)];
            for (name, sec, off, len) in &entries {
                let mut e = encint(name.len() as u64);
                e.extend_from_slice(name.as_bytes());
                e.extend(encint(*sec));
                e.extend(encint(*off));
                e.extend(encint(*len));
                if 0x14 + chunks.last().unwrap().0.len() + e.len() + 2 > chunk_size {
                    chunks.push((Vec::new(), 0));
                }
                let last = chunks.last_mut().unwrap();
                last.0.extend(e);
                last.1 += 1;
            }
            let mut dir = Vec::new();
            for (i, (body, n)) in chunks.iter().enumerate() {
                let mut c = b"PMGL".to_vec();
                c.extend(u32s(&[(chunk_size - 0x14 - body.len()) as u32, 0]));
                c.extend_from_slice(&(i as i32 - 1).to_le_bytes());
                let next = if i + 1 < chunks.len() {
                    i as i32 + 1
                } else {
                    -1
                };
                c.extend_from_slice(&next.to_le_bytes());
                c.extend_from_slice(body);
                c.resize(chunk_size - 2, 0);
                c.extend_from_slice(&n.to_le_bytes());
                dir.extend(c);
            }
            let mut itsp = b"ITSP".to_vec();
            itsp.extend(u32s(&[1, 0x54, 10, chunk_size as u32, 2, 1]));
            itsp.extend_from_slice(&(-1i32).to_le_bytes());
            itsp.extend(u32s(&[0, chunks.len() as u32 - 1]));
            itsp.extend_from_slice(&(-1i32).to_le_bytes());
            itsp.extend(u32s(&[chunks.len() as u32, 0x409]));
            itsp.resize(0x54, 0);
            itsp.extend(dir);

            let hs0_len = 0x18u64;
            let hs1_at = 0x60 + hs0_len;
            let sec0_at = hs1_at + itsp.len() as u64;
            let mut out = b"ITSF".to_vec();
            out.extend(u32s(&[3, 0x60, 1, 0, 0x409]));
            out.resize(0x38, 0);
            for v in [0x60, hs0_len, hs1_at, itsp.len() as u64, sec0_at] {
                out.extend_from_slice(&v.to_le_bytes());
            }
            out.extend(u32s(&[0x1fe, 0]));
            out.extend_from_slice(&(sec0_at + sec0.len() as u64).to_le_bytes());
            out.extend(u32s(&[0, 0]));
            out.extend(itsp);
            out.extend(sec0);
            out
        }
    }
}
use synth::{FRAME, File, Spec};

/// `[offset, offset + len)` of the decoded stream.
fn expected(offset: u64, len: u64) -> Vec<u8> {
    let frames = (offset + len).div_ceil(FRAME as u64) as usize;
    synth::stream(frames)[offset as usize..(offset + len) as usize].to_vec()
}

/// A file of section 1 comes out as the stream it was cut from, whatever the
/// order the directory lists the files in, and whether they lie in one reset
/// interval or in several.
#[test]
fn files_of_the_stream_come_out_whole_in_any_listing_order() {
    let f = FRAME as u64;
    for interval in [1usize, 2, 3, 8] {
        let spec = Spec {
            frames: 8,
            interval,
            damaged: vec![],
            files: vec![
                File::Packed("/c", 5 * f + 17, 2 * f),
                File::Packed("/a", 10, 100),
                File::Packed("/d", 7 * f, f),
                File::Packed("/b", f - 50, 100),
                File::Packed("/e", 0, 8 * f),
            ],
        };
        let blob = spec.build();
        let cache = BlockCache::with_sizes(Cursor::new(blob), 512, 4096).unwrap();
        let (got, end) = collect(&cache, Limits::default());
        end.unwrap();
        assert_eq!(got.len(), 5, "interval {interval}");
        for (name, off, len) in [
            ("/a", 10, 100),
            ("/b", f - 50, 100),
            ("/c", 5 * f + 17, 2 * f),
            ("/d", 7 * f, f),
            ("/e", 0, 8 * f),
        ] {
            let g = by_name(&got, name);
            assert!(g.err.is_none(), "interval {interval}, {name}: {:?}", g.err);
            assert!(
                g.data == expected(off, len),
                "interval {interval}: {name} differs"
            );
        }
    }
}

/// Files are decoded front to back: with the whole stream one reset interval
/// and the directory listing them last first, each is still decoded once.
/// Taken in the order of the directory, each would be decoded from the start
/// of the interval and the stream read over and over.
#[test]
fn the_stream_is_decoded_once_whatever_the_listing_order() {
    let frames = 64;
    let f = FRAME as u64;
    let files = (0..16u64)
        .rev()
        .map(|k| (format!("/m{k:02}"), k * 4 * f, 4 * f))
        .collect::<Vec<_>>();
    let spec = Spec {
        frames,
        interval: frames,
        damaged: vec![],
        files: files
            .iter()
            .map(|(n, o, l)| File::Packed(n, *o, *l))
            .collect(),
    };
    let blob = spec.build();
    let src = Counted {
        data: &blob,
        read: Cell::new(0),
    };
    let (got, end) = collect(&src, Limits::default());
    end.unwrap();
    assert_eq!(got.len(), 16);
    for (name, off, len) in &files {
        let g = by_name(&got, name);
        assert!(g.err.is_none() && g.data == expected(*off, *len), "{name}");
    }
    // The packed stream is most of the file; each byte of it once, with the
    // directory and the tables read besides.
    assert!(
        src.read.get() < 2 * blob.len() as u64,
        "{} bytes read of a {}-byte file",
        src.read.get(),
        blob.len()
    );
}

/// A file behind the decoder (two files that share bytes) makes it restart at
/// the start of its reset interval, and both come out whole.
#[test]
fn a_file_that_starts_behind_the_decoder_restarts_it() {
    let f = FRAME as u64;
    let spec = Spec {
        frames: 8,
        interval: 8,
        damaged: vec![],
        files: vec![
            File::Packed("/long", 0, 6 * f),
            File::Packed("/inside", f + 5, 2 * f),
        ],
    };
    let blob = spec.build();
    let (got, end) = collect(&blob, Limits::default());
    end.unwrap();
    for (name, off, len) in [("/long", 0, 6 * f), ("/inside", f + 5, 2 * f)] {
        let g = by_name(&got, name);
        assert!(g.err.is_none(), "{name}: {:?}", g.err);
        assert!(g.data == expected(off, len), "{name} differs");
    }
}

/// What the decoder runs through without handing over (the frames of a reset
/// interval before a file) is charged to the scan budget: a table cannot make
/// the work unbounded by naming a file deep in a long interval.
#[test]
fn frames_run_through_to_reach_a_file_are_charged_to_the_scan_budget() {
    let f = FRAME as u64;
    let spec = Spec {
        frames: 300,
        interval: 300,
        damaged: vec![],
        files: vec![File::Packed("/deep", 250 * f, 100)],
    };
    let blob = spec.build();
    let (got, end) = collect(&blob, Limits::default());
    end.unwrap();
    assert!(got[0].err.is_none() && got[0].data == expected(250 * f, 100));

    // 250 frames are 8 MB: past a 4 MiB scan budget, refused before decoding.
    let mut limits = Limits::default();
    limits.max_scanned_bytes = 4 * 1024 * 1024;
    let (_, end) = collect(&blob, limits);
    let hit = end.expect_err("the frames before the file are not charged");
    assert!(!hit.is_corrupt(), "{hit}");
}

/// A damaged frame is reported where it is read, the bytes before it kept;
/// the rest of its reset interval cannot be had, and the next interval is
/// read as if nothing had happened.
#[test]
fn a_damaged_frame_is_reported_and_the_next_interval_is_read() {
    let f = FRAME as u64;
    let spec = Spec {
        frames: 6,
        interval: 2,
        damaged: vec![3],
        files: vec![
            File::Packed("/before", 10, 100),
            File::Packed("/across", 2 * f + 100, f + 100),
            File::Packed("/after-the-damage", 3 * f + 10, 100),
            File::Packed("/next-interval", 4 * f + 7, f + 300),
        ],
    };
    let blob = spec.build();
    let (got, end) = collect(&blob, Limits::default());
    end.unwrap();

    let g = by_name(&got, "/before");
    assert!(g.err.is_none() && g.data == expected(10, 100));
    let g = by_name(&got, "/next-interval");
    assert!(g.err.is_none(), "{:?}", g.err);
    assert!(g.data == expected(4 * f + 7, f + 300));

    // The part of /across in the good frame is delivered, then the error.
    let g = by_name(&got, "/across");
    assert!(g.err.is_some(), "a damaged frame was passed over");
    assert!(g.data == expected(2 * f + 100, f - 100), "{}", g.data.len());
    let g = by_name(&got, "/after-the-damage");
    assert!(g.err.is_some() && g.data.is_empty());
}

/// Once a frame of a reset interval has failed, the files after it in that
/// interval fail at once: the decoder is not run through the frames before
/// them again for each. In a long interval that would cost the scan budget
/// of the whole walk, and it would be run again on a state a failure left.
#[test]
fn files_after_a_damaged_frame_do_not_decode_the_interval_again() {
    let f = FRAME as u64;
    let mut files = vec![File::Packed("/before", 5 * f, 100)];
    let names: Vec<String> = (50..90).map(|k| format!("/after-{k}")).collect();
    for (name, k) in names.iter().zip(50u64..) {
        files.push(File::Packed(name, k * f, 100));
    }
    let spec = Spec {
        frames: 120,
        interval: 120,
        damaged: vec![10],
        files,
    };
    let blob = spec.build();
    // The 40 files after the damage, each 40 to 80 frames in, would cost
    // 80 MB if the decoder were run through the frames before each.
    let mut limits = Limits::default();
    limits.max_scanned_bytes = 40 * 1024 * 1024;
    let (got, end) = collect(&blob, limits);
    end.unwrap();
    assert!(by_name(&got, "/before").err.is_none());
    for name in &names {
        let g = by_name(&got, name);
        assert!(g.err.is_some() && g.data.is_empty(), "{name}: {g:?}");
    }
}

/// A file of section 0 is a range of the source, handed over as it lies, and
/// the range says where. Past the end of the source it is cut and reported.
#[test]
fn a_stored_file_is_a_range_of_the_source() {
    let body: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
    let spec = Spec {
        frames: 1,
        interval: 1,
        damaged: vec![],
        files: vec![
            File::Stored("/first.bin", b"first file".to_vec()),
            File::Stored("/second.bin", body.clone()),
        ],
    };
    let blob = spec.build();
    let (got, end) = collect(&blob, Limits::default());
    end.unwrap();
    let g = by_name(&got, "/second.bin");
    assert!(g.data == body && g.err.is_none() && g.unsupported.is_none());
    let (off, len) = g.range.expect("a stored file names its range");
    assert_eq!(len, 5000);
    assert!(blob[off as usize..(off + len) as usize] == body[..]);
    assert!(g.streamed);

    // Cut in the middle of it.
    let cut = &blob[..off as usize + 1200];
    let (got, end) = collect(&cut, Limits::default());
    end.unwrap();
    let g = by_name(&got, "/second.bin");
    assert!(
        g.data == body[..1200],
        "the part that is there is handed over"
    );
    assert!(g.unsupported.is_some(), "a cut file is not reported");
    assert_eq!(g.range, Some((off, 5000)));
}

/// A listing past `max_members` is a limit of that name, after the files
/// before it have been handed over.
#[test]
fn a_listing_past_the_member_limit_is_a_limit() {
    let files = (0..300u32)
        .map(|i| File::Stored("/f", format!("file {i}").into_bytes()))
        .collect();
    let spec = Spec {
        frames: 1,
        interval: 1,
        damaged: vec![],
        files,
    };
    let blob = spec.build();
    let mut limits = Limits::default();
    limits.max_members = 50;
    let (got, end) = collect(&blob, limits);
    assert_eq!(got.len(), 50);
    let hit = end.expect_err("300 files under a limit of 50");
    assert!(!hit.is_corrupt(), "{hit}");
}

/// A file named in the listing and out of what the tables describe is
/// reported: past the decoded length, or with a reset table that declares more
/// entries than the file holds.
#[test]
fn files_the_tables_do_not_reach_are_reported() {
    let f = FRAME as u64;
    let spec = Spec {
        frames: 2,
        interval: 2,
        damaged: vec![],
        files: vec![
            File::Packed("/ok", 0, 100),
            File::Packed("/past-the-end", 2 * f - 10, 100),
            File::Packed("/far", 1 << 56, 100),
        ],
    };
    let blob = spec.build();
    let (got, end) = collect(&blob, Limits::default());
    end.unwrap();
    assert!(by_name(&got, "/ok").unsupported.is_none());
    for n in ["/past-the-end", "/far"] {
        let g = by_name(&got, n);
        assert!(g.unsupported.is_some() && g.data.is_empty(), "{n}: {g:?}");
    }

    // The reset table declares u32::MAX entries.
    let mut bad = blob.clone();
    let rt = bad
        .windows(12)
        .position(|w| w[..8] == [2, 0, 0, 0, 2, 0, 0, 0] && w[8..] == [8, 0, 0, 0])
        .expect("reset table");
    bad[rt + 4..rt + 8].copy_from_slice(&u32::MAX.to_le_bytes());
    let (got, end) = collect(&bad, Limits::default());
    end.unwrap();
    assert!(by_name(&got, "/ok").unsupported.is_some());
}

/// A member of the stream larger than the buffer limit is read as it is
/// decoded, however large.
#[test]
fn a_file_past_the_buffer_limit_is_read_as_it_is_decoded() {
    let frames = 200;
    let spec = Spec {
        frames,
        interval: 2,
        damaged: vec![],
        files: vec![File::Packed("/big", 0, (frames * FRAME) as u64)],
    };
    let blob = spec.build();
    let cache = BlockCache::with_sizes(Cursor::new(blob), 4096, 64 * 1024).unwrap();
    let mut budget = Budget::new(limits_with_buffer(1024 * 1024));
    let mut seen = 0usize;
    let end = walk(Format::Chm, &cache, &mut budget, &mut |_, content, _| {
        let Some(Member::Stream(r)) = content else {
            panic!("a member decoded whole")
        };
        let mut buf = vec![0u8; 5000];
        let mut text = (usize::MAX, Vec::new());
        loop {
            let n = r.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            for (i, b) in buf[..n].iter().enumerate() {
                let p = seen + i;
                if text.0 != p / FRAME {
                    text = (p / FRAME, synth::frame_text(p / FRAME));
                }
                assert_eq!(*b, text.1[p % FRAME], "at {p}");
            }
            seen += n;
        }
        None::<()>
    });
    end.unwrap();
    assert_eq!(seen, frames * FRAME);
}
