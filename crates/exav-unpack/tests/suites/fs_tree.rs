//! The tree every filesystem fixture holds (`fixtures/fs/tree.py`, built into
//! images by `fixtures/fs/make.sh`), and the check of a walk against it.
//!
//! The bytes of a file are made by `pat`, the same function `tree.py` has, so
//! a walk is compared with what was written and not with a list of hashes.

use std::collections::HashMap;

use exav_unpack::{Budget, Entry, Format, LimitHit, Limits, Member, walk};

use super::extract_each;

/// `n` bytes for the file numbered `seed`: runs of 64 that are noise and runs
/// of 64 that are text, so a compressor has something to do and something not
/// to.
pub(super) fn pat(seed: u32, n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| {
            if (i / 64) % 2 == 0 {
                (((i as u32).wrapping_mul(2654435761)).wrapping_add(seed.wrapping_mul(40503)) >> 13)
                    as u8
            } else {
                b"abcdefghij0123456789"[(i + seed as usize) % 20]
            }
        })
        .collect()
}

/// An image of `fixtures/fs`, gunzipped.
pub(super) fn image(name: &str) -> Vec<u8> {
    let p = format!(
        "{}/tests/fixtures/fs/{name}.img.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let raw = exav_unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"));
    let mut out = Vec::new();
    std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&raw[..]), &mut out)
        .unwrap_or_else(|e| panic!("gunzip {p}: {e}"));
    out
}

/// The files of `tree.py`, with `sparse.bin` where asked.
pub(super) fn tree(sparse: bool) -> Vec<(String, Vec<u8>)> {
    let files: [(&str, usize); 10] = [
        ("empty", 0),
        ("tiny.txt", 10),
        ("sixty.bin", 60),
        ("sixtyone.bin", 61),
        ("p1.bin", 1025),
        ("big4k.bin", 4096),
        ("a/b/c/deep.bin", 5000),
        ("caf\u{e9} \u{65e5}\u{672c}.txt", 300),
        ("long name with spaces and a long extension.markdown", 700),
        ("frag.bin", 100000),
    ];
    let mut out: Vec<(String, Vec<u8>)> = files
        .iter()
        .enumerate()
        .map(|(seed, (path, size))| ((*path).to_string(), pat(seed as u32, *size)))
        .collect();
    for i in 0..300u32 {
        out.push((
            format!("many/file_{i:03}.dat"),
            pat(1000 + i, (i % 97) as usize),
        ));
    }
    if sparse {
        let mut data = vec![0u8; (70 << 20) + 4];
        for (k, (at, n)) in [(0usize, 3000usize), (30 << 20, 7000), (70 << 20, 4)]
            .into_iter()
            .enumerate()
        {
            data[at..at + n].copy_from_slice(&pat(2000 + k as u32, n));
        }
        out.push(("sparse.bin".to_string(), data));
    }
    out
}

/// The files `fixtures/fs/extras.py` makes in a mounted volume.
pub(super) fn extras() -> Vec<(String, Vec<u8>)> {
    let mut prealloc = vec![0u8; 1 << 20];
    prealloc[300000..305000].copy_from_slice(&pat(3000, 5000));
    let mut holey = pat(3001, 1 << 20);
    holey[100000..400000].fill(0);
    let mut trunc = b"abc".to_vec();
    trunc.resize(100000, 0);
    let mut out = vec![
        ("k/prealloc.bin".to_string(), prealloc),
        ("k/holey.bin".to_string(), holey),
        ("k/trunc.bin".to_string(), trunc),
    ];
    for i in (0..300usize).filter(|i| i % 3 != 0) {
        out.push((format!("k/d/f{i}"), vec![b'x'; i]));
    }
    out
}

/// The file `extras.py --trunc-only` makes: 3 bytes written and the length set
/// to 100000.
pub(super) fn truncated() -> (String, Vec<u8>) {
    let mut data = b"abc".to_vec();
    data.resize(100000, 0);
    ("k/trunc.bin".to_string(), data)
}

/// What a walk of `img` gave, and how it ended.
pub(super) fn walked(
    fmt: Format,
    img: &[u8],
    limits: Limits,
) -> (Vec<Entry>, Result<Option<()>, LimitHit>) {
    let mut out = Vec::new();
    let mut budget = Budget::new(limits);
    let end = extract_each(fmt, img, &mut budget, &mut |e: Entry, _: &mut Budget| {
        out.push(e);
        None::<()>
    });
    (out, end)
}

/// A member of a walk as it came: whether it was read as it goes, its bytes,
/// the error that ended that read, and what the walk reported of it.
pub(super) struct Came {
    pub(super) name: String,
    pub(super) streamed: bool,
    pub(super) data: Vec<u8>,
    pub(super) read_error: Option<String>,
    pub(super) unsupported: Option<&'static str>,
}

/// A walk of `img` under a buffer limit of `cap` bytes, which a file past it is
/// read as it goes under.
pub(super) fn came(fmt: Format, img: &[u8], cap: u64) -> (Vec<Came>, Result<Option<()>, LimitHit>) {
    let mut out = Vec::new();
    let mut limits = Limits::default();
    limits.max_buffer_bytes = cap;
    let mut budget = Budget::new(limits);
    let end = walk(fmt, &img, &mut budget, &mut |meta, content, _| {
        let mut read_error = None;
        let (streamed, data) = match content {
            None => (false, Vec::new()),
            Some(Member::Bytes(bytes)) => (false, bytes),
            Some(Member::Stream(reader)) => {
                let mut bytes = Vec::new();
                read_error = reader.read_to_end(&mut bytes).err().map(|e| e.to_string());
                (true, bytes)
            }
        };
        out.push(Came {
            name: meta.name.clone(),
            streamed,
            data,
            read_error,
            unsupported: meta.unsupported,
        });
        None::<()>
    });
    (out, end)
}

/// A walk of `img` under a buffer limit of `cap` gives what a walk that holds
/// every file gives, the files past `cap` read as they go and the others
/// held.
pub(super) fn assert_streams_alike(fmt: Format, img: &[u8], cap: u64) {
    let held = members(fmt, img);
    let (came, end) = came(fmt, img, cap);
    end.unwrap_or_else(|h| panic!("{fmt:?} ended: {h:?}"));
    assert_eq!(came.len(), held.len(), "{fmt:?}: the same members");
    for (c, h) in came.iter().zip(&held) {
        assert_eq!(c.name, h.name, "{fmt:?}");
        assert_eq!(c.data, h.data, "{fmt:?}: {}", c.name);
        assert_eq!(c.unsupported, h.unsupported, "{fmt:?}: {}", c.name);
        assert_eq!(c.read_error, None, "{fmt:?}: {}", c.name);
        assert_eq!(c.streamed, c.data.len() as u64 > cap, "{fmt:?}: {}", c.name);
    }
    assert!(
        came.iter().any(|c| c.streamed),
        "{fmt:?}: nothing was past {cap}"
    );
}

/// A walk of `img` that must end cleanly.
pub(super) fn members(fmt: Format, img: &[u8]) -> Vec<Entry> {
    let (e, end) = walked(fmt, img, Limits::default());
    end.unwrap_or_else(|h| panic!("{fmt:?} ended: {h:?}"));
    e
}

/// The walk has every file of `want` with its bytes, and nothing else, and
/// reports nothing unreadable.
pub(super) fn assert_tree(entries: &[Entry], want: &[(String, Vec<u8>)]) {
    let bad: Vec<_> = entries
        .iter()
        .filter(|e| e.unsupported.is_some())
        .map(|e| (&e.name, e.unsupported))
        .collect();
    assert!(bad.is_empty(), "reported: {bad:?}");
    let mut got: HashMap<&str, &[u8]> = HashMap::new();
    for e in entries {
        assert!(
            got.insert(&e.name, &e.data).is_none(),
            "{} came out twice",
            e.name
        );
    }
    let mut missing = Vec::new();
    let mut differ = Vec::new();
    for (path, data) in want {
        match got.get(path.as_str()) {
            None => missing.push(path.as_str()),
            Some(d) if d != &data.as_slice() => differ.push(path.as_str()),
            Some(_) => {}
        }
    }
    let extra: Vec<_> = got
        .keys()
        .filter(|k| !want.iter().any(|(p, _)| p == **k))
        .collect();
    assert!(
        missing.is_empty() && differ.is_empty() && extra.is_empty(),
        "missing {missing:?}, differing {differ:?}, unexpected {extra:?}"
    );
}
