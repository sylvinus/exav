//! A compound file past the buffer limit, read from a source that is not in
//! memory: each stream from its place in the file, one past the limit (an
//! MSI's cabinet) handed over as it is read, and what the macro and
//! embedded-object passes need held until they have run.

use exav_unpack::source::BlockCache;
use exav_unpack::{Budget, Format, Limits, Member};
use std::io::{Cursor, Write};

const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR";
const CAP: u64 = 128 * 1024;

/// One member as the walk gave it: name, bytes, read as it went, why not
/// whole, encrypted.
type Got = (String, Vec<u8>, bool, Option<&'static str>, bool);

fn walk(blob: &[u8], cap: u64) -> (Vec<Got>, Result<(), String>) {
    let cache = BlockCache::with_sizes(Cursor::new(blob.to_vec()), 4096, 64 * 1024).unwrap();
    let mut limits = Limits::default();
    limits.max_buffer_bytes = cap;
    let mut budget = Budget::new(limits);
    let mut out = Vec::new();
    let end = exav_unpack::walk(Format::Ole, &cache, &mut budget, &mut |meta, content, _| {
        let (data, streamed) = match content {
            Some(Member::Stream(r)) => {
                let mut b = Vec::new();
                r.read_to_end(&mut b).unwrap();
                (b, true)
            }
            Some(Member::Bytes(b)) => (b, false),
            #[allow(unreachable_patterns)]
            Some(_) => panic!("{}: an unexpected kind of member", meta.name),
            None => (Vec::new(), false),
        };
        out.push((
            meta.name.clone(),
            data,
            streamed,
            meta.unsupported,
            meta.encrypted,
        ));
        None::<()>
    });
    (out, end.map(|_| ()).map_err(|e| e.to_string()))
}

fn ovba_container(payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0x01u8];
    let header: u16 = (0b011 << 12) | (payload.len() as u16 - 1);
    v.extend_from_slice(&header.to_le_bytes());
    v.extend_from_slice(payload);
    v
}

fn record(id: u16, body: &[u8]) -> Vec<u8> {
    let mut v = id.to_le_bytes().to_vec();
    v.extend_from_slice(&(body.len() as u32).to_le_bytes());
    v.extend_from_slice(body);
    v
}

fn vba_dir() -> Vec<u8> {
    let mut dir = Vec::new();
    dir.extend_from_slice(&record(0x0004, b"VBAProject"));
    dir.extend_from_slice(&record(0x0019, b"Module1"));
    dir.extend_from_slice(&0x001Au16.to_le_bytes());
    dir.extend_from_slice(&7u32.to_le_bytes());
    dir.extend_from_slice(b"Module1");
    dir.extend_from_slice(&0x0032u16.to_le_bytes());
    let utf16: Vec<u8> = "Module1"
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    dir.extend_from_slice(&(utf16.len() as u32).to_le_bytes());
    dir.extend_from_slice(&utf16);
    dir.extend_from_slice(&record(0x0031, &0u32.to_le_bytes()));
    dir.extend_from_slice(&record(0x002B, &[]));
    ovba_container(&dir)
}

fn pattern(n: usize, seed: u32) -> Vec<u8> {
    (0..n as u32)
        .map(|i| (i.wrapping_mul(seed) >> 3) as u8)
        .collect()
}

/// A compound file of `streams`, each `(path, body)`, storages made as their
/// paths need them.
fn compound(streams: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut cf = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
    for (path, body) in streams {
        let parent = &path[..path.rfind('/').unwrap()];
        if !parent.is_empty() && !cf.exists(parent) {
            cf.create_storage_all(parent).unwrap();
        }
        cf.create_stream(path).unwrap().write_all(body).unwrap();
    }
    cf.flush().unwrap();
    cf.into_inner().into_inner()
}

fn find<'a>(got: &'a [Got], name: &str) -> &'a Got {
    got.iter()
        .find(|g| g.0 == name)
        .unwrap_or_else(|| panic!("no member {name}: {:?}", names(got)))
}

fn names(got: &[Got]) -> Vec<&str> {
    got.iter().map(|g| g.0.as_str()).collect()
}

fn installer() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let cab1 = pattern(300_000, 7);
    let mut cab2 = pattern(400_000, 13);
    cab2.extend_from_slice(EICAR);
    let mut module = b"Attribute VB_Name = \"Module1\"\r\nSub AutoOpen()\r\n".to_vec();
    module.extend_from_slice(b"CreateObject(\"WScript.Shell\")\r\nEnd Sub\r\n");
    let blob = compound(&[
        ("/small", b"hello".to_vec()),
        ("/Cab1", cab1.clone()),
        ("/Macros/VBA/dir", vba_dir()),
        ("/Macros/VBA/Module1", ovba_container(&module)),
        ("/Cab2", cab2.clone()),
    ]);
    (blob, cab1, cab2)
}

/// Every stream reached in a file five times the buffer limit: the small ones
/// whole, the two past it as they are read, the signature at the end of the
/// last one there, and the VBA project assembled from the streams held for it.
#[test]
fn a_compound_file_past_the_buffer_limit_is_read_a_stream_at_a_time() {
    let (blob, cab1, cab2) = installer();
    assert!(blob.len() as u64 > 5 * CAP);
    let (got, end) = walk(&blob, CAP);
    end.unwrap();
    assert!(got.iter().all(|g| g.3.is_none()), "{got:?}");
    assert_eq!(find(&got, "/small").1, b"hello");
    assert!(!find(&got, "/small").2);
    let c1 = find(&got, "/Cab1");
    assert!(c1.2 && c1.1 == cab1);
    let c2 = find(&got, "/Cab2");
    assert!(c2.2 && c2.1 == cab2);
    assert!(c2.1.ends_with(EICAR));
    let vba = find(&got, "vba_project_raw");
    assert!(
        vba.1.windows(12).any(|w| w == b"CreateObject"),
        "{}",
        String::from_utf8_lossy(&vba.1)
    );

    // The same file in memory, read whole: the same members.
    let mut budget = Budget::new(Limits::default());
    let whole = exav_unpack::extract(Format::Ole, &blob, &mut budget).unwrap();
    let mut a: Vec<_> = whole
        .iter()
        .map(|e| (e.name.clone(), e.data.clone()))
        .collect();
    let mut b: Vec<_> = got.iter().map(|g| (g.0.clone(), g.1.clone())).collect();
    a.sort();
    b.sort();
    assert_eq!(a, b);
}

/// Cut anywhere, the file gives over a source what it gives in memory: the
/// streams as far as they are in it, no more and no error the other does not
/// have.
#[test]
fn a_cut_file_gives_what_it_holds_as_it_does_in_memory() {
    let (blob, _, _) = installer();
    for n in [blob.len() * 9 / 10, blob.len() * 3 / 4, blob.len() / 2] {
        let cut = &blob[..n];
        let (got, end) = walk(cut, CAP);
        let mut budget = Budget::new(Limits::default());
        match exav_unpack::extract(Format::Ole, &cut, &mut budget) {
            Ok(whole) => {
                end.unwrap();
                let mut a: Vec<_> = whole
                    .iter()
                    .map(|e| (e.name.clone(), e.data.clone()))
                    .collect();
                let mut b: Vec<_> = got.iter().map(|g| (g.0.clone(), g.1.clone())).collect();
                a.sort();
                b.sort();
                assert_eq!(a, b, "cut at {n}");
            }
            Err(e) => assert!(end.is_err(), "cut at {n}: {e} in memory, none off a source"),
        }
    }
}

/// A Word document stream past the limit that says it is encrypted is
/// reported as such and not handed over.
#[test]
fn an_encrypted_document_stream_past_the_limit_is_reported() {
    let mut word = pattern(300_000, 5);
    word[10..12].copy_from_slice(&0x0100u16.to_le_bytes());
    let blob = compound(&[("/WordDocument", word), ("/Data", pattern(400_000, 3))]);
    let (got, end) = walk(&blob, CAP);
    end.unwrap();
    let w = find(&got, "/WordDocument");
    assert!(w.3.is_some() && w.4 && w.1.is_empty(), "{w:?}");
    assert!(find(&got, "/Data").3.is_none());
}

/// A presentation's record stream past the limit is scanned as it is read,
/// and the objects it would hold are reported as not carved.
#[test]
fn a_stream_the_passes_read_past_the_limit_is_reported_as_not_carved() {
    let blob = compound(&[("/PowerPoint Document", pattern(700_000, 9))]);
    let (got, end) = walk(&blob, CAP);
    end.unwrap();
    assert!(find(&got, "/PowerPoint Document").2);
    assert!(find(&got, "/PowerPoint Document-contents").3.is_some());
}

/// A directory longer than the limit is read up to it, and the rest is
/// reported.
#[test]
fn a_directory_past_the_limit_is_reported() {
    let mut streams: Vec<(String, Vec<u8>)> = (0..600)
        .map(|i| (format!("/s{i:03}"), vec![b'x'; 8]))
        .collect();
    streams.push(("/big".to_string(), pattern(200_000, 11)));
    let refs: Vec<(&str, Vec<u8>)> = streams
        .iter()
        .map(|(p, b)| (p.as_str(), b.clone()))
        .collect();
    let blob = compound(&refs);
    let cap = 64 * 1024;
    assert!(blob.len() as u64 > cap);
    let (got, end) = walk(&blob, cap);
    end.unwrap();
    assert!(find(&got, "<directory>").3.is_some());
    assert!(got.len() < 602);
}

/// No stream holds more than the file: one whose directory entry says more is
/// read as far as its chain goes.
#[test]
fn a_stream_said_larger_than_the_file_is_read_as_far_as_it_goes() {
    let mut body = pattern(8_000, 7);
    body.extend_from_slice(EICAR);
    let mut blob = compound(&[("/big", body.clone())]);
    // The size in the stream's directory entry, 120 bytes after its name.
    let name: Vec<u8> = "big".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let at = blob.windows(name.len()).position(|w| w == name).unwrap() + 120;
    blob[at..at + 8].copy_from_slice(&(1u64 << 30).to_le_bytes());
    let mut budget = Budget::new(Limits::default());
    let got = exav_unpack::extract(Format::Ole, &blob, &mut budget).unwrap();
    let big = got.iter().find(|e| e.name == "/big");
    assert!(big.is_some_and(|e| e.data.starts_with(&body)), "{got:?}");
}
