//! A caller can narrow what a build will open, per call.
//!
//! Compile-time features decide what a *binary* can do. This decides what a
//! *call* may do, so one build serves a caller that accepts archives and a
//! caller that does not, without either maintaining its own build.
//!
//! The property that matters is not that exclusion works — it is that an
//! excluded container is REPORTED. "I declined to open this" and "there was
//! nothing here" must never look the same to whatever reads the result.

// `extract` and `Budget` are used only by the tests that open a real container,
// which are behind the `zip` feature; `Format` and `Limits` are always needed.
#[allow(unused_imports)]
use exav_unpack::{extract, Budget, Format, Limits};
use std::collections::BTreeSet;

/// A two-member ZIP, stored (no compression), so the test does not depend on a
/// codec being compiled in.
fn tiny_zip() -> Vec<u8> {
    let mut v = Vec::new();
    let names: [&[u8]; 2] = [b"a.txt", b"b.txt"];
    let bodies: [&[u8]; 2] = [b"hello", b"world"];
    let mut offsets = Vec::new();
    for (name, body) in names.iter().zip(bodies.iter()) {
        offsets.push(v.len() as u32);
        v.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04, 20, 0, 0, 0, 0, 0]);
        v.extend_from_slice(&[0u8; 4]); // time/date
        v.extend_from_slice(&crc32(body).to_le_bytes());
        v.extend_from_slice(&(body.len() as u32).to_le_bytes());
        v.extend_from_slice(&(body.len() as u32).to_le_bytes());
        v.extend_from_slice(&(name.len() as u16).to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(name);
        v.extend_from_slice(body);
    }
    let cd_start = v.len() as u32;
    for (i, (name, body)) in names.iter().zip(bodies.iter()).enumerate() {
        v.extend_from_slice(&[0x50, 0x4b, 0x01, 0x02, 20, 0, 20, 0, 0, 0, 0, 0]);
        v.extend_from_slice(&[0u8; 4]);
        v.extend_from_slice(&crc32(body).to_le_bytes());
        v.extend_from_slice(&(body.len() as u32).to_le_bytes());
        v.extend_from_slice(&(body.len() as u32).to_le_bytes());
        v.extend_from_slice(&(name.len() as u16).to_le_bytes());
        v.extend_from_slice(&[0u8; 8]);
        v.extend_from_slice(&[0u8; 4]);
        v.extend_from_slice(&offsets[i].to_le_bytes());
        v.extend_from_slice(name);
    }
    let cd_len = v.len() as u32 - cd_start;
    v.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0]);
    v.extend_from_slice(&(names.len() as u16).to_le_bytes());
    v.extend_from_slice(&(names.len() as u16).to_le_bytes());
    v.extend_from_slice(&cd_len.to_le_bytes());
    v.extend_from_slice(&cd_start.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & (!(crc & 1)).wrapping_add(1));
        }
    }
    !crc
}

fn limits_allowing(formats: &[Format]) -> Limits {
    Limits {
        allowed_formats: Some(formats.iter().copied().collect::<BTreeSet<_>>()),
        ..Limits::default()
    }
}

/// The default opens everything the build was compiled with. Narrowing has to
/// be asked for; a default that narrowed would hide content from callers who
/// never requested it.
#[test]
#[cfg(feature = "zip")]
fn the_default_allows_every_compiled_format() {
    let blob = tiny_zip();
    let mut budget = Budget::new(Limits::default());
    let entries = extract(Format::Zip, &blob, &mut budget).expect("default should extract");
    assert_eq!(entries.len(), 2, "got {entries:?}");
    assert!(entries.iter().all(|e| e.unsupported.is_none()));
}

/// An allowed format behaves exactly as it does without a list.
#[test]
#[cfg(feature = "zip")]
fn an_allowed_format_extracts_normally() {
    let blob = tiny_zip();
    let mut budget = Budget::new(limits_allowing(&[Format::Zip]));
    let entries = extract(Format::Zip, &blob, &mut budget).expect("zip is allowed");
    assert_eq!(entries.len(), 2, "got {entries:?}");
    assert!(entries.iter().all(|e| e.unsupported.is_none()));
}

/// The one that matters. An excluded format yields a REPORTED entry, not an
/// empty result — a caller that treats "no members" as "nothing to worry about"
/// must not be able to reach that conclusion by excluding a format.
#[test]
#[cfg(feature = "zip")]
fn an_excluded_format_is_reported_rather_than_skipped() {
    let blob = tiny_zip();
    // Allow something other than ZIP, so ZIP is excluded by omission.
    let mut budget = Budget::new(limits_allowing(&[Format::Tar]));
    let entries = extract(Format::Zip, &blob, &mut budget).expect("exclusion is not an error");

    assert_eq!(
        entries.len(),
        1,
        "expected one reporting entry, got {entries:?}"
    );
    let e = &entries[0];
    assert!(
        e.unsupported.is_some(),
        "an excluded container came back looking like an ordinary empty result: {e:?}"
    );
    assert!(
        e.data.is_empty(),
        "an excluded format must not yield content"
    );
}

/// An empty allow-list excludes everything, and still reports.
#[test]
#[cfg(feature = "zip")]
fn an_empty_allow_list_excludes_everything() {
    let blob = tiny_zip();
    let mut budget = Budget::new(limits_allowing(&[]));
    let entries = extract(Format::Zip, &blob, &mut budget).expect("exclusion is not an error");
    assert_eq!(entries.len(), 1);
    assert!(entries[0].unsupported.is_some());
}
