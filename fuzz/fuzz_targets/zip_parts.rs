//! The members of a ZIP package a converter wrote, read by exav's own reader.
use exav_unpack::{Budget, Format, Limits, Member, MemberMeta, walk};

/// `(name, bytes)` of every member, in directory order. Panics when the bytes
/// are not a ZIP or a member does not decode in full: a converter's output has
/// neither.
pub fn parts(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut limits = Limits::default();
    limits.max_members = u64::MAX;
    limits.max_extracted_bytes = u64::MAX;
    limits.max_buffer_bytes = u64::MAX;
    limits.max_compression_ratio = u64::MAX;
    let mut budget = Budget::new(limits);
    let mut seen = Vec::new();
    walk::<()>(
        Format::Zip,
        &bytes,
        &mut budget,
        &mut |meta: &MemberMeta, content: Option<Member<'_>>, budget: &mut Budget| {
            assert!(meta.unsupported.is_none(), "{}: a part", meta.name);
            let data = match content {
                Some(member) => {
                    let (data, partial) = member.into_bytes(meta, budget).expect("a part");
                    assert!(!partial, "{}: a part", meta.name);
                    data
                }
                None => Vec::new(),
            };
            seen.push((meta.name.clone(), data));
            None
        },
    )
    .expect("a ZIP");
    seen
}
